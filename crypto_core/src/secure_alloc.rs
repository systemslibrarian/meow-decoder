//! # SecureBox — Secure Memory Allocator with Guard Pages
//!
//! Provides `SecureBox<T>` — a heap allocation that:
//! 1. `mlock()`s the pages to prevent swap-out
//! 2. Places `PROT_NONE` guard pages before and after to detect overflows
//! 3. Sets `MADV_DONTDUMP` to exclude from core dumps
//! 4. Zeroizes on drop via volatile writes
//! 5. `munlock()`s and `munmap()`s the entire region
//!
//! # Usage
//!
//! ```rust
//! use crypto_core::secure_alloc::SecureBox;
//!
//! // Allocate a 32-byte key in guarded, locked memory
//! let key = SecureBox::new([0u8; 32]).expect("secure alloc failed");
//!
//! // Access the data
//! let data: &[u8; 32] = &*key;
//!
//! // On drop: zeroize → munlock → munmap (including guard pages)
//! drop(key);
//! ```
//!
//! # Security Properties
//!
//! - **No swap**: `mlock`/`VirtualLock` prevents the OS from swapping key pages to disk
//! - **Guard pages**: `PROT_NONE`/`PAGE_NOACCESS` pages before and after detect buffer overflows
//! - **No core dump**: `MADV_DONTDUMP` (Linux) excludes key memory from crash dumps
//! - **Zeroize on drop**: Volatile writes ensure compiler doesn't optimize away zeroing
//! - **Region cleanup**: Full `munmap`/`VirtualFree` releases all pages including guards
//!
//! # Platform Support
//!
//! - **Linux**: Full support (mmap, mlock, mprotect, madvise MADV_DONTDUMP)
//! - **macOS**: Partial (no MADV_DONTDUMP, but mlock + guard pages work)
//! - **Windows**: Full support (VirtualAlloc, VirtualLock, VirtualProtect, guard pages)
//! - **WASM**: Not supported (no virtual memory)

use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use zeroize::Zeroize;

/// Errors from secure allocation.
#[derive(Debug)]
pub enum SecureAllocError {
    /// `mmap` call failed
    MmapFailed(i32),
    /// `mprotect` call failed (could not make data pages read/write)
    MprotectFailed(i32),
    /// Requested size is zero
    ZeroSize,
}

impl std::fmt::Display for SecureAllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureAllocError::MmapFailed(e) => write!(f, "mmap failed (errno {})", e),
            SecureAllocError::MprotectFailed(e) => write!(f, "mprotect failed (errno {})", e),
            SecureAllocError::ZeroSize => write!(f, "cannot allocate zero-size SecureBox"),
        }
    }
}

impl std::error::Error for SecureAllocError {}

/// A heap allocation with guard pages, mlock, MADV_DONTDUMP, and zeroize-on-drop.
///
/// The memory layout is:
/// ```text
/// [PROT_NONE guard page] [PROT_READ|PROT_WRITE data pages] [PROT_NONE guard page]
///                         ↑ data pointer points here
/// ```
pub struct SecureBox<T: Zeroize> {
    /// Pointer to the usable data region (between guard pages)
    data: NonNull<T>,
    /// Base address of the entire mmap region
    mmap_base: *mut u8,
    /// Total size of the mmap region (guards + data)
    mmap_size: usize,
    /// System page size (cached)
    page_size: usize,
    /// Whether mlock succeeded
    mlocked: bool,
}

// SecureBox is not Send/Sync by default due to raw pointers.
// It is safe to send across threads as long as T is Send.
unsafe impl<T: Zeroize + Send> Send for SecureBox<T> {}
unsafe impl<T: Zeroize + Sync> Sync for SecureBox<T> {}

impl<T: Zeroize> SecureBox<T> {
    /// Allocate a new `SecureBox` containing `value`.
    ///
    /// The allocation is:
    /// 1. A full mmap region with guard pages
    /// 2. Data pages are `mlock`'d (best-effort)
    /// 3. `MADV_DONTDUMP` is set (Linux only, best-effort)
    /// 4. The value is written to the data pages
    ///
    /// # Errors
    ///
    /// Returns `SecureAllocError` if `mmap` or `mprotect` fails.
    #[cfg(unix)]
    pub fn new(value: T) -> Result<Self, SecureAllocError> {
        use libc::{
            c_void, mmap, mprotect, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_NONE,
            PROT_READ, PROT_WRITE,
        };

        let data_size = std::mem::size_of::<T>();
        if data_size == 0 {
            return Err(SecureAllocError::ZeroSize);
        }

        let page_size_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size_raw <= 0 {
            // sysconf returned -1 (error) or 0 (invalid).  Casting -1 to
            // usize would silently produce usize::MAX and cause allocation
            // arithmetic to wrap.  Fail-closed instead.
            return Err(SecureAllocError::MmapFailed(0));
        }
        let page_size = page_size_raw as usize;
        // Round data up to page boundary
        let data_pages = data_size.div_ceil(page_size);
        let data_region_size = data_pages * page_size;
        // Total: guard_before + data + guard_after
        let total_size = data_region_size + 2 * page_size;

        // Step 1: mmap entire region as PROT_NONE (all pages inaccessible by default)
        let base = unsafe {
            mmap(
                std::ptr::null_mut(),
                total_size,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == MAP_FAILED {
            return Err(SecureAllocError::MmapFailed(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }

        // Step 2: mprotect the data pages (skip first guard page)
        let data_ptr = unsafe { (base as *mut u8).add(page_size) };
        let ret = unsafe {
            mprotect(
                data_ptr as *mut c_void,
                data_region_size,
                PROT_READ | PROT_WRITE,
            )
        };
        if ret != 0 {
            unsafe {
                munmap(base, total_size);
            }
            return Err(SecureAllocError::MprotectFailed(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }

        // Step 3: mlock the data pages (best-effort — may fail without CAP_IPC_LOCK)
        let mlocked = unsafe { libc::mlock(data_ptr as *const c_void, data_region_size) == 0 };
        if !mlocked {
            // Not fatal: log at debug level in production
            #[cfg(debug_assertions)]
            eprintln!(
                "[WARN] mlock failed for SecureBox ({} bytes) — key memory may be swapped",
                data_size
            );
        }

        // Step 4: MADV_DONTDUMP (Linux only — exclude from core dumps)
        #[cfg(target_os = "linux")]
        {
            const MADV_DONTDUMP: i32 = 16;
            unsafe {
                libc::madvise(data_ptr as *mut c_void, data_region_size, MADV_DONTDUMP);
            }
        }

        // Step 5: Write the value into the secured region
        unsafe {
            std::ptr::write(data_ptr as *mut T, value);
        }

        Ok(SecureBox {
            data: unsafe { NonNull::new_unchecked(data_ptr as *mut T) },
            mmap_base: base as *mut u8,
            mmap_size: total_size,
            page_size,
            mlocked,
        })
    }

    /// Returns true if `mlock` succeeded (pages are locked in RAM).
    pub fn is_locked(&self) -> bool {
        self.mlocked
    }

    /// Returns the size of the usable data region in bytes.
    pub fn data_size(&self) -> usize {
        std::mem::size_of::<T>()
    }

    /// Returns the total mapped region size including guard pages.
    pub fn total_size(&self) -> usize {
        self.mmap_size
    }

    /// Windows implementation: VirtualAlloc + VirtualLock + VirtualProtect
    ///
    /// Layout: [PAGE_NOACCESS guard] [PAGE_READWRITE data] [PAGE_NOACCESS guard]
    #[cfg(windows)]
    pub fn new(value: T) -> Result<Self, SecureAllocError> {
        use std::ptr;
        use winapi::um::memoryapi::{
            VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
        };
        use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
        use winapi::um::winnt::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE,
        };

        let data_size = std::mem::size_of::<T>();
        if data_size == 0 {
            return Err(SecureAllocError::ZeroSize);
        }

        // Get system page size
        let page_size = unsafe {
            let mut si: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut si);
            si.dwPageSize as usize
        };

        // Round data up to page boundary
        let data_pages = data_size.div_ceil(page_size);
        let data_region_size = data_pages * page_size;
        // Total: guard_before + data + guard_after
        let total_size = data_region_size + 2 * page_size;

        // Step 1: VirtualAlloc entire region as PAGE_NOACCESS
        let base = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                total_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_NOACCESS,
            )
        };
        if base.is_null() {
            return Err(SecureAllocError::MmapFailed(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }

        // Step 2: VirtualProtect the data pages to PAGE_READWRITE
        let data_ptr = unsafe { (base as *mut u8).add(page_size) };
        let mut old_protect: u32 = 0;
        let ret = unsafe {
            VirtualProtect(
                data_ptr as *mut _,
                data_region_size,
                PAGE_READWRITE,
                &mut old_protect,
            )
        };
        if ret == 0 {
            unsafe {
                VirtualFree(base, 0, MEM_RELEASE);
            }
            return Err(SecureAllocError::MprotectFailed(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }

        // Step 3: VirtualLock the data pages (best-effort - requires SE_LOCK_MEMORY_PRIVILEGE)
        let mlocked = unsafe { VirtualLock(data_ptr as *mut _, data_region_size) != 0 };
        if !mlocked {
            #[cfg(debug_assertions)]
            eprintln!(
                "[WARN] VirtualLock failed for SecureBox ({} bytes) — key memory may be swapped",
                data_size
            );
        }

        // Step 4: Write the value into the secured region
        unsafe {
            std::ptr::write(data_ptr as *mut T, value);
        }

        Ok(SecureBox {
            data: unsafe { NonNull::new_unchecked(data_ptr as *mut T) },
            mmap_base: base as *mut u8,
            mmap_size: total_size,
            page_size,
            mlocked,
        })
    }
}

#[cfg(unix)]
impl<T: Zeroize> Drop for SecureBox<T> {
    fn drop(&mut self) {
        // Step 1: Zeroize the data (volatile writes)
        unsafe {
            self.data.as_mut().zeroize();
        }

        // Step 2: Drop the inner value so heap-allocating types (e.g. Vec<u8>)
        // free their buffers. Must happen AFTER zeroize, BEFORE munmap.
        unsafe {
            std::ptr::drop_in_place(self.data.as_ptr());
        }

        // Step 3: munlock if we locked it
        if self.mlocked {
            let data_ptr = unsafe { self.mmap_base.add(self.page_size) };
            let data_region_size = self.mmap_size - 2 * self.page_size;
            unsafe {
                libc::munlock(data_ptr as *const libc::c_void, data_region_size);
            }
        }

        // Step 4: munmap the entire region (guard pages + data)
        unsafe {
            libc::munmap(self.mmap_base as *mut libc::c_void, self.mmap_size);
        }
    }
}

#[cfg(windows)]
impl<T: Zeroize> Drop for SecureBox<T> {
    fn drop(&mut self) {
        use winapi::um::memoryapi::{VirtualFree, VirtualUnlock};
        use winapi::um::winnt::MEM_RELEASE;

        // Step 1: Zeroize the data (volatile writes)
        unsafe {
            self.data.as_mut().zeroize();
        }

        // Step 2: Drop the inner value so heap-allocating types (e.g. Vec<u8>)
        // free their buffers. Must happen AFTER zeroize, BEFORE VirtualFree.
        unsafe {
            std::ptr::drop_in_place(self.data.as_ptr());
        }

        // Step 3: VirtualUnlock if we locked it
        if self.mlocked {
            let data_ptr = unsafe { self.mmap_base.add(self.page_size) };
            let data_region_size = self.mmap_size - 2 * self.page_size;
            unsafe {
                VirtualUnlock(data_ptr as *mut _, data_region_size);
            }
        }

        // Step 4: VirtualFree the entire region
        unsafe {
            VirtualFree(self.mmap_base as *mut _, 0, MEM_RELEASE);
        }
    }
}

impl<T: Zeroize> Deref for SecureBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.data.as_ref() }
    }
}

impl<T: Zeroize> DerefMut for SecureBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.data.as_mut() }
    }
}

// Prevent debug output from leaking key material
impl<T: Zeroize> std::fmt::Debug for SecureBox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBox")
            .field("data_size", &self.data_size())
            .field("mlocked", &self.mlocked)
            .field("total_size", &self.total_size())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_box_basic() {
        let key: [u8; 32] = [0x42; 32];
        let sbox = SecureBox::new(key).expect("alloc failed");
        assert_eq!(&*sbox, &[0x42u8; 32]);
        assert_eq!(sbox.data_size(), 32);
        assert!(sbox.total_size() > 32); // Must include guard pages
    }

    #[test]
    fn test_secure_box_mutation() {
        let mut sbox = SecureBox::new([0u8; 16]).expect("alloc failed");
        sbox[0] = 0xFF;
        sbox[15] = 0xAB;
        assert_eq!(sbox[0], 0xFF);
        assert_eq!(sbox[15], 0xAB);
    }

    #[test]
    fn test_secure_box_zero_size_fails() {
        let result = SecureBox::new(());
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_box_debug_no_leak() {
        let sbox = SecureBox::new([0xDE, 0xAD, 0xBE, 0xEF]).expect("alloc failed");
        let debug_str = format!("{:?}", sbox);
        // Debug output must NOT contain key bytes
        assert!(!debug_str.contains("222")); // 0xDE
        assert!(!debug_str.contains("173")); // 0xAD
        assert!(debug_str.contains("SecureBox"));
        assert!(debug_str.contains("data_size"));
    }

    #[test]
    fn test_secure_box_drop_zeroizes() {
        // We can't directly verify memory is zeroed after drop without UB,
        // but we can verify the drop path doesn't panic
        let sbox = SecureBox::new([0xFF; 64]).expect("alloc failed");
        drop(sbox);
        // If we get here, drop (zeroize + munlock + munmap) succeeded
    }

    #[test]
    fn test_secure_box_large_allocation() {
        // Allocate 4 KB — multiple pages
        let data = vec![0xABu8; 4096];
        let mut arr = [0u8; 4096];
        arr.copy_from_slice(&data);
        let sbox = SecureBox::new(arr).expect("alloc failed");
        assert_eq!(sbox[0], 0xAB);
        assert_eq!(sbox[4095], 0xAB);
    }

    #[test]
    fn test_guard_pages_layout() {
        let sbox = SecureBox::new([0u8; 32]).expect("alloc failed");
        let page_size = sbox.page_size;
        // Total must be at least 3 pages (guard + data + guard)
        assert!(sbox.total_size() >= 3 * page_size);
    }
}
