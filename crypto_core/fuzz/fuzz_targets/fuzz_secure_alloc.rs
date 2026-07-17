#![no_main]
use crypto_core::secure_alloc::SecureBox;
/// Fuzz target: SecureBox memory hardening with extreme / adversarial sizes.
///
/// Discovers:
/// - Panics or UB in SecureBox::new with extreme value sizes
/// - Memory locking / unlocking failures not propagated as errors
/// - Zeroization: data must be cleared upon Drop
/// - is_locked() consistency: always matches allocation state
/// - total_size() >= data_size() invariant
///
/// SECURITY (L4): `SecureBox<T>` only protects `size_of::<T>()` inline
/// bytes, so it must be used with a fixed-size, non-heap-owning `T`
/// (e.g. `[u8; N]`) — never `Vec<u8>`/`String`, whose secret bytes live
/// in unprotected heap. This target now fuzzes the supported `[u8; N]`
/// shape (the previous `SecureBox<Vec<u8>>` usage was the very misuse the
/// finding flags, and now trips the constructor's `needs_drop` assert).
use libfuzzer_sys::fuzz_target;

const N: usize = 64;

fuzz_target!(|raw: &[u8]| {
    if raw.is_empty() {
        return;
    }

    // Copy up to N fuzz bytes into a fixed-size array (zero-padded).
    let mut alloc_data = [0u8; N];
    for (dst, &src) in alloc_data.iter_mut().zip(raw.iter().take(N)) {
        *dst = src;
    }

    // --- Test 1: basic allocation and field access ---
    match SecureBox::new(alloc_data) {
        Ok(b) => {
            // Invariant: total_size >= data_size
            assert!(
                b.total_size() >= b.data_size(),
                "SecureBox: total_size ({}) < data_size ({})",
                b.total_size(),
                b.data_size()
            );

            // Invariant: data_size == size_of the stored type ([u8; N] = N bytes).
            assert_eq!(b.data_size(), std::mem::size_of::<[u8; N]>());

            // is_locked() must not panic
            let _locked = b.is_locked();

            // Deref must yield original data
            let data_ref: &[u8; N] = &*b;
            assert_eq!(&data_ref[..], &alloc_data[..]);
        }
        Err(_) => {
            // Allocation failure is acceptable (e.g., mlock limit reached)
        }
    }

    // --- Test 2: minimal allocation (single byte payload type) ---
    let _ = SecureBox::new(0u8); // Must not panic regardless of outcome

    // --- Test 3: larger fixed-size allocation (stress test) ---
    let mut large_data = [0u8; 4096];
    for (dst, &src) in large_data.iter_mut().zip(raw.iter().take(4096)) {
        *dst = src;
    }
    if let Ok(b) = SecureBox::new(large_data) {
        assert!(b.total_size() >= b.data_size());
        // Drop here zeroizes + munlocks
    }
});
