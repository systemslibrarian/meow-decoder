"""
Process-Wide Memory Hardening Guard

Activates OS-level protections to prevent sensitive data from leaking
through swap files, core dumps, or ptrace attachment.

Protections applied:
1. mlockall(MCL_CURRENT | MCL_FUTURE) — lock all pages in RAM (Linux/macOS)
   VirtualLock for critical buffers (Windows)
2. RLIMIT_CORE → 0 — prevent core dump generation (Unix)
   SetErrorMode to suppress crash dialogs (Windows)
3. prctl(PR_SET_DUMPABLE, 0) — prevent ptrace attachment (Linux)
4. RLIMIT_MEMLOCK raise — attempt to increase mlock limit (Unix)

Usage:
    from meow_decoder.memory_guard import activate_memory_guard

    status = activate_memory_guard()
    # status = {"mlockall": True, "no_coredump": True, "no_ptrace": True, ...}

WARNING:
    - mlockall may fail if RLIMIT_MEMLOCK is too low (default 64KB on many distros)
    - Requires root or CAP_IPC_LOCK for mlockall with MCL_FUTURE
    - Windows VirtualLock requires SE_LOCK_MEMORY_PRIVILEGE for large buffers
    - These are best-effort — a root attacker can override all protections
    - Call as early as possible in the process lifecycle

Security Properties:
    - Prevents key material from being written to swap
    - Prevents core dumps from containing key material
    - Prevents debugger attachment (non-root)
    - Does NOT protect against root-level attacks or cold-boot attacks

Cross-platform: Windows, Linux, macOS
"""

import ctypes
import os
import platform
import warnings
from typing import Callable, Dict, Optional

__all__ = [
    "activate_memory_guard",
    "require_memory_guard",
    "get_guard_status",
    "raise_mlock_limit",
    "MemoryGuardWarning",
    "virtual_lock_buffer",
    "virtual_unlock_buffer",
    "require_locked_buffer",
    "GuardedBuffer",
]


class MemoryGuardWarning(UserWarning):
    """Warning issued when a memory guard protection cannot be activated."""

    pass


# Module-level state
_guard_status: Optional[Dict[str, bool]] = None
_guard_activated: bool = False
_system = platform.system()


def _get_libc():
    """Load platform-specific libc."""
    try:
        if _system == "Linux":
            return ctypes.CDLL("libc.so.6", use_errno=True)
        elif _system == "Darwin":
            return ctypes.CDLL("libc.dylib", use_errno=True)
        else:
            return None
    except OSError:
        return None


def _get_kernel32():
    """Load Windows kernel32.dll."""
    if _system != "Windows":
        return None
    try:
        return ctypes.windll.kernel32
    except (OSError, AttributeError):
        return None


def raise_mlock_limit(target_bytes: int = 256 * 1024 * 1024) -> bool:
    """
    Attempt to raise RLIMIT_MEMLOCK to allow locking more memory.

    Args:
        target_bytes: Desired limit in bytes (default 256 MiB).

    Returns:
        True if limit was raised (or already sufficient), False otherwise.

    Note:
        Raising the hard limit requires root or CAP_SYS_RESOURCE.
        This function only raises the soft limit up to the hard limit.
        On Windows, returns True (VirtualLock uses working set limits).
    """
    if _system == "Windows":
        # Windows uses working set limits, not RLIMIT_MEMLOCK
        return True
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        if soft >= target_bytes:
            return True
        new_soft = min(target_bytes, hard)
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (new_soft, hard))
        return new_soft >= target_bytes
    except (ValueError, ImportError, OSError):
        return False


def _activate_mlockall(libc) -> bool:
    """Lock all current and future memory pages in RAM (Unix)."""
    if libc is None:
        return False
    try:
        MCL_CURRENT = 1
        MCL_FUTURE = 2
        result = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        return result == 0
    except (OSError, AttributeError):
        return False


def _disable_core_dumps() -> bool:
    """Set RLIMIT_CORE to 0 or configure Windows to suppress crash dialogs."""
    if _system == "Windows":
        # Windows: Suppress crash dialog boxes via SetErrorMode
        try:
            kernel32 = _get_kernel32()
            if kernel32:
                # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
                SEM_FLAGS = 0x0001 | 0x0002 | 0x8000
                kernel32.SetErrorMode(SEM_FLAGS)
                return True
        except Exception:
            pass
        return False
    else:
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            return True
        except (ValueError, ImportError, OSError):
            return False


def _set_non_dumpable(libc) -> bool:
    """Set PR_SET_DUMPABLE to 0 to prevent ptrace attachment (Linux only)."""
    if _system != "Linux" or libc is None:
        return False
    try:
        PR_SET_DUMPABLE = 4
        result = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        return result == 0
    except (OSError, AttributeError):
        return False


def _set_oom_score(score: int = -1000) -> bool:
    """
    Set OOM score adjustment to prevent OOM killer from targeting this process.
    Linux only.
    """
    if _system != "Linux":
        return False
    try:
        oom_path = f"/proc/{os.getpid()}/oom_score_adj"
        with open(oom_path, "w") as f:
            f.write(str(score))
        return True
    except (OSError, PermissionError):
        if score == -1000:
            return _set_oom_score(-500)
        return False


def _windows_set_privilege() -> bool:
    """Attempt to enable SE_LOCK_MEMORY_PRIVILEGE on Windows."""
    if _system != "Windows":
        return False
    try:
        import ctypes.wintypes

        advapi32 = ctypes.windll.advapi32
        kernel32 = _get_kernel32()

        # Constants
        SE_PRIVILEGE_ENABLED = 0x00000002
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", ctypes.wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", ctypes.wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1),
            ]

        # Open process token
        token = ctypes.wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)
        ):
            return False

        # Lookup privilege
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeLockMemoryPrivilege", ctypes.byref(luid)):
            kernel32.CloseHandle(token)
            return False

        # Enable privilege
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        result = advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        kernel32.CloseHandle(token)

        # Check if privilege was actually enabled
        return result != 0 and kernel32.GetLastError() == 0
    except Exception:
        return False


def virtual_lock_buffer(buf: bytearray) -> bool:
    """
    Lock a specific buffer in memory to prevent swap-out.

    Works on Windows (VirtualLock) and Unix (mlock).

    Args:
        buf: The buffer to lock.

    Returns:
        True if locking succeeded.
    """
    if len(buf) == 0:
        return True

    if _system == "Windows":
        try:
            kernel32 = _get_kernel32()
            if kernel32:
                addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
                return kernel32.VirtualLock(ctypes.c_void_p(addr), len(buf)) != 0
        except Exception:
            pass
        return False
    else:
        libc = _get_libc()
        if libc:
            try:
                addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
                return libc.mlock(ctypes.c_void_p(addr), len(buf)) == 0
            except Exception:
                pass
        return False


def virtual_unlock_buffer(buf: bytearray) -> bool:
    """
    Unlock a previously locked buffer.

    Args:
        buf: The buffer to unlock.

    Returns:
        True if unlocking succeeded.
    """
    if len(buf) == 0:
        return True

    if _system == "Windows":
        try:
            kernel32 = _get_kernel32()
            if kernel32:
                addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
                return kernel32.VirtualUnlock(ctypes.c_void_p(addr), len(buf)) != 0
        except Exception:
            pass
        return False
    else:
        libc = _get_libc()
        if libc:
            try:
                addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
                return libc.munlock(ctypes.c_void_p(addr), len(buf)) == 0
            except Exception:
                pass
        return False


def require_locked_buffer(buf: bytearray) -> None:
    """
    Fail-closed helper for high-risk paths.

    Raises RuntimeError if the buffer cannot be locked in RAM.
    """
    if not virtual_lock_buffer(buf):
        raise RuntimeError(
            "Memory locking failed (VirtualLock/mlock). "
            "Refusing to continue sensitive operation."
        )


# ── Guarded Buffer: Guard Pages for Overflow/Underflow Detection ─────────────
# Mirrors the Rust SecureBox pattern from crypto_core/src/secure_alloc.rs:
#   [PAGE_NOACCESS guard] [PAGE_READWRITE data] [PAGE_NOACCESS guard]
# Any buffer overflow/underflow immediately triggers SIGSEGV/ACCESS_VIOLATION.


class GuardedBuffer:
    """
    Heap-allocated buffer with guard pages for heap overflow/underflow detection.

    Layout: [PROT_NONE guard page] [R/W data pages] [PROT_NONE guard page]

    On Unix:   mmap(PROT_NONE) + mprotect(data, PROT_READ|PROT_WRITE) + mlock
    On Windows: VirtualAlloc(PAGE_NOACCESS) + VirtualProtect(data, PAGE_READWRITE) + VirtualLock

    Any out-of-bounds access immediately triggers SIGSEGV (Unix) or
    ACCESS_VIOLATION (Windows), preventing silent heap corruption.

    Usage:
        with GuardedBuffer(4096) as buf:
            buf.write(b"secret key material")
            data = buf.read(19)
        # buf is automatically zeroed + unmapped on exit

    Security Properties:
        - Guard pages: immediate crash on overflow/underflow (no silent corruption)
        - mlock/VirtualLock: data pages pinned in RAM (no swap leak)
        - Automatic zeroization on close/context-manager exit
        - MADV_DONTDUMP (Linux): excluded from core dumps
        - Compatible with Rust SecureBox layout for cross-language consistency
    """

    def __init__(self, size: int):
        """
        Allocate a guarded buffer of the given size.

        Args:
            size: Number of usable data bytes (will be rounded up to page boundary).

        Raises:
            ValueError: If size <= 0.
            RuntimeError: If allocation or guard page setup fails.
        """
        if size <= 0:
            raise ValueError("GuardedBuffer size must be > 0")

        self._closed = False
        self._size = size
        self._page_size = self._get_page_size()
        # Round data up to page boundary
        self._data_pages = (size + self._page_size - 1) // self._page_size
        self._data_region_size = self._data_pages * self._page_size
        self._total_size = self._data_region_size + 2 * self._page_size

        # Platform-specific allocation
        if _system == "Windows":
            self._base, self._data_ptr = self._alloc_windows()
        else:
            self._base, self._data_ptr = self._alloc_unix()

        self._mlocked = self._try_mlock()

    @staticmethod
    def _get_page_size() -> int:
        """Get OS page size."""
        if _system == "Windows":
            try:
                kernel32 = _get_kernel32()
                if kernel32:

                    class SYSTEM_INFO(ctypes.Structure):
                        _fields_ = [
                            ("wProcessorArchitecture", ctypes.c_ushort),
                            ("wReserved", ctypes.c_ushort),
                            ("dwPageSize", ctypes.c_ulong),
                            ("lpMinimumApplicationAddress", ctypes.c_void_p),
                            ("lpMaximumApplicationAddress", ctypes.c_void_p),
                            ("dwActiveProcessorMask", ctypes.c_size_t),
                            ("dwNumberOfProcessors", ctypes.c_ulong),
                            ("dwProcessorType", ctypes.c_ulong),
                            ("dwAllocationGranularity", ctypes.c_ulong),
                            ("wProcessorLevel", ctypes.c_ushort),
                            ("wProcessorRevision", ctypes.c_ushort),
                        ]

                    si = SYSTEM_INFO()
                    kernel32.GetSystemInfo(ctypes.byref(si))
                    return si.dwPageSize
            except Exception:
                pass
            return 4096  # Default
        else:
            try:
                return os.sysconf("SC_PAGE_SIZE")
            except (ValueError, OSError):
                return 4096

    def _alloc_unix(self):
        """Allocate guarded buffer on Unix (mmap + mprotect)."""
        libc = _get_libc()
        if libc is None:
            raise RuntimeError("Cannot load libc for guarded buffer allocation")

        import ctypes as ct

        # Constants
        PROT_NONE = 0x0
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        MAP_PRIVATE = 0x02
        MAP_ANONYMOUS = 0x20 if _system == "Linux" else 0x1000  # macOS uses 0x1000
        MAP_FAILED = ct.c_void_p(-1).value

        # Step 1: mmap entire region as PROT_NONE (all inaccessible)
        libc.mmap.restype = ct.c_void_p
        libc.mmap.argtypes = [ct.c_void_p, ct.c_size_t, ct.c_int, ct.c_int, ct.c_int, ct.c_long]
        base = libc.mmap(None, self._total_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        if base is None or base == MAP_FAILED:
            raise RuntimeError(f"mmap failed for guarded buffer ({self._total_size} bytes)")

        # Step 2: mprotect data pages to READ|WRITE (skip first guard page)
        data_ptr = base + self._page_size
        libc.mprotect.restype = ct.c_int
        libc.mprotect.argtypes = [ct.c_void_p, ct.c_size_t, ct.c_int]
        ret = libc.mprotect(ct.c_void_p(data_ptr), self._data_region_size, PROT_READ | PROT_WRITE)
        if ret != 0:
            libc.munmap(ct.c_void_p(base), self._total_size)
            raise RuntimeError("mprotect failed for guarded buffer data pages")

        # Step 3: MADV_DONTDUMP (Linux only — exclude from core dumps)
        if _system == "Linux":
            try:
                MADV_DONTDUMP = 16
                libc.madvise(ct.c_void_p(data_ptr), self._data_region_size, MADV_DONTDUMP)
            except Exception:
                pass  # Best-effort

        return base, data_ptr

    def _alloc_windows(self):
        """Allocate guarded buffer on Windows (VirtualAlloc + VirtualProtect)."""
        try:
            kernel32 = _get_kernel32()
            if kernel32 is None:
                raise RuntimeError("Cannot load kernel32.dll")

            import ctypes as ct

            # Constants
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_NOACCESS = 0x01
            PAGE_READWRITE = 0x04

            # Step 1: VirtualAlloc entire region as PAGE_NOACCESS
            kernel32.VirtualAlloc.restype = ct.c_void_p
            base = kernel32.VirtualAlloc(
                None, self._total_size, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS
            )
            if not base:
                raise RuntimeError(
                    f"VirtualAlloc failed for guarded buffer ({self._total_size} bytes)"
                )

            # Step 2: VirtualProtect data pages to PAGE_READWRITE
            data_ptr = base + self._page_size
            old_protect = ct.c_ulong()
            ret = kernel32.VirtualProtect(
                ct.c_void_p(data_ptr), self._data_region_size, PAGE_READWRITE, ct.byref(old_protect)
            )
            if not ret:
                kernel32.VirtualFree(ct.c_void_p(base), 0, 0x8000)  # MEM_RELEASE
                raise RuntimeError("VirtualProtect failed for guarded buffer data pages")

            return base, data_ptr

        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"Windows guarded buffer allocation failed: {e}")

    def _try_mlock(self) -> bool:
        """Try to mlock/VirtualLock the data pages (best-effort)."""
        if _system == "Windows":
            try:
                kernel32 = _get_kernel32()
                if kernel32:
                    return (
                        kernel32.VirtualLock(
                            ctypes.c_void_p(self._data_ptr), self._data_region_size
                        )
                        != 0
                    )
            except Exception:
                pass
            return False
        else:
            libc = _get_libc()
            if libc:
                try:
                    return libc.mlock(ctypes.c_void_p(self._data_ptr), self._data_region_size) == 0
                except Exception:
                    pass
            return False

    @property
    def size(self) -> int:
        """Usable data size in bytes."""
        return self._size

    @property
    def is_locked(self) -> bool:
        """True if data pages are mlock'd / VirtualLock'd."""
        return self._mlocked

    def write(self, data: bytes, offset: int = 0) -> None:
        """
        Write data into the guarded buffer.

        Args:
            data: Bytes to write.
            offset: Byte offset within the buffer.

        Raises:
            ValueError: If write would exceed buffer bounds.
            RuntimeError: If buffer is closed.
        """
        if self._closed:
            raise RuntimeError("GuardedBuffer is closed")
        if offset < 0 or offset + len(data) > self._size:
            raise ValueError(
                f"Write of {len(data)} bytes at offset {offset} "
                f"exceeds buffer size {self._size}"
            )
        ctypes.memmove(self._data_ptr + offset, data, len(data))

    def read(self, length: int, offset: int = 0) -> bytes:
        """
        Read data from the guarded buffer.

        Args:
            length: Number of bytes to read.
            offset: Byte offset within the buffer.

        Returns:
            Bytes read from the buffer.

        Raises:
            ValueError: If read would exceed buffer bounds.
            RuntimeError: If buffer is closed.
        """
        if self._closed:
            raise RuntimeError("GuardedBuffer is closed")
        if offset < 0 or offset + length > self._size:
            raise ValueError(
                f"Read of {length} bytes at offset {offset} " f"exceeds buffer size {self._size}"
            )
        return ctypes.string_at(self._data_ptr + offset, length)

    def zero(self) -> None:
        """Zero the entire data region (secure wipe).

        Raises:
            RuntimeError: If buffer is closed.
        """
        if self._closed:
            raise RuntimeError("GuardedBuffer is closed")
        ctypes.memset(self._data_ptr, 0, self._data_region_size)

    def close(self) -> None:
        """
        Securely close and free the guarded buffer.

        1. Zeroize all data pages
        2. munlock / VirtualUnlock
        3. munmap / VirtualFree entire region (including guard pages)
        """
        if self._closed:
            return
        self._closed = True

        # Step 1: Zeroize data
        try:
            ctypes.memset(self._data_ptr, 0, self._data_region_size)
        except Exception:
            pass

        # Step 2: Unlock
        if self._mlocked:
            if _system == "Windows":
                try:
                    kernel32 = _get_kernel32()
                    if kernel32:
                        kernel32.VirtualUnlock(
                            ctypes.c_void_p(self._data_ptr), self._data_region_size
                        )
                except Exception:
                    pass
            else:
                libc = _get_libc()
                if libc:
                    try:
                        libc.munlock(ctypes.c_void_p(self._data_ptr), self._data_region_size)
                    except Exception:
                        pass

        # Step 3: Free entire region
        if _system == "Windows":
            try:
                kernel32 = _get_kernel32()
                if kernel32:
                    MEM_RELEASE = 0x8000
                    kernel32.VirtualFree(ctypes.c_void_p(self._base), 0, MEM_RELEASE)
            except Exception:
                pass
        else:
            libc = _get_libc()
            if libc:
                try:
                    libc.munmap(ctypes.c_void_p(self._base), self._total_size)
                except Exception:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        """Safety net: ensure cleanup on GC."""
        if not self._closed:
            try:
                self.close()
            except Exception:
                pass

    def __repr__(self) -> str:
        status = "closed" if self._closed else ("locked" if self._mlocked else "unlocked")
        return f"<GuardedBuffer size={self._size} status={status}>"


def activate_memory_guard(
    warn_on_failure: bool = True,
    raise_mlock: bool = True,
    set_oom_protect: bool = False,
) -> Dict[str, bool]:
    """
    Activate all OS-level memory protections.

    Args:
        warn_on_failure: Emit warnings when protections fail.
        raise_mlock: Attempt to raise RLIMIT_MEMLOCK before mlockall.
        set_oom_protect: Set OOM score to prevent OOM kill (may need root).

    Returns:
        Dict mapping protection names to success status.

    Example:
        status = activate_memory_guard()
        if not status["mlockall"]:
            print("WARNING: Memory may be swapped to disk")

    Cross-platform:
        - Linux: mlockall, RLIMIT_CORE=0, PR_SET_DUMPABLE=0
        - macOS: mlockall, RLIMIT_CORE=0
        - Windows: SE_LOCK_MEMORY_PRIVILEGE, SetErrorMode
    """
    global _guard_status, _guard_activated

    status: Dict[str, bool] = {}

    if _system == "Windows":
        # Windows-specific protections
        # 1. Try to enable SE_LOCK_MEMORY_PRIVILEGE
        status["lock_memory_privilege"] = _windows_set_privilege()
        if not status["lock_memory_privilege"] and warn_on_failure:
            warnings.warn(
                "SE_LOCK_MEMORY_PRIVILEGE not available — VirtualLock may fail for large buffers. "
                "Run as Administrator or grant 'Lock pages in memory' policy.",
                MemoryGuardWarning,
                stacklevel=2,
            )

        # 2. Disable crash dialogs (partial core dump equivalent)
        status["no_coredump"] = _disable_core_dumps()

        # 3. mlockall equivalent: Windows doesn't have mlockall, VirtualLock is per-buffer
        # Mark as N/A — use virtual_lock_buffer() for individual buffers
        status["mlockall"] = False  # Not applicable on Windows
        status["windows_mode"] = True

    else:
        # Unix (Linux/macOS) protections
        libc = _get_libc()

        # 1. Raise mlock limit (must be before mlockall)
        if raise_mlock:
            status["mlock_limit_raised"] = raise_mlock_limit()

        # 2. mlockall — lock all memory pages
        status["mlockall"] = _activate_mlockall(libc)
        if not status["mlockall"] and warn_on_failure:
            warnings.warn(
                "mlockall() failed — key memory may be swapped to disk. "
                "Run with CAP_IPC_LOCK or increase RLIMIT_MEMLOCK.",
                MemoryGuardWarning,
                stacklevel=2,
            )

        # 3. Disable core dumps
        status["no_coredump"] = _disable_core_dumps()
        if not status["no_coredump"] and warn_on_failure:
            warnings.warn(
                "Failed to disable core dumps — crashes may leak key material.",
                MemoryGuardWarning,
                stacklevel=2,
            )

        # 4. Set non-dumpable (prevents ptrace, Linux only)
        if _system == "Linux":
            status["no_ptrace"] = _set_non_dumpable(libc)
            if not status["no_ptrace"] and warn_on_failure:
                warnings.warn(
                    "prctl(PR_SET_DUMPABLE, 0) failed — process may be ptrace-able.",
                    MemoryGuardWarning,
                    stacklevel=2,
                )

        # 5. OOM protection (optional, Linux only)
        if set_oom_protect and _system == "Linux":
            status["oom_protect"] = _set_oom_score()

    # Cache result
    _guard_status = status
    _guard_activated = True
    return status


def require_memory_guard(
    raise_mlock: bool = True,
    set_oom_protect: bool = False,
) -> Dict[str, bool]:
    """
    Fail-closed memory guard activation.

    Like activate_memory_guard(), but raises RuntimeError if any critical
    protection fails. Use this in high-security paths where continuing
    without memory protection is unacceptable.

    Critical protections (must ALL succeed):
        - mlockall (Unix) or SE_LOCK_MEMORY_PRIVILEGE + core dump disabling (Windows)
        - Core dump disabling (all platforms)
        - ptrace prevention (Linux only)

    Args:
        raise_mlock: Attempt to raise RLIMIT_MEMLOCK before mlockall.
        set_oom_protect: Set OOM score to prevent OOM kill (may need root).

    Returns:
        Dict mapping protection names to success status (all True).

    Raises:
        RuntimeError: If any critical protection fails.
    """
    status = activate_memory_guard(
        warn_on_failure=False,
        raise_mlock=raise_mlock,
        set_oom_protect=set_oom_protect,
    )

    # Determine which protections are critical for this platform
    failures = []

    if _system == "Windows":
        # On Windows, SE_LOCK_MEMORY_PRIVILEGE is required for VirtualLock
        # to succeed on large buffers.  Core dump suppression is also critical.
        # Both must succeed for the memory guard to be considered active.
        if not status.get("lock_memory_privilege", False):
            failures.append(
                "lock_memory_privilege (SE_LOCK_MEMORY_PRIVILEGE \u2014 required for VirtualLock)"
            )
        if not status.get("no_coredump", False):
            failures.append("core dump disabling")
    else:
        # Unix: mlockall and core dump disabling are critical
        if not status.get("mlockall", False):
            failures.append("mlockall (memory may be swapped to disk)")
        if not status.get("no_coredump", False):
            failures.append("core dump disabling")
        if _system == "Linux" and not status.get("no_ptrace", False):
            failures.append("ptrace prevention (PR_SET_DUMPABLE)")

    if failures:
        raise RuntimeError(
            f"Memory guard activation failed (fail-closed). "
            f"Failed protections: {', '.join(failures)}. "
            f"Run with CAP_IPC_LOCK or as root, or use activate_memory_guard() "
            f"for warn-only mode."
        )

    return status


def get_guard_status() -> Optional[Dict[str, bool]]:
    """
    Return the last activation status, or None if not yet activated.

    Returns:
        Dict of protection statuses, or None.
    """
    return _guard_status


def is_guard_active() -> bool:
    """Return True if activate_memory_guard() has been called."""
    return _guard_activated


def deactivate_memory_guard() -> Dict[str, bool]:
    """
    Reverse memory guard protections (for testing).

    WARNING: Do not use in production. This exists only for test cleanup.

    Returns:
        Dict mapping protection names to deactivation success.
    """
    global _guard_status, _guard_activated

    libc = _get_libc()
    status: Dict[str, bool] = {}

    # Unlock memory
    if libc is not None:
        try:
            result = libc.munlockall()
            status["munlockall"] = result == 0
        except (OSError, AttributeError):
            status["munlockall"] = False
    else:
        status["munlockall"] = False

    # Re-enable core dumps (for testing)
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        status["coredump_restored"] = True
    except (ValueError, resource.error, OSError):
        status["coredump_restored"] = False

    # Re-enable dumpable
    if platform.system() == "Linux" and libc is not None:
        try:
            PR_SET_DUMPABLE = 4
            libc.prctl(PR_SET_DUMPABLE, 1, 0, 0, 0)
            status["dumpable_restored"] = True
        except (OSError, AttributeError):
            status["dumpable_restored"] = False

    _guard_activated = False
    return status
