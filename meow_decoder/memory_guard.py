"""
Process-Wide Memory Hardening Guard

Activates OS-level protections to prevent sensitive data from leaking
through swap files, core dumps, or ptrace attachment.

Protections applied:
1. mlockall(MCL_CURRENT | MCL_FUTURE) — lock all pages in RAM
2. RLIMIT_CORE → 0 — prevent core dump generation
3. prctl(PR_SET_DUMPABLE, 0) — prevent ptrace attachment (Linux)
4. RLIMIT_MEMLOCK raise — attempt to increase mlock limit

Usage:
    from meow_decoder.memory_guard import activate_memory_guard

    status = activate_memory_guard()
    # status = {"mlockall": True, "no_coredump": True, "no_ptrace": True, ...}

WARNING:
    - mlockall may fail if RLIMIT_MEMLOCK is too low (default 64KB on many distros)
    - Requires root or CAP_IPC_LOCK for mlockall with MCL_FUTURE
    - These are best-effort — a root attacker can override all protections
    - Call as early as possible in the process lifecycle

Security Properties:
    - Prevents key material from being written to swap
    - Prevents core dumps from containing key material
    - Prevents debugger attachment (non-root)
    - Does NOT protect against root-level attacks or cold-boot attacks
"""

import ctypes
import os
import platform
import resource
import warnings
from typing import Dict, Optional

__all__ = [
    "activate_memory_guard",
    "get_guard_status",
    "raise_mlock_limit",
    "MemoryGuardWarning",
]


class MemoryGuardWarning(UserWarning):
    """Warning issued when a memory guard protection cannot be activated."""
    pass


# Module-level state
_guard_status: Optional[Dict[str, bool]] = None
_guard_activated: bool = False


def _get_libc():
    """Load platform-specific libc."""
    system = platform.system()
    try:
        if system == "Linux":
            return ctypes.CDLL("libc.so.6", use_errno=True)
        elif system == "Darwin":
            return ctypes.CDLL("libc.dylib", use_errno=True)
        else:
            return None
    except OSError:
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
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        if soft >= target_bytes:
            return True
        new_soft = min(target_bytes, hard)
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (new_soft, hard))
        return new_soft >= target_bytes
    except (ValueError, resource.error, OSError):
        return False


def _activate_mlockall(libc) -> bool:
    """Lock all current and future memory pages in RAM."""
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
    """Set RLIMIT_CORE to 0 to prevent core dump generation."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except (ValueError, resource.error, OSError):
        return False


def _set_non_dumpable(libc) -> bool:
    """Set PR_SET_DUMPABLE to 0 to prevent ptrace attachment (Linux only)."""
    if platform.system() != "Linux" or libc is None:
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

    A score of -1000 means "never kill this process" (requires root).
    A score of -500 means "try hard not to kill" (may work without root).
    """
    try:
        oom_path = f"/proc/{os.getpid()}/oom_score_adj"
        with open(oom_path, "w") as f:
            f.write(str(score))
        return True
    except (OSError, PermissionError):
        # Try less aggressive score
        if score == -1000:
            return _set_oom_score(-500)
        return False


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
    """
    global _guard_status, _guard_activated

    libc = _get_libc()
    status: Dict[str, bool] = {}

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
    if platform.system() == "Linux":
        status["no_ptrace"] = _set_non_dumpable(libc)
        if not status["no_ptrace"] and warn_on_failure:
            warnings.warn(
                "prctl(PR_SET_DUMPABLE, 0) failed — process may be ptrace-able.",
                MemoryGuardWarning,
                stacklevel=2,
            )

    # 5. OOM protection (optional)
    if set_oom_protect:
        status["oom_protect"] = _set_oom_score()

    # Cache result
    _guard_status = status
    _guard_activated = True
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
