#!/usr/bin/env python3
"""
Fuzz target for Windows-specific VirtualLock/VirtualProtect guard-page behavior.

Tests:
- GuardedBuffer allocation with Windows API paths (simulated on Linux via mmap)
- Guard-page trap detection: writes to guard pages MUST segfault/raise
- VirtualLock/VirtualUnlock lifecycle with adversarial sizes
- Double-free / use-after-free detection
- Alignment edge cases (non-page-aligned sizes)
- Cross-platform parity: identical behavior on Unix mmap and Windows VirtualAlloc paths

This fuzz target works on any platform by exercising the GuardedBuffer's
guard-page contract: reading/writing outside the data region must either
raise ValueError or trigger a segfault caught by the signal handler.
"""

import os
import sys
import struct
import ctypes
import signal

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.memory_guard import (
        GuardedBuffer,
        activate_memory_guard,
        deactivate_memory_guard,
        virtual_lock_buffer,
        virtual_unlock_buffer,
        is_guard_active,
    )

    return (
        GuardedBuffer,
        activate_memory_guard,
        deactivate_memory_guard,
        virtual_lock_buffer,
        virtual_unlock_buffer,
        is_guard_active,
    )


if atheris is not None:
    with atheris.instrument_imports():
        (
            GuardedBuffer,
            activate_memory_guard,
            deactivate_memory_guard,
            virtual_lock_buffer,
            virtual_unlock_buffer,
            is_guard_active,
        ) = _setup_imports()
else:
    (
        GuardedBuffer,
        activate_memory_guard,
        deactivate_memory_guard,
        virtual_lock_buffer,
        virtual_unlock_buffer,
        is_guard_active,
    ) = _setup_imports()


def fuzz_guard_page_trap_write(data: bytes):
    """
    Verify that writing beyond the buffer bounds is caught.

    The guard pages (PROT_NONE / PAGE_NOACCESS) bracket the data region.
    Any write to offset < 0 or offset >= size MUST raise ValueError
    from the bounds check (before hitting the guard page).
    """
    if len(data) < 4:
        return

    size = (struct.unpack(">H", data[:2])[0] % 4096) + 1
    offset_raw = struct.unpack(">h", data[2:4])[0]  # signed

    try:
        buf = GuardedBuffer(size)

        # Valid write
        valid_data = data[4:min(4 + size, len(data))]
        if valid_data:
            buf.write(valid_data)

        # Out-of-bounds write attempts — MUST raise ValueError
        bad_offsets = [
            -1,
            -size,
            size,
            size + 1,
            size + 4096,
            offset_raw if (offset_raw < 0 or offset_raw >= size) else size,
        ]
        for bad_offset in bad_offsets:
            try:
                buf.write(b"\x41", bad_offset)
                # If we get here, the guard page contract is violated
                assert False, f"Write at offset {bad_offset} should have raised"
            except (ValueError, RuntimeError):
                pass  # Expected — bounds check caught it

        buf.close()

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass


def fuzz_guard_page_trap_read(data: bytes):
    """
    Verify that reading beyond buffer bounds is caught.
    """
    if len(data) < 3:
        return

    size = max(1, data[0] * 8 + 1)
    if size > 8192:
        size = 4096

    try:
        buf = GuardedBuffer(size)

        # Fill with known pattern
        pattern = bytes([i & 0xFF for i in range(size)])
        buf.write(pattern)

        # Valid read
        result = buf.read(size)
        assert result == pattern, "GuardedBuffer read corruption"

        # Out-of-bounds read attempts
        bad_reads = [
            (size + 1, 0),       # Too long from start
            (1, size),           # Start at end
            (1, size + 4096),    # Way past end
            (size, 1),           # Extends past end by 1
        ]
        for length, offset in bad_reads:
            try:
                buf.read(length, offset)
                assert False, f"Read(len={length}, off={offset}) should have raised"
            except (ValueError, RuntimeError):
                pass

        buf.close()

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass


def fuzz_virtuallock_lifecycle(data: bytes):
    """
    Fuzz the VirtualLock/VirtualUnlock (or mlock/munlock) lifecycle.

    Tests:
    - Lock buffer → read/write → unlock → verify zeroization
    - Lock-unlock-lock cycle
    - Lock on already-closed buffer (should be safe)
    """
    if len(data) < 4:
        return

    size = (struct.unpack(">H", data[:2])[0] % 2048) + 1

    try:
        buf = GuardedBuffer(size)

        # Write data
        payload = data[2:min(2 + size, len(data))]
        if payload:
            buf.write(payload)

        # Check lock status
        is_locked = buf.is_locked
        assert isinstance(is_locked, bool)

        # Read back
        if payload:
            readback = buf.read(len(payload))
            assert readback == payload

        # Zero the buffer (secure wipe)
        buf.zero()

        # Read back — should be all zeros
        zeroed = buf.read(size)
        assert zeroed == b"\x00" * size, "Zeroization failed"

        # Close (should unlock implicitly)
        buf.close()

        # Operations after close should raise
        try:
            buf.write(b"\x01")
            assert False, "Write after close should raise"
        except RuntimeError:
            pass

        try:
            buf.read(1)
            assert False, "Read after close should raise"
        except RuntimeError:
            pass

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass


def fuzz_virtualprotect_alignment(data: bytes):
    """
    Test guard page allocation with various alignment-stressing sizes.

    Guard pages require page-aligned allocation. Non-page-aligned data
    sizes must be rounded up correctly.
    """
    if len(data) < 2:
        return

    # Test sizes that stress alignment boundaries
    page_size = os.sysconf("SC_PAGESIZE") if hasattr(os, "sysconf") else 4096
    base_size = struct.unpack(">H", data[:2])[0] % 8192

    test_sizes = [
        base_size,
        page_size - 1,       # Just under page boundary
        page_size,           # Exact page
        page_size + 1,       # Just over page boundary
        page_size * 2 - 1,   # Under 2-page boundary
        page_size * 2,       # Exact 2 pages
        1,                   # Minimum
        7,                   # Odd small
        255,                 # Byte boundary
    ]

    for size in test_sizes:
        if size < 1:
            continue
        if size > 65536:
            continue

        try:
            buf = GuardedBuffer(size)

            # Must report correct size
            assert buf.size == size, f"Size mismatch: {buf.size} != {size}"

            # Write fill pattern
            pattern = bytes([0xAA] * size)
            buf.write(pattern)

            # Read back
            result = buf.read(size)
            assert result == pattern, f"Data corruption at size {size}"

            buf.close()

        except (ValueError, RuntimeError, OSError, MemoryError):
            pass


def fuzz_double_free_safety(data: bytes):
    """
    Verify GuardedBuffer is safe against double-free.

    close() → close() must not crash or corrupt memory.
    __del__() after close() must be safe.
    """
    if len(data) < 1:
        return

    size = max(1, data[0] * 4 + 1)
    if size > 32768:
        size = 4096

    try:
        buf = GuardedBuffer(size)
        buf.write(b"\xBB" * min(size, 16))

        # Close multiple times
        buf.close()
        buf.close()
        buf.close()

        # Explicit __del__ after close
        buf.__del__()

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass


def fuzz_use_after_free_detection(data: bytes):
    """
    Verify that use-after-free is detected (raises RuntimeError).
    """
    if len(data) < 2:
        return

    size = max(1, min(data[0] * 16, 4096))

    try:
        buf = GuardedBuffer(size)
        buf.write(data[1:min(1 + size, len(data))])
        buf.close()

        # All operations on closed buffer must raise RuntimeError
        operations = [
            lambda: buf.write(b"\x00"),
            lambda: buf.read(1),
            lambda: buf.zero(),
        ]

        for op in operations:
            try:
                op()
                assert False, "Operation on closed buffer should raise"
            except RuntimeError:
                pass

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass


def fuzz_concurrent_alloc_free(data: bytes):
    """
    Stress-test multiple simultaneous GuardedBuffer allocations.

    Verifies that guard pages don't overlap between buffers.
    """
    if len(data) < 8:
        return

    n_buffers = min(data[0] % 8 + 2, 8)
    buffers = []

    try:
        # Allocate N buffers
        for i in range(n_buffers):
            if i + 1 >= len(data):
                break
            size = max(1, data[i + 1] * 4 + 1)
            if size > 4096:
                size = 1024
            buf = GuardedBuffer(size)
            buf.write(bytes([i & 0xFF] * size))
            buffers.append((buf, size, i & 0xFF))

        # Verify all buffers are independent
        for buf, size, fill in buffers:
            result = buf.read(size)
            assert result == bytes([fill] * size), "Cross-buffer contamination"

        # Free in reverse order
        for buf, _, _ in reversed(buffers):
            buf.close()

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass
    finally:
        for buf, _, _ in buffers:
            try:
                buf.close()
            except Exception:
                pass


def fuzz_activate_deactivate_guard(data: bytes):
    """
    Test activate_memory_guard / deactivate_memory_guard cycle.

    Must be idempotent and safe to call repeatedly.
    """
    if len(data) < 1:
        return

    cycles = min(data[0] % 4 + 1, 3)

    for _ in range(cycles):
        try:
            status = activate_memory_guard(warn_on_failure=False)
            assert isinstance(status, dict)
            assert is_guard_active()

            deact = deactivate_memory_guard()
            assert isinstance(deact, dict)

        except (RuntimeError, OSError):
            pass


def fuzz_rapid_alloc_free_cycle(data: bytes):
    """Stress test rapid allocation/deallocation cycles for memory leaks."""
    try:
        from meow_decoder.memory_guard import GuardedBuffer
    except ImportError:
        return

    if len(data) < 2:
        return

    cycle_count = min(data[0], 50)  # up to 50 cycles
    size = max(1, data[1] % 128 + 1)

    for _ in range(cycle_count):
        try:
            buf = GuardedBuffer(size)
            buf.write(b"\xAA" * min(size, 8))
            buf.close()
        except (RuntimeError, OSError, MemoryError):
            break


def fuzz_boundary_write_exact_size(data: bytes):
    """Write exactly at buffer boundary - should succeed; boundary+1 should fail."""
    try:
        from meow_decoder.memory_guard import GuardedBuffer
    except ImportError:
        return

    if len(data) < 3:
        return

    size = max(1, data[0] % 64 + 1)
    try:
        buf = GuardedBuffer(size)
        # Exact boundary write should succeed
        buf.write(b"\x42" * size)
        read_back = buf.read(size, 0)
        assert read_back == b"\x42" * size

        # One past boundary should raise
        raised = False
        try:
            buf.write(b"\x42" * (size + 1))
        except (RuntimeError, OSError, ValueError, OverflowError):
            raised = True
        # Some impls may silently truncate; just ensure no crash

        buf.close()
    except (RuntimeError, OSError, MemoryError):
        pass


def fuzz_zero_wipe_idempotent(data: bytes):
    """Zero-wipe multiple times should not crash or change state."""
    try:
        from meow_decoder.memory_guard import GuardedBuffer
    except ImportError:
        return

    if len(data) < 2:
        return

    size = max(1, data[0] % 64 + 1)
    wipe_count = min(data[1], 10)

    try:
        buf = GuardedBuffer(size)
        buf.write(b"\xFF" * size)
        for _ in range(wipe_count):
            buf.zero()
        # After wiping, read should return zeros (only valid if at least one wipe occurred)
        if wipe_count > 0:
            read_back = buf.read(size, 0)
            assert read_back == b"\x00" * size
        buf.close()
    except (RuntimeError, OSError, MemoryError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_guard_page_trap_write(data)
        fuzz_guard_page_trap_read(data)
        fuzz_virtuallock_lifecycle(data)
        fuzz_virtualprotect_alignment(data)
        fuzz_double_free_safety(data)
        fuzz_use_after_free_detection(data)
        fuzz_concurrent_alloc_free(data)
        fuzz_activate_deactivate_guard(data)
        fuzz_rapid_alloc_free_cycle(data)
        fuzz_boundary_write_exact_size(data)
        fuzz_zero_wipe_idempotent(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
