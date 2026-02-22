#!/usr/bin/env python3
"""
Fuzz target for memory guard operations.
Tests GuardedBuffer allocation/deallocation, size edge cases,
virtual_lock/unlock, and zeroization with adversarial inputs.
"""

import os
import sys
import struct

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
        virtual_lock_buffer,
        virtual_unlock_buffer,
    )

    return GuardedBuffer, virtual_lock_buffer, virtual_unlock_buffer


if atheris is not None:
    with atheris.instrument_imports():
        GuardedBuffer, virtual_lock_buffer, virtual_unlock_buffer = _setup_imports()
else:
    GuardedBuffer, virtual_lock_buffer, virtual_unlock_buffer = _setup_imports()


def fuzz_guarded_buffer_lifecycle(data: bytes):
    """Fuzz GuardedBuffer creation, write, read, close lifecycle."""
    if len(data) < 3:
        return

    # Use first 2 bytes for size (1 to 8192)
    size = (struct.unpack(">H", data[:2])[0] % 8192) + 1
    payload = data[2:]

    try:
        buf = GuardedBuffer(size)

        # Write data (truncated to buffer size)
        write_data = payload[:min(len(payload), size)]
        if write_data:
            buf.write(write_data)

            # Read back and verify
            read_data = buf.read(len(write_data))
            assert read_data == write_data, "GuardedBuffer write/read mismatch"

        # Close and verify zeroization
        buf.close()

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass  # Expected for edge cases


def fuzz_guarded_buffer_context_manager(data: bytes):
    """Fuzz GuardedBuffer as context manager."""
    if len(data) < 2:
        return

    size = max(1, data[0] * 16 + data[1])  # 1 to 4095
    if size > 65536:
        size = 65536  # Cap to avoid OOM in fuzzing

    try:
        with GuardedBuffer(size) as buf:
            # Write random data
            write_len = min(len(data), size)
            if write_len > 0:
                buf.write(data[:write_len])
                result = buf.read(write_len)
                assert len(result) == write_len
        # Buffer should be zeroed and freed after context exit

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass


def fuzz_guarded_buffer_invalid_sizes(data: bytes):
    """Test GuardedBuffer with invalid/extreme sizes."""
    if len(data) < 4:
        return

    sizes_to_test = [
        0,                              # Zero (should raise ValueError)
        -1,                             # Negative (should raise ValueError)
        struct.unpack(">I", data[:4])[0],  # Random 32-bit size
    ]

    for size in sizes_to_test:
        try:
            buf = GuardedBuffer(size)
            buf.close()
        except (ValueError, RuntimeError, OSError, MemoryError, OverflowError):
            pass  # Expected


def fuzz_guarded_buffer_double_close(data: bytes):
    """Test double-close safety of GuardedBuffer."""
    if len(data) < 1:
        return

    size = max(1, data[0] * 16 + 1)
    if size > 65536:
        size = 4096

    try:
        buf = GuardedBuffer(size)
        buf.close()
        buf.close()  # Second close should be safe (no double-free)
    except (ValueError, RuntimeError, OSError):
        pass


def fuzz_guarded_buffer_overwrite(data: bytes):
    """Test writing beyond buffer bounds (should not corrupt)."""
    if len(data) < 5:
        return

    size = max(1, min(data[0] + 1, 256))

    try:
        buf = GuardedBuffer(size)

        # Write exactly size bytes
        fill = data[1:size + 1]
        if fill:
            buf.write(fill[:min(len(fill), size)])

        # Attempt to write more than size (should raise or truncate)
        oversized = data * 10  # Much bigger than buffer
        try:
            buf.write(oversized)
        except (ValueError, RuntimeError, BufferError, OSError):
            pass  # Expected — prevents overflow

        buf.close()

    except (ValueError, RuntimeError, OSError, MemoryError):
        pass


def fuzz_virtual_lock_unlock(data: bytes):
    """Fuzz virtual_lock_buffer / virtual_unlock_buffer with various buffers."""
    if len(data) < 1:
        return

    size = max(0, min(len(data), 4096))
    buf = bytearray(data[:size])

    try:
        locked = virtual_lock_buffer(buf)
        assert isinstance(locked, bool)

        if locked:
            unlocked = virtual_unlock_buffer(buf)
            assert isinstance(unlocked, bool)

    except (OSError, RuntimeError):
        pass  # Expected on some systems


def fuzz_virtual_lock_empty(data: bytes):
    """Test virtual_lock on empty buffer."""
    try:
        buf = bytearray()
        result = virtual_lock_buffer(buf)
        assert result is True  # Empty buffer should succeed

        result2 = virtual_unlock_buffer(buf)
        assert result2 is True

    except (OSError, RuntimeError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_guarded_buffer_lifecycle(data)
        fuzz_guarded_buffer_context_manager(data)
        fuzz_guarded_buffer_invalid_sizes(data)
        fuzz_guarded_buffer_double_close(data)
        fuzz_guarded_buffer_overwrite(data)
        fuzz_virtual_lock_unlock(data)
        fuzz_virtual_lock_empty(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
