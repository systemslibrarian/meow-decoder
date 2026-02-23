"""
Tests for MADV_DONTDUMP integration in constant_time module.

Verifies that SecureBuffer and secure_memory apply MADV_DONTDUMP
to exclude sensitive memory from core dumps.
"""

import platform

import pytest

from meow_decoder.constant_time import (
    SecureBuffer,
    _set_dontdump,
    secure_memory,
    secure_zero_memory,
)


class TestSetDontdump:
    """Test the _set_dontdump helper."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only")
    def test_returns_bool(self):
        """_set_dontdump should return a boolean."""
        buf = bytearray(4096)
        import ctypes

        addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
        result = _set_dontdump(addr, len(buf))
        assert isinstance(result, bool)

    @pytest.mark.skipif(platform.system() == "Linux", reason="Non-Linux test")
    def test_non_linux_returns_false(self):
        """Non-Linux systems should return False."""
        result = _set_dontdump(0, 100)
        assert result is False


class TestSecureBufferDontdump:
    """Test MADV_DONTDUMP integration in SecureBuffer."""

    def test_dontdump_attribute_exists(self):
        """SecureBuffer should have a dontdump attribute."""
        buf = SecureBuffer(1024)
        assert hasattr(buf, "dontdump")
        assert isinstance(buf.dontdump, bool)

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only")
    def test_dontdump_set_when_locked(self):
        """On Linux, dontdump should be set when buffer is mlocked."""
        buf = SecureBuffer(4096)
        # If mlock succeeded, dontdump should also succeed
        if buf.locked:
            assert buf.dontdump is True

    def test_buffer_still_functional_with_dontdump(self):
        """Buffer read/write should work normally with dontdump set."""
        with SecureBuffer(256) as buf:
            data = b"test data for dontdump"
            buf.write(data)
            read = buf.read(len(data))
            assert read == data


class TestSecureMemoryDontdump:
    """Test MADV_DONTDUMP in secure_memory context manager."""

    def test_secure_memory_still_yields_data(self):
        """secure_memory should still yield correct data."""
        data = b"sensitive password"
        with secure_memory(data) as buf:
            assert bytes(buf) == data

    def test_secure_memory_zeros_on_exit(self):
        """Buffer should be zeroed after context exit."""
        data = b"sensitive"
        with secure_memory(data) as buf:
            pass
        # After exit, buffer should be all zeros
        assert all(b == 0 for b in buf)
