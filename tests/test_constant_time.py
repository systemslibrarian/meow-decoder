#!/usr/bin/env python3
"""
Tests for constant-time operations module.
"""

import ctypes
import pytest
import secrets

# Mark as security so Gate 5 (security-coverage) includes these tests
pytestmark = pytest.mark.security
import time

from meow_decoder.constant_time import (
    constant_time_compare,
    secure_zero_memory,
    secure_memory,
    timing_safe_equal_with_delay,
    equalize_timing,
    SecureBuffer,
)


class TestConstantTimeCompare:
    """Tests for constant_time_compare function."""

    def test_equal_bytes(self):
        """Test comparison of equal byte strings."""
        a = b"secret_password_123"
        b = b"secret_password_123"

        assert constant_time_compare(a, b) is True

    def test_unequal_bytes(self):
        """Test comparison of unequal byte strings."""
        a = b"secret_password_123"
        b = b"wrong_password_456"

        assert constant_time_compare(a, b) is False

    def test_different_lengths(self):
        """Test comparison of different length strings."""
        a = b"short"
        b = b"much_longer_string"

        assert constant_time_compare(a, b) is False

    def test_empty_strings(self):
        """Test comparison of empty strings."""
        assert constant_time_compare(b"", b"") is True

    def test_random_data(self):
        """Test comparison of random data."""
        data = secrets.token_bytes(32)

        assert constant_time_compare(data, data) is True
        assert constant_time_compare(data, secrets.token_bytes(32)) is False


class TestSecureZeroMemory:
    """Tests for secure_zero_memory function."""

    def test_zero_bytearray(self):
        """Test zeroing a bytearray."""
        buf = bytearray(b"sensitive data")
        secure_zero_memory(buf)

        assert buf == bytearray(len(buf))

    def test_zero_empty_buffer(self):
        """Test zeroing an empty buffer."""
        buf = bytearray()
        secure_zero_memory(buf)

        assert len(buf) == 0


class TestSecureMemoryContext:
    """Tests for secure_memory context manager."""

    def test_context_manager_basic(self):
        """Test basic context manager usage."""
        data = b"sensitive password"

        with secure_memory(data) as buf:
            assert bytes(buf) == data

    def test_context_manager_modification(self):
        """Test modifying data within context."""
        data = b"original data"

        with secure_memory(data) as buf:
            buf[0] = ord("X")
            assert buf[0] == ord("X")


class TestTimingSafeEqualWithDelay:
    """Tests for timing_safe_equal_with_delay function."""

    def test_equal_with_delay(self):
        """Test equal comparison with delay."""
        a = b"password123"
        b = b"password123"

        start = time.time()
        result = timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=5)
        elapsed = time.time() - start

        assert result is True
        assert elapsed >= 0.001

    def test_unequal_with_delay(self):
        """Test unequal comparison with delay."""
        a = b"password123"
        b = b"password456"

        result = timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=5)

        assert result is False


class TestEqualizeTiming:
    """Tests for equalize_timing function."""

    def test_equalize_fast_operation(self):
        """Test equalizing a fast operation."""
        start = time.time()
        time.sleep(0.01)
        elapsed = time.time() - start

        equalize_start = time.time()
        equalize_timing(elapsed, target_time=0.05)
        equalize_elapsed = time.time() - equalize_start

        assert equalize_elapsed >= 0.03

    def test_equalize_slow_operation(self):
        """Test equalizing when operation exceeds target."""
        equalize_timing(0.1, target_time=0.05)


class TestSecureBuffer:
    """Tests for SecureBuffer class."""

    def test_buffer_creation(self):
        """Test creating a secure buffer."""
        buf = SecureBuffer(32)

        assert buf.size == 32

    def test_buffer_write_read(self):
        """Test writing and reading from buffer."""
        buf = SecureBuffer(32)

        data = b"test data"
        buf.write(data)

        result = buf.read(len(data))
        assert result == data

    def test_buffer_write_with_offset(self):
        """Test writing with offset."""
        buf = SecureBuffer(32)

        buf.write(b"hello", offset=5)
        result = buf.read(5, offset=5)

        assert result == b"hello"

    def test_buffer_write_overflow(self):
        """Test that overflow raises error."""
        buf = SecureBuffer(10)

        with pytest.raises(ValueError):
            buf.write(b"this is too long for the buffer")

    def test_buffer_context_manager(self):
        """Test buffer as context manager."""
        with SecureBuffer(32) as buf:
            buf.write(b"sensitive")
            data = buf.read(9)
            assert data == b"sensitive"

    def test_buffer_deletion(self):
        """Test buffer cleanup on deletion."""
        buf = SecureBuffer(32)
        buf.write(b"secret")

        del buf


# =============================================================================
# _get_libc platform detection
# =============================================================================


class TestLibcLoading:
    def test_get_libc(self):
        from meow_decoder.constant_time import _get_libc

        libc = _get_libc()
        assert libc is None or hasattr(libc, "mlock")

    def test_platform_branches(self, monkeypatch):
        import meow_decoder.constant_time as ct

        monkeypatch.setattr(ct.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(ct.ctypes, "CDLL", lambda _name: object())
        assert ct._get_libc() is not None

        monkeypatch.setattr(ct.platform, "system", lambda: "Windows")
        monkeypatch.setattr(ct.ctypes, "CDLL", lambda _name: object())
        assert ct._get_libc() is not None

        monkeypatch.setattr(ct.platform, "system", lambda: "Plan9")
        assert ct._get_libc() is None

        monkeypatch.setattr(ct.platform, "system", lambda: "Darwin")

        def _boom(_name):
            raise OSError("nope")

        monkeypatch.setattr(ct.ctypes, "CDLL", _boom)
        assert ct._get_libc() is None

    def test_libc_module_variable(self):
        from meow_decoder import constant_time

        assert constant_time._libc is None or callable(getattr(constant_time._libc, "mlock", None))


# --- Merged from test_coverage_boost_extras.py ---


# =====================================================
# constant_time.py — push from 99.07% to 100%
# =====================================================
class TestConstantTimeExtras:
    """Extra constant_time tests."""

    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal values."""
        from meow_decoder.constant_time import constant_time_compare

        a = b"hello world test"
        b_val = b"hello world test"
        assert constant_time_compare(a, b_val) is True

    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison with different values."""
        from meow_decoder.constant_time import constant_time_compare

        a = b"hello world"
        b_val = b"hello world!"
        assert constant_time_compare(a, b_val) is False

    def test_secure_zero_memory_unsupported_type(self):
        """Test secure_zero_memory with unsupported type (hits else branch)."""
        from meow_decoder.constant_time import secure_zero_memory

        # Passing a type that's not bytearray or ctypes.Array
        # exercises the else: return branch
        buf = bytearray(b"\xff" * 16)
        mv = memoryview(buf)
        secure_zero_memory(mv)  # No-op for unsupported type
        # Just verify no crash — the memoryview type hits the fallback


# --- Merged from test_coverage_boost_remaining.py ---


# =====================================================
# constant_time.py small gaps
# =====================================================
class TestConstantTimeBoost:
    def test_secure_zero_memory_ctypes_array(self):
        """Test secure_zero_memory with ctypes.Array."""
        from meow_decoder.constant_time import secure_zero_memory

        buf = (ctypes.c_char * 32)()
        for i in range(32):
            buf[i] = bytes([0xFF])
        secure_zero_memory(buf)
        for i in range(32):
            assert buf[i] == b"\x00"

    def test_secure_zero_memory_bytearray(self):
        """Test secure_zero_memory with bytearray."""
        from meow_decoder.constant_time import secure_zero_memory

        buf = bytearray(b"\xff" * 32)
        secure_zero_memory(buf)
        assert buf == bytearray(32)


# =====================================================
# constant_time.py FULL BRANCH COVERAGE
# =====================================================
class TestConstantTimeFullBranchCoverage:
    """Tests to hit all branches in constant_time.py for 100% coverage."""

    def test_secure_zero_memory_libc_none_fallback(self, monkeypatch):
        """Test fallback zeroing when _libc is None (lines 83-86)."""
        import meow_decoder.constant_time as ct

        monkeypatch.setattr(ct, "_libc", None)

        buf = bytearray(b"\xff" * 16)
        ct.secure_zero_memory(buf)
        assert buf == bytearray(16)

    def test_secure_zero_memory_libc_none_non_bytearray(self, monkeypatch):
        """Test fallback with unsupported type when _libc is None."""
        import meow_decoder.constant_time as ct

        monkeypatch.setattr(ct, "_libc", None)

        # Pass a memoryview - hits else branch, returns without zeroing
        buf = bytearray(b"\xff" * 16)
        mv = memoryview(buf)
        ct.secure_zero_memory(mv)
        # memoryview not zeroed (unsupported in fallback too)
        assert buf == bytearray(b"\xff" * 16)

    def test_secure_zero_memory_empty_ctypes_array(self):
        """Test secure_zero_memory with empty ctypes.Array (lines 96-99)."""
        from meow_decoder.constant_time import secure_zero_memory

        empty_buf = (ctypes.c_char * 0)()
        secure_zero_memory(empty_buf)  # Should return early without error

    def test_secure_zero_memory_memset_exception_fallback(self, monkeypatch):
        """Test memset exception triggers manual fallback (lines 108-112)."""
        import meow_decoder.constant_time as ct

        # Make ctypes.memset raise an exception
        original_memset = ctypes.memset

        def mock_memset(*args, **kwargs):
            raise OSError("Mock memset failure")

        monkeypatch.setattr(ctypes, "memset", mock_memset)

        buf = bytearray(b"\xff" * 16)
        ct.secure_zero_memory(buf)
        assert buf == bytearray(16)  # Should still be zeroed via fallback

        monkeypatch.setattr(ctypes, "memset", original_memset)

    def test_secure_memory_mlock_success(self):
        """Test secure_memory context manager with mlock (lines 142-162)."""
        from meow_decoder.constant_time import secure_memory

        data = b"secret password"
        with secure_memory(data) as buf:
            assert bytes(buf) == data
        # After exiting, buf should be zeroed
        assert buf == bytearray(len(data))

    def test_secure_memory_mlock_failure(self, monkeypatch):
        """Test secure_memory when mlock fails."""
        import meow_decoder.constant_time as ct

        class MockLibc:
            def mlock(self, addr, size):
                return -1  # Simulate failure

            def munlock(self, addr, size):
                return 0

        monkeypatch.setattr(ct, "_libc", MockLibc())

        data = b"secret data"
        with ct.secure_memory(data) as buf:
            assert bytes(buf) == data
        assert buf == bytearray(len(data))

    def test_secure_memory_mlock_exception(self, monkeypatch):
        """Test secure_memory when mlock raises exception."""
        import meow_decoder.constant_time as ct

        class MockLibc:
            def mlock(self, addr, size):
                raise OSError("mlock failed")

            def munlock(self, addr, size):
                return 0

        monkeypatch.setattr(ct, "_libc", MockLibc())

        data = b"protected"
        with ct.secure_memory(data) as buf:
            assert bytes(buf) == data

    def test_secure_memory_munlock_exception(self, monkeypatch):
        """Test secure_memory when munlock raises exception (line 161-162)."""
        import meow_decoder.constant_time as ct

        class MockLibc:
            def mlock(self, addr, size):
                return 0  # Success

            def munlock(self, addr, size):
                raise OSError("munlock failed")

        monkeypatch.setattr(ct, "_libc", MockLibc())

        data = b"locked data"
        with ct.secure_memory(data) as buf:
            assert bytes(buf) == data
        # Should complete without raising despite munlock failure

    def test_secure_buffer_mlock_success(self):
        """Test SecureBuffer with successful mlock (lines 241-247)."""
        from meow_decoder.constant_time import SecureBuffer

        buf = SecureBuffer(64)
        buf.write(b"test data")
        data = buf.read(9)
        assert data == b"test data"
        del buf  # Should trigger cleanup

    def test_secure_buffer_mlock_failure(self, monkeypatch):
        """Test SecureBuffer when mlock fails."""
        import meow_decoder.constant_time as ct

        class MockLibc:
            def mlock(self, addr, size):
                return -1  # Failure

            def munlock(self, addr, size):
                return 0

        monkeypatch.setattr(ct, "_libc", MockLibc())

        buf = ct.SecureBuffer(32)
        assert buf.locked is False
        buf.write(b"data")
        del buf

    def test_secure_buffer_mlock_exception(self, monkeypatch):
        """Test SecureBuffer when mlock raises exception."""
        import meow_decoder.constant_time as ct

        class MockLibc:
            def mlock(self, addr, size):
                raise OSError("mlock fail")

            def munlock(self, addr, size):
                return 0

        monkeypatch.setattr(ct, "_libc", MockLibc())

        buf = ct.SecureBuffer(32)
        assert buf.locked is False

    def test_secure_buffer_munlock_exception_on_del(self, monkeypatch):
        """Test SecureBuffer cleanup when munlock raises (lines 266-271)."""
        import meow_decoder.constant_time as ct

        class MockLibc:
            def mlock(self, addr, size):
                return 0  # Success

            def munlock(self, addr, size):
                raise OSError("munlock failed")

        monkeypatch.setattr(ct, "_libc", MockLibc())

        buf = ct.SecureBuffer(32)
        buf.write(b"secret")
        # Force locked=True for this test path
        buf.locked = True
        del buf  # Should not raise despite munlock failure

    def test_secure_buffer_libc_none_on_del(self, monkeypatch):
        """Test SecureBuffer cleanup when _libc is None."""
        import meow_decoder.constant_time as ct

        # First create buffer with real _libc
        buf = ct.SecureBuffer(32)
        buf.write(b"data")
        buf.locked = True

        # Then set _libc to None before deletion
        monkeypatch.setattr(ct, "_libc", None)
        del buf  # Should handle gracefully

    def test_secure_buffer_read_full(self):
        """Test SecureBuffer read with no length specified (line 257-258)."""
        from meow_decoder.constant_time import SecureBuffer

        buf = SecureBuffer(32)
        buf.write(b"hello world")
        # Read from offset without length
        data = buf.read(offset=6)
        assert data.startswith(b"world")

    def test_secure_zero_memory_memset_exception_ctypes_array(self, monkeypatch):
        """Test memset exception with ctypes.Array (110->exit branch)."""
        import meow_decoder.constant_time as ct

        def mock_memset(*args, **kwargs):
            raise OSError("Mock memset failure")

        monkeypatch.setattr(ctypes, "memset", mock_memset)

        # Use ctypes.Array - when memset fails, the fallback only zeros bytearrays,
        # so this hits the 110->exit (no-op for non-bytearray in exception path)
        buf = (ctypes.c_char * 16)()
        for i in range(16):
            buf[i] = b"\xff"
        ct.secure_zero_memory(buf)
        # Buffer may not be zeroed since fallback skips ctypes.Array

    def test_secure_memory_libc_none(self, monkeypatch):
        """Test secure_memory when _libc is None (142->150 path)."""
        import meow_decoder.constant_time as ct

        monkeypatch.setattr(ct, "_libc", None)

        data = b"test data"
        with ct.secure_memory(data) as buf:
            assert bytes(buf) == data
        # locked is False, so munlock is never attempted
        assert buf == bytearray(len(data))

    def test_secure_buffer_libc_none_creation(self, monkeypatch):
        """Test SecureBuffer creation when _libc is None (241->exit)."""
        import meow_decoder.constant_time as ct

        monkeypatch.setattr(ct, "_libc", None)

        buf = ct.SecureBuffer(32)
        assert buf.locked is False
        buf.write(b"test")
        del buf  # Should cleanup without trying mlock/munlock

    def test_secure_buffer_locked_false_del(self, monkeypatch):
        """Test SecureBuffer __del__ when locked=False (263->exit)."""
        import meow_decoder.constant_time as ct

        class MockLibc:
            def mlock(self, addr, size):
                return -1  # Fail so locked stays False

            def munlock(self, addr, size):
                raise AssertionError("munlock should not be called")

        monkeypatch.setattr(ct, "_libc", MockLibc())

        buf = ct.SecureBuffer(32)
        assert buf.locked is False
        buf.write(b"test")
        # This should NOT call munlock because locked=False
        del buf

    def test_secure_buffer_locked_true_libc_none_del(self, monkeypatch):
        """Test SecureBuffer __del__ when locked=True but _libc is None (263->exit)."""
        import meow_decoder.constant_time as ct

        # Create with real _libc
        buf = ct.SecureBuffer(32)
        buf.write(b"test")
        buf.locked = True  # Force locked even if mlock didn't succeed

        # Now set _libc to None
        monkeypatch.setattr(ct, "_libc", None)
        # Should not try to call munlock since _libc is None
        del buf


# =====================================================
# crypto_enhanced.py small gaps
# =====================================================
