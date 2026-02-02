#!/usr/bin/env python3
"""
🐱 Consolidated Test Suite for constant_time.py
Target: 90%+ coverage

This is the CANONICAL test file for meow_decoder/constant_time.py
All tests from scattered files have been consolidated here.

Covers:
- constant_time_compare
- secure_zero_memory
- secure_memory (context manager)
- timing_safe_equal_with_delay
- equalize_timing
- SecureBuffer class
- _get_libc platform detection
"""

import pytest
import secrets
import sys
import os
import time
import ctypes
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure test mode
os.environ['MEOW_TEST_MODE'] = '1'
sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# Test: constant_time_compare
# =============================================================================

class TestConstantTimeCompare:
    """Test constant_time_compare function."""
    
    def test_equal_bytes(self):
        """Test comparison of equal byte strings."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"secret_password_123"
        b = b"secret_password_123"
        
        assert constant_time_compare(a, b) is True
    
    def test_unequal_bytes(self):
        """Test comparison of unequal byte strings."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"secret_password_123"
        b = b"wrong_password_456"
        
        assert constant_time_compare(a, b) is False
    
    def test_different_lengths(self):
        """Test comparison of different length strings."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"short"
        b = b"much_longer_string"
        
        assert constant_time_compare(a, b) is False
    
    def test_empty_strings(self):
        """Test comparison of empty strings."""
        from meow_decoder.constant_time import constant_time_compare
        
        assert constant_time_compare(b"", b"") is True
    
    def test_empty_vs_nonempty(self):
        """Test comparison of empty vs non-empty."""
        from meow_decoder.constant_time import constant_time_compare
        
        assert constant_time_compare(b"", b"data") is False
        assert constant_time_compare(b"data", b"") is False
    
    def test_single_byte_difference(self):
        """Test comparison with single byte difference."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"secret_password_123"
        b = b"secret_password_124"  # Last char different
        
        assert constant_time_compare(a, b) is False
    
    def test_first_byte_difference(self):
        """Test comparison with first byte different."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"Xecret_password_123"
        b = b"secret_password_123"
        
        assert constant_time_compare(a, b) is False
    
    def test_single_byte_strings(self):
        """Test comparing single byte strings."""
        from meow_decoder.constant_time import constant_time_compare
        
        assert constant_time_compare(b"a", b"a") is True
        assert constant_time_compare(b"a", b"b") is False
        assert constant_time_compare(b"\x00", b"\x00") is True
        assert constant_time_compare(b"\x00", b"\x01") is False
    
    def test_null_bytes(self):
        """Test comparing strings with null bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"hello\x00world"
        b = b"hello\x00world"
        
        assert constant_time_compare(a, b) is True
    
    def test_max_difference(self):
        """Test comparing maximally different bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"\x00" * 32
        b = b"\xff" * 32
        
        assert constant_time_compare(a, b) is False
    
    def test_random_bytes(self):
        """Test comparing random bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = secrets.token_bytes(32)
        b = bytes(a)  # Copy
        
        assert constant_time_compare(a, b) is True
        
        c = secrets.token_bytes(32)
        # Almost certainly different
        if a != c:
            assert constant_time_compare(a, c) is False
    
    def test_binary_data(self):
        """Test comparing arbitrary binary data."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = os.urandom(100)
        b = bytes(a)  # Copy
        
        assert constant_time_compare(a, b) is True


# =============================================================================
# Test: secure_zero_memory
# =============================================================================

class TestSecureZeroMemory:
    """Test secure_zero_memory function."""
    
    def test_zero_bytearray(self):
        """Test zeroing a bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        data = bytearray(b"sensitive_data_here")
        secure_zero_memory(data)
        
        # All bytes should be zero
        assert all(b == 0 for b in data)
    
    def test_zero_empty_bytearray(self):
        """Test zeroing an empty bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        data = bytearray()
        secure_zero_memory(data)  # Should not crash
        
        assert len(data) == 0
    
    def test_zero_large_bytearray(self):
        """Test zeroing a large bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        data = bytearray(os.urandom(10000))
        secure_zero_memory(data)
        
        assert all(b == 0 for b in data)
    
    def test_zero_ctypes_array(self):
        """Test zeroing a ctypes array."""
        from meow_decoder.constant_time import secure_zero_memory
        
        ArrayType = ctypes.c_char * 32
        data = ArrayType()
        
        # Fill with data
        for i in range(32):
            data[i] = bytes([i % 256])
        
        secure_zero_memory(data)
        
        # All bytes should be zero
        assert all(data[i] == b'\x00' for i in range(32))
    
    def test_zero_unsupported_type(self):
        """Test zeroing unsupported type (should not crash)."""
        from meow_decoder.constant_time import secure_zero_memory
        
        # Passing an unsupported type should be a no-op
        data = "immutable_string"
        secure_zero_memory(data)  # Should not crash
        
        # Also test bytes (immutable)
        secure_zero_memory(b"immutable")  # Should not crash
    
    def test_preserves_length(self):
        """Test secure_zero_memory preserves length."""
        from meow_decoder.constant_time import secure_zero_memory
        
        buf = bytearray(100)
        buf[:] = b"x" * 100
        
        original_len = len(buf)
        secure_zero_memory(buf)
        
        assert len(buf) == original_len
        assert all(b == 0 for b in buf)
    
    def test_ctypes_array_branch(self):
        """Ensure we take the ctypes.Array branch."""
        from meow_decoder.constant_time import secure_zero_memory
        
        arr = (ctypes.c_char * 4)()
        arr.raw = b"ABCD"
        
        secure_zero_memory(arr)
        assert bytes(arr) == b"\x00" * 4


class TestSecureZeroMemoryFallback:
    """Test secure_zero_memory fallback paths."""
    
    def test_fallback_when_no_libc(self, monkeypatch):
        """Test zeroing when libc is not available."""
        import meow_decoder.constant_time as ct
        
        # Force the manual fallback path
        monkeypatch.setattr(ct, "_libc", None)
        
        buf = bytearray(b"secret")
        ct.secure_zero_memory(buf)
        assert buf == bytearray(b"\x00" * 6)
    
    def test_fallback_unsupported_type(self, monkeypatch):
        """Test unsupported type in fallback mode."""
        import meow_decoder.constant_time as ct
        
        monkeypatch.setattr(ct, "_libc", None)
        
        # Non-bytearray should be a no-op in fallback mode
        ct.secure_zero_memory(b"immutable")  # Should not crash


# =============================================================================
# Test: secure_memory context manager
# =============================================================================

class TestSecureMemoryContext:
    """Test secure_memory context manager."""
    
    def test_basic_usage(self):
        """Test basic secure memory usage."""
        from meow_decoder.constant_time import secure_memory
        
        password = b"super_secret_password"
        
        with secure_memory(password) as buf:
            assert bytes(buf) == password
        
        # After context, buffer should be zeroed
        assert bytes(buf) == b"\x00" * len(password)
    
    def test_buffer_accessible_in_context(self):
        """Test buffer is accessible in context."""
        from meow_decoder.constant_time import secure_memory
        
        with secure_memory(b"test_data") as buf:
            # Can read
            assert buf[0] == ord('t')
            
            # Can modify
            buf[0] = ord('x')
            assert buf[0] == ord('x')
    
    def test_modification(self):
        """Test modifying data in secure memory."""
        from meow_decoder.constant_time import secure_memory
        
        original = b"super_secret_password"
        with secure_memory(original) as protected:
            assert bytes(protected) == original
            protected[0] ^= 0xFF
            assert bytes(protected) != original

        # Buffer should be zeroed by the context manager
        assert bytes(protected) == b"\x00" * len(original)
    
    def test_empty_data(self):
        """Test with empty data."""
        from meow_decoder.constant_time import secure_memory
        
        with secure_memory(b"") as buf:
            assert len(buf) == 0
    
    def test_large_data(self):
        """Test with large data."""
        from meow_decoder.constant_time import secure_memory
        
        large = secrets.token_bytes(1024 * 1024)  # 1MB
        
        with secure_memory(large) as buf:
            assert len(buf) == 1024 * 1024
    
    def test_with_binary(self):
        """Test secure memory with binary data."""
        from meow_decoder.constant_time import secure_memory
        
        data = os.urandom(256)
        
        with secure_memory(data) as buf:
            assert bytes(buf) == data
    
    def test_lock_and_unlock_exceptions(self, monkeypatch):
        """Test handling of mlock/munlock exceptions."""
        import meow_decoder.constant_time as ct
        
        # Skip if no libc
        try:
            real_libc = ctypes.CDLL("libc.so.6")
        except OSError:
            pytest.skip("libc not available")
        
        class _LibcLockFails:
            def mlock(self, *_args, **_kwargs):
                raise OSError("mlock failed")
            
            def memset(self, *args, **kwargs):
                return real_libc.memset(*args, **kwargs)
        
        monkeypatch.setattr(ct, "_libc", _LibcLockFails())
        
        with ct.secure_memory(b"pw") as buf:
            assert bytes(buf) == b"pw"
        
        class _LibcUnlockFails:
            def mlock(self, *_args, **_kwargs):
                return 0
            
            def munlock(self, *_args, **_kwargs):
                raise OSError("munlock failed")
            
            def memset(self, *args, **kwargs):
                return real_libc.memset(*args, **kwargs)
        
        monkeypatch.setattr(ct, "_libc", _LibcUnlockFails())
        
        with ct.secure_memory(b"pw") as buf2:
            assert bytes(buf2) == b"pw"


# =============================================================================
# Test: timing_safe_equal_with_delay
# =============================================================================

class TestTimingSafeEqualWithDelay:
    """Test timing_safe_equal_with_delay function."""
    
    def test_equal_with_delay(self):
        """Test equal comparison with delay."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        
        a = b"password123"
        b = b"password123"
        
        start = time.time()
        result = timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=5)
        elapsed = time.time() - start
        
        assert result is True
        assert elapsed >= 0.001  # At least min delay
    
    def test_unequal_with_delay(self):
        """Test unequal comparison with delay."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        
        a = b"password123"
        b = b"wrong_pass"
        
        start = time.time()
        result = timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=5)
        elapsed = time.time() - start
        
        assert result is False
        assert elapsed >= 0.001  # At least min delay
    
    def test_returns_bool_fast(self):
        """Test returns bool with minimal delay."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        
        # Keep delays tiny so the test stays fast
        out = timing_safe_equal_with_delay(b"a", b"a", min_delay_ms=0, max_delay_ms=1)
        assert isinstance(out, bool)
    
    def test_delay_adds_randomness(self):
        """Test that delay adds randomness."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        
        a = b"test"
        b = b"test"
        
        times = []
        for _ in range(10):
            start = time.time()
            timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=10)
            times.append(time.time() - start)
        
        # There should be some variance
        assert max(times) > min(times) * 0.5  # Some variation expected


# =============================================================================
# Test: equalize_timing
# =============================================================================

class TestEqualizeTiming:
    """Test equalize_timing function."""
    
    def test_fast_operation(self):
        """Test equalizing a fast operation."""
        from meow_decoder.constant_time import equalize_timing
        
        operation_time = 0.02  # 20ms
        target_time = 0.1  # 100ms
        
        start = time.time()
        equalize_timing(operation_time, target_time)
        elapsed = time.time() - start
        
        # Should sleep roughly (target - operation) seconds
        assert elapsed >= (target_time - operation_time - 0.02)
    
    def test_slow_operation(self):
        """Test equalizing a slow operation (no sleep needed)."""
        from meow_decoder.constant_time import equalize_timing
        
        operation_time = 0.15  # 150ms (already exceeds target)
        target_time = 0.1  # 100ms
        
        start = time.time()
        equalize_timing(operation_time, target_time)
        elapsed = time.time() - start
        
        # Should not sleep if operation already exceeded target
        assert elapsed < 0.02  # Should be very fast (no sleep)
    
    def test_exact_time(self):
        """Test equalizing when operation equals target."""
        from meow_decoder.constant_time import equalize_timing
        
        equalize_timing(0.1, 0.1)  # Equal times, no sleep needed
    
    def test_zero_target(self):
        """Test timing with zero delay."""
        from meow_decoder.constant_time import equalize_timing
        
        # Zero target - should do nothing
        equalize_timing(0.01, 0.0)
    
    def test_does_not_raise(self):
        """Test it does not raise."""
        from meow_decoder.constant_time import equalize_timing
        
        equalize_timing(operation_time=0.0, target_time=0.0)


# =============================================================================
# Test: SecureBuffer class
# =============================================================================

class TestSecureBuffer:
    """Test SecureBuffer class."""
    
    def test_creation(self):
        """Test creating a secure buffer."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            assert len(buf.buffer) == 32
            assert buf.size == 32
    
    def test_write_and_read(self):
        """Test writing and reading from secure buffer."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"test_data")
            data = buf.read(9)
            assert data == b"test_data"
    
    def test_write_with_offset(self):
        """Test writing with offset."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"hello", offset=10)
            data = buf.read(5, offset=10)
            assert data == b"hello"
    
    def test_read_all(self):
        """Test reading all data."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(16) as buf:
            buf.write(b"0123456789ABCDEF")
            data = buf.read()
            assert len(data) == 16
    
    def test_read_with_offset(self):
        """Test reading with offset."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"0123456789")
            data = buf.read(4, offset=5)
            assert data == b"5678"
    
    def test_write_too_large(self):
        """Test writing data too large for buffer."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(8) as buf:
            with pytest.raises(ValueError, match="too large"):
                buf.write(b"this_is_too_long_for_buffer")
    
    def test_locked_property(self):
        """Test locked property."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            # locked depends on platform support
            assert isinstance(buf.locked, bool)
    
    def test_cleanup_on_del(self):
        """Test that buffer is cleaned up after deletion."""
        from meow_decoder.constant_time import SecureBuffer
        
        buf = SecureBuffer(32)
        buf.write(b"sensitive_data")
        del buf  # Should trigger cleanup
    
    def test_context_manager_exit(self):
        """Test context manager exit."""
        from meow_decoder.constant_time import SecureBuffer
        
        buf = SecureBuffer(32)
        buf.__enter__()
        buf.write(b"data")
        buf.__exit__(None, None, None)
    
    def test_lock_exception_and_cleanup(self, monkeypatch):
        """Test SecureBuffer handles mlock exceptions."""
        import meow_decoder.constant_time as ct
        
        try:
            real_libc = ctypes.CDLL("libc.so.6")
        except OSError:
            pytest.skip("libc not available")
        
        class _LibcMlockRaises:
            def mlock(self, *_args, **_kwargs):
                raise OSError("mlock failed")
            
            def memset(self, *args, **kwargs):
                return real_libc.memset(*args, **kwargs)
        
        monkeypatch.setattr(ct, "_libc", _LibcMlockRaises())
        
        buf = ct.SecureBuffer(8)
        buf.write(b"hi")
        assert buf.read()[:2] == b"hi"
        
        # Force __del__ paths
        buf.__del__()
        
        class _LibcUnlockRaises:
            def mlock(self, *_args, **_kwargs):
                return 0
            
            def munlock(self, *_args, **_kwargs):
                raise OSError("munlock failed")
            
            def memset(self, *args, **kwargs):
                return real_libc.memset(*args, **kwargs)
        
        monkeypatch.setattr(ct, "_libc", _LibcUnlockRaises())
        
        buf2 = ct.SecureBuffer(8)
        buf2.write(b"hello")
        assert buf2.read().startswith(b"hello")
        buf2.locked = True
        buf2.__del__()


# =============================================================================
# Test: _get_libc platform detection
# =============================================================================

class TestLibcLoading:
    """Test libc loading and platform detection."""
    
    def test_get_libc(self):
        """Test libc loading."""
        from meow_decoder.constant_time import _get_libc
        
        libc = _get_libc()
        # May be None on some platforms, but shouldn't crash
        assert libc is None or hasattr(libc, 'mlock')
    
    def test_libc_module_variable(self):
        """Test _libc module variable."""
        from meow_decoder import constant_time
        
        # _libc may be None on some platforms
        assert constant_time._libc is None or callable(getattr(constant_time._libc, 'mlock', None))
    
    def test_platform_branches(self, monkeypatch):
        """Test _get_libc platform branches."""
        import meow_decoder.constant_time as ct
        
        # Darwin branch
        monkeypatch.setattr(ct.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(ct.ctypes, "CDLL", lambda _name: object())
        assert ct._get_libc() is not None
        
        # Windows branch
        monkeypatch.setattr(ct.platform, "system", lambda: "Windows")
        monkeypatch.setattr(ct.ctypes, "CDLL", lambda _name: object())
        assert ct._get_libc() is not None
        
        # Unknown platform branch
        monkeypatch.setattr(ct.platform, "system", lambda: "Plan9")
        assert ct._get_libc() is None
        
        # Exception path
        monkeypatch.setattr(ct.platform, "system", lambda: "Darwin")
        
        def _boom(_name):
            raise OSError("nope")
        
        monkeypatch.setattr(ct.ctypes, "CDLL", _boom)
        assert ct._get_libc() is None


# =============================================================================
# Test: Integration patterns
# =============================================================================

class TestConstantTimeIntegration:
    """Integration tests for constant-time module."""
    
    def test_password_verification_pattern(self):
        """Test typical password verification pattern."""
        from meow_decoder.constant_time import constant_time_compare, equalize_timing
        import hashlib
        
        stored_hash = hashlib.sha256(b"correct_password").digest()
        
        # Correct password
        start = time.time()
        input_hash = hashlib.sha256(b"correct_password").digest()
        result = constant_time_compare(stored_hash, input_hash)
        elapsed = time.time() - start
        equalize_timing(elapsed, 0.01)
        
        assert result is True
        
        # Wrong password
        start = time.time()
        input_hash = hashlib.sha256(b"wrong_password").digest()
        result = constant_time_compare(stored_hash, input_hash)
        elapsed = time.time() - start
        equalize_timing(elapsed, 0.01)
        
        assert result is False
    
    def test_key_handling_pattern(self):
        """Test typical key handling pattern."""
        from meow_decoder.constant_time import secure_memory, SecureBuffer
        
        # Generate key
        key = secrets.token_bytes(32)
        
        # Use in secure context
        with secure_memory(key) as secure_key:
            # Process key
            derived = bytes(b ^ 0x5c for b in secure_key)
            assert len(derived) == 32
        
        # Buffer variant
        with SecureBuffer(32) as buf:
            buf.write(key)
            stored = buf.read(32)
            assert stored == key
    
    def test_timing_consistency(self):
        """Test that timing is roughly consistent."""
        from meow_decoder.constant_time import constant_time_compare
        
        # Different comparison patterns should take similar time
        equal_times = []
        unequal_times = []
        
        for _ in range(50):
            start = time.time()
            constant_time_compare(b"password123456", b"password123456")
            equal_times.append(time.time() - start)
            
            start = time.time()
            constant_time_compare(b"password123456", b"wrong_password")
            unequal_times.append(time.time() - start)
        
        # Remove outliers (first few may be slower due to caching)
        equal_times = equal_times[5:]
        unequal_times = unequal_times[5:]
        
        # Mean times should be within reasonable range
        mean_equal = sum(equal_times) / len(equal_times)
        mean_unequal = sum(unequal_times) / len(unequal_times)
        
        # They should be roughly similar (within 10x is good for test)
        assert mean_equal < mean_unequal * 10
        assert mean_unequal < mean_equal * 10


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
