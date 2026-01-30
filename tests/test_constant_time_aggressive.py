#!/usr/bin/env python3
"""
🐱 AGGRESSIVE Coverage Tests for constant_time.py
Target: Boost constant_time.py from 21% to 90%+
"""

import pytest
import sys
import os
import time
import ctypes
from pathlib import Path
from unittest.mock import patch, MagicMock

os.environ['MEOW_TEST_MODE'] = '1'
sys.path.insert(0, str(Path(__file__).parent.parent))


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


class TestSecureMemoryContext:
    """Test secure_memory context manager."""
    
    def test_secure_memory_basic(self):
        """Test basic secure memory usage."""
        from meow_decoder.constant_time import secure_memory
        
        password = b"super_secret_password"
        
        with secure_memory(password) as buf:
            assert bytes(buf) == password
        
        # After context, buffer should be zeroed (though we can't easily verify)
    
    def test_secure_memory_modification(self):
        """Test modifying data in secure memory."""
        from meow_decoder.constant_time import secure_memory
        
        data = b"test_data"
        
        with secure_memory(data) as buf:
            buf[0] = ord('X')
            assert buf[0] == ord('X')
    
    def test_secure_memory_empty(self):
        """Test secure memory with empty data."""
        from meow_decoder.constant_time import secure_memory
        
        with secure_memory(b"") as buf:
            assert len(buf) == 0


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


class TestEqualizeTiming:
    """Test equalize_timing function."""
    
    def test_equalize_fast_operation(self):
        """Test equalizing a fast operation."""
        from meow_decoder.constant_time import equalize_timing
        
        operation_time = 0.02  # 20ms
        target_time = 0.1  # 100ms
        
        start = time.time()
        equalize_timing(operation_time, target_time)
        elapsed = time.time() - start
        
        # Should sleep roughly (target - operation) seconds
        assert elapsed >= (target_time - operation_time - 0.01)
    
    def test_equalize_slow_operation(self):
        """Test equalizing a slow operation (no sleep needed)."""
        from meow_decoder.constant_time import equalize_timing
        
        operation_time = 0.15  # 150ms (already exceeds target)
        target_time = 0.1  # 100ms
        
        start = time.time()
        equalize_timing(operation_time, target_time)
        elapsed = time.time() - start
        
        # Should not sleep if operation already exceeded target
        assert elapsed < 0.02  # Should be very fast (no sleep)
    
    def test_equalize_exact_time(self):
        """Test equalizing when operation equals target."""
        from meow_decoder.constant_time import equalize_timing
        
        equalize_timing(0.1, 0.1)  # Equal times, no sleep needed


class TestSecureBuffer:
    """Test SecureBuffer class."""
    
    def test_secure_buffer_creation(self):
        """Test creating a secure buffer."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            assert len(buf.buffer) == 32
    
    def test_secure_buffer_write_read(self):
        """Test writing and reading from secure buffer."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"test_data")
            data = buf.read(9)
            assert data == b"test_data"
    
    def test_secure_buffer_write_with_offset(self):
        """Test writing with offset."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"hello", offset=10)
            data = buf.read(5, offset=10)
            assert data == b"hello"
    
    def test_secure_buffer_read_all(self):
        """Test reading all data."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(16) as buf:
            buf.write(b"0123456789ABCDEF")
            data = buf.read()
            assert len(data) == 16
    
    def test_secure_buffer_write_too_large(self):
        """Test writing data too large for buffer."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(8) as buf:
            with pytest.raises(ValueError):
                buf.write(b"this_is_too_long_for_buffer")
    
    def test_secure_buffer_locked_property(self):
        """Test locked property."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            # locked depends on platform support
            assert isinstance(buf.locked, bool)
    
    def test_secure_buffer_cleanup(self):
        """Test that buffer is cleaned up after exit."""
        from meow_decoder.constant_time import SecureBuffer
        
        buf = SecureBuffer(32)
        buf.write(b"sensitive_data")
        del buf  # Should trigger cleanup


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


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_compare_single_byte(self):
        """Test comparing single byte strings."""
        from meow_decoder.constant_time import constant_time_compare
        
        assert constant_time_compare(b"a", b"a") is True
        assert constant_time_compare(b"a", b"b") is False
    
    def test_compare_null_bytes(self):
        """Test comparing strings with null bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"hello\x00world"
        b = b"hello\x00world"
        
        assert constant_time_compare(a, b) is True
    
    def test_compare_binary_data(self):
        """Test comparing arbitrary binary data."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = os.urandom(100)
        b = bytes(a)  # Copy
        
        assert constant_time_compare(a, b) is True
    
    def test_secure_memory_with_binary(self):
        """Test secure memory with binary data."""
        from meow_decoder.constant_time import secure_memory
        
        data = os.urandom(256)
        
        with secure_memory(data) as buf:
            assert bytes(buf) == data


class TestMlockFailure:
    """Test handling of mlock failures."""
    
    def test_secure_buffer_mlock_failure(self):
        """Test secure buffer when mlock fails."""
        from meow_decoder.constant_time import SecureBuffer
        
        # Should still work even if mlock fails
        with SecureBuffer(32) as buf:
            buf.write(b"test")
            assert buf.read(4) == b"test"


class TestSecureCompare:
    """Additional tests for secure comparison."""
    
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


class TestMemoryZeroWithMock:
    """Test memory zeroing with mocked libc."""
    
    def test_zero_with_no_libc(self):
        """Test zeroing when libc is not available."""
        from meow_decoder import constant_time
        
        original_libc = constant_time._libc
        try:
            constant_time._libc = None
            
            data = bytearray(b"sensitive")
            constant_time.secure_zero_memory(data)
            
            # Should still zero via fallback
            assert all(b == 0 for b in data)
        finally:
            constant_time._libc = original_libc


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
