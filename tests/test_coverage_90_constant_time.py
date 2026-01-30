#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for constant_time.py - Target: 90%+
Tests all constant-time operation paths.
"""

import pytest
import secrets
import sys
import time
import ctypes
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestConstantTimeCompare:
    """Test constant_time_compare function."""
    
    def test_equal_bytes(self):
        """Test comparing equal bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"test_password_12345"
        b = b"test_password_12345"
        
        assert constant_time_compare(a, b) is True
    
    def test_different_bytes(self):
        """Test comparing different bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"correct_password"
        b = b"wrong_password00"
        
        assert constant_time_compare(a, b) is False
    
    def test_empty_bytes(self):
        """Test comparing empty bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b""
        b = b""
        
        assert constant_time_compare(a, b) is True
    
    def test_different_length(self):
        """Test comparing different length bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"short"
        b = b"much_longer_string"
        
        assert constant_time_compare(a, b) is False
    
    def test_random_bytes(self):
        """Test comparing random bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = secrets.token_bytes(32)
        b = a  # Same reference
        
        assert constant_time_compare(a, b) is True
        
        c = secrets.token_bytes(32)
        
        # Almost certainly different
        if a != c:
            assert constant_time_compare(a, c) is False


class TestSecureZeroMemory:
    """Test secure_zero_memory function."""
    
    def test_zero_bytearray(self):
        """Test zeroing bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        buf = bytearray(b"secret_data_here")
        secure_zero_memory(buf)
        
        assert all(b == 0 for b in buf)
    
    def test_zero_empty_bytearray(self):
        """Test zeroing empty bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        buf = bytearray()
        secure_zero_memory(buf)  # Should not crash
        
        assert len(buf) == 0
    
    def test_zero_ctypes_buffer(self):
        """Test zeroing ctypes buffer."""
        from meow_decoder.constant_time import secure_zero_memory
        
        buf = (ctypes.c_char * 16)()
        buf.value = b"secret_data"
        
        secure_zero_memory(buf)
        
        # Check zeroed
        for i in range(16):
            assert buf[i] == b'\x00'
    
    def test_zero_unsupported_type(self):
        """Test zeroing unsupported type."""
        from meow_decoder.constant_time import secure_zero_memory
        
        # String is unsupported - should not crash
        secure_zero_memory("not_a_buffer")


class TestSecureMemoryContextManager:
    """Test secure_memory context manager."""
    
    def test_basic_usage(self):
        """Test basic context manager usage."""
        from meow_decoder.constant_time import secure_memory
        
        with secure_memory(b"secret_password") as buf:
            assert len(buf) == 15
            assert buf == bytearray(b"secret_password")
    
    def test_buffer_accessible_in_context(self):
        """Test buffer is accessible in context."""
        from meow_decoder.constant_time import secure_memory
        
        with secure_memory(b"test_data") as buf:
            # Can read
            assert buf[0] == ord('t')
            
            # Can modify
            buf[0] = ord('x')
            assert buf[0] == ord('x')
    
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
    
    def test_not_equal_with_delay(self):
        """Test not equal comparison with delay."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        
        a = b"correct"
        b = b"wrong!!"
        
        start = time.time()
        result = timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=5)
        elapsed = time.time() - start
        
        assert result is False
        assert elapsed >= 0.001  # At least min delay


class TestEqualizeTiming:
    """Test equalize_timing function."""
    
    def test_adds_delay_when_needed(self):
        """Test delay is added when operation is fast."""
        from meow_decoder.constant_time import equalize_timing
        
        target = 0.05  # 50ms
        
        start = time.time()
        equalize_timing(0.01, target)  # Operation took 10ms
        elapsed = time.time() - start
        
        # Should sleep for ~40ms
        assert elapsed >= 0.03  # At least 30ms slept
    
    def test_no_delay_when_slow(self):
        """Test no delay when operation is already slow."""
        from meow_decoder.constant_time import equalize_timing
        
        target = 0.01  # 10ms
        
        start = time.time()
        equalize_timing(0.05, target)  # Operation took 50ms
        elapsed = time.time() - start
        
        # Should not sleep
        assert elapsed < 0.01


class TestSecureBuffer:
    """Test SecureBuffer class."""
    
    def test_creation(self):
        """Test creating secure buffer."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            assert buf.size == 32
    
    def test_write_and_read(self):
        """Test writing and reading."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"hello_world")
            data = buf.read(11)
            
            assert data == b"hello_world"
    
    def test_write_with_offset(self):
        """Test writing with offset."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"aaaa", offset=0)
            buf.write(b"bbbb", offset=4)
            
            data = buf.read(8)
            
            assert data == b"aaaabbbb"
    
    def test_read_with_offset(self):
        """Test reading with offset."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"0123456789")
            
            data = buf.read(4, offset=5)
            
            assert data == b"5678"
    
    def test_write_too_large(self):
        """Test writing too large data."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(10) as buf:
            with pytest.raises(ValueError, match="too large"):
                buf.write(b"this_is_way_too_large")
    
    def test_locked_property(self):
        """Test locked property."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            # Check locked property exists
            _ = buf.locked  # Just access it


class TestLibcOperations:
    """Test libc-based operations."""
    
    def test_get_libc(self):
        """Test _get_libc function."""
        from meow_decoder.constant_time import _get_libc
        
        libc = _get_libc()
        # May or may not return libc depending on platform
        # Just make sure it doesn't crash
    
    def test_libc_availability(self):
        """Test libc availability."""
        from meow_decoder import constant_time
        
        # _libc should be set
        _ = constant_time._libc


class TestMlockOperations:
    """Test mlock-related operations."""
    
    def test_secure_buffer_mlock(self):
        """Test SecureBuffer uses mlock when available."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(4096) as buf:
            buf.write(b"sensitive_data")
            
            # Just verify no crash with mlock attempt
            assert buf.size == 4096


class TestConstantTimeEdgeCases:
    """Test edge cases."""
    
    def test_compare_single_byte(self):
        """Test comparing single byte."""
        from meow_decoder.constant_time import constant_time_compare
        
        assert constant_time_compare(b"\x00", b"\x00") is True
        assert constant_time_compare(b"\x00", b"\x01") is False
    
    def test_compare_max_difference(self):
        """Test comparing maximally different bytes."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"\x00" * 32
        b = b"\xff" * 32
        
        assert constant_time_compare(a, b) is False
    
    def test_zero_memory_preserves_length(self):
        """Test secure_zero_memory preserves length."""
        from meow_decoder.constant_time import secure_zero_memory
        
        buf = bytearray(100)
        buf[:] = b"x" * 100
        
        original_len = len(buf)
        secure_zero_memory(buf)
        
        assert len(buf) == original_len
    
    def test_timing_with_zero_delay(self):
        """Test timing with zero delay."""
        from meow_decoder.constant_time import equalize_timing
        
        # Zero target - should do nothing
        equalize_timing(0.01, 0.0)


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


class TestPlatformCompat:
    """Test platform compatibility."""
    
    def test_no_libc_fallback(self):
        """Test fallback when libc unavailable."""
        from meow_decoder.constant_time import secure_zero_memory
        
        # Mock libc as None
        import meow_decoder.constant_time as ct
        original_libc = ct._libc
        
        try:
            ct._libc = None
            
            buf = bytearray(b"test_data")
            secure_zero_memory(buf)
            
            # Should still zero via fallback
            assert all(b == 0 for b in buf)
        finally:
            ct._libc = original_libc


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
