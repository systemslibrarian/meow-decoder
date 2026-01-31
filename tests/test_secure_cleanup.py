#!/usr/bin/env python3
"""
🧪 Tests for secure_cleanup.py - Secure Memory Cleanup Module

Tests secure memory zeroing, cleanup registration, and context management.
"""

import pytest
import gc
import sys
import os

# Add parent directory to path
sys.path.insert(0, str(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from meow_decoder.secure_cleanup import (
    register_sensitive_buffer,
    unregister_and_zero,
    SecureCleanupManager,
    _cleanup_all,
    _sensitive_buffers,
    _buffer_data,
)


class TestRegisterSensitiveBuffer:
    """Tests for register_sensitive_buffer function."""
    
    def test_register_returns_bytearray(self):
        """Registered buffer should be a mutable bytearray."""
        original = b"secret_password_123"
        registered = register_sensitive_buffer(original)
        
        assert isinstance(registered, bytearray)
        assert bytes(registered) == original
    
    def test_registered_buffer_is_mutable(self):
        """Returned bytearray should be mutable."""
        original = b"sensitive_data"
        registered = register_sensitive_buffer(original)
        
        # Should be able to modify in place
        registered[0] = ord('X')
        assert registered[0] == ord('X')
    
    def test_multiple_registrations(self):
        """Multiple buffers can be registered."""
        buf1 = register_sensitive_buffer(b"password1")
        buf2 = register_sensitive_buffer(b"password2")
        buf3 = register_sensitive_buffer(b"password3")
        
        assert bytes(buf1) == b"password1"
        assert bytes(buf2) == b"password2"
        assert bytes(buf3) == b"password3"
        
        # Clean up
        unregister_and_zero(buf1)
        unregister_and_zero(buf2)
        unregister_and_zero(buf3)
    
    def test_empty_buffer_registration(self):
        """Empty buffer can be registered."""
        buf = register_sensitive_buffer(b"")
        assert len(buf) == 0
        unregister_and_zero(buf)


class TestUnregisterAndZero:
    """Tests for unregister_and_zero function."""
    
    def test_zeroes_buffer(self):
        """Buffer should be zeroed after unregistration."""
        original = b"secret_key_material"
        buf = register_sensitive_buffer(original)
        
        # Verify data is there
        assert bytes(buf) == original
        
        # Zero it
        unregister_and_zero(buf)
        
        # Buffer should be all zeros
        assert all(b == 0 for b in buf)
    
    def test_removes_from_registry(self):
        """Buffer should be removed from registry after zeroing."""
        buf = register_sensitive_buffer(b"temporary_secret")
        buf_id = id(buf)
        
        # Should be in registry
        assert buf_id in _sensitive_buffers or buf_id in _buffer_data
        
        # Zero and unregister
        unregister_and_zero(buf)
        
        # Should no longer be in registry
        assert buf_id not in _buffer_data
    
    def test_idempotent_zeroing(self):
        """Zeroing an already-zeroed buffer should be safe."""
        buf = register_sensitive_buffer(b"one_time_secret")
        
        # Zero multiple times (should not raise)
        unregister_and_zero(buf)
        unregister_and_zero(buf)  # Second call should be safe


class TestSecureCleanupManager:
    """Tests for SecureCleanupManager context manager."""
    
    def test_context_manager_basic(self):
        """Basic context manager usage."""
        with SecureCleanupManager() as cleanup:
            buf = cleanup.register(b"context_secret")
            assert bytes(buf) == b"context_secret"
    
    def test_cleanup_on_exit(self):
        """Buffers should be zeroed when context exits."""
        buf_reference = None
        
        with SecureCleanupManager() as cleanup:
            buf_reference = cleanup.register(b"will_be_cleaned")
            assert bytes(buf_reference) == b"will_be_cleaned"
        
        # After context exit, buffer should be zeroed
        assert all(b == 0 for b in buf_reference)
    
    def test_multiple_buffers_in_context(self):
        """Multiple buffers can be managed in one context."""
        buffers = []
        
        with SecureCleanupManager() as cleanup:
            for i in range(5):
                buf = cleanup.register(f"secret_{i}".encode())
                buffers.append(buf)
            
            # All should have data
            for i, buf in enumerate(buffers):
                assert bytes(buf) == f"secret_{i}".encode()
        
        # After exit, all should be zeroed
        for buf in buffers:
            assert all(b == 0 for b in buf)
    
    def test_nested_contexts(self):
        """Nested context managers should work correctly."""
        outer_buf = None
        inner_buf = None
        
        with SecureCleanupManager() as outer:
            outer_buf = outer.register(b"outer_secret")
            
            with SecureCleanupManager() as inner:
                inner_buf = inner.register(b"inner_secret")
                
                # Both should have data
                assert bytes(outer_buf) == b"outer_secret"
                assert bytes(inner_buf) == b"inner_secret"
            
            # Inner should be zeroed
            assert all(b == 0 for b in inner_buf)
            
            # Outer should still have data
            assert bytes(outer_buf) == b"outer_secret"
        
        # Now outer should be zeroed too
        assert all(b == 0 for b in outer_buf)
    
    def test_exception_handling(self):
        """Cleanup should happen even on exception."""
        buf_ref = None
        
        try:
            with SecureCleanupManager() as cleanup:
                buf_ref = cleanup.register(b"exception_secret")
                raise ValueError("Test exception")
        except ValueError:
            pass
        
        # Buffer should still be zeroed
        assert all(b == 0 for b in buf_ref)


class TestCleanupAll:
    """Tests for _cleanup_all function."""
    
    def test_clears_all_buffers(self):
        """_cleanup_all should zero all registered buffers."""
        buffers = []
        
        for i in range(3):
            buf = register_sensitive_buffer(f"global_secret_{i}".encode())
            buffers.append(buf)
        
        # All should have data
        for i, buf in enumerate(buffers):
            assert bytes(buf) == f"global_secret_{i}".encode()
        
        # Cleanup all
        _cleanup_all()
        
        # All should be zeroed
        for buf in buffers:
            assert all(b == 0 for b in buf)
    
    def test_forces_gc(self):
        """Cleanup should trigger garbage collection."""
        buf = register_sensitive_buffer(b"gc_test_secret")
        
        # Should not raise
        _cleanup_all()
        
        # Buffer should be zeroed
        assert all(b == 0 for b in buf)


class TestEdgeCases:
    """Edge cases and boundary conditions."""
    
    def test_large_buffer(self):
        """Large buffers should work correctly."""
        large_secret = b"X" * (1024 * 1024)  # 1 MB
        buf = register_sensitive_buffer(large_secret)
        
        assert len(buf) == len(large_secret)
        assert bytes(buf) == large_secret
        
        unregister_and_zero(buf)
        assert all(b == 0 for b in buf)
    
    def test_binary_data(self):
        """Binary data with null bytes should work."""
        binary_data = bytes(range(256))
        buf = register_sensitive_buffer(binary_data)
        
        assert bytes(buf) == binary_data
        
        unregister_and_zero(buf)
        assert all(b == 0 for b in buf)
    
    def test_unicode_password_bytes(self):
        """Unicode passwords encoded to bytes should work."""
        unicode_password = "密码🔐" 
        password_bytes = unicode_password.encode('utf-8')
        buf = register_sensitive_buffer(password_bytes)
        
        assert bytes(buf) == password_bytes
        
        unregister_and_zero(buf)
        assert all(b == 0 for b in buf)


class TestThreadSafety:
    """Thread safety tests."""
    
    def test_concurrent_registration(self):
        """Concurrent registrations should be thread-safe."""
        import threading
        
        results = []
        errors = []
        
        def register_secret(index):
            try:
                buf = register_sensitive_buffer(f"thread_{index}".encode())
                results.append((index, buf))
                unregister_and_zero(buf)
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=register_secret, args=(i,))
            threads.append(t)
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(results) == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
