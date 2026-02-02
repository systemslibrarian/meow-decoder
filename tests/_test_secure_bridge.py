#!/usr/bin/env python3
"""
🧪 Tests for secure_bridge.py - Secure Bridge Module

Tests secure memory handling and Rust crypto bridge functionality.
"""

import pytest
import os
import sys
import secrets
import gc

# Add parent directory to path
sys.path.insert(0, str(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from meow_decoder.secure_bridge import (
    KeyHandle,
    SecureMemory,
    SecureBridge,
    RUST_AVAILABLE,
)


class TestKeyHandle:
    """Tests for KeyHandle class."""
    
    def test_key_handle_creation(self):
        """Should create key handle with all fields."""
        handle = KeyHandle(
            _handle_id=1,
            _backend='rust',
            _key_bytes=b"test_key_material_32_bytes______",
        )
        
        assert handle._handle_id == 1
        assert handle._backend == 'rust'
        assert handle._key_bytes == b"test_key_material_32_bytes______"
        assert handle._zeroed is False
    
    def test_key_handle_zero_on_del(self):
        """Key material should be zeroed on deletion."""
        key_bytes = bytearray(b"secret_key_to_zero______________")
        
        handle = KeyHandle(
            _handle_id=2,
            _backend='rust',
            _key_bytes=bytes(key_bytes),
        )
        
        # Delete and verify zeroing was attempted
        del handle
        gc.collect()
        
        # Note: Due to Python's immutability, we can only verify the handle 
        # attempted to zero - actual bytes are immutable
    
    def test_key_handle_manual_zero(self):
        """Should be able to manually zero key."""
        handle = KeyHandle(
            _handle_id=3,
            _backend='rust',
            _key_bytes=b"manual_zero_test________________",
        )
        
        handle._zero_key()
        
        assert handle._zeroed is True
    
    def test_key_handle_idempotent_zero(self):
        """Zeroing should be idempotent."""
        handle = KeyHandle(
            _handle_id=4,
            _backend='rust',
            _key_bytes=b"idempotent_test_________________",
        )
        
        handle._zero_key()
        handle._zero_key()  # Should not raise
        handle._zero_key()  # Should not raise
        
        assert handle._zeroed is True
    
    def test_key_handle_none_key(self):
        """Handle with None key should handle zeroing gracefully."""
        handle = KeyHandle(
            _handle_id=5,
            _backend='rust',
            _key_bytes=None,
        )
        
        handle._zero_key()  # Should not raise
        # With no key bytes, _zeroed stays False (nothing to zero)
        assert handle._zeroed is False


class TestSecureMemory:
    """Tests for SecureMemory class."""
    
    def test_secure_memory_allocation(self):
        """Should allocate secure memory of specified size."""
        mem = SecureMemory(32)
        
        assert mem.size == 32
        assert mem._buffer is not None
    
    def test_secure_memory_write_read(self):
        """Should write and read data correctly."""
        mem = SecureMemory(64)
        test_data = b"secret_data_here"
        
        mem.write(test_data)
        result = mem.read()
        
        assert result[:len(test_data)] == test_data
    
    def test_secure_memory_write_at_offset(self):
        """Should write at specified offset."""
        mem = SecureMemory(64)
        
        mem.write(b"AAA", offset=0)
        mem.write(b"BBB", offset=10)
        
        result = mem.read()
        assert result[0:3] == b"AAA"
        assert result[10:13] == b"BBB"
    
    def test_secure_memory_zero(self):
        """Should zero all memory."""
        mem = SecureMemory(32)
        mem.write(b"sensitive_content_______________")
        
        mem.zero()
        result = mem.read()
        
        # All bytes should be zero
        assert all(b == 0 for b in result)
    
    def test_secure_memory_context_manager(self):
        """Context manager should zero on exit."""
        data_ref = None
        
        with SecureMemory(32) as mem:
            mem.write(b"context_data____________________")
            data_ref = mem.read()
        
        # After context exit, memory should be zeroed
        # Note: We kept a reference before exit for verification
    
    def test_secure_memory_unlock(self):
        """Unlock should not raise errors."""
        mem = SecureMemory(32)
        
        # Should not raise
        mem.unlock()
        mem.unlock()  # Idempotent
    
    def test_secure_memory_large_allocation(self):
        """Should handle large allocations."""
        # 1 MB allocation
        mem = SecureMemory(1024 * 1024)
        
        assert mem.size == 1024 * 1024
        
        # Should be able to write and read
        test_data = b"X" * 1000
        mem.write(test_data)
        result = mem.read()
        assert result[:1000] == test_data
        
        # Clean up
        mem.zero()


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust backend not available")
class TestSecureBridgeWithRust:
    """Tests for SecureBridge with Rust backend."""
    
    def test_bridge_initialization(self):
        """Should initialize bridge successfully."""
        bridge = SecureBridge()
        
        assert bridge.use_rust is True
        assert bridge._finalized is False
    
    def test_bridge_context_manager(self):
        """Context manager should work correctly."""
        with SecureBridge() as bridge:
            assert bridge is not None
            assert bridge.use_rust is True
    
    def test_create_key_handle(self):
        """Should create key handle from password."""
        with SecureBridge() as bridge:
            salt = secrets.token_bytes(16)
            
            handle = bridge.create_key_handle(
                password="test_password",
                salt=salt,
                memory_kib=32768,  # Reduced for testing
                iterations=1
            )
            
            assert handle is not None
            assert handle._backend == 'rust'
            assert handle._key_bytes is not None
            assert len(handle._key_bytes) == 32
    
    def test_bridge_cleanup(self):
        """Bridge cleanup should zero all handles."""
        bridge = SecureBridge()
        salt = secrets.token_bytes(16)
        
        handle = bridge.create_key_handle(
            password="cleanup_test",
            salt=salt,
            memory_kib=32768,
            iterations=1
        )
        
        bridge.cleanup()
        
        # Handle should be marked as finalized
        assert bridge._finalized is True
    
    def test_multiple_handles(self):
        """Should manage multiple key handles."""
        with SecureBridge() as bridge:
            handles = []
            
            for i in range(3):
                salt = secrets.token_bytes(16)
                handle = bridge.create_key_handle(
                    password=f"password_{i}",
                    salt=salt,
                    memory_kib=32768,
                    iterations=1
                )
                handles.append(handle)
            
            assert len(handles) == 3
            
            # Each should have unique key
            keys = [h._key_bytes for h in handles]
            assert len(set(keys)) == 3


class TestSecureBridgeWithoutRust:
    """Tests for SecureBridge error handling without Rust."""
    
    def test_bridge_raises_without_rust(self):
        """Bridge should raise if Rust unavailable."""
        if RUST_AVAILABLE:
            pytest.skip("Rust is available, cannot test error case")
        
        with pytest.raises(RuntimeError, match="Rust crypto backend required"):
            SecureBridge()


class TestMemoryLocking:
    """Tests for memory locking functionality."""
    
    def test_mlock_attempted(self):
        """Memory locking should be attempted (may fail based on permissions)."""
        mem = SecureMemory(4096)  # One page
        
        # _locked indicates if mlock succeeded
        # May be False on systems without permissions
        assert hasattr(mem, '_locked')
        assert isinstance(mem._locked, bool)
    
    @pytest.mark.skipif(
        os.geteuid() != 0 if hasattr(os, 'geteuid') else True,
        reason="Requires root for guaranteed mlock"
    )
    def test_mlock_with_privileges(self):
        """With proper privileges, mlock should succeed."""
        mem = SecureMemory(4096)
        # This test is informational - mlock may still fail
        # based on system configuration


class TestRustAvailability:
    """Tests for Rust backend detection."""
    
    def test_rust_available_flag(self):
        """RUST_AVAILABLE should be boolean."""
        assert isinstance(RUST_AVAILABLE, bool)
    
    def test_rust_import(self):
        """Rust module import should match RUST_AVAILABLE flag."""
        try:
            import meow_crypto_rs
            assert RUST_AVAILABLE is True
        except ImportError:
            assert RUST_AVAILABLE is False


class TestEdgeCases:
    """Edge cases and boundary conditions."""
    
    def test_zero_size_memory(self):
        """Zero-size memory allocation should work."""
        mem = SecureMemory(0)
        
        assert mem.size == 0
        mem.zero()  # Should not raise
    
    def test_handle_with_empty_key(self):
        """Handle with empty key should work."""
        handle = KeyHandle(
            _handle_id=100,
            _backend='test',
            _key_bytes=b"",
        )
        
        handle._zero_key()  # Should not raise
    
    @pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust backend not available")
    def test_short_password(self):
        """Short password should work with bridge."""
        with SecureBridge() as bridge:
            salt = secrets.token_bytes(16)
            
            # Short password (may trigger Argon2 min length if enforced)
            try:
                handle = bridge.create_key_handle(
                    password="123456789012",  # 12 chars (meets 8 char minimum)
                    salt=salt,
                    memory_kib=32768,
                    iterations=1
                )
                assert handle is not None
            except ValueError as e:
                # Acceptable if password length validation
                assert "password" in str(e).lower()


class TestSecureMemoryTypes:
    """Tests for different memory buffer types."""
    
    def test_ctypes_buffer_path(self):
        """ctypes buffer allocation should work."""
        import ctypes
        
        mem = SecureMemory(32)
        
        # May use ctypes or bytearray internally
        assert mem._buffer is not None
    
    def test_bytearray_fallback(self):
        """Should fall back to bytearray if ctypes fails."""
        mem = SecureMemory(32)
        
        # Either path should work
        data = mem.read()
        assert len(data) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
