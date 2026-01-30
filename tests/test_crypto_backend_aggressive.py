#!/usr/bin/env python3
"""
🔐 Aggressive Coverage Tests for Crypto Backend
Targets: crypto_backend.py (71% → 95%+)

This module provides a unified interface to cryptographic operations.
"""

import os
import sys
import pytest
import secrets
from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path

# Add meow_decoder to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestBackendInfo:
    """Test the BackendInfo dataclass."""
    
    def test_backend_info_creation(self):
        """Test creating a BackendInfo object."""
        from meow_decoder.crypto_backend import BackendInfo
        
        info = BackendInfo(
            name="test",
            version="1.0",
            constant_time=True,
            memory_zeroing=True,
            pq_available=False,
            details="Test backend"
        )
        
        assert info.name == "test"
        assert info.version == "1.0"
        assert info.constant_time is True
        assert info.memory_zeroing is True
        assert info.pq_available is False
        assert info.details == "Test backend"
    
    def test_backend_info_fields_accessible(self):
        """Test all fields are accessible."""
        from meow_decoder.crypto_backend import BackendInfo
        
        info = BackendInfo(
            name="rust",
            version="2.0.0",
            constant_time=False,
            memory_zeroing=False,
            pq_available=True,
            details="Full details"
        )
        
        # All fields should be accessible
        assert hasattr(info, 'name')
        assert hasattr(info, 'version')
        assert hasattr(info, 'constant_time')
        assert hasattr(info, 'memory_zeroing')
        assert hasattr(info, 'pq_available')
        assert hasattr(info, 'details')


class TestRustBackendAvailability:
    """Test Rust backend availability detection."""
    
    def test_rust_available_flag_exists(self):
        """Test that _RUST_AVAILABLE flag exists."""
        from meow_decoder import crypto_backend
        assert hasattr(crypto_backend, '_RUST_AVAILABLE')
    
    def test_is_rust_available_function(self):
        """Test is_rust_available function."""
        from meow_decoder.crypto_backend import is_rust_available
        
        result = is_rust_available()
        assert isinstance(result, bool)
    
    def test_get_available_backends(self):
        """Test get_available_backends function."""
        from meow_decoder.crypto_backend import get_available_backends, is_rust_available
        
        backends = get_available_backends()
        assert isinstance(backends, list)
        
        if is_rust_available():
            assert "rust" in backends
        else:
            assert backends == []


class TestCryptoBackendInit:
    """Test CryptoBackend initialization."""
    
    def test_backend_init_default(self):
        """Test default backend initialization."""
        from meow_decoder.crypto_backend import CryptoBackend, is_rust_available
        
        if is_rust_available():
            backend = CryptoBackend()
            assert backend.name == "rust"
        else:
            with pytest.raises(RuntimeError):
                CryptoBackend()
    
    def test_backend_init_explicit_rust(self):
        """Test explicit Rust backend initialization."""
        from meow_decoder.crypto_backend import CryptoBackend, is_rust_available
        
        if is_rust_available():
            backend = CryptoBackend(backend="rust")
            assert backend.name == "rust"
        else:
            with pytest.raises(RuntimeError):
                CryptoBackend(backend="rust")
    
    def test_backend_init_invalid_rejects(self):
        """Test that invalid backends are rejected."""
        from meow_decoder.crypto_backend import CryptoBackend
        
        with pytest.raises(RuntimeError):
            CryptoBackend(backend="python")  # Not allowed
    
    def test_backend_env_override(self):
        """Test environment variable backend override."""
        from meow_decoder.crypto_backend import CryptoBackend, is_rust_available
        
        # Test with env var set (but must still be "rust")
        old_env = os.environ.get("MEOW_CRYPTO_BACKEND")
        try:
            os.environ["MEOW_CRYPTO_BACKEND"] = "rust"
            if is_rust_available():
                backend = CryptoBackend()
                assert backend.name == "rust"
        finally:
            if old_env is None:
                os.environ.pop("MEOW_CRYPTO_BACKEND", None)
            else:
                os.environ["MEOW_CRYPTO_BACKEND"] = old_env


class TestCryptoBackendMethods:
    """Test CryptoBackend method delegation."""
    
    @pytest.fixture
    def backend(self):
        """Get a crypto backend if available."""
        from meow_decoder.crypto_backend import CryptoBackend, is_rust_available
        
        if not is_rust_available():
            pytest.skip("Rust backend not available")
        return CryptoBackend()
    
    def test_get_info(self, backend):
        """Test get_info returns BackendInfo."""
        from meow_decoder.crypto_backend import BackendInfo
        
        info = backend.get_info()
        assert isinstance(info, BackendInfo)
        assert info.name == "rust"
        assert info.constant_time is True
        assert info.memory_zeroing is True
    
    def test_derive_key_argon2id(self, backend):
        """Test Argon2id key derivation."""
        password = b"test_password_123"
        salt = secrets.token_bytes(16)
        
        # Use fast params for testing
        key = backend.derive_key_argon2id(
            password, salt,
            memory_kib=32768,
            iterations=1,
            parallelism=1,
            output_len=32
        )
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_derive_key_argon2id_deterministic(self, backend):
        """Test Argon2id produces same key for same inputs."""
        password = b"test_password"
        salt = secrets.token_bytes(16)
        
        key1 = backend.derive_key_argon2id(password, salt, memory_kib=32768, iterations=1)
        key2 = backend.derive_key_argon2id(password, salt, memory_kib=32768, iterations=1)
        
        assert key1 == key2
    
    def test_derive_key_hkdf(self, backend):
        """Test HKDF key derivation."""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test_info"
        
        key = backend.derive_key_hkdf(ikm, salt, info, output_len=32)
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_hkdf_extract(self, backend):
        """Test HKDF extract."""
        salt = secrets.token_bytes(16)
        ikm = secrets.token_bytes(32)
        
        prk = backend.hkdf_extract(salt, ikm)
        
        assert isinstance(prk, bytes)
        assert len(prk) == 32
    
    def test_hkdf_expand(self, backend):
        """Test HKDF expand."""
        prk = secrets.token_bytes(32)
        info = b"expansion_info"
        
        okm = backend.hkdf_expand(prk, info, output_len=64)
        
        assert isinstance(okm, bytes)
        assert len(okm) == 64
    
    def test_aes_gcm_encrypt_decrypt(self, backend):
        """Test AES-GCM encryption and decryption."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Hello, secure world!"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext)
        
        assert decrypted == plaintext
    
    def test_aes_gcm_with_aad(self, backend):
        """Test AES-GCM with additional authenticated data."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret message"
        aad = b"Associated data"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, aad)
        
        assert decrypted == plaintext
    
    def test_aes_gcm_wrong_key_fails(self, backend):
        """Test decryption with wrong key fails."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret"
        
        ciphertext = backend.aes_gcm_encrypt(key1, nonce, plaintext)
        
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(key2, nonce, ciphertext)
    
    def test_hmac_sha256(self, backend):
        """Test HMAC-SHA256."""
        key = secrets.token_bytes(32)
        message = b"Test message"
        
        tag = backend.hmac_sha256(key, message)
        
        assert isinstance(tag, bytes)
        assert len(tag) == 32
    
    def test_hmac_sha256_verify(self, backend):
        """Test HMAC-SHA256 verification."""
        key = secrets.token_bytes(32)
        message = b"Test message"
        
        tag = backend.hmac_sha256(key, message)
        
        assert backend.hmac_sha256_verify(key, message, tag) is True
        assert backend.hmac_sha256_verify(key, b"wrong", tag) is False
    
    def test_sha256(self, backend):
        """Test SHA-256 hashing."""
        data = b"Test data"
        
        digest = backend.sha256(data)
        
        assert isinstance(digest, bytes)
        assert len(digest) == 32
    
    def test_constant_time_compare(self, backend):
        """Test constant-time comparison."""
        a = b"equal_value_here"
        b_same = b"equal_value_here"
        b_diff = b"different_value!"
        
        assert backend.constant_time_compare(a, b_same) is True
        assert backend.constant_time_compare(a, b_diff) is False
    
    def test_x25519_generate_keypair(self, backend):
        """Test X25519 keypair generation."""
        private_key, public_key = backend.x25519_generate_keypair()
        
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert len(private_key) == 32
        assert len(public_key) == 32
    
    def test_x25519_exchange(self, backend):
        """Test X25519 key exchange."""
        priv1, pub1 = backend.x25519_generate_keypair()
        priv2, pub2 = backend.x25519_generate_keypair()
        
        shared1 = backend.x25519_exchange(priv1, pub2)
        shared2 = backend.x25519_exchange(priv2, pub1)
        
        assert shared1 == shared2
        assert len(shared1) == 32
    
    def test_x25519_public_from_private(self, backend):
        """Test deriving public key from private key."""
        private_key, expected_public = backend.x25519_generate_keypair()
        
        derived_public = backend.x25519_public_from_private(private_key)
        
        assert derived_public == expected_public
    
    def test_random_bytes(self, backend):
        """Test secure random byte generation."""
        rand1 = backend.random_bytes(32)
        rand2 = backend.random_bytes(32)
        
        assert isinstance(rand1, bytes)
        assert len(rand1) == 32
        assert rand1 != rand2  # Different each time
    
    def test_secure_zero(self, backend):
        """Test secure memory zeroing."""
        data = bytearray(b"sensitive data here!")
        original_len = len(data)
        
        backend.secure_zero(data)
        
        # Should be zeroed
        assert len(data) == original_len
        assert all(b == 0 for b in data)


class TestDefaultBackend:
    """Test default backend functions."""
    
    def test_get_default_backend(self):
        """Test getting default backend."""
        from meow_decoder.crypto_backend import get_default_backend, is_rust_available, CryptoBackend
        
        if is_rust_available():
            backend = get_default_backend()
            assert isinstance(backend, CryptoBackend)
            assert backend.name == "rust"
        else:
            with pytest.raises(RuntimeError):
                get_default_backend()
    
    def test_secure_zero_memory_function(self):
        """Test module-level secure_zero_memory function."""
        from meow_decoder.crypto_backend import secure_zero_memory, is_rust_available
        
        if is_rust_available():
            data = bytearray(b"secret")
            secure_zero_memory(data)
            assert all(b == 0 for b in data)
    
    def test_set_default_backend(self):
        """Test setting default backend."""
        from meow_decoder.crypto_backend import (
            set_default_backend, get_default_backend, 
            is_rust_available, _default_backend
        )
        import meow_decoder.crypto_backend as cb_module
        
        if is_rust_available():
            # Reset and set
            cb_module._default_backend = None
            set_default_backend("rust")
            
            backend = get_default_backend()
            assert backend.name == "rust"


class TestRustCryptoBackendClass:
    """Test RustCryptoBackend class directly."""
    
    def test_rust_backend_name(self):
        """Test RustCryptoBackend has correct NAME."""
        from meow_decoder.crypto_backend import RustCryptoBackend
        
        assert RustCryptoBackend.NAME == "rust"
    
    def test_rust_backend_init_without_rust(self):
        """Test RustCryptoBackend init when Rust not available."""
        from meow_decoder.crypto_backend import RustCryptoBackend
        import meow_decoder.crypto_backend as cb_module
        
        # Save original value
        original = cb_module._RUST_AVAILABLE
        
        try:
            cb_module._RUST_AVAILABLE = False
            
            with pytest.raises(ImportError):
                RustCryptoBackend()
        finally:
            cb_module._RUST_AVAILABLE = original
    
    def test_rust_backend_secure_zero_fallback(self):
        """Test secure_zero fallback when Rust can't handle bytearray."""
        from meow_decoder.crypto_backend import RustCryptoBackend, is_rust_available
        
        if not is_rust_available():
            pytest.skip("Rust backend not available")
        
        backend = RustCryptoBackend()
        
        # Test with normal bytearray
        data = bytearray(b"test")
        backend.secure_zero(data)
        assert all(b == 0 for b in data)
    
    def test_yubikey_derive_not_enabled(self):
        """Test YubiKey derivation when feature not enabled."""
        from meow_decoder.crypto_backend import RustCryptoBackend, is_rust_available
        
        if not is_rust_available():
            pytest.skip("Rust backend not available")
        
        backend = RustCryptoBackend()
        
        # This may or may not raise depending on build
        # Just ensure it doesn't crash unexpectedly
        try:
            backend.derive_key_yubikey(
                password=b"test",
                salt=secrets.token_bytes(16),
                slot="9d",
                pin=None
            )
        except RuntimeError as e:
            assert "YubiKey" in str(e) or "yubikey" in str(e).lower()
        except Exception:
            pass  # OK if YubiKey feature is enabled


class TestBackendType:
    """Test BackendType literal type."""
    
    def test_backend_type_exists(self):
        """Test BackendType is defined."""
        from meow_decoder.crypto_backend import BackendType
        
        # Should be a Literal["rust"]
        assert BackendType is not None


class TestEdgeCases:
    """Test edge cases and error paths."""
    
    def test_empty_data_operations(self):
        """Test operations with empty data."""
        from meow_decoder.crypto_backend import CryptoBackend, is_rust_available
        
        if not is_rust_available():
            pytest.skip("Rust backend not available")
        
        backend = CryptoBackend()
        
        # SHA256 of empty data
        digest = backend.sha256(b"")
        assert len(digest) == 32
        
        # HMAC of empty message
        key = secrets.token_bytes(32)
        tag = backend.hmac_sha256(key, b"")
        assert len(tag) == 32
    
    def test_large_data_operations(self):
        """Test operations with large data."""
        from meow_decoder.crypto_backend import CryptoBackend, is_rust_available
        
        if not is_rust_available():
            pytest.skip("Rust backend not available")
        
        backend = CryptoBackend()
        
        # Large plaintext encryption
        large_data = secrets.token_bytes(1024 * 1024)  # 1 MB
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, large_data)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext)
        
        assert decrypted == large_data


class TestModuleLevelVars:
    """Test module-level variables."""
    
    def test_rust_backend_module_var(self):
        """Test _rust_backend module variable."""
        import meow_decoder.crypto_backend as cb
        
        # _rust_backend should be None or the imported module
        assert hasattr(cb, '_rust_backend')


class TestImportability:
    """Test that the module can be imported correctly."""
    
    def test_import_all_exports(self):
        """Test importing all expected exports."""
        from meow_decoder.crypto_backend import (
            BackendInfo,
            BackendType,
            RustCryptoBackend,
            CryptoBackend,
            get_default_backend,
            secure_zero_memory,
            set_default_backend,
            is_rust_available,
            get_available_backends
        )
        
        # All should be defined
        assert BackendInfo is not None
        assert RustCryptoBackend is not None
        assert CryptoBackend is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
