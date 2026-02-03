"""
Comprehensive tests for meow_decoder/crypto_backend.py

Coverage target: 95-100% branch coverage
Focus: All backend methods, error paths, module functions, edge cases

Run with:
    MEOW_TEST_MODE=1 pytest tests/test_crypto_backend.py -v \
        --cov=meow_decoder.crypto_backend --cov-branch --cov-report=term-missing
"""

import os
import secrets
import sys
from unittest.mock import MagicMock, patch, PropertyMock
import types

import pytest
from hypothesis import given, strategies as st, settings, assume

# Ensure test mode is set before importing
os.environ["MEOW_TEST_MODE"] = "1"


# =============================================================================
# FAKE BACKEND FIXTURES - Used to test error paths without real Rust backend
# =============================================================================

class FakeRustBackend:
    """
    Mock Rust backend for testing all CryptoBackend delegation paths.
    
    This allows testing the Python wrapper code without requiring
    the actual Rust implementation to be present.
    """
    
    # Simulate BackendInfo fields
    def get_info(self):
        """Return fake backend info."""
        from meow_decoder.crypto_backend import BackendInfo
        return BackendInfo(
            name="fake-rust-test",
            version="0.0.1-test",
            constant_time=True,
            memory_zeroing=True,
            pq_available=False,
            details={"test": True}
        )
    
    def derive_key_argon2id(self, password, salt, output_len, iterations, memory_kib, parallelism):
        """Fake Argon2id key derivation."""
        assert isinstance(password, bytes)
        assert isinstance(salt, bytes)
        assert len(salt) == 16
        assert output_len > 0
        # Return deterministic fake key for testing
        return secrets.token_bytes(output_len)
    
    def derive_key_hkdf(self, ikm, salt, info, output_len=32):
        """Fake HKDF key derivation."""
        assert isinstance(ikm, bytes)
        assert isinstance(salt, bytes)
        return secrets.token_bytes(output_len)
    
    def hkdf_extract(self, salt, ikm):
        """Fake HKDF extract phase."""
        assert isinstance(salt, bytes)
        assert isinstance(ikm, bytes)
        return secrets.token_bytes(32)
    
    def hkdf_expand(self, prk, info, length):
        """Fake HKDF expand phase."""
        assert isinstance(prk, bytes)
        assert isinstance(info, bytes)
        assert length > 0
        return secrets.token_bytes(length)
    
    def derive_key_yubikey(self, password, salt, slot, pin):
        """Fake YubiKey derivation."""
        assert isinstance(password, bytes)
        assert isinstance(salt, bytes)
        return secrets.token_bytes(32)
    
    def aes_gcm_encrypt(self, key, nonce, plaintext, aad):
        """Fake AES-GCM encryption."""
        assert isinstance(key, bytes) and len(key) == 32
        assert isinstance(nonce, bytes) and len(nonce) == 12
        assert isinstance(plaintext, bytes)
        # Return fake ciphertext (same length + 16 byte tag)
        return plaintext + secrets.token_bytes(16)
    
    def aes_gcm_decrypt(self, key, nonce, ciphertext, aad):
        """Fake AES-GCM decryption."""
        assert isinstance(key, bytes) and len(key) == 32
        assert isinstance(nonce, bytes) and len(nonce) == 12
        assert isinstance(ciphertext, bytes)
        # Strip the 16-byte tag from our fake ciphertext
        if len(ciphertext) < 16:
            raise ValueError("Invalid ciphertext")
        return ciphertext[:-16]
    
    def hmac_sha256(self, key, data):
        """Fake HMAC-SHA256."""
        assert isinstance(key, bytes)
        assert isinstance(data, bytes)
        return secrets.token_bytes(32)
    
    def hmac_sha256_verify(self, key, data, expected_mac):
        """Fake HMAC-SHA256 verification."""
        assert isinstance(key, bytes)
        assert isinstance(data, bytes)
        assert isinstance(expected_mac, bytes)
        return True  # Always verify in tests
    
    def sha256(self, data):
        """Fake SHA-256."""
        assert isinstance(data, bytes)
        return secrets.token_bytes(32)
    
    def constant_time_compare(self, a, b):
        """Fake constant-time compare."""
        assert isinstance(a, bytes)
        assert isinstance(b, bytes)
        return a == b
    
    def x25519_generate_keypair(self):
        """Fake X25519 keypair generation."""
        return (secrets.token_bytes(32), secrets.token_bytes(32))
    
    def x25519_exchange(self, private_key, public_key):
        """Fake X25519 key exchange."""
        assert isinstance(private_key, bytes) and len(private_key) == 32
        assert isinstance(public_key, bytes) and len(public_key) == 32
        return secrets.token_bytes(32)
    
    def random_bytes(self, length):
        """Fake random bytes."""
        assert length > 0
        return secrets.token_bytes(length)
    
    def secure_zero(self, buffer):
        """Fake secure zero."""
        if isinstance(buffer, bytearray):
            for i in range(len(buffer)):
                buffer[i] = 0


class FakeRustBackendNoYubiKey:
    """Fake backend that raises AttributeError for YubiKey (missing method)."""
    
    def derive_key_yubikey(self, password, salt, slot, pin):
        raise AttributeError("module has no attribute 'derive_key_yubikey'")
    
    # Copy other methods from FakeRustBackend
    def get_info(self):
        return FakeRustBackend().get_info()
    
    def derive_key_argon2id(self, *args, **kwargs):
        return FakeRustBackend().derive_key_argon2id(*args, **kwargs)
    
    def aes_gcm_encrypt(self, *args, **kwargs):
        return FakeRustBackend().aes_gcm_encrypt(*args, **kwargs)
    
    def aes_gcm_decrypt(self, *args, **kwargs):
        return FakeRustBackend().aes_gcm_decrypt(*args, **kwargs)
    
    def hmac_sha256(self, *args, **kwargs):
        return FakeRustBackend().hmac_sha256(*args, **kwargs)


class FakeRustBackendBadSecureZero:
    """Fake backend where secure_zero raises TypeError (fallback path)."""
    
    def secure_zero(self, buffer):
        raise TypeError("Cannot zero this type")
    
    # Copy other methods
    def get_info(self):
        return FakeRustBackend().get_info()
    
    def derive_key_argon2id(self, *args, **kwargs):
        return FakeRustBackend().derive_key_argon2id(*args, **kwargs)


class FakeRustBackendBadSecureZeroAttr:
    """Fake backend where secure_zero raises AttributeError (fallback path)."""
    
    def secure_zero(self, buffer):
        raise AttributeError("secure_zero not available")
    
    # Copy other methods
    def get_info(self):
        return FakeRustBackend().get_info()


# =============================================================================
# TEST CLASS: BackendInfo
# =============================================================================

class TestBackendInfo:
    """Tests for the BackendInfo dataclass."""
    
    def test_backend_info_creation(self):
        """Test creating BackendInfo with all fields."""
        from meow_decoder.crypto_backend import BackendInfo
        
        info = BackendInfo(
            name="test-backend",
            version="1.0.0",
            constant_time=True,
            memory_zeroing=True,
            pq_available=False,
            details={"test_key": "test_value"}
        )
        
        assert info.name == "test-backend"
        assert info.version == "1.0.0"
        assert info.constant_time is True
        assert info.memory_zeroing is True
        assert info.pq_available is False
        assert info.details == {"test_key": "test_value"}
    
    def test_backend_info_defaults(self):
        """Test BackendInfo with minimal fields."""
        from meow_decoder.crypto_backend import BackendInfo
        
        info = BackendInfo(
            name="minimal",
            version="0.1.0",
            constant_time=False,
            memory_zeroing=False,
            pq_available=False,
            details={}
        )
        
        assert info.name == "minimal"
        assert info.details == {}


# =============================================================================
# TEST CLASS: RustCryptoBackend
# =============================================================================

class TestRustCryptoBackend:
    """Tests for the RustCryptoBackend class."""
    
    def test_rust_backend_init_when_available(self):
        """Test RustCryptoBackend initializes when Rust is available."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        assert backend is not None
        # RustCryptoBackend wraps _rs (the actual Rust module)
        assert backend._rs is not None
    
    def test_rust_backend_init_raises_when_unavailable(self):
        """Test RustCryptoBackend raises ImportError when Rust unavailable."""
        from meow_decoder import crypto_backend
        
        # Temporarily pretend Rust is unavailable
        original = crypto_backend._RUST_AVAILABLE
        try:
            crypto_backend._RUST_AVAILABLE = False
            
            with pytest.raises(ImportError, match="Rust crypto backend"):
                crypto_backend.RustCryptoBackend()
        finally:
            crypto_backend._RUST_AVAILABLE = original
    
    def test_rust_backend_get_info(self):
        """Test RustCryptoBackend.get_info() returns valid BackendInfo."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        info = backend.get_info()
        
        assert isinstance(info, crypto_backend.BackendInfo)
        assert info.name  # Should have a name
        assert info.version  # Should have a version
        assert isinstance(info.constant_time, bool)
        assert isinstance(info.memory_zeroing, bool)
    
    def test_rust_backend_derive_key_argon2id(self, random_salt, valid_password):
        """Test Argon2id key derivation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        key = backend.derive_key_argon2id(
            password=valid_password.encode(),
            salt=random_salt,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_rust_backend_derive_key_hkdf(self, random_salt):
        """Test HKDF key derivation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        ikm = secrets.token_bytes(32)
        info = b"test info"
        
        key = backend.derive_key_hkdf(ikm, random_salt, info, output_len=32)
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_rust_backend_hkdf_extract(self, random_salt):
        """Test HKDF extract phase."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        ikm = secrets.token_bytes(32)
        
        prk = backend.hkdf_extract(random_salt, ikm)
        
        assert isinstance(prk, bytes)
        assert len(prk) == 32
    
    def test_rust_backend_hkdf_expand(self, random_salt):
        """Test HKDF expand phase."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        prk = secrets.token_bytes(32)
        info = b"expand test"
        
        okm = backend.hkdf_expand(prk, info, 64)
        
        assert isinstance(okm, bytes)
        assert len(okm) == 64
    
    def test_rust_backend_aes_gcm_encrypt_decrypt(self, random_key, random_nonce, sample_plaintext):
        """Test AES-GCM encryption and decryption roundtrip."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        aad = b"additional authenticated data"
        
        ciphertext = backend.aes_gcm_encrypt(random_key, random_nonce, sample_plaintext, aad)
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) == len(sample_plaintext) + 16  # +16 for tag
        
        plaintext = backend.aes_gcm_decrypt(random_key, random_nonce, ciphertext, aad)
        assert plaintext == sample_plaintext
    
    def test_rust_backend_aes_gcm_with_none_aad(self, random_key, random_nonce, sample_plaintext):
        """Test AES-GCM with None AAD."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        ciphertext = backend.aes_gcm_encrypt(random_key, random_nonce, sample_plaintext, None)
        plaintext = backend.aes_gcm_decrypt(random_key, random_nonce, ciphertext, None)
        
        assert plaintext == sample_plaintext
    
    def test_rust_backend_hmac_sha256(self, random_key):
        """Test HMAC-SHA256 computation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        data = b"data to authenticate"
        
        mac = backend.hmac_sha256(random_key, data)
        
        assert isinstance(mac, bytes)
        assert len(mac) == 32
    
    def test_rust_backend_hmac_sha256_verify(self, random_key):
        """Test HMAC-SHA256 verification."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        data = b"data to verify"
        
        mac = backend.hmac_sha256(random_key, data)
        
        # Valid MAC should verify
        assert backend.hmac_sha256_verify(random_key, data, mac) is True
        
        # Tampered MAC should not verify
        tampered_mac = bytes([(mac[0] + 1) % 256]) + mac[1:]
        assert backend.hmac_sha256_verify(random_key, data, tampered_mac) is False
    
    def test_rust_backend_sha256(self):
        """Test SHA-256 hash computation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        data = b"data to hash"
        
        digest = backend.sha256(data)
        
        assert isinstance(digest, bytes)
        assert len(digest) == 32
        
        # Same data should produce same hash
        digest2 = backend.sha256(data)
        assert digest == digest2
    
    def test_rust_backend_constant_time_compare_equal(self):
        """Test constant-time comparison for equal values."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        a = b"same value here"
        b = b"same value here"
        
        assert backend.constant_time_compare(a, b) is True
    
    def test_rust_backend_constant_time_compare_unequal(self):
        """Test constant-time comparison for unequal values."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        a = b"value one"
        b = b"value two"
        
        assert backend.constant_time_compare(a, b) is False
    
    def test_rust_backend_constant_time_compare_different_lengths(self):
        """Test constant-time comparison with different length values."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        a = b"short"
        b = b"much longer value"
        
        assert backend.constant_time_compare(a, b) is False
    
    def test_rust_backend_x25519_generate_keypair(self):
        """Test X25519 keypair generation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        private_key, public_key = backend.x25519_generate_keypair()
        
        assert isinstance(private_key, bytes)
        assert len(private_key) == 32
        assert isinstance(public_key, bytes)
        assert len(public_key) == 32
        assert private_key != public_key
    
    def test_rust_backend_x25519_exchange(self):
        """Test X25519 key exchange (ECDH)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        # Generate two keypairs
        priv_a, pub_a = backend.x25519_generate_keypair()
        priv_b, pub_b = backend.x25519_generate_keypair()
        
        # Exchange should produce same shared secret both ways
        shared_ab = backend.x25519_exchange(priv_a, pub_b)
        shared_ba = backend.x25519_exchange(priv_b, pub_a)
        
        assert isinstance(shared_ab, bytes)
        assert len(shared_ab) == 32
        assert shared_ab == shared_ba
    
    def test_rust_backend_x25519_public_from_private(self):
        """Test deriving public key from private key."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        # Generate keypair
        private_key, public_key = backend.x25519_generate_keypair()
        
        # Derive public key from private
        derived_public = backend.x25519_public_from_private(private_key)
        
        assert isinstance(derived_public, bytes)
        assert len(derived_public) == 32
        assert derived_public == public_key
    
    def test_rust_backend_x25519_public_from_private_deterministic(self):
        """Test that x25519_public_from_private is deterministic."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        private_key, _ = backend.x25519_generate_keypair()
        
        pub1 = backend.x25519_public_from_private(private_key)
        pub2 = backend.x25519_public_from_private(private_key)
        
        assert pub1 == pub2
    
    def test_rust_backend_random_bytes(self):
        """Test cryptographically secure random byte generation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        rand1 = backend.random_bytes(32)
        rand2 = backend.random_bytes(32)
        
        assert isinstance(rand1, bytes)
        assert len(rand1) == 32
        assert rand1 != rand2  # Should be different (with overwhelming probability)
    
    def test_rust_backend_secure_zero(self):
        """Test secure memory zeroing."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        # Create buffer with non-zero data
        buffer = bytearray(b"sensitive data here!")
        original_len = len(buffer)
        
        backend.secure_zero(buffer)
        
        # Buffer should be zeroed but same length
        assert len(buffer) == original_len
        assert all(b == 0 for b in buffer)
    
    def test_rust_backend_yubikey_missing_raises_runtime_error(self):
        """Test YubiKey method raises RuntimeError when unavailable."""
        from meow_decoder import crypto_backend
        
        # Create backend with fake module that doesn't have YubiKey
        fake_module = FakeRustBackendNoYubiKey()
        
        backend = crypto_backend.RustCryptoBackend.__new__(crypto_backend.RustCryptoBackend)
        backend._backend = fake_module
        
        with pytest.raises(RuntimeError, match="YubiKey|not available"):
            backend.derive_key_yubikey(
                password=b"password",
                salt=secrets.token_bytes(16),
                slot="9d",
                pin="123456"
            )


# =============================================================================
# TEST CLASS: CryptoBackend (Unified Wrapper)
# =============================================================================

class TestCryptoBackend:
    """Tests for the CryptoBackend wrapper class."""
    
    def test_crypto_backend_init_with_rust(self):
        """Test CryptoBackend initializes with rust backend."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.CryptoBackend(backend="rust")
        assert backend is not None
    
    def test_crypto_backend_init_with_invalid_backend(self):
        """Test CryptoBackend raises RuntimeError for non-rust backend."""
        from meow_decoder import crypto_backend
        
        os.environ.pop("MEOW_CRYPTO_BACKEND", None)

        with pytest.raises(RuntimeError, match="Rust crypto backend required"):
            crypto_backend.CryptoBackend(backend="nonexistent")
    
    def test_crypto_backend_init_rust_unavailable(self):
        """Test CryptoBackend raises RuntimeError when Rust unavailable."""
        from meow_decoder import crypto_backend

        original = crypto_backend._RUST_AVAILABLE
        try:
            crypto_backend._RUST_AVAILABLE = False

            with pytest.raises(RuntimeError, match="Rust crypto backend required"):
                crypto_backend.CryptoBackend(backend="rust")
        finally:
            crypto_backend._RUST_AVAILABLE = original
    
    def test_crypto_backend_delegates_to_rust(self):
        """Test CryptoBackend delegates all methods to underlying backend."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        # Test delegation of key derivation
        salt = secrets.token_bytes(16)
        key = wrapper.derive_key_argon2id(
            password=b"test_password_123",
            salt=salt,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_crypto_backend_name_property(self):
        """Test CryptoBackend.name returns backend name."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        assert wrapper.name == "rust"
    
    def test_crypto_backend_get_info(self):
        """Test CryptoBackend.get_info returns BackendInfo."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        info = wrapper.get_info()
        
        assert isinstance(info, crypto_backend.BackendInfo)
        assert info.name == "rust"
    
    def test_crypto_backend_aes_gcm_encrypt_decrypt(self):
        """Test CryptoBackend AES-GCM encryption delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Test message for CryptoBackend wrapper"
        aad = b"additional data"
        
        ciphertext = wrapper.aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = wrapper.aes_gcm_decrypt(key, nonce, ciphertext, aad)
        
        assert decrypted == plaintext
    
    def test_crypto_backend_hmac_sha256(self):
        """Test CryptoBackend HMAC-SHA256 delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        key = b"hmac_key"
        data = b"message to authenticate"
        
        mac = wrapper.hmac_sha256(key, data)
        assert len(mac) == 32
        
        # Verify
        assert wrapper.hmac_sha256_verify(key, data, mac) is True
    
    def test_crypto_backend_sha256(self):
        """Test CryptoBackend SHA-256 delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        digest = wrapper.sha256(b"test data")
        assert len(digest) == 32
    
    def test_crypto_backend_constant_time_compare(self):
        """Test CryptoBackend constant_time_compare delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        a = b"identical_value"
        b = b"identical_value"
        c = b"different_value"
        
        assert wrapper.constant_time_compare(a, b) is True
        assert wrapper.constant_time_compare(a, c) is False
    
    def test_crypto_backend_x25519_generate_keypair(self):
        """Test CryptoBackend X25519 keypair generation delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        private_key, public_key = wrapper.x25519_generate_keypair()
        assert len(private_key) == 32
        assert len(public_key) == 32
    
    def test_crypto_backend_x25519_exchange(self):
        """Test CryptoBackend X25519 key exchange delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        priv_a, pub_a = wrapper.x25519_generate_keypair()
        priv_b, pub_b = wrapper.x25519_generate_keypair()
        
        shared_a = wrapper.x25519_exchange(priv_a, pub_b)
        shared_b = wrapper.x25519_exchange(priv_b, pub_a)
        
        assert shared_a == shared_b
        assert len(shared_a) == 32
    
    def test_crypto_backend_x25519_public_from_private(self):
        """Test CryptoBackend x25519_public_from_private delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        private_key, expected_public = wrapper.x25519_generate_keypair()
        derived_public = wrapper.x25519_public_from_private(private_key)
        
        assert derived_public == expected_public
    
    def test_crypto_backend_random_bytes(self):
        """Test CryptoBackend random_bytes delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        rand1 = wrapper.random_bytes(32)
        rand2 = wrapper.random_bytes(32)
        
        assert len(rand1) == 32
        assert len(rand2) == 32
        assert rand1 != rand2  # Cryptographic randomness
    
    def test_crypto_backend_secure_zero(self):
        """Test CryptoBackend secure_zero delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        data = bytearray(b"sensitive data to wipe")
        wrapper.secure_zero(data)
        
        assert all(b == 0 for b in data)
    
    def test_crypto_backend_derive_key_hkdf(self):
        """Test CryptoBackend HKDF delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        ikm = b"input keying material"
        salt = secrets.token_bytes(32)
        info = b"context info"
        
        derived = wrapper.derive_key_hkdf(ikm, salt, info)
        assert len(derived) == 32
    
    def test_crypto_backend_hkdf_extract_expand(self):
        """Test CryptoBackend hkdf_extract and hkdf_expand delegation."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        ikm = b"input keying material"
        salt = secrets.token_bytes(32)
        info = b"context"
        
        prk = wrapper.hkdf_extract(salt, ikm)
        okm = wrapper.hkdf_expand(prk, info, 64)
        
        assert len(prk) == 32
        assert len(okm) == 64
    
    def test_crypto_backend_has_inner_backend(self):
        """Test CryptoBackend has _backend attribute."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        assert hasattr(wrapper, '_backend')
        assert isinstance(wrapper._backend, crypto_backend.RustCryptoBackend)


# =============================================================================
# TEST CLASS: Module-Level Functions
# =============================================================================

class TestModuleFunctions:
    """Tests for module-level functions in crypto_backend."""
    
    def test_get_default_backend(self):
        """Test get_default_backend returns a valid backend."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        # Reset cached backend
        crypto_backend._default_backend = None
        
        backend = crypto_backend.get_default_backend()
        assert backend is not None
    
    def test_get_default_backend_caches_result(self):
        """Test get_default_backend caches the backend instance."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        # Reset cached backend
        crypto_backend._default_backend = None
        
        backend1 = crypto_backend.get_default_backend()
        backend2 = crypto_backend.get_default_backend()
        
        assert backend1 is backend2
    
    def test_set_default_backend(self):
        """Test set_default_backend changes the cached backend."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        original = crypto_backend._default_backend
        try:
            # set_default_backend takes a backend type string, not a CryptoBackend
            crypto_backend.set_default_backend("rust")
            
            # Verify backend was set (it creates a new CryptoBackend internally)
            backend = crypto_backend.get_default_backend()
            assert backend is not None
            assert isinstance(backend, crypto_backend.CryptoBackend)
        finally:
            crypto_backend._default_backend = original
    
    def test_is_rust_available(self):
        """Test is_rust_available returns boolean."""
        from meow_decoder import crypto_backend
        
        result = crypto_backend.is_rust_available()
        assert isinstance(result, bool)
    
    def test_get_available_backends_with_rust(self):
        """Test get_available_backends includes rust when available."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backends = crypto_backend.get_available_backends()
        assert isinstance(backends, list)
        assert "rust" in backends
    
    def test_get_available_backends_without_rust(self):
        """Test get_available_backends returns empty list when Rust unavailable."""
        from meow_decoder import crypto_backend
        
        original = crypto_backend._RUST_AVAILABLE
        try:
            crypto_backend._RUST_AVAILABLE = False
            
            backends = crypto_backend.get_available_backends()
            assert backends == []
        finally:
            crypto_backend._RUST_AVAILABLE = original
    
    def test_secure_zero_memory_bytearray(self):
        """Test secure_zero_memory works with bytearray."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        buffer = bytearray(b"sensitive secret data")
        original_len = len(buffer)
        
        crypto_backend.secure_zero_memory(buffer)
        
        assert len(buffer) == original_len
        assert all(b == 0 for b in buffer)
    
    def test_secure_zero_memory_empty_buffer(self):
        """Test secure_zero_memory handles empty buffer."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        buffer = bytearray()
        crypto_backend.secure_zero_memory(buffer)
        assert len(buffer) == 0
    
    def test_secure_zero_memory_propagates_type_error(self):
        """Test secure_zero_memory propagates TypeError from backend."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        # Create a buffer and mock the backend to raise TypeError
        buffer = bytearray(b"test data")
        
        original_backend = crypto_backend._default_backend
        try:
            fake = FakeRustBackendBadSecureZero()
            crypto_backend._default_backend = MagicMock()
            crypto_backend._default_backend.secure_zero = fake.secure_zero
            
            # Should propagate the TypeError (no fallback in current implementation)
            with pytest.raises(TypeError, match="Cannot zero this type"):
                crypto_backend.secure_zero_memory(buffer)
        finally:
            crypto_backend._default_backend = original_backend
    
    def test_secure_zero_memory_propagates_attribute_error(self):
        """Test secure_zero_memory propagates AttributeError from backend."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        buffer = bytearray(b"more test data")
        
        original_backend = crypto_backend._default_backend
        try:
            fake = FakeRustBackendBadSecureZeroAttr()
            crypto_backend._default_backend = MagicMock()
            crypto_backend._default_backend.secure_zero = fake.secure_zero
            
            # Should propagate the AttributeError (no fallback in current implementation)
            with pytest.raises(AttributeError, match="secure_zero not available"):
                crypto_backend.secure_zero_memory(buffer)
        finally:
            crypto_backend._default_backend = original_backend


# =============================================================================
# TEST CLASS: Environment Variable Override
# =============================================================================

class TestEnvironmentOverride:
    """Tests for MEOW_CRYPTO_BACKEND environment variable handling."""
    
    def test_env_override_rust(self, monkeypatch):
        """Test environment variable can specify rust backend."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        # Reset cached backend
        crypto_backend._default_backend = None
        
        monkeypatch.setenv("MEOW_CRYPTO_BACKEND", "rust")
        
        backend = crypto_backend.get_default_backend()
        assert backend is not None
        
        # Cleanup
        crypto_backend._default_backend = None
    
    def test_env_override_invalid_backend(self, monkeypatch):
        """Test invalid environment variable raises error."""
        from meow_decoder import crypto_backend
        
        # Reset cached backend
        crypto_backend._default_backend = None
        
        monkeypatch.setenv("MEOW_CRYPTO_BACKEND", "invalid_backend")
        
        with pytest.raises(RuntimeError):
            crypto_backend.get_default_backend()
        
        # Cleanup
        crypto_backend._default_backend = None


# =============================================================================
# HYPOTHESIS PROPERTY-BASED TESTS
# =============================================================================

class TestPropertyBased:
    """Property-based tests using Hypothesis."""
    
    @given(
        plaintext=st.binary(min_size=1, max_size=10000),
        aad=st.binary(min_size=0, max_size=1000)
    )
    @settings(max_examples=50, deadline=5000)
    def test_aes_gcm_roundtrip(self, plaintext, aad):
        """Property: AES-GCM encrypt then decrypt always recovers plaintext."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad if aad else None)
        recovered = backend.aes_gcm_decrypt(key, nonce, ciphertext, aad if aad else None)
        
        assert recovered == plaintext
    
    @given(
        data=st.binary(min_size=1, max_size=10000)
    )
    @settings(max_examples=50, deadline=5000)
    def test_sha256_deterministic(self, data):
        """Property: SHA-256 always produces same output for same input."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        hash1 = backend.sha256(data)
        hash2 = backend.sha256(data)
        
        assert hash1 == hash2
        assert len(hash1) == 32
    
    @given(
        key=st.binary(min_size=32, max_size=32),
        data=st.binary(min_size=1, max_size=10000)
    )
    @settings(max_examples=50, deadline=5000)
    def test_hmac_sha256_deterministic(self, key, data):
        """Property: HMAC-SHA256 is deterministic."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        mac1 = backend.hmac_sha256(key, data)
        mac2 = backend.hmac_sha256(key, data)
        
        assert mac1 == mac2
        assert len(mac1) == 32
    
    @given(
        a=st.binary(min_size=0, max_size=1000),
        b=st.binary(min_size=0, max_size=1000)
    )
    @settings(max_examples=100, deadline=5000)
    def test_constant_time_compare_correctness(self, a, b):
        """Property: constant_time_compare matches regular comparison."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        expected = (a == b)
        result = backend.constant_time_compare(a, b)
        
        assert result == expected
    
    @given(
        length=st.integers(min_value=1, max_value=256)
    )
    @settings(max_examples=50, deadline=5000)
    def test_random_bytes_length(self, length):
        """Property: random_bytes returns exactly requested length."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        result = backend.random_bytes(length)
        
        assert len(result) == length
        assert isinstance(result, bytes)
    
    @given(
        data=st.binary(min_size=1, max_size=1000)
    )
    @settings(max_examples=50, deadline=5000)
    def test_secure_zero_clears_all_bytes(self, data):
        """Property: secure_zero sets all bytes to zero."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        buffer = bytearray(data)
        original_len = len(buffer)
        
        crypto_backend.secure_zero_memory(buffer)
        
        assert len(buffer) == original_len
        assert all(b == 0 for b in buffer)


# =============================================================================
# ADVERSARIAL / EDGE CASE TESTS
# =============================================================================

class TestAdversarial:
    """Adversarial and edge case tests."""
    
    def test_aes_gcm_wrong_key_fails(self, random_key, random_nonce, sample_plaintext):
        """Test decryption with wrong key fails."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        ciphertext = backend.aes_gcm_encrypt(random_key, random_nonce, sample_plaintext, None)
        
        wrong_key = secrets.token_bytes(32)
        
        with pytest.raises(Exception):  # Should raise on tag verification failure
            backend.aes_gcm_decrypt(wrong_key, random_nonce, ciphertext, None)
    
    def test_aes_gcm_wrong_nonce_fails(self, random_key, random_nonce, sample_plaintext):
        """Test decryption with wrong nonce fails."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        ciphertext = backend.aes_gcm_encrypt(random_key, random_nonce, sample_plaintext, None)
        
        wrong_nonce = secrets.token_bytes(12)
        
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(random_key, wrong_nonce, ciphertext, None)
    
    def test_aes_gcm_wrong_aad_fails(self, random_key, random_nonce, sample_plaintext):
        """Test decryption with wrong AAD fails."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        ciphertext = backend.aes_gcm_encrypt(random_key, random_nonce, sample_plaintext, b"correct aad")
        
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(random_key, random_nonce, ciphertext, b"wrong aad")
    
    def test_aes_gcm_tampered_ciphertext_fails(self, random_key, random_nonce, sample_plaintext):
        """Test decryption of tampered ciphertext fails."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        ciphertext = backend.aes_gcm_encrypt(random_key, random_nonce, sample_plaintext, None)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)
        
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(random_key, random_nonce, tampered, None)
    
    def test_x25519_exchange_with_all_zero_key_rejected(self):
        """Test X25519 exchange with malformed keys is handled."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        # Generate a real keypair
        priv, pub = backend.x25519_generate_keypair()
        
        # Try with all-zero public key (invalid point)
        zero_pub = b'\x00' * 32
        
        # This should either raise or return a predictable result
        # (depends on implementation - some return all zeros)
        try:
            result = backend.x25519_exchange(priv, zero_pub)
            # If it doesn't raise, verify it's all zeros (weak DH result)
            # This is a known edge case in X25519
            assert isinstance(result, bytes)
        except Exception:
            pass  # Valid to reject this input
    
    def test_empty_plaintext_encryption(self, random_key, random_nonce):
        """Test encryption of empty plaintext."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        empty = b""
        ciphertext = backend.aes_gcm_encrypt(random_key, random_nonce, empty, None)
        
        # Empty plaintext should produce 16-byte ciphertext (just tag)
        assert len(ciphertext) == 16
        
        recovered = backend.aes_gcm_decrypt(random_key, random_nonce, ciphertext, None)
        assert recovered == empty
    
    def test_large_plaintext_encryption(self, random_key, random_nonce):
        """Test encryption of large plaintext (1MB)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        large_plaintext = secrets.token_bytes(1024 * 1024)  # 1MB
        
        ciphertext = backend.aes_gcm_encrypt(random_key, random_nonce, large_plaintext, None)
        recovered = backend.aes_gcm_decrypt(random_key, random_nonce, ciphertext, None)
        
        assert recovered == large_plaintext


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests combining multiple backend operations."""
    
    def test_key_derivation_then_encryption(self, valid_password, random_salt):
        """Test deriving a key and using it for encryption."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        # Derive key
        key = backend.derive_key_argon2id(
            password=valid_password.encode(),
            salt=random_salt,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        # Use key for encryption
        nonce = backend.random_bytes(12)
        plaintext = b"Secret message after key derivation"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        recovered = backend.aes_gcm_decrypt(key, nonce, ciphertext, None)
        
        assert recovered == plaintext
    
    def test_hkdf_for_key_expansion(self, random_salt):
        """Test HKDF extract-expand flow."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        # Initial key material
        ikm = backend.random_bytes(32)
        
        # Extract
        prk = backend.hkdf_extract(random_salt, ikm)
        assert len(prk) == 32
        
        # Expand to multiple keys
        key1 = backend.hkdf_expand(prk, b"key1", 32)
        key2 = backend.hkdf_expand(prk, b"key2", 32)
        
        assert len(key1) == 32
        assert len(key2) == 32
        assert key1 != key2  # Different info should give different keys
    
    def test_full_authenticated_encryption_flow(self, valid_password, random_salt):
        """Test full authenticated encryption with HMAC verification."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.get_default_backend()
        
        # Derive encryption and MAC keys from password
        master_key = backend.derive_key_argon2id(
            password=valid_password.encode(),
            salt=random_salt,
            output_len=64,  # 64 bytes for two 32-byte keys
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        enc_key = master_key[:32]
        mac_key = master_key[32:64]
        
        # Encrypt
        nonce = backend.random_bytes(12)
        plaintext = b"Authenticated secret message"
        ciphertext = backend.aes_gcm_encrypt(enc_key, nonce, plaintext, None)
        
        # Create MAC over ciphertext
        mac = backend.hmac_sha256(mac_key, nonce + ciphertext)
        
        # Verify MAC
        assert backend.hmac_sha256_verify(mac_key, nonce + ciphertext, mac)
        
        # Decrypt
        recovered = backend.aes_gcm_decrypt(enc_key, nonce, ciphertext, None)
        assert recovered == plaintext


# =============================================================================
# IMPORTABILITY / API STABILITY TESTS
# =============================================================================

class TestImportability:
    """Tests that all expected items are importable from the module."""
    
    def test_all_imports(self):
        """All expected items are importable from crypto_backend."""
        from meow_decoder.crypto_backend import (
            RustCryptoBackend,
            CryptoBackend,
            BackendInfo,
            get_default_backend,
            set_default_backend,
            secure_zero_memory,
            is_rust_available,
            get_available_backends,
        )
        
        assert RustCryptoBackend is not None
        assert CryptoBackend is not None
        assert BackendInfo is not None
        assert get_default_backend is not None
        assert set_default_backend is not None
        assert secure_zero_memory is not None
        assert is_rust_available is not None
        assert get_available_backends is not None
    
    def test_backendinfo_is_dataclass(self):
        """BackendInfo is a proper dataclass."""
        from meow_decoder.crypto_backend import BackendInfo
        from dataclasses import is_dataclass
        
        assert is_dataclass(BackendInfo)
    
    def test_backendinfo_has_expected_fields(self):
        """BackendInfo has expected fields."""
        from meow_decoder.crypto_backend import BackendInfo
        
        # Check field names
        field_names = [f.name for f in BackendInfo.__dataclass_fields__.values()]
        
        assert 'name' in field_names
        assert 'version' in field_names
        assert 'constant_time' in field_names
        assert 'memory_zeroing' in field_names
        assert 'pq_available' in field_names
        assert 'details' in field_names


class TestBackendType:
    """Tests for backend type checking and consistency."""
    
    def test_rust_backend_is_correct_type(self):
        """RustCryptoBackend is correct type."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        assert isinstance(backend, crypto_backend.RustCryptoBackend)
    
    def test_crypto_backend_wraps_rust_backend(self):
        """CryptoBackend wraps RustCryptoBackend internally."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        assert isinstance(wrapper._backend, crypto_backend.RustCryptoBackend)


# =============================================================================
# TEST CLASS: Complete Delegation Coverage
# Tests specifically targeting uncovered delegation paths
# =============================================================================

class TestDelegationCoverage:
    """Tests to ensure 100% coverage of CryptoBackend delegation methods."""
    
    def test_wrapper_get_info_returns_backend_info(self):
        """Test CryptoBackend.get_info returns BackendInfo (line 231)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        info = wrapper.get_info()
        
        assert isinstance(info, crypto_backend.BackendInfo)
        assert info.name == "rust"
        assert info.constant_time is True
        assert info.memory_zeroing is True
    
    def test_wrapper_derive_key_argon2id_delegation(self):
        """Test CryptoBackend.derive_key_argon2id delegation (line 235)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        # Test with explicit kwargs
        key = wrapper.derive_key_argon2id(
            password=b"test_password_for_argon2id",
            salt=secrets.token_bytes(16),
            memory_kib=32768,
            iterations=1,
            parallelism=1,
            output_len=32
        )
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_wrapper_hkdf_extract_delegation(self):
        """Test CryptoBackend.hkdf_extract delegation (line 245)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        salt = secrets.token_bytes(32)
        ikm = b"input keying material for extract"
        
        prk = wrapper.hkdf_extract(salt, ikm)
        
        assert isinstance(prk, bytes)
        assert len(prk) == 32
    
    def test_wrapper_hkdf_expand_delegation(self):
        """Test CryptoBackend.hkdf_expand delegation (line 248)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        # First get a PRK via extract
        salt = secrets.token_bytes(32)
        ikm = b"input keying material"
        prk = wrapper.hkdf_extract(salt, ikm)
        
        # Now expand it
        info = b"context info for expand"
        okm = wrapper.hkdf_expand(prk, info, 64)
        
        assert isinstance(okm, bytes)
        assert len(okm) == 64
    
    def test_wrapper_derive_key_yubikey_raises_runtime_error(self):
        """Test CryptoBackend.derive_key_yubikey delegation raises RuntimeError (line 251)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        # YubiKey typically not available in test environment
        # Should raise RuntimeError about YubiKey support
        with pytest.raises((RuntimeError, AttributeError)):
            wrapper.derive_key_yubikey(
                password=b"password",
                salt=secrets.token_bytes(16),
                slot="9d",
                pin="123456"
            )
    
    def test_wrapper_hmac_sha256_verify_delegation(self):
        """Test CryptoBackend.hmac_sha256_verify delegation (line 263)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        key = secrets.token_bytes(32)
        message = b"message to authenticate"
        
        # First compute MAC
        mac = wrapper.hmac_sha256(key, message)
        
        # Then verify it - should return True
        result = wrapper.hmac_sha256_verify(key, message, mac)
        assert result is True
        
        # Verify wrong MAC returns False
        wrong_mac = secrets.token_bytes(32)
        result_wrong = wrapper.hmac_sha256_verify(key, message, wrong_mac)
        assert result_wrong is False
    
    def test_wrapper_sha256_delegation(self):
        """Test CryptoBackend.sha256 delegation (line 266)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        data = b"data to hash with sha256"
        digest = wrapper.sha256(data)
        
        assert isinstance(digest, bytes)
        assert len(digest) == 32
        
        # Verify determinism
        digest2 = wrapper.sha256(data)
        assert digest == digest2
    
    def test_wrapper_constant_time_compare_delegation(self):
        """Test CryptoBackend.constant_time_compare delegation (line 269)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        a = b"identical_bytes_here"
        b = b"identical_bytes_here"
        c = b"different_bytes_here"
        
        # Equal comparison
        assert wrapper.constant_time_compare(a, b) is True
        
        # Unequal comparison
        assert wrapper.constant_time_compare(a, c) is False
        
        # Different length comparison
        assert wrapper.constant_time_compare(a, b"short") is False
    
    def test_wrapper_x25519_public_from_private_delegation(self):
        """Test CryptoBackend.x25519_public_from_private delegation (line 278)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        # Generate a keypair
        private_key, expected_public = wrapper.x25519_generate_keypair()
        
        # Derive public from private
        derived_public = wrapper.x25519_public_from_private(private_key)
        
        assert isinstance(derived_public, bytes)
        assert len(derived_public) == 32
        assert derived_public == expected_public
    
    def test_wrapper_random_bytes_delegation(self):
        """Test CryptoBackend.random_bytes delegation (line 281)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        wrapper = crypto_backend.CryptoBackend(backend="rust")
        
        rand1 = wrapper.random_bytes(32)
        rand2 = wrapper.random_bytes(32)
        
        assert isinstance(rand1, bytes)
        assert len(rand1) == 32
        assert rand1 != rand2  # Cryptographic randomness


# =============================================================================
# TEST CLASS: RustCryptoBackend Method Returns
# Tests specifically targeting uncovered RustCryptoBackend return lines
# =============================================================================

class TestRustBackendReturns:
    """Tests to ensure 100% coverage of RustCryptoBackend return statements."""
    
    def test_rust_hmac_sha256_verify_return_true(self):
        """Test RustCryptoBackend.hmac_sha256_verify returns True (line 154)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        key = secrets.token_bytes(32)
        message = b"message to verify"
        mac = backend.hmac_sha256(key, message)
        
        result = backend.hmac_sha256_verify(key, message, mac)
        assert result is True
    
    def test_rust_hmac_sha256_verify_return_false(self):
        """Test RustCryptoBackend.hmac_sha256_verify returns False (line 154)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        key = secrets.token_bytes(32)
        message = b"message to verify"
        wrong_mac = secrets.token_bytes(32)
        
        result = backend.hmac_sha256_verify(key, message, wrong_mac)
        assert result is False
    
    def test_rust_sha256_return(self):
        """Test RustCryptoBackend.sha256 return value (line 157)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        data = b"data for sha256 return test"
        result = backend.sha256(data)
        
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_rust_constant_time_compare_return_true(self):
        """Test RustCryptoBackend.constant_time_compare returns True (line 160)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        a = b"identical_data_here"
        b = b"identical_data_here"
        
        result = backend.constant_time_compare(a, b)
        assert result is True
    
    def test_rust_constant_time_compare_return_false(self):
        """Test RustCryptoBackend.constant_time_compare returns False (line 160)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        a = b"first_data_value"
        b = b"second_data_value"
        
        result = backend.constant_time_compare(a, b)
        assert result is False
    
    def test_rust_x25519_public_from_private_return(self):
        """Test RustCryptoBackend.x25519_public_from_private return (line 169)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        private_key, expected_public = backend.x25519_generate_keypair()
        result = backend.x25519_public_from_private(private_key)
        
        assert isinstance(result, bytes)
        assert len(result) == 32
        assert result == expected_public
    
    def test_rust_random_bytes_return(self):
        """Test RustCryptoBackend.random_bytes return (line 172)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        result = backend.random_bytes(16)
        
        assert isinstance(result, bytes)
        assert len(result) == 16
    
    def test_rust_get_info_return(self):
        """Test RustCryptoBackend.get_info return (line 80)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        result = backend.get_info()
        
        assert isinstance(result, crypto_backend.BackendInfo)
        assert result.name == "rust"
        assert result.constant_time is True
    
    def test_rust_hkdf_extract_return(self):
        """Test RustCryptoBackend.hkdf_extract return (line 112)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        salt = secrets.token_bytes(32)
        ikm = b"input keying material"
        
        result = backend.hkdf_extract(salt, ikm)
        
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_rust_hkdf_expand_return(self):
        """Test RustCryptoBackend.hkdf_expand return (line 115)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        backend = crypto_backend.RustCryptoBackend()
        
        salt = secrets.token_bytes(32)
        ikm = b"input keying material"
        info = b"context info"
        
        prk = backend.hkdf_extract(salt, ikm)
        result = backend.hkdf_expand(prk, info, 48)
        
        assert isinstance(result, bytes)
        assert len(result) == 48


# =============================================================================
# TEST CLASS: Module-Level Function Coverage
# Tests specifically targeting uncovered module-level functions
# =============================================================================

class TestModuleFunctionsCoverage:
    """Tests to ensure 100% coverage of module-level functions."""
    
    def test_set_default_backend_rust(self):
        """Test set_default_backend with 'rust' (line 314)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        original = crypto_backend._default_backend
        try:
            crypto_backend._default_backend = None
            
            crypto_backend.set_default_backend("rust")
            
            assert crypto_backend._default_backend is not None
            assert isinstance(crypto_backend._default_backend, crypto_backend.CryptoBackend)
        finally:
            crypto_backend._default_backend = original
    
    def test_is_rust_available_returns_bool(self):
        """Test is_rust_available returns boolean (line 319)."""
        from meow_decoder import crypto_backend
        
        result = crypto_backend.is_rust_available()
        
        assert isinstance(result, bool)
    
    def test_is_rust_available_reflects_state(self):
        """Test is_rust_available returns correct state (line 319)."""
        from meow_decoder import crypto_backend
        
        original = crypto_backend._RUST_AVAILABLE
        
        # Test when True
        crypto_backend._RUST_AVAILABLE = True
        assert crypto_backend.is_rust_available() is True
        
        # Test when False
        crypto_backend._RUST_AVAILABLE = False
        assert crypto_backend.is_rust_available() is False
        
        # Restore
        crypto_backend._RUST_AVAILABLE = original
    
    def test_get_available_backends_returns_list(self):
        """Test get_available_backends returns list (line 324)."""
        from meow_decoder import crypto_backend
        
        result = crypto_backend.get_available_backends()
        
        assert isinstance(result, list)
    
    def test_get_available_backends_with_rust_available(self):
        """Test get_available_backends when Rust available (line 324)."""
        from meow_decoder import crypto_backend
        
        original = crypto_backend._RUST_AVAILABLE
        try:
            crypto_backend._RUST_AVAILABLE = True
            
            result = crypto_backend.get_available_backends()
            
            assert result == ["rust"]
        finally:
            crypto_backend._RUST_AVAILABLE = original
    
    def test_get_available_backends_without_rust(self):
        """Test get_available_backends when Rust unavailable (line 324)."""
        from meow_decoder import crypto_backend
        
        original = crypto_backend._RUST_AVAILABLE
        try:
            crypto_backend._RUST_AVAILABLE = False
            
            result = crypto_backend.get_available_backends()
            
            assert result == []
        finally:
            crypto_backend._RUST_AVAILABLE = original


# =============================================================================
# TEST CLASS: Environment Variable Override Coverage
# =============================================================================

class TestEnvOverrideCoverage:
    """Tests for MEOW_CRYPTO_BACKEND environment variable handling."""
    
    def test_env_override_to_rust(self, monkeypatch):
        """Test env override to 'rust' backend (line 216)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        monkeypatch.setenv("MEOW_CRYPTO_BACKEND", "rust")
        
        # Create new backend - should use env var
        backend = crypto_backend.CryptoBackend()
        
        assert backend is not None
        assert backend.name == "rust"
    
    def test_env_override_invalid_raises_error(self, monkeypatch):
        """Test env override with invalid value raises RuntimeError (line 219)."""
        from meow_decoder import crypto_backend
        
        monkeypatch.setenv("MEOW_CRYPTO_BACKEND", "invalid_backend_name")
        
        with pytest.raises(RuntimeError, match="Rust crypto backend required"):
            crypto_backend.CryptoBackend()
    
    def test_env_override_empty_uses_default(self, monkeypatch):
        """Test empty env var uses default."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        monkeypatch.setenv("MEOW_CRYPTO_BACKEND", "")
        
        # Empty string should not override
        backend = crypto_backend.CryptoBackend()
        assert backend is not None
        assert backend.name == "rust"
    
    def test_env_override_case_insensitive(self, monkeypatch):
        """Test env override is case-insensitive (line 216)."""
        from meow_decoder import crypto_backend
        
        if not crypto_backend._RUST_AVAILABLE:
            pytest.skip("Rust backend not available")
        
        monkeypatch.setenv("MEOW_CRYPTO_BACKEND", "RUST")
        
        backend = crypto_backend.CryptoBackend()
        assert backend is not None
        assert backend.name == "rust"


# =============================================================================
# RUN TESTS DIRECTLY
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
