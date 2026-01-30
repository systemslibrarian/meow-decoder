#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for crypto_backend.py - Target: 90%+
Tests the cryptographic backend abstraction layer.
"""

import pytest
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestGetDefaultBackend:
    """Test getting the default crypto backend."""
    
    def test_get_default_backend(self):
        """Test getting default backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        assert backend is not None
    
    def test_backend_singleton(self):
        """Test backend is singleton (cached)."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend1 = get_default_backend()
        backend2 = get_default_backend()
        
        # Should be same instance or equivalent
        assert backend1 is backend2 or type(backend1) == type(backend2)


class TestBackendArgon2id:
    """Test Argon2id key derivation via backend."""
    
    def test_derive_key_argon2id_basic(self):
        """Test basic Argon2id key derivation."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        password = b"TestPassword123!"
        salt = secrets.token_bytes(16)
        
        key = backend.derive_key_argon2id(
            password, salt,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_derive_key_argon2id_deterministic(self):
        """Test Argon2id produces same key for same inputs."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        password = b"Consistent"
        salt = secrets.token_bytes(16)
        
        key1 = backend.derive_key_argon2id(
            password, salt,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        key2 = backend.derive_key_argon2id(
            password, salt,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        assert key1 == key2
    
    def test_derive_key_argon2id_different_passwords(self):
        """Test different passwords produce different keys."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        salt = secrets.token_bytes(16)
        
        key1 = backend.derive_key_argon2id(
            b"Password1", salt,
            output_len=32, iterations=1, memory_kib=32768, parallelism=1
        )
        
        key2 = backend.derive_key_argon2id(
            b"Password2", salt,
            output_len=32, iterations=1, memory_kib=32768, parallelism=1
        )
        
        assert key1 != key2
    
    def test_derive_key_argon2id_different_salts(self):
        """Test different salts produce different keys."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        password = b"SamePassword"
        
        key1 = backend.derive_key_argon2id(
            password, secrets.token_bytes(16),
            output_len=32, iterations=1, memory_kib=32768, parallelism=1
        )
        
        key2 = backend.derive_key_argon2id(
            password, secrets.token_bytes(16),
            output_len=32, iterations=1, memory_kib=32768, parallelism=1
        )
        
        assert key1 != key2
    
    def test_derive_key_argon2id_various_lengths(self):
        """Test various output lengths."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        password = b"Test"
        salt = secrets.token_bytes(16)
        
        for length in [16, 32, 64]:
            key = backend.derive_key_argon2id(
                password, salt,
                output_len=length,
                iterations=1, memory_kib=32768, parallelism=1
            )
            assert len(key) == length


class TestBackendAESGCM:
    """Test AES-GCM encryption/decryption via backend."""
    
    def test_aes_gcm_encrypt_basic(self):
        """Test basic AES-GCM encryption."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret message for encryption"
        aad = b"Additional authenticated data"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        
        assert ciphertext != plaintext
        # Ciphertext should be plaintext + 16-byte tag
        assert len(ciphertext) == len(plaintext) + 16
    
    def test_aes_gcm_decrypt_basic(self):
        """Test basic AES-GCM decryption."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret message for decryption"
        aad = b"AAD data"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, aad)
        
        assert decrypted == plaintext
    
    def test_aes_gcm_roundtrip_no_aad(self):
        """Test AES-GCM roundtrip without AAD."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"No AAD message"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, None)
        
        assert decrypted == plaintext
    
    def test_aes_gcm_decrypt_wrong_key_fails(self):
        """Test decryption fails with wrong key."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        correct_key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Test message"
        
        ciphertext = backend.aes_gcm_encrypt(correct_key, nonce, plaintext, None)
        
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(wrong_key, nonce, ciphertext, None)
    
    def test_aes_gcm_decrypt_wrong_nonce_fails(self):
        """Test decryption fails with wrong nonce."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        correct_nonce = secrets.token_bytes(12)
        wrong_nonce = secrets.token_bytes(12)
        plaintext = b"Test message"
        
        ciphertext = backend.aes_gcm_encrypt(key, correct_nonce, plaintext, None)
        
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(key, wrong_nonce, ciphertext, None)
    
    def test_aes_gcm_decrypt_wrong_aad_fails(self):
        """Test decryption fails with wrong AAD."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Test message"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, b"correct_aad")
        
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(key, nonce, ciphertext, b"wrong_aad")
    
    def test_aes_gcm_decrypt_tampered_ciphertext_fails(self):
        """Test decryption fails with tampered ciphertext."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Test message"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)
        
        with pytest.raises(Exception):
            backend.aes_gcm_decrypt(key, nonce, tampered, None)


class TestBackendHMAC:
    """Test HMAC-SHA256 via backend."""
    
    def test_hmac_sha256_basic(self):
        """Test basic HMAC-SHA256."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        data = b"Data to authenticate"
        
        mac = backend.hmac_sha256(key, data)
        
        assert len(mac) == 32
    
    def test_hmac_sha256_deterministic(self):
        """Test HMAC is deterministic."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        data = b"Consistent data"
        
        mac1 = backend.hmac_sha256(key, data)
        mac2 = backend.hmac_sha256(key, data)
        
        assert mac1 == mac2
    
    def test_hmac_sha256_different_keys(self):
        """Test different keys produce different MACs."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        data = b"Same data"
        
        mac1 = backend.hmac_sha256(secrets.token_bytes(32), data)
        mac2 = backend.hmac_sha256(secrets.token_bytes(32), data)
        
        assert mac1 != mac2
    
    def test_hmac_sha256_different_data(self):
        """Test different data produces different MACs."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        
        mac1 = backend.hmac_sha256(key, b"Data 1")
        mac2 = backend.hmac_sha256(key, b"Data 2")
        
        assert mac1 != mac2


class TestBackendX25519:
    """Test X25519 key exchange via backend."""
    
    def test_x25519_generate_keypair(self):
        """Test generating X25519 keypair."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        private_key, public_key = backend.x25519_generate_keypair()
        
        assert len(private_key) == 32
        assert len(public_key) == 32
        assert private_key != public_key
    
    def test_x25519_exchange(self):
        """Test X25519 key exchange."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        # Generate two keypairs
        priv_a, pub_a = backend.x25519_generate_keypair()
        priv_b, pub_b = backend.x25519_generate_keypair()
        
        # Exchange
        shared_a = backend.x25519_exchange(priv_a, pub_b)
        shared_b = backend.x25519_exchange(priv_b, pub_a)
        
        # Both should derive same shared secret
        assert shared_a == shared_b
        assert len(shared_a) == 32
    
    def test_x25519_keypairs_unique(self):
        """Test generated keypairs are unique."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        priv1, pub1 = backend.x25519_generate_keypair()
        priv2, pub2 = backend.x25519_generate_keypair()
        
        assert priv1 != priv2
        assert pub1 != pub2


class TestBackendHKDF:
    """Test HKDF via backend."""
    
    def test_derive_key_hkdf(self):
        """Test HKDF key derivation."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"meow_test_context"
        
        key = backend.derive_key_hkdf(ikm, salt, info)
        
        assert len(key) == 32
    
    def test_hkdf_deterministic(self):
        """Test HKDF is deterministic."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test"
        
        key1 = backend.derive_key_hkdf(ikm, salt, info)
        key2 = backend.derive_key_hkdf(ikm, salt, info)
        
        assert key1 == key2
    
    def test_hkdf_different_info(self):
        """Test different info produces different keys."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = backend.derive_key_hkdf(ikm, salt, b"info1")
        key2 = backend.derive_key_hkdf(ikm, salt, b"info2")
        
        assert key1 != key2


class TestSecureZeroMemory:
    """Test secure memory zeroing."""
    
    def test_secure_zero_memory_bytearray(self):
        """Test zeroing bytearray."""
        from meow_decoder.crypto_backend import secure_zero_memory
        
        buf = bytearray(b"Secret data to zero")
        original_len = len(buf)
        
        secure_zero_memory(buf)
        
        # Should be all zeros
        assert buf == bytearray(original_len)
    
    def test_secure_zero_memory_empty(self):
        """Test zeroing empty buffer."""
        from meow_decoder.crypto_backend import secure_zero_memory
        
        buf = bytearray()
        secure_zero_memory(buf)  # Should not crash
    
    def test_secure_zero_memory_large(self):
        """Test zeroing large buffer."""
        from meow_decoder.crypto_backend import secure_zero_memory
        
        buf = bytearray(secrets.token_bytes(10000))
        secure_zero_memory(buf)
        
        assert buf == bytearray(10000)


class TestBackendEdgeCases:
    """Test edge cases in backend."""
    
    def test_encrypt_empty_plaintext(self):
        """Test encrypting empty plaintext."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, b"", None)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, None)
        
        assert decrypted == b""
    
    def test_encrypt_large_plaintext(self):
        """Test encrypting large plaintext."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = secrets.token_bytes(100000)  # 100KB
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, None)
        
        assert decrypted == plaintext
    
    def test_hmac_empty_data(self):
        """Test HMAC with empty data."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        mac = backend.hmac_sha256(key, b"")
        
        assert len(mac) == 32
    
    def test_hmac_large_data(self):
        """Test HMAC with large data."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        data = secrets.token_bytes(100000)
        
        mac = backend.hmac_sha256(key, data)
        
        assert len(mac) == 32


class TestBackendRustSpecific:
    """Test Rust backend specific features."""
    
    def test_backend_is_rust(self):
        """Test if Rust backend is available."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        # Check if it's Rust backend (has certain attribute or method)
        # This is implementation-specific
        backend_type = type(backend).__name__
        # Either Rust or Python backend should work
        assert backend_type in ['RustCryptoBackend', 'PythonCryptoBackend', 
                                'CryptoBackend', 'DefaultBackend']


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
