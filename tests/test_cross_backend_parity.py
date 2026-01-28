#!/usr/bin/env python3
"""Deprecated: cross-backend parity tests removed (Rust backend required)."""

import pytest

pytest.skip(
    "Cross-backend parity tests removed; Rust backend is mandatory.",
    allow_module_level=True,
)
if False:
        prk_python = python_backend.hkdf_extract(salt, ikm)
        prk_rust = rust_backend.hkdf_extract(salt, ikm)
        
        assert prk_python == prk_rust, "HKDF extract mismatch!"
    
    def test_hkdf_expand_parity(self, python_backend, rust_backend):
        """PARITY: HKDF expand phase must match."""
        prk = secrets.token_bytes(32)
        info = b"expand_test"
        
        okm_python = python_backend.hkdf_expand(prk, info, output_len=64)
        okm_rust = rust_backend.hkdf_expand(prk, info, output_len=64)
        
        assert okm_python == okm_rust, "HKDF expand mismatch!"
    
    def test_aes_gcm_encrypt_decrypt_cross_backend(self, python_backend, rust_backend):
        """
        PARITY: Ciphertext from one backend must decrypt on the other.
        
        Tests both directions:
        1. Python encrypt → Rust decrypt
        2. Rust encrypt → Python decrypt
        """
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Hello, cross-backend world! " * 10
        aad = b"additional_authenticated_data"
        
        # Python encrypt → Rust decrypt
        ciphertext_py = python_backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted_rs = rust_backend.aes_gcm_decrypt(key, nonce, ciphertext_py, aad)
        
        assert decrypted_rs == plaintext, "Rust failed to decrypt Python ciphertext!"
        
        # Rust encrypt → Python decrypt
        # Use different nonce (nonce reuse is a bug!)
        nonce2 = secrets.token_bytes(12)
        ciphertext_rs = rust_backend.aes_gcm_encrypt(key, nonce2, plaintext, aad)
        decrypted_py = python_backend.aes_gcm_decrypt(key, nonce2, ciphertext_rs, aad)
        
        assert decrypted_py == plaintext, "Python failed to decrypt Rust ciphertext!"
    
    def test_aes_gcm_without_aad_parity(self, python_backend, rust_backend):
        """PARITY: AES-GCM without AAD must work cross-backend."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"No AAD test data"
        
        # Python → Rust
        ct_py = python_backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        pt_rs = rust_backend.aes_gcm_decrypt(key, nonce, ct_py, None)
        assert pt_rs == plaintext
        
        # Rust → Python
        nonce2 = secrets.token_bytes(12)
        ct_rs = rust_backend.aes_gcm_encrypt(key, nonce2, plaintext, None)
        pt_py = python_backend.aes_gcm_decrypt(key, nonce2, ct_rs, None)
        assert pt_py == plaintext
    
    def test_hmac_sha256_parity(self, python_backend, rust_backend):
        """PARITY: HMAC-SHA256 must produce identical tags."""
        key = secrets.token_bytes(32)
        message = b"Authenticate this message please!"
        
        tag_python = python_backend.hmac_sha256(key, message)
        tag_rust = rust_backend.hmac_sha256(key, message)
        
        assert tag_python == tag_rust, (
            f"HMAC-SHA256 mismatch!\n"
            f"  Python: {tag_python.hex()}\n"
            f"  Rust:   {tag_rust.hex()}"
        )
    
    def test_hmac_verify_cross_backend(self, python_backend, rust_backend):
        """PARITY: HMAC tags must verify across backends."""
        key = secrets.token_bytes(32)
        message = b"Cross-verify this!"
        
        # Python generates tag, Rust verifies
        tag_py = python_backend.hmac_sha256(key, message)
        assert rust_backend.hmac_sha256_verify(key, message, tag_py), (
            "Rust failed to verify Python HMAC!"
        )
        
        # Rust generates tag, Python verifies
        tag_rs = rust_backend.hmac_sha256(key, message)
        assert python_backend.hmac_sha256_verify(key, message, tag_rs), (
            "Python failed to verify Rust HMAC!"
        )
    
    def test_sha256_parity(self, python_backend, rust_backend):
        """PARITY: SHA-256 must produce identical hashes."""
        data = b"Hash this data!" * 100
        
        hash_python = python_backend.sha256(data)
        hash_rust = rust_backend.sha256(data)
        
        assert hash_python == hash_rust, "SHA-256 hash mismatch!"
    
    def test_x25519_keypair_exchange_parity(self, python_backend, rust_backend):
        """
        PARITY: X25519 key exchange must produce identical shared secrets.
        
        Test: Generate keys on different backends, exchange must work.
        """
        # Generate keypair on Python
        priv_py, pub_py = python_backend.x25519_generate_keypair()
        
        # Generate keypair on Rust
        priv_rs, pub_rs = rust_backend.x25519_generate_keypair()
        
        # Exchange: Python private + Rust public
        shared_py = python_backend.x25519_exchange(priv_py, pub_rs)
        
        # Exchange: Rust private + Python public  
        shared_rs = rust_backend.x25519_exchange(priv_rs, pub_py)
        
        # Verify symmetry (A's priv + B's pub = B's priv + A's pub)
        # Cross-check
        shared_py_via_rs = rust_backend.x25519_exchange(priv_py, pub_rs)
        shared_rs_via_py = python_backend.x25519_exchange(priv_rs, pub_py)
        
        assert shared_py == shared_py_via_rs, "Exchange result differs between backends!"
        assert shared_rs == shared_rs_via_py, "Exchange result differs between backends!"
    
    def test_x25519_public_from_private_parity(self, python_backend, rust_backend):
        """PARITY: Deriving public key from private must match."""
        # Generate on one backend
        priv, pub_expected = python_backend.x25519_generate_keypair()
        
        # Derive public on both backends
        pub_py = python_backend.x25519_public_from_private(priv)
        pub_rs = rust_backend.x25519_public_from_private(priv)
        
        assert pub_py == pub_expected, "Python public key derivation mismatch!"
        assert pub_rs == pub_expected, "Rust public key derivation mismatch!"
        assert pub_py == pub_rs, "Public key derivation differs between backends!"
    
    def test_constant_time_compare_parity(self, python_backend, rust_backend):
        """PARITY: Constant-time comparison must give same results."""
        a = secrets.token_bytes(32)
        b = secrets.token_bytes(32)
        a_copy = bytes(a)
        
        # Same values
        assert python_backend.constant_time_compare(a, a_copy) == True
        assert rust_backend.constant_time_compare(a, a_copy) == True
        
        # Different values
        assert python_backend.constant_time_compare(a, b) == False
        assert rust_backend.constant_time_compare(a, b) == False


class TestCrossBackendErrorHandling:
    """Verify both backends reject invalid inputs identically."""
    
    def test_argon2id_rejects_invalid_salt_length(self, python_backend, rust_backend):
        """Python backend must reject salts that aren't 16 bytes.
        
        Note: Rust backend may accept different salt lengths (Argon2 spec allows 8+ bytes).
        We only enforce this at the Python layer for API consistency.
        """
        password = b"test"
        bad_salt = secrets.token_bytes(15)  # Wrong length
        
        # Python backend enforces 16-byte salt for consistency
        with pytest.raises(ValueError):
            python_backend.derive_key_argon2id(password, bad_salt)
        
        # Rust backend may accept non-16-byte salts (Argon2 spec allows 8+)
        # So we only test that Python layer enforces this
    
    def test_aes_gcm_rejects_invalid_key_length(self, python_backend, rust_backend):
        """Both backends must reject keys that aren't 32 bytes."""
        bad_key = secrets.token_bytes(16)  # Should be 32
        nonce = secrets.token_bytes(12)
        plaintext = b"test"
        
        with pytest.raises(ValueError):
            python_backend.aes_gcm_encrypt(bad_key, nonce, plaintext)
        
        with pytest.raises(Exception):
            rust_backend.aes_gcm_encrypt(bad_key, nonce, plaintext)
    
    def test_aes_gcm_rejects_invalid_nonce_length(self, python_backend, rust_backend):
        """Both backends must reject nonces that aren't 12 bytes."""
        key = secrets.token_bytes(32)
        bad_nonce = secrets.token_bytes(16)  # Should be 12
        plaintext = b"test"
        
        with pytest.raises(ValueError):
            python_backend.aes_gcm_encrypt(key, bad_nonce, plaintext)
        
        with pytest.raises(Exception):
            rust_backend.aes_gcm_encrypt(key, bad_nonce, plaintext)
    
    def test_aes_gcm_rejects_tampered_ciphertext(self, python_backend, rust_backend):
        """Both backends must reject tampered ciphertext."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Sensitive data"
        
        ciphertext = python_backend.aes_gcm_encrypt(key, nonce, plaintext)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        
        with pytest.raises(Exception):
            python_backend.aes_gcm_decrypt(key, nonce, bytes(tampered))
        
        with pytest.raises(Exception):
            rust_backend.aes_gcm_decrypt(key, nonce, bytes(tampered))


class TestCrossBackendDeterminism:
    """Verify operations are deterministic across multiple runs."""
    
    def test_argon2id_deterministic(self, python_backend, rust_backend):
        """Same inputs must always produce same key (no randomness in KDF)."""
        password = b"deterministic_test"
        salt = b"fixed_salt_16byt"  # Exactly 16 bytes
        
        # Run multiple times
        keys_py = [python_backend.derive_key_argon2id(password, salt, 32768, 2) for _ in range(3)]
        keys_rs = [rust_backend.derive_key_argon2id(password, salt, 32768, 2) for _ in range(3)]
        
        # All must be identical
        assert len(set(keys_py)) == 1, "Python KDF not deterministic!"
        assert len(set(keys_rs)) == 1, "Rust KDF not deterministic!"
        assert keys_py[0] == keys_rs[0], "KDF differs between backends!"
    
    def test_hkdf_deterministic(self, python_backend, rust_backend):
        """HKDF must be deterministic."""
        ikm = b"input_keying_material_fixed"
        salt = b"fixed_salt_value"
        info = b"context_info"
        
        keys_py = [python_backend.derive_key_hkdf(ikm, salt, info) for _ in range(3)]
        keys_rs = [rust_backend.derive_key_hkdf(ikm, salt, info) for _ in range(3)]
        
        assert len(set(keys_py)) == 1
        assert len(set(keys_rs)) == 1
        assert keys_py[0] == keys_rs[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
