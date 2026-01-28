"""Deprecated: replaced by test_crypto_backend_rust.py (Rust-only)."""

import pytest

pytest.skip(
    "Deprecated: replaced by test_crypto_backend_rust.py.",
    allow_module_level=True,
)

import secrets
from typing import Dict, Any

from meow_decoder.crypto_backend import (
    RustCryptoBackend,
    is_rust_available,
    get_available_backends,
)


# =============================================================================
# FIXED TEST VECTORS (Deterministic)
# =============================================================================

TEST_VECTORS: Dict[str, Dict[str, Any]] = {
    "argon2id_basic": {
        "password": b"test_password_123",
        "salt": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "memory_kib": 32768,  # 32 MiB for faster tests
        "iterations": 2,
        "parallelism": 4,
        "output_len": 32,
    },
    "aes_gcm_encrypt": {
        "key": bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        "nonce": bytes.fromhex("000102030405060708090a0b"),
        "plaintext": b"Hello, Meow Decoder! This is a test message.",
        "aad": b"additional authenticated data",
    },
    "aes_gcm_no_aad": {
        "key": bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        "nonce": bytes.fromhex("cafebabecafebabe12345678"),
        "plaintext": b"Secret cat message!",
        "aad": None,
    },
    "hmac_sha256": {
        "key": bytes.fromhex("0123456789abcdef0123456789abcdef"),
        "message": b"The quick brown fox jumps over the lazy cat",
    },
    "hkdf_basic": {
        "ikm": bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        "salt": bytes.fromhex("000102030405060708090a0b0c"),
        "info": b"meow_test_info",
        "output_len": 42,
    },
    "sha256": {
        "data": b"The Meow Decoder is a cryptographic tool.",
    },
    "x25519_static": {
        "alice_private": bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
        "bob_private": bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
    },
}


class TestVectorValidation:
    """Validate test vectors produce consistent results."""

    def test_argon2id_vector(self):
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["argon2id_basic"]

        key1 = crypto.derive_key_argon2id(
            vec["password"],
            vec["salt"],
            vec["memory_kib"],
            vec["iterations"],
            vec["parallelism"],
            vec["output_len"],
        )

        key2 = crypto.derive_key_argon2id(
            vec["password"],
            vec["salt"],
            vec["memory_kib"],
            vec["iterations"],
            vec["parallelism"],
            vec["output_len"],
        )

        assert key1 == key2, "Argon2id should be deterministic"
        assert len(key1) == 32, f"Key should be 32 bytes, got {len(key1)}"

    def test_aes_gcm_roundtrip(self):
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["aes_gcm_encrypt"]

        ciphertext = crypto.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        decrypted = crypto.aes_gcm_decrypt(
            vec["key"], vec["nonce"], ciphertext, vec["aad"]
        )

        assert decrypted == vec["plaintext"], "Decryption should recover plaintext"

    def test_aes_gcm_no_aad(self):
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["aes_gcm_no_aad"]

        ciphertext = crypto.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        decrypted = crypto.aes_gcm_decrypt(
            vec["key"], vec["nonce"], ciphertext, vec["aad"]
        )

        assert decrypted == vec["plaintext"]

    def test_hmac_vector(self):
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["hmac_sha256"]

        tag = crypto.hmac_sha256(vec["key"], vec["message"])

        assert len(tag) == 32, f"HMAC should be 32 bytes, got {len(tag)}"
        assert crypto.hmac_sha256_verify(vec["key"], vec["message"], tag)

    def test_hkdf_vector(self):
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["hkdf_basic"]

        okm = crypto.derive_key_hkdf(
            vec["ikm"], vec["salt"], vec["info"], vec["output_len"]
        )

        assert len(okm) == vec["output_len"]

    def test_sha256_vector(self):
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["sha256"]

        digest = crypto.sha256(vec["data"])

        assert len(digest) == 32
        import hashlib

        expected = hashlib.sha256(vec["data"]).digest()
        assert digest == expected

    def test_x25519_exchange_vector(self):
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["x25519_static"]

        alice_pub = crypto.x25519_public_from_private(vec["alice_private"])
        bob_pub = crypto.x25519_public_from_private(vec["bob_private"])

        shared_ab = crypto.x25519_exchange(vec["alice_private"], bob_pub)
        shared_ba = crypto.x25519_exchange(vec["bob_private"], alice_pub)

        assert shared_ab == shared_ba, "DH exchange should be symmetric"


class TestBackendAvailability:
    def test_rust_backend_available(self):
        assert is_rust_available(), "Rust backend is required"
        assert get_available_backends() == ["rust"]


class TestEdgeCases:
    """Test edge cases and error handling."""

    def setup_method(self):
        self.crypto = RustCryptoBackend()

    def test_argon2id_invalid_salt_length(self):
        with pytest.raises(ValueError):
            self.crypto.derive_key_argon2id(b"password", b"short")

    def test_aes_gcm_invalid_key_length(self):
        with pytest.raises(ValueError):
            self.crypto.aes_gcm_encrypt(b"short_key", b"12345678901", b"data")

    def test_aes_gcm_invalid_nonce_length(self):
        key = bytes(32)
        with pytest.raises(ValueError):
            self.crypto.aes_gcm_encrypt(key, b"short", b"data")

    def test_aes_gcm_wrong_key_fails(self):
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ct = self.crypto.aes_gcm_encrypt(key1, nonce, b"secret")

        with pytest.raises(Exception):
            self.crypto.aes_gcm_decrypt(key2, nonce, ct)

    def test_hmac_verify_wrong_tag_fails(self):
        key = secrets.token_bytes(32)
        message = b"test message"

        tag = self.crypto.hmac_sha256(key, message)
        wrong_tag = bytes(32)

        assert self.crypto.hmac_sha256_verify(key, message, tag) is True
        assert self.crypto.hmac_sha256_verify(key, message, wrong_tag) is False

    def test_empty_data(self):
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ct = self.crypto.aes_gcm_encrypt(key, nonce, b"")
        pt = self.crypto.aes_gcm_decrypt(key, nonce, ct)
        assert pt == b""

        tag = self.crypto.hmac_sha256(key, b"")
        assert len(tag) == 32

        digest = self.crypto.sha256(b"")
        assert len(digest) == 32


class TestPerformance:
    """Basic performance sanity checks."""

    def test_argon2id_performance(self):
        crypto = RustCryptoBackend()

        import time

        start = time.time()

        crypto.derive_key_argon2id(
            b"password", secrets.token_bytes(16), memory_kib=32768, iterations=2
        )

        elapsed = time.time() - start
        assert elapsed < 5.0, "Argon2id should complete in reasonable time"

    def test_aes_gcm_performance(self):
        crypto = RustCryptoBackend()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        data = secrets.token_bytes(1024 * 1024)  # 1 MB

        import time

        start = time.time()

        ct = crypto.aes_gcm_encrypt(key, nonce, data)
        pt = crypto.aes_gcm_decrypt(key, nonce, ct)

        elapsed = time.time() - start
        assert elapsed < 1.0, "AES-GCM 1MB should be fast"
        assert pt == data


class TestVectorValidation:
    """Validate test vectors produce consistent results."""
    
    def test_argon2id_vector(self):
        """Test Argon2id produces consistent output."""
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["argon2id_basic"]
        
        key1 = crypto.derive_key_argon2id(
            vec["password"], vec["salt"],
            vec["memory_kib"], vec["iterations"],
            vec["parallelism"], vec["output_len"]
        )
        
        key2 = crypto.derive_key_argon2id(
            vec["password"], vec["salt"],
            vec["memory_kib"], vec["iterations"],
            vec["parallelism"], vec["output_len"]
        )
        
        assert key1 == key2, "Argon2id should be deterministic"
        assert len(key1) == 32, f"Key should be 32 bytes, got {len(key1)}"
        print(f"Argon2id output: {key1.hex()}")
    
    def test_aes_gcm_roundtrip(self):
        """Test AES-GCM encryption/decryption roundtrip."""
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["aes_gcm_encrypt"]
        
        ciphertext = crypto.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        
        decrypted = crypto.aes_gcm_decrypt(
            vec["key"], vec["nonce"], ciphertext, vec["aad"]
        )
        
        assert decrypted == vec["plaintext"], "Decryption should recover plaintext"
        print(f"AES-GCM ciphertext: {ciphertext.hex()}")
    
    def test_aes_gcm_no_aad(self):
        """Test AES-GCM without AAD."""
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["aes_gcm_no_aad"]
        
        ciphertext = crypto.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        
        decrypted = crypto.aes_gcm_decrypt(
            vec["key"], vec["nonce"], ciphertext, vec["aad"]
        )
        
        assert decrypted == vec["plaintext"]
        print(f"AES-GCM (no AAD) ciphertext: {ciphertext.hex()}")
    
    def test_hmac_vector(self):
        """Test HMAC-SHA256 produces correct output."""
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["hmac_sha256"]
        
        tag = crypto.hmac_sha256(vec["key"], vec["message"])
        
        assert len(tag) == 32, f"HMAC should be 32 bytes, got {len(tag)}"
        assert crypto.hmac_sha256_verify(vec["key"], vec["message"], tag)
        print(f"HMAC-SHA256: {tag.hex()}")
    
    def test_hkdf_vector(self):
        """Test HKDF produces correct output."""
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["hkdf_basic"]
        
        okm = crypto.derive_key_hkdf(
            vec["ikm"], vec["salt"], vec["info"], vec["output_len"]
        )
        
        assert len(okm) == vec["output_len"]
        print(f"HKDF output: {okm.hex()}")
    
    def test_sha256_vector(self):
        """Test SHA-256 produces correct output."""
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["sha256"]
        
        digest = crypto.sha256(vec["data"])
        
        assert len(digest) == 32
        # Known SHA-256 output
        import hashlib
        expected = hashlib.sha256(vec["data"]).digest()
        assert digest == expected
        print(f"SHA-256: {digest.hex()}")
    
    def test_x25519_exchange_vector(self):
        """Test X25519 key exchange with known keys."""
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["x25519_static"]
        
        alice_pub = crypto.x25519_public_from_private(vec["alice_private"])
        bob_pub = crypto.x25519_public_from_private(vec["bob_private"])
        
        shared_ab = crypto.x25519_exchange(vec["alice_private"], bob_pub)
        shared_ba = crypto.x25519_exchange(vec["bob_private"], alice_pub)
        
        assert shared_ab == shared_ba, "DH exchange should be symmetric"
        print(f"X25519 shared secret: {shared_ab.hex()}")


@pytest.mark.skipif(not is_rust_available(), reason="Rust backend not installed")
class TestBackendAvailability:
    def test_rust_backend_available(self):
        assert "rust" in get_available_backends()
        
        rs_ct = self.rs_crypto.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        
        assert py_ct == rs_ct, (
            f"AES-GCM ciphertext mismatch!\n"
            f"Python: {py_ct.hex()}\n"
            f"Rust:   {rs_ct.hex()}"
        )
        print(f"✅ AES-GCM encrypt: {py_ct.hex()[:32]}...")
    
    def test_aes_gcm_decrypt_compatibility(self):
        """AES-GCM decryption should work across backends."""
        vec = TEST_VECTORS["aes_gcm_encrypt"]
        
        # Encrypt with Python, decrypt with Rust
        py_ct = self.py_crypto.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        rs_pt = self.rs_crypto.aes_gcm_decrypt(
            vec["key"], vec["nonce"], py_ct, vec["aad"]
        )
        assert rs_pt == vec["plaintext"], "Rust should decrypt Python ciphertext"
        
        # Encrypt with Rust, decrypt with Python
        rs_ct = self.rs_crypto.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        py_pt = self.py_crypto.aes_gcm_decrypt(
            vec["key"], vec["nonce"], rs_ct, vec["aad"]
        )
        assert py_pt == vec["plaintext"], "Python should decrypt Rust ciphertext"
        
        print("✅ AES-GCM cross-backend decryption")
    
    def test_hmac_compatibility(self):
        """HMAC-SHA256 should produce identical tags."""
        vec = TEST_VECTORS["hmac_sha256"]
        
        py_tag = self.py_crypto.hmac_sha256(vec["key"], vec["message"])
        rs_tag = self.rs_crypto.hmac_sha256(vec["key"], vec["message"])
        
        assert py_tag == rs_tag, (
            f"HMAC mismatch!\n"
            f"Python: {py_tag.hex()}\n"
            f"Rust:   {rs_tag.hex()}"
        )
        
        # Cross-verify
        assert self.rs_crypto.hmac_sha256_verify(vec["key"], vec["message"], py_tag)
        assert self.py_crypto.hmac_sha256_verify(vec["key"], vec["message"], rs_tag)
        
        print(f"✅ HMAC-SHA256: {py_tag.hex()}")
    
    def test_hkdf_compatibility(self):
        """HKDF should produce identical output."""
        vec = TEST_VECTORS["hkdf_basic"]
        
        py_okm = self.py_crypto.derive_key_hkdf(
            vec["ikm"], vec["salt"], vec["info"], vec["output_len"]
        )
        rs_okm = self.rs_crypto.derive_key_hkdf(
            vec["ikm"], vec["salt"], vec["info"], vec["output_len"]
        )
        
        assert py_okm == rs_okm, (
            f"HKDF mismatch!\n"
            f"Python: {py_okm.hex()}\n"
            f"Rust:   {rs_okm.hex()}"
        )
        print(f"✅ HKDF: {py_okm.hex()}")
    
    def test_sha256_compatibility(self):
        """SHA-256 should produce identical digests."""
        vec = TEST_VECTORS["sha256"]
        
        py_digest = self.py_crypto.sha256(vec["data"])
        rs_digest = self.rs_crypto.sha256(vec["data"])
        
        assert py_digest == rs_digest, (
            f"SHA-256 mismatch!\n"
            f"Python: {py_digest.hex()}\n"
            f"Rust:   {rs_digest.hex()}"
        )
        print(f"✅ SHA-256: {py_digest.hex()}")
    
    def test_x25519_compatibility(self):
        """X25519 key exchange should produce identical shared secrets."""
        vec = TEST_VECTORS["x25519_static"]
        
        # Generate public keys from both backends
        py_alice_pub = self.py_crypto.x25519_public_from_private(vec["alice_private"])
        rs_alice_pub = self.rs_crypto.x25519_public_from_private(vec["alice_private"])
        assert py_alice_pub == rs_alice_pub, "Public key derivation should match"
        
        py_bob_pub = self.py_crypto.x25519_public_from_private(vec["bob_private"])
        rs_bob_pub = self.rs_crypto.x25519_public_from_private(vec["bob_private"])
        assert py_bob_pub == rs_bob_pub, "Public key derivation should match"
        
        # Test key exchange
        py_shared = self.py_crypto.x25519_exchange(vec["alice_private"], py_bob_pub)
        rs_shared = self.rs_crypto.x25519_exchange(vec["alice_private"], rs_bob_pub)
        
        assert py_shared == rs_shared, (
            f"X25519 shared secret mismatch!\n"
            f"Python: {py_shared.hex()}\n"
            f"Rust:   {rs_shared.hex()}"
        )
        print(f"✅ X25519: {py_shared.hex()}")
    
    def test_constant_time_compare_compatibility(self):
        """Constant-time comparison should match."""
        a = b"test_bytes_12345"
        b = b"test_bytes_12345"
        c = b"different_bytes!"
        
        assert self.py_crypto.constant_time_compare(a, b) == self.rs_crypto.constant_time_compare(a, b)
        assert self.py_crypto.constant_time_compare(a, c) == self.rs_crypto.constant_time_compare(a, c)
        
        print("✅ Constant-time compare")


class TestBackendSwitching:
    """Test backend selection and switching."""
    
    def test_auto_backend_selection(self):
        """Auto should select best available backend."""
        crypto = CryptoBackend(backend="auto")
        
        if is_rust_available():
            assert crypto.name == "rust"
        else:
            assert crypto.name == "python"
        
        print(f"Auto-selected: {crypto.name}")
    
    def test_python_backend_explicit(self):
        """Should be able to force Python backend."""
        crypto = CryptoBackend(backend="python")
        assert crypto.name == "python"
    
    @pytest.mark.skipif(not is_rust_available(), reason="Rust backend not installed")
    def test_rust_backend_explicit(self):
        """Should be able to force Rust backend."""
        crypto = CryptoBackend(backend="rust")
        assert crypto.name == "rust"
    
    def test_get_available_backends(self):
        """Should list available backends."""
        backends = get_available_backends()
        assert "python" in backends
        
        if is_rust_available():
            assert "rust" in backends
        
        print(f"Available backends: {backends}")
    
    def test_invalid_backend_raises(self):
        """Invalid backend should raise ValueError."""
        with pytest.raises(ValueError):
            CryptoBackend(backend="invalid")


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def setup_method(self):
        self.crypto = CryptoBackend(backend="python")
    
    def test_argon2id_invalid_salt_length(self):
        """Argon2id should reject invalid salt length."""
        with pytest.raises(ValueError):
            self.crypto.derive_key_argon2id(b"password", b"short")
    
    def test_aes_gcm_invalid_key_length(self):
        """AES-GCM should reject invalid key length."""
        with pytest.raises(ValueError):
            self.crypto.aes_gcm_encrypt(b"short_key", b"12345678901", b"data")
    
    def test_aes_gcm_invalid_nonce_length(self):
        """AES-GCM should reject invalid nonce length."""
        key = bytes(32)
        with pytest.raises(ValueError):
            self.crypto.aes_gcm_encrypt(key, b"short", b"data")
    
    def test_aes_gcm_wrong_key_fails(self):
        """Decryption with wrong key should fail."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        ct = self.crypto.aes_gcm_encrypt(key1, nonce, b"secret")
        
        with pytest.raises(Exception):
            self.crypto.aes_gcm_decrypt(key2, nonce, ct)
    
    def test_hmac_verify_wrong_tag_fails(self):
        """HMAC verify with wrong tag should return False."""
        key = secrets.token_bytes(32)
        message = b"test message"
        
        tag = self.crypto.hmac_sha256(key, message)
        wrong_tag = bytes(32)
        
        assert self.crypto.hmac_sha256_verify(key, message, tag) is True
        assert self.crypto.hmac_sha256_verify(key, message, wrong_tag) is False
    
    def test_empty_data(self):
        """Should handle empty data gracefully."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # Empty plaintext
        ct = self.crypto.aes_gcm_encrypt(key, nonce, b"")
        pt = self.crypto.aes_gcm_decrypt(key, nonce, ct)
        assert pt == b""
        
        # Empty HMAC message
        tag = self.crypto.hmac_sha256(key, b"")
        assert len(tag) == 32
        
        # Empty SHA256
        digest = self.crypto.sha256(b"")
        assert len(digest) == 32


class TestPerformance:
    """Basic performance sanity checks."""
    
    def test_argon2id_performance(self):
        """Argon2id with low params should complete quickly."""
        crypto = CryptoBackend()
        
        import time
        start = time.time()
        
        # Low params for speed test
        crypto.derive_key_argon2id(
            b"password", secrets.token_bytes(16),
            memory_kib=32768, iterations=2
        )
        
        elapsed = time.time() - start
        print(f"Argon2id (32MB, 2 iter): {elapsed:.3f}s")
        assert elapsed < 5.0, "Argon2id should complete in reasonable time"
    
    def test_aes_gcm_performance(self):
        """AES-GCM should be fast for small data."""
        crypto = CryptoBackend()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        data = secrets.token_bytes(1024 * 1024)  # 1 MB
        
        import time
        start = time.time()
        
        ct = crypto.aes_gcm_encrypt(key, nonce, data)
        pt = crypto.aes_gcm_decrypt(key, nonce, ct)
        
        elapsed = time.time() - start
        print(f"AES-GCM 1MB roundtrip: {elapsed:.3f}s")
        assert elapsed < 1.0, "AES-GCM 1MB should be fast"
        assert pt == data


# Run basic tests when executed directly
if __name__ == "__main__":
    print("🔐 Crypto Backend Compatibility Tests")
    print("=" * 60)
    
    print(f"\nAvailable backends: {get_available_backends()}")
    
    # Run vector tests
    print("\n--- Test Vectors ---")
    tv = TestVectorValidation()
    tv.test_argon2id_vector()
    tv.test_aes_gcm_roundtrip()
    tv.test_hmac_vector()
    tv.test_hkdf_vector()
    tv.test_sha256_vector()
    tv.test_x25519_exchange_vector()
    
    # Run compatibility tests if Rust available
    if is_rust_available():
        print("\n--- Backend Compatibility ---")
        compat = TestBackendCompatibility()
        compat.setup_method()
        compat.test_argon2id_compatibility()
        compat.test_aes_gcm_encrypt_compatibility()
        compat.test_aes_gcm_decrypt_compatibility()
        compat.test_hmac_compatibility()
        compat.test_hkdf_compatibility()
        compat.test_sha256_compatibility()
        compat.test_x25519_compatibility()
        compat.test_constant_time_compare_compatibility()
        print("\n✅ All compatibility tests passed!")
    else:
        print("\n⚠️  Rust backend not available - skipping compatibility tests")
        print("   Build with: cd rust_crypto && maturin develop")
    
    print("\n✅ All tests complete!")
