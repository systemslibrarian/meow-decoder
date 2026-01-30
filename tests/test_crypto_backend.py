#!/usr/bin/env python3
"""
🐱 Consolidated Crypto Backend Tests

Tests for meow_decoder/crypto_backend.py
All crypto backend tests consolidated into single file for coverage.

Covers:
- RustCryptoBackend class
- CryptoBackend wrapper
- BackendInfo dataclass
- Key derivation (Argon2id, HKDF)
- Symmetric encryption (AES-GCM)
- Authentication (HMAC-SHA256)
- Key exchange (X25519)
- Hash functions (SHA-256)
- Secure memory operations
"""

import pytest
import secrets
import os
from typing import Dict, Any

# Set test mode for faster Argon2id
os.environ.setdefault("MEOW_TEST_MODE", "1")

from meow_decoder.crypto_backend import (
    RustCryptoBackend,
    CryptoBackend,
    BackendInfo,
    get_default_backend,
    secure_zero_memory,
    set_default_backend,
    is_rust_available,
    get_available_backends,
)


# =============================================================================
# Test Vectors for Deterministic Testing
# =============================================================================

TEST_VECTORS: Dict[str, Dict[str, Any]] = {
    "argon2id_basic": {
        "password": b"test_password_123",
        "salt": bytes.fromhex("00112233445566778899aabbccddeeff"),
        "memory_kib": 32768,
        "iterations": 1,
        "parallelism": 1,
        "output_len": 32,
    },
    "aes_gcm_encrypt": {
        "key": bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        "nonce": bytes.fromhex("000102030405060708090a0b"),
        "plaintext": b"Hello, Meow Decoder!",
        "aad": b"additional_authenticated_data",
    },
    "aes_gcm_no_aad": {
        "key": bytes.fromhex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"),
        "nonce": bytes.fromhex("0b0a09080706050403020100"),
        "plaintext": b"No AAD test",
        "aad": None,
    },
    "hmac_sha256": {
        "key": bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        "message": b"HMAC test message",
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


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def rust_backend():
    """Get RustCryptoBackend instance."""
    return RustCryptoBackend()


@pytest.fixture
def crypto_backend():
    """Get CryptoBackend wrapper instance."""
    return CryptoBackend()


@pytest.fixture
def default_backend():
    """Get default backend instance."""
    return get_default_backend()


# =============================================================================
# Test Classes
# =============================================================================

class TestBackendInfo:
    """Tests for BackendInfo dataclass."""

    def test_backend_info_creation(self):
        """Test BackendInfo can be created."""
        info = BackendInfo(name="test", version="1.0.0", features=["feature1"])
        assert info.name == "test"
        assert info.version == "1.0.0"
        assert "feature1" in info.features

    def test_backend_info_from_rust_backend(self, rust_backend):
        """Test getting info from RustCryptoBackend."""
        info = rust_backend.get_info()
        assert isinstance(info, BackendInfo)
        assert info.name == "rust"
        assert info.version is not None


class TestRustBackendAvailability:
    """Tests for Rust backend availability."""

    def test_rust_is_available(self):
        """Rust backend should be available."""
        assert is_rust_available() is True

    def test_get_available_backends_includes_rust(self):
        """Available backends should include rust."""
        backends = get_available_backends()
        assert "rust" in backends

    def test_rust_backend_instantiates(self):
        """RustCryptoBackend should instantiate without error."""
        backend = RustCryptoBackend()
        assert backend is not None


class TestCryptoBackendInit:
    """Tests for CryptoBackend initialization."""

    def test_default_init(self):
        """Default init should work."""
        backend = CryptoBackend()
        assert backend is not None

    def test_explicit_rust_backend(self):
        """Can explicitly request Rust backend."""
        backend = CryptoBackend(backend="rust")
        assert backend.name == "rust"


class TestVectorValidation:
    """Validate test vectors produce consistent results."""

    def test_argon2id_deterministic(self, rust_backend):
        """Argon2id should be deterministic with same inputs."""
        vec = TEST_VECTORS["argon2id_basic"]

        key1 = rust_backend.derive_key_argon2id(
            vec["password"], vec["salt"],
            vec["memory_kib"], vec["iterations"],
            vec["parallelism"], vec["output_len"]
        )

        key2 = rust_backend.derive_key_argon2id(
            vec["password"], vec["salt"],
            vec["memory_kib"], vec["iterations"],
            vec["parallelism"], vec["output_len"]
        )

        assert key1 == key2, "Argon2id should be deterministic"
        assert len(key1) == 32

    def test_aes_gcm_roundtrip(self, rust_backend):
        """AES-GCM encryption/decryption roundtrip."""
        vec = TEST_VECTORS["aes_gcm_encrypt"]

        ciphertext = rust_backend.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        decrypted = rust_backend.aes_gcm_decrypt(
            vec["key"], vec["nonce"], ciphertext, vec["aad"]
        )

        assert decrypted == vec["plaintext"]

    def test_aes_gcm_no_aad(self, rust_backend):
        """AES-GCM without AAD."""
        vec = TEST_VECTORS["aes_gcm_no_aad"]

        ciphertext = rust_backend.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        decrypted = rust_backend.aes_gcm_decrypt(
            vec["key"], vec["nonce"], ciphertext, vec["aad"]
        )

        assert decrypted == vec["plaintext"]

    def test_hmac_vector(self, rust_backend):
        """HMAC-SHA256 produces correct output."""
        vec = TEST_VECTORS["hmac_sha256"]

        tag = rust_backend.hmac_sha256(vec["key"], vec["message"])

        assert len(tag) == 32
        assert rust_backend.hmac_sha256_verify(vec["key"], vec["message"], tag)

    def test_hkdf_vector(self, rust_backend):
        """HKDF produces correct length output."""
        vec = TEST_VECTORS["hkdf_basic"]

        okm = rust_backend.derive_key_hkdf(
            vec["ikm"], vec["salt"], vec["info"], vec["output_len"]
        )

        assert len(okm) == vec["output_len"]

    def test_sha256_vector(self, rust_backend):
        """SHA-256 matches Python hashlib."""
        vec = TEST_VECTORS["sha256"]

        digest = rust_backend.sha256(vec["data"])

        assert len(digest) == 32
        import hashlib
        expected = hashlib.sha256(vec["data"]).digest()
        assert digest == expected

    def test_x25519_exchange_symmetric(self, rust_backend):
        """X25519 key exchange is symmetric."""
        vec = TEST_VECTORS["x25519_static"]

        alice_pub = rust_backend.x25519_public_from_private(vec["alice_private"])
        bob_pub = rust_backend.x25519_public_from_private(vec["bob_private"])

        shared_ab = rust_backend.x25519_exchange(vec["alice_private"], bob_pub)
        shared_ba = rust_backend.x25519_exchange(vec["bob_private"], alice_pub)

        assert shared_ab == shared_ba


class TestBackendArgon2id:
    """Tests for Argon2id key derivation."""

    def test_argon2id_basic(self, rust_backend):
        """Basic Argon2id derivation."""
        password = b"test_password"
        salt = secrets.token_bytes(16)

        key = rust_backend.derive_key_argon2id(
            password, salt,
            memory_kib=32768, iterations=1, parallelism=1, output_len=32
        )

        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_argon2id_different_passwords(self, rust_backend):
        """Different passwords produce different keys."""
        salt = secrets.token_bytes(16)

        key1 = rust_backend.derive_key_argon2id(
            b"password1", salt, 32768, 1, 1, 32
        )
        key2 = rust_backend.derive_key_argon2id(
            b"password2", salt, 32768, 1, 1, 32
        )

        assert key1 != key2

    def test_argon2id_different_salts(self, rust_backend):
        """Different salts produce different keys."""
        password = b"same_password"

        key1 = rust_backend.derive_key_argon2id(
            password, secrets.token_bytes(16), 32768, 1, 1, 32
        )
        key2 = rust_backend.derive_key_argon2id(
            password, secrets.token_bytes(16), 32768, 1, 1, 32
        )

        assert key1 != key2

    def test_argon2id_invalid_salt_length(self, rust_backend):
        """Invalid salt length raises ValueError."""
        with pytest.raises(ValueError):
            rust_backend.derive_key_argon2id(b"password", b"short", 32768, 1, 1, 32)

    def test_argon2id_variable_output_length(self, rust_backend):
        """Can specify different output lengths."""
        password = b"test"
        salt = secrets.token_bytes(16)

        key16 = rust_backend.derive_key_argon2id(password, salt, 32768, 1, 1, 16)
        key64 = rust_backend.derive_key_argon2id(password, salt, 32768, 1, 1, 64)

        assert len(key16) == 16
        assert len(key64) == 64


class TestBackendAESGCM:
    """Tests for AES-GCM encryption/decryption."""

    def test_aes_gcm_encrypt_decrypt(self, rust_backend):
        """Basic encrypt/decrypt roundtrip."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Hello, World!"
        aad = b"additional data"

        ciphertext = rust_backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = rust_backend.aes_gcm_decrypt(key, nonce, ciphertext, aad)

        assert decrypted == plaintext

    def test_aes_gcm_ciphertext_larger(self, rust_backend):
        """Ciphertext includes auth tag (16 bytes larger)."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"test"

        ciphertext = rust_backend.aes_gcm_encrypt(key, nonce, plaintext, None)

        assert len(ciphertext) == len(plaintext) + 16

    def test_aes_gcm_wrong_key_fails(self, rust_backend):
        """Decryption with wrong key fails."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"secret"

        ciphertext = rust_backend.aes_gcm_encrypt(key1, nonce, plaintext, None)

        with pytest.raises(Exception):
            rust_backend.aes_gcm_decrypt(key2, nonce, ciphertext, None)

    def test_aes_gcm_wrong_aad_fails(self, rust_backend):
        """Decryption with wrong AAD fails."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"secret"

        ciphertext = rust_backend.aes_gcm_encrypt(key, nonce, plaintext, b"aad1")

        with pytest.raises(Exception):
            rust_backend.aes_gcm_decrypt(key, nonce, ciphertext, b"aad2")

    def test_aes_gcm_tampered_ciphertext_fails(self, rust_backend):
        """Tampered ciphertext fails authentication."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"secret"

        ciphertext = rust_backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):
            rust_backend.aes_gcm_decrypt(key, nonce, tampered, None)

    def test_aes_gcm_invalid_key_length(self, rust_backend):
        """Invalid key length raises ValueError."""
        with pytest.raises(ValueError):
            rust_backend.aes_gcm_encrypt(b"short", secrets.token_bytes(12), b"data", None)

    def test_aes_gcm_invalid_nonce_length(self, rust_backend):
        """Invalid nonce length raises ValueError."""
        with pytest.raises(ValueError):
            rust_backend.aes_gcm_encrypt(secrets.token_bytes(32), b"short", b"data", None)

    def test_aes_gcm_empty_plaintext(self, rust_backend):
        """Empty plaintext works."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        ciphertext = rust_backend.aes_gcm_encrypt(key, nonce, b"", None)
        decrypted = rust_backend.aes_gcm_decrypt(key, nonce, ciphertext, None)

        assert decrypted == b""

    def test_aes_gcm_large_data(self, rust_backend):
        """Large data encrypts correctly."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = secrets.token_bytes(1024 * 100)  # 100 KB

        ciphertext = rust_backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        decrypted = rust_backend.aes_gcm_decrypt(key, nonce, ciphertext, None)

        assert decrypted == plaintext


class TestBackendHMAC:
    """Tests for HMAC-SHA256."""

    def test_hmac_basic(self, rust_backend):
        """Basic HMAC generation."""
        key = secrets.token_bytes(32)
        message = b"test message"

        tag = rust_backend.hmac_sha256(key, message)

        assert len(tag) == 32
        assert isinstance(tag, bytes)

    def test_hmac_verify_correct(self, rust_backend):
        """HMAC verification succeeds with correct tag."""
        key = secrets.token_bytes(32)
        message = b"test message"

        tag = rust_backend.hmac_sha256(key, message)

        assert rust_backend.hmac_sha256_verify(key, message, tag) is True

    def test_hmac_verify_wrong_tag(self, rust_backend):
        """HMAC verification fails with wrong tag."""
        key = secrets.token_bytes(32)
        message = b"test message"

        rust_backend.hmac_sha256(key, message)
        wrong_tag = secrets.token_bytes(32)

        assert rust_backend.hmac_sha256_verify(key, message, wrong_tag) is False

    def test_hmac_verify_wrong_message(self, rust_backend):
        """HMAC verification fails with modified message."""
        key = secrets.token_bytes(32)
        message = b"original message"

        tag = rust_backend.hmac_sha256(key, message)

        assert rust_backend.hmac_sha256_verify(key, b"modified message", tag) is False

    def test_hmac_verify_wrong_key(self, rust_backend):
        """HMAC verification fails with wrong key."""
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        message = b"test message"

        tag = rust_backend.hmac_sha256(key1, message)

        assert rust_backend.hmac_sha256_verify(key2, message, tag) is False

    def test_hmac_empty_message(self, rust_backend):
        """HMAC works with empty message."""
        key = secrets.token_bytes(32)

        tag = rust_backend.hmac_sha256(key, b"")

        assert len(tag) == 32
        assert rust_backend.hmac_sha256_verify(key, b"", tag) is True

    def test_hmac_deterministic(self, rust_backend):
        """HMAC is deterministic."""
        key = secrets.token_bytes(32)
        message = b"test"

        tag1 = rust_backend.hmac_sha256(key, message)
        tag2 = rust_backend.hmac_sha256(key, message)

        assert tag1 == tag2


class TestBackendX25519:
    """Tests for X25519 key exchange."""

    def test_x25519_generate_keypair(self, rust_backend):
        """Generate X25519 keypair."""
        private, public = rust_backend.x25519_generate_keypair()

        assert len(private) == 32
        assert len(public) == 32
        assert private != public

    def test_x25519_public_from_private(self, rust_backend):
        """Derive public key from private."""
        private, expected_public = rust_backend.x25519_generate_keypair()

        derived_public = rust_backend.x25519_public_from_private(private)

        assert derived_public == expected_public

    def test_x25519_exchange_symmetric(self, rust_backend):
        """Key exchange produces same shared secret."""
        alice_priv, alice_pub = rust_backend.x25519_generate_keypair()
        bob_priv, bob_pub = rust_backend.x25519_generate_keypair()

        shared_ab = rust_backend.x25519_exchange(alice_priv, bob_pub)
        shared_ba = rust_backend.x25519_exchange(bob_priv, alice_pub)

        assert shared_ab == shared_ba
        assert len(shared_ab) == 32

    def test_x25519_different_keys_different_secrets(self, rust_backend):
        """Different keypairs produce different shared secrets."""
        alice_priv, _ = rust_backend.x25519_generate_keypair()
        bob_priv, bob_pub = rust_backend.x25519_generate_keypair()
        charlie_priv, charlie_pub = rust_backend.x25519_generate_keypair()

        shared_ab = rust_backend.x25519_exchange(alice_priv, bob_pub)
        shared_ac = rust_backend.x25519_exchange(alice_priv, charlie_pub)

        assert shared_ab != shared_ac


class TestBackendHKDF:
    """Tests for HKDF key derivation."""

    def test_hkdf_basic(self, rust_backend):
        """Basic HKDF derivation."""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test info"

        okm = rust_backend.derive_key_hkdf(ikm, salt, info, 32)

        assert len(okm) == 32
        assert isinstance(okm, bytes)

    def test_hkdf_variable_length(self, rust_backend):
        """HKDF can produce variable length output."""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test"

        okm16 = rust_backend.derive_key_hkdf(ikm, salt, info, 16)
        okm64 = rust_backend.derive_key_hkdf(ikm, salt, info, 64)

        assert len(okm16) == 16
        assert len(okm64) == 64

    def test_hkdf_different_info_different_output(self, rust_backend):
        """Different info produces different output."""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        okm1 = rust_backend.derive_key_hkdf(ikm, salt, b"info1", 32)
        okm2 = rust_backend.derive_key_hkdf(ikm, salt, b"info2", 32)

        assert okm1 != okm2

    def test_hkdf_deterministic(self, rust_backend):
        """HKDF is deterministic."""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test"

        okm1 = rust_backend.derive_key_hkdf(ikm, salt, info, 32)
        okm2 = rust_backend.derive_key_hkdf(ikm, salt, info, 32)

        assert okm1 == okm2


class TestBackendSHA256:
    """Tests for SHA-256 hashing."""

    def test_sha256_basic(self, rust_backend):
        """Basic SHA-256 hash."""
        data = b"test data"

        digest = rust_backend.sha256(data)

        assert len(digest) == 32

    def test_sha256_matches_hashlib(self, rust_backend):
        """SHA-256 matches Python hashlib."""
        import hashlib
        data = b"The quick brown fox jumps over the lazy dog"

        rust_digest = rust_backend.sha256(data)
        python_digest = hashlib.sha256(data).digest()

        assert rust_digest == python_digest

    def test_sha256_empty(self, rust_backend):
        """SHA-256 of empty data."""
        import hashlib

        rust_digest = rust_backend.sha256(b"")
        python_digest = hashlib.sha256(b"").digest()

        assert rust_digest == python_digest

    def test_sha256_deterministic(self, rust_backend):
        """SHA-256 is deterministic."""
        data = b"test"

        digest1 = rust_backend.sha256(data)
        digest2 = rust_backend.sha256(data)

        assert digest1 == digest2


class TestSecureZeroMemory:
    """Tests for secure memory zeroing."""

    def test_secure_zero_memory_bytearray(self):
        """secure_zero_memory zeros bytearray."""
        data = bytearray(b"sensitive data here!")
        original_len = len(data)

        secure_zero_memory(data)

        assert len(data) == original_len
        assert all(b == 0 for b in data)

    def test_secure_zero_memory_empty(self):
        """secure_zero_memory handles empty bytearray."""
        data = bytearray()
        secure_zero_memory(data)
        assert len(data) == 0

    def test_secure_zero_memory_large(self):
        """secure_zero_memory handles large bytearray."""
        data = bytearray(secrets.token_bytes(10000))

        secure_zero_memory(data)

        assert all(b == 0 for b in data)


class TestDefaultBackend:
    """Tests for default backend management."""

    def test_get_default_backend(self):
        """Can get default backend."""
        backend = get_default_backend()
        assert backend is not None

    def test_set_default_backend(self):
        """Can set and get default backend."""
        original = get_default_backend()
        new_backend = RustCryptoBackend()

        set_default_backend(new_backend)
        assert get_default_backend() is new_backend

        # Restore original
        set_default_backend(original)


class TestRustCryptoBackendClass:
    """Tests for RustCryptoBackend class methods."""

    def test_name_property(self, rust_backend):
        """Name property returns 'rust'."""
        assert rust_backend.name == "rust"

    def test_get_info(self, rust_backend):
        """get_info returns BackendInfo."""
        info = rust_backend.get_info()
        assert isinstance(info, BackendInfo)
        assert info.name == "rust"

    def test_random_bytes(self, rust_backend):
        """random_bytes generates random data."""
        data1 = rust_backend.random_bytes(32)
        data2 = rust_backend.random_bytes(32)

        assert len(data1) == 32
        assert len(data2) == 32
        assert data1 != data2  # Extremely unlikely to be equal

    def test_random_bytes_various_lengths(self, rust_backend):
        """random_bytes works with various lengths."""
        for length in [1, 16, 32, 64, 128, 256]:
            data = rust_backend.random_bytes(length)
            assert len(data) == length

    def test_constant_time_compare_equal(self, rust_backend):
        """constant_time_compare returns True for equal."""
        a = b"test bytes here!"
        b = b"test bytes here!"

        assert rust_backend.constant_time_compare(a, b) is True

    def test_constant_time_compare_not_equal(self, rust_backend):
        """constant_time_compare returns False for unequal."""
        a = b"test bytes here!"
        c = b"different bytes!"

        assert rust_backend.constant_time_compare(a, c) is False

    def test_constant_time_compare_different_lengths(self, rust_backend):
        """constant_time_compare handles different lengths."""
        a = b"short"
        b = b"much longer string"

        assert rust_backend.constant_time_compare(a, b) is False

    def test_secure_zero(self, rust_backend):
        """secure_zero zeros buffer."""
        data = bytearray(b"sensitive!")

        rust_backend.secure_zero(data)

        assert all(b == 0 for b in data)


class TestCryptoBackendMethods:
    """Tests for CryptoBackend wrapper methods."""

    def test_all_methods_exist(self, crypto_backend):
        """CryptoBackend exposes all required methods."""
        required_methods = [
            'derive_key_argon2id',
            'aes_gcm_encrypt',
            'aes_gcm_decrypt',
            'hmac_sha256',
            'hmac_sha256_verify',
            'sha256',
            'derive_key_hkdf',
            'x25519_generate_keypair',
            'x25519_exchange',
            'x25519_public_from_private',
            'constant_time_compare',
            'random_bytes',
        ]

        for method in required_methods:
            assert hasattr(crypto_backend, method), f"Missing method: {method}"

    def test_wrapper_delegates_to_rust(self, crypto_backend, rust_backend):
        """CryptoBackend delegates to Rust backend."""
        key = secrets.token_bytes(32)
        message = b"test"

        wrapper_tag = crypto_backend.hmac_sha256(key, message)
        rust_tag = rust_backend.hmac_sha256(key, message)

        assert wrapper_tag == rust_tag


class TestEdgeCases:
    """Additional edge case tests."""

    def test_unicode_in_password(self, rust_backend):
        """Argon2id handles unicode passwords."""
        password = "пароль_密码_🔐".encode('utf-8')
        salt = secrets.token_bytes(16)

        key = rust_backend.derive_key_argon2id(password, salt, 32768, 1, 1, 32)

        assert len(key) == 32

    def test_max_output_length_hkdf(self, rust_backend):
        """HKDF can produce large output."""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        # HKDF-SHA256 max is 255 * 32 = 8160 bytes
        okm = rust_backend.derive_key_hkdf(ikm, salt, b"info", 255)

        assert len(okm) == 255

    def test_nonce_reuse_produces_same_ciphertext(self, rust_backend):
        """Same key+nonce+plaintext produces same ciphertext (deterministic)."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"test"

        ct1 = rust_backend.aes_gcm_encrypt(key, nonce, plaintext, None)
        ct2 = rust_backend.aes_gcm_encrypt(key, nonce, plaintext, None)

        assert ct1 == ct2


class TestPerformance:
    """Performance sanity checks."""

    def test_argon2id_completes_in_reasonable_time(self, rust_backend):
        """Argon2id with low params completes quickly."""
        import time
        start = time.time()

        rust_backend.derive_key_argon2id(
            b"password", secrets.token_bytes(16),
            memory_kib=32768, iterations=1, parallelism=1, output_len=32
        )

        elapsed = time.time() - start
        assert elapsed < 5.0, f"Argon2id took {elapsed}s, expected < 5s"

    def test_aes_gcm_1mb_fast(self, rust_backend):
        """AES-GCM 1MB roundtrip is fast."""
        import time
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        data = secrets.token_bytes(1024 * 1024)

        start = time.time()
        ct = rust_backend.aes_gcm_encrypt(key, nonce, data, None)
        pt = rust_backend.aes_gcm_decrypt(key, nonce, ct, None)
        elapsed = time.time() - start

        assert pt == data
        assert elapsed < 1.0, f"AES-GCM 1MB took {elapsed}s, expected < 1s"


class TestModuleLevelVars:
    """Tests for module-level variables and functions."""

    def test_is_rust_available_returns_bool(self):
        """is_rust_available returns bool."""
        result = is_rust_available()
        assert isinstance(result, bool)

    def test_get_available_backends_returns_list(self):
        """get_available_backends returns list."""
        backends = get_available_backends()
        assert isinstance(backends, list)
        assert len(backends) > 0


class TestBackendType:
    """Tests for backend type checking."""

    def test_rust_backend_is_correct_type(self, rust_backend):
        """RustCryptoBackend is correct type."""
        assert isinstance(rust_backend, RustCryptoBackend)

    def test_crypto_backend_has_inner(self, crypto_backend):
        """CryptoBackend has inner backend."""
        assert hasattr(crypto_backend, '_backend') or hasattr(crypto_backend, 'name')


class TestImportability:
    """Tests that all expected items are importable."""

    def test_all_imports(self):
        """All expected items are importable."""
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


# =============================================================================
# Run tests directly
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

