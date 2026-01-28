"""
Rust crypto backend tests.

Validates deterministic test vectors and basic invariants using the Rust backend.
"""

import secrets
from typing import Dict, Any

import pytest

from meow_decoder.crypto_backend import (
    RustCryptoBackend,
    is_rust_available,
    get_available_backends,
)


TEST_VECTORS: Dict[str, Dict[str, Any]] = {
    "argon2id_basic": {
        "password": b"test_password_123",
        "salt": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "memory_kib": 32768,
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

        assert key1 == key2
        assert len(key1) == 32

    def test_aes_gcm_roundtrip(self):
        crypto = RustCryptoBackend()
        vec = TEST_VECTORS["aes_gcm_encrypt"]

        ciphertext = crypto.aes_gcm_encrypt(
            vec["key"], vec["nonce"], vec["plaintext"], vec["aad"]
        )
        decrypted = crypto.aes_gcm_decrypt(
            vec["key"], vec["nonce"], ciphertext, vec["aad"]
        )

        assert decrypted == vec["plaintext"]

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

        assert len(tag) == 32
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

        assert shared_ab == shared_ba


class TestBackendAvailability:
    def test_rust_backend_available(self):
        assert is_rust_available(), "Rust backend is required"
        assert get_available_backends() == ["rust"]


class TestEdgeCases:
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
    def test_argon2id_performance(self):
        crypto = RustCryptoBackend()

        import time

        start = time.time()

        crypto.derive_key_argon2id(
            b"password", secrets.token_bytes(16), memory_kib=32768, iterations=2
        )

        elapsed = time.time() - start
        assert elapsed < 5.0

    def test_aes_gcm_performance(self):
        crypto = RustCryptoBackend()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        data = secrets.token_bytes(1024 * 1024)

        import time

        start = time.time()

        ct = crypto.aes_gcm_encrypt(key, nonce, data)
        pt = crypto.aes_gcm_decrypt(key, nonce, ct)

        elapsed = time.time() - start
        assert elapsed < 1.0
        assert pt == data
