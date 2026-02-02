#!/usr/bin/env python3
"""
🔐 Crypto Backend Tests

Covers Rust backend wrapper logic and error paths.
"""

import os
import types
import pytest
import importlib

import meow_decoder.crypto_backend as crypto_backend


class FakeRustBackend:
    def backend_info(self):
        return "fake-backend-1.0"

    def derive_key_argon2id(self, password, salt, memory_kib, iterations, parallelism, output_len):
        return b"K" * output_len

    def derive_key_hkdf(self, ikm, salt, info, output_len):
        return b"H" * output_len

    def hkdf_extract(self, salt, ikm):
        return b"E" * 32

    def hkdf_expand(self, prk, info, output_len):
        return b"X" * output_len

    def yubikey_derive_key(self, password, salt, slot, pin):
        return b"Y" * 32

    def aes_gcm_encrypt(self, key, nonce, plaintext, aad=None):
        return b"C" + plaintext

    def aes_gcm_decrypt(self, key, nonce, ciphertext, aad=None):
        return ciphertext[1:]

    def hmac_sha256(self, key, message):
        return b"M" * 32

    def hmac_sha256_verify(self, key, message, tag):
        return tag == b"M" * 32

    def sha256(self, data):
        return b"S" * 32

    def constant_time_compare(self, a, b):
        return a == b

    def x25519_generate_keypair(self):
        return (b"p" * 32, b"P" * 32)

    def x25519_exchange(self, private_key, public_key):
        return b"Z" * 32

    def x25519_public_from_private(self, private_key):
        return b"P" * 32

    def secure_random(self, length):
        return b"R" * length

    def secure_zero(self, data):
        for i in range(len(data)):
            data[i] = 0


class FakeRustBackendNoYubi(FakeRustBackend):
    def yubikey_derive_key(self, password, salt, slot, pin):
        raise AttributeError("no yubikey")


class FakeRustBackendBadZero(FakeRustBackend):
    def secure_zero(self, data):
        raise TypeError("bad zero")


def test_crypto_backend_env_override_non_rust(monkeypatch):
    monkeypatch.setenv("MEOW_CRYPTO_BACKEND", "python")
    monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", True)
    with pytest.raises(RuntimeError, match="Rust crypto backend required"):
        crypto_backend.CryptoBackend()


def test_crypto_backend_rust_missing(monkeypatch):
    monkeypatch.delenv("MEOW_CRYPTO_BACKEND", raising=False)
    monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="Rust crypto backend required"):
        crypto_backend.CryptoBackend()


def test_rust_backend_init_import_error(monkeypatch):
    monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", False)
    with pytest.raises(ImportError, match="Rust crypto backend required"):
        crypto_backend.RustCryptoBackend()


def test_get_available_backends_when_missing(monkeypatch):
    monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", False)
    assert crypto_backend.get_available_backends() == []


def test_rust_backend_methods(monkeypatch):
    monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", True)
    monkeypatch.setattr(crypto_backend, "_rust_backend", FakeRustBackend())

    backend = crypto_backend.RustCryptoBackend()
    info = backend.get_info()
    assert info.name == "rust"
    assert info.constant_time is True

    key = backend.derive_key_argon2id(b"pw", b"s" * 16, output_len=16)
    assert key == b"K" * 16

    assert backend.derive_key_hkdf(b"i", b"s", b"info", 8) == b"H" * 8
    assert backend.hkdf_extract(b"s", b"i") == b"E" * 32
    assert backend.hkdf_expand(b"p", b"i", 7) == b"X" * 7

    ct = backend.aes_gcm_encrypt(b"k", b"n", b"data")
    assert backend.aes_gcm_decrypt(b"k", b"n", ct) == b"data"

    tag = backend.hmac_sha256(b"k", b"m")
    assert backend.hmac_sha256_verify(b"k", b"m", tag) is True

    assert backend.sha256(b"x") == b"S" * 32
    assert backend.constant_time_compare(b"a", b"a") is True

    priv, pub = backend.x25519_generate_keypair()
    assert priv == b"p" * 32
    assert pub == b"P" * 32

    assert backend.x25519_exchange(b"p" * 32, b"P" * 32) == b"Z" * 32
    assert backend.x25519_public_from_private(b"p" * 32) == b"P" * 32
    assert backend.random_bytes(5) == b"R" * 5

    buf = bytearray(b"secret")
    backend.secure_zero(buf)
    assert buf == b"\x00" * 6


def test_rust_backend_yubikey_error(monkeypatch):
    monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", True)
    monkeypatch.setattr(crypto_backend, "_rust_backend", FakeRustBackendNoYubi())

    backend = crypto_backend.RustCryptoBackend()
    with pytest.raises(RuntimeError, match="YubiKey support not enabled"):
        backend.derive_key_yubikey(b"pw", b"s" * 16)


def test_rust_backend_secure_zero_fallback(monkeypatch):
    monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", True)
    monkeypatch.setattr(crypto_backend, "_rust_backend", FakeRustBackendBadZero())

    backend = crypto_backend.RustCryptoBackend()
    buf = bytearray(b"secret")
    backend.secure_zero(buf)
    assert buf == b"\x00" * 6


def test_crypto_backend_delegation_and_defaults(monkeypatch):
    class FakeWrapper:
        NAME = "rust"

        def __init__(self):
            self.calls = []

        def get_info(self):
            return crypto_backend.BackendInfo(
                name="rust",
                version="fake",
                constant_time=True,
                memory_zeroing=True,
                pq_available=False,
                details="fake",
            )

        def derive_key_argon2id(self, *args, **kwargs):
            return b"A" * 32

        def derive_key_hkdf(self, *args, **kwargs):
            return b"H" * 32

        def hkdf_extract(self, *args, **kwargs):
            return b"E" * 32

        def hkdf_expand(self, *args, **kwargs):
            return b"X" * 32

        def derive_key_yubikey(self, *args, **kwargs):
            return b"Y" * 32

        def aes_gcm_encrypt(self, *args, **kwargs):
            return b"C"

        def aes_gcm_decrypt(self, *args, **kwargs):
            return b"D"

        def hmac_sha256(self, *args, **kwargs):
            return b"M" * 32

        def hmac_sha256_verify(self, *args, **kwargs):
            return True

        def sha256(self, *args, **kwargs):
            return b"S" * 32

        def constant_time_compare(self, *args, **kwargs):
            return True

        def x25519_generate_keypair(self):
            return (b"p" * 32, b"P" * 32)

        def x25519_exchange(self, *args, **kwargs):
            return b"Z" * 32

        def x25519_public_from_private(self, *args, **kwargs):
            return b"P" * 32

        def random_bytes(self, length):
            return b"R" * length

        def secure_zero(self, data):
            for i in range(len(data)):
                data[i] = 0

    monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", True)
    monkeypatch.setattr(crypto_backend, "RustCryptoBackend", FakeWrapper)

    crypto_backend._default_backend = None
    backend = crypto_backend.get_default_backend()
    assert backend.name == "rust"
    assert backend.get_info().name == "rust"

    assert backend.derive_key_argon2id(b"pw", b"s" * 16) == b"A" * 32
    assert backend.derive_key_hkdf(b"i", b"s", b"info") == b"H" * 32
    assert backend.hkdf_extract(b"s", b"i") == b"E" * 32
    assert backend.hkdf_expand(b"p", b"info") == b"X" * 32
    assert backend.derive_key_yubikey(b"pw", b"s" * 16) == b"Y" * 32
    assert backend.aes_gcm_encrypt(b"k", b"n", b"p") == b"C"
    assert backend.aes_gcm_decrypt(b"k", b"n", b"c") == b"D"
    assert backend.hmac_sha256(b"k", b"m") == b"M" * 32
    assert backend.hmac_sha256_verify(b"k", b"m", b"t") is True
    assert backend.sha256(b"x") == b"S" * 32
    assert backend.constant_time_compare(b"a", b"a") is True
    assert backend.x25519_generate_keypair() == (b"p" * 32, b"P" * 32)
    assert backend.x25519_exchange(b"p" * 32, b"P" * 32) == b"Z" * 32
    assert backend.x25519_public_from_private(b"p" * 32) == b"P" * 32
    assert backend.random_bytes(3) == b"R" * 3

    buf = bytearray(b"xx")
    backend.secure_zero(buf)
    assert buf == b"\x00\x00"

    # Module-level secure_zero_memory uses default backend
    buf2 = bytearray(b"yy")
    crypto_backend.secure_zero_memory(buf2)
    assert buf2 == b"\x00\x00"

    crypto_backend.set_default_backend("rust")
    assert crypto_backend.is_rust_available() is True


def test_import_error_branch_for_missing_rust(monkeypatch):
    import builtins
    import importlib.util
    import sys

    module_path = crypto_backend.__file__
    spec = importlib.util.spec_from_file_location("tmp_crypto_backend_no_rust", module_path)
    module = importlib.util.module_from_spec(spec)

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "meow_crypto_rs":
            raise ImportError("no rust")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    spec.loader.exec_module(module)

    assert module.is_rust_available() is False
