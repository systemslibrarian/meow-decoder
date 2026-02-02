"""
Canonical crypto tests (consolidated from legacy _test_crypto*.py, _test_pq*.py,
_test_kdf.py, and _test_streaming_crypto.py).
Focus: crypto.py, crypto_backend.py, crypto_enhanced.py, pq_hybrid.py,
pq_signatures.py, and streaming_crypto.py.
"""

import builtins
import gc
import hashlib
import importlib
import io
import os
import secrets
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, strategies as st

# Ensure fast KDF parameters
os.environ.setdefault("MEOW_TEST_MODE", "1")


# -----------------------------------------------------------------------------
# crypto_backend.py (Rust backend wrapper)
# -----------------------------------------------------------------------------
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


class TestCryptoBackend:
    def test_backend_env_override_non_rust(self, monkeypatch):
        monkeypatch.setenv("MEOW_CRYPTO_BACKEND", "python")
        monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", True)
        with pytest.raises(RuntimeError, match="Rust crypto backend required"):
            crypto_backend.CryptoBackend()

    def test_backend_rust_missing(self, monkeypatch):
        monkeypatch.delenv("MEOW_CRYPTO_BACKEND", raising=False)
        monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", False)
        with pytest.raises(RuntimeError, match="Rust crypto backend required"):
            crypto_backend.CryptoBackend()

    def test_rust_backend_init_import_error(self, monkeypatch):
        monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", False)
        with pytest.raises(ImportError, match="Rust crypto backend required"):
            crypto_backend.RustCryptoBackend()

    def test_get_available_backends_when_missing(self, monkeypatch):
        monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", False)
        assert crypto_backend.get_available_backends() == []

    def test_rust_backend_methods(self, monkeypatch):
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

    def test_rust_backend_yubikey_error(self, monkeypatch):
        monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", True)
        monkeypatch.setattr(crypto_backend, "_rust_backend", FakeRustBackendNoYubi())

        backend = crypto_backend.RustCryptoBackend()
        with pytest.raises(RuntimeError, match="YubiKey support not enabled"):
            backend.derive_key_yubikey(b"pw", b"s" * 16)

    def test_rust_backend_secure_zero_fallback(self, monkeypatch):
        monkeypatch.setattr(crypto_backend, "_RUST_AVAILABLE", True)
        monkeypatch.setattr(crypto_backend, "_rust_backend", FakeRustBackendBadZero())

        backend = crypto_backend.RustCryptoBackend()
        buf = bytearray(b"secret")
        backend.secure_zero(buf)
        assert buf == b"\x00" * 6

    def test_default_backend_delegation(self, monkeypatch):
        class FakeWrapper:
            NAME = "rust"

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

        buf2 = bytearray(b"yy")
        crypto_backend.secure_zero_memory(buf2)
        assert buf2 == b"\x00\x00"

        crypto_backend.set_default_backend("rust")
        assert crypto_backend.is_rust_available() is True

    def test_import_error_branch_for_missing_rust(self, monkeypatch):
        import importlib.util

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


# -----------------------------------------------------------------------------
# crypto.py (core)
# -----------------------------------------------------------------------------


def test_derive_key_variants():
    from meow_decoder.crypto import derive_key

    password = "TestPassword123!"
    salt = secrets.token_bytes(16)
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2
    assert len(key1) == 32


def test_derive_key_rejects_invalid_inputs():
    from meow_decoder.crypto import derive_key

    with pytest.raises(ValueError, match="empty"):
        derive_key("", secrets.token_bytes(16))
    with pytest.raises(ValueError, match="at least"):
        derive_key("short", secrets.token_bytes(16))
    with pytest.raises(ValueError, match="16 bytes"):
        derive_key("ValidPassword123!", b"short")


def test_derive_key_with_keyfile_changes_key():
    from meow_decoder.crypto import derive_key

    password = "TestPassword123!"
    salt = secrets.token_bytes(16)
    keyfile = secrets.token_bytes(64)

    key_with = derive_key(password, salt, keyfile)
    key_without = derive_key(password, salt)
    assert key_with != key_without


def test_encrypt_decrypt_roundtrip():
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

    data = b"Test data to encrypt"
    password = "TestPassword123!"

    comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(data, password)
    out = decrypt_to_raw(
        cipher, password, salt, nonce,
        orig_len=len(data), comp_len=len(comp), sha256=sha256
    )
    assert out == data


def test_encrypt_decrypt_with_keyfile():
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

    data = b"Test data to encrypt with keyfile"
    password = "TestPassword123!"
    keyfile = secrets.token_bytes(128)

    comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(
        data, password, keyfile=keyfile
    )
    out = decrypt_to_raw(
        cipher, password, salt, nonce, keyfile,
        orig_len=len(data), comp_len=len(comp), sha256=sha256
    )
    assert out == data


def test_encrypt_decrypt_wrong_password_fails():
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

    data = b"Test data"
    password = "TestPassword123!"
    wrong = "WrongPassword456!"

    comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password)
    with pytest.raises(RuntimeError, match="Decryption failed"):
        decrypt_to_raw(
            cipher, wrong, salt, nonce,
            orig_len=len(data), comp_len=len(comp), sha256=sha256
        )


def test_encrypt_forward_secrecy_roundtrip():
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
    from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair

    data = b"Secret data for forward secrecy test"
    password = "TestPassword123!"
    receiver_priv, receiver_pub = generate_receiver_keypair()

    comp, sha256, salt, nonce, cipher, ephemeral, _ = encrypt_file_bytes(
        data, password, receiver_public_key=receiver_pub
    )

    out = decrypt_to_raw(
        cipher, password, salt, nonce,
        orig_len=len(data), comp_len=len(comp), sha256=sha256,
        ephemeral_public_key=ephemeral, receiver_private_key=receiver_priv
    )
    assert out == data


def test_decrypt_forward_secrecy_missing_private_key_fails():
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
    from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair

    data = b"Test data"
    password = "TestPassword123!"
    _, receiver_pub = generate_receiver_keypair()

    comp, sha256, salt, nonce, cipher, ephemeral, _ = encrypt_file_bytes(
        data, password, receiver_public_key=receiver_pub
    )

    with pytest.raises(RuntimeError, match="requires receiver private key"):
        decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data), comp_len=len(comp), sha256=sha256,
            ephemeral_public_key=ephemeral
        )


def test_precomputed_key_paths():
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

    data = b"Test data for HSM mode"
    password = "TestPassword123!"
    precomputed_key = secrets.token_bytes(32)
    precomputed_salt = secrets.token_bytes(16)

    comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
        data, password, precomputed_key=precomputed_key, precomputed_salt=precomputed_salt
    )

    assert key == precomputed_key
    assert salt == precomputed_salt
    assert ephemeral is None

    out = decrypt_to_raw(
        cipher, password, salt, nonce,
        orig_len=len(data), comp_len=len(comp), sha256=sha256,
        precomputed_key=precomputed_key
    )
    assert out == data

    with pytest.raises((ValueError, RuntimeError)):
        encrypt_file_bytes(
            data, password,
            precomputed_key=secrets.token_bytes(16),
            precomputed_salt=secrets.token_bytes(16)
        )

    with pytest.raises(RuntimeError, match="32 bytes"):
        decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data), comp_len=len(comp), sha256=sha256,
            precomputed_key=b"short"
        )


def test_manifest_pack_unpack_variants():
    from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest

    base = Manifest(
        salt=secrets.token_bytes(16),
        nonce=secrets.token_bytes(12),
        orig_len=1000,
        comp_len=800,
        cipher_len=850,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=10,
        hmac=secrets.token_bytes(32),
    )

    packed = pack_manifest(base)
    assert len(packed) == 115
    unpacked = unpack_manifest(packed)
    assert unpacked.orig_len == base.orig_len

    fs = base
    fs.ephemeral_public_key = secrets.token_bytes(32)
    packed_fs = pack_manifest(fs)
    assert len(packed_fs) == 147

    fs.duress_tag = secrets.token_bytes(32)
    packed_duress = pack_manifest(fs)
    assert len(packed_duress) == 179

    fs.pq_ciphertext = secrets.token_bytes(1088)
    packed_pq = pack_manifest(fs)
    assert len(packed_pq) == 1267


def test_manifest_pack_validation_errors():
    from meow_decoder.crypto import Manifest, pack_manifest

    manifest = Manifest(
        salt=secrets.token_bytes(16),
        nonce=secrets.token_bytes(12),
        orig_len=1000,
        comp_len=800,
        cipher_len=850,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=10,
        hmac=secrets.token_bytes(32),
        ephemeral_public_key=secrets.token_bytes(16),
    )

    with pytest.raises(ValueError, match="Ephemeral public key must be 32 bytes"):
        pack_manifest(manifest)

    manifest.ephemeral_public_key = secrets.token_bytes(32)
    manifest.pq_ciphertext = secrets.token_bytes(500)
    with pytest.raises(ValueError, match="PQ ciphertext must be 1088 bytes"):
        pack_manifest(manifest)

    manifest.pq_ciphertext = None
    manifest.duress_tag = secrets.token_bytes(16)
    with pytest.raises(ValueError, match="Duress tag must be 32 bytes"):
        pack_manifest(manifest)


def test_manifest_unpack_invalid_length_or_magic():
    from meow_decoder.crypto import unpack_manifest, MAGIC

    with pytest.raises(ValueError, match="too short"):
        unpack_manifest(b"short")

    data = MAGIC + secrets.token_bytes(116)
    with pytest.raises(ValueError, match="invalid"):
        unpack_manifest(data)

    data = b"XXXX3" + secrets.token_bytes(110)
    with pytest.raises(ValueError, match="Invalid MAGIC"):
        unpack_manifest(data)


def test_manifest_unpack_meow2_compat():
    from meow_decoder.crypto import unpack_manifest

    data = bytearray(115)
    data[0:5] = b"MEOW2"
    data[5:21] = secrets.token_bytes(16)
    data[21:33] = secrets.token_bytes(12)
    data[51:83] = secrets.token_bytes(32)
    data[83:115] = secrets.token_bytes(32)

    manifest = unpack_manifest(bytes(data))
    assert manifest.ephemeral_public_key is None


def test_pack_manifest_core_includes_pq_and_duress():
    from meow_decoder.crypto import Manifest, pack_manifest_core

    duress = secrets.token_bytes(32)
    pq_ct = secrets.token_bytes(1088)

    manifest = Manifest(
        salt=secrets.token_bytes(16),
        nonce=secrets.token_bytes(12),
        orig_len=1000,
        comp_len=800,
        cipher_len=850,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=10,
        hmac=secrets.token_bytes(32),
        ephemeral_public_key=secrets.token_bytes(32),
        pq_ciphertext=pq_ct,
        duress_tag=duress,
    )

    core_without = pack_manifest_core(manifest, include_duress_tag=False)
    core_with = pack_manifest_core(manifest, include_duress_tag=True)

    assert pq_ct in core_with
    assert duress not in core_without
    assert duress in core_with
    assert len(core_with) - len(core_without) == 32


def test_manifest_hmac_verify_paths():
    from meow_decoder.crypto import (
        Manifest, compute_manifest_hmac, verify_manifest_hmac,
        derive_key, pack_manifest_core
    )

    password = "TestPassword123!"
    wrong = "WrongPassword456!"
    salt = secrets.token_bytes(16)

    manifest = Manifest(
        salt=salt,
        nonce=secrets.token_bytes(12),
        orig_len=1000,
        comp_len=800,
        cipher_len=850,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=10,
        hmac=b"\x00" * 32,
        ephemeral_public_key=None,
    )

    packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)
    enc_key = derive_key(password, salt)
    manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)

    assert verify_manifest_hmac(password, manifest) is True
    assert verify_manifest_hmac(wrong, manifest) is False


def test_verify_hmac_fallback_to_secrets_compare(monkeypatch):
    from meow_decoder.crypto import Manifest, derive_key, compute_manifest_hmac, pack_manifest_core

    password = "TestPassword123!"
    salt = secrets.token_bytes(16)

    manifest = Manifest(
        salt=salt,
        nonce=secrets.token_bytes(12),
        orig_len=100,
        comp_len=80,
        cipher_len=96,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=10,
        hmac=b"\x00" * 32,
    )

    packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=True)
    enc_key = derive_key(password, salt)
    manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)

    original_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if "constant_time" in name:
            raise ImportError(f"blocked: {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocking_import)

    import meow_decoder.crypto as crypto_module
    importlib.reload(crypto_module)

    assert crypto_module.verify_manifest_hmac(password, manifest) is True

    importlib.reload(crypto_module)


def test_duress_tag_binding():
    from meow_decoder.crypto import (
        compute_duress_tag, check_duress_password,
        Manifest, pack_manifest_core
    )

    salt = secrets.token_bytes(16)
    duress_password = "DuressSignal999"

    manifest = Manifest(
        salt=salt,
        nonce=secrets.token_bytes(12),
        orig_len=1000,
        comp_len=800,
        cipher_len=816,
        sha256=secrets.token_bytes(32),
        block_size=512,
        k_blocks=10,
        hmac=secrets.token_bytes(32),
        ephemeral_public_key=secrets.token_bytes(32),
    )

    core = pack_manifest_core(manifest, include_duress_tag=False)
    tag = compute_duress_tag(duress_password, salt, core)

    assert check_duress_password(duress_password, salt, tag, core) is True
    assert check_duress_password("WrongPassword!", salt, tag, core) is False

    manifest.orig_len = 9999
    tampered = pack_manifest_core(manifest, include_duress_tag=False)
    assert check_duress_password(duress_password, salt, tag, tampered) is False


def test_nonce_reuse_guard_and_cache_clear():
    from meow_decoder.crypto import (
        _NONCE_REUSE_CACHE_MAX, _nonce_reuse_cache, _register_nonce_use
    )

    _nonce_reuse_cache.clear()

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    _register_nonce_use(key, nonce)

    with pytest.raises(RuntimeError, match="Nonce reuse detected"):
        _register_nonce_use(key, nonce)

    for _ in range(_NONCE_REUSE_CACHE_MAX + 10):
        _register_nonce_use(secrets.token_bytes(32), secrets.token_bytes(12))

    assert len(_nonce_reuse_cache) <= _NONCE_REUSE_CACHE_MAX


def test_keyfile_verification():
    from meow_decoder.crypto import verify_keyfile

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(secrets.token_bytes(64))
        path = f.name

    try:
        keyfile = verify_keyfile(path)
        assert len(keyfile) == 64
    finally:
        os.unlink(path)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"short")
        path = f.name

    try:
        with pytest.raises(ValueError, match="too small"):
            verify_keyfile(path)
    finally:
        os.unlink(path)

    with pytest.raises(FileNotFoundError):
        verify_keyfile("/nonexistent/keyfile.key")


def test_yubikey_paths_mocked():
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, derive_encryption_key_for_manifest

    data = b"Test data for YubiKey"
    password = "TestPassword123!"
    expected_key = secrets.token_bytes(32)

    mock_backend = MagicMock()
    mock_backend.derive_key_yubikey.return_value = expected_key
    mock_backend.aes_gcm_encrypt.return_value = secrets.token_bytes(100)
    mock_backend.aes_gcm_decrypt.return_value = hashlib.sha256(b"x").digest()  # dummy

    with patch("meow_decoder.crypto.get_default_backend", return_value=mock_backend):
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            data, password, yubikey_slot="9d", yubikey_pin="123456"
        )
        assert key == expected_key

    with patch("meow_decoder.crypto.get_default_backend", return_value=mock_backend):
        # decrypt path uses mocked backend output; may fail on decompress, so just exercise path
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                b"cipher", password, secrets.token_bytes(16), secrets.token_bytes(12),
                yubikey_slot="9d", yubikey_pin="123456"
            )

    with patch("meow_decoder.crypto.get_default_backend", return_value=mock_backend):
        key = derive_encryption_key_for_manifest(
            password, secrets.token_bytes(16), yubikey_slot="9d", yubikey_pin="123456"
        )
        assert key == expected_key


def test_yubikey_keyfile_conflicts():
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, derive_encryption_key_for_manifest

    keyfile = secrets.token_bytes(64)

    with pytest.raises(RuntimeError, match="Cannot combine --yubikey with --keyfile"):
        encrypt_file_bytes(
            b"data", "TestPassword123!", keyfile=keyfile, yubikey_slot="9d"
        )

    with pytest.raises(RuntimeError, match="Cannot combine --yubikey with --keyfile"):
        decrypt_to_raw(
            b"cipher", "TestPassword123!", secrets.token_bytes(16), secrets.token_bytes(12),
            keyfile=keyfile, yubikey_slot="9d"
        )

    with pytest.raises(ValueError, match="Cannot combine --yubikey with --keyfile"):
        derive_encryption_key_for_manifest(
            "TestPassword123!", secrets.token_bytes(16), keyfile=keyfile, yubikey_slot="9d"
        )


def test_encrypt_backend_error_wrapped():
    from meow_decoder.crypto import encrypt_file_bytes

    mock_backend = MagicMock()
    mock_backend.derive_key_argon2id.side_effect = Exception("Backend failure")

    with patch("meow_decoder.crypto.get_default_backend", return_value=mock_backend):
        with pytest.raises(RuntimeError, match="Encryption failed"):
            encrypt_file_bytes(b"data", "TestPassword123!")


def test_metadata_obfuscation_import_fallbacks(monkeypatch):
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

    fake = type(sys)("metadata_obfuscation")
    fake.called_add = False
    fake.called_remove = False

    def add_length_padding(data: bytes) -> bytes:
        fake.called_add = True
        return data

    def remove_length_padding(data: bytes) -> bytes:
        fake.called_remove = True
        return data

    fake.add_length_padding = add_length_padding
    fake.remove_length_padding = remove_length_padding

    original_import = builtins.__import__
    previous = sys.modules.get("metadata_obfuscation")
    sys.modules["metadata_obfuscation"] = fake

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if (
            globals
            and globals.get("__name__") == "meow_decoder.crypto"
            and level == 1
            and name == "metadata_obfuscation"
        ):
            raise ImportError("forced for coverage")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    try:
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            b"padding fallback" * 50, "TestPassword123!", use_length_padding=True
        )
        assert fake.called_add is True

        out = decrypt_to_raw(
            cipher, "TestPassword123!", salt, nonce,
            orig_len=len(b"padding fallback" * 50),
            comp_len=len(comp),
            sha256=sha,
        )
        assert out == b"padding fallback" * 50
        assert fake.called_remove is True
    finally:
        if previous is None:
            sys.modules.pop("metadata_obfuscation", None)
        else:
            sys.modules["metadata_obfuscation"] = previous


def test_decrypt_padding_removal_value_error_ignored(monkeypatch):
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
    import meow_decoder.metadata_obfuscation as real_mod

    data = b"padding removal error" * 10
    password = "TestPassword123!"
    comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
        data, password, use_length_padding=False
    )

    def boom(_data: bytes) -> bytes:
        raise ValueError("forced")

    monkeypatch.setattr(real_mod, "remove_length_padding", boom)

    out = decrypt_to_raw(
        cipher, password, salt, nonce,
        orig_len=len(data), comp_len=len(comp), sha256=sha
    )
    assert out == data


def test_decrypt_no_aad_compatibility():
    import zlib
    from meow_decoder.crypto import decrypt_to_raw, derive_key
    from meow_decoder.crypto_backend import get_default_backend

    raw = b"old-style no-aad ciphertext" * 5
    password = "TestPassword123!"
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt)

    comp = zlib.compress(raw, level=9)
    backend = get_default_backend()
    cipher = backend.aes_gcm_encrypt(key, nonce, comp, aad=None)

    out = decrypt_to_raw(cipher, password, salt, nonce)
    assert out == raw


@settings(max_examples=20)
@given(
    data=st.binary(min_size=1, max_size=4096),
    password=st.text(min_size=8, max_size=32, alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"), min_codepoint=33, max_codepoint=126
    ))
)
def test_property_encrypt_decrypt_roundtrip(data, password):
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

    comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password)
    out = decrypt_to_raw(cipher, password, salt, nonce, orig_len=len(data), comp_len=len(comp), sha256=sha)
    assert out == data


@settings(max_examples=10)
@given(salt=st.binary(min_size=16, max_size=16))
def test_property_kdf_deterministic(salt):
    from meow_decoder.crypto import derive_key

    password = "TestPassword123!"
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2


@settings(max_examples=10)
@given(password=st.text(min_size=1, max_size=7))
def test_property_kdf_rejects_short_passwords(password):
    from meow_decoder.crypto import derive_key

    with pytest.raises(ValueError, match="at least 8 characters"):
        derive_key(password, secrets.token_bytes(16))


# -----------------------------------------------------------------------------
# crypto_enhanced.py
# -----------------------------------------------------------------------------
from meow_decoder.crypto_enhanced import (
    SecureBytes,
    secure_key_context,
    derive_key as derive_key_enhanced,
    derive_block_key,
    encrypt_file_bytes as encrypt_file_bytes_enhanced,
    decrypt_to_raw as decrypt_to_raw_enhanced,
    pack_manifest as pack_manifest_enhanced,
    unpack_manifest as unpack_manifest_enhanced,
    compute_manifest_hmac as compute_manifest_hmac_enhanced,
    verify_manifest_hmac as verify_manifest_hmac_enhanced,
    secure_wipe,
    verify_keyfile as verify_keyfile_enhanced,
    secure_compare,
    StreamingEncryption,
    Manifest as EnhancedManifest,
    MAGIC as ENHANCED_MAGIC,
)


class TestCryptoEnhanced:
    def test_secure_bytes_basic(self):
        data = b"sensitive data"
        sb = SecureBytes(data)
        assert sb.get_bytes() == data
        assert len(sb) == len(data)

    def test_secure_bytes_context(self):
        data = b"secret key material"
        with SecureBytes(data) as sb:
            assert sb.get_bytes() == data

    def test_secure_key_context(self):
        key = b"A" * 32
        with secure_key_context(key) as k:
            assert k == key

    def test_derive_key_enhanced(self):
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        key = derive_key_enhanced(password, salt)
        assert len(key) == 32

    def test_derive_block_key(self):
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        key0 = derive_block_key(master_key, 0, salt)
        key1 = derive_block_key(master_key, 1, salt)
        assert key0 != key1
        assert len(key0) == 32

    def test_encrypt_decrypt_enhanced_roundtrip(self):
        data = b"Hello, Meow Decoder! " * 50
        password = "encrypt_test_password"
        comp, sha, salt, nonce, cipher = encrypt_file_bytes_enhanced(data, password)
        out = decrypt_to_raw_enhanced(cipher, password, salt, nonce)
        assert out == data

    def test_manifest_pack_unpack_enhanced(self):
        manifest = EnhancedManifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
        )
        packed = pack_manifest_enhanced(manifest)
        assert packed[: len(ENHANCED_MAGIC)] == ENHANCED_MAGIC
        unpacked = unpack_manifest_enhanced(packed)
        assert unpacked.orig_len == manifest.orig_len

    def test_hmac_enhanced(self):
        password = "hmac_test"
        salt = secrets.token_bytes(16)
        packed = secrets.token_bytes(100)
        hmac = compute_manifest_hmac_enhanced(password, salt, packed)
        assert len(hmac) == 32
        assert verify_manifest_hmac_enhanced(hmac, hmac) is True

    def test_secure_wipe(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"sensitive data")
            path = f.name
        secure_wipe(path)
        assert not os.path.exists(path)

    def test_verify_keyfile_enhanced(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as f:
            f.write(secrets.token_bytes(64))
            path = f.name
        try:
            keyfile = verify_keyfile_enhanced(path)
            assert len(keyfile) == 64
        finally:
            os.unlink(path)

    def test_secure_compare(self):
        assert secure_compare(b"a", b"a") is True
        assert secure_compare(b"a", b"b") is False

    def test_streaming_encryption_class(self):
        import io

        password = "stream_test"
        salt = secrets.token_bytes(16)
        data = b"Stream test data " * 100

        enc = StreamingEncryption(password, salt)
        input_stream = io.BytesIO(data)
        output_stream = io.BytesIO()
        nonce, compressed_size, original_size = enc.encrypt_stream(input_stream, output_stream)

        assert len(nonce) == 12
        assert original_size == len(data)
        assert compressed_size <= len(data)


# -----------------------------------------------------------------------------
# streaming_crypto.py
# -----------------------------------------------------------------------------
from meow_decoder.streaming_crypto import (
    MemoryConfig,
    StreamingCipher,
    MemoryMonitor,
    create_streaming_encoder,
    HAS_PSUTIL,
)


class TestStreamingCrypto:
    def test_memory_config_init(self):
        config = MemoryConfig(
            chunk_size=65536,
            max_memory_mb=100,
            enable_gc=True,
            enable_mlock=False,
        )
        assert config.chunk_size == 65536

    def test_streaming_cipher_init_and_encrypt_decrypt(self):
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key, chunk_size=1024)

        data = b"Hello, Streaming Crypto! " * 100
        input_stream = io.BytesIO(data)
        encrypted_stream = io.BytesIO()

        orig_size, comp_size, sha256 = cipher.encrypt_stream(
            input_stream, encrypted_stream, enable_compression=True
        )

        assert orig_size == len(data)
        assert len(sha256) == 32

        decryptor = StreamingCipher(key, nonce=cipher.nonce, chunk_size=1024)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        total_written = decryptor.decrypt_stream(
            encrypted_stream, decrypted_stream, enable_decompression=True
        )

        assert decrypted_stream.getvalue() == data
        assert total_written == len(data)

    def test_streaming_cipher_validation_errors(self):
        key = secrets.token_bytes(32)
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            StreamingCipher(b"short")
        with pytest.raises(ValueError, match="Nonce must be 16 bytes"):
            StreamingCipher(key, nonce=b"short")

    def test_decrypt_invalid_compressed_data(self):
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key)
        encrypted_stream = io.BytesIO(secrets.token_bytes(100))
        decrypted_stream = io.BytesIO()

        with pytest.raises(RuntimeError, match="Decompression failed"):
            cipher.decrypt_stream(encrypted_stream, decrypted_stream, enable_decompression=True)

    def test_wrong_nonce_produces_garbage(self):
        key = secrets.token_bytes(32)
        data = b"test data" * 50

        enc = StreamingCipher(key)
        inp = io.BytesIO(data)
        enc_out = io.BytesIO()
        enc.encrypt_stream(inp, enc_out, enable_compression=False)

        dec = StreamingCipher(key, nonce=secrets.token_bytes(16))
        enc_out.seek(0)
        dec_out = io.BytesIO()
        dec.decrypt_stream(enc_out, dec_out, enable_decompression=False)

        assert dec_out.getvalue() != data


# -----------------------------------------------------------------------------
# pq_hybrid.py
# -----------------------------------------------------------------------------
try:
    from meow_decoder import pq_hybrid
    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False


class TestPQHybrid:
    def test_is_pq_available_flag(self):
        if not PQ_AVAILABLE:
            pytest.skip("PQ module not available")
        assert isinstance(pq_hybrid.LIBOQS_AVAILABLE, bool)

    def test_hybrid_keypair_generation(self):
        if not PQ_AVAILABLE:
            pytest.skip("PQ module not available")
        keypair = pq_hybrid.HybridKeyPair(use_pq=True)
        classical_pub, pq_pub = keypair.export_public_keys()
        assert len(classical_pub) == 32
        if pq_hybrid.LIBOQS_AVAILABLE:
            assert pq_pub is not None
        else:
            assert pq_pub is None

    def test_hybrid_encapsulate_classical_only(self):
        if not PQ_AVAILABLE:
            pytest.skip("PQ module not available")

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        shared, eph_pub, pq_ct, pq_ss = pq_hybrid.hybrid_encapsulate(public, None)
        assert len(shared) == 32
        assert len(eph_pub) == 32
        assert pq_ct is None
        assert pq_ss is None

    def test_hybrid_encapsulate_fail_closed_when_pq_requested_unavailable(self, monkeypatch):
        if not PQ_AVAILABLE:
            pytest.skip("PQ module not available")

        monkeypatch.setattr(pq_hybrid, "LIBOQS_AVAILABLE", False)
        monkeypatch.setattr(pq_hybrid, "PQ_ALGORITHM", None)

        with pytest.raises(RuntimeError):
            pq_hybrid.hybrid_encapsulate(
                receiver_classical_public=secrets.token_bytes(32),
                receiver_pq_public=b"\x00" * 1568,
            )


# -----------------------------------------------------------------------------
# pq_signatures.py
# -----------------------------------------------------------------------------
from meow_decoder.pq_signatures import (
    get_available_algorithms,
    generate_keypair,
    sign_manifest,
    Signature,
    SignatureKeyPair,
    SIG_ED25519,
    SIG_DILITHIUM3,
    SIG_HYBRID,
    DILITHIUM_AVAILABLE,
    HAS_LIBOQS,
)


class TestPQSignatures:
    def test_algorithms_include_ed25519(self):
        algos = get_available_algorithms()
        assert "ed25519" in algos

    def test_ed25519_keypair_and_sign(self):
        keypair = generate_keypair("ed25519")
        assert keypair.algorithm == SIG_ED25519
        signature = sign_manifest(b"test manifest", keypair)
        assert signature.algorithm == SIG_ED25519
        packed = signature.pack()
        unpacked = Signature.unpack(packed)
        assert unpacked.signature == signature.signature

    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="liboqs not available")
    def test_dilithium_and_hybrid(self):
        keypair = generate_keypair("dilithium3")
        assert keypair.algorithm == SIG_DILITHIUM3

        hybrid = generate_keypair("hybrid")
        assert hybrid.algorithm == SIG_HYBRID
        sig = sign_manifest(b"hybrid message", hybrid)
        packed = sig.pack()
        unpacked = Signature.unpack(packed)
        assert unpacked.ed25519_sig == sig.ed25519_sig
        assert unpacked.dilithium_sig == sig.dilithium_sig

    def test_unknown_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unknown algorithm"):
            generate_keypair("nonexistent_algo")


# -----------------------------------------------------------------------------
# Hypothesis + property tests (crypto core)
# -----------------------------------------------------------------------------


@settings(max_examples=20)
@given(
    data=st.binary(min_size=1, max_size=2048),
    password=st.text(min_size=8, max_size=32, alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"), min_codepoint=33, max_codepoint=126
    )),
)
def test_property_encrypt_decrypt_roundtrip_small(data, password):
    from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

    comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password)
    out = decrypt_to_raw(cipher, password, salt, nonce, orig_len=len(data), comp_len=len(comp), sha256=sha)
    assert out == data


@settings(max_examples=10)
@given(
    orig_len=st.integers(min_value=0, max_value=10**9),
    comp_len=st.integers(min_value=0, max_value=10**9),
    cipher_len=st.integers(min_value=0, max_value=10**9),
    block_size=st.integers(min_value=64, max_value=65535),
    k_blocks=st.integers(min_value=1, max_value=10**6),
)
def test_property_manifest_pack_unpack(orig_len, comp_len, cipher_len, block_size, k_blocks):
    from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest

    manifest = Manifest(
        salt=secrets.token_bytes(16),
        nonce=secrets.token_bytes(12),
        orig_len=orig_len,
        comp_len=comp_len,
        cipher_len=cipher_len,
        sha256=secrets.token_bytes(32),
        block_size=block_size,
        k_blocks=k_blocks,
        hmac=secrets.token_bytes(32),
    )

    packed = pack_manifest(manifest)
    unpacked = unpack_manifest(packed)
    assert unpacked.orig_len == manifest.orig_len
    assert unpacked.comp_len == manifest.comp_len
    assert unpacked.cipher_len == manifest.cipher_len
    assert unpacked.block_size == manifest.block_size
    assert unpacked.k_blocks == manifest.k_blocks
