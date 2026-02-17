"""Tests for debug and profiling modules."""

import pytest
import ast
from pathlib import Path


class TestCryptoDebug:
    def test_crypto_debug_import(self):
        try:
            from legacy_py import crypto_DEBUG

            assert crypto_DEBUG is not None
        except ImportError:
            pytest.skip("crypto_DEBUG module not available (moved to legacy_py/)")


class TestEncodeDebug:
    def test_encode_debug_import(self):
        try:
            from meow_decoder import encode_DEBUG

            assert encode_DEBUG is not None
        except ImportError:
            pytest.skip("encode_DEBUG module not available")


class TestProfilingImproved:
    def test_profiling_import(self):
        try:
            from meow_decoder import profiling_improved

            assert profiling_improved is not None
        except ImportError:
            pytest.skip("profiling_improved module not available")


class TestMeowEncode:
    def test_meow_encode_import(self):
        try:
            from meow_decoder import meow_encode

            assert meow_encode is not None
        except ImportError:
            pytest.skip("meow_encode module not available")


class TestSetupModule:
    def test_setup_syntax_valid(self):
        setup_path = Path(__file__).parent.parent / "meow_decoder" / "setup.py"
        if setup_path.exists():
            with open(setup_path) as f:
                content = f.read()
            ast.parse(content)
        else:
            pytest.skip("setup.py not found in meow_decoder/")


# --- Merged from test_debug_modules_comprehensive.py ---

import hashlib
import types
from pathlib import Path

import legacy_py.crypto_DEBUG as crypto_debug
import meow_decoder.encode_DEBUG as encode_debug


def _fast_derive_key(password: str, salt: bytes, keyfile=None) -> bytes:
    return hashlib.sha256(password.encode("utf-8") + salt).digest()


def test_crypto_debug_pack_unpack_manifest_roundtrip():
    manifest = crypto_debug.Manifest(
        salt=b"a" * 16,
        nonce=b"b" * 12,
        orig_len=1,
        comp_len=2,
        cipher_len=3,
        sha256=b"c" * 32,
        block_size=512,
        k_blocks=4,
        hmac=b"d" * 32,
        ephemeral_public_key=None,
        pq_ciphertext=None,
    )
    packed = crypto_debug.pack_manifest(manifest)
    unpacked = crypto_debug.unpack_manifest(packed)
    assert unpacked.salt == manifest.salt
    assert unpacked.nonce == manifest.nonce
    assert unpacked.sha256 == manifest.sha256


def test_crypto_debug_compute_manifest_hmac_with_encryption_key():
    packed = b"payload"
    hmac_val = crypto_debug.compute_manifest_hmac(
        password="pw",
        salt=b"a" * 16,
        packed_no_hmac=packed,
        encryption_key=b"k" * 32,
    )
    assert isinstance(hmac_val, bytes)
    assert len(hmac_val) == 32


def test_crypto_debug_verify_manifest_hmac(monkeypatch):
    monkeypatch.setattr(crypto_debug, "derive_key", _fast_derive_key)
    manifest = crypto_debug.Manifest(
        salt=b"a" * 16,
        nonce=b"b" * 12,
        orig_len=1,
        comp_len=2,
        cipher_len=3,
        sha256=b"c" * 32,
        block_size=512,
        k_blocks=4,
        hmac=b"\x00" * 32,
        ephemeral_public_key=None,
        pq_ciphertext=None,
    )
    packed_no_hmac = (
        crypto_debug.MAGIC
        + manifest.salt
        + manifest.nonce
        + crypto_debug.struct.pack(
            ">III", manifest.orig_len, manifest.comp_len, manifest.cipher_len
        )
        + crypto_debug.struct.pack(">HI", manifest.block_size, manifest.k_blocks)
        + manifest.sha256
    )
    manifest.hmac = crypto_debug.compute_manifest_hmac(
        "pw",
        manifest.salt,
        packed_no_hmac,
    )
    assert crypto_debug.verify_manifest_hmac("pw", manifest) is True


def test_encode_debug_encode_file_smoke(tmp_path, monkeypatch):
    input_path = tmp_path / "in.txt"
    output_path = tmp_path / "out.gif"
    input_path.write_bytes(b"hello")

    def fake_encrypt(raw, password, keyfile, receiver_public_key, use_length_padding=True):
        comp = b"comp"
        sha = b"s" * 32
        salt = b"a" * 16
        nonce = b"b" * 12
        cipher = b"ciphertext"
        return comp, sha, salt, nonce, cipher, None, b"k" * 32

    class FakeFountain:
        def __init__(self, data, k_blocks, block_size):
            self.data = data

        def droplet(self):
            return object()

    class FakeQR:
        def __init__(self, *args, **kwargs):
            pass

        def generate(self, data):
            return types.SimpleNamespace(size=(10, 10))

    class FakeGIF:
        def __init__(self, fps=10, loop=0):
            pass

        def create_gif(self, frames, output_path, optimize=True):
            Path(output_path).write_bytes(b"gif")
            return 3

    fake_frame_mac = types.SimpleNamespace(
        pack_frame_with_mac=lambda payload, key, idx, salt: payload + b"mac",
        FrameMACStats=lambda: types.SimpleNamespace(record_valid=lambda: None),
        derive_frame_master_key=lambda key, salt: b"m" * 32,
    )

    monkeypatch.setattr(encode_debug, "encrypt_file_bytes", fake_encrypt)
    monkeypatch.setattr(encode_debug, "FountainEncoder", FakeFountain)
    monkeypatch.setattr(encode_debug, "pack_droplet", lambda droplet: b"drop")
    monkeypatch.setattr(encode_debug, "QRCodeGenerator", FakeQR)
    monkeypatch.setattr(encode_debug, "GIFEncoder", FakeGIF)
    monkeypatch.setitem(__import__("sys").modules, "meow_decoder.frame_mac", fake_frame_mac)

    stats = encode_debug.encode_file(input_path, output_path, password="pw", verbose=False)
    assert stats["input_size"] == 5
    assert stats["output_size"] == 3
    assert stats["qr_frames"] >= 1
