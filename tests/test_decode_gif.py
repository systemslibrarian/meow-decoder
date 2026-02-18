#!/usr/bin/env python3
"""Tests for meow_decoder.decode_gif.
Uses stubs to avoid heavy QR/GIF dependencies.
"""

from pathlib import Path
import pytest
from PIL import Image
import meow_decoder.decode_gif as decode_mod
from meow_decoder.crypto import Manifest, pack_manifest
import meow_decoder.crypto as _crypto_mod
from meow_decoder.fountain import Droplet, pack_droplet

# Imports from merged file
from unittest.mock import patch


class _DummyGIFDecoder:
    def __init__(self, frames=None):
        if frames is None:
            frames = [Image.new("RGB", (64, 64), color=(0, 0, 0))]
        self._frames = frames

    def extract_frames(self, input_path: Path):
        return list(self._frames)


class _DummyQRCodeReader:
    def __init__(self, *args, **kwargs):
        self._calls = 0

    def read_image(self, frame):
        self._calls += 1
        return []


class _SequenceQRCodeReader:
    def __init__(self, sequence):
        self._sequence = list(sequence)

    def read_image(self, frame):
        if self._sequence:
            return [self._sequence.pop(0)]
        return []


class _DummyFountainDecoder:
    def __init__(self, *args, **kwargs):
        self.decoded_count = 1
        self.k_blocks = 1

    def add_droplet(self, droplet):
        return True

    def is_complete(self):
        return True

    def get_data(self, original_length: int):
        return b"dummy-cipher"[:original_length]


class _IncompleteFountainDecoder(_DummyFountainDecoder):
    def __init__(self, *args, **kwargs):
        self.decoded_count = 0
        self.k_blocks = 2

    def is_complete(self):
        return False


def _build_manifest_bytes(
    plaintext: bytes, block_size: int = 64, k_blocks: int = 1, ephemeral_public_key: bytes = None
):
    import hashlib

    manifest = Manifest(
        salt=b"S" * 16,
        nonce=b"N" * 12,
        orig_len=len(plaintext),
        comp_len=1,
        cipher_len=len(b"dummy-cipher"),
        sha256=hashlib.sha256(plaintext).digest(),
        block_size=block_size,
        k_blocks=k_blocks,
        hmac=b"\x00" * 32,
        ephemeral_public_key=ephemeral_public_key,
        mode_byte=0x03 if ephemeral_public_key is not None else 0x02,
    )
    return pack_manifest(manifest)


def test_decode_gif_no_frames(tmp_path, monkeypatch):
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder(frames=[]))

    with pytest.raises(ValueError, match="No frames found in GIF"):
        decode_mod.decode_gif(
            tmp_path / "in.gif", tmp_path / "out.bin", password="password123", verbose=False
        )


def test_decode_gif_no_qr_codes(tmp_path, monkeypatch):
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder())
    monkeypatch.setattr(decode_mod, "QRCodeReader", lambda preprocessing=None: _DummyQRCodeReader())

    with pytest.raises(ValueError, match="No QR codes found in GIF"):
        decode_mod.decode_gif(
            tmp_path / "in.gif", tmp_path / "out.bin", password="password123", verbose=True
        )


def test_decode_gif_invalid_manifest_length(tmp_path, monkeypatch):
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder())

    class _BadReader(_DummyQRCodeReader):
        def read_image(self, frame):
            return [b"X" * 50]

    monkeypatch.setattr(decode_mod, "QRCodeReader", lambda preprocessing=None: _BadReader())

    with pytest.raises(ValueError, match="Manifest QR decode corrupted"):
        decode_mod.decode_gif(
            tmp_path / "in.gif", tmp_path / "out.bin", password="password123", verbose=False
        )


def test_decode_gif_happy_path(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )

    class _Reader(_DummyQRCodeReader):
        def read_image(self, frame):
            self._calls += 1
            if self._calls == 1:
                return [manifest_bytes]
            if self._calls == 2:
                return [droplet_bytes]
            return []

    monkeypatch.setattr(decode_mod, "QRCodeReader", lambda preprocessing=None: _Reader())
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type("HB", (), {"drop": lambda self, h: None})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: plaintext)

    out_path = tmp_path / "out.bin"
    stats = decode_mod.decode_gif(
        tmp_path / "in.gif", out_path, password="password123", verbose=False
    )

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)


def test_decode_gif_hmac_failure(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_bytes, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: False)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\xff" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type("HB", (), {"drop": lambda self, h: None})())

    with pytest.raises(ValueError, match="HMAC verification failed"):
        decode_mod.decode_gif(
            tmp_path / "in.gif", tmp_path / "out.bin", password="password123", verbose=False
        )


def test_decode_gif_frame_mac_invalid_fails_closed(tmp_path, monkeypatch):
    """FIX-E1: Invalid frame MAC now raises ValueError (fail-closed)."""
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)
    manifest_with_mac = b"\x00" * 8 + manifest_bytes

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_with_mac, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type(
        "HB", (), {"drop": lambda self, h: None, "import_key": lambda self, k: 99})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: plaintext)

    import meow_decoder.frame_mac as frame_mac
    monkeypatch.setattr(frame_mac, "derive_frame_master_key_handle", lambda *a, **kw: 42)

    def _invalid_manifest(*args, **kwargs):
        return (False, b"")

    monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", _invalid_manifest)

    out_path = tmp_path / "out.bin"

    # FIX-E1: Frame MAC invalid now raises ValueError instead of silently disabling
    with pytest.raises((ValueError, RuntimeError), match="[Ff]rame MAC"):
        decode_mod.decode_gif(tmp_path / "in.gif", out_path, password="password123", verbose=True)


def test_decode_gif_frame_mac_legacy_valid(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)
    manifest_with_mac = b"\x00" * 8 + manifest_bytes

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_with_mac, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type(
        "HB", (), {"drop": lambda self, h: None, "import_key": lambda self, k: 99})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: plaintext)

    import meow_decoder.frame_mac as frame_mac
    monkeypatch.setattr(frame_mac, "derive_frame_master_key_handle", lambda *a, **kw: 42)

    calls = []

    def _unpack_frame_with_mac(data, *args, **kwargs):
        calls.append(data)
        if len(calls) == 1:
            return (False, b"")
        if len(calls) == 2:
            return (True, b"")
        return (True, droplet_bytes)

    monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", _unpack_frame_with_mac)

    out_path = tmp_path / "out.bin"
    stats = decode_mod.decode_gif(
        tmp_path / "in.gif", out_path, password="password123", verbose=True
    )

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)


def test_decode_gif_incomplete_decode(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext, k_blocks=2)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_bytes, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type("HB", (), {"drop": lambda self, h: None})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _IncompleteFountainDecoder)

    with pytest.raises(RuntimeError, match="Decoding incomplete"):
        decode_mod.decode_gif(
            tmp_path / "in.gif", tmp_path / "out.bin", password="password123", verbose=False
        )


def test_decode_gif_decrypt_failure(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_bytes, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type("HB", (), {"drop": lambda self, h: None})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)

    def _fail_decrypt(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", _fail_decrypt)

    with pytest.raises(RuntimeError, match="Decryption failed"):
        decode_mod.decode_gif(
            tmp_path / "in.gif", tmp_path / "out.bin", password="password123", verbose=False
        )


def test_decode_gif_sha_mismatch(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_bytes, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type("HB", (), {"drop": lambda self, h: None})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: b"wrong")

    with pytest.raises(ValueError, match="SHA256 mismatch"):
        decode_mod.decode_gif(
            tmp_path / "in.gif", tmp_path / "out.bin", password="password123", verbose=False
        )


def test_decode_gif_bad_precomputed_key_length(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_bytes, droplet_bytes]),
    )

    with pytest.raises(ValueError, match="Key derivation failed"):
        decode_mod.decode_gif(
            tmp_path / "in.gif",
            tmp_path / "out.bin",
            password="password123",
            precomputed_key=b"short",
            verbose=False,
        )


def test_decode_gif_forward_secrecy_verbose(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext, ephemeral_public_key=b"E" * 32)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    frames = [Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder(frames=frames))
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_bytes, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type("HB", (), {"drop": lambda self, h: None})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: plaintext)

    out_path = tmp_path / "out.bin"
    stats = decode_mod.decode_gif(
        tmp_path / "in.gif",
        out_path,
        password="password123",
        precomputed_key=b"K" * 32,
        verbose=True,
    )

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)


def test_decode_gif_droplet_unpack_warning(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    frames = [Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder(frames=frames))
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_bytes, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type("HB", (), {"drop": lambda self, h: None})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: plaintext)

    def _raise_unpack(*args, **kwargs):
        raise ValueError("bad droplet")

    monkeypatch.setattr(decode_mod, "unpack_droplet", _raise_unpack)

    out_path = tmp_path / "out.bin"
    stats = decode_mod.decode_gif(
        tmp_path / "in.gif", out_path, password="password123", verbose=True
    )

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)


def test_decode_gif_deadman_import_error(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(
        decode_mod,
        "GIFDecoder",
        lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]),
    )
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_bytes, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type("HB", (), {"drop": lambda self, h: None})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: plaintext)

    import builtins

    real_import = builtins.__import__

    def _import(name, *args, **kwargs):
        if name.endswith("deadmans_switch_cli"):
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _import)

    out_path = tmp_path / "out.bin"
    stats = decode_mod.decode_gif(
        tmp_path / "in.gif", out_path, password="password123", verbose=False
    )

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)


def test_decode_gif_verbose_frame_mac_stats(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)
    manifest_with_mac = b"\x00" * 8 + manifest_bytes

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    frames = [Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder(frames=frames))
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader([manifest_with_mac, droplet_bytes]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type(
        "HB", (), {"drop": lambda self, h: None, "import_key": lambda self, k: 99})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: plaintext)

    import meow_decoder.frame_mac as frame_mac
    monkeypatch.setattr(frame_mac, "derive_frame_master_key_handle", lambda *a, **kw: 42)
    monkeypatch.setattr("meow_decoder.constant_time.constant_time_compare", lambda a, b: a == b)

    def _valid_unpack(data, *args, **kwargs):
        if data == manifest_with_mac:
            return (True, manifest_bytes)
        return (True, droplet_bytes)

    monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", _valid_unpack)

    import hashlib

    class _Backend:
        def secure_zero(self, *args, **kwargs):
            raise RuntimeError("boom")

        def sha256(self, data):
            return hashlib.sha256(data).digest()

    monkeypatch.setattr("meow_decoder.crypto_backend.get_default_backend", lambda: _Backend())

    out_path = tmp_path / "out.bin"
    stats = decode_mod.decode_gif(
        tmp_path / "in.gif",
        out_path,
        password="password123",
        precomputed_key=b"K" * 32,
        verbose=True,
    )

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)


def test_decode_gif_rejects_invalid_droplet_mac_then_succeeds(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    manifest_bytes = _build_manifest_bytes(plaintext)
    manifest_with_mac = b"\x00" * 8 + manifest_bytes

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_bytes = pack_droplet(droplet)

    frames = [Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder(frames=frames))
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceQRCodeReader(
            [manifest_with_mac, b"bad", droplet_bytes]
        ),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac_production", lambda *args, **kwargs: True)
    monkeypatch.setattr(_crypto_mod, "compute_manifest_hmac_from_handle", lambda *args, **kwargs: b"\x00" * 32)
    monkeypatch.setattr(decode_mod, "derive_encryption_key_for_manifest_handle", lambda *args, **kwargs: "test_handle")
    monkeypatch.setattr(decode_mod, "get_handle_backend", lambda: type(
        "HB", (), {"drop": lambda self, h: None, "import_key": lambda self, k: 99})())
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw_production", lambda *args, **kwargs: plaintext)

    import meow_decoder.frame_mac as frame_mac
    monkeypatch.setattr(frame_mac, "derive_frame_master_key_handle", lambda *a, **kw: 42)

    calls = {"count": 0}

    def _unpack_frame_with_mac(data, *args, **kwargs):
        calls["count"] += 1
        if data == manifest_with_mac:
            return (True, manifest_bytes)
        if calls["count"] == 2:
            return (False, b"")
        return (True, droplet_bytes)

    monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", _unpack_frame_with_mac)

    out_path = tmp_path / "out.bin"
    stats = decode_mod.decode_gif(
        tmp_path / "in.gif",
        out_path,
        password="password123",
        precomputed_key=b"K" * 32,
        verbose=True,
    )

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)


# ===============================================================
# Merged from test_decode_gif_main.py
# ===============================================================


def test_main_help_exits():
    with patch("sys.argv", ["meow-decode-gif", "--help"]):
        with pytest.raises(SystemExit) as exc:
            decode_mod.main()
        assert exc.value.code == 0


def test_main_about_exits(monkeypatch):
    monkeypatch.setattr("meow_decoder.cat_utils.meow_about", lambda: "meow", raising=False)
    with patch("sys.argv", ["meow-decode-gif", "--about"]):
        with pytest.raises(SystemExit) as exc:
            decode_mod.main()
        assert exc.value.code == 0


def test_main_hardware_status_exits(monkeypatch):
    class _Caps:
        def summary(self):
            return "ok"

    class _Provider:
        def __init__(self, verbose=False):
            self.verbose = verbose

        def detect_all(self):
            return _Caps()

    monkeypatch.setattr("meow_decoder.hardware_integration.HardwareSecurityProvider", _Provider)
    with patch("sys.argv", ["meow-decode-gif", "--hardware-status"]):
        with pytest.raises(SystemExit) as exc:
            decode_mod.main()
        assert exc.value.code == 0


def test_main_missing_args_exits():
    with patch("sys.argv", ["meow-decode-gif"]):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_input_missing_exits(tmp_path):
    out_path = tmp_path / "out.txt"
    with patch(
        "sys.argv",
        ["meow-decode-gif", "-i", "missing.gif", "-o", str(out_path), "-p", "password123"],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_input_is_directory_exits(tmp_path):
    input_path = tmp_path / "dir"
    input_path.mkdir()
    output_path = tmp_path / "out.txt"

    with patch(
        "sys.argv",
        ["meow-decode-gif", "-i", str(input_path), "-o", str(output_path), "-p", "password123"],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_output_exists_without_force(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    output_path.write_text("exists")

    with patch(
        "sys.argv",
        ["meow-decode-gif", "-i", str(input_path), "-o", str(output_path), "-p", "password123"],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_empty_password_exits(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    with patch(
        "sys.argv", ["meow-decode-gif", "-i", str(input_path), "-o", str(output_path), "-p", ""]
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_success_calls_decode(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    def _fake_decode(*args, **kwargs):
        return {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        }

    monkeypatch.setattr(decode_mod, "decode_gif", _fake_decode)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
        ],
    ):
        decode_mod.main()


def test_main_password_prompt_path(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )
    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "password123")

    with patch(
        "sys.argv", ["meow-decode-gif", "-i", str(input_path), "-o", str(output_path), "--force"]
    ):
        decode_mod.main()


def test_main_receiver_privkey_invalid(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "bad_priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--receiver-privkey",
            str(privkey_path),
            "--receiver-privkey-password",
            "pass",
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_keyfile_error_exits(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "verify_keyfile",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad")),
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--keyfile",
            str(tmp_path / "missing.bin"),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_keyfile_verbose_load(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"keyfile")

    monkeypatch.setattr(decode_mod, "verify_keyfile", lambda *args, **kwargs: b"K" * 32)
    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--verbose",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        decode_mod.main()


def test_main_purr_mode_nine_lives_success(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        "meow_decoder.cat_utils.enable_purr_mode", lambda enabled=True: None, raising=False
    )

    class _Retry:
        def __init__(self, max_lives=9, verbose=True):
            self.succeeded = False

        def attempt(self):
            yield 1

        def success(self, stats):
            self.succeeded = True

        def fail(self, msg):
            pass

    monkeypatch.setattr("meow_decoder.cat_utils.NineLivesRetry", _Retry, raising=False)
    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--purr-mode",
            "--nine-lives",
        ],
    ):
        decode_mod.main()


def test_main_hsm_slot_branch(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )
    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "1234")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--hsm-slot",
            "1",
        ],
    ):
        decode_mod.main()


def test_main_hsm_slot_with_keyfile_error(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"K" * 32)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--hsm-slot",
            "1",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_tpm_derive_branch(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--tpm-derive",
        ],
    ):
        decode_mod.main()


def test_main_tpm_receiver_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--tpm-derive",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_hardware_auto_branch(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--hardware-auto",
        ],
    ):
        decode_mod.main()


def test_main_hardware_auto_with_keyfile_error(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"K" * 32)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--hardware-auto",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_yubikey_conflicts(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"K" * 32)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--yubikey",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_yubikey_receiver_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--yubikey",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_yubikey_pin_prompt(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )
    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "1234")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--yubikey",
        ],
    ):
        decode_mod.main()


def test_main_duress_config_passed(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    captured = {}

    def _fake_decode(*args, **kwargs):
        captured.update(kwargs)
        return {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        }

    monkeypatch.setattr(decode_mod, "decode_gif", _fake_decode)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--duress-mode",
            "panic",
            "--enable-panic",
        ],
    ):
        decode_mod.main()

    assert "duress_config" in captured


def test_main_decode_exception_verbose(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    def _fail(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(decode_mod, "decode_gif", _fail)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--verbose",
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_receiver_privkey_success(tmp_path, monkeypatch):
    import meow_crypto_rs

    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    # Generate X25519 keypair and save in MEOW_X25519 format
    priv_bytes, pub_bytes = meow_crypto_rs.x25519_generate_keypair()
    privkey_path = tmp_path / "priv.key"
    privkey_path.write_bytes(b"MEOW_X25519\x01" + priv_bytes)

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )
    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--receiver-privkey",
            str(privkey_path),
            "--verbose",
        ],
    ):
        decode_mod.main()


def test_main_hsm_receiver_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--hsm-slot",
            "1",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_tpm_keyfile_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"K" * 32)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--tpm-derive",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_hardware_auto_receiver_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--hardware-auto",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_receiver_privkey_wrong_type(tmp_path, monkeypatch):
    # Frozen Ed25519 PEM (wrong key type) — used to verify CLI rejects
    # non-X25519 keys.  Generated once and frozen to remove cryptography import.
    _ED25519_WRONG_TYPE_PEM = (
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MC4CAQAwBQYDK2VwBCIEIPdy2V7ko8eC/XTbXRDvD4xHGUFRKkvrBf0Ie2wmfvDm\n"
        b"-----END PRIVATE KEY-----\n"
    )

    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    privkey_path = tmp_path / "ed.pem"
    privkey_path.write_bytes(_ED25519_WRONG_TYPE_PEM)

    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_receiver_privkey_invalid_verbose(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "bad_priv.pem"
    privkey_path.write_text("not-a-key")

    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--receiver-privkey",
            str(privkey_path),
            "--verbose",
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_module_entrypoint_help():
    import runpy
    import sys

    with patch.object(sys, "argv", ["meow-decode-gif", "--help"]):
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("meow_decoder.decode_gif", run_name="__main__")
        assert exc.value.code == 0


def test_main_nine_lives_failure(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    class _Retry:
        def __init__(self, max_lives=9, verbose=True):
            self.succeeded = False

        def attempt(self):
            yield 1

        def success(self, stats):
            self.succeeded = False

        def fail(self, msg):
            pass

    def _fail(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("meow_decoder.cat_utils.NineLivesRetry", _Retry, raising=False)
    monkeypatch.setattr(decode_mod, "decode_gif", _fail)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--nine-lives",
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()
