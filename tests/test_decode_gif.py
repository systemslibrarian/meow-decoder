#!/usr/bin/env python3
"""Tests for meow_decoder.decode_gif.
Uses stubs to avoid heavy QR/GIF dependencies.
"""

from pathlib import Path

import pytest
from PIL import Image

import meow_decoder.decode_gif as decode_mod
from meow_decoder.crypto import Manifest, pack_manifest
from meow_decoder.fountain import Droplet, pack_droplet


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
    plaintext: bytes, block_size: int = 8, k_blocks: int = 1, ephemeral_public_key: bytes = None
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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: False)

    with pytest.raises(ValueError, match="HMAC verification failed"):
        decode_mod.decode_gif(
            tmp_path / "in.gif", tmp_path / "out.bin", password="password123", verbose=False
        )


def test_decode_gif_frame_mac_invalid_fails_open(tmp_path, monkeypatch):
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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

    import meow_decoder.frame_mac as frame_mac

    def _invalid_manifest(*args, **kwargs):
        return (False, b"")

    monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", _invalid_manifest)

    out_path = tmp_path / "out.bin"
    stats = decode_mod.decode_gif(
        tmp_path / "in.gif", out_path, password="password123", verbose=True
    )

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)


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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

    import meow_decoder.frame_mac as frame_mac

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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)

    def _fail_decrypt(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(decode_mod, "decrypt_to_raw", _fail_decrypt)

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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: b"wrong")

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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

    import meow_decoder.frame_mac as frame_mac

    def _valid_unpack(data, *args, **kwargs):
        if data == manifest_with_mac:
            return (True, manifest_bytes)
        return (True, droplet_bytes)

    monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", _valid_unpack)

    class _Backend:
        def secure_zero(self, *args, **kwargs):
            raise RuntimeError("boom")

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
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)
    monkeypatch.setattr(decode_mod, "FountainDecoder", _DummyFountainDecoder)
    monkeypatch.setattr(decode_mod, "decrypt_to_raw", lambda *args, **kwargs: plaintext)

    import meow_decoder.frame_mac as frame_mac

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
