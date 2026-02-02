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


def test_decode_gif_no_frames(tmp_path, monkeypatch):
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder(frames=[]))

    with pytest.raises(ValueError, match="No frames found in GIF"):
        decode_mod.decode_gif(tmp_path / "in.gif", tmp_path / "out.bin", password="pw", verbose=False)


def test_decode_gif_no_qr_codes(tmp_path, monkeypatch):
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder())
    monkeypatch.setattr(decode_mod, "QRCodeReader", lambda preprocessing=None: _DummyQRCodeReader())

    with pytest.raises(ValueError, match="No QR codes found in GIF"):
        decode_mod.decode_gif(tmp_path / "in.gif", tmp_path / "out.bin", password="pw", verbose=False)


def test_decode_gif_invalid_manifest_length(tmp_path, monkeypatch):
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder())

    class _BadReader(_DummyQRCodeReader):
        def read_image(self, frame):
            return [b"X" * 50]

    monkeypatch.setattr(decode_mod, "QRCodeReader", lambda preprocessing=None: _BadReader())

    with pytest.raises(ValueError, match="Manifest QR decode corrupted"):
        decode_mod.decode_gif(tmp_path / "in.gif", tmp_path / "out.bin", password="pw", verbose=False)


def test_decode_gif_happy_path(tmp_path, monkeypatch):
    plaintext = b"plaintext"
    import hashlib

    manifest = Manifest(
        salt=b"S" * 16,
        nonce=b"N" * 12,
        orig_len=len(plaintext),
        comp_len=1,
        cipher_len=len(b"dummy-cipher"),
        sha256=hashlib.sha256(plaintext).digest(),
        block_size=8,
        k_blocks=1,
        hmac=b"\x00" * 32,
        ephemeral_public_key=None,
    )
    manifest_bytes = pack_manifest(manifest)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * manifest.block_size)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder(frames=[Image.new("RGB", (64, 64)), Image.new("RGB", (64, 64))]))

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
    stats = decode_mod.decode_gif(tmp_path / "in.gif", out_path, password="password123", verbose=False)

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)
