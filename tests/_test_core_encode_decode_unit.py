"""
⚠️ DEPRECATED: This file has been merged into canonical test files.

Encode tests → test_encode.py (TestEncodeUnitWithMocks)
Decode tests → test_decode_gif.py (TestDecodeGifUnitWithMocks)

This file is kept for reference only. All tests are skipped.
Delete after verification of merged tests.

Original purpose: Unit tests with mocked QR/GIF for isolation testing.
Merged on: 2026-02-01
"""
import pytest
pytestmark = pytest.mark.skip(reason="DEPRECATED: Merged into test_encode.py and test_decode_gif.py")

# ============================================================================
# ORIGINAL CODE BELOW (kept for reference)
# ============================================================================

import hashlib
from pathlib import Path

import pytest
from PIL import Image

import meow_decoder.decode_gif as decode_mod
import meow_decoder.encode as encode_mod
from meow_decoder.crypto import Manifest, pack_manifest
from meow_decoder.fountain import Droplet, pack_droplet


class _DummyQRCodeGenerator:
    def __init__(self, *args, **kwargs):
        pass

    def generate(self, payload: bytes):
        # Return a deterministic image (payload isn't used).
        return Image.new("RGB", (64, 64), color=(255, 255, 255))


class _DummyGIFEncoder:
    def __init__(self, *args, **kwargs):
        pass

    def create_gif(self, frames, output_path: Path, optimize: bool = True):
        # Minimal placeholder write so downstream tests see a file.
        output_path.write_bytes(b"GIF89a")
        return output_path.stat().st_size


class _DummyGIFDecoder:
    def extract_frames(self, input_path: Path):
        # Two frames is enough: manifest + one droplet
        return [Image.new("RGB", (64, 64), color=(0, 0, 0)), Image.new("RGB", (64, 64), color=(0, 0, 0))]


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


def test_encode_file_unit_smoke(tmp_path: Path, monkeypatch):
    # Patch out QR/GIF heavy bits but still run the core orchestration.
    monkeypatch.setattr(encode_mod, "QRCodeGenerator", _DummyQRCodeGenerator)
    monkeypatch.setattr(encode_mod, "GIFEncoder", _DummyGIFEncoder)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"hello" * 10)
    out_gif = tmp_path / "out.gif"

    stats = encode_mod.encode_file(input_path, out_gif, password="password_test", verbose=False)
    assert out_gif.exists()
    assert stats["output_size"] > 0
    assert stats["qr_frames"] >= 1


def test_decode_gif_unit_rejects_bad_manifest_length(tmp_path: Path, monkeypatch):
    # Exercise manifest length fail-closed path.
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder())

    class _BadReader(_DummyQRCodeReader):
        def read_image(self, frame):
            # First QR = manifest with invalid length
            return [b"X" * 50]

    monkeypatch.setattr(decode_mod, "QRCodeReader", lambda preprocessing=None: _BadReader())

    with pytest.raises(ValueError):
        decode_mod.decode_gif(tmp_path / "in.gif", tmp_path / "out.bin", password="password_test", verbose=False)


def test_decode_gif_unit_happy_path_with_stubs(tmp_path: Path, monkeypatch):
    # Create a valid MEOW3 manifest bytes.
    plaintext = b"plaintext"
    sha = hashlib.sha256(plaintext).digest()

    manifest = Manifest(
        salt=b"S" * 16,
        nonce=b"N" * 12,
        orig_len=len(plaintext),
        comp_len=1,
        cipher_len=len(b"dummy-cipher"),
        sha256=sha,
        block_size=8,
        k_blocks=1,
        hmac=b"\x00" * 32,
        ephemeral_public_key=None,
    )
    manifest_bytes = pack_manifest(manifest)

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * manifest.block_size)
    droplet_bytes = pack_droplet(droplet)

    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _DummyGIFDecoder())

    class _Reader(_DummyQRCodeReader):
        def read_image(self, frame):
            # Called once per frame. First frame returns manifest, second returns droplet.
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
    stats = decode_mod.decode_gif(tmp_path / "in.gif", out_path, password="password_test", verbose=False)

    assert out_path.read_bytes() == plaintext
    assert stats["output_size"] == len(plaintext)
