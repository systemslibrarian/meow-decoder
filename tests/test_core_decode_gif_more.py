import pytest

import hashlib
from pathlib import Path

from PIL import Image

import meow_decoder.decode_gif as decode_mod
from meow_decoder.crypto import Manifest, pack_manifest
from meow_decoder.fountain import Droplet, pack_droplet


class _FramesOnlyGIFDecoder:
    def __init__(self, frames):
        self._frames = frames

    def extract_frames(self, input_path: Path):
        return self._frames


class _SequenceReader:
    def __init__(self, payloads_per_frame):
        self._payloads = list(payloads_per_frame)
        self._i = 0

    def read_image(self, frame):
        if self._i >= len(self._payloads):
            return []
        payload = self._payloads[self._i]
        self._i += 1
        return payload


def _make_manifest_bytes(cipher_len: int = 16, block_size: int = 8, k_blocks: int = 1) -> bytes:
    plaintext = b"hello"
    sha = hashlib.sha256(plaintext).digest()
    m = Manifest(
        salt=b"S" * 16,
        nonce=b"N" * 12,
        orig_len=len(plaintext),
        comp_len=1,
        cipher_len=cipher_len,
        sha256=sha,
        block_size=block_size,
        k_blocks=k_blocks,
        hmac=b"\x00" * 32,
        ephemeral_public_key=None,
    )
    return pack_manifest(m)


def test_decode_gif_raises_if_no_frames(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _FramesOnlyGIFDecoder([]))
    with pytest.raises(ValueError, match="No frames found"):
        decode_mod.decode_gif(tmp_path / "in.gif", tmp_path / "out.bin", password="password_test", verbose=False)


def test_decode_gif_raises_if_no_qr_codes(tmp_path: Path, monkeypatch):
    frames = [Image.new("RGB", (32, 32), color=(255, 255, 255)) for _ in range(2)]
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _FramesOnlyGIFDecoder(frames))
    monkeypatch.setattr(decode_mod, "QRCodeReader", lambda preprocessing=None: _SequenceReader([[], []]))

    with pytest.raises(ValueError, match="No QR codes found"):
        decode_mod.decode_gif(tmp_path / "in.gif", tmp_path / "out.bin", password="password_test", verbose=False)


def test_decode_gif_manifest_with_frame_mac_then_disable_on_invalid(tmp_path: Path, monkeypatch):
    # manifest_raw length 123 triggers "has_frame_macs" detection (115 + 8)
    manifest_bytes = _make_manifest_bytes(cipher_len=8, block_size=8, k_blocks=1)
    manifest_raw = b"12345678" + manifest_bytes

    frames = [Image.new("RGB", (32, 32), color=(255, 255, 255))]
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _FramesOnlyGIFDecoder(frames))
    monkeypatch.setattr(decode_mod, "QRCodeReader", lambda preprocessing=None: _SequenceReader([[manifest_raw]]))

    # Manifest HMAC passes.
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)

    # Retroactive frame-MAC verification fails, disabling frame MAC mode.
    import meow_decoder.frame_mac as frame_mac
    monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", lambda *args, **kwargs: (False, b""))

    # Decoder will fail later due to no droplets, but we at least cover the MAC path.
    with pytest.raises(RuntimeError, match="Decoding incomplete"):
        decode_mod.decode_gif(tmp_path / "in.gif", tmp_path / "out.bin", password="password_test", verbose=False)


def test_decode_gif_rejects_invalid_frame_macs_on_droplets(tmp_path: Path, monkeypatch):
    manifest_bytes = _make_manifest_bytes(cipher_len=8, block_size=8, k_blocks=1)
    manifest_raw = b"12345678" + manifest_bytes  # 123 bytes

    droplet = Droplet(seed=1, block_indices=[0], data=b"\x00" * 8)
    droplet_raw = b"abcdefgh" + pack_droplet(droplet)

    frames = [Image.new("RGB", (32, 32), color=(255, 255, 255)) for _ in range(3)]
    monkeypatch.setattr(decode_mod, "GIFDecoder", lambda: _FramesOnlyGIFDecoder(frames))
    monkeypatch.setattr(
        decode_mod,
        "QRCodeReader",
        lambda preprocessing=None: _SequenceReader([[manifest_raw], [droplet_raw], [droplet_raw]]),
    )
    monkeypatch.setattr(decode_mod, "verify_manifest_hmac", lambda *args, **kwargs: True)

    import meow_decoder.frame_mac as frame_mac

    # Manifest MAC verifies; droplet MACs fail -> droplets rejected.
    def fake_unpack_frame_with_mac(data, master_key, frame_index, salt):
        if frame_index == 0:
            return True, manifest_bytes
        return False, b""

    monkeypatch.setattr(frame_mac, "unpack_frame_with_mac", fake_unpack_frame_with_mac)

    with pytest.raises(RuntimeError, match="Decoding incomplete"):
        decode_mod.decode_gif(tmp_path / "in.gif", tmp_path / "out.bin", password="password_test", verbose=False)
