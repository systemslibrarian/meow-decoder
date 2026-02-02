import hashlib
from pathlib import Path

import pytest


def test_decode_gif_verbose_frame_macs_progress_and_success(tmp_path: Path, monkeypatch, capsys):
    """Cover verbose + frame-MAC paths in decode_gif.decode_gif without heavy QR/GIF work."""

    import meow_decoder.decode_gif as dg
    from meow_decoder.crypto import Manifest, pack_manifest
    import meow_decoder.frame_mac as fm

    # Keep the "real" payload tiny.
    raw_data = b"hello world"
    sha256 = hashlib.sha256(raw_data).digest()

    # Build a forward-secrecy manifest (includes ephemeral_public_key => 147 bytes packed).
    manifest = Manifest(
        salt=b"S" * 16,
        nonce=b"N" * 12,
        orig_len=len(raw_data),
        comp_len=1,
        cipher_len=8,
        sha256=sha256,
        block_size=16,
        k_blocks=101,
        hmac=b"\x00" * 32,
        ephemeral_public_key=b"E" * 32,
    )
    manifest_bytes = pack_manifest(manifest)
    assert len(manifest_bytes) == 147

    # Simulate frame-MAC wrapping: 8-byte prefix + manifest bytes.
    manifest_raw = b"M" * 8 + manifest_bytes
    assert len(manifest_raw) == 155

    class DummyFrame:
        size = (10, 10)

    # 120 frames is enough to hit "Processed 100/..." print.
    frames = [DummyFrame() for _ in range(120)]
    monkeypatch.setattr(dg.GIFDecoder, "extract_frames", lambda self, _p: frames)

    # Make QR scanning deterministic and cheap.
    call_index = {"i": -1}

    def fake_read_image(self, _frame):
        call_index["i"] += 1
        i = call_index["i"]
        if i == 0:
            return [manifest_raw]
        # Some frames contain no QR to hit the warning branch.
        if i in (10, 11, 12):
            return None
        return [f"FRAME{i}".encode("ascii")]

    monkeypatch.setattr(dg.QRCodeReader, "read_image", fake_read_image)

    # HMAC verification is orthogonal to decode_gif() control-flow coverage here.
    monkeypatch.setattr(dg, "verify_manifest_hmac", lambda *_args, **_kwargs: True)

    # Make manifest frame MAC validate, and mix valid/invalid droplet frames.
    def fake_unpack_frame_with_mac(frame_bytes, _key, frame_index, _salt):
        if frame_index == 0:
            assert frame_bytes == manifest_raw
            return True, manifest_bytes

        # Reject one droplet frame to cover "MAC invalid" path.
        if frame_index == 3:
            return False, b""

        # One droplet payload will fail unpacking to cover the droplet exception path.
        if frame_index == 7:
            return True, b"BAD"

        return True, b"DROPLET"

    monkeypatch.setattr(fm, "unpack_frame_with_mac", fake_unpack_frame_with_mac)

    # Avoid real droplet parsing.
    def fake_unpack_droplet(droplet_bytes: bytes, _block_size: int):
        if droplet_bytes == b"BAD":
            raise ValueError("bad droplet")
        return object()

    monkeypatch.setattr(dg, "unpack_droplet", fake_unpack_droplet)

    # Minimal decoder: progress at 100, complete at 101.
    class DummyDecoder:
        def __init__(self, k_blocks: int, _block_size: int, original_length: int = None):
            self.k_blocks = k_blocks
            self.decoded_count = 0
            self._original_length = original_length

        def add_droplet(self, _droplet):
            self.decoded_count += 1

        def is_complete(self) -> bool:
            return self.decoded_count >= self.k_blocks

        def get_data(self, length: int):
            return b"\x00" * length

    monkeypatch.setattr(dg, "FountainDecoder", DummyDecoder)

    # Decryption returns the known plaintext.
    monkeypatch.setattr(dg, "decrypt_to_raw", lambda *_args, **_kwargs: raw_data)

    out_path = tmp_path / "out.bin"

    stats = dg.decode_gif(
        input_path=tmp_path / "in.gif",
        output_path=out_path,
        password="password_test",
        config=dg.DecodingConfig(preprocessing="normal"),
        keyfile=None,
        receiver_private_key=b"R" * 32,
        verbose=True,
    )

    assert out_path.read_bytes() == raw_data
    assert stats["blocks_decoded"] == 101

    out = capsys.readouterr().out
    # A couple of strong signals that the verbose + MAC paths ran.
    assert "Detected frame MACs" in out
    assert "Frame MAC verification enabled" in out
    assert "Processing Droplets" in out or "Droplets" in out  # Progress bar label changed
    assert "Decoding complete" in out
