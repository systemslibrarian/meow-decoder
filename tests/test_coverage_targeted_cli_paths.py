#!/usr/bin/env python3
"""Targeted tests to lift coverage over the 90% gate.

These tests intentionally exercise otherwise-hard-to-reach CLI branches and
lightweight encode/decode paths without running the full QR/GIF pipeline.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


def test_encode_file_covers_pq_and_fs_branches(monkeypatch, tmp_path: Path, capsys):
    """Exercise encode_file() branches (PQ + forward secrecy) with stubs."""

    # Local import so coverage counts the module under test.
    from meow_decoder.encode import encode_file
    from meow_decoder.config import EncodingConfig

    # Create a tiny input file
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"hello meow")
    out_gif = tmp_path / "out.gif"

    # Stub QR/GIF to avoid heavy work.
    from PIL import Image

    class DummyQRGen:
        def __init__(self, *args, **kwargs):
            pass

        def generate(self, payload: bytes):
            # Return a valid PIL image for GIFEncoder.
            return Image.new("RGB", (8, 8), color=(255, 255, 255))

    class DummyGIFEncoder:
        def __init__(self, *args, **kwargs):
            pass

        def create_gif(self, frames, output_path: Path, optimize: bool = True):
            # Touch the output to keep behavior realistic.
            output_path.write_bytes(b"GIF89a")
            return output_path.stat().st_size

    monkeypatch.setattr("meow_decoder.encode.QRCodeGenerator", DummyQRGen)
    monkeypatch.setattr("meow_decoder.encode.GIFEncoder", DummyGIFEncoder)

    # Stub encrypt_file_bytes to deterministically control FS/PQ branches.
    def fake_encrypt_file_bytes(raw, password, keyfile=None, receiver_public_key=None, use_length_padding=True):
        comp = b"C" * 16
        sha = b"S" * 32
        salt = b"A" * 16
        nonce = b"B" * 12
        cipher = b"X" * 32
        ephemeral = (b"E" * 32) if receiver_public_key is not None else None
        encryption_key = b"K" * 32
        return comp, sha, salt, nonce, cipher, ephemeral, encryption_key

    monkeypatch.setattr("meow_decoder.encode.encrypt_file_bytes", fake_encrypt_file_bytes)

    # Keep droplets at zero to avoid generating lots of frames.
    cfg = EncodingConfig(block_size=16, redundancy=0.0, fps=10)

    # 1) PQ branch
    encode_file(
        inp,
        out_gif,
        password="pw",
        config=cfg,
        forward_secrecy=True,
        receiver_public_key=None,
        use_pq=True,
        verbose=True,
    )

    # 2) Forward secrecy w/ receiver pubkey branch
    out_gif2 = tmp_path / "out2.gif"
    encode_file(
        inp,
        out_gif2,
        password="pw",
        config=cfg,
        forward_secrecy=True,
        receiver_public_key=b"R" * 32,
        use_pq=False,
        verbose=True,
    )

    captured = capsys.readouterr().out
    assert "Using MEOW4 manifest" in captured
    assert "Forward Secrecy + X25519" in captured


def test_decode_main_loads_receiver_privkey_and_keyfile(monkeypatch, tmp_path: Path):
    """Exercise decode CLI: keyfile + receiver private key success path."""

    import meow_decoder.decode_gif as dec

    # Create dummy input GIF file so Path.exists/is_file checks pass.
    in_gif = tmp_path / "in.gif"
    in_gif.write_bytes(b"GIF89a")

    out_file = tmp_path / "out.bin"

    # Create a valid keyfile.
    keyfile_path = tmp_path / "key.bin"
    keyfile_path.write_bytes(b"K" * 64)

    # Create an encrypted X25519 private key PEM.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = X25519PrivateKey.generate()
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"privpw"),
    )

    priv_path = tmp_path / "receiver_private.pem"
    priv_path.write_bytes(pem)

    called = {}

    def fake_decode_gif(input_path, output_path, password, config=None, keyfile=None, receiver_private_key=None, verbose=False):
        called["password"] = password
        called["keyfile_len"] = len(keyfile) if keyfile else None
        called["receiver_private_key_len"] = len(receiver_private_key) if receiver_private_key else None
        return {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 0,
            "blocks_decoded": 0,
            "output_size": 0,
            "efficiency": 0.0,
            "elapsed_time": 0.01,
        }

    monkeypatch.setattr(dec, "decode_gif", fake_decode_gif)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-decode-gif",
            "-i",
            str(in_gif),
            "-o",
            str(out_file),
            "-p",
            "pw",
            "--keyfile",
            str(keyfile_path),
            "--receiver-privkey",
            str(priv_path),
            "--receiver-privkey-password",
            "privpw",
            "--force",
        ],
    )

    # Should not raise.
    dec.main()

    assert called["password"] == "pw"
    assert called["keyfile_len"] == 64
    # X25519 raw private key length is 32 bytes.
    assert called["receiver_private_key_len"] == 32
