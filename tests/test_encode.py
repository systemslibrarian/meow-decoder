#!/usr/bin/env python3
"""Tests for meow_decoder.encode CLI and encode_file.
Lightweight stubs for QR/GIF to avoid heavy dependencies.
"""

from pathlib import Path
import sys

import pytest
from PIL import Image

import meow_decoder.encode as enc


class _DummyQRCodeGenerator:
    def __init__(self, *args, **kwargs):
        pass

    def generate(self, payload: bytes):
        return Image.new("RGB", (64, 64), color=(255, 255, 255))


class _DummyGIFEncoder:
    def __init__(self, *args, **kwargs):
        pass

    def create_gif(self, frames, output_path: Path, optimize: bool = True):
        output_path.write_bytes(b"GIF89a")
        return output_path.stat().st_size


def test_encode_main_generate_keys_branch(monkeypatch, tmp_path: Path):
    called = {"ok": False}

    def fake_generate(out_dir: str):
        called["ok"] = True

    import meow_decoder.x25519_forward_secrecy as fs
    monkeypatch.setattr(fs, "generate_receiver_keys_cli", fake_generate)

    monkeypatch.setattr(sys, "argv", ["meow-encode", "--generate-keys", "--key-output-dir", str(tmp_path)])
    rc = enc.main()
    assert rc == 0
    assert called["ok"] is True


def test_encode_main_rejects_missing_input(monkeypatch, tmp_path: Path):
    out_gif = tmp_path / "out.gif"
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(tmp_path / "nope.bin"), "-o", str(out_gif), "-p", "pw"])

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_password_prompt_mismatch(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    pw = iter(["a", "b"])
    monkeypatch.setattr(enc, "getpass", lambda prompt="": next(pw))
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(out_gif)])

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_happy_path_calls_encode_file(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    called = {"ok": False}

    def fake_encode_file(*args, **kwargs):
        called["ok"] = True
        return {
            "input_size": 4,
            "compressed_size": 4,
            "encrypted_size": 4,
            "output_size": 10,
            "compression_ratio": 1.0,
            "k_blocks": 1,
            "num_droplets": 1,
            "redundancy": 1.5,
            "qr_frames": 1,
            "qr_size": (64, 64),
            "gif_duration": 0.1,
            "elapsed_time": 0.01,
        }

    monkeypatch.setattr(enc, "encode_file", fake_encode_file)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(out_gif), "-p", "pw", "--no-forward-secrecy"])

    enc.main()
    assert called["ok"] is True


def test_encode_main_summon_void_cat_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--summon-void-cat"])
    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 0


def test_encode_main_receiver_pubkey_wrong_length(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    bad_pub = tmp_path / "bad.key"
    bad_pub.write_bytes(b"X" * 31)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--receiver-pubkey", str(bad_pub),
    ])

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_receiver_pubkey_missing_file(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    missing = tmp_path / "missing.key"

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--receiver-pubkey", str(missing),
    ])

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_file_unit_smoke(tmp_path: Path, monkeypatch):
    # Patch out QR/GIF heavy bits but still run the core orchestration.
    monkeypatch.setattr(enc, "QRCodeGenerator", _DummyQRCodeGenerator)
    monkeypatch.setattr(enc, "GIFEncoder", _DummyGIFEncoder)

    import meow_decoder.frame_mac as frame_mac
    monkeypatch.setattr(frame_mac, "pack_frame_with_mac", lambda payload, *args, **kwargs: payload)
    monkeypatch.setattr(frame_mac, "derive_frame_master_key", lambda *args, **kwargs: b"k" * 32)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"hello" * 10)
    out_gif = tmp_path / "out.gif"

    stats = enc.encode_file(input_path, out_gif, password="password_test", verbose=False)
    assert out_gif.exists()
    assert stats["output_size"] > 0
    assert stats["qr_frames"] >= 1
