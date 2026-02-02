#!/usr/bin/env python3
"""Tests for meow_decoder.meow_encode.
Uses stubs to avoid heavy crypto/QR/GIF.
"""

import sys
from pathlib import Path
import types

import pytest
from PIL import Image


class _DummyFountain:
    def __init__(self, *args, **kwargs):
        pass

    def drop_kibble(self):
        return b"kibble"


class _DummyPawMaker:
    def __init__(self, *args, **kwargs):
        pass

    def generate(self, payload: bytes):
        return Image.new("RGB", (32, 32), color=(255, 255, 255))


class _DummyYarnMaker:
    def __init__(self, *args, **kwargs):
        pass

    def create_yarn_ball(self, frames, output_path: Path, optimize: bool = True):
        output_path.write_bytes(b"GIF89a")
        return output_path.stat().st_size

# Stub legacy imports (config/crypto/etc.) used by meow_encode
config_mod = types.ModuleType("config")

class _DummyEncodingConfig:
    def __init__(self, block_size=512, redundancy=1.5, qr_error_correction="M", qr_box_size=10, qr_border=4, fps=10):
        self.block_size = block_size
        self.redundancy = redundancy
        self.qr_error_correction = qr_error_correction
        self.qr_box_size = qr_box_size
        self.qr_border = qr_border
        self.fps = fps

config_mod.MeowConfig = object
config_mod.EncodingConfig = _DummyEncodingConfig
sys.modules["config"] = config_mod

crypto_mod = types.ModuleType("crypto")
crypto_mod.hiss_secret = lambda data, password, catnip: (b"c", b"s" * 32, b"S" * 16, b"N" * 12, b"cipher")
crypto_mod.compute_collar_tag_auth = lambda *args, **kwargs: b"\x00" * 32
crypto_mod.pack_collar_tag = lambda tag: b"tag"

class _DummyCollarTag:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

crypto_mod.CollarTag = _DummyCollarTag
crypto_mod.verify_catnip = lambda path: b"catnip"
sys.modules["crypto"] = crypto_mod

fountain_mod = types.ModuleType("fountain")
fountain_mod.CatnipFountain = lambda *args, **kwargs: _DummyFountain()
fountain_mod.pack_kibble = lambda kibble: b"k"
sys.modules["fountain"] = fountain_mod

qr_mod = types.ModuleType("qr_code")
qr_mod.PawPrintMaker = _DummyPawMaker
sys.modules["qr_code"] = qr_mod

gif_mod = types.ModuleType("gif_handler")
gif_mod.YarnBallMaker = _DummyYarnMaker
sys.modules["gif_handler"] = gif_mod

import meow_decoder.meow_encode as meow


def test_hiss_file_into_yarn_ball_smoke(tmp_path, monkeypatch):
    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"hello")
    output_path = tmp_path / "out.gif"

    stats = meow.hiss_file_into_yarn_ball(input_path, output_path, password="pw", verbose=False)
    assert output_path.exists()
    assert stats["output_size"] > 0
    assert stats["paw_prints"] >= 1


def test_main_missing_input(monkeypatch, tmp_path):
    out_gif = tmp_path / "out.gif"
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(tmp_path / "nope.bin"), "-o", str(out_gif), "-p", "pw"])

    with pytest.raises(SystemExit) as e:
        meow.main()
    assert e.value.code == 1


def test_main_password_mismatch(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    pw = iter(["a", "b"])
    monkeypatch.setattr(meow, "getpass", lambda prompt="": next(pw))
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(out_gif)])

    with pytest.raises(SystemExit) as e:
        meow.main()
    assert e.value.code == 1


def test_main_catnip_missing(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    def _raise_missing(path):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(meow, "verify_catnip", _raise_missing)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(out_gif), "-p", "pw", "--catnip", str(tmp_path / "nope")])

    with pytest.raises(SystemExit) as e:
        meow.main()
    assert e.value.code == 1


def test_main_happy_path_and_shred(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    def fake_hiss(*args, **kwargs):
        return {
            "input_size": 4,
            "compressed_size": 4,
            "hissed_size": 4,
            "output_size": 10,
            "compression_ratio": 1.0,
            "scratching_posts": 1,
            "kibbles": 1,
            "redundancy": 1.5,
            "paw_prints": 1,
            "paw_size": (32, 32),
            "yarn_duration": 0.1,
            "elapsed_time": 0.01,
        }

    monkeypatch.setattr(meow, "hiss_file_into_yarn_ball", fake_hiss)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--shred-source",
    ])

    meow.main()
    assert not inp.exists()
