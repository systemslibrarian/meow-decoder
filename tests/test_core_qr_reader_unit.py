"""
⚠️ DEPRECATED: Tests consolidated into test_qr_code.py
This file will be removed after verification that all unique tests are migrated.
"""

import pytest

# Skip all tests in this module - consolidated into test_qr_code.py
pytestmark = pytest.mark.skip(reason="Consolidated into test_qr_code.py")

import types

import numpy as np
from PIL import Image

import meow_decoder.qr_code as qr_mod


class _Obj:
    def __init__(self, data):
        self.data = data


def test_qr_reader_read_image_base85_path(monkeypatch):
    # Make pyzbar.decode return an ASCII base85 payload.
    payload = b"hello"
    import base64

    encoded = base64.b85encode(payload)

    def fake_decode(_img):
        return [_Obj(encoded)]

    monkeypatch.setattr(qr_mod.pyzbar, "decode", fake_decode)

    reader = qr_mod.QRCodeReader(preprocessing="normal")
    img = Image.new("RGB", (32, 32), color=(255, 255, 255))
    out = reader.read_image(img)

    assert out == [payload]


def test_qr_reader_fallback_raw_bytes(monkeypatch):
    # Force base85 decode to fail so we exercise the fallback path.
    def fake_decode(_img):
        # Non-ASCII bytes trigger the exception path (decode('ascii') fails).
        return [_Obj(b"\xff\xfe\x00\x01")]

    monkeypatch.setattr(qr_mod.pyzbar, "decode", fake_decode)

    reader = qr_mod.QRCodeReader(preprocessing="normal")
    img = Image.new("RGB", (32, 32), color=(255, 255, 255))
    out = reader.read_image(img)

    assert out == [b"\xff\xfe\x00\x01"]


def test_qr_reader_read_frame_aggressive(monkeypatch):
    # Cover aggressive preprocessing and read_frame.
    def fake_decode(_img):
        return [_Obj(b"\xff\x00")]

    monkeypatch.setattr(qr_mod.pyzbar, "decode", fake_decode)

    reader = qr_mod.QRCodeReader(preprocessing="aggressive")
    frame = np.zeros((64, 64, 3), dtype=np.uint8)
    out = reader.read_frame(frame)

    assert out == [b"\xff\x00"]
