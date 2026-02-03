#!/usr/bin/env python3
"""Coverage tests for qr_code.py (target 95%+)."""

import base64

import numpy as np
import pytest
from PIL import Image

import meow_decoder.qr_code as qr_code
from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader, WebcamQRReader


def test_qr_generator_generate_and_batch():
    gen = QRCodeGenerator(error_correction="L", box_size=4, border=1)
    img = gen.generate(b"payload")
    assert img.mode == "RGB"

    batch = gen.generate_batch([b"a", b"b", b"c"])
    assert len(batch) == 3


def test_qr_reader_read_image_base85(monkeypatch):
    payload = b"hello"
    encoded = base64.b85encode(payload)

    class DummyObj:
        def __init__(self, data):
            self.data = data

    monkeypatch.setattr(qr_code.pyzbar, "decode", lambda img: [DummyObj(encoded)])

    reader = QRCodeReader(preprocessing="normal")
    img = Image.new("RGB", (10, 10), "white")
    results = reader.read_image(img)

    assert results == [payload]


def test_qr_reader_read_image_fallback_raw(monkeypatch):
    raw = b"\xff\xfe"

    class DummyObj:
        def __init__(self, data):
            self.data = data

    monkeypatch.setattr(qr_code.pyzbar, "decode", lambda img: [DummyObj(raw)])

    reader = QRCodeReader(preprocessing="normal")
    img = Image.new("RGB", (10, 10), "white")
    results = reader.read_image(img)

    assert results == [raw]


def test_qr_reader_read_frame_base85(monkeypatch):
    payload = b"frame"
    encoded = base64.b85encode(payload)

    class DummyObj:
        def __init__(self, data):
            self.data = data

    monkeypatch.setattr(qr_code.pyzbar, "decode", lambda img: [DummyObj(encoded)])

    reader = QRCodeReader(preprocessing="normal")
    frame = np.zeros((10, 10, 3), dtype=np.uint8)
    results = reader.read_frame(frame)

    assert results == [payload]


def test_preprocess_normal_and_aggressive():
    reader = QRCodeReader(preprocessing="normal")
    color = np.zeros((10, 10, 3), dtype=np.uint8)

    normal = reader._preprocess_normal(color)
    aggressive = reader._preprocess_aggressive(color)

    assert normal.ndim == 2
    assert aggressive.ndim == 2


def test_webcam_reader_read_next_and_release(monkeypatch):
    frames = [np.zeros((10, 10, 3), dtype=np.uint8), np.zeros((10, 10, 3), dtype=np.uint8)]

    class DummyCap:
        def __init__(self, frames):
            self._frames = list(frames)
            self.released = False

        def isOpened(self):
            return True

        def read(self):
            if not self._frames:
                return False, None
            return True, self._frames.pop(0)

        def release(self):
            self.released = True

    dummy = DummyCap(frames)
    monkeypatch.setattr(qr_code.cv2, "VideoCapture", lambda device: dummy)

    reader = WebcamQRReader(device=0, preprocessing="normal", frame_skip=1)
    monkeypatch.setattr(reader.reader, "read_frame", lambda frame: [b"data"])

    result = reader.read_next()
    assert result[0] == b"data"

    reader.release()
    assert dummy.released is True


def test_webcam_reader_read_continuous(monkeypatch):
    class DummyCap:
        def __init__(self):
            self.released = False

        def isOpened(self):
            return True

        def read(self):
            return False, None

        def release(self):
            self.released = True

    dummy = DummyCap()
    monkeypatch.setattr(qr_code.cv2, "VideoCapture", lambda device: dummy)

    reader = WebcamQRReader(device=0, preprocessing="normal", frame_skip=0)

    results = []

    def fake_read_next():
        if len(results) >= 2:
            return None
        return b"payload", np.zeros((10, 10, 3), dtype=np.uint8)

    monkeypatch.setattr(reader, "read_next", fake_read_next)

    def callback(data, frame):
        results.append(data)

    reader.read_continuous(callback, max_frames=2)
    assert results == [b"payload", b"payload"]
