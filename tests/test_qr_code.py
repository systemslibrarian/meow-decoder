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


def test_qr_generator_invalid_error_correction_defaults_to_m():
    gen = QRCodeGenerator(error_correction="Z")
    assert gen.error_correction == qr_code.qrcode.constants.ERROR_CORRECT_M


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


def test_qr_reader_read_image_aggressive_str_fallback(monkeypatch):
    import base64

    class DummyObj:
        def __init__(self, data):
            self.data = data

    monkeypatch.setattr(base64, "b85decode", lambda _s: (_ for _ in ()).throw(ValueError("bad")))
    monkeypatch.setattr(qr_code.pyzbar, "decode", lambda img: [DummyObj("not-base85")])

    reader = QRCodeReader(preprocessing="aggressive")
    img = Image.new("RGB", (10, 10), "white")
    results = reader.read_image(img)

    assert results == [b"not-base85"]


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


def test_qr_reader_read_frame_grayscale(monkeypatch):
    payload = b"gray"
    encoded = base64.b85encode(payload)

    class DummyObj:
        def __init__(self, data):
            self.data = data

    monkeypatch.setattr(qr_code.pyzbar, "decode", lambda img: [DummyObj(encoded)])

    reader = QRCodeReader(preprocessing="aggressive")
    frame = np.zeros((10, 10), dtype=np.uint8)
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


def test_webcam_reader_init_fails_when_closed(monkeypatch):
    class DummyCap:
        def isOpened(self):
            return False

        def release(self):
            return None

    monkeypatch.setattr(qr_code.cv2, "VideoCapture", lambda device: DummyCap())

    with pytest.raises(RuntimeError):
        WebcamQRReader(device=0)


def test_webcam_reader_read_next_returns_none_on_read_failure(monkeypatch):
    """Test that read_next returns None when cap.read() fails (line 285)."""

    class DummyCap:
        def isOpened(self):
            return True

        def read(self):
            # Always fail - covers line 284-285
            return False, None

        def release(self):
            pass

    dummy = DummyCap()
    monkeypatch.setattr(qr_code.cv2, "VideoCapture", lambda device: dummy)

    reader = WebcamQRReader(device=0, preprocessing="normal", frame_skip=0)
    # Now read_next should return None because cap.read() returns (False, None)
    result = reader.read_next()
    assert result is None


def test_webcam_reader_read_next_loops_when_no_qr_found(monkeypatch):
    """Test that read_next loops when no QR code found (line 295 partial branch)."""

    class DummyCap:
        def __init__(self):
            self.call_count = 0

        def isOpened(self):
            return True

        def read(self):
            self.call_count += 1
            return True, np.zeros((10, 10, 3), dtype=np.uint8)

        def release(self):
            pass

    dummy = DummyCap()
    monkeypatch.setattr(qr_code.cv2, "VideoCapture", lambda device: dummy)

    reader = WebcamQRReader(device=0, preprocessing="normal", frame_skip=0)

    read_frame_calls = [0]

    def fake_read_frame(frame):
        read_frame_calls[0] += 1
        if read_frame_calls[0] < 3:
            # Return empty list first 2 times - covers loop continuation
            return []
        # Return result on 3rd call
        return [b"found"]

    monkeypatch.setattr(reader.reader, "read_frame", fake_read_frame)

    result = reader.read_next()
    assert result is not None
    assert result[0] == b"found"
    # Verify we looped at least twice before finding QR
    assert read_frame_calls[0] >= 3


def test_webcam_reader_read_continuous_loops_when_result_none(monkeypatch):
    """Test read_continuous loops when read_next returns None (line 313 partial branch)."""

    class DummyCap:
        def isOpened(self):
            return True

        def read(self):
            return True, np.zeros((10, 10, 3), dtype=np.uint8)

        def release(self):
            pass

    dummy = DummyCap()
    monkeypatch.setattr(qr_code.cv2, "VideoCapture", lambda device: dummy)

    reader = WebcamQRReader(device=0, preprocessing="normal", frame_skip=0)

    call_count = [0]
    collected = []

    def fake_read_next():
        call_count[0] += 1
        if call_count[0] <= 2:
            # Return None first 2 times - covers loop continuation at line 313
            return None
        if call_count[0] == 3:
            # Return valid result
            return b"data", np.zeros((10, 10, 3), dtype=np.uint8)
        # After max_frames, return None to stop
        return None

    monkeypatch.setattr(reader, "read_next", fake_read_next)

    def callback(data, frame):
        collected.append(data)

    reader.read_continuous(callback, max_frames=1)
    assert collected == [b"data"]
    # Verify we went through the loop multiple times
    assert call_count[0] >= 3


def test_webcam_reader_release_when_cap_is_none(monkeypatch):
    """Test release() handles self.cap being None (line 320 partial branch)."""

    class DummyCap:
        def isOpened(self):
            return True

        def read(self):
            return True, np.zeros((10, 10, 3), dtype=np.uint8)

        def release(self):
            pass

    monkeypatch.setattr(qr_code.cv2, "VideoCapture", lambda device: DummyCap())

    reader = WebcamQRReader(device=0, preprocessing="normal", frame_skip=0)
    # Manually set cap to None to test the branch
    reader.cap = None
    # Should not raise, just early return
    reader.release()
    # Success if no exception


def test_webcam_reader_del_calls_release(monkeypatch):
    """Test __del__ calls release for cleanup."""

    class DummyCap:
        def __init__(self):
            self.released = False

        def isOpened(self):
            return True

        def read(self):
            return True, np.zeros((10, 10, 3), dtype=np.uint8)

        def release(self):
            self.released = True

    dummy = DummyCap()
    monkeypatch.setattr(qr_code.cv2, "VideoCapture", lambda device: dummy)

    reader = WebcamQRReader(device=0, preprocessing="normal", frame_skip=0)
    reader.__del__()
    assert dummy.released is True