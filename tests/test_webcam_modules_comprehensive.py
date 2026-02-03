import importlib
import sys
import types

import numpy as np


def _install_cv2_stub():
    cv2 = types.SimpleNamespace()
    cv2.COLOR_BGR2GRAY = 0
    cv2.CV_64F = 0
    cv2.ADAPTIVE_THRESH_GAUSSIAN_C = 0
    cv2.THRESH_BINARY = 0
    cv2.THRESH_OTSU = 0
    cv2.INTER_CUBIC = 0
    cv2.FONT_HERSHEY_SIMPLEX = 0

    def cvtColor(frame, code):
        if frame.ndim == 3:
            return frame.mean(axis=2).astype(frame.dtype)
        return frame

    def Laplacian(gray, depth):
        return np.zeros_like(gray, dtype=float)

    def adaptiveThreshold(gray, *_args, **_kwargs):
        return gray

    def threshold(gray, *_args, **_kwargs):
        return 0, gray

    def GaussianBlur(gray, *_args, **_kwargs):
        return gray

    def resize(gray, size, interpolation=None):
        return np.zeros((size[1], size[0]), dtype=gray.dtype)

    cv2.cvtColor = cvtColor
    cv2.Laplacian = Laplacian
    cv2.adaptiveThreshold = adaptiveThreshold
    cv2.threshold = threshold
    cv2.GaussianBlur = GaussianBlur
    cv2.resize = resize
    cv2.polylines = lambda *args, **kwargs: None
    cv2.putText = lambda *args, **kwargs: None

    sys.modules["cv2"] = cv2
    return cv2


def _install_pyzbar_stub():
    pyzbar = types.SimpleNamespace()
    pyzbar.pyzbar = types.SimpleNamespace(decode=lambda *_args, **_kwargs: [])
    sys.modules["pyzbar"] = pyzbar
    sys.modules["pyzbar.pyzbar"] = pyzbar.pyzbar


def test_paw_progress_and_overlay():
    _install_cv2_stub()
    _install_pyzbar_stub()
    webcam_enhanced = importlib.import_module("meow_decoder.webcam_enhanced")

    progress = webcam_enhanced.PawProgress(total=10)
    progress.update(5)
    assert progress.get_percentage() == 50.0
    assert "kibbles" in progress.get_status()

    frame = np.zeros((100, 100, 3), dtype=np.uint8)

    class _Point:
        def __init__(self, x, y):
            self.x = x
            self.y = y

    class _QR:
        polygon = [_Point(10, 10), _Point(20, 10), _Point(20, 20), _Point(10, 20)]

    overlay = webcam_enhanced.draw_qr_overlay(frame, [_QR()])
    assert overlay.shape == frame.shape


def test_decode_webcam_with_resume_utilities():
    _install_cv2_stub()
    module = importlib.import_module("meow_decoder.decode_webcam_with_resume")

    assert module.estimate_qr_version("ABCD") >= 1
    assert module.format_size(1024).endswith("KB")
    assert "ago" in module.format_time_ago(module.datetime.now().isoformat())

    frame = np.zeros((10, 10, 3), dtype=np.uint8)
    assert module.detect_glare(frame) is False
    assert module.calculate_blur_score(frame) == 0.0
