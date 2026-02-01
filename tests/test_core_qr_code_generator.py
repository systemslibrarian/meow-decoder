"""
⚠️ DEPRECATED: Tests consolidated into test_qr_code.py
This file will be removed after verification that all unique tests are migrated.
"""

import pytest

# Skip all tests in this module - consolidated into test_qr_code.py
pytestmark = pytest.mark.skip(reason="Consolidated into test_qr_code.py")

from meow_decoder.qr_code import QRCodeGenerator


def test_qr_code_generator_produces_image():
    gen = QRCodeGenerator(error_correction="M", box_size=4, border=2)
    img = gen.generate(b"hello")

    # Pillow Image-like API
    assert hasattr(img, "size")
    w, h = img.size
    assert w > 0 and h > 0
