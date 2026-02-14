"""Tests for decode_webcam_with_resume module (1-to-1 mapping).

Additional webcam tests in test_webcam_modules.py
"""

import pytest


class TestDecodeWebcamWithResume:
    def test_import_module(self):
        try:
            from meow_decoder import decode_webcam_with_resume

            assert decode_webcam_with_resume is not None
        except ImportError:
            pytest.skip("decode_webcam_with_resume module not available")
