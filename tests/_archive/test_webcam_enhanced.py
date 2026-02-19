"""Tests for webcam_enhanced module (1-to-1 mapping).

Additional webcam tests in test_webcam_modules.py
"""

import pytest


class TestWebcamEnhanced:
    def test_import_module(self):
        try:
            from meow_decoder import webcam_enhanced

            assert webcam_enhanced is not None
        except ImportError:
            pytest.skip("webcam_enhanced module not available")
