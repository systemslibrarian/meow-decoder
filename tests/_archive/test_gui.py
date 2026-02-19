"""Tests for GUI modules."""

import pytest


class TestMeowDashboard:
    def test_dashboard_import(self):
        try:
            from meow_decoder import meow_dashboard_demo

            assert meow_dashboard_demo is not None
        except ImportError:
            pytest.skip("meow_dashboard_demo module not available")


class TestMeowGuiEnhanced:
    def test_gui_enhanced_import(self):
        try:
            from meow_decoder import meow_gui_enhanced

            assert meow_gui_enhanced is not None
        except ImportError:
            pytest.skip("meow_gui_enhanced module not available")


class TestGuiLogoExample:
    def test_gui_logo_import(self):
        try:
            from meow_decoder import gui_logo_example

            assert gui_logo_example is not None
        except ImportError:
            pytest.skip("gui_logo_example module not available")


class TestLogoEyes:
    def test_logo_eyes_import(self):
        try:
            from meow_decoder import logo_eyes

            assert logo_eyes is not None
        except ImportError:
            pytest.skip("logo_eyes module not available")


class TestWebcamEnhanced:
    def test_webcam_enhanced_import(self):
        try:
            from meow_decoder import webcam_enhanced

            assert webcam_enhanced is not None
        except ImportError:
            pytest.skip("webcam_enhanced module not available")


class TestDecodeWebcamWithResume:
    def test_decode_webcam_resume_import(self):
        try:
            from meow_decoder import decode_webcam_with_resume

            assert decode_webcam_with_resume is not None
        except ImportError:
            pytest.skip("decode_webcam_with_resume module not available")
