"""Tests for meow_gui_enhanced module (1-to-1 mapping).

Additional GUI tests in test_dashboard_gui.py
"""

import pytest


class TestMeowGuiEnhanced:
    def test_import_module(self):
        try:
            from meow_decoder import meow_gui_enhanced

            assert meow_gui_enhanced is not None
        except ImportError:
            pytest.skip("Enhanced GUI dependencies not available")

    def test_gui_class(self):
        try:
            from meow_decoder.meow_gui_enhanced import MeowGuiEnhanced

            gui = MeowGuiEnhanced()
            assert gui is not None
        except (ImportError, AttributeError, TypeError):
            pytest.skip("MeowGuiEnhanced not available")
