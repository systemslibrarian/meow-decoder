"""Tests for meow_dashboard_demo module (1-to-1 mapping).

Additional GUI tests in test_dashboard_gui.py
"""

import pytest


class TestMeowDashboardDemo:
    def test_import_module(self):
        try:
            from meow_decoder import meow_dashboard_demo

            assert meow_dashboard_demo is not None
        except ImportError:
            pytest.skip("Dashboard demo dependencies not available")

    def test_main_callable(self):
        try:
            from meow_decoder.meow_dashboard_demo import main

            assert callable(main)
        except (ImportError, AttributeError):
            pytest.skip("Dashboard demo not fully available")
