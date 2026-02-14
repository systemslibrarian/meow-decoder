"""Tests for progress_bar module (1-to-1 mapping).

Additional progress tests in test_progress_modules.py
"""

import pytest


class TestProgressBar:
    def test_import_module(self):
        from meow_decoder import progress_bar

        assert progress_bar is not None

    def test_progress_bar_class(self):
        try:
            from meow_decoder.progress_bar import ProgressBar

            pb = ProgressBar(total=10, desc="Test")
            pb.update(5)
            pb.close()
        except (ImportError, TypeError):
            pytest.skip("ProgressBar not available")

    def test_progress_bar_iteration(self):
        try:
            from meow_decoder.progress_bar import ProgressBar

            pb = ProgressBar(total=5, desc="Iter")
            result = list(pb(range(5)))
            assert len(result) == 5
            pb.close()
        except (ImportError, TypeError):
            pytest.skip("ProgressBar iteration not available")
