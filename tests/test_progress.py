"""Tests for progress bar modules."""

import pytest
from meow_decoder.progress import ProgressBar


class TestProgressBar:
    def test_progress_bar_import(self):
        assert ProgressBar is not None

    def test_progress_bar_disabled(self):
        pb = ProgressBar(total=100, desc="Test", disable=True)
        items = list(range(10))
        result = list(pb(items))
        assert result == items

    def test_progress_bar_iteration(self):
        pb = ProgressBar(total=5, desc="Test", disable=True)
        items = [1, 2, 3, 4, 5]
        result = list(pb(items))
        assert result == items

    def test_progress_bar_with_unit(self):
        pb = ProgressBar(total=10, desc="Frames", unit="frames", disable=True)
        result = list(pb(range(10)))
        assert len(result) == 10

    def test_progress_bar_call(self):
        pb = ProgressBar(total=3, disable=True)
        data = [1, 2, 3]
        collected = []
        for item in pb(data):
            collected.append(item)
        assert collected == data

    def test_progress_bar_empty(self):
        pb = ProgressBar(total=0, disable=True)
        result = list(pb([]))
        assert result == []


class TestAsciiQR:
    def test_ascii_qr_import(self):
        try:
            from meow_decoder import ascii_qr

            assert ascii_qr is not None
        except ImportError:
            pytest.skip("ascii_qr module not available")


class TestNinjaCatUltra:
    def test_ninja_cat_import(self):
        try:
            from meow_decoder import ninja_cat_ultra

            assert ninja_cat_ultra is not None
        except ImportError:
            pytest.skip("ninja_cat_ultra module not available")
