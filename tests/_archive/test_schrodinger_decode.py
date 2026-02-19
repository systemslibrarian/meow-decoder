"""Tests for schrodinger_decode module (1-to-1 mapping).

Additional Schrödinger tests in test_schrodinger.py
"""

import pytest


class TestSchrodingerDecode:
    def test_import_module(self):
        from meow_decoder import schrodinger_decode

        assert schrodinger_decode is not None
