"""Tests for schrodinger_encode module (1-to-1 mapping).

Additional Schrödinger tests in test_schrodinger.py
"""

import pytest


class TestSchrodingerEncode:
    def test_import_module(self):
        from meow_decoder import schrodinger_encode

        assert schrodinger_encode is not None
