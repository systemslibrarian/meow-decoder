"""Tests for meow_decoder/clowder_decode.py.

Additional tests in test_clowder_modules.py and test_clowder.py.
This file ensures 1-to-1 module-to-test mapping.
"""

import pytest


class TestClowderDecode:
    def test_import_module(self):
        from meow_decoder import clowder_decode

        assert clowder_decode is not None

    def test_decode_clowder_function(self):
        from meow_decoder.clowder_decode import decode_clowder

        assert callable(decode_clowder)

    def test_hash_password(self):
        from meow_decoder.clowder_decode import hash_password

        h1 = hash_password("test")
        h2 = hash_password("test")
        assert h1 == h2
        assert isinstance(h1, str)
