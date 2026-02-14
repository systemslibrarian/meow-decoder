"""Tests for meow_decoder/crypto_DEBUG.py (DEPRECATED).

Additional debug module tests in test_debug_modules.py.
This file ensures 1-to-1 module-to-test mapping.

This module is deprecated — use meow_decoder.crypto instead.
"""

import pytest

pytestmark = pytest.mark.deprecated


class TestCryptoDebug:
    def test_import_module(self):
        from meow_decoder import crypto_DEBUG

        assert crypto_DEBUG is not None

    def test_manifest_class(self):
        from meow_decoder.crypto_DEBUG import Manifest

        assert Manifest is not None
