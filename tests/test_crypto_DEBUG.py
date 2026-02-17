"""Tests for legacy_py/crypto_DEBUG.py (QUARANTINED).

This module has been moved out of production to legacy_py/.
It uses the Python `cryptography` library directly and is not
part of the production import path.
"""

import pytest

pytestmark = pytest.mark.deprecated


class TestCryptoDebug:
    def test_import_module(self):
        from legacy_py import crypto_DEBUG

        assert crypto_DEBUG is not None

    def test_manifest_class(self):
        from legacy_py.crypto_DEBUG import Manifest

        assert Manifest is not None
