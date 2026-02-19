"""Tests for meow_decoder/clowder_encode.py.

Additional tests in test_clowder_modules.py and test_clowder.py.
This file ensures 1-to-1 module-to-test mapping.
"""

import pytest


class TestClowderEncode:
    def test_import_module(self):
        from meow_decoder import clowder_encode

        assert clowder_encode is not None

    def test_clowder_manifest_class(self):
        from meow_decoder.clowder_encode import ClowderManifest

        manifest = ClowderManifest(clowder_id="test-123", password_hash="abc")
        assert manifest.clowder_id == "test-123"
        assert manifest.password_hash == "abc"
