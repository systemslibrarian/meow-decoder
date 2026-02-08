"""Tests for clowder (multi-device) encoding/decoding modules."""

import pytest


class TestClowderEncode:
    def test_clowder_encode_import(self):
        try:
            from meow_decoder import clowder_encode

            assert clowder_encode is not None
        except ImportError:
            pytest.skip("clowder_encode module not available")


class TestClowderDecode:
    def test_clowder_decode_import(self):
        try:
            from meow_decoder import clowder_decode

            assert clowder_decode is not None
        except ImportError:
            pytest.skip("clowder_decode module not available")


class TestBidirectional:
    def test_bidirectional_import(self):
        try:
            from meow_decoder import bidirectional

            assert bidirectional is not None
        except ImportError:
            pytest.skip("bidirectional module not available")


class TestProwlingMode:
    def test_prowling_mode_import(self):
        try:
            from meow_decoder import prowling_mode

            assert prowling_mode is not None
        except ImportError:
            pytest.skip("prowling_mode module not available")
