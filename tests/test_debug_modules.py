"""Tests for debug and profiling modules."""

import pytest
import ast
from pathlib import Path


class TestCryptoDebug:
    def test_crypto_debug_import(self):
        try:
            from meow_decoder import crypto_DEBUG

            assert crypto_DEBUG is not None
        except ImportError:
            pytest.skip("crypto_DEBUG module not available")


class TestEncodeDebug:
    def test_encode_debug_import(self):
        try:
            from meow_decoder import encode_DEBUG

            assert encode_DEBUG is not None
        except ImportError:
            pytest.skip("encode_DEBUG module not available")


class TestProfilingImproved:
    def test_profiling_import(self):
        try:
            from meow_decoder import profiling_improved

            assert profiling_improved is not None
        except ImportError:
            pytest.skip("profiling_improved module not available")


class TestMeowEncode:
    def test_meow_encode_import(self):
        try:
            from meow_decoder import meow_encode

            assert meow_encode is not None
        except ImportError:
            pytest.skip("meow_encode module not available")


class TestSetupModule:
    def test_setup_syntax_valid(self):
        setup_path = Path(__file__).parent.parent / "meow_decoder" / "setup.py"
        if setup_path.exists():
            with open(setup_path) as f:
                content = f.read()
            ast.parse(content)
        else:
            pytest.skip("setup.py not found in meow_decoder/")
