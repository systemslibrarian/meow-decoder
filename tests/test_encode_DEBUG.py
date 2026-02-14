"""Tests for encode_DEBUG module (1-to-1 mapping).

Additional debug module tests in test_debug_modules.py.
This module is DEPRECATED — use meow_decoder.encode instead.
"""

import pytest

pytestmark = pytest.mark.deprecated


class TestEncodeDebug:
    def test_import_module(self):
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from meow_decoder import encode_DEBUG

            assert encode_DEBUG is not None

    def test_encode_file_exists(self):
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from meow_decoder.encode_DEBUG import encode_file

            assert callable(encode_file)
