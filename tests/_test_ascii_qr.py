#!/usr/bin/env python3
"""
🧪 Test Suite: ascii_qr.py
Tests ASCII QR code generation for terminal display.

⚠️ DEPRECATED: Tests consolidated into test_qr_code.py
This file will be removed after verification that all unique tests are migrated.
"""

import pytest

# Skip all tests in this module - consolidated into test_qr_code.py
pytestmark = pytest.mark.skip(reason="Consolidated into test_qr_code.py")

import os
os.environ["MEOW_TEST_MODE"] = "1"

# Try to import ascii_qr module
try:
    from meow_decoder.ascii_qr import (
        generate_ascii_qr,
        qr_to_ascii,
        display_qr_terminal,
    )
    ASCII_QR_AVAILABLE = True
except ImportError:
    ASCII_QR_AVAILABLE = False


@pytest.mark.skipif(not ASCII_QR_AVAILABLE, reason="ascii_qr module not available")
class TestGenerateAsciiQR:
    """Tests for ASCII QR generation."""

    def test_generate_basic(self):
        """Test basic ASCII QR generation."""
        result = generate_ascii_qr("Hello")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_generate_with_data(self):
        """Test ASCII QR with binary data."""
        result = generate_ascii_qr(b"test data")
        assert isinstance(result, str)

    def test_generate_empty_string(self):
        """Test with empty string."""
        result = generate_ascii_qr("")
        assert isinstance(result, str)


@pytest.mark.skipif(not ASCII_QR_AVAILABLE, reason="ascii_qr module not available")
class TestQRToAscii:
    """Tests for QR to ASCII conversion."""

    def test_convert_basic(self):
        """Test basic QR to ASCII conversion."""
        from qrcode import QRCode
        qr = QRCode()
        qr.add_data("test")
        qr.make()
        result = qr_to_ascii(qr)
        assert isinstance(result, str)


@pytest.mark.skipif(not ASCII_QR_AVAILABLE, reason="ascii_qr module not available")
class TestDisplayQRTerminal:
    """Tests for terminal display."""

    def test_display_basic(self, capsys):
        """Test terminal display output."""
        display_qr_terminal("test")
        captured = capsys.readouterr()
        assert len(captured.out) > 0


# Fallback test if module not available
@pytest.mark.skipif(ASCII_QR_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not ASCII_QR_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
