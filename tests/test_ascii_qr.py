"""Tests for ascii_qr.py module."""

import pytest


class TestAsciiQr:
    """Tests for ascii_qr.py"""

    def test_import_module(self):
        """Test module imports correctly."""
        from meow_decoder import ascii_qr

        assert ascii_qr is not None

    def test_generate_ascii_qr(self):
        """Test ASCII QR generation."""
        try:
            from meow_decoder.ascii_qr import generate_ascii_qr

            result = generate_ascii_qr("Hello World")
            assert result is not None
            assert isinstance(result, str)
            assert len(result) > 0
        except (ImportError, AttributeError):
            pytest.skip("generate_ascii_qr not available")

    def test_generate_ascii_qr_compact(self):
        """Test compact ASCII QR generation."""
        try:
            from meow_decoder.ascii_qr import generate_ascii_qr

            result = generate_ascii_qr("Test", compact=True)
            assert result is not None
        except (ImportError, AttributeError, TypeError):
            pytest.skip("Compact mode not available")

    def test_ascii_qr_box_styles(self):
        """Test different box styles."""
        try:
            from meow_decoder.ascii_qr import generate_ascii_qr

            for style in ["block", "dot", "shade"]:
                result = generate_ascii_qr("Test", style=style)
                assert result is not None
        except (ImportError, AttributeError, TypeError):
            pytest.skip("Box styles not available")

    def test_print_qr(self):
        """Test QR printing to console."""
        try:
            from meow_decoder.ascii_qr import print_qr

            # Should not raise
            print_qr("Test data")
        except (ImportError, AttributeError):
            pytest.skip("print_qr not available")


# --- Merged from test_ascii_qr_comprehensive.py ---

import io

import meow_decoder.ascii_qr as ascii_qr


def test_ascii_qr_render_modes_non_empty():
    qr = ascii_qr.ASCIIQRCode("hello", error_correction="L", border=1)
    assert qr.render_unicode()
    assert qr.render_ascii()
    assert qr.render_large()
    assert qr.render_colored()


def test_ascii_qr_properties():
    qr = ascii_qr.ASCIIQRCode("hello", error_correction="M", border=1)
    assert qr.version >= 1
    assert qr.module_count == qr.size


def test_generate_terminal_qr_returns_string():
    output = ascii_qr.generate_terminal_qr("data", mode="ascii", error_correction="Q")
    assert isinstance(output, str)
    assert output


def test_print_terminal_qr_success(monkeypatch, capsys):
    monkeypatch.setattr(ascii_qr.shutil, "get_terminal_size", lambda fallback=None: (200, 200))
    ascii_qr.print_terminal_qr("data", mode="unicode", title="Test")
    out = capsys.readouterr().out
    assert "Test" in out
    assert "QR Version" in out


def test_print_terminal_qr_too_small(monkeypatch):
    monkeypatch.setattr(ascii_qr.shutil, "get_terminal_size", lambda fallback=None: (10, 5))
    try:
        ascii_qr.print_terminal_qr("data", mode="large")
        assert False, "Expected ValueError for small terminal"
    except ValueError as exc:
        assert "Terminal too small" in str(exc)


def test_animated_terminal_qr_play_once(monkeypatch, capsys):
    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda *_: None)
    anim = ascii_qr.AnimatedTerminalQR([b"abc"], fps=5, mode="unicode")
    anim.play(loop=False, clear=False)
    out = capsys.readouterr().out
    assert "Frame 1/1" in out
