"""
Tests for secure password input module.

Tests cover:
- Timing normalization (pre/post delays)
- Non-TTY warning
- CSPRNG delay bounds
"""

import os
import sys
import time
import warnings
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.security

from meow_decoder.secure_input import (
    SecurePasswordWarning,
    _csprng_delay,
    _is_tty,
    secure_getpass,
)


class TestCsprngDelay:
    """Tests for CSPRNG delay generation."""

    def test_delay_within_bounds(self):
        """Delay should be within [min_ms, max_ms] converted to seconds."""
        for _ in range(100):
            delay = _csprng_delay(50, 300)
            assert 0.050 <= delay <= 0.300

    def test_delay_equal_min_max(self):
        """Equal min/max should return exact value."""
        delay = _csprng_delay(100, 100)
        assert delay == pytest.approx(0.100)

    def test_delay_invalid_range(self):
        """min > max should raise ValueError."""
        with pytest.raises(ValueError, match="min_ms must be <= max_ms"):
            _csprng_delay(300, 50)

    def test_delay_is_float(self):
        """Delay should be a float (seconds)."""
        delay = _csprng_delay(10, 200)
        assert isinstance(delay, float)

    def test_delay_distribution_not_constant(self):
        """Multiple calls should produce varying results."""
        delays = {_csprng_delay(10, 1000) for _ in range(20)}
        # With 20 samples from a 990ms range, we should get variation
        assert len(delays) > 5


class TestIsTty:
    """Tests for TTY detection."""

    def test_is_tty_returns_bool(self):
        """Should return a boolean."""
        result = _is_tty()
        assert isinstance(result, bool)

    @patch("os.isatty", return_value=True)
    @patch("sys.stdin")
    def test_is_tty_true(self, mock_stdin, mock_isatty):
        """Should return True when stdin is a TTY."""
        mock_stdin.fileno.return_value = 0
        assert _is_tty() is True

    @patch("os.isatty", return_value=False)
    @patch("sys.stdin")
    def test_is_tty_false(self, mock_stdin, mock_isatty):
        """Should return False when stdin is not a TTY."""
        mock_stdin.fileno.return_value = 0
        assert _is_tty() is False

    @patch("os.isatty", side_effect=OSError)
    @patch("sys.stdin")
    def test_is_tty_error(self, mock_stdin, mock_isatty):
        """Should return False on OSError."""
        mock_stdin.fileno.return_value = 0
        assert _is_tty() is False


class TestSecureGetpass:
    """Tests for secure password input."""

    @patch("meow_decoder.secure_input.getpass", return_value="test_password")
    @patch("meow_decoder.secure_input._is_tty", return_value=True)
    def test_returns_password(self, mock_tty, mock_getpass):
        """Should return the password from getpass."""
        result = secure_getpass("Enter: ", min_delay_ms=1, max_delay_ms=2)
        assert result == "test_password"

    @patch("meow_decoder.secure_input.getpass", return_value="pw")
    @patch("meow_decoder.secure_input._is_tty", return_value=True)
    def test_timing_adds_delay(self, mock_tty, mock_getpass):
        """Total time should include pre and post delays."""
        start = time.monotonic()
        secure_getpass("Enter: ", min_delay_ms=50, max_delay_ms=50)
        elapsed = time.monotonic() - start
        # At least 100ms total (50ms pre + 50ms post)
        assert elapsed >= 0.09  # Small tolerance for scheduling

    @patch("meow_decoder.secure_input.getpass", return_value="pw")
    @patch("meow_decoder.secure_input._is_tty", return_value=False)
    def test_non_tty_warning(self, mock_tty, mock_getpass):
        """Should warn when stdin is not a TTY."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            secure_getpass("Enter: ", min_delay_ms=1, max_delay_ms=2, warn_non_tty=True)
            tty_warnings = [x for x in w if issubclass(x.category, SecurePasswordWarning)]
            assert len(tty_warnings) == 1
            assert "not a TTY" in str(tty_warnings[0].message)

    @patch("meow_decoder.secure_input.getpass", return_value="pw")
    @patch("meow_decoder.secure_input._is_tty", return_value=False)
    def test_non_tty_warning_suppressed(self, mock_tty, mock_getpass):
        """Should NOT warn when warn_non_tty=False."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            secure_getpass("Enter: ", min_delay_ms=1, max_delay_ms=2, warn_non_tty=False)
            tty_warnings = [x for x in w if issubclass(x.category, SecurePasswordWarning)]
            assert len(tty_warnings) == 0

    @patch("meow_decoder.secure_input.getpass", return_value="pw")
    @patch("meow_decoder.secure_input._is_tty", return_value=True)
    def test_custom_prompt_passed(self, mock_tty, mock_getpass):
        """Custom prompt should be forwarded to getpass."""
        secure_getpass("Custom prompt: ", min_delay_ms=1, max_delay_ms=2)
        mock_getpass.assert_called_once_with("Custom prompt: ")


class TestTimingNormalization:
    """Statistical tests for timing normalization."""

    @patch("meow_decoder.secure_input.getpass", return_value="pw")
    @patch("meow_decoder.secure_input._is_tty", return_value=True)
    def test_timing_variance(self, mock_tty, mock_getpass):
        """Multiple calls should show timing variance from random delays."""
        times = []
        for _ in range(10):
            start = time.monotonic()
            secure_getpass("p: ", min_delay_ms=10, max_delay_ms=100)
            times.append(time.monotonic() - start)

        # Should have variance (not all identical)
        min_t = min(times)
        max_t = max(times)
        # With [10, 100]ms delays x2, expect range of at least 20ms
        assert max_t - min_t > 0.005  # 5ms minimum spread
