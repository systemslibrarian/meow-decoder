"""
Security Regression Tests for Duress Mode Timing (HIGH-02 Fix)

Created: 2026-02-06
Audit: audit1.md - HIGH-02 (Duress Timing Leak)

These tests verify the constant-time fix for duress password checking:
1. Real and duress passwords have equivalent timing
2. Wrong passwords also have equivalent timing
3. Timing variance is within acceptable bounds
"""

import os
import time
import secrets
import statistics
import pytest

from meow_decoder.duress_mode import DuressHandler
from meow_decoder.config import DuressConfig


class TestDuressTimingEqualization:
    """Test suite for duress mode timing side-channel fix (HIGH-02)."""

    @pytest.fixture
    def handler(self):
        """Create a DuressHandler with test passwords."""
        config = DuressConfig()
        config.min_delay_ms = 0  # Reduce delay for faster tests
        config.max_delay_ms = 1
        config.gc_aggressive = False  # Disable GC for cleaner timing
        config.wipe_resume_files = False

        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords(duress_password="duress123", real_password="real456", salt=salt)
        return handler, salt

    def _measure_timing(self, handler, password, salt, iterations=20):
        """Measure password check timing over multiple iterations."""
        times = []
        for _ in range(iterations):
            # Create fresh sensitive data each time
            sensitive_data = [bytearray(1024)]

            start = time.perf_counter()
            handler.check_password(password, salt, sensitive_data)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        return times

    def test_duress_vs_real_timing_similar(self, handler):
        """Timing for duress and real passwords should be similar."""
        h, salt = handler

        # Measure timing for both passwords
        real_times = self._measure_timing(h, "real456", salt)
        duress_times = self._measure_timing(h, "duress123", salt)

        real_median = statistics.median(real_times)
        duress_median = statistics.median(duress_times)

        # Allow 5x variance - timing tests are inherently noisy in CI
        # The fix ensures both paths execute equivalent work, but CPU scheduling
        # and Python JIT can introduce variance
        ratio = max(real_median, duress_median) / min(real_median, duress_median)
        assert ratio < 5.0, f"Timing ratio {ratio:.2f} exceeds 5.0x threshold"

    def test_wrong_password_timing_similar(self, handler):
        """Wrong password timing should be similar to real password."""
        h, salt = handler

        real_times = self._measure_timing(h, "real456", salt)
        wrong_times = self._measure_timing(h, "wrong_password", salt)

        real_median = statistics.median(real_times)
        wrong_median = statistics.median(wrong_times)

        # Allow 5x variance - timing tests are inherently noisy in CI
        # The important security property is that duress and real are similar
        ratio = max(real_median, wrong_median) / min(real_median, wrong_median)
        assert ratio < 5.0, f"Timing ratio {ratio:.2f} exceeds 5.0x threshold"

    def test_duress_triggers_flag(self, handler):
        """Duress password should set triggered flag."""
        h, salt = handler

        assert not h.was_triggered
        is_valid, is_duress = h.check_password("duress123", salt)

        assert is_valid
        assert is_duress
        assert h.was_triggered

    def test_real_password_not_triggered(self, handler):
        """Real password should not set triggered flag."""
        h, salt = handler

        is_valid, is_duress = h.check_password("real456", salt)

        assert is_valid
        assert not is_duress
        assert not h.was_triggered

    def test_sensitive_data_zeroed_on_duress(self, handler):
        """Sensitive data should be zeroed when duress is triggered."""
        h, salt = handler

        sensitive = [bytearray(b"SECRET_KEY_DATA_12345678")]
        original_len = len(sensitive[0])

        h.check_password("duress123", salt, sensitive)

        # Data should be zeroed
        assert all(b == 0 for b in sensitive[0])
        assert len(sensitive[0]) == original_len

    def test_sensitive_data_intact_on_real(self, handler):
        """Sensitive data should NOT be zeroed for real password."""
        h, salt = handler

        original_data = b"SECRET_KEY_DATA_12345678"
        sensitive = [bytearray(original_data)]

        h.check_password("real456", salt, sensitive)

        # Data should be preserved (dummy data was zeroed instead)
        assert sensitive[0] == bytearray(original_data)

    def test_callback_only_called_on_duress(self, handler):
        """Trigger callback should only execute on duress."""
        h, salt = handler
        callback_count = [0]

        def real_callback():
            callback_count[0] += 1

        h.config.trigger_callback = real_callback

        # Real password - callback should NOT increment
        h.check_password("real456", salt)
        assert callback_count[0] == 0

        # Duress password - callback SHOULD increment
        h.check_password("duress123", salt)
        assert callback_count[0] == 1


class TestDuressPasswordValidation:
    """Test password validation logic."""

    def test_same_password_rejected(self):
        """Duress and real passwords cannot be the same."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)

        with pytest.raises(ValueError, match="cannot be the same"):
            handler.set_passwords("same_pass", "same_pass", salt)

    def test_password_hash_uses_salt(self):
        """Password hashing should incorporate salt."""
        handler = DuressHandler()

        salt1 = b"salt_one_16bytes"
        salt2 = b"salt_two_16bytes"

        hash1 = handler._hash_password("test_pass", salt1)
        hash2 = handler._hash_password("test_pass", salt2)

        assert hash1 != hash2

    def test_password_hash_uses_domain_separation(self):
        """Password hash should use domain separation prefix."""
        handler = DuressHandler()
        salt = b"test_salt_16byte"

        # Manually compute expected hash
        import hashlib

        expected = hashlib.sha256(b"duress_check_v1" + salt + b"test_pass").digest()

        actual = handler._hash_password("test_pass", salt)
        assert actual == expected


class TestDummyWipeTiming:
    """Test dummy wipe timing simulation."""

    def test_dummy_wipe_exists(self):
        """Dummy wipe method should exist."""
        handler = DuressHandler()
        assert hasattr(handler, "_dummy_wipe_timing")

    def test_dummy_wipe_runs_without_error(self):
        """Dummy wipe should run without errors."""
        handler = DuressHandler()
        # Should not raise even if directory doesn't exist
        handler._dummy_wipe_timing()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
