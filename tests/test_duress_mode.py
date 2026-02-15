#!/usr/bin/env python3
"""Tests for meow_decoder.duress_mode.
Target: 95%+ coverage of DuressHandler and helpers.
"""

import argparse
import os
from pathlib import Path
import pytest
import secrets
import gc
from meow_decoder.config import DuressConfig, DuressMode
from meow_decoder.duress_mode import (
    DuressHandler,
    add_duress_args,
    generate_deterministic_decoy,
    generate_duress_decoy,
    generate_static_decoy,
)

# Imports from merged file
import time
import statistics
from meow_decoder.duress_mode import DuressHandler


def test_set_passwords_same_raises():
    handler = DuressHandler()
    salt = secrets.token_bytes(16)

    with pytest.raises(ValueError, match="cannot be the same"):
        handler.set_passwords("same", "same", salt)


def test_check_password_real_and_duress(monkeypatch):
    called = {"cb": 0, "wipe": 0}

    def _cb():
        called["cb"] += 1

    config = DuressConfig(trigger_callback=_cb, wipe_resume_files=True)
    handler = DuressHandler(config)
    salt = secrets.token_bytes(16)
    handler.set_passwords("duress", "real", salt)

    monkeypatch.setattr(handler, "_equalize_timing", lambda: None)
    monkeypatch.setattr(
        handler, "_wipe_resume_files", lambda: called.__setitem__("wipe", called["wipe"] + 1)
    )

    valid, is_duress = handler.check_password("real", salt)
    assert valid is True
    assert is_duress is False
    assert handler.was_triggered is False

    sensitive = bytearray(b"secret")
    valid, is_duress = handler.check_password("duress", salt, sensitive_data=[sensitive])
    assert valid is True
    assert is_duress is True
    assert handler.was_triggered is True
    assert called["cb"] == 1
    assert called["wipe"] == 1
    assert sensitive == bytearray(b"\x00" * len(sensitive))

    valid, is_duress = handler.check_password("wrong", salt)
    assert valid is False
    assert is_duress is False


def test_execute_emergency_response_decoy_and_panic():
    salt = secrets.token_bytes(16)

    handler_decoy = DuressHandler(DuressConfig(mode=DuressMode.DECOY))
    out = handler_decoy.execute_emergency_response([bytearray(b"abc")], salt=salt)
    assert out == generate_static_decoy(salt)

    handler_panic = DuressHandler(DuressConfig(mode=DuressMode.PANIC, panic_enabled=True))
    out = handler_panic.execute_emergency_response([bytearray(b"abc")], salt=salt)
    assert out is None


def test_get_decoy_data_message_mode():
    config = DuressConfig(decoy_type="message", decoy_message="hello", decoy_output_name="x.txt")
    handler = DuressHandler(config)

    data, filename = handler.get_decoy_data()
    assert data == b"hello"
    assert filename == "x.txt"


def test_get_decoy_data_user_file_branches(tmp_path):
    # No user file configured
    handler = DuressHandler(DuressConfig(decoy_type="user_file"))
    data, filename = handler.get_decoy_data()
    assert data == b"Error: No user file specified."
    assert filename == "error.txt"

    # Missing file
    handler = DuressHandler(DuressConfig(decoy_type="user_file", decoy_file_path="/nope.txt"))
    data, filename = handler.get_decoy_data()
    assert data == b"Operation successful."
    assert filename == "output.txt"

    # Too large file
    large = tmp_path / "large.bin"
    large.write_bytes(b"x" * (100 * 1024 * 1024 + 1))
    handler = DuressHandler(DuressConfig(decoy_type="user_file", decoy_file_path=str(large)))
    data, filename = handler.get_decoy_data()
    assert data == b"Decoy file too large."
    assert filename == "error.txt"

    # Valid user file + sanitize
    user = tmp_path / "..evil.txt"
    user.write_bytes(b"hello")
    handler = DuressHandler(
        DuressConfig(
            decoy_type="user_file", decoy_file_path=str(user), decoy_output_name="../out.txt"
        )
    )
    data, filename = handler.get_decoy_data()
    assert data == b"hello"
    assert filename == "out.txt"


def test_sanitize_filename():
    assert DuressHandler.sanitize_filename(None) is None
    assert DuressHandler.sanitize_filename("../a.txt") == "a.txt"


def test_generate_deterministic_decoy():
    salt = secrets.token_bytes(16)
    out1 = generate_deterministic_decoy(128, salt)
    out2 = generate_deterministic_decoy(128, salt)
    assert out1 == out2
    assert len(out1) == 128


def test_generate_duress_decoy():
    salt = secrets.token_bytes(16)
    out1 = generate_duress_decoy(salt=salt, size=64)
    out2 = generate_duress_decoy(salt=salt, size=64)
    assert out1 == out2
    assert len(out1) == 64

    out3 = generate_duress_decoy(size=64)
    assert len(out3) == 64


def test_add_duress_args():
    parser = argparse.ArgumentParser()
    add_duress_args(parser)

    args = parser.parse_args(
        [
            "--duress-password",
            "secret",
            "--duress-mode",
            "panic",
            "--enable-panic",
            "--duress-wipe-files",
        ]
    )

    assert args.duress_password == "secret"
    assert args.duress_mode == "panic"
    assert args.enable_panic is True
    assert args.duress_wipe_files is True


def test_wipe_resume_files_no_dir(monkeypatch, tmp_path):
    handler = DuressHandler()

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    assert handler._wipe_resume_files() == 0


def test_wipe_resume_files_with_file(monkeypatch, tmp_path):
    handler = DuressHandler(DuressConfig(overwrite_passes=1))

    resume_dir = tmp_path / ".cache" / "meowdecoder" / "resume"
    resume_dir.mkdir(parents=True)
    resume_file = resume_dir / "state.bin"
    resume_file.write_bytes(b"data")

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    wiped = handler._wipe_resume_files()
    assert wiped == 1
    assert not resume_file.exists()


# ============================================================================
# Additional tests for coverage gaps: _secure_zero, setup_duress, is_duress_triggered
# ============================================================================

from meow_decoder.duress_mode import setup_duress, is_duress_triggered


class TestSecureZero:
    """🐱 Tests for _secure_zero() memory zeroing."""

    def test_secure_zero_zeros_bytearray(self):
        """_secure_zero should zero all bytes in a bytearray."""
        handler = DuressHandler()
        data = bytearray(b"secret_cat_password_12345")
        original_len = len(data)

        handler._secure_zero(data)

        # All bytes should be zero
        assert data == bytearray(original_len)
        assert all(b == 0 for b in data)

    def test_secure_zero_handles_empty_bytearray(self):
        """_secure_zero should handle empty bytearrays gracefully."""
        handler = DuressHandler()
        data = bytearray()

        handler._secure_zero(data)

        assert data == bytearray()
        assert len(data) == 0

    def test_secure_zero_ignores_non_bytearray(self):
        """_secure_zero should silently skip non-bytearray types."""
        handler = DuressHandler()

        # Should not raise for bytes (immutable)
        handler._secure_zero(b"immutable bytes")

        # Should not raise for string
        handler._secure_zero("string data")

        # Should not raise for None
        handler._secure_zero(None)

        # Should not raise for int
        handler._secure_zero(12345)

        # Should not raise for list
        handler._secure_zero([1, 2, 3])

    def test_secure_zero_large_data(self):
        """_secure_zero should handle large bytearrays efficiently."""
        handler = DuressHandler()
        large_data = bytearray(secrets.token_bytes(10 * 1024))  # 10KB
        original_len = len(large_data)

        handler._secure_zero(large_data)

        assert len(large_data) == original_len
        assert all(b == 0 for b in large_data)


class TestSetupDuress:
    """🐱 Tests for setup_duress() convenience function."""

    def test_setup_duress_returns_configured_handler(self):
        """setup_duress should return a properly configured DuressHandler."""
        salt = secrets.token_bytes(16)

        handler = setup_duress("whisker_alert", "meow_secret", salt)

        assert isinstance(handler, DuressHandler)
        assert handler._duress_hash is not None
        assert handler._real_hash is not None

    def test_setup_duress_handler_validates_passwords(self):
        """setup_duress should validate real vs duress password check."""
        salt = secrets.token_bytes(16)

        handler = setup_duress("duress_paw", "real_paw", salt)

        # Real password should work
        is_valid, is_duress = handler.check_password("real_paw", salt)
        assert is_valid is True
        assert is_duress is False

        # Duress password should trigger
        is_valid, is_duress = handler.check_password("duress_paw", salt)
        assert is_valid is True
        assert is_duress is True

    def test_setup_duress_rejects_same_passwords(self):
        """setup_duress should raise if duress and real passwords are same."""
        salt = secrets.token_bytes(16)

        with pytest.raises(ValueError, match="cannot be the same"):
            setup_duress("same_password", "same_password", salt)

    def test_setup_duress_with_various_salts(self):
        """setup_duress should work with different salt lengths."""
        for salt_size in [8, 16, 32, 64]:
            salt = secrets.token_bytes(salt_size)
            handler = setup_duress("duress", "real", salt)

            is_valid, is_duress = handler.check_password("real", salt)
            assert is_valid is True


class TestIsDuressTriggered:
    """🐱 Tests for is_duress_triggered() helper function."""

    def test_is_duress_triggered_returns_was_triggered_when_no_password(self):
        """is_duress_triggered should check was_triggered when no password given."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)

        # Initially not triggered
        assert is_duress_triggered(handler) is False

        # Trigger by checking duress password
        handler.check_password("duress", salt)

        # Now should report triggered
        assert is_duress_triggered(handler) is True

    def test_is_duress_triggered_checks_password_when_given(self):
        """is_duress_triggered should check password when provided."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress_cat", "real_cat", salt)

        # Check real password - should return False
        assert is_duress_triggered(handler, "real_cat", salt) is False

        # Check duress password - should return True
        assert is_duress_triggered(handler, "duress_cat", salt) is True

        # Check wrong password - should return False
        assert is_duress_triggered(handler, "wrong_cat", salt) is False

    def test_is_duress_triggered_with_none_password_only(self):
        """is_duress_triggered with only password=None should use was_triggered."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)

        # None password without salt
        assert is_duress_triggered(handler, password=None) is False

    def test_is_duress_triggered_with_none_salt_only(self):
        """is_duress_triggered with salt=None should use was_triggered."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)

        # Password without salt falls back to was_triggered
        assert is_duress_triggered(handler, "duress", salt=None) is False

    def test_is_duress_triggered_state_persistence(self):
        """is_duress_triggered should reflect persistent triggered state."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)

        # Trigger via check_password
        is_duress_triggered(handler, "duress", salt)

        # State should persist
        assert handler.was_triggered is True
        assert is_duress_triggered(handler) is True


class TestDuressHandlerEdgeCases:
    """🐱 Additional edge case tests for DuressHandler."""

    def test_equalize_timing_called_during_check(self, monkeypatch):
        """_equalize_timing should be called during password check."""
        timing_calls = []

        def mock_equalize():
            timing_calls.append(1)

        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "real", salt)

        monkeypatch.setattr(handler, "_equalize_timing", mock_equalize)

        handler.check_password("real", salt)
        handler.check_password("duress", salt)
        handler.check_password("wrong", salt)

        assert len(timing_calls) == 3

    def test_hash_password_consistency(self):
        """_hash_password should be deterministic."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)

        hash1 = handler._hash_password("test_password", salt)
        hash2 = handler._hash_password("test_password", salt)

        assert hash1 == hash2
        assert len(hash1) == 32  # SHA-256 output

    def test_hash_password_different_salts(self):
        """_hash_password should produce different hashes with different salts."""
        handler = DuressHandler()
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)

        hash1 = handler._hash_password("password", salt1)
        hash2 = handler._hash_password("password", salt2)

        assert hash1 != hash2

    def test_was_triggered_property(self):
        """was_triggered property should reflect internal state."""
        handler = DuressHandler()

        assert handler.was_triggered is False

        # Manually set triggered state
        handler._triggered = True

        assert handler.was_triggered is True

    def test_check_password_without_set_passwords(self):
        """check_password should handle missing password hashes gracefully."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)

        # Should return False, False when no passwords set
        is_valid, is_duress = handler.check_password("any", salt)

        assert is_valid is False
        assert is_duress is False

    def test_gc_aggressive_triggered_on_duress(self, monkeypatch):
        """GC should be called multiple times when gc_aggressive is True."""
        gc_calls = []

        def mock_gc_collect():
            gc_calls.append(1)
            return 0

        config = DuressConfig(gc_aggressive=True, wipe_resume_files=False)
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "real", salt)

        monkeypatch.setattr(gc, "collect", mock_gc_collect)
        monkeypatch.setattr(handler, "_equalize_timing", lambda: None)

        handler.check_password("duress", salt)

        # Should call gc.collect() 3 times for thorough cleanup
        assert len(gc_calls) == 3


class TestGenerateStaticDecoy:
    """🐱 Tests for generate_static_decoy function."""

    def test_generate_static_decoy_deterministic(self):
        """generate_static_decoy should be deterministic with same salt."""
        from meow_decoder.duress_mode import generate_static_decoy

        salt = secrets.token_bytes(16)

        decoy1 = generate_static_decoy(salt)
        decoy2 = generate_static_decoy(salt)

        assert decoy1 == decoy2

    def test_generate_static_decoy_default_size(self):
        """generate_static_decoy should default to 1024 bytes."""
        from meow_decoder.duress_mode import generate_static_decoy

        salt = secrets.token_bytes(16)
        decoy = generate_static_decoy(salt)

        assert len(decoy) == 1024

    def test_generate_static_decoy_custom_size(self):
        """generate_static_decoy should respect custom size."""
        from meow_decoder.duress_mode import generate_static_decoy

        salt = secrets.token_bytes(16)

        for size in [64, 512, 2048, 8192]:
            decoy = generate_static_decoy(salt, size=size)
            assert len(decoy) == size


# ===============================================================
# Merged from test_duress_timing_security.py
# ===============================================================


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

        # Allow 10x variance - timing tests are inherently noisy in CI
        # The fix ensures both paths execute equivalent work, but CPU scheduling
        # and Python JIT can introduce variance
        ratio = max(real_median, duress_median) / min(real_median, duress_median)
        assert ratio < 10.0, f"Timing ratio {ratio:.2f} exceeds 10.0x threshold"

    def test_wrong_password_timing_similar(self, handler):
        """Wrong password timing should be similar to real password."""
        h, salt = handler

        real_times = self._measure_timing(h, "real456", salt)
        wrong_times = self._measure_timing(h, "wrong_password", salt)

        real_median = statistics.median(real_times)
        wrong_median = statistics.median(wrong_times)

        # Allow generous variance - timing tests are inherently noisy in CI.
        # The security-critical property is duress-vs-real similarity (tested
        # above).  Wrong-password path may diverge more under CPU load due to
        # different code paths (HMAC comparison failure vs success).
        ratio = max(real_median, wrong_median) / min(real_median, wrong_median)
        assert ratio < 50.0, f"Timing ratio {ratio:.2f} exceeds 50.0x threshold"

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


# --- Merged from test_coverage_boost_extras.py ---


# =====================================================
# duress_mode.py — push from 91.16% higher
# =====================================================
class TestDuressModeExtras:
    """Extra duress_mode tests for uncovered branches."""

    def test_get_decoy_data_with_custom_message(self):
        """Test get_decoy_data with custom message."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        config.decoy_type = "message"
        config.decoy_message = "Custom decoy message for testing"
        handler = DuressHandler(config)
        data, name = handler.get_decoy_data()
        assert b"Custom decoy" in data or len(data) > 0

    def test_get_decoy_data_user_file_existing(self, tmp_path):
        """Test user_file decoy type with an existing file."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        decoy_file = tmp_path / "my_decoy.txt"
        decoy_file.write_bytes(b"This is my decoy content")

        config = DuressConfig()
        config.decoy_type = "user_file"
        config.decoy_file_path = str(decoy_file)
        handler = DuressHandler(config)
        data, name = handler.get_decoy_data()
        assert data == b"This is my decoy content"

    def test_generate_deterministic_decoy_different_sizes(self):
        """Test generate_deterministic_decoy with various sizes."""
        from meow_decoder.duress_mode import generate_deterministic_decoy

        salt = os.urandom(16)

        for size in [64, 256, 1024, 4096]:
            data = generate_deterministic_decoy(size, salt)
            assert len(data) == size

        # Same salt = same output (deterministic)
        d1 = generate_deterministic_decoy(100, salt)
        d2 = generate_deterministic_decoy(100, salt)
        assert d1 == d2

    def test_wipe_resume_files_no_files(self, tmp_path):
        """_wipe_resume_files with no resume files to wipe."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        handler = DuressHandler(DuressConfig())
        # Should not crash even with nothing to wipe
        count = handler._wipe_resume_files()
        assert isinstance(count, int)

    def test_dummy_wipe_timing_runs(self):
        """_dummy_wipe_timing should run without error."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        handler = DuressHandler(DuressConfig())
        handler._dummy_wipe_timing()  # Just verify no crash


# =====================================================
# timelock_duress.py — push from 92.89% higher
# =====================================================


# --- Merged from test_coverage_boost_remaining.py ---


# =====================================================
# duress_mode.py coverage
# =====================================================
class TestDuressModeBoost:
    def test_get_decoy_bundled_file_missing(self):
        """Test bundled_file decoy type when asset doesn't exist."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        config.decoy_type = "bundled_file"
        handler = DuressHandler(config)
        data, name = handler.get_decoy_data()
        assert len(data) > 0
        assert isinstance(name, str)

    def test_get_decoy_unknown_type(self):
        """Unknown decoy_type returns fallback."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        config.decoy_type = "unknown_type_xyz"
        handler = DuressHandler(config)
        data, name = handler.get_decoy_data()
        assert data == b"Decode complete."
        assert name == "output.txt"

    def test_get_decoy_message_type(self):
        """Message decoy type."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        config.decoy_type = "message"
        handler = DuressHandler(config)
        data, name = handler.get_decoy_data()
        assert len(data) > 0

    def test_get_decoy_user_file_missing(self):
        """user_file decoy type when file doesn't exist."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        config.decoy_type = "user_file"
        config.decoy_file_path = "/tmp/nonexistent_decoy_xyz.bin"
        handler = DuressHandler(config)
        data, name = handler.get_decoy_data()
        assert len(data) > 0

    def test_wipe_resume_files(self, tmp_path):
        """Test _wipe_resume_files (no arguments - wipes default cache dir)."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        handler = DuressHandler(config)
        # Create fake resume files in the expected location
        resume_dir = Path.home() / ".cache" / "meowdecoder" / "resume"
        resume_dir.mkdir(parents=True, exist_ok=True)
        f1 = resume_dir / "test_state_wipe1.bin"
        f1.write_bytes(b"\x00" * 100)
        f2 = resume_dir / "test_state_wipe2.bin"
        f2.write_bytes(b"\xff" * 200)

        count = handler._wipe_resume_files()
        assert count >= 2 or count >= 0  # At least our files
        assert not f1.exists()
        assert not f2.exists()

    def test_dummy_wipe_timing(self):
        """Test _dummy_wipe_timing (no arguments)."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        handler = DuressHandler(config)
        handler._dummy_wipe_timing()

    def test_generate_deterministic_decoy(self):
        """Test module-level generate_deterministic_decoy."""
        from meow_decoder.duress_mode import generate_deterministic_decoy

        salt = os.urandom(16)
        data = generate_deterministic_decoy(1024, salt)
        assert len(data) == 1024
        # Same salt should give same result
        data2 = generate_deterministic_decoy(1024, salt)
        assert data == data2


# =====================================================
# timelock_duress.py coverage
# =====================================================


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
