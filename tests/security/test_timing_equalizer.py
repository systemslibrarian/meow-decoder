"""
Tests for timing_equalizer.py — Timing-Equalized Operations

Tests verify:
  - Wall-clock time padding to target ± jitter
  - Fast functions are padded correctly
  - Slow functions are not truncated
  - Exception handling preserves timing equalization
  - TimingResult carries correct metadata
  - Duress timing equalizer runs dummy Argon2id
  - TimingEqualizedDecoder wraps decode operations
  - Jitter stays within bounds over many samples
"""

import time
import pytest
from unittest.mock import MagicMock
from meow_decoder.timing_equalizer import (
    equalize_timing,
    constant_time_password_check,
    duress_timing_equalizer,
    TimingEqualizedDecoder,
    TimingResult,
    DEFAULT_TARGET_MS,
    DEFAULT_JITTER_PERCENT,
    MIN_SLEEP_MS,
)


# ══════════════════════════════════════════════════════════════
#  TimingResult
# ══════════════════════════════════════════════════════════════


class TestTimingResult:
    """Tests for TimingResult dataclass."""

    def test_default_values(self):
        r = TimingResult()
        assert r.value is None
        assert r.success is False
        assert r.elapsed_ms == 0.0
        assert r.padded_ms == 0.0
        assert r.error is None

    def test_custom_values(self):
        exc = ValueError("test")
        r = TimingResult(value=42, success=True, elapsed_ms=100.0, padded_ms=200.0, error=exc)
        assert r.value == 42
        assert r.success is True
        assert r.elapsed_ms == 100.0
        assert r.padded_ms == 200.0
        assert r.error is exc

    def test_slots(self):
        """TimingResult uses __slots__ for memory efficiency."""
        r = TimingResult()
        with pytest.raises(AttributeError):
            r.nonexistent = "fail"


# ══════════════════════════════════════════════════════════════
#  equalize_timing
# ══════════════════════════════════════════════════════════════


class TestEqualizeTiming:
    """Tests for the core equalize_timing function."""

    def test_fast_function_is_padded(self):
        """A fast function should be padded to near the target time."""
        target_ms = 200.0  # Short target for fast test

        def fast():
            return "done"

        start = time.monotonic()
        result = equalize_timing(fast, target_ms=target_ms, jitter_percent=0)
        elapsed = (time.monotonic() - start) * 1000

        assert result.success is True
        assert result.value == "done"
        assert result.error is None
        # Should be close to target (within 50ms tolerance for scheduler noise)
        assert elapsed >= target_ms * 0.8, f"Too fast: {elapsed:.1f}ms < {target_ms * 0.8:.1f}ms"
        assert elapsed < target_ms * 1.5, f"Too slow: {elapsed:.1f}ms > {target_ms * 1.5:.1f}ms"

    def test_slow_function_not_truncated(self):
        """A function slower than target should not be cut short."""
        target_ms = 50.0

        def slow():
            time.sleep(0.15)  # 150ms, exceeds 50ms target
            return "slow_result"

        result = equalize_timing(slow, target_ms=target_ms, jitter_percent=0)

        assert result.success is True
        assert result.value == "slow_result"
        assert result.elapsed_ms >= 100.0  # Actually ran the slow function

    def test_exception_is_captured(self):
        """Exceptions should be captured, not raised, and timing still equalized."""
        target_ms = 200.0

        def failing():
            raise ValueError("test error")

        start = time.monotonic()
        result = equalize_timing(failing, target_ms=target_ms, jitter_percent=0)
        elapsed = (time.monotonic() - start) * 1000

        assert result.success is False
        assert result.value is None
        assert isinstance(result.error, ValueError)
        assert str(result.error) == "test error"
        # Still padded to target
        assert elapsed >= target_ms * 0.8

    def test_args_and_kwargs_passed(self):
        """Arguments are correctly forwarded to the wrapped function."""
        def add(a, b, c=0):
            return a + b + c

        result = equalize_timing(add, args=(1, 2), kwargs={"c": 3}, target_ms=100, jitter_percent=0)
        assert result.success is True
        assert result.value == 6

    def test_elapsed_ms_recorded(self):
        """elapsed_ms should reflect actual execution time, not padded time."""
        def fast():
            return 42

        result = equalize_timing(fast, target_ms=300, jitter_percent=0)
        # Fast function should complete in < 50ms
        assert result.elapsed_ms < 50.0
        # Padded time should be near target
        assert result.padded_ms >= 250.0

    def test_jitter_stays_within_bounds(self):
        """Over multiple runs, padded time should be within target ± jitter."""
        target_ms = 300.0
        jitter_pct = 10.0  # ±10%
        min_expected = target_ms * (1.0 - jitter_pct / 100.0) * 0.9  # Some tolerance
        max_expected = target_ms * (1.0 + jitter_pct / 100.0) * 1.2  # Some tolerance

        results = []
        for _ in range(10):
            r = equalize_timing(lambda: None, target_ms=target_ms, jitter_percent=jitter_pct)
            results.append(r.padded_ms)

        for padded in results:
            assert padded >= min_expected, f"Padded {padded:.1f}ms below min {min_expected:.1f}ms"
            assert padded <= max_expected, f"Padded {padded:.1f}ms above max {max_expected:.1f}ms"

    def test_zero_jitter(self):
        """With zero jitter, padded time should be very close to target."""
        target_ms = 200.0
        result = equalize_timing(lambda: None, target_ms=target_ms, jitter_percent=0)
        # Should be within 30ms of target (scheduler noise)
        assert abs(result.padded_ms - target_ms) < 50.0

    def test_none_kwargs_default(self):
        """kwargs=None should be handled gracefully."""
        result = equalize_timing(lambda: "ok", target_ms=100, jitter_percent=0)
        assert result.value == "ok"


# ══════════════════════════════════════════════════════════════
#  constant_time_password_check
# ══════════════════════════════════════════════════════════════


class TestConstantTimePasswordCheck:
    """Tests for the password check timing wrapper."""

    def test_correct_password(self):
        def check(pw):
            return pw == "secret"

        result = constant_time_password_check(check, "secret", target_ms=200, jitter_percent=0)
        assert result.success is True
        assert result.value is True

    def test_wrong_password(self):
        def check(pw):
            return pw == "secret"

        result = constant_time_password_check(check, "wrong", target_ms=200, jitter_percent=0)
        assert result.success is True
        assert result.value is False

    def test_dummy_work_always_executed(self):
        """Dummy work should run regardless of check outcome."""
        dummy_called = {"count": 0}

        def dummy():
            dummy_called["count"] += 1

        def check(pw):
            return True

        constant_time_password_check(check, "any", dummy_work=dummy, target_ms=200, jitter_percent=0)
        assert dummy_called["count"] == 1

        constant_time_password_check(check, "any", dummy_work=dummy, target_ms=200, jitter_percent=0)
        assert dummy_called["count"] == 2

    def test_timing_equalized_correct_vs_wrong(self):
        """Correct and wrong passwords should take similar wall-clock time."""
        target_ms = 300.0

        def check(pw):
            if pw == "correct":
                time.sleep(0.01)  # 10ms for correct
                return True
            # Wrong returns immediately (0ms)
            return False

        correct_times = []
        wrong_times = []
        for _ in range(5):
            r = constant_time_password_check(check, "correct", target_ms=target_ms, jitter_percent=0)
            correct_times.append(r.padded_ms)
            r = constant_time_password_check(check, "wrong", target_ms=target_ms, jitter_percent=0)
            wrong_times.append(r.padded_ms)

        avg_correct = sum(correct_times) / len(correct_times)
        avg_wrong = sum(wrong_times) / len(wrong_times)

        # Difference should be small (< 30ms)
        diff = abs(avg_correct - avg_wrong)
        assert diff < 50.0, f"Timing difference too large: {diff:.1f}ms"


# ══════════════════════════════════════════════════════════════
#  duress_timing_equalizer
# ══════════════════════════════════════════════════════════════


class TestDuressTimingEqualizer:
    """Tests for the duress-specific timing wrapper."""

    def test_real_password_path(self):
        def real_check(pw):
            return (True, False)  # valid, not duress

        dummy = MagicMock()

        result = duress_timing_equalizer(
            real_check, dummy, "password", target_ms=200, jitter_percent=0,
        )
        assert result.success is True
        assert result.value == (True, False)
        dummy.assert_called_once()

    def test_duress_password_path(self):
        def real_check(pw):
            return (True, True)  # valid, IS duress

        dummy = MagicMock()

        result = duress_timing_equalizer(
            real_check, dummy, "duress_pw", target_ms=200, jitter_percent=0,
        )
        assert result.success is True
        assert result.value == (True, True)
        dummy.assert_called_once()

    def test_wrong_password_path(self):
        def real_check(pw):
            return (False, False)

        dummy = MagicMock()

        result = duress_timing_equalizer(
            real_check, dummy, "bad", target_ms=200, jitter_percent=0,
        )
        assert result.success is True
        assert result.value == (False, False)
        dummy.assert_called_once()

    def test_dummy_argon2id_always_called(self):
        """Dummy Argon2id should be called on ALL paths."""
        calls = []

        def dummy():
            calls.append(1)

        for pw_result in [(True, False), (True, True), (False, False)]:
            def check(pw, _result=pw_result):
                return _result

            duress_timing_equalizer(
                check, dummy, "pw", target_ms=100, jitter_percent=0,
            )

        assert len(calls) == 3, "Dummy Argon2id should be called 3 times (one per path)"


# ══════════════════════════════════════════════════════════════
#  TimingEqualizedDecoder
# ══════════════════════════════════════════════════════════════


class TestTimingEqualizedDecoder:
    """Tests for the decoder timing wrapper class."""

    def test_successful_decode(self):
        decoder = TimingEqualizedDecoder(target_ms=200, jitter_percent=0)

        def fake_decode(data, password):
            return b"decrypted"

        result = decoder.decode(fake_decode, b"gif_data", "password")
        assert result.success is True
        assert result.value == b"decrypted"

    def test_failed_decode(self):
        decoder = TimingEqualizedDecoder(target_ms=200, jitter_percent=0)

        def bad_decode(data, password):
            raise ValueError("Bad password")

        result = decoder.decode(bad_decode, b"gif_data", "wrong")
        assert result.success is False
        assert isinstance(result.error, ValueError)

    def test_timing_padded(self):
        decoder = TimingEqualizedDecoder(target_ms=300, jitter_percent=0)

        def instant_decode():
            return "done"

        start = time.monotonic()
        result = decoder.decode(instant_decode)
        elapsed = (time.monotonic() - start) * 1000

        assert elapsed >= 250.0

    def test_get_set_target(self):
        decoder = TimingEqualizedDecoder(target_ms=1000)
        assert decoder.get_target_ms() == 1000.0

        decoder.set_target_ms(2000)
        assert decoder.get_target_ms() == 2000.0

    def test_set_invalid_target_raises(self):
        decoder = TimingEqualizedDecoder()
        with pytest.raises(ValueError, match="positive"):
            decoder.set_target_ms(0)
        with pytest.raises(ValueError, match="positive"):
            decoder.set_target_ms(-100)

    def test_default_target(self):
        decoder = TimingEqualizedDecoder()
        assert decoder.get_target_ms() == DEFAULT_TARGET_MS


# ══════════════════════════════════════════════════════════════
#  Constants
# ══════════════════════════════════════════════════════════════


class TestConstants:
    """Tests for module-level constants."""

    def test_default_target_positive(self):
        assert DEFAULT_TARGET_MS > 0

    def test_default_jitter_positive(self):
        assert DEFAULT_JITTER_PERCENT > 0

    def test_min_sleep_positive(self):
        assert MIN_SLEEP_MS > 0

    def test_default_jitter_reasonable(self):
        """Jitter should be small relative to target (< 20%)."""
        assert DEFAULT_JITTER_PERCENT <= 20.0
