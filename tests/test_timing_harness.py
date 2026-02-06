#!/usr/bin/env python3
"""
⏱️  Timing Attack Test Harness (MT-5)

Statistical timing comparison for:
  1. Correct vs wrong password   → should be indistinguishable
  2. Duress vs real password     → should be indistinguishable

Uses Welch's t-test with configurable significance level.
Skips on CI runners that are too noisy (coefficient of variation > threshold).

Run:   MEOW_TEST_MODE=1 pytest tests/test_timing_harness.py -v
Skip:  pytest -m "not slow" (these are inherently slow)
"""

import os
import time
import statistics
import math

import pytest

pytestmark = [pytest.mark.security, pytest.mark.slow]

os.environ.setdefault("MEOW_TEST_MODE", "1")

# ── Configuration ─────────────────────────────────────────────────────────────
SAMPLES = 15            # Number of timing samples per category
CV_SKIP_THRESHOLD = 0.6 # Skip if coefficient of variation > 60% (noisy runner)
# Welch's t-test p-value threshold (two-tailed). If p < this → FAIL (timing leak)
# Using 0.01 (1%) to avoid false positives on noisy CI.
ALPHA = 0.01


# ── Helpers ───────────────────────────────────────────────────────────────────

def _welch_t_statistic(a: list[float], b: list[float]) -> tuple[float, float]:
    """Compute Welch's t-statistic and approximate degrees of freedom.

    Returns (t, df).  Caller can compare |t| to critical value.
    """
    n_a, n_b = len(a), len(b)
    mean_a, mean_b = statistics.mean(a), statistics.mean(b)
    var_a = statistics.variance(a) if n_a > 1 else 0.0
    var_b = statistics.variance(b) if n_b > 1 else 0.0

    se = math.sqrt(var_a / n_a + var_b / n_b) if (var_a + var_b) > 0 else 1e-12
    t = (mean_a - mean_b) / se

    # Welch-Satterthwaite degrees of freedom
    num = (var_a / n_a + var_b / n_b) ** 2
    denom = 0.0
    if n_a > 1 and var_a > 0:
        denom += (var_a / n_a) ** 2 / (n_a - 1)
    if n_b > 1 and var_b > 0:
        denom += (var_b / n_b) ** 2 / (n_b - 1)
    df = num / denom if denom > 0 else max(n_a, n_b) - 1

    return t, df


def _t_critical(df: float, alpha: float = 0.01) -> float:
    """Approximate two-tailed t critical value (good enough for security test).

    Uses the approximation: t ≈ z + (z³ + z) / (4·df)  for df > 2.
    For very small df we use a conservative lookup.
    """
    # z for common alpha values
    z_map = {0.01: 2.576, 0.02: 2.326, 0.05: 1.96, 0.10: 1.645}
    z = z_map.get(alpha, 2.576)

    if df < 3:
        return 12.71  # very conservative (df=1 level)
    return z + (z ** 3 + z) / (4 * df)


def _coefficient_of_variation(samples: list[float]) -> float:
    """CV = stdev / mean.  High CV → noisy measurements."""
    m = statistics.mean(samples)
    if m == 0:
        return float("inf")
    return statistics.stdev(samples) / abs(m)


def _skip_if_noisy(*sample_sets: list[float]):
    """Skip the test if any sample set is too noisy for meaningful comparison."""
    for samples in sample_sets:
        cv = _coefficient_of_variation(samples)
        if cv > CV_SKIP_THRESHOLD:
            pytest.skip(
                f"Runner too noisy for timing test (CV={cv:.2f} > {CV_SKIP_THRESHOLD}). "
                "Re-run on dedicated hardware."
            )


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestPasswordTimingIndistinguishability:
    """Correct vs wrong password timing should be statistically indistinguishable."""

    def test_encrypt_decrypt_timing(self):
        """Timing of decrypt with correct vs wrong password must not leak which is correct."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw

        plaintext = os.urandom(256)
        password = "correct-password-timing-test"
        ct = encrypt_file_bytes(plaintext, password)

        # Warm up
        for _ in range(2):
            try:
                decrypt_to_raw(ct, password)
            except Exception:
                pass
            try:
                decrypt_to_raw(ct, "wrong-password-timing-test")
            except Exception:
                pass

        correct_times: list[float] = []
        wrong_times: list[float] = []

        for _ in range(SAMPLES):
            # Correct password
            t0 = time.perf_counter_ns()
            try:
                decrypt_to_raw(ct, password)
            except Exception:
                pass
            correct_times.append(time.perf_counter_ns() - t0)

            # Wrong password
            t0 = time.perf_counter_ns()
            try:
                decrypt_to_raw(ct, "wrong-password-timing-test")
            except Exception:
                pass
            wrong_times.append(time.perf_counter_ns() - t0)

        _skip_if_noisy(correct_times, wrong_times)

        t, df = _welch_t_statistic(correct_times, wrong_times)
        t_crit = _t_critical(df, ALPHA)

        mean_c = statistics.mean(correct_times) / 1e6  # ms
        mean_w = statistics.mean(wrong_times) / 1e6

        print(f"\n  Correct mean: {mean_c:.2f} ms")
        print(f"  Wrong   mean: {mean_w:.2f} ms")
        print(f"  Welch t={t:.3f}, df={df:.1f}, critical={t_crit:.3f} (α={ALPHA})")

        assert abs(t) < t_crit, (
            f"Timing leak detected! |t|={abs(t):.3f} > {t_crit:.3f} "
            f"(correct={mean_c:.2f}ms, wrong={mean_w:.2f}ms). "
            f"Password verification may not be constant-time."
        )


class TestDuressTimingIndistinguishability:
    """Duress password vs real password timing should be statistically indistinguishable."""

    def test_duress_vs_real_password_timing(self):
        """Duress and real password derivation should take the same time."""
        from meow_decoder.crypto import derive_key

        salt = os.urandom(16)
        real_password = "real-password-for-timing"
        duress_password = "duress-password-for-timing"

        # Warm up
        for _ in range(2):
            derive_key(real_password, salt)
            derive_key(duress_password, salt)

        real_times: list[float] = []
        duress_times: list[float] = []

        for _ in range(SAMPLES):
            t0 = time.perf_counter_ns()
            derive_key(real_password, salt)
            real_times.append(time.perf_counter_ns() - t0)

            t0 = time.perf_counter_ns()
            derive_key(duress_password, salt)
            duress_times.append(time.perf_counter_ns() - t0)

        _skip_if_noisy(real_times, duress_times)

        t, df = _welch_t_statistic(real_times, duress_times)
        t_crit = _t_critical(df, ALPHA)

        mean_r = statistics.mean(real_times) / 1e6
        mean_d = statistics.mean(duress_times) / 1e6

        print(f"\n  Real   mean: {mean_r:.2f} ms")
        print(f"  Duress mean: {mean_d:.2f} ms")
        print(f"  Welch t={t:.3f}, df={df:.1f}, critical={t_crit:.3f} (α={ALPHA})")

        assert abs(t) < t_crit, (
            f"Timing leak detected! |t|={abs(t):.3f} > {t_crit:.3f} "
            f"(real={mean_r:.2f}ms, duress={mean_d:.2f}ms). "
            f"Duress detection may leak via timing."
        )


class TestConstantTimeCompareHarness:
    """HMAC compare must be constant-time regardless of input length or match position."""

    def test_compare_first_byte_vs_last_byte_mismatch(self):
        """Mismatch at first byte vs last byte should take the same time."""
        import secrets

        correct = secrets.token_bytes(32)
        wrong_first = b"\xff" + correct[1:]   # first byte wrong
        wrong_last = correct[:-1] + b"\xff"   # last byte wrong

        first_times: list[float] = []
        last_times: list[float] = []

        for _ in range(SAMPLES * 5):
            t0 = time.perf_counter_ns()
            secrets.compare_digest(correct, wrong_first)
            first_times.append(time.perf_counter_ns() - t0)

            t0 = time.perf_counter_ns()
            secrets.compare_digest(correct, wrong_last)
            last_times.append(time.perf_counter_ns() - t0)

        _skip_if_noisy(first_times, last_times)

        t, df = _welch_t_statistic(first_times, last_times)
        t_crit = _t_critical(df, ALPHA)

        assert abs(t) < t_crit, (
            f"Constant-time comparison leak! |t|={abs(t):.3f} > {t_crit:.3f}. "
            f"First-byte mismatch takes different time than last-byte mismatch."
        )
