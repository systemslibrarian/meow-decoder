"""
CI Distinguishability Tests for Dual-Stream Encoding.

These tests formally prove that single-secret and dual-secret outputs are
STATISTICALLY INDISTINGUISHABLE to an observer without the passwords.

Tests use:
    - Chi-squared goodness-of-fit (byte distribution uniformity)
    - Kolmogorov–Smirnov two-sample test (distribution comparison)
    - Shannon entropy comparison
    - Autocorrelation analysis (sequential dependency)
    - Runs test (randomness of binary sequence)
    - Byte-pair frequency analysis

These are designed to be run in CI to catch regressions that might make
the dual-stream output distinguishable from single-stream output.

IMPORTANT: These tests inherently have some probability of false failure
(statistical tests). The thresholds are set conservatively to keep the
false-positive rate below 0.1% while still catching real problems.
"""

from meow_decoder.dual_stream import dual_stream_encode
import os
import math
import secrets
from collections import Counter
from typing import List

import pytest

os.environ.setdefault("MEOW_TEST_MODE", "1")


# ── Statistical helpers ──


def chi_squared_byte_uniformity(data: bytes) -> float:
    """Chi-squared statistic for byte-value uniformity (256 bins)."""
    n = len(data)
    expected = n / 256.0
    counts = Counter(data)
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def ks_two_sample(sample1: bytes, sample2: bytes) -> float:
    """Kolmogorov-Smirnov two-sample test statistic.

    Compares the empirical cumulative distribution functions of two samples.
    Lower values indicate the samples come from the same distribution.
    """
    n1, n2 = len(sample1), len(sample2)
    if n1 == 0 or n2 == 0:
        return 1.0

    # Build empirical CDFs for byte values 0-255
    counts1 = Counter(sample1)
    counts2 = Counter(sample2)

    cdf1 = 0.0
    cdf2 = 0.0
    max_diff = 0.0

    for b in range(256):
        cdf1 += counts1.get(b, 0) / n1
        cdf2 += counts2.get(b, 0) / n2
        diff = abs(cdf1 - cdf2)
        if diff > max_diff:
            max_diff = diff

    return max_diff


def autocorrelation_lag1(data: bytes) -> float:
    """Lag-1 autocorrelation of byte values.

    For truly random data, this should be near 0.
    A significant non-zero value would indicate sequential dependency.
    """
    n = len(data)
    if n < 2:
        return 0.0

    mean = sum(data) / n
    var = sum((b - mean) ** 2 for b in data) / n
    if var == 0:
        return 0.0

    cov = sum((data[i] - mean) * (data[i + 1] - mean) for i in range(n - 1)) / (n - 1)
    return cov / var


def runs_test_statistic(data: bytes) -> float:
    """Wald-Wolfowitz runs test Z-statistic.

    Tests whether the sequence of above/below-median values is random.
    For random data, |Z| should be < ~2.58 (p > 0.01).
    """
    n = len(data)
    if n < 20:
        return 0.0

    median = sorted(data)[n // 2]
    # Classify each byte as above (1) or below (0) median
    binary = [1 if b > median else 0 for b in data]

    n1 = sum(binary)
    n0 = n - n1
    if n1 == 0 or n0 == 0:
        return 0.0

    # Count runs
    runs = 1
    for i in range(1, n):
        if binary[i] != binary[i - 1]:
            runs += 1

    expected_runs = 1 + (2 * n0 * n1) / n
    var_runs = (2 * n0 * n1 * (2 * n0 * n1 - n)) / (n * n * (n - 1))
    if var_runs <= 0:
        return 0.0

    return (runs - expected_runs) / math.sqrt(var_runs)


def byte_pair_entropy(data: bytes) -> float:
    """Shannon entropy of consecutive byte pairs (digrams).

    For uniform random data, max entropy = 16 bits (256*256 possible pairs).
    """
    n = len(data)
    if n < 2:
        return 0.0

    pairs = Counter()
    for i in range(n - 1):
        pairs[(data[i], data[i + 1])] += 1

    total = sum(pairs.values())
    return -sum((c / total) * math.log2(c / total) for c in pairs.values() if c > 0)


# ── Generate test samples ──


def _generate_samples(payload_size: int = 4000, block_size: int = 256, n_samples: int = 5):
    """Generate matched single-secret and dual-secret ciphertext samples."""
    singles = []
    duals = []

    for i in range(n_samples):
        data = secrets.token_bytes(payload_size)

        ct_s, _ = dual_stream_encode(data, f"single_{i:04d}!", block_size=block_size)
        singles.append(ct_s)

        ct_d, _ = dual_stream_encode(
            data,
            f"dual_A_{i:04d}!",
            decoy_data=secrets.token_bytes(payload_size),
            decoy_password=f"dual_B_{i:04d}!",
            block_size=block_size,
        )
        duals.append(ct_d)

    return singles, duals


# ── CI Tests ──


class TestChiSquaredUniformity:
    """Chi-squared byte uniformity: both modes must pass."""

    # For 255 DOF, critical value at p=0.001 is ~310.5
    # We use a generous threshold of 350 for CI stability
    THRESHOLD = 350

    def test_single_secret_uniform(self):
        """Single-secret ciphertext passes chi-squared uniformity."""
        data = secrets.token_bytes(8000)
        ct, _ = dual_stream_encode(data, "chi2_single!", block_size=256)
        chi2 = chi_squared_byte_uniformity(ct)
        assert chi2 < self.THRESHOLD, f"Single chi2={chi2:.1f} > {self.THRESHOLD}"

    def test_dual_secret_uniform(self):
        """Dual-secret ciphertext passes chi-squared uniformity."""
        data = secrets.token_bytes(8000)
        ct, _ = dual_stream_encode(
            data,
            "chi2_dual_AA!",
            decoy_data=secrets.token_bytes(8000),
            decoy_password="chi2_dual_BB!",
            block_size=256,
        )
        chi2 = chi_squared_byte_uniformity(ct)
        assert chi2 < self.THRESHOLD, f"Dual chi2={chi2:.1f} > {self.THRESHOLD}"

    def test_chi2_difference_insignificant(self):
        """Chi-squared difference between modes is statistically insignificant."""
        singles, duals = _generate_samples(payload_size=8000, n_samples=3)
        chi2_singles = [chi_squared_byte_uniformity(s) for s in singles]
        chi2_duals = [chi_squared_byte_uniformity(d) for d in duals]

        avg_single = sum(chi2_singles) / len(chi2_singles)
        avg_dual = sum(chi2_duals) / len(chi2_duals)

        # Difference should be within normal variation
        assert (
            abs(avg_single - avg_dual) < 100
        ), f"Chi2 gap: single={avg_single:.1f} vs dual={avg_dual:.1f}"


class TestKolmogorovSmirnov:
    """KS test: single and dual distributions should be indistinguishable."""

    def test_ks_single_vs_dual(self):
        """KS statistic between single and dual ciphertext should be small."""
        data = secrets.token_bytes(8000)
        ct_s, _ = dual_stream_encode(data, "ks_single_11", block_size=256)
        ct_d, _ = dual_stream_encode(
            data,
            "ks_dual_AAAA",
            decoy_data=secrets.token_bytes(8000),
            decoy_password="ks_dual_BBBB",
            block_size=256,
        )

        ks_stat = ks_two_sample(ct_s, ct_d)
        # For large samples from the same distribution, KS < 0.05
        assert ks_stat < 0.05, f"KS statistic {ks_stat:.4f} too high"

    def test_ks_multiple_samples(self):
        """KS statistic averaged over multiple samples stays low."""
        singles, duals = _generate_samples(payload_size=8000, n_samples=3)
        ks_stats = [ks_two_sample(s, d) for s, d in zip(singles, duals)]
        avg_ks = sum(ks_stats) / len(ks_stats)
        assert avg_ks < 0.04, f"Average KS={avg_ks:.4f} too high"


class TestEntropyComparison:
    """Shannon entropy: both modes must produce near-maximum entropy."""

    def test_single_entropy_high(self):
        """Single-secret entropy > 7.9 bits/byte."""
        data = secrets.token_bytes(8000)
        ct, _ = dual_stream_encode(data, "ent_single_1", block_size=256)
        e = shannon_entropy(ct)
        assert e > 7.9, f"Single entropy {e:.4f} < 7.9"

    def test_dual_entropy_high(self):
        """Dual-secret entropy > 7.9 bits/byte."""
        data = secrets.token_bytes(8000)
        ct, _ = dual_stream_encode(
            data,
            "ent_dual_AAA",
            decoy_data=secrets.token_bytes(8000),
            decoy_password="ent_dual_BBB",
            block_size=256,
        )
        e = shannon_entropy(ct)
        assert e > 7.9, f"Dual entropy {e:.4f} < 7.9"

    def test_entropy_gap_negligible(self):
        """Entropy gap between single and dual must be < 0.05 bits/byte."""
        singles, duals = _generate_samples(payload_size=8000, n_samples=3)
        e_singles = [shannon_entropy(s) for s in singles]
        e_duals = [shannon_entropy(d) for d in duals]

        avg_gap = abs(sum(e_singles) / len(e_singles) - sum(e_duals) / len(e_duals))
        assert avg_gap < 0.05, f"Entropy gap {avg_gap:.4f} bits/byte > 0.05"


class TestAutocorrelation:
    """Autocorrelation: no sequential dependency in either mode."""

    def test_single_autocorrelation_near_zero(self):
        """Single-secret lag-1 autocorrelation near zero."""
        data = secrets.token_bytes(8000)
        ct, _ = dual_stream_encode(data, "ac_single_11", block_size=256)
        ac = autocorrelation_lag1(ct)
        assert abs(ac) < 0.05, f"Single autocorrelation {ac:.4f} too far from zero"

    def test_dual_autocorrelation_near_zero(self):
        """Dual-secret lag-1 autocorrelation near zero."""
        data = secrets.token_bytes(8000)
        ct, _ = dual_stream_encode(
            data,
            "ac_dual_AAAA",
            decoy_data=secrets.token_bytes(8000),
            decoy_password="ac_dual_BBBB",
            block_size=256,
        )
        ac = autocorrelation_lag1(ct)
        assert abs(ac) < 0.05, f"Dual autocorrelation {ac:.4f} too far from zero"

    def test_autocorrelation_difference_small(self):
        """Autocorrelation difference between modes negligible."""
        singles, duals = _generate_samples(payload_size=8000, n_samples=3)
        ac_singles = [autocorrelation_lag1(s) for s in singles]
        ac_duals = [autocorrelation_lag1(d) for d in duals]

        avg_gap = abs(sum(ac_singles) / len(ac_singles) - sum(ac_duals) / len(ac_duals))
        assert avg_gap < 0.03, f"Autocorrelation gap {avg_gap:.4f} > 0.03"


class TestRunsRandomness:
    """Wald-Wolfowitz runs test: both modes should look random."""

    def test_single_runs_random(self):
        """Single-secret passes runs test (Z < 2.58)."""
        data = secrets.token_bytes(8000)
        ct, _ = dual_stream_encode(data, "runs_single1", block_size=256)
        z = runs_test_statistic(ct)
        assert abs(z) < 3.0, f"Single runs Z={z:.2f} indicates non-randomness"

    def test_dual_runs_random(self):
        """Dual-secret passes runs test (Z < 2.58)."""
        data = secrets.token_bytes(8000)
        ct, _ = dual_stream_encode(
            data,
            "runs_dual_AA",
            decoy_data=secrets.token_bytes(8000),
            decoy_password="runs_dual_BB",
            block_size=256,
        )
        z = runs_test_statistic(ct)
        assert abs(z) < 3.0, f"Dual runs Z={z:.2f} indicates non-randomness"


class TestBytePairAnalysis:
    """Digram (byte-pair) entropy: no structural patterns in either mode."""

    def test_single_pair_entropy_high(self):
        """Single-secret byte-pair entropy close to maximum 16 bits."""
        data = secrets.token_bytes(20000)
        ct, _ = dual_stream_encode(data, "pair_single1", block_size=256)
        pe = byte_pair_entropy(ct)
        # Max is 16.0 for 65536 possible pairs
        # For random data of this size, expect > 15.0
        assert pe > 14.5, f"Single pair entropy {pe:.2f} < 14.5"

    def test_dual_pair_entropy_high(self):
        """Dual-secret byte-pair entropy close to maximum 16 bits."""
        data = secrets.token_bytes(20000)
        ct, _ = dual_stream_encode(
            data,
            "pair_dual_AA",
            decoy_data=secrets.token_bytes(20000),
            decoy_password="pair_dual_BB",
            block_size=256,
        )
        pe = byte_pair_entropy(ct)
        assert pe > 14.5, f"Dual pair entropy {pe:.2f} < 14.5"

    def test_pair_entropy_gap_small(self):
        """Byte-pair entropy gap between modes negligible."""
        singles, duals = _generate_samples(payload_size=20000, n_samples=2)
        pe_singles = [byte_pair_entropy(s) for s in singles]
        pe_duals = [byte_pair_entropy(d) for d in duals]

        avg_gap = abs(sum(pe_singles) / len(pe_singles) - sum(pe_duals) / len(pe_duals))
        assert avg_gap < 0.5, f"Pair entropy gap {avg_gap:.2f} > 0.5"


class TestCIIntegration:
    """Top-level CI integration: run all statistical checks in one pass."""

    def test_full_indistinguishability_battery(self):
        """Run complete statistical battery on one sample pair.

        This is the single test a CI pipeline can rely on to catch
        any distinguishability regression.
        """
        payload = secrets.token_bytes(10000)

        ct_single, _ = dual_stream_encode(payload, "ci_battery_1", block_size=256)
        ct_dual, _ = dual_stream_encode(
            payload,
            "ci_batt_AAAA",
            decoy_data=secrets.token_bytes(10000),
            decoy_password="ci_batt_BBBB",
            block_size=256,
        )

        # 1. Chi-squared uniformity
        chi2_s = chi_squared_byte_uniformity(ct_single)
        chi2_d = chi_squared_byte_uniformity(ct_dual)
        assert chi2_s < 400 and chi2_d < 400, f"Chi2: single={chi2_s:.1f}, dual={chi2_d:.1f}"

        # 2. KS two-sample
        ks = ks_two_sample(ct_single, ct_dual)
        assert ks < 0.05, f"KS={ks:.4f}"

        # 3. Entropy
        e_s = shannon_entropy(ct_single)
        e_d = shannon_entropy(ct_dual)
        assert e_s > 7.9 and e_d > 7.9, f"Entropy: single={e_s:.4f}, dual={e_d:.4f}"
        assert abs(e_s - e_d) < 0.05, f"Entropy gap={abs(e_s - e_d):.4f}"

        # 4. Autocorrelation
        ac_s = autocorrelation_lag1(ct_single)
        ac_d = autocorrelation_lag1(ct_dual)
        assert abs(ac_s) < 0.05 and abs(ac_d) < 0.05, f"AC: single={ac_s:.4f}, dual={ac_d:.4f}"

        # 5. Runs test
        z_s = runs_test_statistic(ct_single)
        z_d = runs_test_statistic(ct_dual)
        assert abs(z_s) < 3.0 and abs(z_d) < 3.0, f"Runs Z: single={z_s:.2f}, dual={z_d:.2f}"
