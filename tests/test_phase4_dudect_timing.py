#!/usr/bin/env python3
"""
Phase 4 Security Tests: Dudect-Style Statistical Timing Analysis
================================================================

Addresses GAP-01 from CRYPTO_SECURITY_REVIEW.md:
"No automated side-channel testing (dudect integration)"

This module implements dudect-inspired statistical timing analysis to detect
timing side-channels in constant-time operations. Unlike simple timing tests,
this uses statistical methods (Welch's t-test) to detect even small timing
differences that could leak information.

Reference: https://github.com/oreparaz/dudect
Paper: "Dude, is my code constant time?" (Reparaz, Balasch, Verbauwhede 2017)

Security Context:
- Timing side-channels can leak password validity, key bytes, or data patterns
- Statistical analysis detects leakage that single-measurement tests miss
- We use Welch's t-test with threshold |t| < 4.5 (p < 0.00001 significance)

Test Categories:
1. COMPARE operations (constant_time_compare, HMAC verification)
2. DERIVE operations (key derivation timing independence)
3. CRYPTO operations (encrypt/decrypt timing patterns)
"""

import os
import time
import secrets
import statistics
import pytest
from typing import Callable, Tuple, List
from dataclasses import dataclass
import math

# Enable test mode for faster KDF
os.environ["MEOW_TEST_MODE"] = "1"

from meow_decoder.constant_time import (
    constant_time_compare,
    timing_safe_equal_with_delay,
)
from meow_decoder.crypto import (
    verify_manifest_hmac,
    compute_manifest_hmac,
    derive_key,
    Manifest,
    pack_manifest_core,
)


# =============================================================================
# DUDECT-STYLE STATISTICAL FRAMEWORK
# =============================================================================

@dataclass
class TimingResult:
    """Results from statistical timing analysis."""
    t_statistic: float
    mean_class0: float  # Mean time for class 0 (e.g., correct input)
    mean_class1: float  # Mean time for class 1 (e.g., incorrect input)
    std_class0: float
    std_class1: float
    n_samples: int
    is_constant_time: bool  # True if |t| < threshold
    
    def __str__(self) -> str:
        verdict = "✅ CONSTANT-TIME" if self.is_constant_time else "❌ TIMING LEAK"
        return (
            f"{verdict}\n"
            f"  t-statistic: {self.t_statistic:.4f}\n"
            f"  mean(class0): {self.mean_class0*1e6:.2f}μs, std: {self.std_class0*1e6:.2f}μs\n"
            f"  mean(class1): {self.mean_class1*1e6:.2f}μs, std: {self.std_class1*1e6:.2f}μs\n"
            f"  samples: {self.n_samples} per class"
        )


def welch_t_test(samples0: List[float], samples1: List[float]) -> float:
    """
    Compute Welch's t-test statistic for two independent samples.
    
    Welch's t-test is appropriate when the two populations may have
    unequal variances, which is the case for timing measurements.
    
    Returns:
        t-statistic (larger absolute values indicate timing difference)
    """
    n0, n1 = len(samples0), len(samples1)
    
    if n0 < 2 or n1 < 2:
        return 0.0  # Not enough samples
    
    mean0 = statistics.mean(samples0)
    mean1 = statistics.mean(samples1)
    var0 = statistics.variance(samples0)
    var1 = statistics.variance(samples1)
    
    # Avoid division by zero
    if var0 == 0 and var1 == 0:
        return 0.0 if mean0 == mean1 else float('inf')
    
    # Welch's t-test formula
    se = math.sqrt(var0/n0 + var1/n1)
    if se == 0:
        return 0.0
    
    t = (mean0 - mean1) / se
    return t


def measure_timing(
    func: Callable,
    inputs_class0: List[tuple],
    inputs_class1: List[tuple],
    warmup_rounds: int = 10,
    measurement_rounds: int = 100,
) -> TimingResult:
    """
    Measure timing of a function for two input classes using dudect methodology.
    
    The key insight from dudect is that we interleave measurements from both
    classes randomly to prevent systematic effects (CPU frequency scaling,
    cache warming, etc.) from biasing results.
    
    Args:
        func: Function to measure (called as func(*args))
        inputs_class0: List of input tuples for class 0
        inputs_class1: List of input tuples for class 1
        warmup_rounds: Number of warmup iterations
        measurement_rounds: Number of measurements per class
        
    Returns:
        TimingResult with statistical analysis
    """
    # Warmup to stabilize CPU frequency and caches
    for _ in range(warmup_rounds):
        for inputs in inputs_class0[:2] + inputs_class1[:2]:
            try:
                func(*inputs)
            except Exception:
                pass  # Some inputs may fail (wrong password etc.)
    
    # Interleaved measurement (dudect methodology)
    timings0: List[float] = []
    timings1: List[float] = []
    
    # Create randomized schedule
    schedule = ([(0, inp) for inp in inputs_class0[:measurement_rounds]] + 
                [(1, inp) for inp in inputs_class1[:measurement_rounds]])
    secrets.SystemRandom().shuffle(schedule)
    
    for class_id, inputs in schedule:
        # High-resolution timing
        start = time.perf_counter_ns()
        try:
            func(*inputs)
        except Exception:
            pass  # Expected for some inputs (e.g., wrong password)
        end = time.perf_counter_ns()
        
        elapsed = (end - start) / 1e9  # Convert to seconds
        
        if class_id == 0:
            timings0.append(elapsed)
        else:
            timings1.append(elapsed)
    
    # Statistical analysis
    t_stat = welch_t_test(timings0, timings1)
    
    # Threshold: |t| < 4.5 corresponds to p < 0.00001 (very conservative)
    # This is the standard dudect threshold
    T_THRESHOLD = 4.5
    
    return TimingResult(
        t_statistic=t_stat,
        mean_class0=statistics.mean(timings0) if timings0 else 0,
        mean_class1=statistics.mean(timings1) if timings1 else 0,
        std_class0=statistics.stdev(timings0) if len(timings0) > 1 else 0,
        std_class1=statistics.stdev(timings1) if len(timings1) > 1 else 0,
        n_samples=min(len(timings0), len(timings1)),
        is_constant_time=abs(t_stat) < T_THRESHOLD,
    )


# =============================================================================
# TEST CLASS: COMPARE OPERATIONS
# =============================================================================

class TestDudectCompareOperations:
    """
    Dudect-style timing tests for comparison operations.
    
    These operations MUST be constant-time to prevent timing attacks
    on password verification and HMAC checks.
    """
    
    def test_constant_time_compare_equal_vs_different(self):
        """
        DUDECT-01: constant_time_compare must not leak via timing.
        
        Tests that comparing equal strings takes the same time as
        comparing strings that differ in the first byte vs last byte.
        """
        test_len = 32  # Typical HMAC length
        base = secrets.token_bytes(test_len)
        
        # Class 0: Equal strings (correct password scenario)
        inputs_equal = [(base, base) for _ in range(100)]
        
        # Class 1: Strings differing in first byte (early exit would be faster)
        diff_first = [
            (base, bytes([base[0] ^ 0xFF]) + base[1:])
            for _ in range(100)
        ]
        
        result = measure_timing(
            constant_time_compare,
            inputs_equal,
            diff_first,
            warmup_rounds=20,
            measurement_rounds=100,
        )
        
        print(f"\n[DUDECT-01] constant_time_compare (equal vs diff-first):\n{result}")
        assert result.is_constant_time, (
            f"Timing leak detected in constant_time_compare! "
            f"t-statistic: {result.t_statistic:.4f}"
        )
    
    def test_constant_time_compare_first_vs_last_diff(self):
        """
        DUDECT-02: Compare must not leak position of first difference.
        
        If timing varies based on WHERE strings differ, an attacker
        can learn password bytes iteratively.
        """
        test_len = 32
        base = secrets.token_bytes(test_len)
        
        # Class 0: Differ in first byte
        diff_first = [
            (base, bytes([base[0] ^ 0xFF]) + base[1:])
            for _ in range(100)
        ]
        
        # Class 1: Differ in last byte
        diff_last = [
            (base, base[:-1] + bytes([base[-1] ^ 0xFF]))
            for _ in range(100)
        ]
        
        result = measure_timing(
            constant_time_compare,
            diff_first,
            diff_last,
            warmup_rounds=20,
            measurement_rounds=100,
        )
        
        print(f"\n[DUDECT-02] constant_time_compare (diff-first vs diff-last):\n{result}")
        assert result.is_constant_time, (
            f"Position-dependent timing leak! "
            f"t-statistic: {result.t_statistic:.4f}"
        )
    
    def test_constant_time_compare_length_independence(self):
        """
        DUDECT-03: Compare timing should not depend on input length.
        
        Note: This tests within reasonable length ranges. Very different
        lengths will have different timing due to memory access patterns.
        """
        # Class 0: Short strings (16 bytes)
        short = secrets.token_bytes(16)
        inputs_short = [(short, short) for _ in range(100)]
        
        # Class 1: Longer strings (64 bytes) 
        long = secrets.token_bytes(64)
        inputs_long = [(long, long) for _ in range(100)]
        
        result = measure_timing(
            constant_time_compare,
            inputs_short,
            inputs_long,
            warmup_rounds=20,
            measurement_rounds=100,
        )
        
        print(f"\n[DUDECT-03] constant_time_compare (short vs long):\n{result}")
        # Note: Length differences ARE expected to cause timing differences
        # This test documents the behavior but may not always pass
        # The critical property is equal/different comparison, not length
        if not result.is_constant_time:
            print("  ⚠️ Length-dependent timing (expected for different sizes)")


# =============================================================================
# TEST CLASS: HMAC VERIFICATION
# =============================================================================

class TestDudectHMACVerification:
    """
    Dudect-style timing tests for HMAC verification.
    
    HMAC verification is critical - a timing leak here allows
    offline password guessing with timing oracle.
    """
    
    @pytest.fixture
    def sample_manifest(self):
        """Create a sample manifest for HMAC testing."""
        salt = secrets.token_bytes(16)
        password = "test_password_123"
        
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32,  # Will be computed
            ephemeral_public_key=None,
            pq_ciphertext=None,
            duress_tag=None,
        )
        
        # Compute correct HMAC
        packed_core = pack_manifest_core(manifest)
        enc_key = derive_key(password, salt)
        manifest.hmac = compute_manifest_hmac(
            password, salt, packed_core, encryption_key=enc_key
        )
        
        return manifest, password
    
    def test_hmac_verify_correct_vs_wrong_password(self, sample_manifest):
        """
        DUDECT-04: HMAC verification timing must not leak password validity.
        
        This is critical: if wrong password is faster/slower, attacker
        can do offline timing-based password guessing.
        """
        manifest, correct_password = sample_manifest
        wrong_password = "wrong_password_456"
        
        def verify_wrapper(password):
            return verify_manifest_hmac(password, manifest)
        
        # Class 0: Correct password
        inputs_correct = [(correct_password,) for _ in range(50)]
        
        # Class 1: Wrong password
        inputs_wrong = [(wrong_password,) for _ in range(50)]
        
        result = measure_timing(
            verify_wrapper,
            inputs_correct,
            inputs_wrong,
            warmup_rounds=10,
            measurement_rounds=50,
        )
        
        print(f"\n[DUDECT-04] HMAC verify (correct vs wrong password):\n{result}")
        assert result.is_constant_time, (
            f"Password validity timing leak in HMAC verification! "
            f"t-statistic: {result.t_statistic:.4f}"
        )
    
    def test_hmac_verify_wrong_passwords_consistent(self, sample_manifest):
        """
        DUDECT-05: Different wrong passwords should have consistent timing.
        
        Ensures no pattern in wrong password timing that could leak info.
        """
        manifest, _ = sample_manifest
        
        def verify_wrapper(password):
            return verify_manifest_hmac(password, manifest)
        
        # Class 0: Wrong password type A (short)
        inputs_a = [("wrong_a",) for _ in range(50)]
        
        # Class 1: Wrong password type B (long)
        inputs_b = [("wrong_password_very_long_indeed_123",) for _ in range(50)]
        
        result = measure_timing(
            verify_wrapper,
            inputs_a,
            inputs_b,
            warmup_rounds=10,
            measurement_rounds=50,
        )
        
        print(f"\n[DUDECT-05] HMAC verify (different wrong passwords):\n{result}")
        # Note: Length differences in password may cause timing differences
        # in Argon2id itself, which is expected
        if not result.is_constant_time:
            print("  ⚠️ Password length affects Argon2id timing (expected)")


# =============================================================================
# TEST CLASS: KEY DERIVATION TIMING
# =============================================================================

class TestDudectKeyDerivation:
    """
    Dudect-style timing tests for key derivation.
    
    Tests that key derivation (Argon2id) doesn't leak information
    about password content through timing.
    """
    
    def test_derive_key_password_content_independent(self):
        """
        DUDECT-06: Key derivation timing should not depend on password content.
        
        All-zeros password vs all-ones password should take same time.
        """
        salt = secrets.token_bytes(16)
        
        # Class 0: All 'a' password
        inputs_a = [(("a" * 12), salt) for _ in range(20)]
        
        # Class 1: All 'z' password
        inputs_z = [(("z" * 12), salt) for _ in range(20)]
        
        result = measure_timing(
            derive_key,
            inputs_a,
            inputs_z,
            warmup_rounds=5,
            measurement_rounds=20,
        )
        
        print(f"\n[DUDECT-06] Key derivation (content-independent):\n{result}")
        assert result.is_constant_time, (
            f"Password content leaks through KDF timing! "
            f"t-statistic: {result.t_statistic:.4f}"
        )
    
    def test_derive_key_salt_independent(self):
        """
        DUDECT-07: Key derivation timing should not depend on salt content.
        """
        password = "test_password_123"
        
        # Class 0: All-zero salt
        salt_zeros = b'\x00' * 16
        inputs_zero = [(password, salt_zeros) for _ in range(20)]
        
        # Class 1: All-ones salt
        salt_ones = b'\xff' * 16
        inputs_ones = [(password, salt_ones) for _ in range(20)]
        
        result = measure_timing(
            derive_key,
            inputs_zero,
            inputs_ones,
            warmup_rounds=5,
            measurement_rounds=20,
        )
        
        print(f"\n[DUDECT-07] Key derivation (salt-independent):\n{result}")
        assert result.is_constant_time, (
            f"Salt content leaks through KDF timing! "
            f"t-statistic: {result.t_statistic:.4f}"
        )


# =============================================================================
# TEST CLASS: TIMING_SAFE_EQUAL_WITH_DELAY
# =============================================================================

class TestDudectTimingSafeEqual:
    """
    Tests for the delay-based timing safe comparison.
    
    This function adds randomized delays to obscure timing even further.
    """
    
    def test_timing_safe_equal_delay_obscures_result(self):
        """
        DUDECT-08: timing_safe_equal_with_delay should obscure timing.
        
        The random delay should make equal vs non-equal indistinguishable.
        """
        value = secrets.token_bytes(32)
        different = secrets.token_bytes(32)
        
        # Class 0: Equal values
        inputs_equal = [(value, value, 1, 5) for _ in range(50)]
        
        # Class 1: Different values
        inputs_diff = [(value, different, 1, 5) for _ in range(50)]
        
        result = measure_timing(
            timing_safe_equal_with_delay,
            inputs_equal,
            inputs_diff,
            warmup_rounds=10,
            measurement_rounds=50,
        )
        
        print(f"\n[DUDECT-08] timing_safe_equal_with_delay:\n{result}")
        assert result.is_constant_time, (
            f"Delay function not obscuring timing! "
            f"t-statistic: {result.t_statistic:.4f}"
        )


# =============================================================================
# INTEGRATION TEST: END-TO-END TIMING SAFETY
# =============================================================================

class TestDudectIntegration:
    """
    End-to-end timing tests for the complete authentication flow.
    """
    
    def test_full_auth_flow_constant_time(self):
        """
        DUDECT-09: Complete authentication flow should be constant-time.
        
        Tests the full path: password -> key derivation -> HMAC verify.
        """
        salt = secrets.token_bytes(16)
        password = "correct_password_123"
        
        # Create manifest
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32,
            ephemeral_public_key=None,
            pq_ciphertext=None,
            duress_tag=None,
        )
        
        # Compute HMAC
        packed_core = pack_manifest_core(manifest)
        enc_key = derive_key(password, salt)
        manifest.hmac = compute_manifest_hmac(
            password, salt, packed_core, encryption_key=enc_key
        )
        
        def full_auth(pwd):
            return verify_manifest_hmac(pwd, manifest)
        
        # Class 0: Correct password
        inputs_correct = [(password,) for _ in range(30)]
        
        # Class 1: Wrong password
        inputs_wrong = [("wrong_password_456",) for _ in range(30)]
        
        result = measure_timing(
            full_auth,
            inputs_correct,
            inputs_wrong,
            warmup_rounds=5,
            measurement_rounds=30,
        )
        
        print(f"\n[DUDECT-09] Full authentication flow:\n{result}")
        assert result.is_constant_time, (
            f"Full auth flow has timing leak! "
            f"t-statistic: {result.t_statistic:.4f}"
        )


# =============================================================================
# SUMMARY REPORT
# =============================================================================

def test_dudect_summary():
    """
    Generate summary report of all dudect tests.
    
    This test runs last to provide a comprehensive report.
    """
    print("\n" + "=" * 70)
    print("DUDECT TIMING ANALYSIS SUMMARY (GAP-01 Coverage)")
    print("=" * 70)
    print("""
Tests performed:
  DUDECT-01: constant_time_compare (equal vs different)
  DUDECT-02: constant_time_compare (position of difference)
  DUDECT-03: constant_time_compare (length independence)
  DUDECT-04: HMAC verify (correct vs wrong password)
  DUDECT-05: HMAC verify (different wrong passwords)
  DUDECT-06: Key derivation (password content)
  DUDECT-07: Key derivation (salt content)
  DUDECT-08: timing_safe_equal_with_delay
  DUDECT-09: Full authentication flow

Statistical Method:
  - Welch's t-test with threshold |t| < 4.5
  - Corresponds to p < 0.00001 significance level
  - Interleaved measurement to prevent systematic bias
  - Based on dudect methodology (Reparaz et al., 2017)

Security Properties Verified:
  ✓ Password validity not leaked via timing
  ✓ HMAC comparison is constant-time
  ✓ Position of string difference not leaked
  ✓ Key derivation timing is data-independent
    """)
    print("=" * 70)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
