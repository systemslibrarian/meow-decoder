"""
Security Test Suite: Deniability / Statistical Distinguishability

Tests attempting to distinguish single-secret from dual-secret (Schrödinger)
outputs. These tests verify INV-025 from SECURITY_INVARIANTS.md.

Current status: These are basic statistical tests that exercise the
distinguishability boundary. They are intentionally conservative —
some may detect real differences (which is honest reporting, not a bug).
"""

from meow_decoder.quantum_mixer import entangle_realities, collapse_to_reality
from meow_decoder.crypto import encrypt_file_bytes
from meow_decoder.crypto_backend import get_default_backend, get_handle_backend
import os
import math
import secrets
import struct
from collections import Counter

import pytest

os.environ["MEOW_TEST_MODE"] = "1"
os.environ["MEOW_PRODUCTION_MODE"] = "0"


@pytest.fixture
def backend():
    return get_default_backend()


# ═══════════════════════════════════════════════════════════════════════════
# BYTE DISTRIBUTION TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestByteDistribution:
    """Test that ciphertext byte distributions are statistically uniform."""

    def _chi_square_uniformity(self, data: bytes) -> float:
        """Compute chi-square statistic for byte distribution uniformity.
        Expected: uniform distribution (each byte value ≈ n/256).
        Returns chi-square value. For 255 degrees of freedom,
        critical value at p=0.01 is ~310.5."""
        n = len(data)
        expected = n / 256.0
        counts = Counter(data)
        chi2 = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))
        return chi2

    def _entropy(self, data: bytes) -> float:
        """Compute Shannon entropy of byte distribution (bits).
        Max for uniform: 8.0 bits."""
        n = len(data)
        if n == 0:
            return 0.0
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / n
                entropy -= p * math.log2(p)
        return entropy

    def test_single_ciphertext_uniform(self, backend):
        """Single AES-256-GCM ciphertext should have near-uniform byte distribution."""
        data = secrets.token_bytes(10000)
        _, _, _, _, cipher, _, _ = encrypt_file_bytes(data, "testpass", None, None)

        chi2 = self._chi_square_uniformity(cipher)
        entropy = self._entropy(cipher)

        # Chi-square: should be < 350 for p=0.001 (generous threshold)
        assert chi2 < 400, f"Single ciphertext chi-square too high: {chi2:.1f}"
        # Entropy: should be near 8.0 for good cipher
        assert entropy > 7.9, f"Single ciphertext entropy too low: {entropy:.4f}"

    def test_interleaved_ciphertext_uniform(self, backend):
        """Interleaved (Schrödinger) ciphertext should also be near-uniform."""
        data_a = secrets.token_bytes(5000)
        data_b = secrets.token_bytes(5000)

        _, _, _, _, cipher_a, _, _ = encrypt_file_bytes(data_a, "password_a", None, None)
        _, _, _, _, cipher_b, _, _ = encrypt_file_bytes(data_b, "password_b", None, None)

        interleaved = entangle_realities(cipher_a, cipher_b)

        chi2 = self._chi_square_uniformity(interleaved)
        entropy = self._entropy(interleaved)

        assert chi2 < 400, f"Interleaved ciphertext chi-square too high: {chi2:.1f}"
        assert entropy > 7.9, f"Interleaved ciphertext entropy too low: {entropy:.4f}"

    def test_single_vs_dual_chi_square_similar(self, backend):
        """Chi-square statistics of single vs dual should be in the same range."""
        # Generate 5 single-secret ciphertexts
        single_chi2s = []
        for _ in range(5):
            data = secrets.token_bytes(10000)
            _, _, _, _, cipher, _, _ = encrypt_file_bytes(data, "password1", None, None)
            single_chi2s.append(self._chi_square_uniformity(cipher))

        # Generate 5 dual-secret interleaved ciphertexts
        dual_chi2s = []
        for _ in range(5):
            data_a = secrets.token_bytes(5000)
            data_b = secrets.token_bytes(5000)
            _, _, _, _, ca, _, _ = encrypt_file_bytes(data_a, "passwd_a1", None, None)
            _, _, _, _, cb, _, _ = encrypt_file_bytes(data_b, "passwd_b1", None, None)
            interleaved = entangle_realities(ca, cb)
            dual_chi2s.append(self._chi_square_uniformity(interleaved))

        # Both distributions should be similar (both near uniform)
        avg_single = sum(single_chi2s) / len(single_chi2s)
        avg_dual = sum(dual_chi2s) / len(dual_chi2s)

        # They should both be in reasonable range (< 400)
        assert avg_single < 400, f"Single avg chi2 too high: {avg_single:.1f}"
        assert avg_dual < 400, f"Dual avg chi2 too high: {avg_dual:.1f}"


# ═══════════════════════════════════════════════════════════════════════════
# ENTROPY TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestEntropyDistinguishability:
    """Test that entropy measurements cannot distinguish single from dual."""

    def _byte_entropy(self, data: bytes) -> float:
        n = len(data)
        if n == 0:
            return 0.0
        counts = Counter(data)
        return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)

    def test_entropy_single_vs_dual_indistinguishable(self, backend):
        """Shannon entropy should not distinguish single from dual ciphertext."""
        single_entropies = []
        dual_entropies = []

        for _ in range(10):
            # Single
            data = secrets.token_bytes(8000)
            _, _, _, _, cipher, _, _ = encrypt_file_bytes(data, "password1", None, None)
            single_entropies.append(self._byte_entropy(cipher))

            # Dual
            da = secrets.token_bytes(4000)
            db = secrets.token_bytes(4000)
            _, _, _, _, ca, _, _ = encrypt_file_bytes(da, "passwd_a1", None, None)
            _, _, _, _, cb, _, _ = encrypt_file_bytes(db, "passwd_b1", None, None)
            dual_entropies.append(self._byte_entropy(entangle_realities(ca, cb)))

        avg_single = sum(single_entropies) / len(single_entropies)
        avg_dual = sum(dual_entropies) / len(dual_entropies)

        # Both should be near 8.0 bits (max entropy for byte stream)
        assert abs(avg_single - avg_dual) < 0.05, (
            f"Entropy gap too large: single={avg_single:.4f}, dual={avg_dual:.4f}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# INTERLEAVING PATTERN TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestInterleavingPatterns:
    """Test that interleaving does not introduce detectable patterns."""

    def test_even_odd_byte_distributions_match(self, backend):
        """Even and odd bytes of interleaved ciphertext should both be uniform."""
        da = secrets.token_bytes(5000)
        db = secrets.token_bytes(5000)
        _, _, _, _, ca, _, _ = encrypt_file_bytes(da, "passwd_a1", None, None)
        _, _, _, _, cb, _, _ = encrypt_file_bytes(db, "passwd_b1", None, None)

        interleaved = entangle_realities(ca, cb)

        even_bytes = bytes(interleaved[i] for i in range(0, len(interleaved), 2))
        odd_bytes = bytes(interleaved[i] for i in range(1, len(interleaved), 2))

        even_entropy = self._entropy(even_bytes)
        odd_entropy = self._entropy(odd_bytes)

        assert even_entropy > 7.9, f"Even bytes entropy too low: {even_entropy:.4f}"
        assert odd_entropy > 7.9, f"Odd bytes entropy too low: {odd_entropy:.4f}"

    def test_collapse_recovers_original(self, backend):
        """collapse_to_reality correctly recovers the original ciphertext."""
        ca = secrets.token_bytes(5000)
        cb = secrets.token_bytes(5000)

        interleaved = entangle_realities(ca, cb)
        recovered_a = collapse_to_reality(interleaved, 0)
        recovered_b = collapse_to_reality(interleaved, 1)

        assert recovered_a == ca
        assert recovered_b == cb

    def _entropy(self, data: bytes) -> float:
        n = len(data)
        if n == 0:
            return 0.0
        counts = Counter(data)
        return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)

    def test_random_fill_for_single_secret_uniform(self, backend):
        """When one stream is random (single-secret mode), result is still uniform."""
        real_data = secrets.token_bytes(5000)
        _, _, _, _, cipher_real, _, _ = encrypt_file_bytes(real_data, "password1", None, None)

        # Simulate single-secret: second stream is pure random
        dummy = secrets.token_bytes(len(cipher_real))
        interleaved = entangle_realities(cipher_real, dummy)

        entropy = self._entropy(interleaved)
        assert entropy > 7.9, f"Single-secret interleaved entropy too low: {entropy:.4f}"


# ═══════════════════════════════════════════════════════════════════════════
# TIMING DISTINGUISHABILITY (placeholder for future work)
# ═══════════════════════════════════════════════════════════════════════════


class TestTimingDistinguishability:
    """Placeholder: timing tests for encode/decode path equalization.

    These are intentionally basic — proper timing tests require
    statistical methods and controlled environments.
    """

    def test_single_and_dual_encrypt_both_succeed(self, backend):
        """Basic smoke test: both paths complete without error."""
        # Single
        data = secrets.token_bytes(1000)
        _, _, _, _, cipher, _, _ = encrypt_file_bytes(data, "password1", None, None)
        assert len(cipher) > 0

        # Dual (simulated)
        da = secrets.token_bytes(500)
        db = secrets.token_bytes(500)
        _, _, _, _, ca, _, _ = encrypt_file_bytes(da, "passwd_a1", None, None)
        _, _, _, _, cb, _, _ = encrypt_file_bytes(db, "passwd_b1", None, None)
        interleaved = entangle_realities(ca, cb)
        assert len(interleaved) > 0
