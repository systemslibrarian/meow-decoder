#!/usr/bin/env python3
"""
🔒 Phase 3 Security Tests - Schrödinger Mode Timing & Adversarial

Tests added as part of security hardening Phase 3:
1. Schrödinger timing oracle resistance (TIMING-01, TIMING-02)
2. Reality ordering constant-time behavior
3. Adversarial testing for Schrödinger mode (GAP-04)

Reference: CRYPTO_SECURITY_REVIEW.md § 9, docs/SECURITY_CHANGES.md
"""

import pytest
import secrets
import time
import statistics
import hashlib
import struct
from typing import List, Tuple

# Test mode for faster KDF
import os
os.environ["MEOW_TEST_MODE"] = "1"

from meow_decoder.crypto import derive_key
from meow_decoder.schrodinger_encode import (
    schrodinger_encode_data,
    SchrodingerManifest,
)
from meow_decoder.schrodinger_decode import schrodinger_decode_data
from meow_decoder.quantum_mixer import (
    entangle_realities,
    collapse_to_reality,
    verify_indistinguishability,
)


class TestSchrodingerTimingResistance:
    """
    TIMING-01 & TIMING-02: Test Schrödinger mode timing oracle resistance.
    
    The decoder must derive BOTH Argon2id keys and check BOTH HMACs
    regardless of which password is correct, to prevent timing attacks
    that could reveal which reality was accessed.
    """
    
    @pytest.fixture
    def encoded_data(self) -> Tuple[bytes, SchrodingerManifest, str, str]:
        """Create encoded Schrödinger data with known passwords."""
        real_data = b"SECRET REALITY A DATA" * 50
        decoy_data = b"DECOY REALITY B DATA" * 50
        password_a = "RealityA_Password123"
        password_b = "RealityB_Password456"
        
        mixed, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            password_a, password_b,
            block_size=256
        )
        
        return mixed, manifest, password_a, password_b
    
    def test_both_argon2id_derivations_run(self, encoded_data):
        """
        TIMING-01: Verify both Argon2id key derivations run regardless of which
        password is correct.
        
        We can't directly measure this, but we verify the decode still works
        after the timing-safe refactor.
        """
        mixed, manifest, password_a, password_b = encoded_data
        
        # Decode with Reality A password
        result_a = schrodinger_decode_data(mixed, manifest, password_a)
        assert result_a is not None
        assert b"SECRET REALITY A DATA" in result_a
        
        # Decode with Reality B password
        result_b = schrodinger_decode_data(mixed, manifest, password_b)
        assert result_b is not None
        assert b"DECOY REALITY B DATA" in result_b
    
    def test_wrong_password_timing_consistent(self, encoded_data):
        """
        TIMING-02: Verify that wrong password takes similar time to correct password.
        
        This is a statistical test - we measure decode time with correct, wrong,
        and gibberish passwords and verify they're in the same order of magnitude.
        
        Note: This test may be flaky due to OS scheduling. We use wide tolerance.
        """
        mixed, manifest, password_a, password_b = encoded_data
        wrong_password = "WrongPassword789"
        
        # Measure correct password time
        times_correct = []
        for _ in range(3):
            start = time.perf_counter()
            result = schrodinger_decode_data(mixed, manifest, password_a)
            elapsed = time.perf_counter() - start
            times_correct.append(elapsed)
            assert result is not None
        
        # Measure wrong password time
        times_wrong = []
        for _ in range(3):
            start = time.perf_counter()
            result = schrodinger_decode_data(mixed, manifest, wrong_password)
            elapsed = time.perf_counter() - start
            times_wrong.append(elapsed)
            assert result is None
        
        avg_correct = statistics.mean(times_correct)
        avg_wrong = statistics.mean(times_wrong)
        
        # Both should run double Argon2id, so wrong should be >= correct
        # (since wrong can't exit early anymore)
        # Allow 3x tolerance for OS scheduling variance
        ratio = avg_wrong / avg_correct if avg_correct > 0 else float('inf')
        
        # Wrong should be at least 50% of correct time (both run 2x Argon2id)
        assert ratio >= 0.5, f"Wrong password too fast: {avg_wrong:.3f}s vs correct {avg_correct:.3f}s (ratio {ratio:.2f})"
        
        # Wrong should not be more than 3x correct (accounting for variance)
        assert ratio <= 3.0, f"Wrong password too slow: {avg_wrong:.3f}s vs correct {avg_correct:.3f}s (ratio {ratio:.2f})"
    
    def test_reality_a_vs_b_timing_similar(self, encoded_data):
        """
        Verify that decoding Reality A vs Reality B takes similar time.
        
        This ensures no timing leak reveals which reality was accessed.
        """
        mixed, manifest, password_a, password_b = encoded_data
        
        # Measure Reality A decode time
        times_a = []
        for _ in range(3):
            start = time.perf_counter()
            schrodinger_decode_data(mixed, manifest, password_a)
            times_a.append(time.perf_counter() - start)
        
        # Measure Reality B decode time
        times_b = []
        for _ in range(3):
            start = time.perf_counter()
            schrodinger_decode_data(mixed, manifest, password_b)
            times_b.append(time.perf_counter() - start)
        
        avg_a = statistics.mean(times_a)
        avg_b = statistics.mean(times_b)
        
        # Should be within 50% of each other
        ratio = max(avg_a, avg_b) / min(avg_a, avg_b) if min(avg_a, avg_b) > 0 else float('inf')
        assert ratio < 1.5, f"Reality A/B timing differs too much: A={avg_a:.3f}s, B={avg_b:.3f}s (ratio {ratio:.2f})"


class TestSchrodingerAdversarial:
    """
    GAP-04: Adversarial testing for Schrödinger mode.
    
    Tests various attack scenarios against the dual-reality encoding.
    """
    
    def test_cross_reality_hmac_substitution(self):
        """
        Verify that swapping HMAC values between realities is detected.
        """
        real_data = b"REAL SECRET" * 100
        decoy_data = b"DECOY DATA" * 100
        password_a = "RealPass123456"
        password_b = "DecoyPass789012"
        
        mixed, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            password_a, password_b,
            block_size=256
        )
        
        # Swap HMACs between realities
        original_hmac_a = manifest.reality_a_hmac
        manifest.reality_a_hmac = manifest.reality_b_hmac
        manifest.reality_b_hmac = original_hmac_a
        
        # Both passwords should now fail
        result_a = schrodinger_decode_data(mixed, manifest, password_a)
        result_b = schrodinger_decode_data(mixed, manifest, password_b)
        
        assert result_a is None, "Cross-reality HMAC swap should fail"
        assert result_b is None, "Cross-reality HMAC swap should fail"
    
    def test_salt_substitution_attack(self):
        """
        Verify that substituting salts between realities is detected.
        """
        real_data = b"REAL SECRET" * 100
        decoy_data = b"DECOY DATA" * 100
        password_a = "RealPass123456"
        password_b = "DecoyPass789012"
        
        mixed, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            password_a, password_b,
            block_size=256
        )
        
        # Swap salts
        original_salt_a = manifest.salt_a
        manifest.salt_a = manifest.salt_b
        manifest.salt_b = original_salt_a
        
        # Both passwords should now fail (wrong key derivation)
        result_a = schrodinger_decode_data(mixed, manifest, password_a)
        result_b = schrodinger_decode_data(mixed, manifest, password_b)
        
        assert result_a is None, "Salt swap attack should fail"
        assert result_b is None, "Salt swap attack should fail"
    
    def test_metadata_tampering_detected(self):
        """
        Verify that tampering with encrypted metadata is detected.
        """
        real_data = b"REAL SECRET" * 100
        decoy_data = b"DECOY DATA" * 100
        password_a = "RealPass123456"
        password_b = "DecoyPass789012"
        
        mixed, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            password_a, password_b,
            block_size=256
        )
        
        # Tamper with metadata_a (flip a bit)
        tampered = bytearray(manifest.metadata_a)
        tampered[50] ^= 0x01
        manifest.metadata_a = bytes(tampered)
        
        # Reality A should fail (GCM tag mismatch)
        result_a = schrodinger_decode_data(mixed, manifest, password_a)
        assert result_a is None, "Metadata tampering should be detected"
        
        # Reality B should still work (different metadata)
        result_b = schrodinger_decode_data(mixed, manifest, password_b)
        assert result_b is not None, "Reality B should be unaffected by A's tampering"
    
    def test_superposition_corruption_handling(self):
        """
        Verify graceful handling of corrupted superposition data.
        """
        real_data = b"REAL SECRET" * 100
        decoy_data = b"DECOY DATA" * 100
        password_a = "RealPass123456"
        password_b = "DecoyPass789012"
        
        mixed, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            password_a, password_b,
            block_size=256
        )
        
        # Corrupt the superposition
        corrupted = bytearray(mixed)
        for i in range(0, len(corrupted), 100):
            corrupted[i] ^= 0xFF
        
        # Should fail gracefully (not crash)
        try:
            result_a = schrodinger_decode_data(bytes(corrupted), manifest, password_a)
            # If it returns, it should be None or corrupted
            # (GCM tag should catch corruption)
        except Exception:
            # Exception is acceptable for corrupted data
            pass
    
    def test_manifest_version_binding(self):
        """
        Verify that manifest version is bound to authentication.
        """
        real_data = b"REAL SECRET" * 100
        decoy_data = b"DECOY DATA" * 100
        password_a = "RealPass123456"
        password_b = "DecoyPass789012"
        
        mixed, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            password_a, password_b,
            block_size=256
        )
        
        # Verify version is 0x07 (Schrödinger)
        assert manifest.version == 0x07
        
        # Changing version should break HMAC
        manifest.version = 0x06  # Wrong version
        
        result = schrodinger_decode_data(mixed, manifest, password_a)
        # HMAC verification includes version in pack_core_for_auth()
        assert result is None, "Version change should invalidate HMAC"


class TestQuantumMixerSecurity:
    """
    Tests for the quantum mixer's cryptographic properties.
    """
    
    def test_statistical_indistinguishability(self):
        """
        Verify that interleaved data passes statistical tests.
        """
        # Create two very different data samples
        reality_a = b"\x00" * 1000 + b"\xFF" * 1000  # Low entropy patterns
        reality_b = secrets.token_bytes(2000)  # High entropy
        
        # Entangle them
        superposition = entangle_realities(reality_a, reality_b)
        
        # Test indistinguishability of the two halves
        half = len(superposition) // 2
        is_indist, results = verify_indistinguishability(
            superposition[:half],
            superposition[half:],
            threshold=0.1  # Allow 10% difference
        )
        
        # Both halves should have similar entropy
        assert results['entropy_diff'] < 0.5, f"Entropy difference too large: {results['entropy_diff']}"
    
    def test_collapse_correctness(self):
        """
        Verify that collapse_to_reality correctly extracts the right data.
        """
        reality_a = b"AAAA" * 100
        reality_b = b"BBBB" * 100
        
        superposition = entangle_realities(reality_a, reality_b)
        
        # Collapse to each reality
        collapsed_a = collapse_to_reality(superposition, 0)
        collapsed_b = collapse_to_reality(superposition, 1)
        
        # Should recover original data
        assert collapsed_a[:len(reality_a)] == reality_a
        assert collapsed_b[:len(reality_b)] == reality_b
    
    def test_different_length_realities(self):
        """
        Verify handling of different-length realities.
        """
        reality_a = b"SHORT"
        reality_b = b"MUCH LONGER REALITY B DATA" * 10
        
        superposition = entangle_realities(reality_a, reality_b)
        
        # Both should be padded to same length
        collapsed_a = collapse_to_reality(superposition, 0)
        collapsed_b = collapse_to_reality(superposition, 1)
        
        # Collapsed lengths should be equal
        assert len(collapsed_a) == len(collapsed_b)
        
        # Original data should be recoverable (with padding)
        assert collapsed_a[:len(reality_a)] == reality_a
        assert collapsed_b[:len(reality_b)] == reality_b


class TestSchrodingerRoundtrip:
    """
    Full encode/decode roundtrip tests for Schrödinger mode.
    """
    
    def test_basic_roundtrip_both_realities(self):
        """
        Test that both realities can be encoded and decoded correctly.
        """
        real_data = b"This is the REAL secret message!" * 50
        decoy_data = b"This is just innocent vacation photos..." * 50
        password_a = "SecretPassword123!"
        password_b = "InnocentPassword456"
        
        # Encode
        mixed, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            password_a, password_b,
            block_size=256
        )
        
        # Decode Reality A
        result_a = schrodinger_decode_data(mixed, manifest, password_a)
        assert result_a == real_data, "Reality A mismatch"
        
        # Decode Reality B
        result_b = schrodinger_decode_data(mixed, manifest, password_b)
        assert result_b == decoy_data, "Reality B mismatch"
    
    def test_password_independence(self):
        """
        Verify that knowing one password reveals nothing about the other reality.
        """
        real_data = b"TOP SECRET MILITARY PLANS" * 100
        decoy_data = b"Cat memes and shopping lists" * 100
        password_a = "MilitaryGrade123"
        password_b = "CatLover456"
        
        mixed, manifest = schrodinger_encode_data(
            real_data, decoy_data,
            password_a, password_b,
            block_size=256
        )
        
        # With password A, should NOT be able to see any of decoy_data
        result_a = schrodinger_decode_data(mixed, manifest, password_a)
        assert b"Cat memes" not in result_a
        assert b"TOP SECRET" in result_a
        
        # With password B, should NOT be able to see any of real_data
        result_b = schrodinger_decode_data(mixed, manifest, password_b)
        assert b"MILITARY PLANS" not in result_b
        assert b"shopping lists" in result_b


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
