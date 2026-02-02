#!/usr/bin/env python3
"""
🔒 Phase 2 Security Tests - Timing Oracles, Nonce Uniqueness, Birthday Bounds

Tests added as part of security hardening Phase 2:
1. Timing oracle resistance (constant-time comparisons)
2. Nonce uniqueness assertions 
3. Frame MAC birthday bound adversarial testing (GAP-07)

Reference: CRYPTO_SECURITY_REVIEW.md, docs/SECURITY_CHANGES.md
"""

import pytest
import secrets
import time
import statistics
import hashlib
from typing import List

# Test mode for faster KDF
import os
os.environ["MEOW_TEST_MODE"] = "1"

from meow_decoder.crypto import (
    _register_nonce_use,
    _nonce_reuse_cache,
    verify_manifest_hmac,
    derive_key,
    Manifest,
    pack_manifest_core,
    compute_manifest_hmac,
)
from meow_decoder.frame_mac import (
    compute_frame_mac,
    verify_frame_mac,
    derive_frame_key,
    MAC_SIZE,
)
from meow_decoder.constant_time import (
    constant_time_compare,
    timing_safe_equal_with_delay,
)


class TestNonceUniqueness:
    """
    P2-02: Test nonce uniqueness enforcement.
    
    Verifies that the nonce reuse guard works correctly to prevent
    catastrophic GCM nonce reuse.
    """
    
    def setup_method(self):
        """Clear nonce cache before each test."""
        _nonce_reuse_cache.clear()
    
    def test_same_key_nonce_raises_on_reuse(self):
        """Using the same (key, nonce) pair twice should raise RuntimeError."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First use should succeed
        _register_nonce_use(key, nonce)
        
        # Second use should fail
        with pytest.raises(RuntimeError, match="Nonce reuse detected"):
            _register_nonce_use(key, nonce)
    
    def test_different_nonces_allowed(self):
        """Different nonces with same key should work."""
        key = secrets.token_bytes(32)
        
        for _ in range(100):
            nonce = secrets.token_bytes(12)
            _register_nonce_use(key, nonce)  # Should not raise
    
    def test_different_keys_same_nonce_allowed(self):
        """Same nonce with different keys should work (different encryption contexts)."""
        nonce = secrets.token_bytes(12)
        
        for _ in range(10):
            key = secrets.token_bytes(32)
            _register_nonce_use(key, nonce)  # Should not raise
    
    def test_cache_eviction_does_not_cause_false_positive(self):
        """
        After cache eviction, previously used nonces should NOT raise.
        
        Note: This is a known limitation - after 1024 nonces, the cache clears.
        This test documents that behavior.
        """
        key = secrets.token_bytes(32)
        original_nonce = secrets.token_bytes(12)
        
        # Use the original nonce
        _register_nonce_use(key, original_nonce)
        
        # Fill the cache to trigger eviction
        for _ in range(1025):
            _register_nonce_use(secrets.token_bytes(32), secrets.token_bytes(12))
        
        # Original nonce can be reused after eviction (cache cleared)
        # This is a known limitation - document it
        _register_nonce_use(key, original_nonce)  # Should not raise after eviction


class TestTimingOracleResistance:
    """
    P2-01: Test timing oracle resistance.
    
    These tests verify that security-critical comparisons don't leak
    timing information that could be used to guess passwords/MACs.
    
    Note: Python timing tests are inherently noisy. We test for:
    1. Usage of constant-time primitives (secrets.compare_digest)
    2. Variance is within expected bounds
    3. No obvious early-exit behavior
    """
    
    def test_constant_time_compare_uses_secrets_module(self):
        """Verify constant_time_compare uses secrets.compare_digest."""
        import inspect
        source = inspect.getsource(constant_time_compare)
        assert "compare_digest" in source, "Must use secrets.compare_digest"
    
    def test_hmac_verification_timing_consistency(self):
        """
        HMAC verification should take similar time for correct vs wrong passwords.
        
        Note: This test is statistical and may be flaky due to Python/OS timing noise.
        We're checking for gross timing differences (>10x), not cryptographic precision.
        """
        salt = secrets.token_bytes(16)
        password = "CorrectPassword123"
        wrong_password = "WrongPassword456"
        
        # Create a manifest for testing
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
        
        # Compute correct HMAC
        packed = pack_manifest_core(manifest, include_duress_tag=False)
        manifest.hmac = compute_manifest_hmac(password, salt, packed)
        
        # Time correct password verification
        correct_times: List[float] = []
        for _ in range(5):
            start = time.perf_counter()
            result = verify_manifest_hmac(password, manifest)
            correct_times.append(time.perf_counter() - start)
            assert result is True
        
        # Time wrong password verification
        wrong_times: List[float] = []
        for _ in range(5):
            start = time.perf_counter()
            result = verify_manifest_hmac(wrong_password, manifest)
            wrong_times.append(time.perf_counter() - start)
            assert result is False
        
        # Check that timing difference isn't suspicious (>10x would indicate early exit)
        avg_correct = statistics.mean(correct_times)
        avg_wrong = statistics.mean(wrong_times)
        
        # Both should be in similar order of magnitude
        # Allow 10x variance due to Python/OS noise, Argon2 dominates anyway
        ratio = max(avg_correct, avg_wrong) / max(min(avg_correct, avg_wrong), 1e-9)
        assert ratio < 10, f"Timing ratio {ratio:.2f}x suggests timing leak"
    
    def test_frame_mac_verification_no_early_exit(self):
        """Frame MAC verification should not exit early on first byte mismatch."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        frame_data = b"Test frame data for MAC verification"
        
        # Compute correct MAC
        correct_mac = compute_frame_mac(frame_data, master_key, 0, salt)
        
        # Create MACs with first byte wrong vs last byte wrong
        first_byte_wrong = bytes([correct_mac[0] ^ 0xFF]) + correct_mac[1:]
        last_byte_wrong = correct_mac[:-1] + bytes([correct_mac[-1] ^ 0xFF])
        
        # Time verification of each
        first_wrong_times: List[float] = []
        last_wrong_times: List[float] = []
        
        for _ in range(20):
            start = time.perf_counter()
            verify_frame_mac(frame_data, first_byte_wrong, master_key, 0, salt)
            first_wrong_times.append(time.perf_counter() - start)
            
            start = time.perf_counter()
            verify_frame_mac(frame_data, last_byte_wrong, master_key, 0, salt)
            last_wrong_times.append(time.perf_counter() - start)
        
        # Both should take similar time (no early exit on first byte mismatch)
        avg_first = statistics.mean(first_wrong_times)
        avg_last = statistics.mean(last_wrong_times)
        
        # Allow 5x variance due to noise
        ratio = max(avg_first, avg_last) / max(min(avg_first, avg_last), 1e-9)
        assert ratio < 5, f"Timing ratio {ratio:.2f}x suggests early exit behavior"


class TestFrameMACBirthdayBound:
    """
    P2-03 / GAP-07: Frame MAC birthday bound adversarial testing.
    
    Tests that frame MAC collisions are astronomically unlikely
    within practical frame counts.
    """
    
    def test_mac_uniqueness_within_session(self):
        """All frame MACs within a session should be unique."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Generate MACs for 1000 frames (typical GIF size)
        macs = set()
        for frame_index in range(1000):
            frame_data = f"Frame {frame_index} data content".encode()
            mac = compute_frame_mac(frame_data, master_key, frame_index, salt)
            macs.add(mac)
        
        # All 1000 MACs should be unique
        assert len(macs) == 1000, f"MAC collision detected! Only {len(macs)} unique MACs"
    
    def test_mac_uniqueness_across_sessions(self):
        """MACs with different salts should be unique (cross-session)."""
        master_key = secrets.token_bytes(32)
        frame_data = b"Same frame data across sessions"
        
        macs = set()
        for _ in range(100):
            salt = secrets.token_bytes(16)  # New salt per session
            mac = compute_frame_mac(frame_data, master_key, 0, salt)
            macs.add(mac)
        
        # All 100 MACs should be unique
        assert len(macs) == 100, f"Cross-session MAC collision! Only {len(macs)} unique MACs"
    
    def test_per_frame_key_derivation_uniqueness(self):
        """Each frame index should derive a unique key."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        keys = set()
        for frame_index in range(1000):
            frame_key = derive_frame_key(master_key, frame_index, salt)
            keys.add(frame_key)
        
        # All 1000 keys should be unique
        assert len(keys) == 1000, f"Key derivation collision! Only {len(keys)} unique keys"
    
    def test_birthday_bound_adversarial(self):
        """
        Adversarial test: Try to find collisions in 2^16 random MACs.
        
        With 64-bit MACs, birthday bound is ~2^32 for 50% collision probability.
        At 2^16 attempts, collision probability is ~2^(-32) = negligible.
        
        This test verifies no implementation bugs cause unexpected collisions.
        """
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Generate 2^12 = 4096 random MACs (practical limit for test speed)
        num_macs = 4096
        macs = set()
        
        for i in range(num_macs):
            # Random frame data to maximize collision chance
            frame_data = secrets.token_bytes(64)
            mac = compute_frame_mac(frame_data, master_key, i, salt)
            
            if mac in macs:
                pytest.fail(f"Collision found at iteration {i}! This should be astronomically unlikely.")
            macs.add(mac)
        
        # If we get here, no collisions (expected)
        assert len(macs) == num_macs
    
    def test_mac_size_is_documented(self):
        """Verify MAC size matches documented security rationale."""
        assert MAC_SIZE == 8, "MAC_SIZE should be 8 bytes (64 bits) per security rationale"
        
        # Verify a computed MAC has the correct size
        mac = compute_frame_mac(b"test", secrets.token_bytes(32), 0, secrets.token_bytes(16))
        assert len(mac) == MAC_SIZE


class TestDuressTimingProtection:
    """
    Tests for CRIT-04 fix: Duress password timing protection.
    
    Verifies that duress detection doesn't create timing oracles.
    """
    
    def test_duress_check_imports_exist(self):
        """Verify duress checking functions are importable."""
        from meow_decoder.crypto import check_duress_password, compute_duress_tag
        assert callable(check_duress_password)
        assert callable(compute_duress_tag)
    
    def test_duress_tag_uses_constant_time_compare(self):
        """Duress tag verification should use constant-time comparison."""
        import inspect
        from meow_decoder.crypto import check_duress_password
        
        source = inspect.getsource(check_duress_password)
        # Should use secrets.compare_digest
        assert "compare_digest" in source, "Duress check must use constant-time comparison"


class TestKeyDerivationSecurity:
    """Additional key derivation security tests."""
    
    def test_different_salts_produce_different_keys(self):
        """Same password with different salts should produce different keys."""
        password = "TestPassword123"
        
        keys = set()
        for _ in range(100):
            salt = secrets.token_bytes(16)
            key = derive_key(password, salt)
            keys.add(key)
        
        assert len(keys) == 100, "All keys should be unique with different salts"
    
    def test_key_derivation_deterministic(self):
        """Same password and salt should produce same key."""
        password = "TestPassword123"
        salt = secrets.token_bytes(16)
        
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        
        assert key1 == key2, "Key derivation should be deterministic"
    
    def test_minimum_password_length_enforced(self):
        """Short passwords should be rejected."""
        from meow_decoder.crypto import MIN_PASSWORD_LENGTH
        
        salt = secrets.token_bytes(16)
        short_password = "a" * (MIN_PASSWORD_LENGTH - 1)
        
        with pytest.raises(ValueError, match="at least"):
            derive_key(short_password, salt)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
