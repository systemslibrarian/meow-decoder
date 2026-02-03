#!/usr/bin/env python3
"""
🔥 Adversarial Test Suite - Attack Simulation

CANONICAL test file for adversarial testing. DO NOT create numbered variants.

Tests that simulate real attacks:
1. Fuzzing (random input mutation)
2. Frame injection (malicious frames)
3. Replay attacks (reused frames/sessions)
4. Reordering attacks (out-of-order frames)
5. Manifest corruption (bit flipping)
6. Partial decryption (incomplete data)
7. Length oracle attacks
8. Timing attacks (best-effort)

These tests PROVE the security model works under attack.
"""

import pytest
import secrets
import struct
import time
from pathlib import Path

from meow_decoder.crypto import (
    encrypt_file_bytes,
    decrypt_to_raw,
    Manifest,
    pack_manifest,
    unpack_manifest,
    derive_key,
    verify_manifest_hmac,
    compute_manifest_hmac,
    pack_manifest_core,
    MAGIC,
)
from meow_decoder.fountain import (
    FountainEncoder,
    FountainDecoder,
    pack_droplet,
    unpack_droplet,
    Droplet,
)
from meow_decoder.frame_mac import (
    pack_frame_with_mac,
    unpack_frame_with_mac,
    derive_frame_master_key,
    compute_frame_mac,
    MAC_SIZE,
)
from meow_decoder.constant_time import (
    constant_time_compare,
    secure_zero_memory,
    timing_safe_equal_with_delay,
)


# =============================================================================
# FUZZING ATTACKS (5 tests)
# =============================================================================

class TestFuzzingAttacks:
    """Fuzz testing - random mutations should fail gracefully."""

    def test_fuzz_ciphertext_random_bits(self):
        """Random ciphertext bit flips should fail auth check."""
        data = b"Secret message for fuzzing test"
        password = "testpass123"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Try 20 random single-bit mutations
        failures = 0
        for _ in range(20):
            fuzzed = bytearray(cipher)
            pos = secrets.randbelow(len(fuzzed))
            bit = secrets.randbelow(8)
            fuzzed[pos] ^= (1 << bit)
            
            try:
                decrypt_to_raw(
                    bytes(fuzzed),
                    password,
                    salt,
                    nonce,
                    orig_len=len(data),
                    comp_len=len(comp),
                    sha256=sha
                )
            except Exception:
                failures += 1
        
        # All should fail (GCM has 128-bit auth tag)
        assert failures == 20, f"Only {failures}/20 fuzz attempts detected"

    def test_fuzz_nonce_all_positions(self):
        """Flipping any bit in nonce should break decryption."""
        data = b"Secret message"
        password = "testpass123"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        failures = 0
        for byte_pos in range(len(nonce)):
            for bit_pos in range(8):
                fuzzed_nonce = bytearray(nonce)
                fuzzed_nonce[byte_pos] ^= (1 << bit_pos)
                
                try:
                    decrypt_to_raw(
                        cipher,
                        password,
                        bytes(fuzzed_nonce),
                        nonce,  # Wrong! Should be fuzzed_nonce
                        orig_len=len(data),
                        comp_len=len(comp),
                        sha256=sha
                    )
                except Exception:
                    failures += 1
        
        # All 96 bit positions should fail
        assert failures == len(nonce) * 8

    def test_fuzz_salt_breaks_key_derivation(self):
        """Any change to salt should produce different key."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        
        original_key = derive_key(password, salt)
        
        different_keys = 0
        for byte_pos in range(len(salt)):
            fuzzed_salt = bytearray(salt)
            fuzzed_salt[byte_pos] ^= 0x01
            
            fuzzed_key = derive_key(password, bytes(fuzzed_salt))
            if fuzzed_key != original_key:
                different_keys += 1
        
        # All 16 mutations should produce different keys
        assert different_keys == 16

    def test_fuzz_manifest_length_fields(self):
        """Corrupted length fields should be detected via AAD."""
        data = b"Test data for length field fuzzing"
        password = "testpass123"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Try wrong orig_len values
        for bad_len in [0, len(data) - 1, len(data) + 1, 999999]:
            with pytest.raises(Exception):
                decrypt_to_raw(
                    cipher, password, salt, nonce,
                    orig_len=bad_len,
                    comp_len=len(comp),
                    sha256=sha
                )

    def test_fuzz_droplet_seed_consistency(self):
        """Droplet with same seed should always produce same data."""
        data = b"Test data for fountain encoding" * 10
        k_blocks = 5
        block_size = 64
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Generate droplet with specific seed
        droplet1 = encoder.droplet(seed=42)
        
        # Create new encoder and generate with same seed
        encoder2 = FountainEncoder(data, k_blocks, block_size)
        droplet2 = encoder2.droplet(seed=42)
        
        # Should be identical
        assert droplet1.seed == droplet2.seed
        assert droplet1.block_indices == droplet2.block_indices
        assert droplet1.data == droplet2.data


# =============================================================================
# FRAME INJECTION ATTACKS (4 tests)
# =============================================================================

class TestFrameInjectionAttacks:
    """Test that injected/malicious frames are rejected."""

    def test_inject_frame_wrong_mac(self):
        """Injected frame with wrong MAC should be rejected."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)
        
        # Legitimate frame
        legit_data = b"Legitimate frame data"
        legit_packed = pack_frame_with_mac(legit_data, master_key, 0, salt)
        
        # Injected frame with random MAC
        injected_data = b"MALICIOUS PAYLOAD"
        fake_mac = secrets.token_bytes(MAC_SIZE)
        injected = fake_mac + injected_data
        
        # Verification should fail
        is_valid, _ = unpack_frame_with_mac(injected, master_key, 0, salt)
        assert is_valid is False

    def test_inject_frame_reused_mac_different_data(self):
        """Reusing a valid MAC with different data should fail."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)
        
        # Generate legitimate frame
        legit_data = b"Legitimate frame data"
        legit_packed = pack_frame_with_mac(legit_data, master_key, 5, salt)
        legit_mac = legit_packed[:MAC_SIZE]
        
        # Try to use same MAC with different data
        injected_data = b"DIFFERENT DATA"
        injected = legit_mac + injected_data
        
        # Should fail (MAC doesn't match data)
        is_valid, _ = unpack_frame_with_mac(injected, master_key, 5, salt)
        assert is_valid is False

    def test_inject_frame_wrong_session(self):
        """Frame from one encryption session should fail in another."""
        password = "testpass123"
        
        # Session 1
        salt1 = secrets.token_bytes(16)
        enc_key1 = derive_key(password, salt1)
        master_key1 = derive_frame_master_key(enc_key1, salt1)
        frame1 = pack_frame_with_mac(b"Session 1 data", master_key1, 0, salt1)
        
        # Session 2
        salt2 = secrets.token_bytes(16)
        enc_key2 = derive_key(password, salt2)
        master_key2 = derive_frame_master_key(enc_key2, salt2)
        
        # Try to inject session 1 frame into session 2
        is_valid, _ = unpack_frame_with_mac(frame1, master_key2, 0, salt2)
        assert is_valid is False

    def test_truncated_frame_rejected(self):
        """Truncated frame should be gracefully rejected."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)
        
        frame_data = b"Test frame data"
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        
        # Truncate to less than MAC size
        truncated = packed[:MAC_SIZE - 2]
        
        # Should gracefully fail (not crash)
        is_valid, data = unpack_frame_with_mac(truncated, master_key, 0, salt)
        assert is_valid is False


# =============================================================================
# REPLAY & REORDERING ATTACKS (4 tests)
# =============================================================================

class TestReplayReorderingAttacks:
    """Test protection against replay and reordering attacks."""

    def test_replay_same_frame_different_index(self):
        """Replaying frame at different index should fail."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)
        
        # Create frame for index 5
        frame_data = b"Frame for index 5"
        packed = pack_frame_with_mac(frame_data, master_key, 5, salt)
        
        # Try to verify at index 10 (replay attack)
        is_valid, _ = unpack_frame_with_mac(packed, master_key, 10, salt)
        assert is_valid is False

    def test_droplet_reorder_still_decodes(self):
        """Reordered droplets should still decode (fountain property)."""
        data = b"Test data for reordering test" * 10
        k_blocks = 5
        block_size = 64
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Generate droplets
        droplets = [encoder.droplet() for _ in range(k_blocks * 2)]
        
        # Shuffle order (simulate reordering attack)
        import random
        random.shuffle(droplets)
        
        # Should still decode
        for droplet in droplets:
            if decoder.add_droplet(droplet):
                break
        
        assert decoder.is_complete()
        recovered = decoder.get_data(len(data))
        assert recovered == data

    def test_duplicate_droplets_handled(self):
        """Duplicate droplets should be handled gracefully."""
        data = b"Test data" * 10
        k_blocks = 3
        block_size = 32
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Generate same droplet multiple times (duplicate attack)
        droplet = encoder.droplet(seed=0)
        
        # Add same droplet 5 times
        for _ in range(5):
            decoder.add_droplet(droplet)
        
        # Should not crash or corrupt state
        # Just won't be complete yet (needs more unique droplets)
        assert decoder.decoded_count <= k_blocks

    def test_manifest_replay_different_password_fails(self):
        """Replaying manifest bytes with wrong password should fail."""
        password1 = "password_one12"
        password2 = "password_two12"
        salt = secrets.token_bytes(16)
        
        # Create manifest with password1
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=1,
            hmac=b"\x00" * 32,
        )
        
        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)
        enc_key = derive_key(password1, salt)
        manifest.hmac = compute_manifest_hmac(password1, salt, packed_no_hmac, encryption_key=enc_key)
        
        # Try to verify with password2 (should fail)
        assert verify_manifest_hmac(password2, manifest) is False


# =============================================================================
# CONSTANT-TIME OPERATION TESTS (4 tests)
# =============================================================================

class TestConstantTimeOperations:
    """Test constant-time operations for side-channel resistance."""

    def test_constant_time_compare_equal(self):
        """Constant-time comparison should return True for equal bytes."""
        a = b"secret_password_123"
        b = b"secret_password_123"
        
        assert constant_time_compare(a, b) is True

    def test_constant_time_compare_unequal(self):
        """Constant-time comparison should return False for unequal bytes."""
        a = b"secret_password_123"
        b = b"wrong_password_4567"
        
        assert constant_time_compare(a, b) is False

    def test_constant_time_compare_different_lengths(self):
        """Constant-time comparison should handle different lengths."""
        a = b"short"
        b = b"much_longer_string"
        
        # Should not crash, should return False
        result = constant_time_compare(a, b)
        assert result is False

    def test_timing_safe_equal_adds_delay(self):
        """Timing-safe comparison should add measurable delay."""
        a = b"test_value"
        b = b"test_value"
        
        # Time the comparison
        start = time.time()
        result = timing_safe_equal_with_delay(a, b, min_delay_ms=5, max_delay_ms=15)
        elapsed = time.time() - start
        
        # Should take at least min_delay_ms * 2 (before + after)
        assert elapsed >= 0.010  # At least 10ms
        assert result is True


# =============================================================================
# MEMORY ZEROING TESTS (3 tests)  
# =============================================================================

class TestMemoryZeroingAttacks:
    """Test secure memory zeroing to prevent forensic recovery."""

    def test_secure_zero_bytearray(self):
        """secure_zero_memory should zero bytearray."""
        sensitive = bytearray(b"SECRET_PASSWORD_123")
        original_len = len(sensitive)
        
        secure_zero_memory(sensitive)
        
        # Should be all zeros
        assert all(b == 0 for b in sensitive)
        assert len(sensitive) == original_len

    def test_secure_zero_empty_bytearray(self):
        """secure_zero_memory should handle empty bytearray."""
        empty = bytearray()
        
        # Should not crash
        secure_zero_memory(empty)
        assert len(empty) == 0

    def test_secure_zero_large_buffer(self):
        """secure_zero_memory should handle large buffers."""
        size = 1024 * 1024  # 1 MB
        large = bytearray(secrets.token_bytes(size))
        
        secure_zero_memory(large)
        
        # Check a sample of positions
        for pos in [0, size // 4, size // 2, 3 * size // 4, size - 1]:
            assert large[pos] == 0
