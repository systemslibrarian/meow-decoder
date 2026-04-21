#!/usr/bin/env python3
"""
🔒 Security Test Suite - Part 2 of 3: Frame MAC Invariants

Tests per-frame MAC integrity, replay protection, and salt binding.
Run consecutively with test_security_crypto.py and test_security_manifest.py.

1. Bit-flip detection
2. Frame index binding
3. Salt / session binding
4. Replay prevention across sessions
"""

from meow_decoder.frame_mac import (
    compute_frame_mac,
    verify_frame_mac,
    pack_frame_with_mac,
    unpack_frame_with_mac,
    FrameMACStats,
    MAC_SIZE,
    derive_frame_master_key,
)
from meow_decoder.crypto import derive_key
import secrets
import pytest

pytestmark = pytest.mark.security


# =============================================================================
# FRAME MAC SECURITY TESTS (5 tests)
# =============================================================================


class TestFrameMACSecurityInvariants:
    """Test frame MAC security invariants."""

    def test_frame_mac_detects_bit_flip(self):
        """Single bit flip in frame data should be detected."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)

        frame_data = b"This is test frame data for MAC verification"
        frame_idx = 5

        # Pack with MAC
        packed = pack_frame_with_mac(frame_data, master_key, frame_idx, salt)

        # Flip one bit in the data portion (after MAC)
        corrupted = bytearray(packed)
        corrupted[MAC_SIZE + 5] ^= 0x01  # Flip bit in data

        # Verification should fail
        is_valid, _ = unpack_frame_with_mac(bytes(corrupted), master_key, frame_idx, salt)
        assert is_valid is False

    def test_frame_mac_detects_wrong_frame_index(self):
        """Frame index mismatch should cause MAC verification to fail."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)

        frame_data = b"Test frame data"

        # Pack with frame index 5
        packed = pack_frame_with_mac(frame_data, master_key, 5, salt)

        # Try to verify with frame index 10 (should fail)
        is_valid, _ = unpack_frame_with_mac(packed, master_key, 10, salt)
        assert is_valid is False

    def test_frame_mac_detects_wrong_salt(self):
        """Wrong salt should cause MAC verification to fail."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        wrong_salt = secrets.token_bytes(16)

        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)
        wrong_master_key = derive_frame_master_key(enc_key, wrong_salt)

        frame_data = b"Test frame data"
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)

        # Verify with wrong key (derived from wrong salt)
        is_valid, _ = unpack_frame_with_mac(packed, wrong_master_key, 0, wrong_salt)
        assert is_valid is False

    def test_frame_mac_stats_tracks_invalid(self):
        """FrameMACStats should correctly track valid/invalid frames."""
        stats = FrameMACStats()

        # Record some valid and invalid
        for _ in range(10):
            stats.record_valid()
        for _ in range(5):
            stats.record_invalid()

        assert stats.valid_frames == 10
        assert stats.invalid_frames == 5
        assert abs(stats.success_rate() - 10 / 15) < 0.001

    def test_frame_mac_prevents_replay_different_salt(self):
        """Frame MAC from one session should not validate in another."""
        password = "testpass123"

        # Session 1
        salt1 = secrets.token_bytes(16)
        enc_key1 = derive_key(password, salt1)
        master_key1 = derive_frame_master_key(enc_key1, salt1)

        # Session 2 (different salt)
        salt2 = secrets.token_bytes(16)
        enc_key2 = derive_key(password, salt2)
        master_key2 = derive_frame_master_key(enc_key2, salt2)

        frame_data = b"Test frame data"
        packed_session1 = pack_frame_with_mac(frame_data, master_key1, 0, salt1)

        # Try to verify session 1 MAC with session 2 key
        is_valid, _ = unpack_frame_with_mac(packed_session1, master_key2, 0, salt2)
        assert is_valid is False
