#!/usr/bin/env python3
"""
🔒 TIER 1: Frame MAC Authentication Tests

Tests for per-frame MAC authentication (DoS protection).
These tests verify:

1. Frame MACs are computed correctly
2. Valid MACs pass verification
3. Tampered frames are rejected
4. Wrong key produces invalid MACs
5. Frame ordering is protected
6. Replay attacks are prevented

SECURITY PRINCIPLE: Every frame must be authenticated
before processing to prevent DoS via malicious frames.
"""

import pytest
import secrets
import hashlib

from meow_decoder.frame_mac import (
    derive_frame_master_key,
    pack_frame_with_mac,
    unpack_frame_with_mac,
    FrameMACStats,
)


class TestFrameMACDerivation:
    """Test frame MAC key derivation."""
    
    def test_derive_frame_key_deterministic(self):
        """Same inputs must produce same frame key."""
        encryption_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(encryption_key, salt)
        key2 = derive_frame_master_key(encryption_key, salt)
        
        assert key1 == key2
        
    def test_derive_frame_key_length(self):
        """Frame key must be 32 bytes."""
        encryption_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key = derive_frame_master_key(encryption_key, salt)
        assert len(key) == 32
        
    def test_different_encryption_keys_different_frame_keys(self):
        """Different encryption keys must produce different frame keys."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(secrets.token_bytes(32), salt)
        key2 = derive_frame_master_key(secrets.token_bytes(32), salt)
        
        assert key1 != key2
        
    def test_different_salts_different_frame_keys(self):
        """Different salts must produce different frame keys."""
        encryption_key = secrets.token_bytes(32)
        
        key1 = derive_frame_master_key(encryption_key, secrets.token_bytes(16))
        key2 = derive_frame_master_key(encryption_key, secrets.token_bytes(16))
        
        assert key1 != key2


class TestFrameMACPackUnpack:
    """Test frame MAC packing and unpacking."""
    
    def test_pack_unpack_roundtrip(self):
        """Frame data must round-trip through pack/unpack."""
        frame_data = b"Test frame data for MAC verification"
        master_key = secrets.token_bytes(32)
        frame_index = 42
        salt = secrets.token_bytes(16)
        
        # Pack
        packed = pack_frame_with_mac(frame_data, master_key, frame_index, salt)
        
        # Unpack
        valid, recovered = unpack_frame_with_mac(packed, master_key, frame_index, salt)
        
        assert valid == True
        assert recovered == frame_data
        
    def test_mac_adds_8_bytes(self):
        """MAC should add 8 bytes to frame."""
        frame_data = b"Test data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        
        assert len(packed) == len(frame_data) + 8
        
    def test_empty_frame_works(self):
        """Empty frame should still work with MAC."""
        frame_data = b""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        valid, recovered = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid == True
        assert recovered == b""


class TestFrameMACValidation:
    """Test frame MAC validation (security tests)."""
    
    def test_wrong_key_rejected(self):
        """Wrong master key must cause validation failure."""
        frame_data = b"Sensitive frame data"
        correct_key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, correct_key, 0, salt)
        valid, _ = unpack_frame_with_mac(packed, wrong_key, 0, salt)
        
        assert valid == False
        
    def test_wrong_frame_index_rejected(self):
        """Wrong frame index must cause validation failure."""
        frame_data = b"Frame data with index binding"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Pack with frame index 0
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        
        # Try to unpack with frame index 1
        valid, _ = unpack_frame_with_mac(packed, master_key, 1, salt)
        
        assert valid == False
        
    def test_wrong_salt_rejected(self):
        """Wrong salt must cause validation failure."""
        frame_data = b"Frame data with salt binding"
        master_key = secrets.token_bytes(32)
        correct_salt = secrets.token_bytes(16)
        wrong_salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, correct_salt)
        valid, _ = unpack_frame_with_mac(packed, master_key, 0, wrong_salt)
        
        assert valid == False
        
    def test_tampered_data_rejected(self):
        """Tampered frame data must cause validation failure."""
        frame_data = b"Original frame data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        
        # Tamper with data portion (after 8-byte MAC)
        tampered = bytearray(packed)
        tampered[10] ^= 0xFF
        tampered = bytes(tampered)
        
        valid, _ = unpack_frame_with_mac(tampered, master_key, 0, salt)
        
        assert valid == False
        
    def test_tampered_mac_rejected(self):
        """Tampered MAC must cause validation failure."""
        frame_data = b"Frame data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        
        # Tamper with MAC (first 8 bytes)
        tampered = bytearray(packed)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)
        
        valid, _ = unpack_frame_with_mac(tampered, master_key, 0, salt)
        
        assert valid == False


class TestFrameIndexProtection:
    """Test that frame indices are protected."""
    
    def test_each_frame_has_unique_mac(self):
        """Different frame indices must produce different MACs."""
        frame_data = b"Same data for all frames"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        macs = set()
        for i in range(10):
            packed = pack_frame_with_mac(frame_data, master_key, i, salt)
            mac = packed[:8]
            macs.add(mac)
            
        # All 10 MACs should be unique
        assert len(macs) == 10
        
    def test_frame_reordering_detected(self):
        """Swapping frame positions must be detected."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        frame0_data = b"Frame 0 content"
        frame1_data = b"Frame 1 content"
        
        packed0 = pack_frame_with_mac(frame0_data, master_key, 0, salt)
        packed1 = pack_frame_with_mac(frame1_data, master_key, 1, salt)
        
        # Try to validate frame0's data at position 1
        valid, _ = unpack_frame_with_mac(packed0, master_key, 1, salt)
        assert valid == False
        
        # Try to validate frame1's data at position 0
        valid, _ = unpack_frame_with_mac(packed1, master_key, 0, salt)
        assert valid == False


class TestFrameMACStats:
    """Test frame MAC statistics tracking."""
    
    def test_stats_initial_state(self):
        """Stats should start at zero."""
        stats = FrameMACStats()
        
        assert stats.valid_frames == 0
        assert stats.invalid_frames == 0
        
    def test_stats_track_valid(self):
        """Valid frame count should increment."""
        stats = FrameMACStats()
        
        stats.record_valid()
        stats.record_valid()
        stats.record_valid()
        
        assert stats.valid_frames == 3
        assert stats.invalid_frames == 0
        
    def test_stats_track_invalid(self):
        """Invalid frame count should increment."""
        stats = FrameMACStats()
        
        stats.record_invalid()
        stats.record_invalid()
        
        assert stats.valid_frames == 0
        assert stats.invalid_frames == 2
        
    def test_stats_success_rate(self):
        """Success rate calculation should be correct."""
        stats = FrameMACStats()
        
        # 8 valid, 2 invalid = 80% success
        for _ in range(8):
            stats.record_valid()
        for _ in range(2):
            stats.record_invalid()
            
        rate = stats.success_rate()
        assert rate == pytest.approx(0.8)
        
    def test_stats_success_rate_all_valid(self):
        """All valid should give 100% success rate."""
        stats = FrameMACStats()
        
        for _ in range(10):
            stats.record_valid()
            
        rate = stats.success_rate()
        assert rate == pytest.approx(1.0)
        
    def test_stats_success_rate_none(self):
        """No frames should give 0% success rate."""
        stats = FrameMACStats()
        
        rate = stats.success_rate()
        assert rate == pytest.approx(0.0)


class TestEdgeCases:
    """Test edge cases for frame MAC."""
    
    def test_large_frame_index(self):
        """Large frame indices should work."""
        frame_data = b"Test data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        large_index = 2**31 - 1
        
        packed = pack_frame_with_mac(frame_data, master_key, large_index, salt)
        valid, recovered = unpack_frame_with_mac(packed, master_key, large_index, salt)
        
        assert valid == True
        assert recovered == frame_data
        
    def test_binary_data_in_frame(self):
        """Binary data with all byte values should work."""
        frame_data = bytes(range(256))
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        valid, recovered = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid == True
        assert recovered == frame_data
        
    def test_short_packed_data_rejected(self):
        """Packed data shorter than MAC should fail safely."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Data shorter than 8 bytes (MAC size)
        short_data = b"short"
        
        valid, _ = unpack_frame_with_mac(short_data, master_key, 0, salt)
        
        # Should return False, not crash
        assert valid == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
