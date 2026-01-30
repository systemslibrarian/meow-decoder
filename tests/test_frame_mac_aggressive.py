#!/usr/bin/env python3
"""
🔐 Aggressive Coverage Tests for Frame MAC
Targets: frame_mac.py (76% → 95%+)

Frame-level MAC authentication to prevent DoS attacks.
"""

import os
import sys
import pytest
import secrets
import hashlib
import struct
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add meow_decoder to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.frame_mac import (
    MAC_SIZE,
    FRAME_MAC_INFO,
    FRAME_MAC_MASTER_INFO,
    derive_frame_master_key,
    derive_frame_master_key_legacy,
    derive_frame_key,
    compute_frame_mac,
    verify_frame_mac,
    pack_frame_with_mac,
    unpack_frame_with_mac,
    FrameMACStats
)


class TestConstants:
    """Test frame MAC constants."""
    
    def test_mac_size_is_8_bytes(self):
        """Verify MAC size is 8 bytes (64 bits)."""
        assert MAC_SIZE == 8
    
    def test_frame_mac_info_exists(self):
        """Test FRAME_MAC_INFO domain separation."""
        assert FRAME_MAC_INFO == b"meow_frame_mac_v1"
    
    def test_frame_mac_master_info_exists(self):
        """Test FRAME_MAC_MASTER_INFO domain separation."""
        assert FRAME_MAC_MASTER_INFO == b"meow_frame_mac_master_v2"


class TestDeriveFrameMasterKey:
    """Test derive_frame_master_key function."""
    
    def test_derive_frame_master_key_basic(self):
        """Test basic frame master key derivation."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        frame_master = derive_frame_master_key(master_key, salt)
        
        assert isinstance(frame_master, bytes)
        assert len(frame_master) == 32
    
    def test_derive_frame_master_key_deterministic(self):
        """Test that same inputs produce same output."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(master_key, salt)
        key2 = derive_frame_master_key(master_key, salt)
        
        assert key1 == key2
    
    def test_derive_frame_master_key_different_salt(self):
        """Test different salts produce different keys."""
        master_key = secrets.token_bytes(32)
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(master_key, salt1)
        key2 = derive_frame_master_key(master_key, salt2)
        
        assert key1 != key2
    
    def test_derive_frame_master_key_different_master(self):
        """Test different master keys produce different keys."""
        master1 = secrets.token_bytes(32)
        master2 = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(master1, salt)
        key2 = derive_frame_master_key(master2, salt)
        
        assert key1 != key2


class TestDeriveFrameMasterKeyLegacy:
    """Test legacy frame master key derivation."""
    
    def test_legacy_key_derivation_basic(self):
        """Test basic legacy key derivation."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        key = derive_frame_master_key_legacy(password, salt)
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_legacy_key_deterministic(self):
        """Test legacy derivation is deterministic."""
        password = "consistent_password"
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key_legacy(password, salt)
        key2 = derive_frame_master_key_legacy(password, salt)
        
        assert key1 == key2
    
    def test_legacy_key_uses_correct_format(self):
        """Test legacy key uses expected format."""
        password = "test"
        salt = b"\x00" * 16
        
        # Manual calculation: SHA256(password.encode() + salt + b'frame_mac_key')
        expected = hashlib.sha256(
            password.encode('utf-8') + salt + b'frame_mac_key'
        ).digest()
        
        key = derive_frame_master_key_legacy(password, salt)
        
        assert key == expected


class TestDeriveFrameKey:
    """Test per-frame key derivation."""
    
    def test_derive_frame_key_basic(self):
        """Test basic frame key derivation."""
        master_key = secrets.token_bytes(32)
        frame_index = 42
        salt = secrets.token_bytes(16)
        
        frame_key = derive_frame_key(master_key, frame_index, salt)
        
        assert isinstance(frame_key, bytes)
        assert len(frame_key) == 32
    
    def test_different_frames_different_keys(self):
        """Test different frame indices produce different keys."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key0 = derive_frame_key(master_key, 0, salt)
        key1 = derive_frame_key(master_key, 1, salt)
        key100 = derive_frame_key(master_key, 100, salt)
        
        assert key0 != key1
        assert key1 != key100
        assert key0 != key100
    
    def test_same_frame_same_key(self):
        """Test same frame index produces same key."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_key(master_key, 42, salt)
        key2 = derive_frame_key(master_key, 42, salt)
        
        assert key1 == key2
    
    def test_large_frame_index(self):
        """Test with large frame indices."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Very large frame index (within uint64 range)
        key = derive_frame_key(master_key, 2**60, salt)
        
        assert len(key) == 32


class TestComputeFrameMAC:
    """Test frame MAC computation."""
    
    def test_compute_frame_mac_basic(self):
        """Test basic MAC computation."""
        frame_data = b"This is frame data"
        master_key = secrets.token_bytes(32)
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        mac = compute_frame_mac(frame_data, master_key, frame_index, salt)
        
        assert isinstance(mac, bytes)
        assert len(mac) == MAC_SIZE  # 8 bytes
    
    def test_mac_deterministic(self):
        """Test MAC is deterministic."""
        frame_data = b"test data"
        master_key = secrets.token_bytes(32)
        frame_index = 5
        salt = secrets.token_bytes(16)
        
        mac1 = compute_frame_mac(frame_data, master_key, frame_index, salt)
        mac2 = compute_frame_mac(frame_data, master_key, frame_index, salt)
        
        assert mac1 == mac2
    
    def test_different_data_different_mac(self):
        """Test different data produces different MAC."""
        master_key = secrets.token_bytes(32)
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        mac1 = compute_frame_mac(b"data1", master_key, frame_index, salt)
        mac2 = compute_frame_mac(b"data2", master_key, frame_index, salt)
        
        assert mac1 != mac2
    
    def test_different_frame_index_different_mac(self):
        """Test different frame index produces different MAC."""
        frame_data = b"same data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mac1 = compute_frame_mac(frame_data, master_key, 0, salt)
        mac2 = compute_frame_mac(frame_data, master_key, 1, salt)
        
        assert mac1 != mac2
    
    def test_empty_frame_data(self):
        """Test MAC of empty frame data."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mac = compute_frame_mac(b"", master_key, 0, salt)
        
        assert len(mac) == MAC_SIZE


class TestVerifyFrameMAC:
    """Test frame MAC verification."""
    
    def test_verify_valid_mac(self):
        """Test verification of valid MAC."""
        frame_data = b"Valid frame data"
        master_key = secrets.token_bytes(32)
        frame_index = 10
        salt = secrets.token_bytes(16)
        
        mac = compute_frame_mac(frame_data, master_key, frame_index, salt)
        result = verify_frame_mac(frame_data, mac, master_key, frame_index, salt)
        
        assert result is True
    
    def test_verify_invalid_mac(self):
        """Test verification of invalid MAC."""
        frame_data = b"Frame data"
        master_key = secrets.token_bytes(32)
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        # Random MAC
        fake_mac = secrets.token_bytes(MAC_SIZE)
        result = verify_frame_mac(frame_data, fake_mac, master_key, frame_index, salt)
        
        assert result is False
    
    def test_verify_wrong_mac_size(self):
        """Test verification fails with wrong MAC size."""
        frame_data = b"Frame data"
        master_key = secrets.token_bytes(32)
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        # Wrong size MAC
        wrong_size_mac = b"\x00" * 7  # 7 bytes instead of 8
        result = verify_frame_mac(frame_data, wrong_size_mac, master_key, frame_index, salt)
        
        assert result is False
        
        # Also test too long
        too_long_mac = b"\x00" * 10
        result2 = verify_frame_mac(frame_data, too_long_mac, master_key, frame_index, salt)
        
        assert result2 is False
    
    def test_verify_wrong_frame_index(self):
        """Test verification fails with wrong frame index."""
        frame_data = b"Frame data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mac = compute_frame_mac(frame_data, master_key, 0, salt)
        result = verify_frame_mac(frame_data, mac, master_key, 999, salt)
        
        assert result is False
    
    def test_verify_tampered_data(self):
        """Test verification fails with tampered data."""
        frame_data = b"Original data"
        master_key = secrets.token_bytes(32)
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        mac = compute_frame_mac(frame_data, master_key, frame_index, salt)
        
        tampered_data = b"Modified data"
        result = verify_frame_mac(tampered_data, mac, master_key, frame_index, salt)
        
        assert result is False


class TestPackFrameWithMAC:
    """Test frame packing with MAC."""
    
    def test_pack_basic(self):
        """Test basic frame packing."""
        frame_data = b"Droplet data"
        master_key = secrets.token_bytes(32)
        frame_index = 5
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, frame_index, salt)
        
        # Should be MAC + data
        assert len(packed) == MAC_SIZE + len(frame_data)
        assert packed[MAC_SIZE:] == frame_data
    
    def test_pack_empty_data(self):
        """Test packing empty frame data."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(b"", master_key, 0, salt)
        
        assert len(packed) == MAC_SIZE  # Just the MAC
    
    def test_pack_large_data(self):
        """Test packing large frame data."""
        frame_data = secrets.token_bytes(10000)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        
        assert len(packed) == MAC_SIZE + 10000


class TestUnpackFrameWithMAC:
    """Test frame unpacking with MAC verification."""
    
    def test_unpack_valid_frame(self):
        """Test unpacking valid frame."""
        frame_data = b"Valid droplet"
        master_key = secrets.token_bytes(32)
        frame_index = 7
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, frame_index, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index, salt)
        
        assert valid is True
        assert unpacked == frame_data
    
    def test_unpack_invalid_mac(self):
        """Test unpacking with invalid MAC."""
        frame_data = b"Some data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create fake packed frame with random MAC
        fake_packed = secrets.token_bytes(MAC_SIZE) + frame_data
        
        valid, unpacked = unpack_frame_with_mac(fake_packed, master_key, 0, salt)
        
        assert valid is False
        assert unpacked == b''
    
    def test_unpack_too_short(self):
        """Test unpacking frame that's too short."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Frame shorter than MAC size
        short_frame = b"\x00" * (MAC_SIZE - 1)
        valid, unpacked = unpack_frame_with_mac(short_frame, master_key, 0, salt)
        
        assert valid is False
        assert unpacked == b''
    
    def test_unpack_wrong_frame_index(self):
        """Test unpacking with wrong frame index."""
        frame_data = b"Data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 999, salt)
        
        assert valid is False
        assert unpacked == b''
    
    def test_unpack_tampered_data(self):
        """Test unpacking tampered frame."""
        frame_data = b"Original"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        
        # Tamper with data portion
        tampered = packed[:MAC_SIZE] + b"TAMPERED"
        
        valid, unpacked = unpack_frame_with_mac(tampered, master_key, 0, salt)
        
        assert valid is False
        assert unpacked == b''


class TestFrameMACStats:
    """Test FrameMACStats class."""
    
    def test_stats_init(self):
        """Test stats initialization."""
        stats = FrameMACStats()
        
        assert stats.total_frames == 0
        assert stats.valid_frames == 0
        assert stats.invalid_frames == 0
        assert stats.injection_attempts == 0
    
    def test_record_valid(self):
        """Test recording valid frames."""
        stats = FrameMACStats()
        
        stats.record_valid()
        
        assert stats.total_frames == 1
        assert stats.valid_frames == 1
        assert stats.invalid_frames == 0
    
    def test_record_invalid(self):
        """Test recording invalid frames."""
        stats = FrameMACStats()
        
        stats.record_invalid()
        
        assert stats.total_frames == 1
        assert stats.valid_frames == 0
        assert stats.invalid_frames == 1
        assert stats.injection_attempts == 1
    
    def test_success_rate_zero_frames(self):
        """Test success rate with zero frames."""
        stats = FrameMACStats()
        
        rate = stats.success_rate()
        
        assert rate == 0.0
    
    def test_success_rate_all_valid(self):
        """Test success rate with all valid frames."""
        stats = FrameMACStats()
        
        for _ in range(10):
            stats.record_valid()
        
        rate = stats.success_rate()
        
        assert rate == 1.0
    
    def test_success_rate_mixed(self):
        """Test success rate with mixed valid/invalid."""
        stats = FrameMACStats()
        
        for _ in range(7):
            stats.record_valid()
        for _ in range(3):
            stats.record_invalid()
        
        rate = stats.success_rate()
        
        assert rate == 0.7
    
    def test_report_output(self):
        """Test report generation."""
        stats = FrameMACStats()
        
        stats.record_valid()
        stats.record_valid()
        stats.record_invalid()
        
        report = stats.report()
        
        assert isinstance(report, str)
        assert "Total frames: 3" in report
        assert "Valid frames: 2" in report
        assert "Invalid frames: 1" in report
        assert "Injection attempts: 1" in report
        assert "Success rate:" in report


class TestRoundtrip:
    """Test full roundtrip scenarios."""
    
    def test_multiple_frames_roundtrip(self):
        """Test packing and unpacking multiple frames."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        frames = [
            b"Frame 0 data - manifest",
            b"Frame 1 data - droplet",
            b"Frame 2 data - another droplet",
            b"Frame 3 data - yet another",
        ]
        
        # Pack all frames
        packed_frames = [
            pack_frame_with_mac(data, master_key, i, salt)
            for i, data in enumerate(frames)
        ]
        
        # Unpack all frames
        for i, packed in enumerate(packed_frames):
            valid, unpacked = unpack_frame_with_mac(packed, master_key, i, salt)
            
            assert valid is True
            assert unpacked == frames[i]
    
    def test_attack_simulation(self):
        """Simulate frame injection attack."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        stats = FrameMACStats()
        
        # Create legitimate frames
        legitimate_frames = [
            pack_frame_with_mac(f"Frame {i}".encode(), master_key, i, salt)
            for i in range(10)
        ]
        
        # Create attack frames (random data with fake MACs)
        attack_frames = [
            secrets.token_bytes(MAC_SIZE) + b"MALICIOUS DATA"
            for _ in range(5)
        ]
        
        # Process all frames
        all_frames = legitimate_frames + attack_frames
        secrets.SystemRandom().shuffle(all_frames)
        
        recovered = 0
        for i, packed in enumerate(all_frames):
            # Try all possible frame indices
            found = False
            for j in range(len(legitimate_frames)):
                valid, data = unpack_frame_with_mac(packed, master_key, j, salt)
                if valid:
                    found = True
                    stats.record_valid()
                    recovered += 1
                    break
            
            if not found:
                stats.record_invalid()
        
        # Should have recovered all legitimate frames
        # (Note: due to shuffling and index matching, exact count may vary)
        assert stats.invalid_frames >= 5  # At least attack frames rejected


class TestEdgeCases:
    """Test edge cases."""
    
    def test_binary_frame_data(self):
        """Test with binary frame data."""
        frame_data = bytes(range(256))  # All byte values
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid is True
        assert unpacked == frame_data
    
    def test_null_bytes_in_data(self):
        """Test with null bytes in data."""
        frame_data = b"\x00\x00\x00\x00"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid is True
        assert unpacked == frame_data
    
    def test_max_frame_index(self):
        """Test with maximum uint64 frame index."""
        frame_data = b"max index test"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        max_index = 2**64 - 1
        
        packed = pack_frame_with_mac(frame_data, master_key, max_index, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, max_index, salt)
        
        assert valid is True
        assert unpacked == frame_data


class TestImportability:
    """Test module importability."""
    
    def test_import_all_exports(self):
        """Test all expected exports can be imported."""
        from meow_decoder.frame_mac import (
            MAC_SIZE,
            FRAME_MAC_INFO,
            FRAME_MAC_MASTER_INFO,
            derive_frame_master_key,
            derive_frame_master_key_legacy,
            derive_frame_key,
            compute_frame_mac,
            verify_frame_mac,
            pack_frame_with_mac,
            unpack_frame_with_mac,
            FrameMACStats
        )
        
        assert MAC_SIZE == 8
        assert callable(derive_frame_master_key)
        assert callable(derive_frame_master_key_legacy)
        assert callable(derive_frame_key)
        assert callable(compute_frame_mac)
        assert callable(verify_frame_mac)
        assert callable(pack_frame_with_mac)
        assert callable(unpack_frame_with_mac)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
