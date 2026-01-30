#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for frame_mac.py - Target: 90%+
Tests all frame MAC authentication paths.
"""

import pytest
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestDeriveFrameMasterKey:
    """Test derive_frame_master_key function."""
    
    def test_basic_derivation(self):
        """Test basic key derivation."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        encryption_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        master_key = derive_frame_master_key(encryption_key, salt)
        
        assert len(master_key) == 32
    
    def test_deterministic(self):
        """Test key derivation is deterministic."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        encryption_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(encryption_key, salt)
        key2 = derive_frame_master_key(encryption_key, salt)
        
        assert key1 == key2
    
    def test_different_keys_different_output(self):
        """Test different encryption keys give different output."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(secrets.token_bytes(32), salt)
        key2 = derive_frame_master_key(secrets.token_bytes(32), salt)
        
        assert key1 != key2
    
    def test_different_salts_different_output(self):
        """Test different salts give different output."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        encryption_key = secrets.token_bytes(32)
        
        key1 = derive_frame_master_key(encryption_key, secrets.token_bytes(16))
        key2 = derive_frame_master_key(encryption_key, secrets.token_bytes(16))
        
        assert key1 != key2


class TestDeriveFrameMasterKeyLegacy:
    """Test derive_frame_master_key_legacy function."""
    
    def test_basic_derivation(self):
        """Test basic legacy key derivation."""
        from meow_decoder.frame_mac import derive_frame_master_key_legacy
        
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        
        master_key = derive_frame_master_key_legacy(password, salt)
        
        assert len(master_key) == 32
    
    def test_deterministic(self):
        """Test legacy derivation is deterministic."""
        from meow_decoder.frame_mac import derive_frame_master_key_legacy
        
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key_legacy(password, salt)
        key2 = derive_frame_master_key_legacy(password, salt)
        
        assert key1 == key2
    
    def test_different_passwords(self):
        """Test different passwords give different keys."""
        from meow_decoder.frame_mac import derive_frame_master_key_legacy
        
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key_legacy("password1", salt)
        key2 = derive_frame_master_key_legacy("password2", salt)
        
        assert key1 != key2


class TestComputeFrameMAC:
    """Test compute_frame_mac function."""
    
    def test_basic_computation(self):
        """Test basic MAC computation."""
        from meow_decoder.frame_mac import compute_frame_mac
        
        master_key = secrets.token_bytes(32)
        data = b"frame_data_here"
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        mac = compute_frame_mac(master_key, data, frame_index, salt)
        
        assert len(mac) == 8  # Truncated HMAC
    
    def test_deterministic(self):
        """Test MAC computation is deterministic."""
        from meow_decoder.frame_mac import compute_frame_mac
        
        master_key = secrets.token_bytes(32)
        data = b"test_data"
        frame_index = 5
        salt = secrets.token_bytes(16)
        
        mac1 = compute_frame_mac(master_key, data, frame_index, salt)
        mac2 = compute_frame_mac(master_key, data, frame_index, salt)
        
        assert mac1 == mac2
    
    def test_different_data_different_mac(self):
        """Test different data gives different MAC."""
        from meow_decoder.frame_mac import compute_frame_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mac1 = compute_frame_mac(master_key, b"data1", 0, salt)
        mac2 = compute_frame_mac(master_key, b"data2", 0, salt)
        
        assert mac1 != mac2
    
    def test_different_index_different_mac(self):
        """Test different frame index gives different MAC."""
        from meow_decoder.frame_mac import compute_frame_mac
        
        master_key = secrets.token_bytes(32)
        data = b"same_data"
        salt = secrets.token_bytes(16)
        
        mac1 = compute_frame_mac(master_key, data, 0, salt)
        mac2 = compute_frame_mac(master_key, data, 1, salt)
        
        assert mac1 != mac2


class TestPackFrameWithMAC:
    """Test pack_frame_with_mac function."""
    
    def test_basic_packing(self):
        """Test basic frame packing."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        data = b"frame_data"
        master_key = secrets.token_bytes(32)
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_index, salt)
        
        # Should be MAC (8 bytes) + data
        assert len(packed) == 8 + len(data)
    
    def test_mac_at_start(self):
        """Test MAC is at start of packed frame."""
        from meow_decoder.frame_mac import pack_frame_with_mac, compute_frame_mac
        
        data = b"frame_data"
        master_key = secrets.token_bytes(32)
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_index, salt)
        expected_mac = compute_frame_mac(master_key, data, frame_index, salt)
        
        assert packed[:8] == expected_mac
    
    def test_data_after_mac(self):
        """Test data is after MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        data = b"test_frame_data"
        master_key = secrets.token_bytes(32)
        frame_index = 3
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_index, salt)
        
        assert packed[8:] == data


class TestUnpackFrameWithMAC:
    """Test unpack_frame_with_mac function."""
    
    def test_valid_frame(self):
        """Test unpacking valid frame."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        original_data = b"original_data"
        master_key = secrets.token_bytes(32)
        frame_index = 0
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(original_data, master_key, frame_index, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index, salt)
        
        assert valid is True
        assert unpacked == original_data
    
    def test_invalid_mac(self):
        """Test unpacking frame with wrong key."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"test_data"
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)  # Different key
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, key1, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, key2, 0, salt)
        
        assert valid is False
    
    def test_wrong_frame_index(self):
        """Test unpacking with wrong frame index."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"test_data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, 0, salt)
        valid, _ = unpack_frame_with_mac(packed, master_key, 1, salt)  # Wrong index
        
        assert valid is False
    
    def test_corrupted_data(self):
        """Test unpacking corrupted frame."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"test_data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, 0, salt)
        
        # Corrupt the data portion
        corrupted = packed[:8] + b"corrupted"
        
        valid, _ = unpack_frame_with_mac(corrupted, master_key, 0, salt)
        
        assert valid is False
    
    def test_too_short(self):
        """Test unpacking too short data."""
        from meow_decoder.frame_mac import unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        valid, _ = unpack_frame_with_mac(b"short", master_key, 0, salt)
        
        assert valid is False


class TestFrameMACRoundtrip:
    """Test frame MAC roundtrip."""
    
    def test_multiple_frames(self):
        """Test roundtrip with multiple frames."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        frames = [
            (0, b"manifest_data"),
            (1, b"droplet_1"),
            (2, b"droplet_2"),
            (3, b"droplet_3"),
        ]
        
        for idx, data in frames:
            packed = pack_frame_with_mac(data, master_key, idx, salt)
            valid, unpacked = unpack_frame_with_mac(packed, master_key, idx, salt)
            
            assert valid is True
            assert unpacked == data
    
    def test_binary_data(self):
        """Test roundtrip with binary data."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        data = secrets.token_bytes(500)
        
        packed = pack_frame_with_mac(data, master_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid is True
        assert unpacked == data


class TestFrameMACStats:
    """Test FrameMACStats class."""
    
    def test_creation(self):
        """Test creating stats."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        assert stats.valid_frames == 0
        assert stats.invalid_frames == 0
    
    def test_record_valid(self):
        """Test recording valid frame."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        stats.record_valid()
        stats.record_valid()
        
        assert stats.valid_frames == 2
    
    def test_record_invalid(self):
        """Test recording invalid frame."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        stats.record_invalid()
        stats.record_invalid()
        stats.record_invalid()
        
        assert stats.invalid_frames == 3
    
    def test_success_rate(self):
        """Test success rate calculation."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        stats.record_valid()
        stats.record_valid()
        stats.record_valid()
        stats.record_invalid()
        
        rate = stats.success_rate()
        
        assert rate == 0.75  # 3/4
    
    def test_success_rate_no_frames(self):
        """Test success rate with no frames."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        rate = stats.success_rate()
        
        assert rate == 0.0
    
    def test_success_rate_all_valid(self):
        """Test success rate with all valid."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        for _ in range(10):
            stats.record_valid()
        
        rate = stats.success_rate()
        
        assert rate == 1.0


class TestFrameMACEdgeCases:
    """Test edge cases."""
    
    def test_empty_data(self):
        """Test with empty data."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(b"", master_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid is True
        assert unpacked == b""
    
    def test_large_frame_index(self):
        """Test with large frame index."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(b"data", master_key, 1000000, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 1000000, salt)
        
        assert valid is True
        assert unpacked == b"data"
    
    def test_null_bytes_in_data(self):
        """Test with null bytes in data."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        data = b"\x00" * 50
        
        packed = pack_frame_with_mac(data, master_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid is True
        assert unpacked == data


class TestFrameMACIntegration:
    """Integration tests for frame MAC."""
    
    def test_with_crypto_key(self):
        """Test with key from crypto module."""
        from meow_decoder.frame_mac import derive_frame_master_key, pack_frame_with_mac, unpack_frame_with_mac
        from meow_decoder.crypto import derive_key
        
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        
        # Derive encryption key
        encryption_key = derive_key(password, salt)
        
        # Derive frame MAC key
        frame_key = derive_frame_master_key(encryption_key, salt)
        
        # Use for frames
        data = b"test_frame_data"
        packed = pack_frame_with_mac(data, frame_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, frame_key, 0, salt)
        
        assert valid is True
        assert unpacked == data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
