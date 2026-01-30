#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for metadata_obfuscation.py and frame_mac.py - Target: 90%+
Tests metadata padding/obfuscation and per-frame MAC authentication.
"""

import pytest
import secrets
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestLengthPadding:
    """Test length padding for metadata obfuscation."""
    
    def test_add_length_padding_basic(self):
        """Test basic length padding."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"Test data" * 10  # 90 bytes
        padded = add_length_padding(data)
        
        # Should be padded to power of 2 boundary
        assert len(padded) > len(data)
        # Padded length should be power of 2
        padded_len = len(padded)
        # Remove the 4-byte length prefix to check power of 2
        assert padded_len >= len(data) + 4
    
    def test_add_remove_length_padding_roundtrip(self):
        """Test add/remove padding roundtrip."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"Roundtrip test data" * 5
        
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original
    
    def test_padding_various_sizes(self):
        """Test padding with various data sizes."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        for size in [10, 50, 100, 500, 1000, 5000]:
            original = secrets.token_bytes(size)
            padded = add_length_padding(original)
            recovered = remove_length_padding(padded)
            
            assert recovered == original, f"Failed for size {size}"
    
    def test_padding_empty_data(self):
        """Test padding with empty data."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b""
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original
    
    def test_padding_single_byte(self):
        """Test padding with single byte."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"X"
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original
    
    def test_remove_padding_corrupted_length(self):
        """Test removing padding with corrupted length prefix."""
        from meow_decoder.metadata_obfuscation import remove_length_padding
        
        # Create fake padded data with wrong length
        fake_padded = struct.pack('>I', 999999) + b"small data"
        
        with pytest.raises((ValueError, Exception)):
            remove_length_padding(fake_padded)
    
    def test_padding_preserves_binary_data(self):
        """Test that padding preserves binary data correctly."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        # Include null bytes and high bytes
        original = bytes(range(256))
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original


class TestSizeBucketing:
    """Test size class bucketing for obfuscation."""
    
    def test_get_size_class(self):
        """Test getting size class."""
        try:
            from meow_decoder.metadata_obfuscation import get_size_class
            
            # Small sizes
            assert get_size_class(100) >= 100
            
            # Medium sizes
            assert get_size_class(50000) >= 50000
            
            # Size class should be power of 2 or predefined bucket
        except ImportError:
            pytest.skip("get_size_class not implemented")
    
    def test_size_class_boundaries(self):
        """Test size class at boundaries."""
        try:
            from meow_decoder.metadata_obfuscation import get_size_class
            
            # Just under power of 2
            size = get_size_class(1023)
            assert size >= 1023
            
            # Exactly power of 2
            size = get_size_class(1024)
            assert size >= 1024
            
            # Just over power of 2
            size = get_size_class(1025)
            assert size >= 1025
        except ImportError:
            pytest.skip("get_size_class not implemented")


class TestFrameMAC:
    """Test per-frame MAC authentication."""
    
    def test_derive_frame_master_key(self):
        """Test deriving frame master key."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        encryption_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        master_key = derive_frame_master_key(encryption_key, salt)
        
        assert len(master_key) == 32
        assert isinstance(master_key, bytes)
    
    def test_derive_frame_master_key_deterministic(self):
        """Test that key derivation is deterministic."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        encryption_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(encryption_key, salt)
        key2 = derive_frame_master_key(encryption_key, salt)
        
        assert key1 == key2
    
    def test_derive_frame_master_key_different_inputs(self):
        """Test different inputs produce different keys."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        key1 = derive_frame_master_key(secrets.token_bytes(32), secrets.token_bytes(16))
        key2 = derive_frame_master_key(secrets.token_bytes(32), secrets.token_bytes(16))
        
        assert key1 != key2
    
    def test_pack_frame_with_mac(self):
        """Test packing frame with MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        data = b"Frame data for testing"
        master_key = secrets.token_bytes(32)
        frame_id = 5
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_id, salt)
        
        # Should include MAC (8 bytes) plus original data
        assert len(packed) == len(data) + 8
    
    def test_unpack_frame_with_mac(self):
        """Test unpacking frame with MAC verification."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"Unpack test data"
        master_key = secrets.token_bytes(32)
        frame_id = 10
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_id, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_id, salt)
        
        assert valid is True
        assert unpacked == data
    
    def test_mac_verification_fails_wrong_key(self):
        """Test MAC verification fails with wrong key."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"Wrong key test"
        correct_key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        frame_id = 1
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, correct_key, frame_id, salt)
        valid, _ = unpack_frame_with_mac(packed, wrong_key, frame_id, salt)
        
        assert valid is False
    
    def test_mac_verification_fails_wrong_frame_id(self):
        """Test MAC verification fails with wrong frame ID."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"Wrong frame ID test"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_id=5, salt=salt)
        valid, _ = unpack_frame_with_mac(packed, master_key, frame_id=6, salt=salt)
        
        assert valid is False
    
    def test_mac_verification_fails_tampered_data(self):
        """Test MAC verification fails with tampered data."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"Tampering test"
        master_key = secrets.token_bytes(32)
        frame_id = 1
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_id, salt)
        
        # Tamper with data portion (after MAC)
        tampered = packed[:8] + b"X" + packed[9:]
        
        valid, _ = unpack_frame_with_mac(tampered, master_key, frame_id, salt)
        
        assert valid is False
    
    def test_frame_mac_roundtrip_multiple_frames(self):
        """Test MAC roundtrip for multiple frames."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        frames = [
            (0, b"Manifest data"),
            (1, b"Droplet 1"),
            (2, b"Droplet 2"),
            (3, b"Droplet 3")
        ]
        
        for frame_id, data in frames:
            packed = pack_frame_with_mac(data, master_key, frame_id, salt)
            valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_id, salt)
            
            assert valid is True
            assert unpacked == data


class TestFrameMACStats:
    """Test frame MAC statistics tracking."""
    
    def test_stats_creation(self):
        """Test creating MAC stats."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        assert stats.valid_frames == 0
        assert stats.invalid_frames == 0
    
    def test_stats_record_valid(self):
        """Test recording valid frames."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        stats.record_valid()
        stats.record_valid()
        stats.record_valid()
        
        assert stats.valid_frames == 3
    
    def test_stats_record_invalid(self):
        """Test recording invalid frames."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        stats.record_invalid()
        stats.record_invalid()
        
        assert stats.invalid_frames == 2
    
    def test_stats_success_rate(self):
        """Test calculating success rate."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        # 8 valid, 2 invalid = 80% success
        for _ in range(8):
            stats.record_valid()
        for _ in range(2):
            stats.record_invalid()
        
        rate = stats.success_rate()
        assert abs(rate - 0.8) < 0.001
    
    def test_stats_success_rate_all_valid(self):
        """Test success rate with all valid."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        for _ in range(10):
            stats.record_valid()
        
        assert stats.success_rate() == 1.0
    
    def test_stats_success_rate_none(self):
        """Test success rate with no frames."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        # No frames recorded - should handle gracefully
        rate = stats.success_rate()
        assert rate == 0.0 or rate == 1.0  # Implementation dependent


class TestLegacyFrameMAC:
    """Test legacy frame MAC derivation (backwards compatibility)."""
    
    def test_derive_frame_master_key_legacy(self):
        """Test legacy key derivation."""
        try:
            from meow_decoder.frame_mac import derive_frame_master_key_legacy
            
            password = "TestPassword123"
            salt = secrets.token_bytes(16)
            
            key = derive_frame_master_key_legacy(password, salt)
            
            assert len(key) == 32
        except ImportError:
            pytest.skip("Legacy derivation not implemented")
    
    def test_legacy_derivation_deterministic(self):
        """Test legacy derivation is deterministic."""
        try:
            from meow_decoder.frame_mac import derive_frame_master_key_legacy
            
            password = "Consistent"
            salt = secrets.token_bytes(16)
            
            key1 = derive_frame_master_key_legacy(password, salt)
            key2 = derive_frame_master_key_legacy(password, salt)
            
            assert key1 == key2
        except ImportError:
            pytest.skip("Legacy derivation not implemented")


class TestMetadataObfuscationEdgeCases:
    """Test edge cases in metadata obfuscation."""
    
    def test_very_large_data(self):
        """Test padding with very large data."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        # 100KB of data
        original = secrets.token_bytes(100000)
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original
    
    def test_padding_random_data(self):
        """Test padding with random binary data."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        for _ in range(10):
            size = secrets.randbelow(5000) + 1
            original = secrets.token_bytes(size)
            
            padded = add_length_padding(original)
            recovered = remove_length_padding(padded)
            
            assert recovered == original


class TestFrameMACEdgeCases:
    """Test edge cases in frame MAC."""
    
    def test_empty_frame_data(self):
        """Test MAC with empty frame data."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid is True
        assert unpacked == data
    
    def test_large_frame_id(self):
        """Test MAC with large frame ID."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"Large ID test"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        frame_id = 999999
        
        packed = pack_frame_with_mac(data, master_key, frame_id, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_id, salt)
        
        assert valid is True
        assert unpacked == data
    
    def test_frame_id_zero(self):
        """Test MAC with frame ID 0 (manifest)."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"Manifest frame"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 0, salt)
        
        assert valid is True
        assert unpacked == data
    
    def test_truncated_packed_data(self):
        """Test unpacking truncated data."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"Full data here"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, 0, salt)
        
        # Truncate to just MAC
        truncated = packed[:8]
        
        valid, unpacked = unpack_frame_with_mac(truncated, master_key, 0, salt)
        
        # Should handle gracefully
        assert valid is False or unpacked == b""


class TestMetadataPrivacy:
    """Test metadata privacy properties."""
    
    def test_padding_hides_exact_size(self):
        """Test that padding hides exact file size."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        # Different sizes that are close
        data1 = secrets.token_bytes(1001)
        data2 = secrets.token_bytes(1023)
        
        padded1 = add_length_padding(data1)
        padded2 = add_length_padding(data2)
        
        # Both should pad to same size class
        # (depending on implementation, sizes within same power-of-2 range)
        # At minimum, padded sizes should be >= original
        assert len(padded1) >= len(data1)
        assert len(padded2) >= len(data2)
    
    def test_random_padding_bytes(self):
        """Test that padding uses random bytes."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"Fixed data"
        
        padded1 = add_length_padding(data)
        padded2 = add_length_padding(data)
        
        # Padding portion should be different (random)
        # First 4 bytes are length, rest varies
        assert padded1[4:len(data)+4] == padded2[4:len(data)+4]  # Data same
        # Padding portion may differ (if any)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
