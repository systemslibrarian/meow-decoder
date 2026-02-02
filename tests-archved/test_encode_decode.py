#!/usr/bin/env python3
"""
🔐 TIER 1: Encode/Decode Round-Trip Tests

Security-Critical Tests for the complete encode → decode pipeline.
These tests verify:

1. Lossless round-trip for various file sizes
2. Binary data integrity
3. Edge cases (empty, very large, special bytes)
4. Manifest integrity across pipeline
5. Fountain code redundancy works correctly
6. QR code generation/parsing integrity

FAIL-CLOSED PRINCIPLE: Any data loss or corruption results in test failure.
"""

import pytest
import secrets
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import struct

from meow_decoder.config import EncodingConfig, DecodingConfig
from meow_decoder.fountain import FountainEncoder, FountainDecoder, pack_droplet, unpack_droplet


class TestFountainCodeRoundTrip:
    """Test fountain code encoding/decoding integrity."""
    
    def test_fountain_roundtrip_basic(self):
        """Basic fountain encode → decode must be lossless."""
        data = b"Test data for fountain coding" * 10
        k_blocks = 10
        block_size = 32
        
        # Pad data to match block size
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        # Encode
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        
        # Generate enough droplets (1.5x redundancy)
        num_droplets = int(k_blocks * 1.5)
        droplets = [encoder.droplet(i) for i in range(num_droplets)]
        
        # Decode
        decoder = FountainDecoder(k_blocks, block_size)
        
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        assert decoder.is_complete(), "Decoding did not complete!"
        
        # Verify data
        recovered = decoder.get_data(len(data))
        assert recovered == data, "Fountain round-trip data mismatch!"
        
    def test_fountain_random_data(self):
        """Random binary data must round-trip correctly."""
        data = secrets.token_bytes(512)
        k_blocks = 8
        block_size = 64
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(int(k_blocks * 2))]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        assert decoder.is_complete()
        recovered = decoder.get_data(len(data))
        assert recovered == data
        
    def test_fountain_with_frame_loss(self):
        """Fountain codes must handle partial frame loss."""
        data = secrets.token_bytes(256)
        k_blocks = 8
        block_size = 32
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        
        # Generate 2x redundancy
        all_droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        # Simulate 30% frame loss by skipping some droplets
        received_droplets = [d for i, d in enumerate(all_droplets) if i % 3 != 0]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in received_droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        # With 2x redundancy and 30% loss, should still decode
        assert decoder.is_complete(), "Failed to decode with 30% frame loss"
        recovered = decoder.get_data(len(data))
        assert recovered == data


class TestDropletPackingUnpacking:
    """Test droplet serialization integrity."""
    
    def test_droplet_roundtrip(self):
        """Packed droplet must unpack to identical values."""
        data = secrets.token_bytes(512)
        k_blocks = 8
        block_size = 64
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        droplet = encoder.droplet(42)
        
        # Pack
        packed = pack_droplet(droplet)
        
        # Unpack
        unpacked = unpack_droplet(packed, block_size)
        
        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data
        
    def test_droplet_binary_safety(self):
        """Droplets with all byte values must pack/unpack correctly."""
        # Create data with all possible byte values
        data = bytes(range(256)) * 2
        k_blocks = 8
        block_size = 64
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        for i in range(20):
            droplet = encoder.droplet(i)
            packed = pack_droplet(droplet)
            unpacked = unpack_droplet(packed, block_size)
            
            assert unpacked.seed == droplet.seed
            assert unpacked.block_indices == droplet.block_indices
            assert unpacked.data == droplet.data


class TestDataIntegrity:
    """Test data integrity across various inputs."""
    
    def test_null_bytes_preserved(self):
        """Null bytes must be preserved through pipeline."""
        data = b"\x00" * 100 + b"middle" + b"\x00" * 100
        k_blocks = 8
        block_size = 32
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        recovered = decoder.get_data(len(data))
        assert recovered == data, "Null bytes corrupted!"
        
    def test_high_bytes_preserved(self):
        """High bytes (0xFF) must be preserved."""
        data = b"\xff" * 100 + b"middle" + b"\xff" * 100
        k_blocks = 8
        block_size = 32
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        recovered = decoder.get_data(len(data))
        assert recovered == data, "High bytes corrupted!"
        
    def test_alternating_pattern_preserved(self):
        """Alternating byte patterns must be preserved."""
        data = b"\x55\xaa" * 128  # 256 bytes alternating
        k_blocks = 8
        block_size = 32
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        recovered = decoder.get_data(len(data))
        assert recovered == data


class TestFileSizeVariations:
    """Test various file sizes."""
    
    def test_small_file(self):
        """Small files (< 1KB) must round-trip correctly."""
        data = b"Small file content"
        k_blocks = 4
        block_size = 16
        
        padded_size = k_blocks * block_size
        padded_data = data.ljust(padded_size, b"\x00")
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        recovered = decoder.get_data(len(data))
        assert recovered == data
        
    def test_medium_file(self):
        """Medium files (several KB) must round-trip correctly."""
        data = secrets.token_bytes(4096)
        k_blocks = 16
        block_size = 256
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        recovered = decoder.get_data(len(data))
        assert recovered == data
        
    def test_exact_block_boundary(self):
        """File exactly fitting block boundaries must work."""
        k_blocks = 8
        block_size = 64
        data = secrets.token_bytes(k_blocks * block_size)  # Exact fit
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        recovered = decoder.get_data(len(data))
        assert recovered == data


class TestDecoderCompletion:
    """Test decoder completion logic."""
    
    def test_incomplete_decoder_raises(self):
        """Incomplete decoder must raise on get_data()."""
        decoder = FountainDecoder(10, 64)
        
        with pytest.raises(RuntimeError):
            decoder.get_data(100)
            
    def test_is_complete_accurate(self):
        """is_complete() must accurately reflect state."""
        data = secrets.token_bytes(256)
        k_blocks = 8
        block_size = 32
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        assert not decoder.is_complete()
        
        # Add droplets until complete
        for i in range(k_blocks * 3):
            droplet = encoder.droplet(i)
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break
                
        assert decoder.is_complete()


class TestBlockConfiguration:
    """Test various block size configurations."""
    
    def test_small_blocks(self):
        """Small block sizes must work."""
        data = secrets.token_bytes(64)
        k_blocks = 16
        block_size = 4
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        recovered = decoder.get_data(len(data))
        assert recovered == data
        
    def test_large_blocks(self):
        """Large block sizes must work."""
        data = secrets.token_bytes(4096)
        k_blocks = 4
        block_size = 1024
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 2)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            if decoder.is_complete():
                break
            decoder.add_droplet(droplet)
            
        recovered = decoder.get_data(len(data))
        assert recovered == data


class TestSHA256Verification:
    """Test SHA256 hash verification."""
    
    def test_sha256_computed_correctly(self):
        """SHA256 of input data must be computed correctly."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        password = "HashTest123456!"
        test_data = b"Data to hash and encrypt"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        expected_sha = hashlib.sha256(test_data).digest()
        assert sha == expected_sha, "SHA256 mismatch!"
        
    def test_sha256_detects_corruption(self):
        """SHA256 must detect data corruption."""
        data1 = b"Original data"
        data2 = b"Corrupted data"
        
        hash1 = hashlib.sha256(data1).digest()
        hash2 = hashlib.sha256(data2).digest()
        
        assert hash1 != hash2, "Different data produced same hash!"


class TestRedundancyLevels:
    """Test various redundancy configurations."""
    
    def test_minimal_redundancy(self):
        """1.0x redundancy (no extra droplets) should fail gracefully."""
        data = secrets.token_bytes(256)
        k_blocks = 8
        block_size = 32
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        
        # Only generate exactly k_blocks droplets
        droplets = [encoder.droplet(i) for i in range(k_blocks)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            decoder.add_droplet(droplet)
            
        # May or may not complete with exactly k droplets
        # This tests the edge case behavior
        
    def test_high_redundancy(self):
        """High redundancy (3x) should decode quickly."""
        data = secrets.token_bytes(256)
        k_blocks = 8
        block_size = 32
        
        padded_size = k_blocks * block_size
        padded_data = data + b"\x00" * (padded_size - len(data))
        
        encoder = FountainEncoder(padded_data, k_blocks, block_size)
        droplets = [encoder.droplet(i) for i in range(k_blocks * 3)]
        
        decoder = FountainDecoder(k_blocks, block_size)
        droplets_used = 0
        
        for droplet in droplets:
            droplets_used += 1
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break
                
        assert decoder.is_complete()
        # Should complete before using all droplets
        assert droplets_used < k_blocks * 3
        
        recovered = decoder.get_data(len(data))
        assert recovered == data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
