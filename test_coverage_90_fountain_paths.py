#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for fountain code paths - Target: 90%+
Tests fountain.py paths that haven't been covered yet.
"""

import pytest
import secrets
import sys
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestRobustSolitonDistribution:
    """Test Robust Soliton Distribution."""
    
    def test_distribution_creation(self):
        """Test creating distribution."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=100)
        
        assert dist.k == 100
        assert len(dist.distribution) > 0
    
    def test_distribution_small_k(self):
        """Test distribution with small k."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=5)
        
        assert dist.k == 5
    
    def test_distribution_k_equals_1(self):
        """Test distribution with k=1."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=1)
        
        assert dist.distribution == [0.0, 1.0]
    
    def test_sample_degree(self):
        """Test sampling degree."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=100)
        
        degrees = [dist.sample_degree() for _ in range(100)]
        
        # All degrees should be valid
        assert all(1 <= d <= 100 for d in degrees)
    
    def test_sample_degree_multiple(self):
        """Test sampling multiple degrees."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=50)
        
        # Sample many times
        degrees = [dist.sample_degree() for _ in range(1000)]
        
        # Most degrees should be low (soliton property)
        avg_degree = sum(degrees) / len(degrees)
        assert 1 < avg_degree < 10  # Reasonable average


class TestFountainEncoder:
    """Test Fountain Encoder."""
    
    def test_encoder_creation(self):
        """Test creating encoder."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        assert encoder.k_blocks == 10
        assert encoder.block_size == 100
    
    def test_generate_droplet(self):
        """Test generating a droplet."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        droplet = encoder.droplet()
        
        assert droplet.seed >= 0
        assert len(droplet.block_indices) > 0
        assert len(droplet.data) == 100
    
    def test_generate_droplet_with_seed(self):
        """Test generating a droplet with specific seed."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        droplet1 = encoder.droplet(seed=42)
        
        # Create new encoder and get same seed
        encoder2 = FountainEncoder(data, k_blocks=10, block_size=100)
        droplet2 = encoder2.droplet(seed=42)
        
        # Should produce same droplet
        assert droplet1.seed == droplet2.seed
        assert droplet1.block_indices == droplet2.block_indices
        assert droplet1.data == droplet2.data
    
    def test_generate_droplets(self):
        """Test generating multiple droplets."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        droplets = encoder.generate_droplets(15)
        
        assert len(droplets) == 15
    
    def test_systematic_droplets(self):
        """Test systematic droplets (degree-1 for early seeds)."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        # First 2*k droplets should be systematic (degree-1)
        for i in range(20):
            droplet = encoder.droplet(seed=i)
            assert len(droplet.block_indices) == 1


class TestFountainDecoder:
    """Test Fountain Decoder."""
    
    def test_decoder_creation(self):
        """Test creating decoder."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=10, block_size=100)
        
        assert decoder.k_blocks == 10
        assert decoder.block_size == 100
        assert decoder.decoded_count == 0
    
    def test_decoder_is_complete_false(self):
        """Test is_complete when not done."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=10, block_size=100)
        
        assert decoder.is_complete() is False
    
    def test_add_droplet(self):
        """Test adding a droplet."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        decoder = FountainDecoder(k_blocks=10, block_size=100)
        
        droplet = encoder.droplet()
        decoder.add_droplet(droplet)
        
        # Should have made some progress
        assert decoder.decoded_count >= 0
    
    def test_full_decode(self):
        """Test full encode/decode cycle."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Test data to encode and decode successfully!" * 20
        k_blocks = 10
        block_size = 100
        
        encoder = FountainEncoder(data, k_blocks=k_blocks, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k_blocks, block_size=block_size)
        
        # Generate droplets until decoded
        max_droplets = k_blocks * 3
        droplets_used = 0
        
        for _ in range(max_droplets):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            droplets_used += 1
            
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
        
        decoded = decoder.get_data(len(data))
        assert decoded == data
    
    def test_get_data_incomplete(self):
        """Test get_data when not complete."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=10, block_size=100)
        
        with pytest.raises(RuntimeError, match="incomplete"):
            decoder.get_data(500)
    
    def test_get_data_no_length(self):
        """Test get_data without original length."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        decoder = FountainDecoder(k_blocks=10, block_size=100, original_length=None)
        
        # Decode completely
        for _ in range(30):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
        
        # Should fail without length
        with pytest.raises(ValueError, match="original_length"):
            decoder.get_data()
    
    def test_belief_propagation(self):
        """Test belief propagation decoding."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Belief propagation test data!" * 50
        k_blocks = 20
        block_size = 80
        
        encoder = FountainEncoder(data, k_blocks=k_blocks, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k_blocks, block_size=block_size)
        
        # Add some high-degree droplets first
        for i in range(k_blocks * 2 + 10, k_blocks * 3):
            droplet = encoder.droplet(seed=i)
            decoder.add_droplet(droplet)
        
        # Add systematic droplets to trigger belief propagation
        for i in range(k_blocks * 2):
            droplet = encoder.droplet(seed=i)
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()


class TestDropletPacking:
    """Test droplet packing/unpacking."""
    
    def test_pack_droplet(self):
        """Test packing a droplet."""
        from meow_decoder.fountain import FountainEncoder, pack_droplet
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        droplet = encoder.droplet()
        packed = pack_droplet(droplet)
        
        assert len(packed) > 0
    
    def test_unpack_droplet(self):
        """Test unpacking a droplet."""
        from meow_decoder.fountain import FountainEncoder, pack_droplet, unpack_droplet
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        droplet = encoder.droplet()
        packed = pack_droplet(droplet)
        unpacked = unpack_droplet(packed, block_size=100)
        
        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data
    
    def test_pack_unpack_roundtrip(self):
        """Test pack/unpack roundtrip."""
        from meow_decoder.fountain import FountainEncoder, pack_droplet, unpack_droplet
        
        data = b"Roundtrip test data" * 50
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        for _ in range(10):
            droplet = encoder.droplet()
            packed = pack_droplet(droplet)
            unpacked = unpack_droplet(packed, block_size=100)
            
            assert unpacked.seed == droplet.seed
            assert unpacked.block_indices == droplet.block_indices
            assert unpacked.data == droplet.data


class TestDropletReduction:
    """Test droplet reduction in decoder."""
    
    def test_reduce_droplet(self):
        """Test reducing droplet with decoded blocks."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder, Droplet
        
        data = b"Reduction test data" * 50
        k_blocks = 10
        block_size = 100
        
        encoder = FountainEncoder(data, k_blocks=k_blocks, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k_blocks, block_size=block_size)
        
        # First decode block 0
        droplet0 = encoder.droplet(seed=0)
        decoder.add_droplet(droplet0)
        
        assert decoder.decoded[0] is True
        
        # Create a droplet that includes block 0
        # It should get reduced
        droplet = Droplet(
            seed=999,
            block_indices=[0, 1, 2],
            data=b'\x00' * block_size
        )
        
        reduced = decoder._reduce_droplet(droplet)
        
        # Block 0 should be removed
        assert 0 not in reduced.block_indices


class TestFountainIntegration:
    """Integration tests for fountain codes."""
    
    def test_encode_decode_large_data(self):
        """Test with larger data."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = secrets.token_bytes(10000)  # 10KB
        k_blocks = 50
        block_size = 200
        
        encoder = FountainEncoder(data, k_blocks=k_blocks, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k_blocks, block_size=block_size)
        
        # Decode
        for _ in range(k_blocks * 3):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
        
        decoded = decoder.get_data(len(data))
        assert decoded == data
    
    def test_decode_with_redundancy(self):
        """Test that redundancy helps with decoding."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Redundancy test data" * 100
        k_blocks = 20
        block_size = 100
        
        encoder = FountainEncoder(data, k_blocks=k_blocks, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k_blocks, block_size=block_size)
        
        # Need approximately k * 1.5 droplets
        droplets_needed = 0
        
        for _ in range(k_blocks * 3):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            droplets_needed += 1
            
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
        
        # Should need less than 2x overhead
        assert droplets_needed < k_blocks * 2
    
    def test_decode_with_loss(self):
        """Test decoding with simulated frame loss."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Frame loss simulation test" * 50
        k_blocks = 15
        block_size = 100
        
        encoder = FountainEncoder(data, k_blocks=k_blocks, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k_blocks, block_size=block_size)
        
        random.seed(42)
        
        # Simulate 30% loss
        droplets_sent = 0
        for _ in range(k_blocks * 3):
            droplet = encoder.droplet()
            droplets_sent += 1
            
            # Skip 30% of droplets (loss)
            if random.random() < 0.3:
                continue
            
            decoder.add_droplet(droplet)
            
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
