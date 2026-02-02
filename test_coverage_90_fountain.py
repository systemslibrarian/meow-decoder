#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for fountain.py - Target: 90%+
Tests Luby Transform fountain codes for rateless encoding.
"""

import pytest
import secrets
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestRobustSolitonDistribution:
    """Test the Robust Soliton distribution for degree selection."""
    
    def test_distribution_creation(self):
        """Test creating distribution."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=100)
        assert dist is not None
        assert len(dist.distribution) == 101  # 0 to k
    
    def test_distribution_small_k(self):
        """Test distribution with small k."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=5)
        assert dist is not None
        
        # Sample multiple times
        for _ in range(100):
            degree = dist.sample_degree()
            assert 1 <= degree <= 5
    
    def test_distribution_large_k(self):
        """Test distribution with large k."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=1000)
        
        degrees = [dist.sample_degree() for _ in range(1000)]
        
        # Should have degree 1 samples (important for decoding)
        assert 1 in degrees
        
        # Average degree should be reasonable (typically 3-10)
        avg_degree = sum(degrees) / len(degrees)
        assert 1 < avg_degree < 50
    
    def test_distribution_edge_k_equals_1(self):
        """Test distribution with k=1."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=1)
        
        # With k=1, all droplets should have degree 1
        for _ in range(10):
            assert dist.sample_degree() == 1
    
    def test_distribution_normalization(self):
        """Test that distribution sums to 1."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=50)
        total = sum(dist.distribution)
        
        # Should be approximately 1.0
        assert abs(total - 1.0) < 0.001
    
    def test_distribution_custom_parameters(self):
        """Test distribution with custom c and delta."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist1 = RobustSolitonDistribution(k=100, c=0.05, delta=0.1)
        dist2 = RobustSolitonDistribution(k=100, c=0.2, delta=0.9)
        
        # Both should be valid distributions
        assert abs(sum(dist1.distribution) - 1.0) < 0.001
        assert abs(sum(dist2.distribution) - 1.0) < 0.001


class TestFountainEncoder:
    """Test fountain code encoding."""
    
    def test_encoder_creation(self):
        """Test creating encoder."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Hello, Fountain Code!"
        encoder = FountainEncoder(data, k_blocks=5, block_size=10)
        
        assert encoder.k_blocks == 5
        assert encoder.block_size == 10
    
    def test_encoder_droplet_generation(self):
        """Test generating droplets."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data for fountain encoding" * 10
        encoder = FountainEncoder(data, k_blocks=10, block_size=50)
        
        droplet = encoder.droplet()
        
        assert droplet is not None
        assert droplet.seed is not None
        assert len(droplet.block_indices) > 0
        assert len(droplet.data) == 50
    
    def test_encoder_droplet_with_seed(self):
        """Test generating droplet with specific seed."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Seeded droplet test" * 10
        encoder = FountainEncoder(data, k_blocks=5, block_size=50)
        
        droplet1 = encoder.droplet(seed=42)
        droplet2 = encoder.droplet(seed=42)
        
        # Same seed should produce same droplet
        assert droplet1.seed == droplet2.seed
        assert droplet1.block_indices == droplet2.block_indices
        assert droplet1.data == droplet2.data
    
    def test_encoder_generate_multiple_droplets(self):
        """Test generating multiple droplets."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Multiple droplets test" * 10
        encoder = FountainEncoder(data, k_blocks=8, block_size=30)
        
        droplets = encoder.generate_droplets(15)
        
        assert len(droplets) == 15
        for d in droplets:
            assert len(d.data) == 30
    
    def test_encoder_systematic_droplets(self):
        """Test systematic droplets (first 2*k droplets are degree-1)."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Systematic test" * 20
        encoder = FountainEncoder(data, k_blocks=5, block_size=50)
        
        # First 2*k droplets should have degree 1
        for i in range(10):
            droplet = encoder.droplet(seed=i)
            # Systematic droplets have degree 1
            assert len(droplet.block_indices) == 1
    
    def test_encoder_non_systematic_droplets(self):
        """Test non-systematic droplets (after 2*k)."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Non-systematic test" * 20
        encoder = FountainEncoder(data, k_blocks=5, block_size=50)
        
        # Droplets after 2*k use soliton distribution
        # Generate many to get variety
        high_degree_found = False
        for seed in range(20, 100):
            droplet = encoder.droplet(seed=seed)
            if len(droplet.block_indices) > 1:
                high_degree_found = True
                break
        
        assert high_degree_found
    
    def test_encoder_padding(self):
        """Test that data is padded correctly."""
        from meow_decoder.fountain import FountainEncoder
        
        # Data that doesn't fit evenly into blocks
        data = b"Padding test" * 3  # 36 bytes
        encoder = FountainEncoder(data, k_blocks=5, block_size=10)  # 50 bytes needed
        
        # Internal data should be padded to 50 bytes
        assert len(encoder.data) == 50


class TestFountainDecoder:
    """Test fountain code decoding."""
    
    def test_decoder_creation(self):
        """Test creating decoder."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=10, block_size=50)
        
        assert decoder.k_blocks == 10
        assert decoder.block_size == 50
        assert not decoder.is_complete()
    
    def test_decoder_add_degree1_droplet(self):
        """Test adding degree-1 droplet (immediate decode)."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder, Droplet
        
        # Create known data
        data = b"A" * 50 + b"B" * 50  # 100 bytes, 2 blocks
        encoder = FountainEncoder(data, k_blocks=2, block_size=50)
        
        decoder = FountainDecoder(k_blocks=2, block_size=50)
        
        # Create a degree-1 droplet manually
        droplet = Droplet(seed=0, block_indices=[0], data=b"A" * 50)
        decoder.add_droplet(droplet)
        
        assert decoder.decoded_count == 1
    
    def test_decoder_complete_decode(self):
        """Test complete decoding."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original_data = b"Complete decode test!" * 5
        k_blocks = 5
        block_size = 30
        
        encoder = FountainEncoder(original_data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(original_data))
        
        # Add droplets until complete
        attempts = 0
        while not decoder.is_complete() and attempts < k_blocks * 3:
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            attempts += 1
        
        assert decoder.is_complete()
        recovered = decoder.get_data(len(original_data))
        assert recovered == original_data
    
    def test_decoder_is_complete(self):
        """Test is_complete method."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Completion test" * 10
        k_blocks = 5
        block_size = 30
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Initially not complete
        assert not decoder.is_complete()
        
        # Add droplets
        for _ in range(k_blocks * 2):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        # Should be complete
        assert decoder.is_complete()
    
    def test_decoder_get_data_requires_complete(self):
        """Test that get_data requires complete decoding."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=10, block_size=50)
        
        with pytest.raises(RuntimeError):
            decoder.get_data(original_length=100)
    
    def test_decoder_with_original_length_in_init(self):
        """Test decoder with original_length in constructor."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Init length test" * 5
        k_blocks = 3
        block_size = 40
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(original))
        
        # Complete decoding
        for _ in range(k_blocks * 2):
            decoder.add_droplet(encoder.droplet())
        
        # Can call get_data without length argument
        recovered = decoder.get_data()
        assert recovered == original
    
    def test_decoder_redundant_droplets(self):
        """Test handling of redundant droplets."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Redundancy test" * 10
        k_blocks = 5
        block_size = 30
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Add many more droplets than needed
        for _ in range(k_blocks * 5):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        assert decoder.is_complete()


class TestDropletPacking:
    """Test droplet serialization."""
    
    def test_pack_droplet(self):
        """Test packing droplet to bytes."""
        from meow_decoder.fountain import Droplet, pack_droplet
        
        droplet = Droplet(
            seed=12345,
            block_indices=[0, 3, 7],
            data=b"X" * 50
        )
        
        packed = pack_droplet(droplet)
        
        assert isinstance(packed, bytes)
        # Header: 4 (seed) + 2 (num_indices) + 2*3 (indices) + 50 (data) = 62
        assert len(packed) == 62
    
    def test_unpack_droplet(self):
        """Test unpacking droplet from bytes."""
        from meow_decoder.fountain import Droplet, pack_droplet, unpack_droplet
        
        original = Droplet(
            seed=99999,
            block_indices=[1, 2, 5, 8],
            data=b"Y" * 100
        )
        
        packed = pack_droplet(original)
        unpacked = unpack_droplet(packed, block_size=100)
        
        assert unpacked.seed == original.seed
        assert unpacked.block_indices == original.block_indices
        assert unpacked.data == original.data
    
    def test_pack_unpack_roundtrip(self):
        """Test pack/unpack roundtrip."""
        from meow_decoder.fountain import Droplet, pack_droplet, unpack_droplet
        
        for _ in range(10):
            block_size = 50
            num_indices = secrets.randbelow(5) + 1
            
            droplet = Droplet(
                seed=secrets.randbelow(1000000),
                block_indices=sorted(secrets.randbelow(20) for _ in range(num_indices)),
                data=secrets.token_bytes(block_size)
            )
            
            packed = pack_droplet(droplet)
            unpacked = unpack_droplet(packed, block_size)
            
            assert unpacked.seed == droplet.seed
            assert unpacked.data == droplet.data


class TestFountainRoundtrip:
    """Test complete encode/decode roundtrip."""
    
    def test_roundtrip_small(self):
        """Test roundtrip with small data."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Small test data"
        k_blocks = 3
        block_size = 10
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        while not decoder.is_complete():
            decoder.add_droplet(encoder.droplet())
        
        recovered = decoder.get_data(len(original))
        assert recovered == original
    
    def test_roundtrip_medium(self):
        """Test roundtrip with medium data."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = secrets.token_bytes(500)
        k_blocks = 10
        block_size = 60
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        max_attempts = k_blocks * 3
        for _ in range(max_attempts):
            decoder.add_droplet(encoder.droplet())
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
        recovered = decoder.get_data(len(original))
        assert recovered == original
    
    def test_roundtrip_large(self):
        """Test roundtrip with larger data."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = secrets.token_bytes(2000)
        k_blocks = 20
        block_size = 120
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        max_attempts = k_blocks * 3
        for _ in range(max_attempts):
            decoder.add_droplet(encoder.droplet())
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
        recovered = decoder.get_data(len(original))
        assert recovered == original
    
    def test_roundtrip_with_skipped_droplets(self):
        """Test roundtrip simulating frame loss."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Frame loss test" * 20
        k_blocks = 10
        block_size = 50
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Simulate 30% frame loss
        droplets = encoder.generate_droplets(int(k_blocks * 2))
        
        for i, droplet in enumerate(droplets):
            if secrets.randbelow(10) < 7:  # 70% survival rate
                decoder.add_droplet(droplet)
        
        # Add more if needed
        while not decoder.is_complete():
            decoder.add_droplet(encoder.droplet())
        
        recovered = decoder.get_data(len(original))
        assert recovered == original


class TestBeliefPropagation:
    """Test belief propagation decoding."""
    
    def test_cascade_solving(self):
        """Test that degree-1 droplets trigger cascade solving."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        # With systematic droplets, first 2*k should quickly decode
        original = b"Cascade test" * 10
        k_blocks = 5
        block_size = 25
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Add systematic droplets (first 2*k)
        for i in range(k_blocks * 2):
            droplet = encoder.droplet(seed=i)
            decoder.add_droplet(droplet)
        
        # Should be complete
        assert decoder.is_complete()
    
    def test_pending_droplets_resolved(self):
        """Test that pending droplets get resolved."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Pending resolution test" * 8
        k_blocks = 8
        block_size = 25
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Generate some higher-degree droplets first
        for seed in range(k_blocks * 2, k_blocks * 4):
            droplet = encoder.droplet(seed=seed)
            decoder.add_droplet(droplet)
        
        # Then add systematic ones to trigger resolution
        for seed in range(k_blocks * 2):
            droplet = encoder.droplet(seed=seed)
            decoder.add_droplet(droplet)
        
        assert decoder.is_complete()


class TestDropletDataclass:
    """Test Droplet dataclass."""
    
    def test_droplet_creation(self):
        """Test creating Droplet."""
        from meow_decoder.fountain import Droplet
        
        droplet = Droplet(
            seed=42,
            block_indices=[0, 1, 2],
            data=b"test"
        )
        
        assert droplet.seed == 42
        assert droplet.block_indices == [0, 1, 2]
        assert droplet.data == b"test"
    
    def test_droplet_equality(self):
        """Test Droplet equality."""
        from meow_decoder.fountain import Droplet
        
        d1 = Droplet(seed=1, block_indices=[0], data=b"a")
        d2 = Droplet(seed=1, block_indices=[0], data=b"a")
        d3 = Droplet(seed=2, block_indices=[0], data=b"a")
        
        assert d1 == d2
        assert d1 != d3


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
