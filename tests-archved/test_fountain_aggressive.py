#!/usr/bin/env python3
"""
🐱 AGGRESSIVE Coverage Tests for fountain.py
Target: Boost fountain.py from 67% to 90%+
"""

import pytest
import sys
import struct
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestRobustSolitonDistribution:
    """Test RobustSolitonDistribution class."""
    
    def test_creation(self):
        """Test creation."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=10)
        
        assert dist.k == 10
    
    def test_distribution_computed(self):
        """Test distribution is computed."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=10)
        
        assert dist.distribution is not None
        assert len(dist.distribution) > 0
    
    def test_sample_degree(self):
        """Test sample_degree."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=10)
        
        degree = dist.sample_degree()
        
        assert degree >= 1
        assert degree <= 10
    
    def test_sample_degree_multiple(self):
        """Test sampling multiple degrees."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=100)
        
        degrees = [dist.sample_degree() for _ in range(100)]
        
        assert all(1 <= d <= 100 for d in degrees)
    
    def test_small_k(self):
        """Test with small k."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=1)
        
        degree = dist.sample_degree()
        assert degree == 1
    
    def test_k_equals_2(self):
        """Test with k=2."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=2)
        
        degrees = [dist.sample_degree() for _ in range(10)]
        assert all(1 <= d <= 2 for d in degrees)
    
    def test_different_c_values(self):
        """Test with different c values."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist1 = RobustSolitonDistribution(k=10, c=0.1)
        dist2 = RobustSolitonDistribution(k=10, c=0.5)
        
        # Both should work
        assert dist1.sample_degree() >= 1
        assert dist2.sample_degree() >= 1
    
    def test_different_delta_values(self):
        """Test with different delta values."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=10, delta=0.1)
        
        assert dist.sample_degree() >= 1


class TestDroplet:
    """Test Droplet dataclass."""
    
    def test_creation(self):
        """Test creation."""
        from meow_decoder.fountain import Droplet
        
        droplet = Droplet(
            seed=123,
            block_indices=[0, 1, 2],
            data=b"test data"
        )
        
        assert droplet.seed == 123
        assert droplet.block_indices == [0, 1, 2]
        assert droplet.data == b"test data"
    
    def test_single_block_droplet(self):
        """Test single block droplet."""
        from meow_decoder.fountain import Droplet
        
        droplet = Droplet(
            seed=0,
            block_indices=[5],
            data=b"single"
        )
        
        assert len(droplet.block_indices) == 1


class TestFountainEncoder:
    """Test FountainEncoder class."""
    
    def test_creation(self):
        """Test creation."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Hello World!" * 10
        encoder = FountainEncoder(data, k_blocks=5, block_size=30)
        
        assert encoder.k_blocks == 5
        assert encoder.block_size == 30
    
    def test_data_padding(self):
        """Test data is padded."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Short"
        encoder = FountainEncoder(data, k_blocks=2, block_size=10)
        
        # Data should be padded to k_blocks * block_size
        assert len(encoder.data) == 20
    
    def test_blocks_created(self):
        """Test blocks are created."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"a" * 50
        encoder = FountainEncoder(data, k_blocks=5, block_size=10)
        
        assert len(encoder.blocks) == 5
        assert all(len(b) == 10 for b in encoder.blocks)
    
    def test_droplet_generation(self):
        """Test droplet generation."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data for encoding"
        encoder = FountainEncoder(data, k_blocks=3, block_size=10)
        
        droplet = encoder.droplet()
        
        assert droplet is not None
        assert droplet.seed >= 0
        assert len(droplet.block_indices) >= 1
        assert len(droplet.data) == 10
    
    def test_droplet_with_seed(self):
        """Test droplet with specific seed."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data for encoding"
        encoder = FountainEncoder(data, k_blocks=3, block_size=10)
        
        droplet = encoder.droplet(seed=42)
        
        assert droplet.seed == 42
    
    def test_reproducible_droplets(self):
        """Test droplets with same seed are reproducible."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data for encoding" * 5
        
        encoder1 = FountainEncoder(data, k_blocks=5, block_size=20)
        encoder2 = FountainEncoder(data, k_blocks=5, block_size=20)
        
        droplet1 = encoder1.droplet(seed=100)
        droplet2 = encoder2.droplet(seed=100)
        
        assert droplet1.block_indices == droplet2.block_indices
        assert droplet1.data == droplet2.data
    
    def test_generate_droplets(self):
        """Test generating multiple droplets."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 10
        encoder = FountainEncoder(data, k_blocks=5, block_size=20)
        
        droplets = encoder.generate_droplets(10)
        
        assert len(droplets) == 10
    
    def test_droplet_count(self):
        """Test droplet counter."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 10
        encoder = FountainEncoder(data, k_blocks=5, block_size=20)
        
        assert encoder.droplet_count == 0
        
        encoder.droplet()
        assert encoder.droplet_count == 1
        
        encoder.droplet()
        assert encoder.droplet_count == 2


class TestFountainDecoder:
    """Test FountainDecoder class."""
    
    def test_creation(self):
        """Test creation."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=5, block_size=10)
        
        assert decoder.k_blocks == 5
        assert decoder.block_size == 10
    
    def test_creation_with_length(self):
        """Test creation with original length."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=5, block_size=10, original_length=45)
        
        assert decoder.original_length == 45
    
    def test_is_complete_initially_false(self):
        """Test is_complete initially false."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=5, block_size=10)
        
        assert decoder.is_complete() == False
    
    def test_add_droplet(self):
        """Test adding droplet."""
        from meow_decoder.fountain import FountainDecoder, Droplet
        
        decoder = FountainDecoder(k_blocks=3, block_size=10)
        
        # Degree 1 droplet
        droplet = Droplet(
            seed=0,
            block_indices=[0],
            data=b"0123456789"
        )
        
        result = decoder.add_droplet(droplet)
        
        assert decoder.decoded_count == 1
    
    def test_decode_complete(self):
        """Test decoding until complete."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Hello World! Test data here." * 3
        k_blocks = 4
        block_size = 25
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Add droplets until complete
        for i in range(k_blocks * 3):
            droplet = encoder.droplet()
            if decoder.add_droplet(droplet):
                break
        
        assert decoder.is_complete()
    
    def test_get_data(self):
        """Test getting decoded data."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Test data for fountain codes!"
        k_blocks = 3
        block_size = 15
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        result = decoder.get_data(len(original))
        
        assert result == original
    
    def test_get_data_with_stored_length(self):
        """Test get_data with stored length."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Test data!"
        k_blocks = 2
        block_size = 10
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(original))
        
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        result = decoder.get_data()
        
        assert result == original
    
    def test_get_data_incomplete_raises(self):
        """Test get_data raises when incomplete."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=5, block_size=10)
        
        with pytest.raises(RuntimeError):
            decoder.get_data(10)
    
    def test_get_data_no_length_raises(self):
        """Test get_data raises when no length provided."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Test data!"
        k_blocks = 2
        block_size = 10
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)  # No original_length
        
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        with pytest.raises(ValueError):
            decoder.get_data()  # No length provided
    
    def test_redundant_droplets_ignored(self):
        """Test redundant droplets are handled."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Test!"
        k_blocks = 1
        block_size = 10
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Add many droplets (most will be redundant)
        for _ in range(10):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        assert decoder.is_complete()
    
    def test_belief_propagation(self):
        """Test belief propagation decoding."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"A" * 50
        k_blocks = 5
        block_size = 10
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Add droplets - belief propagation should handle high-degree droplets
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        result = decoder.get_data(len(original))
        assert result == original


class TestPackDroplet:
    """Test pack_droplet function."""
    
    def test_basic_pack(self):
        """Test basic packing."""
        from meow_decoder.fountain import Droplet, pack_droplet
        
        droplet = Droplet(
            seed=123,
            block_indices=[0, 1, 2],
            data=b"test data!"
        )
        
        packed = pack_droplet(droplet)
        
        assert isinstance(packed, bytes)
        assert len(packed) > 0
    
    def test_pack_contains_seed(self):
        """Test packed data contains seed."""
        from meow_decoder.fountain import Droplet, pack_droplet
        
        droplet = Droplet(
            seed=12345,
            block_indices=[0],
            data=b"data"
        )
        
        packed = pack_droplet(droplet)
        
        # First 4 bytes should be seed
        seed = struct.unpack(">I", packed[:4])[0]
        assert seed == 12345
    
    def test_pack_contains_num_indices(self):
        """Test packed data contains num indices."""
        from meow_decoder.fountain import Droplet, pack_droplet
        
        droplet = Droplet(
            seed=0,
            block_indices=[1, 2, 3],
            data=b"data"
        )
        
        packed = pack_droplet(droplet)
        
        # Bytes 4-5 should be num indices
        num_indices = struct.unpack(">H", packed[4:6])[0]
        assert num_indices == 3


class TestUnpackDroplet:
    """Test unpack_droplet function."""
    
    def test_basic_unpack(self):
        """Test basic unpacking."""
        from meow_decoder.fountain import Droplet, pack_droplet, unpack_droplet
        
        original = Droplet(
            seed=42,
            block_indices=[1, 2],
            data=b"0123456789"
        )
        
        packed = pack_droplet(original)
        unpacked = unpack_droplet(packed, block_size=10)
        
        assert unpacked.seed == original.seed
        assert unpacked.block_indices == original.block_indices
        assert unpacked.data == original.data
    
    def test_roundtrip(self):
        """Test pack/unpack roundtrip."""
        from meow_decoder.fountain import Droplet, pack_droplet, unpack_droplet
        
        block_size = 20
        data = b"a" * block_size
        
        original = Droplet(
            seed=999,
            block_indices=[0, 5, 10],
            data=data
        )
        
        packed = pack_droplet(original)
        unpacked = unpack_droplet(packed, block_size)
        
        assert unpacked.seed == original.seed
        assert unpacked.block_indices == original.block_indices
        assert unpacked.data == original.data


class TestFullRoundtrip:
    """Test full encode/decode roundtrip."""
    
    def test_simple_roundtrip(self):
        """Test simple roundtrip."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Simple test message!"
        k_blocks = 2
        block_size = 15
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        result = decoder.get_data(len(original))
        assert result == original
    
    def test_large_data_roundtrip(self):
        """Test roundtrip with larger data."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"X" * 1000
        k_blocks = 10
        block_size = 100
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        result = decoder.get_data(len(original))
        assert result == original
    
    def test_binary_data_roundtrip(self):
        """Test roundtrip with binary data."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = bytes(range(256))  # All byte values
        k_blocks = 4
        block_size = 64
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        result = decoder.get_data(len(original))
        assert result == original
    
    def test_with_redundancy(self):
        """Test with excess droplets (simulating loss)."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Test data with redundancy!"
        k_blocks = 3
        block_size = 15
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Generate many more droplets than needed
        droplets = encoder.generate_droplets(k_blocks * 3)
        
        for droplet in droplets:
            if decoder.add_droplet(droplet):
                break
        
        result = decoder.get_data(len(original))
        assert result == original


class TestEdgeCases:
    """Test edge cases."""
    
    def test_single_block(self):
        """Test with single block."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Single block"
        k_blocks = 1
        block_size = 20
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        result = decoder.get_data(len(original))
        assert result == original
    
    def test_empty_data_padded(self):
        """Test empty data gets padded."""
        from meow_decoder.fountain import FountainEncoder
        
        encoder = FountainEncoder(b"", k_blocks=1, block_size=10)
        
        assert len(encoder.data) == 10
    
    def test_many_blocks(self):
        """Test with many blocks."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"M" * 500
        k_blocks = 50
        block_size = 10
        
        encoder = FountainEncoder(original, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        while not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        result = decoder.get_data(len(original))
        assert result == original


class TestSystematicDroplets:
    """Test systematic droplet generation."""
    
    def test_early_seeds_systematic(self):
        """Test early seeds produce systematic (degree-1) droplets."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"a" * 100
        k_blocks = 10
        block_size = 10
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # First 2*k droplets should be degree 1
        for i in range(2 * k_blocks):
            droplet = encoder.droplet(seed=i)
            assert len(droplet.block_indices) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
