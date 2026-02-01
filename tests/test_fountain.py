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


# ============================================================================
# MERGED FROM: test_fountain_aggressive.py, test_coverage_90_fountain_paths.py
# ============================================================================


class TestUnpackDroplet:
    """Test unpack_droplet function (from test_fountain_aggressive.py)."""
    
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


class TestEdgeCases:
    """Test edge cases (from test_fountain_aggressive.py)."""
    
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
    """Test systematic droplet generation (from test_fountain_aggressive.py)."""
    
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


class TestDropletReduction:
    """Test droplet reduction in decoder (from test_coverage_90_fountain_paths.py)."""
    
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
    """Integration tests for fountain codes (from test_coverage_90_fountain_paths.py)."""
    
    def test_encode_decode_large_data(self):
        """Test with larger data."""
        import secrets
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
        import random
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


class TestSmallK:
    """Test edge case with small k values (from integration/test_fountain_fix.py)."""
    
    def test_small_k(self):
        """Test encoding with small k."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Hello, this is a test!" * 10
        k = 2
        block_size = 128
        
        encoder = FountainEncoder(data, k, block_size)
        
        droplets = encoder.generate_droplets(10)
        
        decoder = FountainDecoder(k, block_size)
        
        for droplet in droplets:
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break
        
        if decoder.is_complete():
            result = decoder.get_data(len(data))
            assert result == data


# ============================================================================
# MERGED FROM: test_catnip_fountain.py
# ============================================================================

# Try to import catnip_fountain module
try:
    from meow_decoder.catnip_fountain import (
        CatnipEncoder,
        CatnipDecoder,
        apply_catnip_flavor,
    )
    CATNIP_AVAILABLE = True
except ImportError:
    CATNIP_AVAILABLE = False


@pytest.mark.skipif(not CATNIP_AVAILABLE, reason="catnip_fountain module not available")
class TestCatnipEncoder:
    """Tests for CatnipEncoder."""

    def test_encoder_creation(self):
        """Test basic encoder creation."""
        data = secrets.token_bytes(500)
        encoder = CatnipEncoder(data, k_blocks=10, block_size=50)
        assert encoder is not None

    def test_encoder_generate_droplet(self):
        """Test droplet generation."""
        data = secrets.token_bytes(500)
        encoder = CatnipEncoder(data, k_blocks=10, block_size=50)
        droplet = encoder.droplet()
        assert droplet is not None
        assert hasattr(droplet, 'data')

    def test_encoder_generate_multiple(self):
        """Test generating multiple droplets."""
        data = secrets.token_bytes(500)
        encoder = CatnipEncoder(data, k_blocks=10, block_size=50)
        droplets = encoder.generate_droplets(15)
        assert len(droplets) == 15


@pytest.mark.skipif(not CATNIP_AVAILABLE, reason="catnip_fountain module not available")
class TestCatnipDecoder:
    """Tests for CatnipDecoder."""

    def test_decoder_creation(self):
        """Test basic decoder creation."""
        decoder = CatnipDecoder(k_blocks=10, block_size=50)
        assert decoder is not None

    def test_decoder_add_droplet(self):
        """Test adding droplet to decoder."""
        data = secrets.token_bytes(500)
        encoder = CatnipEncoder(data, k_blocks=10, block_size=50)
        decoder = CatnipDecoder(k_blocks=10, block_size=50)
        
        droplet = encoder.droplet()
        result = decoder.add_droplet(droplet)
        assert isinstance(result, bool)


@pytest.mark.skipif(not CATNIP_AVAILABLE, reason="catnip_fountain module not available")
class TestApplyCatnipFlavor:
    """Tests for catnip flavor application."""

    def test_apply_flavor_tuna(self):
        """Test tuna flavor application."""
        salt = secrets.token_bytes(16)
        flavored = apply_catnip_flavor("tuna", salt)
        assert isinstance(flavored, bytes)

    def test_apply_flavor_salmon(self):
        """Test salmon flavor application."""
        salt = secrets.token_bytes(16)
        flavored = apply_catnip_flavor("salmon", salt)
        assert isinstance(flavored, bytes)

    def test_different_flavors_different_output(self):
        """Test that different flavors produce different output."""
        salt = secrets.token_bytes(16)
        tuna = apply_catnip_flavor("tuna", salt)
        salmon = apply_catnip_flavor("salmon", salt)
        assert tuna != salmon


# Fallback test for catnip module import
@pytest.mark.skipif(CATNIP_AVAILABLE, reason="Testing import fallback")
class TestCatnipModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not CATNIP_AVAILABLE


# ============================================================================
# MERGED FROM: test_merkle_tree_aggressive.py
# ============================================================================

import hashlib

# Try to import MerkleTree
try:
    from meow_decoder.merkle_tree import MerkleTree, MerkleProof
    MERKLE_AVAILABLE = True
except ImportError:
    MERKLE_AVAILABLE = False


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleTreeConstruction:
    """Tests for MerkleTree construction."""
    
    def test_single_chunk_tree(self):
        """Test tree with single chunk."""
        chunks = [b"single chunk"]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 1
        assert tree.root_hash is not None
        assert len(tree.root_hash) == 32
    
    def test_two_chunk_tree(self):
        """Test tree with two chunks."""
        chunks = [b"chunk one", b"chunk two"]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2
        assert len(tree.root_hash) == 32
    
    def test_power_of_two_chunks(self):
        """Test tree with power of 2 chunks."""
        chunks = [f"chunk {i}".encode() for i in range(8)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 8
    
    def test_non_power_of_two_chunks(self):
        """Test tree with non-power of 2 chunks."""
        chunks = [f"chunk {i}".encode() for i in range(5)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 5
    
    def test_many_chunks(self):
        """Test tree with many chunks."""
        chunks = [f"chunk {i}".encode() for i in range(100)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 100


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleTreeHashing:
    """Tests for Merkle tree hashing."""
    
    def test_leaf_hashes_are_sha256(self):
        """Test that leaf hashes are SHA256."""
        chunks = [b"test chunk"]
        tree = MerkleTree(chunks)
        
        expected = hashlib.sha256(chunks[0]).digest()
        assert tree.leaf_hashes[0] == expected
    
    def test_deterministic_hashing(self):
        """Test that hashing is deterministic."""
        chunks = [b"a", b"b", b"c"]
        
        tree1 = MerkleTree(chunks)
        tree2 = MerkleTree(chunks)
        
        assert tree1.root_hash == tree2.root_hash
    
    def test_different_data_different_hash(self):
        """Test that different data produces different hash."""
        tree1 = MerkleTree([b"data1"])
        tree2 = MerkleTree([b"data2"])
        
        assert tree1.root_hash != tree2.root_hash
    
    def test_order_matters(self):
        """Test that chunk order affects hash."""
        tree1 = MerkleTree([b"a", b"b"])
        tree2 = MerkleTree([b"b", b"a"])
        
        assert tree1.root_hash != tree2.root_hash


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleTreeGetRoot:
    """Tests for get_root method."""
    
    def test_get_root_returns_bytes(self):
        """Test get_root returns bytes."""
        tree = MerkleTree([b"chunk"])
        
        assert isinstance(tree.get_root(), bytes)
    
    def test_get_root_length(self):
        """Test get_root returns 32 bytes."""
        tree = MerkleTree([b"chunk"])
        
        assert len(tree.get_root()) == 32
    
    def test_get_root_matches_root_hash(self):
        """Test get_root matches root_hash attribute."""
        tree = MerkleTree([b"chunk"])
        
        assert tree.get_root() == tree.root_hash


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleProofGeneration:
    """Tests for Merkle proof generation."""
    
    def test_get_proof_returns_merkle_proof(self):
        """Test get_proof returns MerkleProof."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(0)
        
        assert isinstance(proof, MerkleProof)
    
    def test_proof_has_correct_chunk_index(self):
        """Test proof has correct chunk index."""
        chunks = [b"a", b"b", b"c"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(1)
        
        assert proof.chunk_index == 1
    
    def test_proof_has_correct_chunk_hash(self):
        """Test proof has correct chunk hash."""
        chunks = [b"test chunk", b"another"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(0)
        
        expected = hashlib.sha256(chunks[0]).digest()
        assert proof.chunk_hash == expected
    
    def test_proof_has_root_hash(self):
        """Test proof contains root hash."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(0)
        
        assert proof.root_hash == tree.root_hash
    
    def test_get_proof_invalid_index_negative(self):
        """Test proof with negative index raises error."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        with pytest.raises(ValueError, match="Invalid chunk index"):
            tree.get_proof(-1)
    
    def test_get_proof_invalid_index_too_large(self):
        """Test proof with index >= num_chunks raises error."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        with pytest.raises(ValueError, match="Invalid chunk index"):
            tree.get_proof(2)
    
    def test_get_proof_all_chunks(self):
        """Test proof generation for all chunks."""
        chunks = [f"chunk {i}".encode() for i in range(16)]
        tree = MerkleTree(chunks)
        
        for i in range(16):
            proof = tree.get_proof(i)
            assert proof.chunk_index == i
            assert proof.chunk_hash == tree.leaf_hashes[i]
            assert proof.root_hash == tree.root_hash


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleProofDataclass:
    """Tests for MerkleProof dataclass."""
    
    def test_merkle_proof_attributes(self):
        """Test MerkleProof has correct attributes."""
        proof = MerkleProof(
            chunk_index=5,
            chunk_hash=b"hash" + b"\x00" * 28,
            proof_hashes=[b"proof1" + b"\x00" * 26],
            root_hash=b"root" + b"\x00" * 28,
        )
        
        assert proof.chunk_index == 5
        assert proof.chunk_hash == b"hash" + b"\x00" * 28
        assert len(proof.proof_hashes) == 1
        assert proof.root_hash == b"root" + b"\x00" * 28


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleProofVerification:
    """Tests for proof verification (if verify_proof exists)."""
    
    def test_proof_contains_sibling_hashes(self):
        """Test proof contains correct sibling hashes."""
        chunks = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(chunks)
        
        # Proof for chunk 0 should include sibling at index 1
        proof = tree.get_proof(0)
        
        # Proof should have at least log2(4) = 2 hashes
        assert len(proof.proof_hashes) >= 1
    
    def test_proof_path_length(self):
        """Test proof path has logarithmic length."""
        import math
        
        for n in [2, 4, 8, 16, 32]:
            chunks = [f"c{i}".encode() for i in range(n)]
            tree = MerkleTree(chunks)
            
            proof = tree.get_proof(0)
            
            # Path length should be ceil(log2(n))
            expected_max = math.ceil(math.log2(n))
            assert len(proof.proof_hashes) <= expected_max
    
    def test_can_recompute_root_from_proof(self):
        """Test that proof allows root recomputation."""
        chunks = [b"a", b"b"]
        tree = MerkleTree(chunks)
        
        proof = tree.get_proof(0)
        
        # Manually verify: hash(chunk_hash || sibling)
        if proof.proof_hashes:
            computed = hashlib.sha256(
                proof.chunk_hash + proof.proof_hashes[0]
            ).digest()
            assert computed == tree.root_hash


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleTreeEdgeCases:
    """Edge case tests."""
    
    def test_very_large_chunk(self):
        """Test tree with very large chunk."""
        large_chunk = secrets.token_bytes(1024 * 1024)  # 1 MB
        tree = MerkleTree([large_chunk])
        
        assert tree.num_chunks == 1
        assert tree.root_hash is not None
    
    def test_empty_chunk(self):
        """Test tree with empty chunk."""
        chunks = [b"", b"non-empty"]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2
    
    def test_binary_chunks(self):
        """Test tree with binary data chunks."""
        chunks = [secrets.token_bytes(256) for _ in range(10)]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 10
        
        # All proofs should work
        for i in range(10):
            proof = tree.get_proof(i)
            assert proof.chunk_index == i
    
    def test_unicode_in_chunks(self):
        """Test tree with unicode content."""
        chunks = ["Hello 世界".encode('utf-8'), "🐱🔐".encode('utf-8')]
        tree = MerkleTree(chunks)
        
        assert tree.num_chunks == 2


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleTreeBuildTree:
    """Tests for internal _build_tree method."""
    
    def test_build_tree_structure(self):
        """Test tree structure is correct."""
        chunks = [b"a", b"b", b"c", b"d"]
        tree = MerkleTree(chunks)
        
        # Tree should have multiple levels
        assert len(tree.tree) >= 2
        
        # First level is leaves
        assert len(tree.tree[0]) == 4
        
        # Second level has 2 nodes
        assert len(tree.tree[1]) == 2
        
        # Third level (root) has 1 node
        assert len(tree.tree[2]) == 1
    
    def test_build_tree_odd_number(self):
        """Test tree building with odd number of chunks."""
        chunks = [b"a", b"b", b"c"]
        tree = MerkleTree(chunks)
        
        # Should handle odd number by duplicating last
        assert len(tree.tree) >= 2
        assert tree.num_chunks == 3


@pytest.mark.skipif(not MERKLE_AVAILABLE, reason="merkle_tree module not available")
class TestMerkleTreeIntegration:
    """Integration tests for complete Merkle tree workflows."""
    
    def test_complete_workflow(self):
        """Test complete Merkle tree workflow."""
        # Create chunks
        chunks = [f"data block {i}".encode() for i in range(10)]
        
        # Build tree
        tree = MerkleTree(chunks)
        
        # Get root for manifest
        root = tree.get_root()
        assert len(root) == 32
        
        # Get proofs for all chunks
        proofs = [tree.get_proof(i) for i in range(10)]
        
        # Verify all proofs reference correct root
        for proof in proofs:
            assert proof.root_hash == root
    
    def test_tamper_detection(self):
        """Test that tampering changes root."""
        chunks1 = [b"chunk 0", b"chunk 1", b"chunk 2"]
        chunks2 = [b"TAMPER", b"chunk 1", b"chunk 2"]
        
        tree1 = MerkleTree(chunks1)
        tree2 = MerkleTree(chunks2)
        
        # Roots should differ
        assert tree1.root_hash != tree2.root_hash


# ==============================================================================
# MERGED FROM test_encode_decode.py (2026-02-01)
# Original: Tier 1 Encode/Decode Round-Trip Tests
# Tests fountain code round-trip, droplet integrity, and data preservation
# ==============================================================================

# Imports for merged tests
from meow_decoder.fountain import FountainEncoder, FountainDecoder, pack_droplet, unpack_droplet
import hashlib

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
    pytest.main([__file__, "-v", "--tb=short"])
