#!/usr/bin/env python3
"""Coverage tests for fountain.py (target 95%+)."""

import random

import pytest

from meow_decoder.fountain import (
    RobustSolitonDistribution,
    Droplet,
    FountainEncoder,
    FountainDecoder,
    pack_droplet,
    unpack_droplet,
)


def test_robust_soliton_distribution_small_k():
    dist = RobustSolitonDistribution(k=1)
    degree = dist.sample_degree()
    assert degree == 1


def test_robust_soliton_distribution_sampling_range():
    dist = RobustSolitonDistribution(k=10)
    degrees = [dist.sample_degree() for _ in range(50)]
    assert all(1 <= d <= 10 for d in degrees)


def test_fountain_encoder_systematic_droplet_seeded():
    data = b"abcdef" * 2
    encoder = FountainEncoder(data, k_blocks=2, block_size=6)

    droplet = encoder.droplet(seed=0)
    assert droplet.block_indices == [0]
    assert droplet.data == encoder.blocks[0]


def test_fountain_encoder_random_droplet_seeded():
    data = b"0123456789" * 5
    encoder = FountainEncoder(data, k_blocks=5, block_size=10)

    droplet = encoder.droplet(seed=20)
    assert droplet.seed == 20
    assert len(droplet.block_indices) >= 1
    assert len(droplet.data) == 10


def test_pack_unpack_droplet_roundtrip():
    droplet = Droplet(seed=123, block_indices=[0, 2, 5], data=b"x" * 8)
    packed = pack_droplet(droplet)
    unpacked = unpack_droplet(packed, block_size=8)

    assert unpacked.seed == droplet.seed
    assert unpacked.block_indices == droplet.block_indices
    assert unpacked.data == droplet.data


def test_fountain_decoder_completes_roundtrip():
    data = b"hello fountain" * 3
    block_size = 8
    k_blocks = (len(data) + block_size - 1) // block_size

    encoder = FountainEncoder(data, k_blocks=k_blocks, block_size=block_size)
    decoder = FountainDecoder(k_blocks=k_blocks, block_size=block_size, original_length=len(data))

    # Use systematic droplets for each block
    for seed in range(k_blocks):
        droplet = encoder.droplet(seed=seed)
        decoder.add_droplet(droplet)

    assert decoder.is_complete()
    assert decoder.get_data() == data


def test_fountain_decoder_pending_resolution():
    data = b"abc" * 10
    block_size = 6
    k_blocks = (len(data) + block_size - 1) // block_size
    encoder = FountainEncoder(data, k_blocks=k_blocks, block_size=block_size)
    decoder = FountainDecoder(k_blocks=k_blocks, block_size=block_size, original_length=len(data))

    random.seed(123)
    droplet = encoder.droplet(seed=999)
    decoder.add_droplet(droplet)

    # Add systematic droplets to resolve pending ones
    for seed in range(k_blocks):
        decoder.add_droplet(encoder.droplet(seed=seed))

    assert decoder.is_complete()
    assert decoder.get_data() == data

# --- Merged from test_coverage_boost_extras.py ---

# =====================================================
# fountain.py — push from 96.75% higher
# =====================================================
class TestFountainExtras:
    """Extra fountain.py tests for small uncovered branches."""

    def test_fountain_full_roundtrip(self):
        """Full encode/decode roundtrip with redundancy."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder

        data = b"Fountain code roundtrip test! " * 20
        block_size = 50
        k_blocks = (len(data) + block_size - 1) // block_size

        encoder = FountainEncoder(data, k_blocks, block_size)
        # Generate 2x droplets for redundancy
        droplets = encoder.generate_droplets(k_blocks * 2)

        decoder = FountainDecoder(k_blocks, block_size)
        for droplet in droplets:
            decoder.add_droplet(droplet)
            if decoder.is_complete():
                break

        assert decoder.is_complete()
        recovered = decoder.get_data(original_length=len(data))
        assert recovered == data

    def test_fountain_not_enough_droplets(self):
        """Decoder that hasn't received enough droplets should not be complete."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder

        data = b"X" * 200
        block_size = 20
        k_blocks = 10

        encoder = FountainEncoder(data, k_blocks, block_size)
        droplets = encoder.generate_droplets(2)  # Way too few

        decoder = FountainDecoder(k_blocks, block_size)
        for d in droplets:
            decoder.add_droplet(d)

        assert not decoder.is_complete()


# =====================================================
# secure_cleanup.py — push from 96.25% higher
# =====================================================

# --- Merged from test_coverage_boost_remaining.py ---

# =====================================================
# fountain.py small gaps
# =====================================================
class TestFountainSmallGaps:
    def test_generate_droplets_method(self):
        """Test FountainEncoder.generate_droplets() list method."""
        from meow_decoder.fountain import FountainEncoder

        data = b"hello fountain" * 10
        k = 7
        block_size = 20
        encoder = FountainEncoder(data, k, block_size)
        droplets = encoder.generate_droplets(10)
        assert len(droplets) == 10

    def test_get_data_no_original_length(self):
        """get_data without original_length should raise."""
        from meow_decoder.fountain import FountainDecoder

        decoder = FountainDecoder(5, 20)
        with pytest.raises((ValueError, RuntimeError)):
            decoder.get_data()

    def test_single_droplet(self):
        """Test single droplet generation."""
        from meow_decoder.fountain import FountainEncoder

        data = b"test data for fountain" * 5
        encoder = FountainEncoder(data, 5, 20)
        droplet = encoder.droplet()
        assert droplet is not None
        assert hasattr(droplet, "seed")
        assert hasattr(droplet, "data")


# =====================================================
# forward_secrecy_x25519.py small gaps
# =====================================================

