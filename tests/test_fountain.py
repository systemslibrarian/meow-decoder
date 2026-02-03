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
