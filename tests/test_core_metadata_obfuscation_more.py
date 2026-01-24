import secrets

import pytest

from meow_decoder.metadata_obfuscation import (
    SIZE_CLASSES,
    round_up_to_size_class,
    randomize_frame_order,
    unshuffle_frames,
    pad_frame_count,
    obfuscate_encoding_parameters,
)


def test_round_up_to_size_class_basic():
    assert round_up_to_size_class(0) == SIZE_CLASSES[0]
    assert round_up_to_size_class(SIZE_CLASSES[0]) == SIZE_CLASSES[0]
    assert round_up_to_size_class(SIZE_CLASSES[0] + 1) == SIZE_CLASSES[1]


def test_randomize_and_unshuffle_deterministic():
    frames = [f"f{i}".encode() for i in range(20)]
    seed = b"\x01" * 32
    shuffled1, idx1 = randomize_frame_order(frames, seed)
    shuffled2, idx2 = randomize_frame_order(frames, seed)

    assert shuffled1 == shuffled2
    assert idx1 == idx2
    assert unshuffle_frames(shuffled1, idx1) == frames


def test_pad_frame_count_adds_decoys():
    frames = [b"A" * 8, b"B" * 8]
    padded = pad_frame_count(frames, 5)
    assert padded[:2] == frames
    assert len(padded) == 5
    # Decoys should be same-length random blobs
    assert all(len(x) == 8 for x in padded)


def test_obfuscate_encoding_parameters_bounds():
    for _ in range(50):
        bsz, red, fps = obfuscate_encoding_parameters(512, 1.5, 10)
        assert bsz >= 64
        assert red >= 1.0
        assert fps >= 1
