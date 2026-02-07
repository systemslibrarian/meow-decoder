"""Tests for metadata obfuscation utilities."""

import secrets
import pytest
import runpy

from meow_decoder.metadata_obfuscation import (
    SIZE_CLASSES,
    add_length_padding,
    remove_length_padding,
    round_up_to_size_class,
    randomize_frame_order,
    unshuffle_frames,
    pad_frame_count,
    obfuscate_encoding_parameters,
)


class TestLengthPaddingRoundTrip:
    def test_basic_roundtrip(self):
        data = b"Test data for padding"
        padded = add_length_padding(data)
        recovered = remove_length_padding(padded)
        assert recovered == data

    def test_empty_roundtrip(self):
        data = b""
        padded = add_length_padding(data)
        recovered = remove_length_padding(padded)
        assert recovered == data

    def test_various_sizes_roundtrip(self):
        for size in [1, 10, 100, 1000, 10000, 100000]:
            data = secrets.token_bytes(size)
            padded = add_length_padding(data)
            recovered = remove_length_padding(padded)
            assert recovered == data

    def test_binary_data_roundtrip(self):
        data = bytes(range(256)) * 2
        padded = add_length_padding(data)
        recovered = remove_length_padding(padded)
        assert recovered == data


class TestPaddingValidation:
    def test_round_up_to_size_class(self):
        assert round_up_to_size_class(0) == SIZE_CLASSES[0]
        assert round_up_to_size_class(SIZE_CLASSES[0]) == SIZE_CLASSES[0]
        assert round_up_to_size_class(SIZE_CLASSES[0] + 1) == SIZE_CLASSES[1]
        assert round_up_to_size_class(SIZE_CLASSES[-1] + 1) % (64 * 1024 * 1024) == 0

    def test_padded_size_at_least_original(self):
        data = secrets.token_bytes(1234)
        padded = add_length_padding(data)
        assert len(padded) >= len(data)

    def test_invalid_length_field_raises(self):
        data = secrets.token_bytes(100)
        padded = add_length_padding(data)
        # Corrupt length field to exceed padded payload
        corrupted = padded[:-8] + (len(padded) + 10).to_bytes(8, "little")
        with pytest.raises(ValueError):
            remove_length_padding(corrupted)

    def test_padding_len_negative_advances_size_class(self):
        size = SIZE_CLASSES[0] - 4
        data = secrets.token_bytes(size)
        padded = add_length_padding(data)
        assert len(padded) >= size + 8

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            remove_length_padding(b"short")


class TestFrameObfuscation:
    def test_randomize_and_unshuffle_deterministic(self):
        frames = [f"frame-{i}".encode() for i in range(10)]
        seed = b"\x01" * 32
        shuffled1, idx1 = randomize_frame_order(frames, seed)
        shuffled2, idx2 = randomize_frame_order(frames, seed)
        assert shuffled1 == shuffled2
        assert idx1 == idx2
        assert unshuffle_frames(shuffled1, idx1) == frames

    def test_unshuffle_restores_original(self):
        frames = [f"F{i}".encode() for i in range(5)]
        shuffled, indices = randomize_frame_order(frames, b"\x02" * 32)
        assert unshuffle_frames(shuffled, indices) == frames

    def test_pad_frame_count_adds_decoys(self):
        frames = [b"A" * 8, b"B" * 8]
        padded = pad_frame_count(frames, 5)
        assert padded[:2] == frames
        assert len(padded) == 5
        assert all(len(x) == 8 for x in padded)

    def test_pad_frame_count_noop_when_large(self):
        frames = [b"X" * 4, b"Y" * 4, b"Z" * 4]
        padded = pad_frame_count(frames, 2)
        assert padded == frames

    def test_randomize_frame_order_default_seed(self, monkeypatch):
        frames = [b"A", b"B", b"C"]
        monkeypatch.setattr(
            "meow_decoder.metadata_obfuscation.secrets.token_bytes", lambda n: b"\x02" * 32
        )
        shuffled, indices = randomize_frame_order(frames)
        assert sorted(indices) == list(range(len(frames)))
        assert unshuffle_frames(shuffled, indices) == frames


class TestParameterObfuscation:
    def test_obfuscate_bounds(self):
        for _ in range(25):
            block_size, redundancy, fps = obfuscate_encoding_parameters(512, 1.5, 10)
            assert block_size >= 64
            assert redundancy >= 1.0
            assert fps >= 1

    def test_obfuscate_clamps_to_minimums(self, monkeypatch):
        calls = iter([0, 0, 0])

        def _randbelow(_):
            return next(calls)

        monkeypatch.setattr("meow_decoder.metadata_obfuscation.secrets.randbelow", _randbelow)
        block_size, redundancy, fps = obfuscate_encoding_parameters(32, 0.5, 0)
        assert block_size == 64
        assert redundancy == 1.0
        assert fps == 1


def test_module_main_runs(monkeypatch, capsys):
    monkeypatch.setattr("meow_decoder.metadata_obfuscation.secrets.token_bytes", lambda n: b"x")
    monkeypatch.setattr("meow_decoder.metadata_obfuscation.secrets.randbelow", lambda n: 1)
    runpy.run_module("meow_decoder.metadata_obfuscation", run_name="__main__")
    out = capsys.readouterr().out
    assert "Metadata Obfuscation Test" in out
