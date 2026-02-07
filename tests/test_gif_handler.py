#!/usr/bin/env python3
"""Coverage tests for gif_handler.py (target 95%+)."""

from pathlib import Path

import pytest
from PIL import Image

from meow_decoder.gif_handler import GIFEncoder, GIFDecoder, GIFOptimizer


def _make_frame(color, size=(64, 64)):
    return Image.new("RGB", size, color)


def test_gif_encoder_create_gif_and_decoder_roundtrip(tmp_path):
    frames = [_make_frame("red"), _make_frame("blue")]
    output = tmp_path / "out.gif"

    encoder = GIFEncoder(fps=2, loop=0)
    size = encoder.create_gif(frames, output, optimize=False)

    assert size > 0
    assert output.exists()

    decoder = GIFDecoder()
    extracted = decoder.extract_frames(output)
    assert len(extracted) == 2

    assert decoder.get_frame_count(output) == 2
    frame1 = decoder.get_frame(output, 1)
    assert frame1.size == frames[0].size


def test_gif_encoder_empty_frames_raises(tmp_path):
    encoder = GIFEncoder(fps=2)
    with pytest.raises(ValueError):
        encoder.create_gif([], tmp_path / "empty.gif")


def test_gif_encoder_create_gif_bytes_roundtrip():
    frames = [_make_frame("green", (32, 32)), _make_frame("yellow", (32, 32))]
    encoder = GIFEncoder(fps=5)
    data = encoder.create_gif_bytes(frames, optimize=False)

    assert data[:3] == b"GIF"

    decoder = GIFDecoder()
    extracted = decoder.extract_frames_bytes(data)
    assert len(extracted) == 2


def test_gif_decoder_get_frame_out_of_range(tmp_path):
    frames = [_make_frame("black")]
    output = tmp_path / "single.gif"
    encoder = GIFEncoder(fps=1)
    encoder.create_gif(frames, output)

    decoder = GIFDecoder()
    with pytest.raises(IndexError):
        decoder.get_frame(output, 1)


def test_gif_optimizer_optimizes(tmp_path):
    frames = [_make_frame("white", (64, 64)), _make_frame("gray", (64, 64))]
    input_path = tmp_path / "input.gif"
    output_path = tmp_path / "optimized.gif"

    GIFEncoder(fps=2).create_gif(frames, input_path)

    original_size, optimized_size = GIFOptimizer.optimize_gif(
        input_path, output_path, colors=64, reduce_size=True
    )

    assert original_size > 0
    assert optimized_size > 0
    assert output_path.exists()


def test_gif_encoder_resizes_and_converts(tmp_path):
    frames = [
        Image.new("L", (32, 32), color=128),
        Image.new("RGB", (64, 64), color="blue"),
    ]
    output = tmp_path / "out.gif"

    encoder = GIFEncoder(fps=2)
    size = encoder.create_gif(frames, output, optimize=False)

    assert size > 0
    assert output.exists()


def test_gif_encoder_create_gif_bytes_resizes_and_converts():
    frames = [
        Image.new("L", (16, 16), color=200),
        Image.new("RGB", (32, 32), color="red"),
    ]
    encoder = GIFEncoder(fps=5)
    data = encoder.create_gif_bytes(frames, optimize=True)

    assert data[:3] == b"GIF"


def test_gif_optimizer_get_gif_info(tmp_path):
    frames = [_make_frame("white", (32, 32))]
    input_path = tmp_path / "input.gif"

    GIFEncoder(fps=3).create_gif(frames, input_path)
    info = GIFOptimizer.get_gif_info(input_path)

    assert info["frames"] == 1
    assert info["size"] == (32, 32)

# --- Merged from test_coverage_boost_extras.py ---

# =====================================================
# gif_handler.py — push from 98.86% higher
# =====================================================
class TestGifHandlerExtras:
    """Extra gif_handler tests for small uncovered branches."""

    def test_create_gif_bytes_roundtrip(self):
        """Create GIF bytes and verify they're valid."""
        from meow_decoder.gif_handler import GIFEncoder
        from PIL import Image

        frames = [
            Image.new("RGB", (50, 50), "red"),
            Image.new("RGB", (50, 50), "green"),
            Image.new("RGB", (50, 50), "blue"),
        ]
        encoder = GIFEncoder(fps=5)
        gif_bytes = encoder.create_gif_bytes(frames)
        assert gif_bytes.startswith(b"GIF")
        assert len(gif_bytes) > 100

    def test_create_gif_mismatched_sizes(self, tmp_path):
        """Frames of different sizes should be resized."""
        from meow_decoder.gif_handler import GIFEncoder
        from PIL import Image

        frames = [
            Image.new("RGB", (100, 100), "red"),
            Image.new("RGB", (50, 50), "blue"),  # Different size
        ]
        encoder = GIFEncoder()
        output = tmp_path / "mismatch.gif"
        encoder.create_gif(frames, output)
        assert output.exists()


# =====================================================
# multi_secret.py — push from 98.25% higher
# =====================================================

# --- Merged from test_coverage_boost_remaining.py ---

# =====================================================
# gif_handler.py small gaps
# =====================================================
class TestGifHandlerBoost:
    def test_create_gif_bytes_empty_frames(self):
        """Empty frames should raise ValueError."""
        from meow_decoder.gif_handler import GIFEncoder

        handler = GIFEncoder()
        with pytest.raises(ValueError, match="No frames"):
            handler.create_gif_bytes([])

    def test_create_gif_empty_frames(self, tmp_path):
        """create_gif with empty frames should raise ValueError."""
        from meow_decoder.gif_handler import GIFEncoder

        handler = GIFEncoder()
        with pytest.raises(ValueError, match="No frames"):
            handler.create_gif([], tmp_path / "test.gif")

    def test_gif_decoder_extract_frames(self, tmp_path):
        """Test GIFDecoder.extract_frames."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from PIL import Image

        # Create a test GIF
        frames = [Image.new("RGB", (10, 10), "red"), Image.new("RGB", (10, 10), "blue")]
        encoder = GIFEncoder(fps=2)
        encoder.create_gif(frames, tmp_path / "test.gif")

        decoder = GIFDecoder()
        extracted = decoder.extract_frames(tmp_path / "test.gif")
        assert len(extracted) >= 2


# =====================================================
# spec_v12/encode.py and decode.py small gaps
# =====================================================

