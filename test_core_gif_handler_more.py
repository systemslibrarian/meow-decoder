from pathlib import Path

import pytest
from PIL import Image

from meow_decoder.gif_handler import GIFEncoder, GIFDecoder, GIFOptimizer


def test_gif_encoder_create_gif_bytes_and_decoder_extract_bytes():
    frames = [
        Image.new("RGB", (64, 64), color=(255, 255, 255)),
        Image.new("RGB", (64, 64), color=(0, 0, 0)),
    ]
    enc = GIFEncoder(fps=5)
    gif_bytes = enc.create_gif_bytes(frames, optimize=False)

    dec = GIFDecoder()
    out_frames = dec.extract_frames_bytes(gif_bytes)
    assert len(out_frames) == 2
    assert out_frames[0].size == (64, 64)


def test_gif_decoder_get_frame_and_count(tmp_path: Path):
    frames = [
        Image.new("RGB", (32, 32), color=(255, 255, 255)),
        Image.new("RGB", (32, 32), color=(0, 0, 0)),
        Image.new("RGB", (32, 32), color=(127, 127, 127)),
    ]
    out = tmp_path / "x.gif"
    GIFEncoder(fps=10).create_gif(frames, out, optimize=False)

    dec = GIFDecoder()
    assert dec.get_frame_count(out) == 3
    f1 = dec.get_frame(out, 1)
    assert f1.size == (32, 32)
    with pytest.raises(IndexError):
        dec.get_frame(out, 99)


def test_gif_optimizer_optimize_gif(tmp_path: Path):
    frames = [
        Image.new("RGB", (64, 64), color=(255, 255, 255)),
        Image.new("RGB", (64, 64), color=(0, 0, 0)),
    ]
    inp = tmp_path / "in.gif"
    outp = tmp_path / "out.gif"
    GIFEncoder(fps=10).create_gif(frames, inp, optimize=False)

    original_size, optimized_size = GIFOptimizer.optimize_gif(
        inp, outp, colors=16, reduce_size=True
    )
    assert original_size > 0
    assert optimized_size > 0
    assert outp.exists()
