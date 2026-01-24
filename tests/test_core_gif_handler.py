from pathlib import Path

import pytest
from PIL import Image

from meow_decoder.gif_handler import GIFEncoder, GIFDecoder


def test_gif_create_and_extract_roundtrip(tmp_path: Path):
    frames = [
        Image.new("RGB", (64, 64), color=(255, 0, 0)),
        Image.new("RGB", (64, 64), color=(0, 255, 0)),
        Image.new("RGB", (64, 64), color=(0, 0, 255)),
    ]

    out_path = tmp_path / "out.gif"

    enc = GIFEncoder(fps=10, loop=0)
    size = enc.create_gif(frames, out_path, optimize=False)
    assert size > 0
    assert out_path.exists()

    dec = GIFDecoder()
    extracted = dec.extract_frames(out_path)
    assert len(extracted) >= 1
    assert extracted[0].size == (64, 64)


def test_gif_decoder_rejects_missing_file(tmp_path: Path):
    dec = GIFDecoder()
    with pytest.raises(Exception):
        dec.extract_frames(tmp_path / "does_not_exist.gif")
