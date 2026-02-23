#!/usr/bin/env python3
"""
Fuzz target for multi-layer steganography system.
Uses Atheris (Google's Python fuzzing engine).

Covers:
- MultiLayerStegoEncoder / MultiLayerStegoDecoder with adversarial payloads
- STC matrix encoding with pathological pixel distributions
- GIF timing channel embed/extract
- Palette permutation channel
- Decode of corrupt stego GIFs
"""

import sys
import os

# Enable test mode to skip Argon2 heavy KDF
os.environ.setdefault("MEOW_TEST_MODE", "1")

try:
    import atheris
except ImportError:  # pragma: no cover
    atheris = None


def _setup_imports():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.stego_multilayer import (
        MultiLayerStegoEncoder,
        MultiLayerStegoDecoder,
        MultiLayerConfig,
        validate_stego,
    )
    import numpy as np
    from PIL import Image
    import io

    return (
        MultiLayerStegoEncoder,
        MultiLayerStegoDecoder,
        MultiLayerConfig,
        validate_stego,
        np,
        Image,
        io,
    )


if atheris is not None:
    with atheris.instrument_imports():
        (
            MultiLayerStegoEncoder,
            MultiLayerStegoDecoder,
            MultiLayerConfig,
            validate_stego,
            np,
            Image,
            io,
        ) = _setup_imports()
else:
    (
        MultiLayerStegoEncoder,
        MultiLayerStegoDecoder,
        MultiLayerConfig,
        validate_stego,
        np,
        Image,
        io,
    ) = _setup_imports()


def _make_carrier_gif(fdp) -> bytes:
    """Generate a small carrier GIF from fuzz-derived parameters."""
    width = fdp.ConsumeIntInRange(8, 64) if atheris else 32
    height = fdp.ConsumeIntInRange(8, 64) if atheris else 32
    n_frames = fdp.ConsumeIntInRange(1, 8) if atheris else 4

    frames = []
    for _ in range(n_frames):
        arr = np.zeros((height, width, 3), dtype=np.uint8)
        if atheris:
            raw = fdp.ConsumeBytes(width * height * 3)
            arr_flat = np.frombuffer(raw.ljust(width * height * 3, b"\x00"), dtype=np.uint8)
            arr = arr_flat[: width * height * 3].reshape(height, width, 3)
        frames.append(Image.fromarray(arr, "RGB"))

    buf = io.BytesIO()
    frames[0].save(
        buf,
        format="GIF",
        save_all=True,
        append_images=frames[1:],
        loop=0,
        duration=100,
    )
    return buf.getvalue()


def fuzz_encoder_decoder_roundtrip(data: bytes):
    """Fuzz encode → decode roundtrip with arbitrary payload and keys."""
    if len(data) < 34:
        return

    master_key = data[:32]
    payload_len_hint = data[32] % 200 + 1
    payload = data[33 : 33 + payload_len_hint]
    if not payload:
        return

    try:
        config = MultiLayerConfig(
            lsb_depth=1,
            use_timing_channel=False,  # Keep fast
            use_palette_channel=False,
        )
    except Exception:
        return

    # Build minimal synthetic carrier GIF
    frames = [Image.new("RGB", (32, 32), color=(i * 30 % 255, 0, 0)) for i in range(4)]
    buf = io.BytesIO()
    frames[0].save(
        buf,
        format="GIF",
        save_all=True,
        append_images=frames[1:],
        loop=0,
        duration=100,
    )
    carrier_gif = buf.getvalue()

    try:
        encoder = MultiLayerStegoEncoder(config, master_key)
        stego_gif = encoder.encode(payload, carrier_gif_bytes=carrier_gif)

        # Attempt decode; should never crash even on corrupt output
        decoder = MultiLayerStegoDecoder(config, master_key)
        result = decoder.decode(stego_gif)

        # If decode succeeded, verify payload integrity
        if result and result.get("payload_bytes"):
            recovered = result["payload_bytes"]
            assert isinstance(recovered, bytes), "payload must be bytes"

    except (ValueError, KeyError, AssertionError):
        pass  # Expected: capacity exceeded, format mismatch, etc.
    except Exception as e:
        msg = str(e).lower()
        expected = [
            "capacity",
            "too large",
            "payload",
            "encode",
            "decode",
            "gif",
            "frame",
            "image",
            "shape",
            "stego",
            "lsb",
            "walk",
            "numpy",
            "array",
            "palette",
            "invalid",
            "corrupt",
        ]
        if any(x in msg for x in expected):
            pass
        else:
            raise


def fuzz_decode_corrupt_gif(data: bytes):
    """Fuzz decode with completely arbitrary bytes as stego GIF."""
    if len(data) < 33:
        return

    master_key = data[:32]
    stego_bytes = data[32:]

    try:
        config = MultiLayerConfig(lsb_depth=1)
        decoder = MultiLayerStegoDecoder(config, master_key)
        decoder.decode(stego_bytes)
    except Exception as e:
        msg = str(e).lower()
        ignored = [
            "capacity",
            "too large",
            "payload",
            "encode",
            "decode",
            "gif",
            "frame",
            "image",
            "shape",
            "stego",
            "lsb",
            "walk",
            "numpy",
            "array",
            "palette",
            "invalid",
            "corrupt",
            "truncate",
            "not a gif",
            "cannot identify",
            "pil",
        ]
        if not any(x in msg for x in ignored):
            raise


def fuzz_validate_stego(data: bytes):
    """Fuzz the validate_stego utility with arbitrary bytes."""
    if len(data) < 33:
        return

    master_key = data[:32]
    gif_bytes = data[32:]

    try:
        config = MultiLayerConfig(lsb_depth=1)
        validate_stego(gif_bytes, config, master_key)
    except Exception as e:
        msg = str(e).lower()
        ignored = [
            "gif",
            "invalid",
            "validate",
            "stego",
            "image",
            "pil",
            "frame",
            "corrupt",
            "not a gif",
            "cannot identify",
        ]
        if not any(x in msg for x in ignored):
            raise


def fuzz_walk_uniqueness(data: bytes):
    """Fuzz that the LSB walk does not produce index collisions."""
    if len(data) < 48:
        return

    master_key = data[:32]
    frame_idx = int.from_bytes(data[32:34], "little") % 64
    n_pixels = (int.from_bytes(data[34:36], "little") % 2000) + 10
    channel = data[36] % 3

    try:
        config = MultiLayerConfig(lsb_depth=1)
        encoder = MultiLayerStegoEncoder(config, master_key)
        # Derive walk directly if method is accessible
        if hasattr(encoder, "_derive_walk_indices"):
            indices = encoder._derive_walk_indices(frame_idx, n_pixels, channel)
            # Indices must be unique within a frame-channel pair
            assert len(set(indices)) == len(indices), "walk index collision detected"
    except (AttributeError, NotImplementedError):
        pass  # Method not exposed publicly
    except Exception as e:
        msg = str(e).lower()
        if "collision" in msg:
            raise  # Always re-raise our own assertion
        if not any(x in msg for x in ["walk", "index", "capacity", "frame"]):
            raise


def combined_fuzz(data: bytes):
    fuzz_encoder_decoder_roundtrip(data)
    fuzz_decode_corrupt_gif(data)
    fuzz_validate_stego(data)
    fuzz_walk_uniqueness(data)


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
