#!/usr/bin/env python3
"""Tests for meow_decoder.stego_advanced."""

import numpy as np
from PIL import Image

from meow_decoder.stego_advanced import (
    StealthLevel,
    create_green_mask,
    calculate_masked_capacity,
    AdvancedStegoEncoder,
    AdvancedStegoDecoder,
    encode_with_stego,
    decode_with_stego,
)


def _image(color, size=(4, 4)):
    return Image.new("RGB", size, color=color)


def test_create_green_mask_rgb_and_gray():
    green = _image((0, 200, 0))
    red = _image((200, 0, 0))

    mask_green = create_green_mask(green)
    mask_red = create_green_mask(red)

    assert bool(mask_green.any()) is True
    assert bool(mask_red.any()) is False

    gray = Image.new("L", (4, 4), color=128)
    mask_gray = create_green_mask(gray)
    assert bool(mask_gray.any()) is False


def test_calculate_masked_capacity():
    mask = np.array([[True, False], [True, True]])
    info = calculate_masked_capacity(mask, lsb_bits=2)

    assert info["usable_pixels"] == 3
    assert info["total_pixels"] == 4
    assert info["bytes_capacity"] >= 0
    assert info["lsb_bits"] == 2


def test_lsb_bits_by_stealth_level():
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.VISIBLE)
    assert enc.lsb_bits == 3

    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.SUBTLE)
    assert enc.lsb_bits == 2

    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.HIDDEN)
    assert enc.lsb_bits == 1

    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.PARANOID)
    assert enc.lsb_bits == 1


def test_embed_frame_and_quality():
    qr = _image((255, 255, 255))
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.SUBTLE, quality_threshold=0.0)

    stego, quality = enc.embed_frame(qr)
    assert stego.size == qr.size
    assert quality.psnr >= 0.0
    assert quality.lsb_bits == 2


def test_embed_lsb_with_roi_mask():
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.SUBTLE, quality_threshold=0.0)

    qr = np.zeros((2, 2, 3), dtype=np.uint8)
    carrier = np.ones((2, 2, 3), dtype=np.uint8) * 255
    mask = np.array([[True, False], [False, True]])

    stego = enc._embed_lsb(qr, carrier, roi_mask=mask)

    # Unmasked pixels should remain unchanged
    assert (stego[0, 1] == carrier[0, 1]).all()
    assert (stego[1, 0] == carrier[1, 0]).all()


def test_encode_decode_with_stego_roundtrip():
    qr_frames = [_image((255, 255, 255)), _image((0, 0, 0))]

    stego_frames, qualities = encode_with_stego(qr_frames, stealth_level=StealthLevel.SUBTLE)
    assert len(stego_frames) == len(qr_frames)
    assert len(qualities) == len(qr_frames)

    extracted = decode_with_stego(stego_frames, lsb_bits=2, aggressive=True)
    assert len(extracted) == len(qr_frames)
    assert extracted[0].size == qr_frames[0].size


def test_advanced_decoder_extract():
    qr = _image((255, 0, 0))
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.SUBTLE, quality_threshold=0.0)
    stego, _ = enc.embed_frame(qr)

    dec = AdvancedStegoDecoder(lsb_bits=2, aggressive=True)
    extracted = dec.extract_frame(stego)

    assert extracted.size == qr.size
