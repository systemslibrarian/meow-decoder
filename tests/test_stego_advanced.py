#!/usr/bin/env python3
"""Tests for meow_decoder.stego_advanced."""

import sys
import types
import runpy
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


def test_embed_frame_paranoid_obfuscation():
    qr = _image((255, 255, 255))
    enc = AdvancedStegoEncoder(
        stealth_level=StealthLevel.PARANOID,
        enable_obfuscation=True,
        quality_threshold=0.0,
    )

    stego, quality = enc.embed_frame(qr)
    assert stego.size == qr.size
    assert quality.stealth_level == StealthLevel.PARANOID


def test_embed_frame_quality_threshold_fails():
    qr = _image((255, 255, 255))
    carrier = _image((0, 0, 0))
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.VISIBLE, quality_threshold=1e6)

    try:
        enc.embed_frame(qr, carrier)
    except ValueError as exc:
        assert "Quality below threshold" in str(exc)
    else:
        assert False, "Expected ValueError for strict threshold"


def test_embed_lsb_with_roi_mask():
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.SUBTLE, quality_threshold=0.0)

    qr = np.zeros((2, 2, 3), dtype=np.uint8)
    carrier = np.ones((2, 2, 3), dtype=np.uint8) * 255
    mask = np.array([[True, False], [False, True]])

    stego = enc._embed_lsb(qr, carrier, roi_mask=mask)

    # Unmasked pixels should remain unchanged
    assert (stego[0, 1] == carrier[0, 1]).all()
    assert (stego[1, 0] == carrier[1, 0]).all()


def test_generate_carriers_static_and_animated():
    enc_static = AdvancedStegoEncoder(enable_animation=False)
    static = enc_static._generate_carrier((2, 2), 0)
    assert static.size == (2, 2)

    enc_anim = AdvancedStegoEncoder(enable_animation=True)
    animated = enc_anim._generate_carrier((2, 2), 1)
    assert animated.size == (2, 2)


def test_apply_obfuscation_with_scipy(monkeypatch):
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.PARANOID, enable_obfuscation=True)
    data = np.zeros((2, 2, 3), dtype=np.uint8)

    fake_scipy = types.SimpleNamespace()
    fake_scipy.ndimage = types.SimpleNamespace(gaussian_filter=lambda arr, sigma: arr)
    monkeypatch.setitem(sys.modules, "scipy", fake_scipy)
    monkeypatch.setitem(sys.modules, "scipy.ndimage", fake_scipy.ndimage)

    obfuscated = enc._apply_obfuscation(data)
    assert obfuscated.shape == data.shape


def test_calculate_quality_zero_mse():
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.SUBTLE, quality_threshold=0.0)
    carrier = np.zeros((2, 2, 3), dtype=np.uint8)
    quality = enc._calculate_quality(carrier, carrier.copy())
    assert quality.psnr == float("inf")
    assert quality.passed_threshold is True


def test_encode_decode_with_stego_roundtrip():
    qr_frames = [_image((255, 255, 255)), _image((0, 0, 0))]

    stego_frames, qualities = encode_with_stego(qr_frames, stealth_level=StealthLevel.SUBTLE)
    assert len(stego_frames) == len(qr_frames)
    assert len(qualities) == len(qr_frames)

    extracted = decode_with_stego(stego_frames, lsb_bits=2, aggressive=True)
    assert len(extracted) == len(qr_frames)
    assert extracted[0].size == qr_frames[0].size


def test_encode_with_stego_carrier_shorter_list():
    qr_frames = [_image((255, 255, 255)), _image((0, 0, 0))]
    carriers = [_image((10, 10, 10))]

    stego_frames, qualities = encode_with_stego(qr_frames, carriers=carriers)
    assert len(stego_frames) == 2
    assert len(qualities) == 2


def test_advanced_decoder_extract():
    qr = _image((255, 0, 0))
    enc = AdvancedStegoEncoder(stealth_level=StealthLevel.SUBTLE, quality_threshold=0.0)
    stego, _ = enc.embed_frame(qr)

    dec = AdvancedStegoDecoder(lsb_bits=2, aggressive=True)
    extracted = dec.extract_frame(stego)

    assert extracted.size == qr.size


def test_decoder_aggressive_preprocess_with_scipy(monkeypatch):
    dec = AdvancedStegoDecoder(lsb_bits=2, aggressive=True)
    arr = np.ones((2, 2, 3), dtype=np.uint8) * 128

    fake_scipy = types.SimpleNamespace()
    fake_scipy.ndimage = types.SimpleNamespace(median_filter=lambda a, size: a)
    monkeypatch.setitem(sys.modules, "scipy", fake_scipy)
    monkeypatch.setitem(sys.modules, "scipy.ndimage", fake_scipy.ndimage)

    processed = dec._aggressive_preprocess(arr.copy())
    assert processed.shape == arr.shape


def test_decode_with_stego_non_aggressive():
    frames = [_image((255, 255, 255))]
    decoded = decode_with_stego(frames, lsb_bits=1, aggressive=False)
    assert len(decoded) == 1


def test_stego_advanced_main_runs(monkeypatch):
    def fake_randint(low, high=None, size=None, dtype=None):
        return np.zeros((2, 2, 3), dtype=np.uint8)

    monkeypatch.setattr(np.random, "randint", fake_randint)
    runpy.run_module("meow_decoder.stego_advanced", run_name="__main__")
