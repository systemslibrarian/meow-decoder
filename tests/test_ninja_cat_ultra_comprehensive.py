#!/usr/bin/env python3
"""
🥷 Comprehensive tests for ninja_cat_ultra.py
Targets ~75-85% coverage with functional and edge-case checks.
"""

import numpy as np
import pytest
from PIL import Image

from meow_decoder.ninja_cat_ultra import (
    NinjaCatUltra,
    NinjaCatLevel,
    NinjaConfig,
    create_ninja_encoder,
)


@pytest.fixture
def sample_frame():
    """Create a small deterministic RGB frame."""
    data = np.zeros((10, 10, 3), dtype=np.uint8)
    data[:, :, 0] = 120
    data[:, :, 1] = 200
    data[:, :, 2] = 30
    return Image.fromarray(data, mode="RGB")


@pytest.fixture
def sample_frames(sample_frame):
    """Create a list of small frames."""
    return [sample_frame.copy() for _ in range(5)]


class TestNinjaCatInit:
    """Basic initialization tests."""

    def test_default_init_uses_ultra(self, capsys):
        encoder = NinjaCatUltra()
        assert encoder.config.stealth_level == NinjaCatLevel.ULTRA
        captured = capsys.readouterr()
        assert "Ninja Cat ULTRA" in captured.out

    def test_custom_config_respected(self):
        config = NinjaConfig(stealth_level=NinjaCatLevel.SUBTLE, enable_dummy_frames=False)
        encoder = NinjaCatUltra(config)
        assert encoder.config.stealth_level == NinjaCatLevel.SUBTLE
        assert encoder.config.enable_dummy_frames is False


class TestNinjaTransforms:
    """Transform behavior tests."""

    def test_temporal_noise_disabled_returns_same(self, sample_frame):
        config = NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE, enable_dynamic_noise=False)
        encoder = NinjaCatUltra(config)
        result = encoder.add_temporal_noise(sample_frame, 0)
        assert np.array(result).tolist() == np.array(sample_frame).tolist()

    def test_temporal_noise_enabled_changes_pixels(self, sample_frame):
        encoder = NinjaCatUltra(NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE))
        result = encoder.add_temporal_noise(sample_frame, 1)
        assert result.size == sample_frame.size
        assert np.array(result).shape == np.array(sample_frame).shape

    def test_hue_jitter_disabled_returns_same(self, sample_frame):
        config = NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE, enable_hue_jitter=False)
        encoder = NinjaCatUltra(config)
        result = encoder.add_hue_jitter(sample_frame, 0)
        assert np.array(result).tolist() == np.array(sample_frame).tolist()

    def test_hue_jitter_enabled_preserves_size(self, sample_frame):
        encoder = NinjaCatUltra(NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE))
        result = encoder.add_hue_jitter(sample_frame, 2)
        assert result.size == sample_frame.size

    def test_micro_rotation_disabled_returns_same(self, sample_frame):
        config = NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE, enable_micro_rotation=False)
        encoder = NinjaCatUltra(config)
        result = encoder.add_micro_rotation(sample_frame, 0)
        assert np.array(result).tolist() == np.array(sample_frame).tolist()

    def test_micro_rotation_enabled_preserves_size(self, sample_frame):
        encoder = NinjaCatUltra(NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE))
        result = encoder.add_micro_rotation(sample_frame, 3)
        assert result.size == sample_frame.size

    def test_apply_full_obfuscation_calls_all(self, sample_frame, monkeypatch):
        encoder = NinjaCatUltra(NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE))
        calls = {"noise": 0, "hue": 0, "rot": 0}

        def noise(frame, idx):
            calls["noise"] += 1
            return frame

        def hue(frame, idx):
            calls["hue"] += 1
            return frame

        def rot(frame, idx):
            calls["rot"] += 1
            return frame

        monkeypatch.setattr(encoder, "add_temporal_noise", noise)
        monkeypatch.setattr(encoder, "add_hue_jitter", hue)
        monkeypatch.setattr(encoder, "add_micro_rotation", rot)

        result = encoder.apply_full_obfuscation(sample_frame, 5)
        assert result is sample_frame
        assert calls == {"noise": 1, "hue": 1, "rot": 1}


class TestNinjaDummyFrames:
    """Dummy frame behavior."""

    def test_create_dummy_frame_properties(self):
        encoder = NinjaCatUltra(NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE))
        dummy = encoder.create_dummy_frame((8, 8), seed=123)
        assert dummy.size == (8, 8)
        assert dummy.mode == "RGB"

    def test_inject_dummy_frames_disabled(self, sample_frames):
        config = NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE, enable_dummy_frames=False)
        encoder = NinjaCatUltra(config)
        result = encoder.inject_dummy_frames(sample_frames)
        assert result == sample_frames

    def test_inject_dummy_frames_frequency(self, sample_frames):
        config = NinjaConfig(
            stealth_level=NinjaCatLevel.VISIBLE,
            enable_dummy_frames=True,
            dummy_frequency=2,
        )
        encoder = NinjaCatUltra(config)
        result = encoder.inject_dummy_frames(sample_frames)
        # 5 frames, inject after frame 1 and 3 => +2
        assert len(result) == 7


class TestNinjaQuality:
    """PSNR and auto-adjust tests."""

    def test_calculate_psnr_identical_is_inf(self, sample_frame):
        encoder = NinjaCatUltra(NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE))
        psnr = encoder.calculate_psnr(sample_frame, sample_frame.copy())
        assert psnr == float("inf")

    def test_calculate_psnr_different_is_finite(self, sample_frame):
        encoder = NinjaCatUltra(NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE))
        modified = sample_frame.copy()
        arr = np.array(modified)
        arr[0, 0, 0] = (arr[0, 0, 0] + 10) % 255
        modified = Image.fromarray(arr, mode="RGB")
        psnr = encoder.calculate_psnr(sample_frame, modified)
        assert psnr != float("inf")

    def test_auto_adjust_disabled_returns_current(self, sample_frames):
        config = NinjaConfig(stealth_level=NinjaCatLevel.SUBTLE, auto_adjust=False)
        encoder = NinjaCatUltra(config)
        level = encoder.auto_adjust_stealth(sample_frames, sample_frames)
        assert level == NinjaCatLevel.SUBTLE

    def test_auto_adjust_upgrades_to_ultra(self, sample_frames, capsys):
        config = NinjaConfig(stealth_level=NinjaCatLevel.SUBTLE, auto_adjust=True)
        encoder = NinjaCatUltra(config)
        level = encoder.auto_adjust_stealth(sample_frames, sample_frames)
        assert level == NinjaCatLevel.ULTRA
        captured = capsys.readouterr()
        assert "Upgrading to ULTRA" in captured.out


class TestNinjaProcess:
    """Process flow tests."""

    def test_process_frames_no_dummy(self, sample_frames):
        config = NinjaConfig(
            stealth_level=NinjaCatLevel.VISIBLE,
            enable_dummy_frames=False,
            auto_adjust=False,
        )
        encoder = NinjaCatUltra(config)
        processed = encoder.process_frames(sample_frames)
        assert len(processed) == len(sample_frames)

    def test_process_frames_with_dummy(self, sample_frames):
        config = NinjaConfig(
            stealth_level=NinjaCatLevel.VISIBLE,
            enable_dummy_frames=True,
            dummy_frequency=2,
            auto_adjust=False,
        )
        encoder = NinjaCatUltra(config)
        processed = encoder.process_frames(sample_frames)
        assert len(processed) == 7

    def test_show_warning_banner_prints(self, capsys):
        encoder = NinjaCatUltra(NinjaConfig(stealth_level=NinjaCatLevel.VISIBLE))
        encoder.show_warning_banner()
        captured = capsys.readouterr()
        assert "STEALTH RECOMMENDATIONS" in captured.out


class TestCreateNinjaEncoder:
    """Factory tests."""

    def test_create_ninja_encoder_defaults(self, capsys):
        encoder = create_ninja_encoder()
        assert isinstance(encoder, NinjaCatUltra)
        assert encoder.config.stealth_level == NinjaCatLevel.ULTRA
        captured = capsys.readouterr()
        assert "STEALTH RECOMMENDATIONS" in captured.out

    def test_create_ninja_encoder_custom_level(self):
        encoder = create_ninja_encoder(stealth_level=3, enable_all_tricks=False)
        assert encoder.config.stealth_level == NinjaCatLevel.HIDDEN
        assert encoder.config.enable_dummy_frames is False
