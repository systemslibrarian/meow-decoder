#!/usr/bin/env python3
"""Tests for config.py (target 95%+ coverage)."""

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

import meow_decoder.config as config_module
from meow_decoder.config import (
    DuressConfig,
    DuressMode,
    EncodingConfig,
    DecodingConfig,
    CryptoConfig,
    PathConfig,
    MeowConfig,
    get_config,
    save_config,
)


def test_duress_config_defaults():
    config = DuressConfig()
    assert config.enabled is False
    assert config.mode == DuressMode.DECOY
    assert config.panic_enabled is False
    assert config.wipe_memory is True
    assert config.wipe_resume_files is True


def test_duress_config_custom():
    config = DuressConfig(
        enabled=True,
        mode=DuressMode.PANIC,
        panic_enabled=True,
        decoy_message="Custom",
        overwrite_passes=7,
    )
    assert config.enabled is True
    assert config.mode == DuressMode.PANIC
    assert config.decoy_message == "Custom"
    assert config.overwrite_passes == 7


def test_encoding_config_defaults():
    config = EncodingConfig()
    assert config.block_size == 512
    assert config.redundancy == 2.5  # resilient default (emits coded droplets ≥2×k)
    assert config.qr_error_correction == "H"
    assert config.qr_box_size == 14
    assert config.fps == 2
    assert config.enable_forward_secrecy is True
    assert config.enable_pq is True


def test_encoding_config_custom():
    config = EncodingConfig(
        block_size=256,
        redundancy=2.0,
        qr_error_correction="L",
        fps=10,
        enable_stego=True,
        stealth_level=4,
    )
    assert config.block_size == 256
    assert config.redundancy == 2.0
    assert config.qr_error_correction == "L"
    assert config.fps == 10
    assert config.enable_stego is True
    assert config.stealth_level == 4


def test_decoding_config_defaults():
    config = DecodingConfig()
    assert config.webcam_device == 0
    assert config.frame_skip == 0
    assert config.preprocessing == "normal"
    assert config.enable_resume is True
    assert config.max_memory_mb == 500


def test_decoding_config_custom():
    config = DecodingConfig(
        webcam_device=1,
        preprocessing="aggressive",
        enable_stego=True,
        max_memory_mb=1000,
    )
    assert config.webcam_device == 1
    assert config.preprocessing == "aggressive"
    assert config.enable_stego is True
    assert config.max_memory_mb == 1000


def test_crypto_config_defaults():
    config = CryptoConfig()
    assert config.key_derivation == "argon2id"
    assert config.argon2_memory == 524288
    assert config.argon2_iterations == 20
    assert config.argon2_parallelism == 4
    assert config.cipher == "aes-256-gcm"
    assert config.enable_forward_secrecy is True
    assert config.enable_pq is True
    assert config.kyber_variant == "kyber768"
    assert config.pq_paranoid is False


def test_crypto_config_ultra_hardened():
    config = CryptoConfig(ultra_hardened=True)
    assert config.ultra_hardened is True


def test_path_config_creates_directories(tmp_path):
    cache = tmp_path / "cache"
    resume = tmp_path / "resume"
    temp = tmp_path / "temp"
    config = PathConfig(cache_dir=cache, resume_dir=resume, temp_dir=temp)
    # Directories are created lazily via ensure_dirs(), not at construction
    assert not cache.exists()
    config.ensure_dirs()
    assert cache.exists()
    assert resume.exists()
    assert temp.exists()


def test_meow_config_save_load_roundtrip(tmp_path):
    config = MeowConfig()
    config.duress.mode = DuressMode.PANIC
    config.encoding.block_size = 1024
    config.verbose = True

    path = tmp_path / "config.json"
    config.save(path)

    loaded = MeowConfig.load(path)
    assert loaded.duress.mode == DuressMode.PANIC
    assert loaded.encoding.block_size == 1024
    assert loaded.verbose is True


def test_meow_config_load_with_invalid_mode_fallback(tmp_path):
    data = {
        "encoding": {},
        "decoding": {},
        "crypto": {},
        "duress": {"mode": "invalid"},
        "paths": {
            "cache_dir": str(tmp_path / "cache"),
            "resume_dir": str(tmp_path / "resume"),
            "temp_dir": str(tmp_path / "temp"),
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))

    loaded = MeowConfig.load(path)
    assert loaded.duress.mode == DuressMode.DECOY


def test_get_config_missing_file_returns_default(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module.Path, "home", lambda: tmp_path)
    cfg = get_config()
    assert isinstance(cfg, MeowConfig)


def test_get_config_invalid_json_returns_default(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module.Path, "home", lambda: tmp_path)
    cfg_path = tmp_path / ".config" / "meowdecoder" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text("{not: json}")

    cfg = get_config()
    assert isinstance(cfg, MeowConfig)


def test_save_config_writes_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module.Path, "home", lambda: tmp_path)
    config = MeowConfig()
    save_config(config)

    cfg_path = tmp_path / ".config" / "meowdecoder" / "config.json"
    assert cfg_path.exists()


# --- Merged from test_coverage_boost_remaining.py ---


# =====================================================
# config.py additional coverage
# =====================================================
class TestConfig:
    def test_encoding_config_defaults(self):
        """Test EncodingConfig default values."""
        from meow_decoder.config import EncodingConfig

        config = EncodingConfig()
        assert config.block_size > 0
        assert config.redundancy >= 1.0

    def test_meow_config(self):
        """Test MeowConfig creation."""
        from meow_decoder.config import MeowConfig

        config = MeowConfig()
        assert config is not None

    def test_duress_config_defaults(self):
        """Test DuressConfig defaults."""
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        assert config.decoy_type == "message"
        assert config.wipe_memory is True


# =====================================================
# frame_mac.py coverage
# =====================================================
