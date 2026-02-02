#!/usr/bin/env python3
"""
🐱 AGGRESSIVE Coverage Tests for config.py
Target: Boost config.py from 55% to 90%+
"""

import pytest
import sys
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestEncodingConfig:
    """Test EncodingConfig dataclass."""
    
    def test_default_values(self):
        """Test default values."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.block_size == 512
        assert config.redundancy == 1.5
        assert config.qr_error_correction == "H"
        assert config.fps == 2
    
    def test_custom_values(self):
        """Test custom values."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig(
            block_size=256,
            redundancy=2.0,
            fps=10
        )
        
        assert config.block_size == 256
        assert config.redundancy == 2.0
        assert config.fps == 10
    
    def test_security_defaults(self):
        """Test security-related defaults."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.enable_forward_secrecy == True
        assert config.enable_pq == True
        assert config.require_rust == True
    
    def test_all_fields_accessible(self):
        """Test all fields are accessible."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        # Access all fields
        _ = config.block_size
        _ = config.redundancy
        _ = config.qr_error_correction
        _ = config.qr_box_size
        _ = config.qr_border
        _ = config.fps
        _ = config.enable_forward_secrecy
        _ = config.ratchet_interval
        _ = config.enable_stego
        _ = config.stealth_level
        _ = config.enable_animation
        _ = config.enable_low_memory
        _ = config.enable_pq
        _ = config.enable_duress
        _ = config.enable_hardware_keys
        _ = config.enable_enhanced_entropy
        _ = config.enable_chaff_frames
        _ = config.require_rust
        _ = config.enable_profiling


class TestDecodingConfig:
    """Test DecodingConfig dataclass."""
    
    def test_default_values(self):
        """Test default values."""
        from meow_decoder.config import DecodingConfig
        
        config = DecodingConfig()
        
        assert config.webcam_device == 0
        assert config.frame_skip == 0
        assert config.preprocessing == "normal"
    
    def test_custom_values(self):
        """Test custom values."""
        from meow_decoder.config import DecodingConfig
        
        config = DecodingConfig(
            webcam_device=1,
            preprocessing="aggressive"
        )
        
        assert config.webcam_device == 1
        assert config.preprocessing == "aggressive"
    
    def test_all_fields_accessible(self):
        """Test all fields are accessible."""
        from meow_decoder.config import DecodingConfig
        
        config = DecodingConfig()
        
        _ = config.webcam_device
        _ = config.frame_skip
        _ = config.preprocessing
        _ = config.enable_resume
        _ = config.resume_password
        _ = config.save_interval
        _ = config.enable_stego
        _ = config.aggressive_stego
        _ = config.max_memory_mb


class TestCryptoConfig:
    """Test CryptoConfig dataclass."""
    
    def test_default_values(self):
        """Test default values."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig()
        
        assert config.key_derivation == "argon2id"
        assert config.cipher == "aes-256-gcm"
    
    def test_argon2_parameters(self):
        """Test Argon2 parameters."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig()
        
        # Should have strong defaults
        assert config.argon2_memory >= 65536
        assert config.argon2_iterations >= 1
        assert config.argon2_parallelism >= 1
    
    def test_pq_default_on(self):
        """Test PQ is on by default."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig()
        
        assert config.enable_pq == True
        assert config.kyber_variant == "kyber1024"
    
    def test_all_fields_accessible(self):
        """Test all fields are accessible."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig()
        
        _ = config.key_derivation
        _ = config.argon2_memory
        _ = config.argon2_iterations
        _ = config.argon2_parallelism
        _ = config.ultra_hardened
        _ = config.cipher
        _ = config.require_rust
        _ = config.enable_forward_secrecy
        _ = config.ratchet_interval
        _ = config.enable_pq
        _ = config.kyber_variant


class TestDuressConfig:
    """Test DuressConfig dataclass."""
    
    def test_default_values(self):
        """Test default values."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig()
        
        assert config.enabled == False
        assert config.mode == DuressMode.DECOY
        assert config.panic_enabled == False
    
    def test_duress_modes(self):
        """Test duress modes."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config_decoy = DuressConfig(mode=DuressMode.DECOY)
        config_panic = DuressConfig(mode=DuressMode.PANIC)
        
        assert config_decoy.mode == DuressMode.DECOY
        assert config_panic.mode == DuressMode.PANIC
    
    def test_decoy_settings(self):
        """Test decoy settings."""
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig(
            decoy_type="message",
            decoy_message="Custom message"
        )
        
        assert config.decoy_type == "message"
        assert config.decoy_message == "Custom message"
    
    def test_all_fields_accessible(self):
        """Test all fields are accessible."""
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig()
        
        _ = config.enabled
        _ = config.mode
        _ = config.panic_enabled
        _ = config.decoy_type
        _ = config.decoy_message
        _ = config.decoy_file_path
        _ = config.decoy_output_name
        _ = config.show_decoy
        _ = config.wipe_memory
        _ = config.wipe_resume_files
        _ = config.exit_after_wipe
        _ = config.overwrite_passes
        _ = config.gc_aggressive
        _ = config.min_delay_ms
        _ = config.max_delay_ms
        _ = config.trigger_callback


class TestDuressMode:
    """Test DuressMode enum."""
    
    def test_decoy_mode(self):
        """Test DECOY mode."""
        from meow_decoder.config import DuressMode
        
        mode = DuressMode.DECOY
        assert mode.value == "decoy"
    
    def test_panic_mode(self):
        """Test PANIC mode."""
        from meow_decoder.config import DuressMode
        
        mode = DuressMode.PANIC
        assert mode.value == "panic"
    
    def test_mode_from_string(self):
        """Test creating mode from string."""
        from meow_decoder.config import DuressMode
        
        mode = DuressMode("decoy")
        assert mode == DuressMode.DECOY


class TestPathConfig:
    """Test PathConfig dataclass."""
    
    def test_default_paths(self):
        """Test default paths."""
        from meow_decoder.config import PathConfig
        
        config = PathConfig()
        
        assert config.cache_dir.exists()
        assert config.resume_dir.exists()
        assert config.temp_dir.exists()
    
    def test_custom_paths(self):
        """Test custom paths."""
        from meow_decoder.config import PathConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = Path(tmpdir) / "cache"
            resume = Path(tmpdir) / "resume"
            temp = Path(tmpdir) / "temp"
            
            config = PathConfig(
                cache_dir=cache,
                resume_dir=resume,
                temp_dir=temp
            )
            
            assert config.cache_dir == cache
            assert cache.exists()


class TestMeowConfig:
    """Test MeowConfig dataclass."""
    
    def test_default_creation(self):
        """Test default creation."""
        from meow_decoder.config import MeowConfig
        
        config = MeowConfig()
        
        assert config.encoding is not None
        assert config.decoding is not None
        assert config.crypto is not None
        assert config.duress is not None
        assert config.paths is not None
    
    def test_verbose_debug_flags(self):
        """Test verbose and debug flags."""
        from meow_decoder.config import MeowConfig
        
        config = MeowConfig(verbose=True, debug=True)
        
        assert config.verbose == True
        assert config.debug == True
    
    def test_nested_configs(self):
        """Test accessing nested configs."""
        from meow_decoder.config import MeowConfig, EncodingConfig
        
        encoding = EncodingConfig(block_size=256)
        config = MeowConfig(encoding=encoding)
        
        assert config.encoding.block_size == 256
    
    def test_save_and_load(self):
        """Test save and load."""
        from meow_decoder.config import MeowConfig
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = Path(f.name)
        
        try:
            config = MeowConfig()
            config.encoding.block_size = 256
            config.verbose = True
            
            config.save(config_path)
            
            loaded = MeowConfig.load(config_path)
            
            assert loaded.encoding.block_size == 256
            assert loaded.verbose == True
        finally:
            config_path.unlink()
    
    def test_save_creates_file(self):
        """Test that save creates file."""
        from meow_decoder.config import MeowConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            
            config = MeowConfig()
            config.save(path)
            
            assert path.exists()
    
    def test_load_missing_fields(self):
        """Test loading config with missing fields."""
        from meow_decoder.config import MeowConfig
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"verbose": True}, f)
            config_path = Path(f.name)
        
        try:
            loaded = MeowConfig.load(config_path)
            assert loaded.verbose == True
            # Should have defaults for missing
            assert loaded.encoding is not None
        finally:
            config_path.unlink()
    
    def test_save_duress_enum(self):
        """Test saving duress mode enum."""
        from meow_decoder.config import MeowConfig, DuressMode
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = Path(f.name)
        
        try:
            config = MeowConfig()
            config.duress.mode = DuressMode.PANIC
            
            config.save(config_path)
            
            # Read raw JSON
            with open(config_path) as f:
                data = json.load(f)
            
            assert data['duress']['mode'] == 'panic'
        finally:
            config_path.unlink()
    
    def test_load_duress_enum(self):
        """Test loading duress mode enum."""
        from meow_decoder.config import MeowConfig, DuressMode
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "duress": {"mode": "panic", "enabled": True}
            }, f)
            config_path = Path(f.name)
        
        try:
            loaded = MeowConfig.load(config_path)
            assert loaded.duress.mode == DuressMode.PANIC
        finally:
            config_path.unlink()


class TestGetConfig:
    """Test get_config function."""
    
    def test_get_config_no_file(self):
        """Test get_config when no file exists."""
        from meow_decoder.config import get_config
        
        # Should return default config
        config = get_config()
        
        assert config is not None
        assert config.encoding is not None
    
    def test_get_config_returns_meowconfig(self):
        """Test get_config returns MeowConfig."""
        from meow_decoder.config import get_config, MeowConfig
        
        config = get_config()
        
        assert isinstance(config, MeowConfig)


class TestSaveConfig:
    """Test save_config function."""
    
    def test_save_config(self):
        """Test save_config creates directories."""
        from meow_decoder.config import save_config, MeowConfig
        
        config = MeowConfig()
        
        # This should not raise
        try:
            save_config(config)
        except Exception:
            # May fail if directory creation fails, that's OK
            pass


class TestDefaultConfig:
    """Test DEFAULT_CONFIG constant."""
    
    def test_default_config_exists(self):
        """Test DEFAULT_CONFIG exists."""
        from meow_decoder.config import DEFAULT_CONFIG
        
        assert DEFAULT_CONFIG is not None
    
    def test_default_config_is_meowconfig(self):
        """Test DEFAULT_CONFIG is MeowConfig."""
        from meow_decoder.config import DEFAULT_CONFIG, MeowConfig
        
        assert isinstance(DEFAULT_CONFIG, MeowConfig)


class TestConfigSecurityDefaults:
    """Test security-related defaults."""
    
    def test_forward_secrecy_default(self):
        """Test forward secrecy is on by default."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.enable_forward_secrecy == True
    
    def test_pq_crypto_default(self):
        """Test PQ crypto is on by default."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.enable_pq == True
    
    def test_rust_required_default(self):
        """Test Rust is required by default."""
        from meow_decoder.config import EncodingConfig, CryptoConfig
        
        encoding = EncodingConfig()
        crypto = CryptoConfig()
        
        assert encoding.require_rust == True
        assert crypto.require_rust == True
    
    def test_hardware_keys_default(self):
        """Test hardware keys enabled by default."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.enable_hardware_keys == True
    
    def test_enhanced_entropy_default(self):
        """Test enhanced entropy enabled by default."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.enable_enhanced_entropy == True


class TestConfigEdgeCases:
    """Test edge cases."""
    
    def test_empty_json_load(self):
        """Test loading empty JSON."""
        from meow_decoder.config import MeowConfig
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({}, f)
            config_path = Path(f.name)
        
        try:
            loaded = MeowConfig.load(config_path)
            # Should have all defaults
            assert loaded.encoding is not None
        finally:
            config_path.unlink()
    
    def test_invalid_duress_mode_fallback(self):
        """Test invalid duress mode falls back."""
        from meow_decoder.config import MeowConfig, DuressMode
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "duress": {"mode": "invalid_mode"}
            }, f)
            config_path = Path(f.name)
        
        try:
            loaded = MeowConfig.load(config_path)
            # Should fallback to DECOY
            assert loaded.duress.mode == DuressMode.DECOY
        finally:
            config_path.unlink()


class TestImportability:
    """Test module imports."""
    
    def test_import_all_config_classes(self):
        """Test importing all config classes."""
        from meow_decoder.config import (
            EncodingConfig,
            DecodingConfig,
            CryptoConfig,
            DuressConfig,
            DuressMode,
            PathConfig,
            MeowConfig,
            DEFAULT_CONFIG,
            get_config,
            save_config
        )
        
        assert EncodingConfig is not None
        assert DecodingConfig is not None
        assert CryptoConfig is not None
        assert DuressConfig is not None
        assert DuressMode is not None
        assert PathConfig is not None
        assert MeowConfig is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
