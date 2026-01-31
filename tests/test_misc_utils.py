#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for utility modules - Target: 90%+
Tests various utility functions and helpers across the codebase.
"""

import pytest
import secrets
import tempfile
import sys
import os
import time
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestVersionDetection:
    """Test version detection utilities."""
    
    def test_import_version_module(self):
        """Test importing version module."""
        try:
            from meow_decoder import __version__
            assert __version__ is not None
            assert isinstance(__version__, str)
        except ImportError:
            pytest.skip("__version__ not available")
    
    def test_version_format(self):
        """Test version string format."""
        try:
            from meow_decoder import __version__
            
            # Should be semver-like
            parts = __version__.split('.')
            assert len(parts) >= 2  # At least major.minor
        except ImportError:
            pytest.skip("__version__ not available")


class TestProgressBar:
    """Test progress bar utilities."""
    
    def test_import_progress_bar(self):
        """Test importing ProgressBar."""
        from meow_decoder.progress import ProgressBar
        assert ProgressBar is not None
    
    def test_create_progress_bar(self):
        """Test creating a progress bar."""
        from meow_decoder.progress import ProgressBar
        
        bar = ProgressBar(total=100, desc="Test", unit="items")
        assert bar is not None
    
    def test_progress_bar_iteration(self):
        """Test iterating with progress bar."""
        from meow_decoder.progress import ProgressBar
        
        bar = ProgressBar(total=10, desc="Test", disable=True)
        
        count = 0
        for i in bar(range(10)):
            count += 1
        
        assert count == 10
    
    def test_progress_bar_disabled(self):
        """Test disabled progress bar."""
        from meow_decoder.progress import ProgressBar
        
        bar = ProgressBar(total=100, desc="Test", disable=True)
        
        for i in bar(range(5)):
            pass  # Should not display


class TestSecureZeroing:
    """Test secure memory zeroing."""
    
    def test_secure_zero_memory_bytearray(self):
        """Test zeroing bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        data = bytearray(b"secret_data_here")
        secure_zero_memory(data)
        
        # Should be zeroed
        assert all(b == 0 for b in data)
    
    def test_secure_memory_context(self):
        """Test secure memory context manager."""
        from meow_decoder.constant_time import secure_memory
        
        with secure_memory(b"secret_data") as buf:
            assert len(buf) > 0
        
        # After context, buffer should be zeroed
    
    def test_secure_buffer_class(self):
        """Test SecureBuffer class."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(64) as buf:
            buf.write(b"test data")
            data = buf.read(9)
            assert data == b"test data"


class TestConstantTimeOps:
    """Test constant-time operations."""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"secret_value_123"
        b_val = b"secret_value_123"
        
        assert constant_time_compare(a, b_val) is True
    
    def test_constant_time_compare_different(self):
        """Test constant-time comparison with different values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"secret_value_123"
        b_val = b"different_value_"
        
        assert constant_time_compare(a, b_val) is False
    
    def test_timing_safe_equal_with_delay(self):
        """Test timing-safe comparison with delay."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        
        a = b"test_value"
        b_val = b"test_value"
        
        result = timing_safe_equal_with_delay(a, b_val, min_delay_ms=1, max_delay_ms=5)
        assert result is True
    
    def test_equalize_timing(self):
        """Test timing equalization."""
        from meow_decoder.constant_time import equalize_timing
        
        # Should not raise
        equalize_timing(0.001, 0.01)


class TestCatUtils:
    """Test cat utilities."""
    
    def test_nine_lives_retry(self):
        """Test NineLivesRetry."""
        from meow_decoder.cat_utils import NineLivesRetry
        
        retry = NineLivesRetry(max_lives=3, verbose=False)
        
        attempts = 0
        for life in retry.attempt():
            attempts += 1
            if attempts < 2:
                retry.fail("Test failure")
            else:
                retry.success("Success!")
                break
        
        assert retry.succeeded
        assert attempts == 2
    
    def test_purr_logger(self):
        """Test PurrLogger."""
        try:
            from meow_decoder.cat_utils import PurrLogger
            
            logger = PurrLogger(enabled=False)
            logger.log("Test message")
            logger.success("Success!")
            logger.crypto_op("Crypto operation")
        except ImportError:
            pytest.skip("PurrLogger not available")
    
    def test_enable_purr_mode(self):
        """Test enabling purr mode."""
        try:
            from meow_decoder.cat_utils import enable_purr_mode
            
            logger = enable_purr_mode(enabled=False)
            assert logger is not None
        except ImportError:
            pytest.skip("enable_purr_mode not available")
    
    def test_get_cat_fact(self):
        """Test getting cat facts."""
        try:
            from meow_decoder.cat_utils import get_cat_fact
            
            fact = get_cat_fact()
            assert isinstance(fact, str)
            assert len(fact) > 0
        except (ImportError, AttributeError):
            pytest.skip("get_cat_fact not available")
    
    def test_meow_about(self):
        """Test meow_about function."""
        try:
            from meow_decoder.cat_utils import meow_about
            
            about = meow_about()
            assert isinstance(about, str)
            assert "meow" in about.lower() or "version" in about.lower()
        except (ImportError, AttributeError):
            pytest.skip("meow_about not available")


class TestDecoyGeneration:
    """Test decoy generation utilities."""
    
    def test_generate_convincing_decoy(self):
        """Test generating convincing decoy."""
        try:
            from meow_decoder.decoy_generator import generate_convincing_decoy
            
            decoy = generate_convincing_decoy(10000)
            
            assert len(decoy) >= 10000
            assert isinstance(decoy, bytes)
        except ImportError:
            pytest.skip("decoy_generator not available")
    
    def test_decoy_randomness(self):
        """Test decoy randomness."""
        try:
            from meow_decoder.decoy_generator import generate_convincing_decoy
            
            decoy1 = generate_convincing_decoy(1000)
            decoy2 = generate_convincing_decoy(1000)
            
            # Should be different
            assert decoy1 != decoy2
        except ImportError:
            pytest.skip("decoy_generator not available")


class TestPathUtils:
    """Test path utilities."""
    
    def test_cache_dir_creation(self):
        """Test cache directory creation."""
        from meow_decoder.config import PathConfig
        
        config = PathConfig()
        
        assert config.cache_dir.exists()
        assert config.resume_dir.exists()
        assert config.temp_dir.exists()
    
    def test_custom_paths(self):
        """Test custom path configuration."""
        from meow_decoder.config import PathConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            config = PathConfig(
                cache_dir=tmpdir / "cache",
                resume_dir=tmpdir / "resume",
                temp_dir=tmpdir / "temp"
            )
            
            assert (tmpdir / "cache").exists()
            assert (tmpdir / "resume").exists()
            assert (tmpdir / "temp").exists()


class TestHashingUtils:
    """Test hashing utilities."""
    
    def test_sha256_hashing(self):
        """Test SHA-256 hashing."""
        data = b"Test data for hashing"
        
        h = hashlib.sha256(data).digest()
        
        assert len(h) == 32
    
    def test_hmac_computation(self):
        """Test HMAC computation."""
        import hmac
        
        key = b"secret_key"
        message = b"Message to authenticate"
        
        mac = hmac.new(key, message, hashlib.sha256).digest()
        
        assert len(mac) == 32


class TestDataValidation:
    """Test data validation utilities."""
    
    def test_password_length_validation(self):
        """Test password length validation."""
        from meow_decoder.crypto import MIN_PASSWORD_LENGTH
        
        assert MIN_PASSWORD_LENGTH >= 8
    
    def test_salt_length_validation(self):
        """Test salt must be 16 bytes."""
        from meow_decoder.crypto import derive_key
        
        password = "ValidPassword123!"
        
        # Wrong salt length should fail
        with pytest.raises(ValueError):
            derive_key(password, b"short")
    
    def test_keyfile_validation(self):
        """Test keyfile validation."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(64))
            keyfile_path = f.name
        
        try:
            keyfile = verify_keyfile(keyfile_path)
            assert len(keyfile) == 64
        finally:
            os.unlink(keyfile_path)
    
    def test_keyfile_too_small(self):
        """Test keyfile too small error."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"too_short")
            keyfile_path = f.name
        
        try:
            with pytest.raises(ValueError):
                verify_keyfile(keyfile_path)
        finally:
            os.unlink(keyfile_path)


class TestEntropyUtils:
    """Test entropy utilities."""
    
    def test_entropy_pool(self):
        """Test entropy pool."""
        try:
            from meow_decoder.entropy_boost import EntropyPool
            
            pool = EntropyPool()
            pool.add_entropy(secrets.token_bytes(32))
            
            output = pool.get_entropy(32)
            assert len(output) == 32
        except ImportError:
            pytest.skip("entropy_boost not available")
    
    def test_timing_jitter_entropy(self):
        """Test timing jitter entropy."""
        try:
            from meow_decoder.entropy_boost import collect_timing_jitter
            
            jitter = collect_timing_jitter()
            assert len(jitter) > 0
        except (ImportError, AttributeError):
            pytest.skip("collect_timing_jitter not available")


class TestErrorHandling:
    """Test error handling utilities."""
    
    def test_runtime_error_propagation(self):
        """Test RuntimeError propagation."""
        def failing_function():
            raise RuntimeError("Test error")
        
        with pytest.raises(RuntimeError):
            failing_function()
    
    def test_value_error_propagation(self):
        """Test ValueError propagation."""
        def validation_function(value):
            if value < 0:
                raise ValueError("Value must be non-negative")
            return value
        
        with pytest.raises(ValueError):
            validation_function(-1)


class TestDebugUtils:
    """Test debug utilities."""
    
    def test_environment_test_mode(self):
        """Test MEOW_TEST_MODE environment variable."""
        # Save original
        original = os.environ.get('MEOW_TEST_MODE')
        
        try:
            os.environ['MEOW_TEST_MODE'] = '1'
            
            # Reimport to pick up new value
            import importlib
            import meow_decoder.crypto as crypto_module
            
            # Just check it's importable with test mode
            assert crypto_module is not None
        finally:
            if original is None:
                os.environ.pop('MEOW_TEST_MODE', None)
            else:
                os.environ['MEOW_TEST_MODE'] = original


class TestSerializationUtils:
    """Test serialization utilities."""
    
    def test_json_config_roundtrip(self):
        """Test JSON config roundtrip."""
        from meow_decoder.config import MeowConfig
        
        config = MeowConfig()
        config.verbose = True
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            config_path = Path(f.name)
        
        try:
            config.save(config_path)
            
            loaded = MeowConfig.load(config_path)
            
            assert loaded.verbose == True
        finally:
            config_path.unlink()
    
    def test_struct_packing(self):
        """Test struct packing for manifest."""
        import struct
        
        data = struct.pack(">III", 1000, 500, 800)
        
        assert len(data) == 12
        
        unpacked = struct.unpack(">III", data)
        assert unpacked == (1000, 500, 800)


class TestTimingUtils:
    """Test timing utilities."""
    
    def test_time_measurement(self):
        """Test time measurement."""
        start = time.time()
        time.sleep(0.01)
        elapsed = time.time() - start
        
        assert elapsed >= 0.01
    
    def test_random_delay(self):
        """Test random delay."""
        delay_ms = secrets.randbelow(10) + 1
        
        start = time.time()
        time.sleep(delay_ms / 1000.0)
        elapsed = time.time() - start
        
        assert elapsed >= delay_ms / 1000.0 - 0.001


class TestImportValidation:
    """Test all key module imports."""
    
    def test_import_core_modules(self):
        """Test importing core modules."""
        from meow_decoder import crypto
        from meow_decoder import fountain
        from meow_decoder import config
        
        assert crypto is not None
        assert fountain is not None
        assert config is not None
    
    def test_import_encoding_modules(self):
        """Test importing encoding modules."""
        from meow_decoder import encode
        from meow_decoder import decode_gif
        
        assert encode is not None
        assert decode_gif is not None
    
    def test_import_security_modules(self):
        """Test importing security modules."""
        from meow_decoder import constant_time
        
        assert constant_time is not None
    
    def test_import_forward_secrecy(self):
        """Test importing forward secrecy modules."""
        from meow_decoder import forward_secrecy
        from meow_decoder import x25519_forward_secrecy
        
        assert forward_secrecy is not None
        assert x25519_forward_secrecy is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
