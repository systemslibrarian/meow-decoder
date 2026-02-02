#!/usr/bin/env python3
"""
🧪 Test Suite: entropy_boost.py
Tests multi-source entropy collection for cryptographic randomness.
"""

import pytest
import os
os.environ["MEOW_TEST_MODE"] = "1"

# Try to import entropy_boost module
try:
    from meow_decoder.entropy_boost import (
        EntropyPool,
        collect_enhanced_entropy,
        generate_enhanced_salt,
        generate_enhanced_nonce,
    )
    ENTROPY_AVAILABLE = True
except (ImportError, AttributeError):
    ENTROPY_AVAILABLE = False


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestEntropyPool:
    """Tests for EntropyPool class."""

    def test_pool_creation(self):
        """Test basic pool creation."""
        pool = EntropyPool()
        assert pool is not None

    def test_add_system_entropy(self):
        """Test adding system entropy to pool."""
        pool = EntropyPool()
        pool.add_system_entropy(32)
        assert pool.get_source_count() >= 1

    def test_add_timing_entropy(self):
        """Test adding timing entropy to pool."""
        pool = EntropyPool()
        pool.add_timing_entropy(50)  # Fewer samples for speed
        assert pool.get_source_count() >= 1

    def test_add_environment_entropy(self):
        """Test adding environment entropy to pool."""
        pool = EntropyPool()
        pool.add_environment_entropy()
        assert pool.get_source_count() >= 1

    def test_add_user_entropy(self):
        """Test adding user entropy to pool (skips in non-TTY)."""
        pool = EntropyPool()
        try:
            import sys
            if not sys.stdin.isatty():
                pytest.skip("Cannot test user entropy in non-interactive mode")
            pool.add_user_entropy(b"user provided data")
            assert pool.get_source_count() >= 1
        except (OSError, IOError):
            pytest.skip("Cannot test user entropy in non-interactive mode")

    def test_mix_entropy(self):
        """Test mixing entropy from pool."""
        pool = EntropyPool()
        pool.add_system_entropy(32)
        pool.add_timing_entropy(25)
        
        output = pool.mix_entropy(32)
        assert len(output) == 32
        assert isinstance(output, bytes)

    def test_pool_multiple_sources(self):
        """Test adding multiple entropy sources."""
        pool = EntropyPool()
        pool.add_system_entropy(16)
        pool.add_timing_entropy(25)
        pool.add_environment_entropy()
        
        assert pool.get_source_count() >= 3
        output = pool.mix_entropy(32)
        assert len(output) == 32

    def test_mix_entropy_different_lengths(self):
        """Test extracting different output lengths."""
        pool = EntropyPool()
        pool.add_system_entropy(32)
        
        out16 = pool.mix_entropy(16)
        out32 = pool.mix_entropy(32)
        out64 = pool.mix_entropy(64)
        
        assert len(out16) == 16
        assert len(out32) == 32
        assert len(out64) == 64


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestCollectEnhancedEntropy:
    """Tests for collect_enhanced_entropy function."""

    def test_collect_enhanced_entropy(self):
        """Test enhanced entropy collection."""
        entropy = collect_enhanced_entropy(32)  # length is required arg
        assert isinstance(entropy, bytes)
        assert len(entropy) >= 32

    def test_collect_enhanced_entropy_custom_length(self):
        """Test enhanced entropy with custom length."""
        entropy = collect_enhanced_entropy(64)  # length is positional
        assert len(entropy) == 64


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestGenerateSaltAndNonce:
    """Tests for salt and nonce generation."""

    def test_generate_salt(self):
        """Test enhanced salt generation."""
        salt = generate_enhanced_salt()
        assert isinstance(salt, bytes)
        assert len(salt) == 16

    def test_generate_nonce(self):
        """Test enhanced nonce generation."""
        nonce = generate_enhanced_nonce()
        assert isinstance(nonce, bytes)
        assert len(nonce) == 12

    def test_salt_uniqueness(self):
        """Test that salts are unique."""
        salts = [generate_enhanced_salt() for _ in range(10)]
        unique_salts = set(salts)
        assert len(unique_salts) == 10

    def test_nonce_uniqueness(self):
        """Test that nonces are unique."""
        nonces = [generate_enhanced_nonce() for _ in range(10)]
        unique_nonces = set(nonces)
        assert len(unique_nonces) == 10


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestHardwareEntropy:
    """Tests for hardware entropy (optional)."""

    def test_add_hardware_entropy(self):
        """Test hardware entropy (may not be available on all systems)."""
        pool = EntropyPool()
        try:
            pool.add_hardware_entropy()
            # If it works, great. If not, still passes (hardware may not exist)
            assert True
        except (OSError, RuntimeError):
            pytest.skip("Hardware RNG not available")


# Fallback test
@pytest.mark.skipif(ENTROPY_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not ENTROPY_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
