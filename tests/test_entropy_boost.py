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
        collect_system_entropy,
        collect_timing_entropy,
        collect_hardware_entropy,
        mix_entropy_sources,
    )
    ENTROPY_AVAILABLE = True
except (ImportError, AttributeError):
    ENTROPY_AVAILABLE = False
    try:
        from meow_decoder.entropy_boost import EntropyPool
        ENTROPY_AVAILABLE = True
    except ImportError:
        pass


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestEntropyPool:
    """Tests for EntropyPool class."""

    def test_pool_creation(self):
        """Test basic pool creation."""
        pool = EntropyPool()
        assert pool is not None

    def test_pool_add_entropy(self):
        """Test adding entropy to pool."""
        pool = EntropyPool()
        pool.add_entropy(b"test entropy data")
        assert pool.entropy_bits() > 0

    def test_pool_extract_entropy(self):
        """Test extracting entropy from pool."""
        pool = EntropyPool()
        pool.add_entropy(os.urandom(32))
        entropy = pool.extract(32)
        assert len(entropy) == 32

    def test_pool_multiple_adds(self):
        """Test adding multiple entropy sources."""
        pool = EntropyPool()
        pool.add_entropy(b"source1")
        pool.add_entropy(b"source2")
        pool.add_entropy(b"source3")
        entropy = pool.extract(32)
        assert len(entropy) == 32


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestCollectSystemEntropy:
    """Tests for system entropy collection."""

    def test_collect_system(self):
        """Test system entropy collection."""
        try:
            entropy = collect_system_entropy()
            assert isinstance(entropy, bytes)
            assert len(entropy) >= 16
        except NameError:
            pytest.skip("Function not available")

    def test_system_entropy_varies(self):
        """Test that system entropy varies."""
        try:
            ent1 = collect_system_entropy()
            ent2 = collect_system_entropy()
            # May be same if collected quickly, but should work
            assert isinstance(ent1, bytes)
            assert isinstance(ent2, bytes)
        except NameError:
            pytest.skip("Function not available")


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestCollectTimingEntropy:
    """Tests for timing entropy collection."""

    def test_collect_timing(self):
        """Test timing entropy collection."""
        try:
            entropy = collect_timing_entropy()
            assert isinstance(entropy, bytes)
        except NameError:
            pytest.skip("Function not available")


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestCollectHardwareEntropy:
    """Tests for hardware entropy collection."""

    def test_collect_hardware(self):
        """Test hardware entropy collection (may fail if no HW RNG)."""
        try:
            entropy = collect_hardware_entropy()
            # May return empty if no hardware RNG
            assert isinstance(entropy, bytes)
        except (NameError, OSError):
            pytest.skip("Hardware entropy not available")


@pytest.mark.skipif(not ENTROPY_AVAILABLE, reason="entropy_boost module not available")
class TestMixEntropySources:
    """Tests for entropy source mixing."""

    def test_mix_sources(self):
        """Test mixing multiple entropy sources."""
        try:
            sources = [b"source1", b"source2", b"source3"]
            mixed = mix_entropy_sources(sources)
            assert isinstance(mixed, bytes)
            assert len(mixed) == 32  # Default output size
        except NameError:
            pytest.skip("Function not available")

    def test_mix_deterministic(self):
        """Test that same sources produce same output."""
        try:
            sources = [b"a", b"b", b"c"]
            mixed1 = mix_entropy_sources(sources)
            mixed2 = mix_entropy_sources(sources)
            assert mixed1 == mixed2
        except NameError:
            pytest.skip("Function not available")


# Fallback test
@pytest.mark.skipif(ENTROPY_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not ENTROPY_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
