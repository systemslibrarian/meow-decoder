#!/usr/bin/env python3
"""
⚠️ DEPRECATED - MERGED INTO test_fountain.py ⚠️

This file has been merged into test_fountain.py as part of test consolidation.
See: tests/test_fountain.py

Original description:
🧪 Test Suite: catnip_fountain.py
Tests the catnip-flavored fountain code extensions.
"""

import pytest
pytest.skip("DEPRECATED: Tests merged into test_fountain.py", allow_module_level=True)

import secrets
import os
os.environ["MEOW_TEST_MODE"] = "1"

# Try to import catnip_fountain module
try:
    from meow_decoder.catnip_fountain import (
        CatnipEncoder,
        CatnipDecoder,
        apply_catnip_flavor,
    )
    CATNIP_AVAILABLE = True
except ImportError:
    CATNIP_AVAILABLE = False


@pytest.mark.skipif(not CATNIP_AVAILABLE, reason="catnip_fountain module not available")
class TestCatnipEncoder:
    """Tests for CatnipEncoder."""

    def test_encoder_creation(self):
        """Test basic encoder creation."""
        data = secrets.token_bytes(500)
        encoder = CatnipEncoder(data, k_blocks=10, block_size=50)
        assert encoder is not None

    def test_encoder_generate_droplet(self):
        """Test droplet generation."""
        data = secrets.token_bytes(500)
        encoder = CatnipEncoder(data, k_blocks=10, block_size=50)
        droplet = encoder.droplet()
        assert droplet is not None
        assert hasattr(droplet, 'data')

    def test_encoder_generate_multiple(self):
        """Test generating multiple droplets."""
        data = secrets.token_bytes(500)
        encoder = CatnipEncoder(data, k_blocks=10, block_size=50)
        droplets = encoder.generate_droplets(15)
        assert len(droplets) == 15


@pytest.mark.skipif(not CATNIP_AVAILABLE, reason="catnip_fountain module not available")
class TestCatnipDecoder:
    """Tests for CatnipDecoder."""

    def test_decoder_creation(self):
        """Test basic decoder creation."""
        decoder = CatnipDecoder(k_blocks=10, block_size=50)
        assert decoder is not None

    def test_decoder_add_droplet(self):
        """Test adding droplet to decoder."""
        data = secrets.token_bytes(500)
        encoder = CatnipEncoder(data, k_blocks=10, block_size=50)
        decoder = CatnipDecoder(k_blocks=10, block_size=50)
        
        droplet = encoder.droplet()
        result = decoder.add_droplet(droplet)
        assert isinstance(result, bool)


@pytest.mark.skipif(not CATNIP_AVAILABLE, reason="catnip_fountain module not available")
class TestApplyCatnipFlavor:
    """Tests for catnip flavor application."""

    def test_apply_flavor_tuna(self):
        """Test tuna flavor application."""
        salt = secrets.token_bytes(16)
        flavored = apply_catnip_flavor("tuna", salt)
        assert isinstance(flavored, bytes)

    def test_apply_flavor_salmon(self):
        """Test salmon flavor application."""
        salt = secrets.token_bytes(16)
        flavored = apply_catnip_flavor("salmon", salt)
        assert isinstance(flavored, bytes)

    def test_different_flavors_different_output(self):
        """Test that different flavors produce different output."""
        salt = secrets.token_bytes(16)
        tuna = apply_catnip_flavor("tuna", salt)
        salmon = apply_catnip_flavor("salmon", salt)
        assert tuna != salmon


# Fallback test
@pytest.mark.skipif(CATNIP_AVAILABLE, reason="Testing import fallback")
class TestModuleImportFallback:
    """Test module import fallback behavior."""

    def test_import_failure_handled(self):
        """Test that import failure is handled gracefully."""
        assert not CATNIP_AVAILABLE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
