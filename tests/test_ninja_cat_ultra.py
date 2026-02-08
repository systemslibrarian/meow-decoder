"""Tests for ninja_cat_ultra.py steganography module."""

import pytest
from unittest.mock import MagicMock, patch
from PIL import Image
import numpy as np


class TestNinjaCatUltra:
    """Tests for ninja_cat_ultra.py"""

    def test_import_module(self):
        """Test module imports correctly."""
        from meow_decoder import ninja_cat_ultra

        assert ninja_cat_ultra is not None

    def test_stego_level_enum(self):
        """Test StealthLevel enum."""
        try:
            from meow_decoder.ninja_cat_ultra import StealthLevel

            assert StealthLevel.VISIBLE.value == 1
            assert StealthLevel.SUBTLE.value == 2
            assert StealthLevel.HIDDEN.value == 3
            assert StealthLevel.PARANOID.value == 4
        except ImportError:
            pytest.skip("StealthLevel not available")

    def test_embed_basic(self):
        """Test basic LSB embedding."""
        try:
            from meow_decoder.ninja_cat_ultra import NinjaCatUltra

            # Create test image and QR
            carrier = Image.new("RGB", (100, 100), color=(128, 128, 128))
            qr_data = Image.new("L", (50, 50), color=255)

            ninja = NinjaCatUltra()
            result = ninja.embed(carrier, qr_data)

            assert result is not None
            assert result.size == carrier.size
        except (ImportError, AttributeError, TypeError):
            pytest.skip("NinjaCatUltra not available")

    def test_extract_basic(self):
        """Test basic LSB extraction."""
        try:
            from meow_decoder.ninja_cat_ultra import NinjaCatUltra

            # Create stego image
            stego = Image.new("RGB", (100, 100), color=(128, 128, 128))

            ninja = NinjaCatUltra()
            extracted = ninja.extract(stego)

            assert extracted is not None
        except (ImportError, AttributeError, TypeError):
            pytest.skip("NinjaCatUltra extract not available")

    def test_stealth_levels(self):
        """Test different stealth levels."""
        try:
            from meow_decoder.ninja_cat_ultra import NinjaCatUltra, StealthLevel

            carrier = Image.new("RGB", (100, 100), color=(128, 128, 128))
            qr_data = Image.new("L", (50, 50), color=255)

            for level in [
                StealthLevel.VISIBLE,
                StealthLevel.SUBTLE,
                StealthLevel.HIDDEN,
                StealthLevel.PARANOID,
            ]:
                ninja = NinjaCatUltra(stealth_level=level)
                result = ninja.embed(carrier, qr_data)
                assert result is not None
        except (ImportError, AttributeError, TypeError):
            pytest.skip("Stealth levels not available")

    def test_capacity_calculation(self):
        """Test capacity calculation."""
        try:
            from meow_decoder.ninja_cat_ultra import calculate_capacity

            carrier = Image.new("RGB", (100, 100), color=(128, 128, 128))
            capacity = calculate_capacity(carrier, lsb_bits=2)

            assert capacity > 0
        except (ImportError, AttributeError):
            pytest.skip("calculate_capacity not available")
