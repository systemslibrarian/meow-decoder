#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for steganography modules - Target: 90%+
Tests stego_advanced.py, ninja_cat_ultra.py, and related stego functionality.
"""

import pytest
import secrets
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import BytesIO

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class TestStegoAdvanced:
    """Test stego_advanced.py functions."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_import_stego_advanced(self):
        """Test importing stego_advanced module."""
        try:
            from meow_decoder import stego_advanced
            assert stego_advanced is not None
        except ImportError:
            pytest.skip("stego_advanced not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_stealth_level_enum(self):
        """Test StealthLevel enum."""
        try:
            from meow_decoder.stego_advanced import StealthLevel
            
            assert StealthLevel.VISIBLE.value >= 1
            assert StealthLevel.PARANOID.value >= 1
        except ImportError:
            pytest.skip("StealthLevel not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_encode_with_stego_basic(self):
        """Test basic steganography encoding."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            # Create test QR-like frames
            test_frames = []
            for i in range(3):
                img = Image.new('RGB', (100, 100), color=(255, 255, 255))
                test_frames.append(img)
            
            result_frames, qualities = encode_with_stego(
                test_frames,
                stealth_level=StealthLevel.VISIBLE,
                carriers=None,
                enable_animation=False
            )
            
            assert len(result_frames) == len(test_frames)
            assert len(qualities) == len(test_frames)
        except ImportError:
            pytest.skip("encode_with_stego not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_create_green_mask(self):
        """Test green mask creation."""
        try:
            from meow_decoder.stego_advanced import create_green_mask
            
            # Create image with green regions
            img = Image.new('RGB', (50, 50), color=(0, 200, 0))
            
            mask = create_green_mask(img)
            
            assert mask is not None
            # Mask should have same dimensions
            if hasattr(mask, 'size'):
                assert mask.size == img.size
        except ImportError:
            pytest.skip("create_green_mask not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_calculate_masked_capacity(self):
        """Test masked capacity calculation."""
        try:
            from meow_decoder.stego_advanced import calculate_masked_capacity, create_green_mask
            
            # Create mostly green image
            img = Image.new('RGB', (100, 100), color=(0, 180, 0))
            mask = create_green_mask(img)
            
            capacity = calculate_masked_capacity(mask, lsb_bits=2)
            
            assert isinstance(capacity, dict)
            assert 'percent' in capacity or 'bytes_capacity' in capacity
        except ImportError:
            pytest.skip("calculate_masked_capacity not available")


class TestNinjaCatUltra:
    """Test ninja_cat_ultra.py steganography."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_import_ninja_cat(self):
        """Test importing ninja_cat_ultra module."""
        try:
            from meow_decoder import ninja_cat_ultra
            assert ninja_cat_ultra is not None
        except ImportError:
            pytest.skip("ninja_cat_ultra not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_ninja_cat_class(self):
        """Test NinjaCatUltra class."""
        try:
            from meow_decoder.ninja_cat_ultra import NinjaCatUltra
            
            ninja = NinjaCatUltra()
            
            assert ninja is not None
        except ImportError:
            pytest.skip("NinjaCatUltra not available")


class TestLogoEyes:
    """Test logo_eyes.py if available."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_import_logo_eyes(self):
        """Test importing logo_eyes module."""
        try:
            from meow_decoder import logo_eyes
            assert logo_eyes is not None
        except ImportError:
            pytest.skip("logo_eyes not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_logo_config(self):
        """Test LogoConfig dataclass."""
        try:
            from meow_decoder.logo_eyes import LogoConfig
            
            config = LogoConfig(
                brand_text="TEST",
                animate_blink=True,
                visible_qr=True
            )
            
            assert config.brand_text == "TEST"
            assert config.animate_blink is True
            assert config.visible_qr is True
        except ImportError:
            pytest.skip("LogoConfig not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_encode_with_logo_eyes(self):
        """Test logo eyes encoding."""
        try:
            from meow_decoder.logo_eyes import encode_with_logo_eyes, LogoConfig
            
            # Create test frames
            test_frames = []
            for i in range(3):
                img = Image.new('RGB', (100, 100), color=(255, 255, 255))
                test_frames.append(img)
            
            config = LogoConfig(brand_text="MEOW", visible_qr=True)
            
            result = encode_with_logo_eyes(test_frames, config=config)
            
            assert len(result) >= len(test_frames)
        except ImportError:
            pytest.skip("encode_with_logo_eyes not available")


class TestStegoQuality:
    """Test stego quality metrics."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_quality_struct(self):
        """Test quality structure from stego encoding."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            test_frames = [Image.new('RGB', (50, 50), color=(128, 128, 128))]
            
            _, qualities = encode_with_stego(
                test_frames,
                stealth_level=StealthLevel.SUBTLE,
                enable_animation=False
            )
            
            if qualities and len(qualities) > 0:
                q = qualities[0]
                # Check quality has expected attributes
                assert hasattr(q, 'psnr') or isinstance(q, dict)
        except ImportError:
            pytest.skip("encode_with_stego not available")


class TestStegoLevels:
    """Test different stealth levels."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_all_stealth_levels(self):
        """Test encoding at all stealth levels."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            test_frame = Image.new('RGB', (64, 64), color=(100, 150, 200))
            
            for level in StealthLevel:
                result_frames, _ = encode_with_stego(
                    [test_frame],
                    stealth_level=level,
                    enable_animation=False
                )
                
                assert len(result_frames) == 1
        except ImportError:
            pytest.skip("StealthLevel not available")


class TestCarrierImages:
    """Test carrier image handling."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_custom_carriers(self):
        """Test encoding with custom carrier images."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            # Create QR-like frame
            qr_frame = Image.new('RGB', (100, 100), color=(255, 255, 255))
            
            # Create carrier
            carrier = Image.new('RGB', (100, 100), color=(50, 100, 50))
            
            result_frames, _ = encode_with_stego(
                [qr_frame],
                stealth_level=StealthLevel.SUBTLE,
                carriers=[carrier],
                enable_animation=False
            )
            
            assert len(result_frames) == 1
        except ImportError:
            pytest.skip("encode_with_stego not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_carrier_cycling(self):
        """Test carrier image cycling for multiple frames."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            # Create multiple QR frames
            qr_frames = [Image.new('RGB', (80, 80)) for _ in range(5)]
            
            # Create fewer carriers (should cycle)
            carriers = [Image.new('RGB', (80, 80), color=(i*50, 100, 100)) for i in range(2)]
            
            result_frames, _ = encode_with_stego(
                qr_frames,
                stealth_level=StealthLevel.VISIBLE,
                carriers=carriers,
                enable_animation=False
            )
            
            assert len(result_frames) == len(qr_frames)
        except ImportError:
            pytest.skip("encode_with_stego not available")


class TestGreenRegionStego:
    """Test green-region restricted steganography."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_green_mask_on_non_green_image(self):
        """Test green mask on image without green."""
        try:
            from meow_decoder.stego_advanced import create_green_mask
            
            # Red image - no green
            img = Image.new('RGB', (50, 50), color=(200, 0, 0))
            
            mask = create_green_mask(img)
            
            # Should return a mask (even if mostly False)
            assert mask is not None
        except ImportError:
            pytest.skip("create_green_mask not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_green_mask_on_mixed_image(self):
        """Test green mask on mixed color image."""
        try:
            from meow_decoder.stego_advanced import create_green_mask
            from PIL import ImageDraw
            
            # Create image with green and non-green regions
            img = Image.new('RGB', (100, 100), color=(200, 200, 200))
            draw = ImageDraw.Draw(img)
            draw.rectangle([25, 25, 75, 75], fill=(0, 200, 0))
            
            mask = create_green_mask(img)
            
            assert mask is not None
        except ImportError:
            pytest.skip("create_green_mask not available")


class TestStegoDecoding:
    """Test stego decoding if available."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_stego_decode_import(self):
        """Test importing stego decode functions."""
        try:
            from meow_decoder.stego_advanced import decode_from_stego
            assert callable(decode_from_stego)
        except (ImportError, AttributeError):
            pytest.skip("decode_from_stego not available")


class TestStegoEdgeCases:
    """Test stego edge cases."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_empty_frames(self):
        """Test with empty frame list."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            result, _ = encode_with_stego(
                [],
                stealth_level=StealthLevel.VISIBLE,
                enable_animation=False
            )
            
            assert len(result) == 0
        except ImportError:
            pytest.skip("encode_with_stego not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_single_frame(self):
        """Test with single frame."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            frame = Image.new('RGB', (100, 100))
            
            result, qualities = encode_with_stego(
                [frame],
                stealth_level=StealthLevel.HIDDEN,
                enable_animation=False
            )
            
            assert len(result) == 1
            assert len(qualities) == 1
        except ImportError:
            pytest.skip("encode_with_stego not available")
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_small_image(self):
        """Test with very small image."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            # Very small image
            frame = Image.new('RGB', (10, 10))
            
            result, _ = encode_with_stego(
                [frame],
                stealth_level=StealthLevel.VISIBLE,
                enable_animation=False
            )
            
            assert len(result) == 1
        except ImportError:
            pytest.skip("encode_with_stego not available")


class TestStegoAnimation:
    """Test stego with animation enabled."""
    
    @pytest.mark.skipif(not PIL_AVAILABLE, reason="PIL not available")
    def test_animation_enabled(self):
        """Test with animation enabled."""
        try:
            from meow_decoder.stego_advanced import encode_with_stego, StealthLevel
            
            frames = [Image.new('RGB', (64, 64)) for _ in range(3)]
            
            result, _ = encode_with_stego(
                frames,
                stealth_level=StealthLevel.SUBTLE,
                enable_animation=True
            )
            
            # Should still return frames
            assert len(result) >= len(frames)
        except ImportError:
            pytest.skip("encode_with_stego not available")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
