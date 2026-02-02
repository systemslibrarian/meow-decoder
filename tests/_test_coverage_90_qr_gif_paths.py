#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for QR and GIF paths - Target: 90%+
Tests qr_code.py and gif_handler.py paths that haven't been covered yet.

⚠️ DEPRECATED: Tests consolidated into test_qr_code.py and test_gif_handler.py
This file will be removed after verification that all unique tests are migrated.
"""

import pytest

# Skip all tests in this module - consolidated into test_qr_code.py and test_gif_handler.py
pytestmark = pytest.mark.skip(reason="Consolidated into test_qr_code.py")
import secrets
import sys
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from PIL import Image

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestQRCodeGenerator:
    """Test QR code generator."""
    
    def test_generator_creation(self):
        """Test creating generator."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        
        assert gen is not None
    
    def test_generator_with_options(self):
        """Test creating generator with options."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator(
            error_correction="H",
            box_size=10,
            border=4
        )
        
        assert gen is not None
    
    def test_generate_basic(self):
        """Test generating QR code."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        
        data = b"Test data for QR code"
        qr = gen.generate(data)
        
        assert qr is not None
        assert isinstance(qr, Image.Image)
    
    def test_generate_large_data(self):
        """Test generating QR code with large data."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator(error_correction="L")
        
        data = secrets.token_bytes(500)
        qr = gen.generate(data)
        
        assert qr is not None
    
    def test_generate_batch(self):
        """Test generating multiple QR codes."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        
        data_list = [b"Data 1", b"Data 2", b"Data 3"]
        qrs = gen.generate_batch(data_list)
        
        assert len(qrs) == 3
        for qr in qrs:
            assert isinstance(qr, Image.Image)
    
    def test_error_correction_levels(self):
        """Test different error correction levels."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        data = b"Test data"
        
        for level in ["L", "M", "Q", "H"]:
            gen = QRCodeGenerator(error_correction=level)
            qr = gen.generate(data)
            
            assert qr is not None


class TestQRCodeReader:
    """Test QR code reader."""
    
    def test_reader_creation(self):
        """Test creating reader."""
        from meow_decoder.qr_code import QRCodeReader
        
        reader = QRCodeReader()
        
        assert reader is not None
    
    def test_read_image_basic(self):
        """Test reading QR code from image."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        reader = QRCodeReader()
        
        data = b"Test data to read"
        qr = gen.generate(data)
        
        result = reader.read_image(qr)
        
        assert result is not None
        assert data in result
    
    def test_read_image_no_qr(self):
        """Test reading image with no QR code."""
        from meow_decoder.qr_code import QRCodeReader
        
        reader = QRCodeReader()
        
        # Create blank image
        img = Image.new('RGB', (100, 100), color='white')
        
        result = reader.read_image(img)
        
        assert result is None or len(result) == 0
    
    def test_read_multiple_qr(self):
        """Test reading multiple QR codes from image."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator(box_size=5)
        reader = QRCodeReader()
        
        # Generate two QR codes
        qr1 = gen.generate(b"Data 1")
        qr2 = gen.generate(b"Data 2")
        
        # Combine them side by side
        combined = Image.new('RGB', (qr1.width + qr2.width, max(qr1.height, qr2.height)), 'white')
        combined.paste(qr1, (0, 0))
        combined.paste(qr2, (qr1.width, 0))
        
        result = reader.read_image(combined)
        
        # Should read at least one
        assert result is not None or len(result) >= 1
    
    def test_preprocessing_modes(self):
        """Test preprocessing modes."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        data = b"Preprocessing test"
        qr = gen.generate(data)
        
        for mode in ["normal", "aggressive"]:
            reader = QRCodeReader(preprocessing=mode)
            result = reader.read_image(qr)
            
            assert data in result


class TestQRCodeRoundtrip:
    """Test QR code roundtrip."""
    
    def test_roundtrip_basic(self):
        """Test basic roundtrip."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        reader = QRCodeReader()
        
        original = b"Test data for roundtrip"
        qr = gen.generate(original)
        decoded = reader.read_image(qr)
        
        assert original in decoded
    
    def test_roundtrip_binary(self):
        """Test roundtrip with binary data."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        reader = QRCodeReader()
        
        original = secrets.token_bytes(100)
        qr = gen.generate(original)
        decoded = reader.read_image(qr)
        
        assert original in decoded


class TestGIFEncoder:
    """Test GIF encoder."""
    
    def test_encoder_creation(self):
        """Test creating encoder."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder()
        
        assert encoder is not None
    
    def test_encoder_with_fps(self):
        """Test creating encoder with FPS."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10)
        
        assert encoder is not None
    
    def test_create_gif(self):
        """Test creating GIF."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=2)
        
        # Create test frames
        frames = [
            Image.new('RGB', (100, 100), 'red'),
            Image.new('RGB', (100, 100), 'green'),
            Image.new('RGB', (100, 100), 'blue'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, temp_path)
            
            assert temp_path.exists()
            assert size > 0
        finally:
            temp_path.unlink()
    
    def test_create_gif_optimize(self):
        """Test creating optimized GIF."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=2)
        
        frames = [
            Image.new('RGB', (100, 100), 'red'),
            Image.new('RGB', (100, 100), 'green'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            size = encoder.create_gif(frames, temp_path, optimize=True)
            
            assert temp_path.exists()
        finally:
            temp_path.unlink()


class TestGIFDecoder:
    """Test GIF decoder."""
    
    def test_decoder_creation(self):
        """Test creating decoder."""
        from meow_decoder.gif_handler import GIFDecoder
        
        decoder = GIFDecoder()
        
        assert decoder is not None
    
    def test_extract_frames(self):
        """Test extracting frames from GIF."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        # Create test GIF
        encoder = GIFEncoder(fps=2)
        
        frames = [
            Image.new('RGB', (50, 50), 'red'),
            Image.new('RGB', (50, 50), 'green'),
            Image.new('RGB', (50, 50), 'blue'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            encoder.create_gif(frames, temp_path)
            
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(temp_path)
            
            assert len(extracted) == 3
            for frame in extracted:
                assert isinstance(frame, Image.Image)
        finally:
            temp_path.unlink()
    
    def test_extract_frames_from_path(self):
        """Test extracting frames from path."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder(fps=2)
        
        frames = [
            Image.new('RGB', (50, 50), 'cyan'),
            Image.new('RGB', (50, 50), 'magenta'),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            temp_path = f.name
        
        try:
            encoder.create_gif(frames, Path(temp_path))
            
            decoder = GIFDecoder()
            # Test with string path
            extracted = decoder.extract_frames(temp_path)
            
            assert len(extracted) == 2
        finally:
            os.unlink(temp_path)


class TestGIFRoundtrip:
    """Test GIF roundtrip."""
    
    def test_encode_decode_roundtrip(self):
        """Test encoding and decoding GIF."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder(fps=5)
        decoder = GIFDecoder()
        
        # Create frames
        colors = ['red', 'green', 'blue', 'yellow', 'cyan']
        original_frames = [Image.new('RGB', (50, 50), c) for c in colors]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            encoder.create_gif(original_frames, temp_path)
            extracted_frames = decoder.extract_frames(temp_path)
            
            assert len(extracted_frames) == len(original_frames)
        finally:
            temp_path.unlink()


class TestQRGIFIntegration:
    """Integration tests for QR and GIF."""
    
    def test_qr_in_gif_roundtrip(self):
        """Test QR codes in GIF roundtrip."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        gen = QRCodeGenerator()
        reader = QRCodeReader()
        encoder = GIFEncoder(fps=2)
        decoder = GIFDecoder()
        
        # Create QR codes
        data_list = [b"Frame 1 data", b"Frame 2 data", b"Frame 3 data"]
        qr_frames = [gen.generate(d) for d in data_list]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            # Create GIF
            encoder.create_gif(qr_frames, temp_path)
            
            # Extract frames
            extracted = decoder.extract_frames(temp_path)
            
            # Read QR codes
            for i, frame in enumerate(extracted):
                result = reader.read_image(frame)
                
                assert data_list[i] in result
        finally:
            temp_path.unlink()


class TestQRCodeEdgeCases:
    """Test QR code edge cases."""
    
    def test_empty_data(self):
        """Test with empty data."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        
        # Empty bytes
        qr = gen.generate(b"")
        
        assert qr is not None
    
    def test_special_characters(self):
        """Test with special characters."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        reader = QRCodeReader()
        
        data = "Special: !@#$%^&*() 日本語 🐱".encode('utf-8')
        qr = gen.generate(data)
        result = reader.read_image(qr)
        
        assert data in result
    
    def test_all_zeros(self):
        """Test with all zeros."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        reader = QRCodeReader()
        
        data = b'\x00' * 100
        qr = gen.generate(data)
        result = reader.read_image(qr)
        
        assert data in result


class TestGIFEdgeCases:
    """Test GIF edge cases."""
    
    def test_single_frame(self):
        """Test with single frame."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder()
        decoder = GIFDecoder()
        
        frames = [Image.new('RGB', (50, 50), 'red')]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            encoder.create_gif(frames, temp_path)
            extracted = decoder.extract_frames(temp_path)
            
            assert len(extracted) >= 1
        finally:
            temp_path.unlink()
    
    def test_many_frames(self):
        """Test with many frames."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        
        encoder = GIFEncoder(fps=30)
        decoder = GIFDecoder()
        
        frames = [Image.new('RGB', (50, 50), (i % 256, i % 256, i % 256)) 
                  for i in range(100)]
        
        with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            encoder.create_gif(frames, temp_path)
            extracted = decoder.extract_frames(temp_path)
            
            assert len(extracted) == 100
        finally:
            temp_path.unlink()
    
    def test_different_sizes(self):
        """Test with different frame sizes."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder()
        
        sizes = [(50, 50), (100, 100), (200, 200)]
        
        for w, h in sizes:
            frames = [Image.new('RGB', (w, h), 'blue')]
            
            with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as f:
                temp_path = Path(f.name)
            
            try:
                size = encoder.create_gif(frames, temp_path)
                
                assert size > 0
            finally:
                temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
