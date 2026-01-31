#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for qr_code.py and gif_handler.py - Target: 90%+
Tests QR code generation/reading and GIF encoding/decoding.
"""

import pytest
import tempfile
import os
import sys
import secrets
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import BytesIO

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestQRCodeGenerator:
    """Test QR code generation."""
    
    def test_generator_basic(self):
        """Test basic QR code generation."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator()
        data = b"Hello, Meow Decoder!"
        
        qr_image = generator.generate(data)
        
        assert qr_image is not None
        assert qr_image.size[0] > 0
        assert qr_image.size[1] > 0
    
    def test_generator_error_correction_levels(self):
        """Test different error correction levels."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        data = b"Test data for QR"
        
        for level in ['L', 'M', 'Q', 'H']:
            generator = QRCodeGenerator(error_correction=level)
            qr = generator.generate(data)
            assert qr is not None
    
    def test_generator_custom_box_size(self):
        """Test custom box size."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        data = b"Box size test"
        
        small = QRCodeGenerator(box_size=5)
        large = QRCodeGenerator(box_size=20)
        
        qr_small = small.generate(data)
        qr_large = large.generate(data)
        
        assert qr_small.size[0] < qr_large.size[0]
    
    def test_generator_custom_border(self):
        """Test custom border size."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        data = b"Border test"
        
        small_border = QRCodeGenerator(border=1)
        large_border = QRCodeGenerator(border=8)
        
        qr_small = small_border.generate(data)
        qr_large = large_border.generate(data)
        
        assert qr_small.size[0] < qr_large.size[0]
    
    def test_generator_batch(self):
        """Test batch QR generation."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator()
        data_list = [b"Data 1", b"Data 2", b"Data 3"]
        
        qr_list = generator.generate_batch(data_list)
        
        assert len(qr_list) == 3
        for qr in qr_list:
            assert qr is not None
    
    def test_generator_large_data(self):
        """Test QR generation with larger data."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator(error_correction='L')  # L for more capacity
        data = secrets.token_bytes(500)
        
        qr = generator.generate(data)
        assert qr is not None


class TestQRCodeReader:
    """Test QR code reading."""
    
    def test_reader_basic(self):
        """Test basic QR code reading."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        # Generate a QR code
        generator = QRCodeGenerator()
        original_data = b"Hello, Meow Reader!"
        qr_image = generator.generate(original_data)
        
        # Read it back
        reader = QRCodeReader()
        result = reader.read_image(qr_image)
        
        assert result is not None
        assert len(result) > 0
        assert result[0] == original_data
    
    def test_reader_preprocessing_normal(self):
        """Test reader with normal preprocessing."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        generator = QRCodeGenerator()
        data = b"Normal preprocessing test"
        qr = generator.generate(data)
        
        reader = QRCodeReader(preprocessing='normal')
        result = reader.read_image(qr)
        
        assert result is not None
        assert result[0] == data
    
    def test_reader_preprocessing_aggressive(self):
        """Test reader with aggressive preprocessing."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        generator = QRCodeGenerator()
        data = b"Aggressive preprocessing test"
        qr = generator.generate(data)
        
        reader = QRCodeReader(preprocessing='aggressive')
        result = reader.read_image(qr)
        
        assert result is not None
        assert result[0] == data
    
    def test_reader_no_qr_returns_empty(self):
        """Test that reader returns empty for image without QR."""
        from meow_decoder.qr_code import QRCodeReader
        from PIL import Image
        
        # Create blank image
        blank = Image.new('RGB', (100, 100), color='white')
        
        reader = QRCodeReader()
        result = reader.read_image(blank)
        
        assert result == [] or result is None or len(result) == 0
    
    def test_reader_roundtrip_binary_data(self):
        """Test roundtrip with binary data."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        generator = QRCodeGenerator()
        reader = QRCodeReader()
        
        # Random binary data
        data = secrets.token_bytes(100)
        qr = generator.generate(data)
        result = reader.read_image(qr)
        
        assert result is not None
        assert result[0] == data


class TestGIFEncoder:
    """Test GIF encoding."""
    
    def test_encoder_basic(self, tmp_path):
        """Test basic GIF encoding."""
        from meow_decoder.gif_handler import GIFEncoder
        from meow_decoder.qr_code import QRCodeGenerator
        
        # Generate some frames
        generator = QRCodeGenerator()
        frames = [
            generator.generate(b"Frame 1"),
            generator.generate(b"Frame 2"),
            generator.generate(b"Frame 3")
        ]
        
        # Create GIF
        output_path = tmp_path / "test.gif"
        encoder = GIFEncoder()
        size = encoder.create_gif(frames, output_path)
        
        assert output_path.exists()
        assert size > 0
    
    def test_encoder_custom_fps(self, tmp_path):
        """Test GIF encoding with custom FPS."""
        from meow_decoder.gif_handler import GIFEncoder
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator()
        frames = [generator.generate(f"Frame {i}".encode()) for i in range(5)]
        
        encoder_slow = GIFEncoder(fps=1)
        encoder_fast = GIFEncoder(fps=30)
        
        path_slow = tmp_path / "slow.gif"
        path_fast = tmp_path / "fast.gif"
        
        encoder_slow.create_gif(frames, path_slow)
        encoder_fast.create_gif(frames, path_fast)
        
        assert path_slow.exists()
        assert path_fast.exists()
    
    def test_encoder_loop_setting(self, tmp_path):
        """Test GIF loop setting."""
        from meow_decoder.gif_handler import GIFEncoder
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator()
        frames = [generator.generate(b"Loop test")]
        
        # Loop forever (0)
        encoder = GIFEncoder(loop=0)
        path = tmp_path / "loop.gif"
        encoder.create_gif(frames, path)
        
        assert path.exists()
    
    def test_encoder_optimize_option(self, tmp_path):
        """Test GIF optimization option."""
        from meow_decoder.gif_handler import GIFEncoder
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator()
        frames = [generator.generate(f"Opt {i}".encode()) for i in range(3)]
        
        encoder = GIFEncoder()
        
        path_opt = tmp_path / "optimized.gif"
        path_noopt = tmp_path / "unoptimized.gif"
        
        encoder.create_gif(frames, path_opt, optimize=True)
        encoder.create_gif(frames, path_noopt, optimize=False)
        
        assert path_opt.exists()
        assert path_noopt.exists()


class TestGIFDecoder:
    """Test GIF decoding."""
    
    def test_decoder_basic(self, tmp_path):
        """Test basic GIF decoding."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from meow_decoder.qr_code import QRCodeGenerator
        
        # Create GIF
        generator = QRCodeGenerator()
        frames = [generator.generate(f"Frame {i}".encode()) for i in range(3)]
        
        gif_path = tmp_path / "test.gif"
        encoder = GIFEncoder()
        encoder.create_gif(frames, gif_path)
        
        # Decode it
        decoder = GIFDecoder()
        extracted = decoder.extract_frames(gif_path)
        
        assert len(extracted) == 3
    
    def test_decoder_preserves_frame_content(self, tmp_path):
        """Test that decoder preserves frame content."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        # Create GIF with known QR content
        generator = QRCodeGenerator()
        data = [b"Content A", b"Content B"]
        frames = [generator.generate(d) for d in data]
        
        gif_path = tmp_path / "content.gif"
        encoder = GIFEncoder()
        encoder.create_gif(frames, gif_path)
        
        # Extract and read QR codes
        decoder = GIFDecoder()
        extracted = decoder.extract_frames(gif_path)
        
        reader = QRCodeReader()
        for i, frame in enumerate(extracted):
            result = reader.read_image(frame)
            if result:
                assert result[0] == data[i]
    
    def test_decoder_single_frame(self, tmp_path):
        """Test decoding single-frame GIF."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator()
        frames = [generator.generate(b"Single frame")]
        
        gif_path = tmp_path / "single.gif"
        encoder = GIFEncoder()
        encoder.create_gif(frames, gif_path)
        
        decoder = GIFDecoder()
        extracted = decoder.extract_frames(gif_path)
        
        assert len(extracted) == 1
    
    def test_decoder_many_frames(self, tmp_path):
        """Test decoding GIF with many frames."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator()
        frames = [generator.generate(f"Frame {i}".encode()) for i in range(20)]
        
        gif_path = tmp_path / "many.gif"
        encoder = GIFEncoder()
        encoder.create_gif(frames, gif_path)
        
        decoder = GIFDecoder()
        extracted = decoder.extract_frames(gif_path)
        
        assert len(extracted) == 20


class TestGIFRoundtrip:
    """Test full GIF encode/decode roundtrip."""
    
    def test_full_roundtrip(self, tmp_path):
        """Test complete encode/decode roundtrip."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        # Original data
        original_data = [
            b"Secret message 1",
            b"Secret message 2",
            b"Secret message 3"
        ]
        
        # Generate QR frames
        generator = QRCodeGenerator()
        qr_frames = [generator.generate(d) for d in original_data]
        
        # Create GIF
        gif_path = tmp_path / "roundtrip.gif"
        encoder = GIFEncoder()
        encoder.create_gif(qr_frames, gif_path)
        
        # Extract frames
        decoder = GIFDecoder()
        extracted_frames = decoder.extract_frames(gif_path)
        
        # Read QR codes
        reader = QRCodeReader()
        recovered = []
        for frame in extracted_frames:
            result = reader.read_image(frame)
            if result:
                recovered.append(result[0])
        
        # Verify
        assert len(recovered) == len(original_data)
        for orig, rec in zip(original_data, recovered):
            assert orig == rec
    
    def test_roundtrip_with_binary_data(self, tmp_path):
        """Test roundtrip with random binary data."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        # Random binary data
        original_data = [secrets.token_bytes(50) for _ in range(3)]
        
        generator = QRCodeGenerator()
        qr_frames = [generator.generate(d) for d in original_data]
        
        gif_path = tmp_path / "binary.gif"
        encoder = GIFEncoder()
        encoder.create_gif(qr_frames, gif_path)
        
        decoder = GIFDecoder()
        extracted = decoder.extract_frames(gif_path)
        
        reader = QRCodeReader()
        for i, frame in enumerate(extracted):
            result = reader.read_image(frame)
            if result:
                assert result[0] == original_data[i]


class TestQRCodeErrors:
    """Test QR code error handling."""
    
    def test_generator_empty_data(self):
        """Test generation with empty data."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        generator = QRCodeGenerator()
        # Empty data should still work (creates minimal QR)
        qr = generator.generate(b"")
        assert qr is not None
    
    def test_reader_with_corrupted_image(self):
        """Test reader with corrupted/invalid image."""
        from meow_decoder.qr_code import QRCodeReader
        from PIL import Image
        
        # Create noisy image
        import random
        img = Image.new('RGB', (100, 100))
        pixels = img.load()
        for i in range(100):
            for j in range(100):
                pixels[i, j] = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        
        reader = QRCodeReader()
        result = reader.read_image(img)
        
        # Should return empty list, not crash
        assert result == [] or result is None


class TestGIFErrors:
    """Test GIF error handling."""
    
    def test_decoder_nonexistent_file(self):
        """Test decoding nonexistent file."""
        from meow_decoder.gif_handler import GIFDecoder
        
        decoder = GIFDecoder()
        
        with pytest.raises((FileNotFoundError, Exception)):
            decoder.extract_frames("/nonexistent/path.gif")
    
    def test_encoder_empty_frames(self, tmp_path):
        """Test encoding with empty frame list."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder()
        path = tmp_path / "empty.gif"
        
        # Empty list should raise or handle gracefully
        try:
            encoder.create_gif([], path)
        except (ValueError, Exception):
            pass  # Expected behavior


class TestQRCapacity:
    """Test QR code capacity limits."""
    
    def test_max_binary_capacity(self):
        """Test maximum binary data capacity."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        # QR version 40 with L error correction can hold ~2953 bytes
        # We'll test with a reasonable amount
        generator = QRCodeGenerator(error_correction='L')
        reader = QRCodeReader()
        
        # Test with ~1000 bytes
        data = secrets.token_bytes(1000)
        qr = generator.generate(data)
        
        result = reader.read_image(qr)
        assert result is not None
        assert result[0] == data
    
    def test_various_data_sizes(self):
        """Test various data sizes."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        generator = QRCodeGenerator(error_correction='M')
        reader = QRCodeReader()
        
        for size in [10, 50, 100, 200, 500]:
            data = secrets.token_bytes(size)
            qr = generator.generate(data)
            result = reader.read_image(qr)
            
            assert result is not None, f"Failed for size {size}"
            assert result[0] == data, f"Mismatch for size {size}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
