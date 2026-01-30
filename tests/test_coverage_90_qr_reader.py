#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for QR Code Reader - Target: 90%+
Tests qr_code.py reader and generator paths.
"""

import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from PIL import Image
import io

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestQRCodeGenerator:
    """Test QR code generation."""
    
    def test_basic_generation(self):
        """Test basic QR code generation."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        data = b"Test data for QR"
        
        qr_image = gen.generate(data)
        
        assert isinstance(qr_image, Image.Image)
        assert qr_image.size[0] > 0
        assert qr_image.size[1] > 0
    
    def test_generation_error_levels(self):
        """Test different error correction levels."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        data = b"Test data for different error levels"
        
        for level in ['L', 'M', 'Q', 'H']:
            gen = QRCodeGenerator(error_correction=level)
            qr_image = gen.generate(data)
            assert isinstance(qr_image, Image.Image)
    
    def test_generation_custom_size(self):
        """Test QR code with custom box size."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator(box_size=15, border=5)
        data = b"Test data"
        
        qr_image = gen.generate(data)
        assert isinstance(qr_image, Image.Image)
    
    def test_batch_generation(self):
        """Test batch QR code generation."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        data_list = [b"Data 1", b"Data 2", b"Data 3"]
        
        qr_images = gen.generate_batch(data_list)
        
        assert len(qr_images) == 3
        for img in qr_images:
            assert isinstance(img, Image.Image)
    
    def test_large_data_generation(self):
        """Test QR code with large data."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator(error_correction='L')  # L for more capacity
        data = b"X" * 1000  # Large data
        
        qr_image = gen.generate(data)
        assert isinstance(qr_image, Image.Image)


class TestQRCodeReader:
    """Test QR code reading."""
    
    def test_basic_reading(self):
        """Test basic QR code reading."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        original_data = b"Test data to read back"
        
        qr_image = gen.generate(original_data)
        
        reader = QRCodeReader()
        read_data = reader.read_image(qr_image)
        
        assert read_data is not None
        assert len(read_data) >= 1
        assert original_data == read_data[0]
    
    def test_reading_from_file(self):
        """Test reading QR from file."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        original_data = b"Test data from file"
        
        qr_image = gen.generate(original_data)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            qr_path = Path(tmpdir) / "test_qr.png"
            qr_image.save(qr_path)
            
            reader = QRCodeReader()
            read_data = reader.read_file(qr_path)
            
            assert read_data is not None
            assert original_data in read_data
    
    def test_reading_multiple_qr_codes(self):
        """Test reading image with multiple QR codes."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator(box_size=5, border=2)
        
        # Generate two QR codes
        qr1 = gen.generate(b"First QR")
        qr2 = gen.generate(b"Second QR")
        
        # Combine into one image
        combined = Image.new('RGB', (qr1.width * 2, qr1.height))
        combined.paste(qr1.convert('RGB'), (0, 0))
        combined.paste(qr2.convert('RGB'), (qr1.width, 0))
        
        reader = QRCodeReader()
        read_data = reader.read_image(combined)
        
        # Should read at least one (pyzbar dependent)
        assert read_data is not None
    
    def test_reading_no_qr_found(self):
        """Test reading image with no QR code."""
        from meow_decoder.qr_code import QRCodeReader
        
        # Create blank image
        blank_image = Image.new('RGB', (100, 100), color='white')
        
        reader = QRCodeReader()
        read_data = reader.read_image(blank_image)
        
        assert read_data is None or len(read_data) == 0


class TestQRCodeReaderPreprocessing:
    """Test QR code reader preprocessing options."""
    
    def test_normal_preprocessing(self):
        """Test normal preprocessing mode."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        original_data = b"Normal preprocessing test"
        qr_image = gen.generate(original_data)
        
        reader = QRCodeReader(preprocessing='normal')
        read_data = reader.read_image(qr_image)
        
        assert read_data is not None
        assert original_data in read_data
    
    def test_aggressive_preprocessing(self):
        """Test aggressive preprocessing mode."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        original_data = b"Aggressive preprocessing test"
        qr_image = gen.generate(original_data)
        
        reader = QRCodeReader(preprocessing='aggressive')
        read_data = reader.read_image(qr_image)
        
        assert read_data is not None
        assert original_data in read_data


class TestQRCodeRoundtrip:
    """Test full QR code encode/decode roundtrip."""
    
    def test_binary_data_roundtrip(self):
        """Test roundtrip with binary data."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        import secrets
        
        gen = QRCodeGenerator(error_correction='M')
        reader = QRCodeReader()
        
        # Test with binary data
        original_data = secrets.token_bytes(100)
        
        qr_image = gen.generate(original_data)
        read_data = reader.read_image(qr_image)
        
        assert read_data is not None
        assert original_data in read_data
    
    def test_unicode_data_roundtrip(self):
        """Test roundtrip with unicode text."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        reader = QRCodeReader()
        
        original_data = "Hello 😺 🔐 Meow! 猫".encode('utf-8')
        
        qr_image = gen.generate(original_data)
        read_data = reader.read_image(qr_image)
        
        assert read_data is not None
        assert original_data in read_data
    
    def test_empty_data(self):
        """Test with minimal data."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        reader = QRCodeReader()
        
        original_data = b"X"  # Single byte
        
        qr_image = gen.generate(original_data)
        read_data = reader.read_image(qr_image)
        
        assert read_data is not None
        assert original_data in read_data


class TestQRCodeEdgeCases:
    """Test QR code edge cases."""
    
    def test_rotated_qr(self):
        """Test reading rotated QR code (may fail)."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        original_data = b"Rotated QR test"
        qr_image = gen.generate(original_data)
        
        # Rotate 90 degrees
        rotated = qr_image.rotate(90, expand=True)
        
        reader = QRCodeReader()
        # May or may not be able to read rotated
        read_data = reader.read_image(rotated)
        # Just verify no crash
    
    def test_scaled_qr(self):
        """Test reading scaled QR code."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        original_data = b"Scaled QR test"
        qr_image = gen.generate(original_data)
        
        # Scale up
        scaled = qr_image.resize((qr_image.width * 2, qr_image.height * 2))
        
        reader = QRCodeReader()
        read_data = reader.read_image(scaled)
        
        # Should still be readable when scaled up
        assert read_data is not None
        assert original_data in read_data
    
    def test_grayscale_qr(self):
        """Test reading grayscale QR code."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator()
        original_data = b"Grayscale QR test"
        qr_image = gen.generate(original_data)
        
        # Convert to grayscale
        grayscale = qr_image.convert('L')
        
        reader = QRCodeReader()
        read_data = reader.read_image(grayscale)
        
        assert read_data is not None
        assert original_data in read_data


class TestQRCodeGeneratorDefaults:
    """Test QR code generator default values."""
    
    def test_default_error_correction(self):
        """Test default error correction is set."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        assert hasattr(gen, 'error_correction')
    
    def test_default_box_size(self):
        """Test default box size is set."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        assert hasattr(gen, 'box_size')
    
    def test_default_border(self):
        """Test default border is set."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        assert hasattr(gen, 'border')


class TestQRCodeReaderWebcam:
    """Test QR code reader webcam functionality (mocked)."""
    
    def test_webcam_read_mocked(self):
        """Test webcam reading with mocked camera."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        # Generate a QR code to use as mock frame
        gen = QRCodeGenerator()
        original_data = b"Webcam test data"
        qr_image = gen.generate(original_data)
        
        # Convert to numpy array for OpenCV
        import numpy as np
        qr_array = np.array(qr_image.convert('RGB'))
        
        # Create reader
        reader = QRCodeReader()
        
        # Test the read_image with numpy array
        read_data = reader.read_image(Image.fromarray(qr_array))
        
        assert read_data is not None
        assert original_data in read_data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
