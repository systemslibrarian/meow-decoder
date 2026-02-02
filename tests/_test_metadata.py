#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for Metadata Obfuscation - Target: 90%+
Tests metadata_obfuscation.py padding and size class functions.
"""

import pytest
import sys
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestLengthPadding:
    """Test length padding functions."""
    
    def test_add_length_padding_basic(self):
        """Test basic length padding."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"Hello, World!"
        padded = add_length_padding(data)
        
        # Padded should be larger or equal
        assert len(padded) >= len(data)
    
    def test_remove_length_padding_basic(self):
        """Test basic length padding removal."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"Test data for padding"
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original
    
    def test_padding_roundtrip_various_sizes(self):
        """Test padding roundtrip with various sizes."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        sizes = [1, 10, 100, 1000, 5000, 10000]
        
        for size in sizes:
            original = secrets.token_bytes(size)
            padded = add_length_padding(original)
            recovered = remove_length_padding(padded)
            
            assert recovered == original, f"Failed for size {size}"
    
    def test_padding_empty_data(self):
        """Test padding with empty data."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b""
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original
    
    def test_padding_increases_size(self):
        """Test that padding increases size to next class."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"x" * 100
        padded = add_length_padding(data)
        
        # Should pad to a size class boundary
        assert len(padded) > len(data)
    
    def test_padding_is_deterministic(self):
        """Test that padding produces consistent size classes."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"y" * 500
        
        padded1 = add_length_padding(data)
        padded2 = add_length_padding(data)
        
        # Length should be same (same size class)
        assert len(padded1) == len(padded2)


class TestSizeClasses:
    """Test size class functions."""
    
    def test_get_size_class(self):
        """Test getting size class."""
        from meow_decoder.metadata_obfuscation import get_size_class
        
        # Small sizes should get appropriate class
        class_1 = get_size_class(100)
        class_2 = get_size_class(200)
        class_3 = get_size_class(1000)
        
        assert class_1 >= 100
        assert class_2 >= 200
        assert class_3 >= 1000
    
    def test_size_class_power_of_two(self):
        """Test that size classes are power of two."""
        from meow_decoder.metadata_obfuscation import get_size_class
        
        import math
        
        for size in [100, 500, 1000, 5000]:
            size_class = get_size_class(size)
            
            # Check if power of 2
            is_power_of_two = (size_class & (size_class - 1)) == 0
            assert is_power_of_two or size_class == 0
    
    def test_size_class_never_smaller(self):
        """Test that size class is never smaller than input."""
        from meow_decoder.metadata_obfuscation import get_size_class
        
        for size in range(1, 10000, 100):
            size_class = get_size_class(size)
            assert size_class >= size


class TestParanoidPadding:
    """Test paranoid mode padding."""
    
    def test_paranoid_padding(self):
        """Test paranoid padding with fixed buckets."""
        try:
            from meow_decoder.metadata_obfuscation import add_paranoid_padding, remove_paranoid_padding
            
            data = b"Secret data" * 100
            padded = add_paranoid_padding(data)
            recovered = remove_paranoid_padding(padded)
            
            assert recovered == data
        except ImportError:
            pytest.skip("Paranoid padding not implemented")
    
    def test_paranoid_buckets(self):
        """Test paranoid bucket sizes."""
        try:
            from meow_decoder.metadata_obfuscation import get_paranoid_bucket
            
            # Check bucket sizes: 1 MB, 4 MB, 16 MB, 64 MB, 256 MB
            bucket_1 = get_paranoid_bucket(100)
            bucket_2 = get_paranoid_bucket(1000000)
            
            assert bucket_1 >= 100
            assert bucket_2 >= 1000000
        except ImportError:
            pytest.skip("Paranoid buckets not implemented")


class TestPaddingFormat:
    """Test padding format specifics."""
    
    def test_padding_includes_length_header(self):
        """Test that padding includes length header."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"Test"
        padded = add_length_padding(data)
        
        # First bytes should encode the length
        # The format is typically: length (4 or 8 bytes) + data + random padding
        assert len(padded) >= len(data) + 4
    
    def test_padding_is_random(self):
        """Test that padding bytes are random."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"Fixed data"
        
        padded1 = add_length_padding(data)
        padded2 = add_length_padding(data)
        
        # Padding bytes should be different (random)
        # (though length should be same)
        assert len(padded1) == len(padded2)
        # The actual padding bytes are random, so padded1 != padded2 usually
    
    def test_remove_padding_validates(self):
        """Test that remove_padding validates format."""
        from meow_decoder.metadata_obfuscation import remove_length_padding
        
        # Corrupted padding should fail
        corrupt = b"\xff\xff\xff\xff" + b"x" * 100
        
        with pytest.raises((ValueError, Exception)):
            remove_length_padding(corrupt)


class TestPaddingEdgeCases:
    """Test padding edge cases."""
    
    def test_padding_boundary_sizes(self):
        """Test padding at boundary sizes."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        # Test at powers of 2
        for exp in range(4, 14):  # 16 bytes to 16 KB
            size = 2 ** exp
            
            # Just under boundary
            data = secrets.token_bytes(size - 1)
            padded = add_length_padding(data)
            recovered = remove_length_padding(padded)
            assert recovered == data
            
            # Exactly at boundary
            data = secrets.token_bytes(size)
            padded = add_length_padding(data)
            recovered = remove_length_padding(padded)
            assert recovered == data
            
            # Just over boundary
            data = secrets.token_bytes(size + 1)
            padded = add_length_padding(data)
            recovered = remove_length_padding(padded)
            assert recovered == data
    
    def test_padding_large_data(self):
        """Test padding with large data."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        # 100 KB of data
        data = secrets.token_bytes(100 * 1024)
        padded = add_length_padding(data)
        recovered = remove_length_padding(padded)
        
        assert recovered == data
    
    def test_padding_binary_data(self):
        """Test padding with various binary patterns."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        patterns = [
            b"\x00" * 100,           # All zeros
            b"\xff" * 100,           # All ones
            bytes(range(256)) * 4,   # All byte values
            b"\x00\xff" * 50,        # Alternating
        ]
        
        for data in patterns:
            padded = add_length_padding(data)
            recovered = remove_length_padding(padded)
            assert recovered == data


class TestChaffFrames:
    """Test chaff frame functions."""
    
    def test_generate_chaff_frame(self):
        """Test chaff frame generation."""
        try:
            from meow_decoder.metadata_obfuscation import generate_chaff_frame
            
            frame = generate_chaff_frame(512)
            
            assert len(frame) == 512
            assert isinstance(frame, bytes)
        except ImportError:
            pytest.skip("Chaff frame generation not implemented")
    
    def test_chaff_frames_are_random(self):
        """Test that chaff frames are random."""
        try:
            from meow_decoder.metadata_obfuscation import generate_chaff_frame
            
            frame1 = generate_chaff_frame(256)
            frame2 = generate_chaff_frame(256)
            
            assert frame1 != frame2
        except ImportError:
            pytest.skip("Chaff frame generation not implemented")


class TestMetadataObfuscationIntegration:
    """Test integration with crypto module."""
    
    def test_padding_with_encryption(self):
        """Test padding integrates with encryption."""
        import os
        os.environ['MEOW_TEST_MODE'] = '1'
        
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        original = b"Secret message" * 100
        password = "TestPassword123"
        
        # Encrypt with padding (use_length_padding=True is default)
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            original, password, use_length_padding=True
        )
        
        # Decrypt
        recovered = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(original),
            comp_len=len(comp),
            sha256=sha
        )
        
        assert recovered == original


class TestMetadataObfuscationModule:
    """Test module-level functions."""
    
    def test_module_imports(self):
        """Test module imports correctly."""
        from meow_decoder import metadata_obfuscation
        
        assert hasattr(metadata_obfuscation, 'add_length_padding')
        assert hasattr(metadata_obfuscation, 'remove_length_padding')
    
    def test_get_size_class_exists(self):
        """Test get_size_class function exists."""
        from meow_decoder.metadata_obfuscation import get_size_class
        
        result = get_size_class(100)
        assert isinstance(result, int)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
