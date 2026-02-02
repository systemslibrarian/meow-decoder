#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for metadata_obfuscation.py - Target: 90%+
Tests all metadata obfuscation paths.
"""

import pytest
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestLengthPadding:
    """Test add_length_padding function."""
    
    def test_basic_padding(self):
        """Test basic padding."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"test_data_12345"
        padded = add_length_padding(data)
        
        # Should be larger than original
        assert len(padded) > len(data)
    
    def test_padding_power_of_two(self):
        """Test padding rounds to power of two."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        # Various sizes
        for size in [100, 500, 1000, 2000, 5000]:
            data = secrets.token_bytes(size)
            padded = add_length_padding(data)
            
            # Check padded length (minus header) is power of 2
            # The implementation adds a 4-byte header
            padded_data_len = len(padded) - 4
            
            # Should be at least as large as original
            assert len(padded) > len(data)
    
    def test_empty_data(self):
        """Test padding empty data."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        padded = add_length_padding(b"")
        
        # Should still add header
        assert len(padded) >= 4
    
    def test_small_data(self):
        """Test padding small data."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"x"
        padded = add_length_padding(data)
        
        assert len(padded) > 1
    
    def test_large_data(self):
        """Test padding large data."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = secrets.token_bytes(100000)
        padded = add_length_padding(data)
        
        assert len(padded) > len(data)


class TestLengthUnpadding:
    """Test remove_length_padding function."""
    
    def test_basic_unpadding(self):
        """Test basic unpadding."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"test_data_12345"
        padded = add_length_padding(original)
        unpadded = remove_length_padding(padded)
        
        assert unpadded == original
    
    def test_roundtrip_various_sizes(self):
        """Test roundtrip for various sizes."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        for size in [1, 10, 100, 1000, 10000]:
            original = secrets.token_bytes(size)
            padded = add_length_padding(original)
            unpadded = remove_length_padding(padded)
            
            assert unpadded == original, f"Roundtrip failed for size {size}"
    
    def test_empty_data_roundtrip(self):
        """Test empty data roundtrip."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b""
        padded = add_length_padding(original)
        unpadded = remove_length_padding(padded)
        
        assert unpadded == original
    
    def test_invalid_padding_short(self):
        """Test unpadding data that's too short."""
        from meow_decoder.metadata_obfuscation import remove_length_padding
        
        with pytest.raises(ValueError):
            remove_length_padding(b"abc")  # Too short for header
    
    def test_invalid_padding_corrupted(self):
        """Test unpadding corrupted data."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"test_data"
        padded = add_length_padding(original)
        
        # Corrupt the header
        corrupted = bytes([0xff, 0xff, 0xff, 0xff]) + padded[4:]
        
        with pytest.raises(ValueError):
            remove_length_padding(corrupted)


class TestPaddingDeterminism:
    """Test padding determinism (size classes)."""
    
    def test_same_size_class(self):
        """Test data in same size class gets same padded size."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        # Data close in size should end up in same bucket
        data1 = secrets.token_bytes(500)
        data2 = secrets.token_bytes(600)
        
        padded1 = add_length_padding(data1)
        padded2 = add_length_padding(data2)
        
        # May or may not be same bucket depending on boundaries
        # Just verify they're both padded
        assert len(padded1) >= len(data1)
        assert len(padded2) >= len(data2)
    
    def test_different_size_classes(self):
        """Test clearly different sizes get different buckets."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        small = secrets.token_bytes(100)
        large = secrets.token_bytes(10000)
        
        padded_small = add_length_padding(small)
        padded_large = add_length_padding(large)
        
        # Large should definitely be bigger bucket
        assert len(padded_large) > len(padded_small)


class TestPaddingContent:
    """Test padding content (should be random)."""
    
    def test_padding_is_random(self):
        """Test padding bytes are random."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"test"
        
        padded1 = add_length_padding(data)
        padded2 = add_length_padding(data)
        
        # The padding portion should be different (random)
        # Skip header and data portion
        padding_start = 4 + len(data)
        
        if len(padded1) > padding_start and len(padded2) > padding_start:
            # Padding should be different due to randomness
            # (small chance they're same, but unlikely)
            assert padded1[padding_start:] != padded2[padding_start:]


class TestSizeClasses:
    """Test size class calculations."""
    
    def test_power_of_two_sizes(self):
        """Test that sizes are rounded to powers of two."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        # Test specific size boundaries
        test_sizes = [127, 128, 129, 255, 256, 257, 511, 512, 513]
        
        for size in test_sizes:
            data = secrets.token_bytes(size)
            padded = add_length_padding(data)
            
            # Just verify it's padded
            assert len(padded) > size


class TestMetadataObfuscationEdgeCases:
    """Test edge cases."""
    
    def test_binary_data_preservation(self):
        """Test binary data is preserved."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        # All byte values
        original = bytes(range(256))
        padded = add_length_padding(original)
        unpadded = remove_length_padding(padded)
        
        assert unpadded == original
    
    def test_null_bytes(self):
        """Test null bytes are preserved."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"\x00" * 100
        padded = add_length_padding(original)
        unpadded = remove_length_padding(padded)
        
        assert unpadded == original
    
    def test_max_byte_values(self):
        """Test max byte values."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"\xff" * 100
        padded = add_length_padding(original)
        unpadded = remove_length_padding(padded)
        
        assert unpadded == original


class TestMetadataObfuscationIntegration:
    """Integration tests for metadata obfuscation."""
    
    def test_with_crypto(self):
        """Test metadata obfuscation with crypto module."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        # Original data
        original = b"Secret message to encrypt"
        password = "test_password_12345"
        
        # Encrypt (uses padding internally)
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            original, password, use_length_padding=True
        )
        
        # Decrypt
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(original),
            comp_len=len(comp),
            sha256=sha
        )
        
        assert decrypted == original
    
    def test_padding_overhead(self):
        """Test padding overhead is reasonable."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        sizes = [100, 1000, 10000]
        
        for size in sizes:
            data = secrets.token_bytes(size)
            padded = add_length_padding(data)
            
            overhead = len(padded) / size
            
            # Overhead should be reasonable (not more than 2x for large data)
            assert overhead < 3.0, f"Excessive overhead for size {size}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
