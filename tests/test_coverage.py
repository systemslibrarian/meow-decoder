#!/usr/bin/env python3
"""
📊 Comprehensive Coverage Tests - Target 90%

Tests all major code paths in core modules to increase coverage from 12% → 90%.
Focuses on:
- Crypto module variations
- Fountain code edge cases
- QR code generation/decoding
- GIF handler operations
- Config variations
- Error handling paths
"""

import pytest
import secrets
import tempfile
from pathlib import Path

from meow_decoder.crypto import (
    encrypt_file_bytes, decrypt_to_raw, derive_key, MAGIC
)
from meow_decoder.fountain import FountainEncoder, FountainDecoder, Droplet
from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
from meow_decoder.config import EncodingConfig, DecodingConfig, CryptoConfig


class TestCryptoComprehensive:
    """Comprehensive crypto module testing."""
    
    def test_key_derivation_variations(self):
        """Test KDF with various inputs."""
        password = "testpass"
        salt = secrets.token_bytes(16)
        
        # Basic derivation
        key1 = derive_key(password, salt, None)
        assert len(key1) == 32
        
        # Same inputs = same key
        key2 = derive_key(password, salt, None)
        assert key1 == key2
        
        # Different salt = different key
        salt2 = secrets.token_bytes(16)
        key3 = derive_key(password, salt2, None)
        assert key1 != key3
        
        # With keyfile
        keyfile = b"additional_secret"
        key4 = derive_key(password, salt, keyfile)
        assert key4 != key1  # Keyfile changes output
    
    def test_encryption_roundtrip_variations(self):
        """Test encrypt/decrypt with various data sizes."""
        password = "testpass123"
        
        test_cases = [
            b"",  # Empty
            b"X",  # Single byte
            b"Short message",  # Short
            b"A" * 1000,  # Medium (compressible)
            secrets.token_bytes(1000),  # Medium (incompressible)
            b"B" * 10000,  # Large (compressible)
        ]
        
        for data in test_cases:
            # Encrypt
            comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
                data, password, None, None
            )
            
            # Decrypt
            decrypted = decrypt_to_raw(
                cipher, password, salt, nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha
            )
            
            assert decrypted == data, f"Failed for {len(data)}-byte input"
    
    def test_compression_detection(self):
        """Test that compression works for compressible data."""
        password = "testpass"
        
        # Highly compressible
        compressible = b"A" * 10000
        comp1, sha1, salt1, nonce1, cipher1, _, _ = encrypt_file_bytes(
            compressible, password, None, None
        )
        
        # Incompressible
        incompressible = secrets.token_bytes(10000)
        comp2, sha2, salt2, nonce2, cipher2, _, _ = encrypt_file_bytes(
            incompressible, password, None, None
        )
        
        # Compressed size should be much smaller for compressible data
        assert len(comp1) < len(comp2) * 0.1, "Compression not working"


class TestFountainComprehensive:
    """Comprehensive fountain code testing."""
    
    def test_various_block_sizes(self):
        """Test fountain codes with different block sizes."""
        data = b"Test data" * 100
        
        for block_size in [8, 16, 32, 64, 128, 256, 512]:
            k_blocks = (len(data) + block_size - 1) // block_size
            
            encoder = FountainEncoder(data, k_blocks, block_size)
            decoder = FountainDecoder(k_blocks, block_size, len(data))
            
            # Encode/decode
            while not decoder.is_complete():
                droplet = encoder.droplet()
                decoder.add_droplet(droplet)
            
            decoded = decoder.get_data()
            assert decoded == data, f"Failed with block_size={block_size}"
    
    def test_redundancy_levels(self):
        """Test decoding with various redundancy levels."""
        data = b"Test data for redundancy" * 20
        block_size = 32
        k_blocks = (len(data) + block_size - 1) // block_size
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Generate many droplets
        droplets = [encoder.droplet() for _ in range(int(k_blocks * 2.0))]
        
        # Try decoding with different amounts
        for redundancy in [1.0, 1.2, 1.5, 1.8]:
            n_droplets = int(k_blocks * redundancy)
            decoder = FountainDecoder(k_blocks, block_size, len(data))
            
            for droplet in droplets[:n_droplets]:
                decoder.add_droplet(droplet)
            
            # Should complete with enough redundancy
            # Note: 1.2x redundancy is probabilistic, might occasionally need more
            if redundancy >= 1.5:
                assert decoder.is_complete(), f"Failed at redundancy={redundancy}"
                decoded = decoder.get_data()
                assert decoded == data


class TestQRComprehensive:
    """Comprehensive QR code testing."""
    
    def test_qr_error_correction_levels(self):
        """Test all QR error correction levels."""
        data = b"Test QR data" * 10
        
        for error_level in ["L", "M", "Q", "H"]:
            gen = QRCodeGenerator(error_correction=error_level)
            qr_image = gen.generate(data)
            
            assert qr_image is not None
    
    def test_qr_box_sizes(self):
        """Test different QR box sizes."""
        data = b"Test" * 5
        
        for box_size in [5, 10, 14, 20]:
            gen = QRCodeGenerator(box_size=box_size)
            qr_image = gen.generate(data)
            
            # Larger box size = larger image
            assert qr_image.size[0] >= box_size * 10


class TestConfigComprehensive:
    """Test configuration variations."""
    
    def test_encoding_config_defaults(self):
        """Test encoding config defaults."""
        config = EncodingConfig()
        
        assert config.block_size == 512
        assert config.redundancy == 1.5
        assert config.qr_error_correction == "H"
        assert config.enable_forward_secrecy == True
    
    def test_crypto_config_defaults(self):
        """Test crypto config defaults."""
        config = CryptoConfig()
        
        assert config.key_derivation == "argon2id"
        assert config.argon2_memory == 65536  # 64 MB
        assert config.argon2_iterations == 3


class TestErrorHandling:
    """Test error handling paths."""
    
    def test_invalid_password_length(self):
        """Test that empty password is rejected."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            derive_key("", secrets.token_bytes(16), None)
    
    def test_invalid_salt_length(self):
        """Test that wrong salt length is rejected."""
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            derive_key("password", b"short", None)
    
    def test_incomplete_fountain_decode(self):
        """Test that incomplete decoding is detected."""
        data = b"Test"
        block_size = 4
        k_blocks = 2
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, len(data))
        
        # Add only one droplet (not enough)
        decoder.add_droplet(encoder.droplet())
        
        # Should not be complete
        assert not decoder.is_complete()
        
        # get_data should fail
        with pytest.raises(RuntimeError, match="Decoding incomplete"):
            decoder.get_data()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
