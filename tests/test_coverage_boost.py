#!/usr/bin/env python3
"""
🎯 Coverage Boost Tests - Target 90%

Comprehensive tests for all major code paths in core modules.
These tests target untested branches and edge cases.
"""

import pytest
import secrets
import tempfile
from pathlib import Path
import io

from meow_decoder.crypto import (
    encrypt_file_bytes, decrypt_to_raw, derive_key, MAGIC
)
from meow_decoder.fountain import (
    FountainEncoder, FountainDecoder, Droplet,
    pack_droplet, unpack_droplet, RobustSolitonDistribution
)
from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif


class TestCryptoDeepCoverage:
    """Deep coverage of crypto module edge cases."""
    
    def test_encryption_with_keyfile(self):
        """Test encryption with keyfile."""
        data = b"Secret data"
        password = "password"
        keyfile = b"additional_secret_key_data"
        
        # Encrypt with keyfile
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, keyfile, None
        )
        
        # Decrypt with same keyfile
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha,
            keyfile=keyfile
        )
        assert decrypted == data
        
        # Wrong keyfile should fail
        wrong_keyfile = b"wrong_key"
        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher, password, salt, nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
                keyfile=wrong_keyfile
            )
    
    def test_compression_edge_cases(self):
        """Test compression with various data patterns."""
        password = "test"
        
        # Already compressed data (should not compress further)
        compressed_data = secrets.token_bytes(1000)
        comp1, sha1, salt1, nonce1, cipher1, _, _ = encrypt_file_bytes(
            compressed_data, password, None, None
        )
        
        # Ratio should be close to 1.0 (no compression)
        ratio = len(comp1) / len(compressed_data)
        assert ratio > 0.9, f"Incompressible data compressed to {ratio:.2%}"
    
    def test_magic_constant(self):
        """Test that MAGIC constant is correct."""
        assert MAGIC == b"MEOW"
        assert len(MAGIC) == 4
    
    def test_derive_key_deterministic(self):
        """Test that key derivation is deterministic."""
        password = "password"
        salt = secrets.token_bytes(16)
        
        key1 = derive_key(password, salt, None)
        key2 = derive_key(password, salt, None)
        key3 = derive_key(password, salt, None)
        
        # All should be identical
        assert key1 == key2 == key3
        
        # Should be 32 bytes (256 bits)
        assert len(key1) == 32


class TestFountainDeepCoverage:
    """Deep coverage of fountain code edge cases."""
    
    def test_robust_soliton_distribution(self):
        """Test robust soliton distribution."""
        k = 100
        c = 0.1
        delta = 0.5
        
        dist = RobustSolitonDistribution(k, c, delta)
        
        # Generate many degrees
        degrees = [dist.sample() for _ in range(1000)]
        
        # Should have variety
        unique_degrees = set(degrees)
        assert len(unique_degrees) >= 5, f"Only {len(unique_degrees)} unique degrees"
        
        # Should have degree-1 droplets
        assert 1 in degrees
        
        # No degree should exceed k
        assert max(degrees) <= k
    
    def test_droplet_packing_unpacking(self):
        """Test droplet serialization."""
        block_size = 16
        
        # Create test droplet
        original = Droplet(
            block_indices=[0, 5, 10, 15],
            data=secrets.token_bytes(block_size)
        )
        
        # Pack and unpack
        packed = pack_droplet(original)
        unpacked = unpack_droplet(packed, block_size)
        
        # Should be identical
        assert unpacked.block_indices == original.block_indices
        assert unpacked.data == original.data
    
    def test_decoder_with_exact_k_droplets(self):
        """Test decoding with exactly k droplets (no redundancy)."""
        data = b"Test data" * 10
        block_size = 16
        k_blocks = (len(data) + block_size - 1) // block_size
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, len(data))
        
        # Add exactly k droplets
        for _ in range(k_blocks):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        # Might not be complete (probabilistic)
        # But should not crash
        if decoder.is_complete():
            decoded = decoder.get_data()
            assert decoded == data
    
    def test_decoder_with_many_redundant_droplets(self):
        """Test decoding with 5x redundancy."""
        data = b"Test" * 20
        block_size = 8
        k_blocks = (len(data) + block_size - 1) // block_size
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, len(data))
        
        # Add 5x redundant droplets
        for _ in range(k_blocks * 5):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            
            if decoder.is_complete():
                break
        
        # Should definitely be complete
        assert decoder.is_complete()
        decoded = decoder.get_data()
        assert decoded == data
    
    def test_fountain_with_very_small_data(self):
        """Test fountain codes with very small data."""
        data = b"X"  # Single byte
        block_size = 1
        k_blocks = 1
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, len(data))
        
        # Should only need 1-2 droplets
        droplet = encoder.droplet()
        decoder.add_droplet(droplet)
        
        if not decoder.is_complete():
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
        
        assert decoder.is_complete()
        decoded = decoder.get_data()
        assert decoded == data
    
    def test_fountain_with_large_block_size(self):
        """Test fountain with block size larger than data."""
        data = b"Small"
        block_size = 1024  # Much larger than data
        k_blocks = 1
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, len(data))
        
        droplet = encoder.droplet()
        decoder.add_droplet(droplet)
        
        assert decoder.is_complete()
        decoded = decoder.get_data()
        assert decoded == data


class TestQRDeepCoverage:
    """Deep coverage of QR code generation."""
    
    def test_qr_with_empty_data(self):
        """Test QR generation with empty data."""
        gen = QRCodeGenerator()
        
        # Should handle empty data
        qr = gen.generate(b"")
        assert qr is not None
    
    def test_qr_with_very_large_data(self):
        """Test QR with data near capacity limit."""
        gen = QRCodeGenerator()
        
        # QR codes have size limits
        large_data = b"X" * 2000  # Near limit
        
        try:
            qr = gen.generate(large_data)
            assert qr is not None
        except Exception:
            # Some QR implementations reject large data
            pass
    
    def test_qr_all_error_correction_levels(self):
        """Test all QR error correction levels."""
        data = b"Test data"
        
        for level in ["L", "M", "Q", "H"]:
            gen = QRCodeGenerator(error_correction=level)
            qr = gen.generate(data)
            assert qr is not None
            
            # Higher error correction = larger QR code
            if level == "H":
                assert qr.size[0] > 100


class TestGIFDeepCoverage:
    """Deep coverage of GIF handling."""
    
    def test_gif_with_single_frame(self, tmp_path):
        """Test GIF with only one frame."""
        from PIL import Image
        
        frame = Image.new('RGB', (100, 100), color=(255, 0, 0))
        gif_file = tmp_path / "single.gif"
        
        encoder = GIFEncoder()
        encoder.save_gif([frame], gif_file)
        
        # Decode
        decoder = GIFDecoder()
        frames = decoder.read_gif(gif_file)
        
        assert len(frames) == 1
    
    def test_gif_with_many_frames(self, tmp_path):
        """Test GIF with many frames."""
        from PIL import Image
        
        frames = [Image.new('RGB', (50, 50), color=(i*10, 0, 0)) for i in range(50)]
        gif_file = tmp_path / "many.gif"
        
        encoder = GIFEncoder()
        encoder.save_gif(frames, gif_file)
        
        # Decode
        decoder = GIFDecoder()
        decoded_frames = decoder.read_gif(gif_file)
        
        assert len(decoded_frames) == len(frames)
    
    def test_gif_with_different_fps(self, tmp_path):
        """Test GIF encoding with different frame rates."""
        from PIL import Image
        
        frames = [Image.new('RGB', (50, 50)) for _ in range(10)]
        
        for fps in [1, 5, 10, 30]:
            gif_file = tmp_path / f"fps_{fps}.gif"
            encoder = GIFEncoder(fps=fps)
            encoder.save_gif(frames, gif_file)
            
            assert gif_file.exists()


class TestE2EDeepCoverage:
    """Deep end-to-end coverage."""
    
    def test_roundtrip_with_binary_data(self, tmp_path):
        """Test roundtrip with random binary data."""
        input_file = tmp_path / "binary.dat"
        binary_data = secrets.token_bytes(5000)
        input_file.write_bytes(binary_data)
        
        gif_file = tmp_path / "binary.gif"
        output_file = tmp_path / "output.dat"
        
        # Encode and decode
        encode_file(input_file, gif_file, password="testpass")
        decode_gif(gif_file, output_file, password="testpass")
        
        # Verify
        assert output_file.read_bytes() == binary_data
    
    def test_roundtrip_with_unicode_content(self, tmp_path):
        """Test roundtrip with Unicode text."""
        input_file = tmp_path / "unicode.txt"
        unicode_text = "Hello 世界 🐱 Привет مرحبا"
        input_file.write_text(unicode_text, encoding='utf-8')
        
        gif_file = tmp_path / "unicode.gif"
        output_file = tmp_path / "output.txt"
        
        # Encode and decode
        encode_file(input_file, gif_file, password="testpass")
        decode_gif(gif_file, output_file, password="testpass")
        
        # Verify
        assert output_file.read_text(encoding='utf-8') == unicode_text
    
    def test_roundtrip_with_very_long_password(self, tmp_path):
        """Test with very long password."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # 10KB password
        long_password = "x" * 10000
        
        encode_file(input_file, gif_file, password=long_password)
        decode_gif(gif_file, output_file, password=long_password)
        
        assert output_file.read_text() == "Secret"
    
    def test_roundtrip_with_special_chars_password(self, tmp_path):
        """Test with special characters in password."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Data")
        
        gif_file = tmp_path / "test.gif"
        output_file = tmp_path / "output.txt"
        
        # Password with special characters
        special_password = "p@ssw0rd!#$%^&*(){}[]<>?/|\\~`"
        
        encode_file(input_file, gif_file, password=special_password)
        decode_gif(gif_file, output_file, password=special_password)
        
        assert output_file.read_text() == "Data"


class TestErrorPathCoverage:
    """Test error handling paths."""
    
    def test_decode_with_corrupted_magic(self, tmp_path):
        """Test decoding with corrupted magic bytes."""
        # Create valid GIF first
        input_file = tmp_path / "test.txt"
        input_file.write_text("Test")
        
        gif_file = tmp_path / "test.gif"
        encode_file(input_file, gif_file, password="test")
        
        # Corrupt magic bytes
        gif_data = bytearray(gif_file.read_bytes())
        
        # Find and corrupt MEOW magic
        for i in range(len(gif_data) - 4):
            if gif_data[i:i+4] == b"MEOW":
                gif_data[i:i+4] = b"FAKE"
                break
        
        gif_file.write_bytes(bytes(gif_data))
        
        # Should fail
        output_file = tmp_path / "output.txt"
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, password="test")
    
    def test_fountain_decoder_get_data_without_length(self):
        """Test get_data without original_length set."""
        decoder = FountainDecoder(k_blocks=5, block_size=16)
        
        # Manually mark as complete
        decoder.decoded_count = decoder.k_blocks
        decoder.blocks = [b"test" * 4] * 5
        
        # Should raise ValueError
        with pytest.raises(ValueError, match="original_length"):
            decoder.get_data()
    
    def test_fountain_encoder_generate_many_droplets(self):
        """Test generating many droplets from encoder."""
        data = b"Test" * 100
        block_size = 32
        k_blocks = (len(data) + block_size - 1) // block_size
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Generate 1000 droplets (way more than needed)
        droplets = []
        for _ in range(1000):
            droplet = encoder.droplet()
            assert droplet is not None
            assert len(droplet.data) == block_size
            droplets.append(droplet)
        
        # Should have variety
        degrees = [len(d.block_indices) for d in droplets]
        assert len(set(degrees)) >= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
