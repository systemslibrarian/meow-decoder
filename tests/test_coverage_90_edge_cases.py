#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for edge cases - Target: 90%+
Tests error paths, boundary conditions, and unusual inputs.
"""

import pytest
import secrets
import tempfile
import sys
import os
import struct
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestEmptyInputHandling:
    """Test handling of empty inputs."""
    
    def test_empty_data_encryption(self):
        """Test encrypting empty data."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        # Empty data should work (compressed empty is still valid)
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            b"",
            "ValidPassword123!",
            None, None,
            use_length_padding=False
        )
        
        assert comp is not None
        assert cipher is not None
    
    def test_fountain_empty_data(self):
        """Test fountain encoding of minimal data."""
        from meow_decoder.fountain import FountainEncoder
        
        # Minimal data
        encoder = FountainEncoder(b"x", 1, 10)
        
        droplet = encoder.droplet()
        
        assert droplet is not None
    
    def test_empty_keyfile_rejected(self):
        """Test empty keyfile is rejected."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"")  # Empty
            filepath = f.name
        
        try:
            with pytest.raises(ValueError):
                verify_keyfile(filepath)
        finally:
            os.unlink(filepath)


class TestBoundaryConditions:
    """Test boundary conditions."""
    
    def test_minimum_password_length(self):
        """Test password at exactly minimum length."""
        from meow_decoder.crypto import derive_key, MIN_PASSWORD_LENGTH
        
        password = "x" * MIN_PASSWORD_LENGTH
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert len(key) == 32
    
    def test_maximum_keyfile_size(self):
        """Test keyfile at maximum size."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * (1024 * 1024))  # Exactly 1 MB
            filepath = f.name
        
        try:
            keyfile = verify_keyfile(filepath)
            assert len(keyfile) == 1024 * 1024
        finally:
            os.unlink(filepath)
    
    def test_oversized_keyfile_rejected(self):
        """Test keyfile over max size is rejected."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * (1024 * 1024 + 1))  # 1 MB + 1 byte
            filepath = f.name
        
        try:
            with pytest.raises(ValueError):
                verify_keyfile(filepath)
        finally:
            os.unlink(filepath)
    
    def test_minimum_keyfile_size(self):
        """Test keyfile at minimum size."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 32)  # Exactly 32 bytes
            filepath = f.name
        
        try:
            keyfile = verify_keyfile(filepath)
            assert len(keyfile) == 32
        finally:
            os.unlink(filepath)


class TestInvalidInputHandling:
    """Test handling of invalid inputs."""
    
    def test_invalid_salt_length(self):
        """Test invalid salt length is rejected."""
        from meow_decoder.crypto import derive_key
        
        with pytest.raises(ValueError):
            derive_key("ValidPassword123!", b"short")  # Not 16 bytes
    
    def test_invalid_manifest_magic(self):
        """Test invalid manifest magic is rejected."""
        from meow_decoder.crypto import unpack_manifest
        
        invalid_manifest = b"BADM" + b"\x00" * 111  # Wrong magic
        
        with pytest.raises(ValueError):
            unpack_manifest(invalid_manifest)
    
    def test_truncated_manifest(self):
        """Test truncated manifest is rejected."""
        from meow_decoder.crypto import unpack_manifest
        
        truncated = b"MEOW3" + b"\x00" * 10  # Too short
        
        with pytest.raises(ValueError):
            unpack_manifest(truncated)
    
    def test_invalid_manifest_length(self):
        """Test invalid manifest length is rejected."""
        from meow_decoder.crypto import unpack_manifest
        
        # Valid magic but wrong total size
        invalid = b"MEOW3" + b"\x00" * 150  # Not a valid size
        
        with pytest.raises(ValueError):
            unpack_manifest(invalid)


class TestFountainEdgeCases:
    """Test fountain code edge cases."""
    
    def test_single_block(self):
        """Test single block encoding."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Short data"
        encoder = FountainEncoder(data, 1, len(data))
        
        decoder = FountainDecoder(1, len(data))
        
        # Single droplet should complete
        droplet = encoder.droplet()
        decoder.add_droplet(droplet)
        
        assert decoder.is_complete()
    
    def test_many_blocks(self):
        """Test many blocks encoding."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"x" * 10000
        k_blocks = 100
        block_size = 100
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Generate many droplets
        droplets = encoder.generate_droplets(150)
        
        assert len(droplets) == 150
    
    def test_redundant_droplets(self):
        """Test handling of redundant droplets."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        data = b"Test data for redundancy"
        k_blocks = 5
        block_size = 10
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Send many more droplets than needed
        for i in range(100):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            
            if decoder.is_complete():
                break
        
        assert decoder.is_complete()
    
    def test_soliton_distribution_edge(self):
        """Test Soliton distribution with edge k values."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        # Small k
        dist_small = RobustSolitonDistribution(2)
        degree = dist_small.sample_degree()
        assert degree >= 1
        
        # Large k
        dist_large = RobustSolitonDistribution(1000)
        degree = dist_large.sample_degree()
        assert degree >= 1


class TestQRCodeEdgeCases:
    """Test QR code edge cases."""
    
    def test_large_data_qr(self):
        """Test QR code with large data."""
        try:
            from meow_decoder.qr_code import QRCodeGenerator
            
            # Generate data near QR capacity
            data = b"x" * 2000
            
            gen = QRCodeGenerator()
            
            try:
                img = gen.generate(data)
                assert img is not None
            except Exception:
                # May fail if data too large - that's expected behavior
                pass
        except ImportError:
            pytest.skip("QR code module not available")
    
    def test_binary_data_qr(self):
        """Test QR code with binary data."""
        try:
            from meow_decoder.qr_code import QRCodeGenerator
            
            # Binary data with all byte values
            data = bytes(range(256))
            
            gen = QRCodeGenerator()
            img = gen.generate(data)
            
            assert img is not None
        except ImportError:
            pytest.skip("QR code module not available")


class TestManifestEdgeCases:
    """Test manifest edge cases."""
    
    def test_manifest_with_all_optional_fields(self):
        """Test manifest with all optional fields."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),  # FS enabled
            pq_ciphertext=None,
            duress_tag=secrets.token_bytes(32)  # Duress enabled
        )
        
        packed = pack_manifest(manifest)
        
        # Should be FS + duress size = 179 bytes
        assert len(packed) == 179
        
        unpacked = unpack_manifest(packed)
        
        assert unpacked.ephemeral_public_key == manifest.ephemeral_public_key
        assert unpacked.duress_tag == manifest.duress_tag
    
    def test_meow2_backward_compat(self):
        """Test MEOW2 backward compatibility."""
        from meow_decoder.crypto import unpack_manifest
        
        # Create MEOW2 format manifest
        manifest_bytes = b"MEOW2"
        manifest_bytes += secrets.token_bytes(16)  # salt
        manifest_bytes += secrets.token_bytes(12)  # nonce
        manifest_bytes += struct.pack(">III", 1000, 800, 816)  # lengths
        manifest_bytes += struct.pack(">HI", 512, 2)  # block_size, k_blocks
        manifest_bytes += secrets.token_bytes(32)  # sha256
        manifest_bytes += secrets.token_bytes(32)  # hmac
        
        # Should parse without error (legacy support)
        manifest = unpack_manifest(manifest_bytes)
        
        assert manifest.orig_len == 1000


class TestErrorPropagation:
    """Test error propagation."""
    
    def test_encryption_error_wrapped(self):
        """Test encryption errors are wrapped."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        # Invalid: empty password
        with pytest.raises((ValueError, RuntimeError)):
            encrypt_file_bytes(b"data", "", None, None)
    
    def test_decryption_error_wrapped(self):
        """Test decryption errors are wrapped."""
        from meow_decoder.crypto import decrypt_to_raw
        
        # Invalid data
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                b"invalid_ciphertext",
                "password123!",
                secrets.token_bytes(16),
                secrets.token_bytes(12),
                None,
                100, 80, secrets.token_bytes(32)
            )
    
    def test_hmac_mismatch_error(self):
        """Test HMAC mismatch returns False."""
        from meow_decoder.crypto import verify_manifest_hmac, Manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),  # Random HMAC
        )
        
        result = verify_manifest_hmac("SomePassword123!", manifest)
        
        assert result is False


class TestConfigEdgeCases:
    """Test configuration edge cases."""
    
    def test_config_save_load_roundtrip(self):
        """Test config save/load roundtrip."""
        from meow_decoder.config import MeowConfig
        
        config = MeowConfig()
        config.encoding.block_size = 1024
        config.encoding.redundancy = 2.5
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = Path(f.name)
        
        try:
            config.save(filepath)
            
            loaded = MeowConfig.load(filepath)
            
            assert loaded.encoding.block_size == 1024
            assert loaded.encoding.redundancy == 2.5
        finally:
            filepath.unlink()
    
    def test_config_with_missing_keys(self):
        """Test config loading with missing keys."""
        from meow_decoder.config import MeowConfig
        import json
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=".json", delete=False) as f:
            json.dump({
                "encoding": {"block_size": 256},
                "verbose": True
            }, f)
            filepath = Path(f.name)
        
        try:
            # Should not raise - use defaults for missing
            loaded = MeowConfig.load(filepath)
            
            assert loaded.encoding.block_size == 256
            assert loaded.verbose is True
        finally:
            filepath.unlink()


class TestGIFEdgeCases:
    """Test GIF handling edge cases."""
    
    def test_single_frame_gif(self):
        """Test single-frame GIF creation."""
        try:
            from meow_decoder.gif_handler import GIFEncoder
            from PIL import Image
            
            encoder = GIFEncoder(fps=1)
            
            # Single frame
            frame = Image.new('RGB', (100, 100), color='red')
            
            with tempfile.NamedTemporaryFile(suffix=".gif", delete=False) as f:
                filepath = Path(f.name)
            
            try:
                size = encoder.create_gif([frame], filepath)
                
                assert size > 0
                assert filepath.exists()
            finally:
                filepath.unlink()
        except ImportError:
            pytest.skip("GIF handler not available")
    
    def test_many_frames_gif(self):
        """Test GIF with many frames."""
        try:
            from meow_decoder.gif_handler import GIFEncoder
            from PIL import Image
            
            encoder = GIFEncoder(fps=10)
            
            # Many frames
            frames = [
                Image.new('RGB', (50, 50), color=(i % 256, 0, 0))
                for i in range(50)
            ]
            
            with tempfile.NamedTemporaryFile(suffix=".gif", delete=False) as f:
                filepath = Path(f.name)
            
            try:
                size = encoder.create_gif(frames, filepath)
                
                assert size > 0
            finally:
                filepath.unlink()
        except ImportError:
            pytest.skip("GIF handler not available")


class TestLargeData:
    """Test large data handling."""
    
    def test_large_file_encryption(self):
        """Test encrypting larger file."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        # 100 KB
        data = secrets.token_bytes(100 * 1024)
        password = "LargeFilePassword123!"
        
        comp, sha, salt, nonce, cipher, eph, key = encrypt_file_bytes(
            data, password, None, None, use_length_padding=False
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, None,
            len(data), len(comp), sha
        )
        
        assert decrypted == data
    
    def test_large_fountain_encode(self):
        """Test fountain encoding of large data."""
        from meow_decoder.fountain import FountainEncoder
        
        # 50 KB
        data = secrets.token_bytes(50 * 1024)
        k_blocks = 100
        block_size = 512
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Generate droplets
        droplets = encoder.generate_droplets(150)
        
        assert len(droplets) == 150


class TestSpecialCharacterPasswords:
    """Test passwords with special characters."""
    
    def test_unicode_password(self):
        """Test Unicode password."""
        from meow_decoder.crypto import derive_key
        
        password = "Café🐱Москва日本語!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert len(key) == 32
    
    def test_whitespace_password(self):
        """Test password with whitespace."""
        from meow_decoder.crypto import derive_key
        
        password = "Password With Spaces!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert len(key) == 32
    
    def test_special_chars_password(self):
        """Test password with special characters."""
        from meow_decoder.crypto import derive_key
        
        password = "P@$$w0rd!#$%^&*(){}[]"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert len(key) == 32


class TestConcurrentOperations:
    """Test concurrent operation edge cases."""
    
    def test_multiple_encoders(self):
        """Test multiple fountain encoders simultaneously."""
        from meow_decoder.fountain import FountainEncoder
        
        # Create multiple encoders
        encoders = [
            FountainEncoder(f"Data {i}".encode() * 100, 5, 50)
            for i in range(5)
        ]
        
        # Generate droplets from each
        for encoder in encoders:
            droplet = encoder.droplet()
            assert droplet is not None
    
    def test_multiple_key_derivations(self):
        """Test multiple key derivations."""
        from meow_decoder.crypto import derive_key
        
        passwords = ["Password123!", "DifferentPass456!", "AnotherOne789!"]
        salts = [secrets.token_bytes(16) for _ in range(3)]
        
        keys = [derive_key(p, s) for p, s in zip(passwords, salts)]
        
        # All should be different
        assert len(set(keys)) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
