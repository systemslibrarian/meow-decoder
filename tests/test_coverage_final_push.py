#!/usr/bin/env python3
"""
Final Coverage Push Tests
Targets specific uncovered lines to reach 95%+ coverage
"""

import sys
import io
import tempfile
import ctypes
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure module is importable
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestConstantTimeEdgeCases:
    """Test edge cases in constant_time module."""
    
    def test_secure_zero_memory_empty_bytearray(self):
        """Test zeroing empty bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        buf = bytearray()
        secure_zero_memory(buf)  # Should handle gracefully
        assert len(buf) == 0
    
    def test_secure_zero_memory_ctypes_array(self):
        """Test zeroing ctypes array."""
        from meow_decoder.constant_time import secure_zero_memory
        
        # Create ctypes array
        arr = (ctypes.c_char * 10)(b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J')
        
        # Zero it
        secure_zero_memory(arr)
        
        # Check it's zeroed
        for c in arr:
            assert c == b'\x00'
    
    def test_secure_zero_memory_empty_ctypes_array(self):
        """Test zeroing empty ctypes array."""
        from meow_decoder.constant_time import secure_zero_memory
        
        arr = (ctypes.c_char * 0)()
        secure_zero_memory(arr)  # Should handle gracefully
    
    def test_secure_zero_memory_unsupported_type(self):
        """Test zeroing unsupported type."""
        from meow_decoder.constant_time import secure_zero_memory
        
        # Pass unsupported type - should skip without error
        secure_zero_memory("string")
        secure_zero_memory(12345)
        secure_zero_memory([1, 2, 3])
    
    def test_secure_zero_memory_memset_exception(self):
        """Test zeroing when memset raises exception."""
        from meow_decoder.constant_time import secure_zero_memory
        import meow_decoder.constant_time as ct
        
        buf = bytearray(b'secret')
        
        # Mock ctypes.memset to raise
        original_memset = ctypes.memset
        def raising_memset(*args, **kwargs):
            raise OSError("memset failed")
        
        with patch.object(ctypes, 'memset', raising_memset):
            secure_zero_memory(buf)
        
        # Fallback should have zeroed manually
        assert buf == bytearray(6)


class TestCryptoEdgeCases:
    """Test edge cases in crypto module."""
    
    def test_decrypt_forward_secrecy_no_private_key(self):
        """Test decryption with FS ephemeral key but no private key."""
        from meow_decoder.crypto import decrypt_to_raw
        
        # Should raise ValueError when ephemeral_public_key present but no receiver_private_key
        try:
            decrypt_to_raw(
                cipher=b'A' * 32,
                password="test",
                salt=b'B' * 16,
                nonce=b'C' * 12,
                ephemeral_public_key=b'D' * 32,  # FS key present
                receiver_private_key=None  # But no private key!
            )
            assert False, "Should have raised ValueError"
        except (ValueError, RuntimeError) as e:
            assert "private key" in str(e).lower() or "forward secrecy" in str(e).lower()
    
    def test_manifest_hmac_fs_mode_during_decoding(self):
        """Test HMAC computation in forward secrecy mode during decoding."""
        from meow_decoder.crypto import compute_manifest_hmac
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        from cryptography.hazmat.primitives import serialization
        
        # Generate receiver keypair
        recv_priv, recv_pub = generate_receiver_keypair()
        
        # Get raw private key bytes
        recv_priv_bytes = recv_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Compute HMAC without encryption_key (decoding path)
        from meow_decoder.x25519_forward_secrecy import serialize_public_key, generate_ephemeral_keypair
        
        eph = generate_ephemeral_keypair()
        eph_pub_bytes = serialize_public_key(eph.ephemeral_public)
        
        salt = b'A' * 16
        packed_no_hmac = b'test manifest data'
        
        # This should work with receiver_private_key
        hmac_result = compute_manifest_hmac(
            password="test",
            salt=salt,
            packed_no_hmac=packed_no_hmac,
            ephemeral_public_key=eph_pub_bytes,
            receiver_private_key=recv_priv_bytes
        )
        
        assert len(hmac_result) == 32


class TestDecodeGifEdgeCases:
    """Test edge cases in decode_gif module."""
    
    def test_decode_missing_input(self):
        """Test decode with non-existent input file."""
        import subprocess
        
        result = subprocess.run(
            [sys.executable, '-m', 'meow_decoder.decode_gif',
             '-i', '/nonexistent/path/file.gif',
             '-o', '/tmp/output.txt',
             '-p', 'password'],
            capture_output=True,
            text=True
        )
        
        # Should fail gracefully
        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()
    
    def test_decode_output_exists_no_force(self):
        """Test decode when output file exists without --force."""
        import subprocess
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create dummy input and output
            input_file = Path(tmpdir) / "input.gif"
            output_file = Path(tmpdir) / "output.txt"
            
            # Create files
            input_file.write_bytes(b'GIF89a')  # Minimal GIF header
            output_file.write_text("existing")
            
            result = subprocess.run(
                [sys.executable, '-m', 'meow_decoder.decode_gif',
                 '-i', str(input_file),
                 '-o', str(output_file),
                 '-p', 'password'],
                capture_output=True,
                text=True
            )
            
            # Should fail because output exists
            assert result.returncode != 0
            assert "exists" in result.stderr.lower() or "force" in result.stderr.lower()


class TestQrCodeEdgeCases:
    """Test edge cases in qr_code module."""
    
    def test_qr_reader_empty_image(self):
        """Test QR reader with blank image."""
        from meow_decoder.qr_code import QRCodeReader
        from PIL import Image
        
        reader = QRCodeReader()
        
        # Create blank white image
        blank = Image.new('RGB', (100, 100), 'white')
        result = reader.read_image(blank)
        
        # Should return empty list (no QR codes)
        assert result == [] or result is None


class TestEncodeEdgeCases:
    """Test edge cases in encode module."""
    
    def test_encode_nonexistent_file(self):
        """Test encode with non-existent input file."""
        import subprocess
        
        result = subprocess.run(
            [sys.executable, '-m', 'meow_decoder.encode',
             '-i', '/nonexistent/path/file.txt',
             '-o', '/tmp/output.gif',
             '-p', 'password'],
            capture_output=True,
            text=True
        )
        
        # Should fail gracefully
        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()
    
    def test_encode_void_cat_mode(self):
        """Test encode with void cat mode."""
        import subprocess
        
        result = subprocess.run(
            [sys.executable, '-m', 'meow_decoder.encode',
             '--summon-void-cat'],
            capture_output=True,
            text=True
        )
        
        # Should show void cat and exit
        assert "VOID CAT" in result.stdout or "void cat" in result.stdout.lower()


class TestFountainEdgeCases:
    """Test edge cases in fountain module."""
    
    def test_fountain_decoder_original_length_error(self):
        """Test decoder get_data without original_length."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=5, block_size=100)
        
        # Manually mark as complete
        decoder.blocks = [b'A' * 100] * 5
        decoder.decoded = [True] * 5
        decoder.decoded_count = 5
        
        # Should raise ValueError without original_length
        try:
            decoder.get_data()
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "original_length" in str(e)


class TestForwardSecrecyManager:
    """Test forward secrecy manager edge cases."""
    
    def test_fs_manager_cleanup(self):
        """Test ForwardSecrecyManager cleanup."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        import secrets
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True)
        
        # Derive some keys
        manager.derive_block_key(0)
        manager.derive_block_key(100)
        
        # Cleanup should not raise
        manager.cleanup()
        
        # Double cleanup should be safe
        manager.cleanup()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
