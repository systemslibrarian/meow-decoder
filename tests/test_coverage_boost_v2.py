import unittest
from unittest.mock import MagicMock, patch, mock_open
import sys
import numpy as np
from PIL import Image
import os
from pathlib import Path

# Import modules to test
from meow_decoder import crypto
from meow_decoder import qr_code
from meow_decoder import config
from meow_decoder.config import MeowConfig

class TestCryptoEdgeCases(unittest.TestCase):
    
    def test_derive_key_exception(self):
        """Test derive_key raises RuntimeError on internal failure."""
        with patch('meow_decoder.crypto.get_default_backend') as mock_backend:
            mock_backend.return_value.derive_key_argon2id.side_effect = Exception("Boom")
            with self.assertRaises(RuntimeError) as cm:
                crypto.derive_key("test_password", b"salt"*4)
            self.assertIn("Key derivation failed", str(cm.exception))

    def test_encrypt_file_bytes_exception(self):
        """Test encrypt_file_bytes raises RuntimeError on failure."""
        # Force zlib failure
        with patch('zlib.compress', side_effect=Exception("Zip fail")):
            with self.assertRaises(RuntimeError) as cm:
                crypto.encrypt_file_bytes(b"data", "test_password")
            self.assertIn("Encryption failed", str(cm.exception))

    def test_decrypt_to_raw_exception(self):
        """Test decrypt_to_raw raises RuntimeError."""
        # Mock the backend to make decryption fail
        with patch('meow_decoder.crypto.get_default_backend') as mock_backend:
             mock_backend.return_value.aes_gcm_decrypt.side_effect = Exception("Decrypt fail")
             with self.assertRaises(RuntimeError) as cm:
                 crypto.decrypt_to_raw(b"cipher", "test_password", b"salt"*4, b"nonce"*3)
             self.assertIn("Decryption failed", str(cm.exception))

    def test_forward_secrecy_missing_privkey(self):
        """Test decrypt_to_raw raises ValueError if privkey missing in FS mode."""
        with self.assertRaises(RuntimeError) as cm:
            crypto.decrypt_to_raw(
                b"cipher", "pass", b"salt"*4, b"nonce"*4,
                ephemeral_public_key=b"pubkey"*8,
                receiver_private_key=None
            )
        self.assertIn("Forward secrecy mode requires receiver private key", str(cm.exception))


class TestQRCodeEdgeCases(unittest.TestCase):
    
    def test_read_image_str_data(self):
        """Test read_image handles string data from pyzbar (rare case)."""
        reader = qr_code.QRCodeReader()
        
        # Mock pyzbar decode result
        mock_obj = MagicMock()
        mock_obj.data = "base85encodedstring" 
        # But wait, logic is: if not bytes, ascii_str = obj.data
        # then base64.b85decode(ascii_str)
        # Let's assume input is valid base85 string
        
        with patch('meow_decoder.qr_code.pyzbar.decode', return_value=[mock_obj]), \
             patch('base64.b85decode', return_value=b"decoded") as mock_b85:
            
            img = Image.new('RGB', (10, 10))
            results = reader.read_image(img)
            self.assertEqual(results, [b"decoded"])
            mock_b85.assert_called_with("base85encodedstring")

    def test_preprocess_normal_grayscale(self):
        """Test _preprocess_normal with 2D (grayscale) image."""
        reader = qr_code.QRCodeReader()
        img = np.zeros((10, 10), dtype=np.uint8) # 2D array
        
        # Should NOT call cvtColor
        with patch('cv2.cvtColor') as mock_cvt:
            res = reader._preprocess_normal(img)
            mock_cvt.assert_not_called()
            self.assertEqual(res.shape, (10, 10))

    def test_webcam_init_failure(self):
        """Test WebcamQRReader raises RuntimeError if device cannot be opened."""
        with patch('cv2.VideoCapture') as mock_cap:
            mock_cap.return_value.isOpened.return_value = False
            with self.assertRaises(RuntimeError) as cm:
                qr_code.WebcamQRReader(device=99)
            self.assertIn("Failed to open webcam device 99", str(cm.exception))

class TestConfigEdgeCases(unittest.TestCase):

    def test_get_config_exists(self):
        """Test get_config loads from file if it exists."""
        with patch.object(Path, 'exists', return_value=True), \
             patch('meow_decoder.config.MeowConfig.load') as mock_load:
            
            mock_load.return_value = MeowConfig(verbose=True)
            cfg = config.get_config()
            self.assertTrue(cfg.verbose)
            mock_load.assert_called()

    def test_get_config_exists_but_fails(self):
        """Test get_config falls back to default if load fails."""
        with patch.object(Path, 'exists', return_value=True), \
             patch('meow_decoder.config.MeowConfig.load', side_effect=Exception("Load fail")):
            
            # Should print warning (we could capture stdout but mostly care about return)
            cfg = config.get_config()
            self.assertIsInstance(cfg, MeowConfig)
            # Default verbose is False
            self.assertFalse(cfg.verbose)

    def test_save_config(self):
        """Test save_config creates dir and saves."""
        with patch('pathlib.Path.mkdir') as mock_mkdir, \
             patch('meow_decoder.config.MeowConfig.save') as mock_save:
            
            cfg = MeowConfig()
            config.save_config(cfg)
            mock_mkdir.assert_called()
            mock_save.assert_called()

if __name__ == '__main__':
    unittest.main()
