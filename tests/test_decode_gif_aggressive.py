#!/usr/bin/env python3
"""
🐱 AGGRESSIVE Coverage Tests for decode_gif.py
Target: Boost decode_gif.py from 25% to 80%+
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

os.environ['MEOW_TEST_MODE'] = '1'
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestDecodeGifMainFunction:
    """Test the main() function in decode_gif.py."""
    
    def test_main_help(self):
        """Test main with --help."""
        from meow_decoder import decode_gif
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                decode_gif.main()
            assert exc_info.value.code == 0
    
    def test_main_about(self):
        """Test main with --about."""
        from meow_decoder import decode_gif
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--about']):
            with pytest.raises(SystemExit) as exc_info:
                decode_gif.main()
            assert exc_info.value.code == 0
    
    def test_main_hardware_status(self):
        """Test main with --hardware-status."""
        from meow_decoder import decode_gif
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--hardware-status']):
            with pytest.raises(SystemExit) as exc_info:
                decode_gif.main()
            assert exc_info.value.code == 0


class TestDecodeGifCLIArgs:
    """Test CLI argument parsing."""
    
    def test_missing_input_output(self):
        """Test error when input/output missing."""
        from meow_decoder import decode_gif
        
        with patch.object(sys, 'argv', ['meow-decode-gif']):
            with pytest.raises(SystemExit) as exc_info:
                decode_gif.main()
            assert exc_info.value.code != 0
    
    def test_input_not_exists(self):
        """Test error when input file doesn't exist."""
        from meow_decoder import decode_gif
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(sys, 'argv', [
                'meow-decode-gif',
                '-i', '/nonexistent/file.gif',
                '-o', f'{tmpdir}/out.txt',
                '-p', 'password'
            ]):
                with pytest.raises(SystemExit) as exc_info:
                    decode_gif.main()
                assert exc_info.value.code != 0
    
    def test_empty_password(self):
        """Test error on empty password."""
        from meow_decoder import decode_gif
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.gif"
            input_path.write_bytes(b"GIF89a")  # Minimal GIF header
            
            with patch.object(sys, 'argv', [
                'meow-decode-gif',
                '-i', str(input_path),
                '-o', f'{tmpdir}/out.txt',
                '-p', ''
            ]):
                with pytest.raises(SystemExit) as exc_info:
                    decode_gif.main()
                assert exc_info.value.code != 0
    
    def test_output_exists_no_force(self):
        """Test error when output exists without --force."""
        from meow_decoder import decode_gif
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.gif"
            input_path.write_bytes(b"GIF89a")
            
            output_path = Path(tmpdir) / "output.txt"
            output_path.write_text("existing")
            
            with patch.object(sys, 'argv', [
                'meow-decode-gif',
                '-i', str(input_path),
                '-o', str(output_path),
                '-p', 'password123'
            ]):
                with pytest.raises(SystemExit) as exc_info:
                    decode_gif.main()
                assert exc_info.value.code != 0


class TestDecodeGifRoundtrip:
    """Test encode -> decode roundtrip."""
    
    def test_basic_roundtrip(self):
        """Test basic encode and decode roundtrip."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and encode
            input_path = Path(tmpdir) / "original.txt"
            input_path.write_text("Hello, World! This is a test message.")
            
            gif_path = Path(tmpdir) / "encoded.gif"
            
            config = EncodingConfig(block_size=128, redundancy=2.0)
            encode_file(input_path, gif_path, "password123", config=config)
            
            # Decode
            output_path = Path(tmpdir) / "decoded.txt"
            stats = decode_gif(gif_path, output_path, "password123")
            
            assert output_path.exists()
            assert output_path.read_text() == input_path.read_text()
    
    def test_roundtrip_with_keyfile(self):
        """Test roundtrip with keyfile."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create keyfile
            keyfile_path = Path(tmpdir) / "keyfile.bin"
            keyfile_bytes = os.urandom(64)
            keyfile_path.write_bytes(keyfile_bytes)
            
            # Create and encode
            input_path = Path(tmpdir) / "original.txt"
            input_path.write_text("Secret data with keyfile")
            
            gif_path = Path(tmpdir) / "encoded.gif"
            
            config = EncodingConfig(block_size=128, redundancy=2.0)
            encode_file(input_path, gif_path, "password123", config=config, keyfile=keyfile_bytes)
            
            # Decode
            output_path = Path(tmpdir) / "decoded.txt"
            stats = decode_gif(gif_path, output_path, "password123", keyfile=keyfile_bytes)
            
            assert output_path.exists()
            assert output_path.read_text() == input_path.read_text()
    
    def test_roundtrip_wrong_password_fails(self):
        """Test that wrong password fails."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and encode
            input_path = Path(tmpdir) / "original.txt"
            input_path.write_text("Secret message")
            
            gif_path = Path(tmpdir) / "encoded.gif"
            
            config = EncodingConfig(block_size=128, redundancy=2.0)
            encode_file(input_path, gif_path, "correct_password", config=config)
            
            # Decode with wrong password
            output_path = Path(tmpdir) / "decoded.txt"
            
            with pytest.raises(Exception):
                decode_gif(gif_path, output_path, "wrong_password")
    
    def test_roundtrip_with_forward_secrecy(self):
        """Test roundtrip with forward secrecy keys."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate receiver keypair
            priv_key, pub_key = generate_receiver_keypair()
            
            # Create and encode
            input_path = Path(tmpdir) / "original.txt"
            input_path.write_text("Forward secrecy test")
            
            gif_path = Path(tmpdir) / "encoded.gif"
            
            config = EncodingConfig(block_size=128, redundancy=2.0)
            encode_file(
                input_path, gif_path, "password123",
                config=config,
                forward_secrecy=True,
                receiver_public_key=pub_key
            )
            
            # Decode with receiver private key
            output_path = Path(tmpdir) / "decoded.txt"
            stats = decode_gif(
                gif_path, output_path, "password123",
                receiver_private_key=priv_key
            )
            
            assert output_path.exists()
            assert output_path.read_text() == input_path.read_text()


class TestDecodeGifVerbose:
    """Test verbose output."""
    
    def test_decode_verbose(self):
        """Test decoding with verbose output."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "original.txt"
            input_path.write_text("Test data")
            
            gif_path = Path(tmpdir) / "encoded.gif"
            
            config = EncodingConfig(block_size=128, redundancy=2.0)
            encode_file(input_path, gif_path, "password123", config=config)
            
            output_path = Path(tmpdir) / "decoded.txt"
            stats = decode_gif(gif_path, output_path, "password123", verbose=True)
            
            assert output_path.exists()


class TestDecodeGifDuressMode:
    """Test duress mode in decode."""
    
    def test_duress_config_decoy_mode(self):
        """Test DuressConfig in decoy mode."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.DECOY,
            decoy_message="Nothing to see here"
        )
        
        assert config.enabled
        assert config.mode == DuressMode.DECOY
    
    def test_duress_config_panic_mode(self):
        """Test DuressConfig in panic mode."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.PANIC,
            panic_enabled=True
        )
        
        assert config.enabled
        assert config.mode == DuressMode.PANIC
        assert config.panic_enabled


class TestDecodeGifManifestParsing:
    """Test manifest parsing paths."""
    
    def test_unpack_manifest_password_only(self):
        """Test unpacking password-only manifest."""
        from meow_decoder.crypto import unpack_manifest, pack_manifest, Manifest
        
        manifest = Manifest(
            salt=os.urandom(16),
            nonce=os.urandom(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=820,
            sha256=os.urandom(32),
            block_size=512,
            k_blocks=10,
            hmac=os.urandom(32),
            ephemeral_public_key=None,
            pq_ciphertext=None,
            duress_tag=None
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.ephemeral_public_key is None
    
    def test_unpack_manifest_forward_secrecy(self):
        """Test unpacking forward secrecy manifest."""
        from meow_decoder.crypto import unpack_manifest, pack_manifest, Manifest
        
        manifest = Manifest(
            salt=os.urandom(16),
            nonce=os.urandom(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=820,
            sha256=os.urandom(32),
            block_size=512,
            k_blocks=10,
            hmac=os.urandom(32),
            ephemeral_public_key=os.urandom(32),  # FS enabled
            pq_ciphertext=None,
            duress_tag=None
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.ephemeral_public_key is not None
        assert len(unpacked.ephemeral_public_key) == 32
    
    def test_unpack_manifest_with_duress(self):
        """Test unpacking manifest with duress tag."""
        from meow_decoder.crypto import unpack_manifest, pack_manifest, Manifest
        
        manifest = Manifest(
            salt=os.urandom(16),
            nonce=os.urandom(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=820,
            sha256=os.urandom(32),
            block_size=512,
            k_blocks=10,
            hmac=os.urandom(32),
            ephemeral_public_key=os.urandom(32),
            pq_ciphertext=None,
            duress_tag=os.urandom(32)  # Duress enabled
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.duress_tag is not None
        assert len(unpacked.duress_tag) == 32


class TestDecodeGifErrorHandling:
    """Test error handling in decode."""
    
    def test_invalid_gif_data(self):
        """Test handling of invalid GIF data."""
        from meow_decoder.decode_gif import decode_gif
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create invalid GIF
            bad_gif = Path(tmpdir) / "bad.gif"
            bad_gif.write_bytes(b"not a gif")
            
            output_path = Path(tmpdir) / "output.txt"
            
            with pytest.raises(Exception):
                decode_gif(bad_gif, output_path, "password123")
    
    def test_empty_gif(self):
        """Test handling of empty GIF."""
        from meow_decoder.decode_gif import decode_gif
        
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_gif = Path(tmpdir) / "empty.gif"
            empty_gif.write_bytes(b"")
            
            output_path = Path(tmpdir) / "output.txt"
            
            with pytest.raises(Exception):
                decode_gif(empty_gif, output_path, "password123")


class TestDecodeGifNineLivesMode:
    """Test nine lives retry mode in decode."""
    
    def test_nine_lives_cli_flag(self):
        """Test --nine-lives CLI flag."""
        from meow_decoder import decode_gif as decode_module
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--nine-lives', '--about']):
            with pytest.raises(SystemExit):
                decode_module.main()


class TestDecodeGifPurrMode:
    """Test purr mode in decode."""
    
    def test_purr_mode_cli_flag(self):
        """Test --purr-mode CLI flag."""
        from meow_decoder import decode_gif as decode_module
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--purr-mode', '--about']):
            with pytest.raises(SystemExit):
                decode_module.main()


class TestDecodeGifAggressivePreprocessing:
    """Test aggressive preprocessing mode."""
    
    def test_aggressive_cli_flag(self):
        """Test --aggressive CLI flag."""
        from meow_decoder import decode_gif as decode_module
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--aggressive', '--about']):
            with pytest.raises(SystemExit):
                decode_module.main()


class TestDecodeGifDecodingConfig:
    """Test DecodingConfig options."""
    
    def test_decoding_config_defaults(self):
        """Test DecodingConfig default values."""
        from meow_decoder.config import DecodingConfig
        
        config = DecodingConfig()
        
        assert config.webcam_device == 0
        assert config.frame_skip == 0
        assert config.preprocessing == "normal"
        assert config.enable_resume == True
    
    def test_decoding_config_aggressive(self):
        """Test DecodingConfig with aggressive preprocessing."""
        from meow_decoder.config import DecodingConfig
        
        config = DecodingConfig(preprocessing="aggressive")
        
        assert config.preprocessing == "aggressive"


class TestDecodeGifFrameMAC:
    """Test frame MAC verification paths."""
    
    def test_frame_mac_valid(self):
        """Test valid frame MAC verification."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"test frame data"
        master_key = os.urandom(32)
        salt = os.urandom(16)
        frame_index = 1
        
        packed = pack_frame_with_mac(data, master_key, frame_index, salt)
        is_valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index, salt)
        
        assert is_valid
        assert unpacked == data
    
    def test_frame_mac_invalid(self):
        """Test invalid frame MAC detection."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"test frame data"
        master_key = os.urandom(32)
        wrong_key = os.urandom(32)
        salt = os.urandom(16)
        frame_index = 1
        
        packed = pack_frame_with_mac(data, master_key, frame_index, salt)
        is_valid, unpacked = unpack_frame_with_mac(packed, wrong_key, frame_index, salt)
        
        assert not is_valid


class TestDecodeGifHardwareMode:
    """Test hardware security mode paths."""
    
    def test_hsm_slot_cli_option(self):
        """Test --hsm-slot CLI option."""
        from meow_decoder import decode_gif as decode_module
        
        # Just verify parsing works
        with patch.object(sys, 'argv', ['meow-decode-gif', '--hsm-slot', '0', '--about']):
            with pytest.raises(SystemExit):
                decode_module.main()
    
    def test_tpm_derive_cli_option(self):
        """Test --tpm-derive CLI option."""
        from meow_decoder import decode_gif as decode_module
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--tpm-derive', '--about']):
            with pytest.raises(SystemExit):
                decode_module.main()
    
    def test_hardware_auto_cli_option(self):
        """Test --hardware-auto CLI option."""
        from meow_decoder import decode_gif as decode_module
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--hardware-auto', '--about']):
            with pytest.raises(SystemExit):
                decode_module.main()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
