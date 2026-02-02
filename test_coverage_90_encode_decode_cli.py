#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for Encode/Decode CLI Paths - Target: 90%+
Tests encode.py and decode_gif.py CLI entry points and error handling.
"""

import pytest
import secrets
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import io

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestEncodeFileFunction:
    """Test encode_file function paths."""
    
    def test_basic_encode(self):
        """Test basic file encoding."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create test file
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data " * 100)
            
            output_file = tmpdir / "test.gif"
            
            config = EncodingConfig(
                block_size=256,
                redundancy=1.5,
                fps=10
            )
            
            stats = encode_file(
                input_file,
                output_file,
                "test_password_123",
                config=config,
                verbose=False
            )
            
            assert output_file.exists()
            assert stats['output_size'] > 0
    
    def test_encode_with_keyfile(self):
        """Test encoding with keyfile."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create test file
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data with keyfile")
            
            # Create keyfile
            keyfile_path = tmpdir / "keyfile.bin"
            keyfile_path.write_bytes(secrets.token_bytes(64))
            keyfile_content = keyfile_path.read_bytes()
            
            output_file = tmpdir / "test.gif"
            
            config = EncodingConfig(block_size=256, redundancy=1.5)
            
            stats = encode_file(
                input_file,
                output_file,
                "password_with_keyfile",
                config=config,
                keyfile=keyfile_content,
                verbose=False
            )
            
            assert output_file.exists()
    
    def test_encode_with_forward_secrecy(self):
        """Test encoding with forward secrecy."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create test file
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data with FS")
            
            # Generate receiver keypair
            private_key, public_key = generate_receiver_keypair()
            
            output_file = tmpdir / "test.gif"
            
            config = EncodingConfig(block_size=256, redundancy=1.5)
            
            stats = encode_file(
                input_file,
                output_file,
                "password_with_fs",
                config=config,
                forward_secrecy=True,
                receiver_public_key=public_key,
                verbose=False
            )
            
            assert output_file.exists()
            assert stats['qr_frames'] > 0
    
    def test_encode_duress_password(self):
        """Test encoding with duress password."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data with duress")
            
            # Generate receiver keypair (required for duress mode)
            private_key, public_key = generate_receiver_keypair()
            
            output_file = tmpdir / "test.gif"
            
            config = EncodingConfig(block_size=256, redundancy=1.5)
            
            stats = encode_file(
                input_file,
                output_file,
                "real_password_123",
                config=config,
                forward_secrecy=True,
                receiver_public_key=public_key,
                duress_password="panic_password",
                verbose=False
            )
            
            assert output_file.exists()
    
    def test_encode_duress_same_password_rejected(self):
        """Test that duress password same as main is rejected."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data")
            
            private_key, public_key = generate_receiver_keypair()
            
            output_file = tmpdir / "test.gif"
            
            config = EncodingConfig(block_size=256, redundancy=1.5)
            
            with pytest.raises(ValueError, match="same as encryption password"):
                encode_file(
                    input_file,
                    output_file,
                    "same_password",
                    config=config,
                    forward_secrecy=True,
                    receiver_public_key=public_key,
                    duress_password="same_password",
                    verbose=False
                )


class TestDecodeGifFunction:
    """Test decode_gif function paths."""
    
    def test_basic_decode(self):
        """Test basic GIF decoding."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create and encode test file
            original_data = b"Test data for decode " * 50
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(original_data)
            
            gif_file = tmpdir / "test.gif"
            password = "decode_test_password"
            
            config = EncodingConfig(block_size=256, redundancy=2.0)
            encode_file(input_file, gif_file, password, config=config, verbose=False)
            
            # Now decode
            output_file = tmpdir / "decoded.txt"
            
            stats = decode_gif(
                gif_file,
                output_file,
                password,
                verbose=False
            )
            
            assert output_file.exists()
            assert output_file.read_bytes() == original_data
    
    def test_decode_wrong_password(self):
        """Test decoding with wrong password fails."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Secret data")
            
            gif_file = tmpdir / "test.gif"
            
            config = EncodingConfig(block_size=256, redundancy=1.5)
            encode_file(input_file, gif_file, "correct_password", config=config, verbose=False)
            
            output_file = tmpdir / "decoded.txt"
            
            with pytest.raises(Exception):  # Should fail
                decode_gif(
                    gif_file,
                    output_file,
                    "wrong_password",
                    verbose=False
                )
    
    def test_decode_with_keyfile(self):
        """Test decoding with keyfile."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            original_data = b"Test data with keyfile decode"
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(original_data)
            
            keyfile_content = secrets.token_bytes(64)
            
            gif_file = tmpdir / "test.gif"
            password = "keyfile_decode_test"
            
            config = EncodingConfig(block_size=256, redundancy=2.0)
            encode_file(
                input_file, gif_file, password,
                config=config, keyfile=keyfile_content, verbose=False
            )
            
            output_file = tmpdir / "decoded.txt"
            
            stats = decode_gif(
                gif_file,
                output_file,
                password,
                keyfile=keyfile_content,
                verbose=False
            )
            
            assert output_file.read_bytes() == original_data


class TestEncodeMainCLI:
    """Test encode.py main() CLI entry point."""
    
    def test_main_help(self):
        """Test CLI help flag."""
        from meow_decoder.encode import main
        
        with patch('sys.argv', ['meow-encode', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
    
    def test_main_about(self):
        """Test CLI about flag."""
        from meow_decoder.encode import main
        
        with patch('sys.argv', ['meow-encode', '--about']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
    
    def test_main_generate_keys(self):
        """Test CLI key generation."""
        from meow_decoder.encode import main
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('sys.argv', ['meow-encode', '--generate-keys', '--key-output-dir', tmpdir]):
                with patch('sys.stdin', io.StringIO("password\npassword\n")):
                    try:
                        main()
                    except SystemExit as e:
                        assert e.code == 0
    
    def test_main_missing_input(self):
        """Test CLI with missing input file."""
        from meow_decoder.encode import main
        
        with patch('sys.argv', ['meow-encode', '-o', 'output.gif', '-p', 'password']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0
    
    def test_main_hardware_status(self):
        """Test CLI hardware status flag."""
        from meow_decoder.encode import main
        
        with patch('sys.argv', ['meow-encode', '--hardware-status']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            # May exit 0 or non-zero depending on hardware


class TestDecodeMainCLI:
    """Test decode_gif.py main() CLI entry point."""
    
    def test_main_help(self):
        """Test CLI help flag."""
        from meow_decoder.decode_gif import main
        
        with patch('sys.argv', ['meow-decode-gif', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
    
    def test_main_about(self):
        """Test CLI about flag."""
        from meow_decoder.decode_gif import main
        
        with patch('sys.argv', ['meow-decode-gif', '--about']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
    
    def test_main_missing_input(self):
        """Test CLI with missing input file."""
        from meow_decoder.decode_gif import main
        
        with patch('sys.argv', ['meow-decode-gif', '-o', 'output.txt', '-p', 'password']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0


class TestEncodeVerboseOutput:
    """Test encode verbose output paths."""
    
    def test_encode_verbose(self):
        """Test verbose encoding output."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data " * 100)
            
            output_file = tmpdir / "test.gif"
            
            config = EncodingConfig(block_size=256, redundancy=1.5)
            
            # Capture stdout
            with patch('sys.stdout', new_callable=io.StringIO):
                stats = encode_file(
                    input_file,
                    output_file,
                    "test_password_123",
                    config=config,
                    verbose=True
                )
            
            assert stats['qr_frames'] > 0


class TestDecodeVerboseOutput:
    """Test decode verbose output paths."""
    
    def test_decode_verbose(self):
        """Test verbose decoding output."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            original_data = b"Test data for verbose decode " * 50
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(original_data)
            
            gif_file = tmpdir / "test.gif"
            password = "verbose_decode_test"
            
            config = EncodingConfig(block_size=256, redundancy=2.0)
            encode_file(input_file, gif_file, password, config=config, verbose=False)
            
            output_file = tmpdir / "decoded.txt"
            
            # Capture stdout
            with patch('sys.stdout', new_callable=io.StringIO):
                stats = decode_gif(
                    gif_file,
                    output_file,
                    password,
                    verbose=True
                )


class TestEncodeErrorHandling:
    """Test encode error handling paths."""
    
    def test_encode_nonexistent_input(self):
        """Test encoding nonexistent input file."""
        from meow_decoder.encode import encode_file
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(FileNotFoundError):
                encode_file(
                    Path(tmpdir) / "nonexistent.txt",
                    Path(tmpdir) / "output.gif",
                    "password",
                    verbose=False
                )
    
    def test_encode_empty_password(self):
        """Test encoding with empty password."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data")
            
            output_file = tmpdir / "test.gif"
            
            with pytest.raises(ValueError):
                encode_file(
                    input_file,
                    output_file,
                    "",  # Empty password
                    verbose=False
                )


class TestDecodeErrorHandling:
    """Test decode error handling paths."""
    
    def test_decode_nonexistent_input(self):
        """Test decoding nonexistent GIF."""
        from meow_decoder.decode_gif import decode_gif
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(Exception):  # FileNotFoundError or similar
                decode_gif(
                    Path(tmpdir) / "nonexistent.gif",
                    Path(tmpdir) / "output.txt",
                    "password",
                    verbose=False
                )
    
    def test_decode_corrupted_gif(self):
        """Test decoding corrupted GIF."""
        from meow_decoder.decode_gif import decode_gif
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create fake GIF
            fake_gif = tmpdir / "fake.gif"
            fake_gif.write_bytes(b"GIF89a" + secrets.token_bytes(100))
            
            output_file = tmpdir / "output.txt"
            
            with pytest.raises(Exception):  # Should fail to decode
                decode_gif(
                    fake_gif,
                    output_file,
                    "password",
                    verbose=False
                )


class TestEncodeConfigOptions:
    """Test various encode config options."""
    
    def test_encode_high_redundancy(self):
        """Test encoding with high redundancy."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data " * 50)
            
            output_file = tmpdir / "test.gif"
            
            config = EncodingConfig(
                block_size=256,
                redundancy=3.0,  # High redundancy
                fps=5
            )
            
            stats = encode_file(
                input_file,
                output_file,
                "test_password_123",
                config=config,
                verbose=False
            )
            
            assert stats['redundancy'] == 3.0
    
    def test_encode_different_block_sizes(self):
        """Test encoding with different block sizes."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            input_file = tmpdir / "test.txt"
            input_file.write_bytes(b"Test data " * 100)
            
            for block_size in [128, 256, 512]:
                output_file = tmpdir / f"test_{block_size}.gif"
                
                config = EncodingConfig(
                    block_size=block_size,
                    redundancy=1.5
                )
                
                stats = encode_file(
                    input_file,
                    output_file,
                    "test_password_123",
                    config=config,
                    verbose=False
                )
                
                assert output_file.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
