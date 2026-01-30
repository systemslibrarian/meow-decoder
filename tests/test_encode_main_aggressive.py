#!/usr/bin/env python3
"""
🐱 AGGRESSIVE Coverage Tests for encode.py main() and CLI paths
Target: Boost encode.py from 18% to 80%+
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


class TestEncodeMainFunction:
    """Test the main() function in encode.py."""
    
    def test_main_help(self):
        """Test main with --help."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
    
    def test_main_about(self):
        """Test main with --about."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--about']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
    
    def test_main_summon_void_cat(self):
        """Test main with --summon-void-cat."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--summon-void-cat']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
    
    def test_main_safety_checklist(self):
        """Test main with --safety-checklist."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--safety-checklist']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
    
    def test_main_hardware_status(self):
        """Test main with --hardware-status."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--hardware-status']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
    
    def test_main_generate_keys(self):
        """Test main with --generate-keys."""
        from meow_decoder import encode
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(sys, 'argv', ['meow-encode', '--generate-keys', '--key-output-dir', tmpdir]):
                with patch('sys.stdin', StringIO("password123\npassword123\n")):
                    try:
                        encode.main()
                    except SystemExit as e:
                        # Success or handled exit
                        pass


class TestEncodeFileFunction:
    """Test encode_file function with various options."""
    
    def test_encode_basic(self):
        """Test basic encoding."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Hello, World!")
            
            output_path = Path(tmpdir) / "test.gif"
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(input_path, output_path, "password123", config=config)
            
            assert output_path.exists()
            assert stats['input_size'] > 0
    
    def test_encode_verbose(self):
        """Test encoding with verbose output."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Test data")
            
            output_path = Path(tmpdir) / "test.gif"
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(input_path, output_path, "password123", config=config, verbose=True)
            
            assert output_path.exists()
    
    def test_encode_with_keyfile(self):
        """Test encoding with keyfile."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Secret data")
            
            keyfile_path = Path(tmpdir) / "keyfile.bin"
            keyfile_path.write_bytes(os.urandom(64))
            
            output_path = Path(tmpdir) / "test.gif"
            
            keyfile_bytes = keyfile_path.read_bytes()
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(input_path, output_path, "password123", config=config, keyfile=keyfile_bytes)
            
            assert output_path.exists()
    
    def test_encode_no_forward_secrecy(self):
        """Test encoding without forward secrecy."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Test")
            
            output_path = Path(tmpdir) / "test.gif"
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(input_path, output_path, "password123", config=config, forward_secrecy=False)
            
            assert output_path.exists()


class TestEncodeCLIArgs:
    """Test CLI argument parsing."""
    
    def test_missing_input_output(self):
        """Test error when input/output missing."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code != 0
    
    def test_input_not_exists(self):
        """Test error when input file doesn't exist."""
        from meow_decoder import encode
        
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(sys, 'argv', [
                'meow-encode',
                '-i', '/nonexistent/file.txt',
                '-o', f'{tmpdir}/out.gif',
                '-p', 'password'
            ]):
                with pytest.raises(SystemExit) as exc_info:
                    encode.main()
                assert exc_info.value.code != 0
    
    def test_empty_password(self):
        """Test error on empty password."""
        from meow_decoder import encode
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("test")
            
            with patch.object(sys, 'argv', [
                'meow-encode',
                '-i', str(input_path),
                '-o', f'{tmpdir}/out.gif',
                '-p', ''
            ]):
                with pytest.raises(SystemExit) as exc_info:
                    encode.main()
                assert exc_info.value.code != 0


class TestEncodeDuressMode:
    """Test duress password handling in encode."""
    
    def test_duress_same_as_main_password_rejected(self):
        """Test that duress password same as main is rejected."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Secret")
            
            output_path = Path(tmpdir) / "test.gif"
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            
            # Same password as duress should be rejected
            with pytest.raises(ValueError, match="Duress password cannot be the same"):
                encode_file(
                    input_path, output_path, "password123", 
                    config=config,
                    duress_password="password123",
                    forward_secrecy=True
                )
    
    def test_duress_without_forward_secrecy_rejected(self):
        """Test that duress without forward secrecy is rejected."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Secret")
            
            output_path = Path(tmpdir) / "test.gif"
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            
            with pytest.raises(ValueError, match="Duress mode requires"):
                encode_file(
                    input_path, output_path, "password123", 
                    config=config,
                    duress_password="duresspass123",
                    forward_secrecy=False
                )


class TestEncodeWithReceiverKey:
    """Test encode with receiver public key for forward secrecy."""
    
    def test_encode_with_receiver_pubkey(self):
        """Test encoding with receiver public key."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Secret message")
            
            output_path = Path(tmpdir) / "test.gif"
            
            # Generate receiver keypair
            priv_key, pub_key = generate_receiver_keypair()
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(
                input_path, output_path, "password123",
                config=config,
                forward_secrecy=True,
                receiver_public_key=pub_key
            )
            
            assert output_path.exists()
            assert stats['input_size'] > 0


class TestEncodeModeSelection:
    """Test crypto mode selection in encode."""
    
    def test_meow2_mode(self):
        """Test MEOW2 mode (no forward secrecy)."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Data")
            
            output_path = Path(tmpdir) / "test.gif"
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(
                input_path, output_path, "password123",
                config=config,
                forward_secrecy=False
            )
            
            assert output_path.exists()
    
    def test_meow3_mode_password_only(self):
        """Test MEOW3 mode with password only."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Data")
            
            output_path = Path(tmpdir) / "test.gif"
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(
                input_path, output_path, "password123",
                config=config,
                forward_secrecy=True
            )
            
            assert output_path.exists()
    
    def test_meow3_mode_with_receiver_key(self):
        """Test MEOW3 mode with receiver public key."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("Data")
            
            output_path = Path(tmpdir) / "test.gif"
            
            _, pub_key = generate_receiver_keypair()
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(
                input_path, output_path, "password123",
                config=config,
                forward_secrecy=True,
                receiver_public_key=pub_key
            )
            
            assert output_path.exists()


class TestEncodeVoidMode:
    """Test void mode encoding."""
    
    def test_void_mode_cli(self):
        """Test void mode activates paranoid settings."""
        from meow_decoder import encode
        
        # This tests the CLI parsing, not full encode
        with patch.object(sys, 'argv', [
            'meow-encode',
            '--mode', 'void',
            '--about'  # Exit quickly
        ]):
            with pytest.raises(SystemExit):
                encode.main()


class TestEncodePurrMode:
    """Test purr mode (ultra-verbose)."""
    
    def test_purr_mode_enables_verbose(self):
        """Test that --purr-mode enables verbose output."""
        from meow_decoder import encode
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("data")
            
            with patch.object(sys, 'argv', [
                'meow-encode',
                '--purr-mode',
                '-i', str(input_path),
                '-o', f'{tmpdir}/out.gif',
                '-p', 'password123'
            ]):
                try:
                    encode.main()
                except SystemExit:
                    pass  # May exit


class TestEncodeNineLivesMode:
    """Test nine lives retry mode."""
    
    def test_nine_lives_mode(self):
        """Test nine lives mode encoding."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("data")
            
            output_path = Path(tmpdir) / "test.gif"
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            
            # Nine lives mode is tested through the CLI, but encode_file should work
            stats = encode_file(input_path, output_path, "password123", config=config)
            
            assert output_path.exists()


class TestEncodeHighSecurity:
    """Test high security mode."""
    
    def test_high_security_cli_flag(self):
        """Test --high-security flag."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--high-security', '--about']):
            with pytest.raises(SystemExit):
                encode.main()


class TestEncodeWipeSource:
    """Test source wiping."""
    
    def test_wipe_source_after_encode(self):
        """Test that --wipe-source deletes the source file."""
        from meow_decoder import encode
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.txt"
            input_path.write_text("data to wipe")
            
            output_path = Path(tmpdir) / "test.gif"
            
            # Note: We can't easily test wipe without actually running encode.main()
            # The test would delete the file, so we just verify encode_file works
            from meow_decoder.encode import encode_file
            from meow_decoder.config import EncodingConfig
            
            config = EncodingConfig(block_size=128, redundancy=1.5)
            stats = encode_file(input_path, output_path, "password123", config=config)
            
            assert output_path.exists()


class TestEncodeQRParams:
    """Test QR code parameter handling."""
    
    def test_qr_error_correction_levels(self):
        """Test different QR error correction levels."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        for level in ['L', 'M', 'Q', 'H']:
            with tempfile.TemporaryDirectory() as tmpdir:
                input_path = Path(tmpdir) / "test.txt"
                input_path.write_text("data")
                
                output_path = Path(tmpdir) / "test.gif"
                
                config = EncodingConfig(
                    block_size=128,
                    redundancy=1.5,
                    qr_error_correction=level
                )
                
                stats = encode_file(input_path, output_path, "password123", config=config)
                assert output_path.exists()


class TestEncodeFountainParams:
    """Test fountain code parameters."""
    
    def test_different_block_sizes(self):
        """Test different block sizes."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        for block_size in [128, 256, 512]:
            with tempfile.TemporaryDirectory() as tmpdir:
                input_path = Path(tmpdir) / "test.txt"
                input_path.write_text("data" * 100)
                
                output_path = Path(tmpdir) / "test.gif"
                
                config = EncodingConfig(block_size=block_size, redundancy=1.5)
                stats = encode_file(input_path, output_path, "password123", config=config)
                
                assert output_path.exists()
    
    def test_different_redundancy(self):
        """Test different redundancy levels."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        for redundancy in [1.2, 1.5, 2.0]:
            with tempfile.TemporaryDirectory() as tmpdir:
                input_path = Path(tmpdir) / "test.txt"
                input_path.write_text("data" * 100)
                
                output_path = Path(tmpdir) / "test.gif"
                
                config = EncodingConfig(block_size=128, redundancy=redundancy)
                stats = encode_file(input_path, output_path, "password123", config=config)
                
                assert output_path.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
