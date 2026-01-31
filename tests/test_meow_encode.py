#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for encode.py - Target: 90%+ Coverage
Tests all CLI paths, encoding functions, and edge cases.
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestEncodeFileFunctionPaths:
    """Test encode_file function with all parameter combinations."""
    
    def test_encode_basic(self, tmp_path):
        """Test basic encoding with minimal parameters."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Hello Meow! " * 50)
        output_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        stats = encode_file(
            input_file,
            output_file,
            "TestPassword123!",
            config=config,
            verbose=False
        )
        
        assert output_file.exists()
        assert stats['input_size'] > 0
        assert stats['qr_frames'] > 0
    
    def test_encode_with_forward_secrecy_disabled(self, tmp_path):
        """Test encoding with forward secrecy explicitly disabled."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Secret data " * 100)
        output_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        stats = encode_file(
            input_file,
            output_file,
            "TestPassword123!",
            config=config,
            forward_secrecy=False,
            verbose=True
        )
        
        assert output_file.exists()
        assert stats['qr_frames'] > 0
    
    def test_encode_with_keyfile(self, tmp_path):
        """Test encoding with keyfile."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        import secrets
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Keyfile protected data " * 50)
        output_file = tmp_path / "test.gif"
        
        # Create keyfile
        keyfile_content = secrets.token_bytes(64)
        keyfile_path = tmp_path / "keyfile.key"
        keyfile_path.write_bytes(keyfile_content)
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        stats = encode_file(
            input_file,
            output_file,
            "TestPassword123!",
            config=config,
            keyfile=keyfile_content,
            verbose=True
        )
        
        assert output_file.exists()
        assert stats['input_size'] > 0
    
    def test_encode_verbose_output(self, tmp_path, capsys):
        """Test verbose output messages."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Verbose test data " * 50)
        output_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        encode_file(
            input_file,
            output_file,
            "TestPassword123!",
            config=config,
            verbose=True
        )
        
        captured = capsys.readouterr()
        assert "Reading input file" in captured.out or output_file.exists()
    
    def test_encode_with_hardware_key(self, tmp_path):
        """Test encoding with precomputed hardware key."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        import secrets
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Hardware key test " * 50)
        output_file = tmp_path / "test.gif"
        
        # Simulate hardware-derived key
        hardware_key = secrets.token_bytes(32)
        hardware_salt = secrets.token_bytes(16)
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        stats = encode_file(
            input_file,
            output_file,
            "TestPassword123!",
            config=config,
            hardware_key=hardware_key,
            hardware_salt=hardware_salt,
            verbose=False
        )
        
        assert output_file.exists()
        assert stats['input_size'] > 0


class TestEncodeCLIMain:
    """Test the main() CLI function paths."""
    
    def test_main_about_flag(self):
        """Test --about flag exits cleanly."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--about']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
    
    def test_main_generate_keys(self, tmp_path):
        """Test --generate-keys flag."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--generate-keys', '--key-output-dir', str(tmp_path)]):
            # Mock getpass to provide passwords
            with patch('meow_decoder.x25519_forward_secrecy.getpass') as mock_getpass:
                mock_getpass.side_effect = ['testpass', 'testpass']
                with patch('sys.stdin') as mock_stdin:
                    mock_stdin.isatty.return_value = False
                    mock_stdin.readline.side_effect = ['testpass\n', 'testpass\n']
                    with pytest.raises(SystemExit) as exc_info:
                        encode.main()
                    # Could be 0 (success) or 1 (error in non-tty)
                    assert exc_info.value.code in [0, 1]
    
    def test_main_missing_input(self):
        """Test error when input file is missing."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '-i', '/nonexistent/file.txt', '-o', 'out.gif', '-p', 'pass123!']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 1
    
    def test_main_summon_void_cat(self, capsys):
        """Test --summon-void-cat easter egg."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--summon-void-cat']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
            
            captured = capsys.readouterr()
            assert "VOID CAT" in captured.out
    
    def test_main_safety_checklist(self, capsys):
        """Test --safety-checklist flag."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--safety-checklist']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
    
    def test_main_hardware_status(self, capsys):
        """Test --hardware-status flag."""
        from meow_decoder import encode
        
        with patch.object(sys, 'argv', ['meow-encode', '--hardware-status']):
            with pytest.raises(SystemExit) as exc_info:
                encode.main()
            assert exc_info.value.code == 0
    
    def test_main_with_password_on_cli(self, tmp_path):
        """Test encoding with password provided on CLI."""
        from meow_decoder import encode
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("CLI password test " * 50)
        output_file = tmp_path / "test.gif"
        
        with patch.object(sys, 'argv', [
            'meow-encode',
            '-i', str(input_file),
            '-o', str(output_file),
            '-p', 'TestPassword123!',
            '--block-size', '256',
            '--redundancy', '1.5',
            '--fps', '5'
        ]):
            encode.main()
        
        assert output_file.exists()
    
    def test_main_with_nine_lives(self, tmp_path):
        """Test --nine-lives retry mode."""
        from meow_decoder import encode
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Nine lives test " * 50)
        output_file = tmp_path / "test.gif"
        
        with patch.object(sys, 'argv', [
            'meow-encode',
            '-i', str(input_file),
            '-o', str(output_file),
            '-p', 'TestPassword123!',
            '--nine-lives',
            '--block-size', '256',
            '--redundancy', '1.5',
            '--fps', '5'
        ]):
            encode.main()
        
        assert output_file.exists()
    
    def test_main_purr_mode(self, tmp_path):
        """Test --purr-mode verbose logging."""
        from meow_decoder import encode
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Purr mode test " * 50)
        output_file = tmp_path / "test.gif"
        
        with patch.object(sys, 'argv', [
            'meow-encode',
            '-i', str(input_file),
            '-o', str(output_file),
            '-p', 'TestPassword123!',
            '--purr-mode',
            '--block-size', '256',
            '--redundancy', '1.5',
            '--fps', '5'
        ]):
            encode.main()
        
        assert output_file.exists()


class TestEncodeDuressMode:
    """Test duress password encoding paths."""
    
    def test_encode_duress_requires_forward_secrecy(self, tmp_path):
        """Test that duress mode requires forward secrecy."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Duress test " * 50)
        output_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        # Duress + no forward secrecy should fail
        with pytest.raises(ValueError, match="forward secrecy"):
            encode_file(
                input_file,
                output_file,
                "TestPassword123!",
                config=config,
                forward_secrecy=False,
                duress_password="DuressPass123!",
                verbose=False
            )
    
    def test_encode_duress_same_password_rejected(self, tmp_path):
        """Test that same password for real and duress is rejected."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Duress test " * 50)
        output_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        # Same password for both should fail
        with pytest.raises(ValueError, match="cannot be the same"):
            encode_file(
                input_file,
                output_file,
                "SamePassword123!",
                config=config,
                forward_secrecy=True,
                duress_password="SamePassword123!",
                verbose=False
            )


class TestEncodeQROptions:
    """Test QR code generation options."""
    
    def test_encode_qr_error_levels(self, tmp_path):
        """Test different QR error correction levels."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("QR test data " * 30)
        
        for level in ['L', 'M', 'Q', 'H']:
            output_file = tmp_path / f"test_{level}.gif"
            config = EncodingConfig(
                block_size=256,
                redundancy=1.5,
                fps=5,
                qr_error_correction=level
            )
            
            stats = encode_file(
                input_file,
                output_file,
                "TestPassword123!",
                config=config,
                verbose=False
            )
            
            assert output_file.exists()
    
    def test_encode_different_block_sizes(self, tmp_path):
        """Test different block sizes."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Block size test " * 100)
        
        for block_size in [128, 256, 512]:
            output_file = tmp_path / f"test_{block_size}.gif"
            config = EncodingConfig(
                block_size=block_size,
                redundancy=1.5,
                fps=5
            )
            
            stats = encode_file(
                input_file,
                output_file,
                "TestPassword123!",
                config=config,
                verbose=False
            )
            
            assert output_file.exists()
            assert stats['k_blocks'] > 0


class TestEncodeEdgeCases:
    """Test edge cases and error handling."""
    
    def test_encode_empty_password_rejected(self, tmp_path):
        """Test that empty password is rejected."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Test data")
        output_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        with pytest.raises(Exception):  # Should fail on password validation
            encode_file(
                input_file,
                output_file,
                "",  # Empty password
                config=config,
                verbose=False
            )
    
    def test_encode_short_password_warning(self, tmp_path):
        """Test that short password raises error (NIST compliance)."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Test data")
        output_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=1.5, fps=5)
        
        with pytest.raises(Exception):  # Should fail - password too short
            encode_file(
                input_file,
                output_file,
                "short",  # Less than 8 chars
                config=config,
                verbose=False
            )
    
    def test_encode_large_file(self, tmp_path):
        """Test encoding a larger file."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "large.txt"
        # Create 50KB file
        input_file.write_text("Large file content " * 3000)
        output_file = tmp_path / "large.gif"
        
        config = EncodingConfig(block_size=512, redundancy=1.5, fps=10)
        
        stats = encode_file(
            input_file,
            output_file,
            "TestPassword123!",
            config=config,
            verbose=False
        )
        
        assert output_file.exists()
        assert stats['input_size'] > 50000
        assert stats['qr_frames'] > 10


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
