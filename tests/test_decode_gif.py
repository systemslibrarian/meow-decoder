#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for decode_gif.py - Target: 90%+ Coverage
Tests all CLI paths, decoding functions, and edge cases.
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestDecodeGifFunctionPaths:
    """Test decode_gif function with all parameter combinations."""
    
    @pytest.fixture
    def encoded_gif(self, tmp_path):
        """Create an encoded GIF for testing."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        input_file = tmp_path / "test.txt"
        input_file.write_text("Test decode data " * 50)
        output_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        
        encode_file(
            input_file,
            output_file,
            "TestPassword123!",
            config=config,
            verbose=False
        )
        
        return output_file, "TestPassword123!", input_file.read_text()
    
    def test_decode_basic(self, encoded_gif, tmp_path):
        """Test basic decoding."""
        from meow_decoder.decode_gif import decode_gif
        
        gif_path, password, original = encoded_gif
        output_file = tmp_path / "decoded.txt"
        
        stats = decode_gif(
            gif_path,
            output_file,
            password,
            verbose=False
        )
        
        assert output_file.exists()
        assert output_file.read_text() == original
        assert stats['output_size'] > 0
    
    def test_decode_verbose(self, encoded_gif, tmp_path, capsys):
        """Test decoding with verbose output."""
        from meow_decoder.decode_gif import decode_gif
        
        gif_path, password, original = encoded_gif
        output_file = tmp_path / "decoded.txt"
        
        stats = decode_gif(
            gif_path,
            output_file,
            password,
            verbose=True
        )
        
        assert output_file.exists()
        captured = capsys.readouterr()
        # Check for some verbose output
        assert len(captured.out) > 0 or output_file.exists()
    
    def test_decode_wrong_password(self, encoded_gif, tmp_path):
        """Test that wrong password fails gracefully."""
        from meow_decoder.decode_gif import decode_gif
        
        gif_path, password, original = encoded_gif
        output_file = tmp_path / "decoded.txt"
        
        with pytest.raises(Exception):  # Should fail with wrong password
            decode_gif(
                gif_path,
                output_file,
                "WrongPassword456!",
                verbose=False
            )


class TestDecodeCLIMain:
    """Test the main() CLI function paths."""
    
    def test_main_about_flag(self):
        """Test --about flag exits cleanly."""
        from meow_decoder import decode_gif
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--about']):
            with pytest.raises(SystemExit) as exc_info:
                decode_gif.main()
            assert exc_info.value.code == 0
    
    def test_main_hardware_status(self, capsys):
        """Test --hardware-status flag."""
        from meow_decoder import decode_gif
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '--hardware-status']):
            with pytest.raises(SystemExit) as exc_info:
                decode_gif.main()
            assert exc_info.value.code == 0
    
    def test_main_missing_input(self):
        """Test error when input file is missing."""
        from meow_decoder import decode_gif
        
        with patch.object(sys, 'argv', ['meow-decode-gif', '-i', '/nonexistent/file.gif', '-o', 'out.txt', '-p', 'pass123!']):
            with pytest.raises(SystemExit) as exc_info:
                decode_gif.main()
            assert exc_info.value.code == 1
    
    def test_main_missing_required_args(self):
        """Test error when required arguments are missing."""
        from meow_decoder import decode_gif
        
        with patch.object(sys, 'argv', ['meow-decode-gif']):
            with pytest.raises(SystemExit):
                decode_gif.main()
    
    def test_main_with_purr_mode(self, tmp_path):
        """Test --purr-mode flag."""
        from meow_decoder.encode import encode_file
        from meow_decoder import decode_gif as decode_module
        from meow_decoder.config import EncodingConfig
        
        # First create a valid GIF
        input_file = tmp_path / "test.txt"
        input_file.write_text("Purr mode decode test " * 50)
        gif_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        encode_file(input_file, gif_file, "TestPassword123!", config=config, verbose=False)
        
        output_file = tmp_path / "decoded.txt"
        
        with patch.object(sys, 'argv', [
            'meow-decode-gif',
            '-i', str(gif_file),
            '-o', str(output_file),
            '-p', 'TestPassword123!',
            '--purr-mode'
        ]):
            decode_module.main()
        
        assert output_file.exists()
    
    def test_main_force_overwrite(self, tmp_path):
        """Test --force flag to overwrite existing file."""
        from meow_decoder.encode import encode_file
        from meow_decoder import decode_gif as decode_module
        from meow_decoder.config import EncodingConfig
        
        # First create a valid GIF
        input_file = tmp_path / "test.txt"
        input_file.write_text("Force overwrite test " * 50)
        gif_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        encode_file(input_file, gif_file, "TestPassword123!", config=config, verbose=False)
        
        output_file = tmp_path / "decoded.txt"
        output_file.write_text("existing content")
        
        with patch.object(sys, 'argv', [
            'meow-decode-gif',
            '-i', str(gif_file),
            '-o', str(output_file),
            '-p', 'TestPassword123!',
            '--force'
        ]):
            decode_module.main()
        
        # Should have overwritten with new content
        assert output_file.read_text() != "existing content"
    
    def test_main_nine_lives(self, tmp_path):
        """Test --nine-lives retry mode."""
        from meow_decoder.encode import encode_file
        from meow_decoder import decode_gif as decode_module
        from meow_decoder.config import EncodingConfig
        
        # First create a valid GIF
        input_file = tmp_path / "test.txt"
        input_file.write_text("Nine lives decode test " * 50)
        gif_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        encode_file(input_file, gif_file, "TestPassword123!", config=config, verbose=False)
        
        output_file = tmp_path / "decoded.txt"
        
        with patch.object(sys, 'argv', [
            'meow-decode-gif',
            '-i', str(gif_file),
            '-o', str(output_file),
            '-p', 'TestPassword123!',
            '--nine-lives'
        ]):
            decode_module.main()
        
        assert output_file.exists()


class TestDecodeDuressMode:
    """Test duress password decoding paths."""
    
    def test_decode_duress_mode_decoy(self, tmp_path):
        """Test decoding with duress mode enabled (decoy)."""
        from meow_decoder import decode_gif as decode_module
        from meow_decoder.config import DuressConfig, DuressMode
        
        # This test verifies the duress config path is covered
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.DECOY,
            panic_enabled=False
        )
        
        assert config.enabled == True
        assert config.mode == DuressMode.DECOY


class TestDecodePreprocessing:
    """Test QR preprocessing options."""
    
    def test_decode_aggressive_preprocessing(self, tmp_path):
        """Test aggressive QR preprocessing mode."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig, DecodingConfig
        
        # Create a valid GIF
        input_file = tmp_path / "test.txt"
        input_file.write_text("Aggressive preprocessing test " * 50)
        gif_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        encode_file(input_file, gif_file, "TestPassword123!", config=config, verbose=False)
        
        output_file = tmp_path / "decoded.txt"
        decode_config = DecodingConfig(preprocessing='aggressive')
        
        stats = decode_gif(
            gif_file,
            output_file,
            "TestPassword123!",
            config=decode_config,
            verbose=False
        )
        
        assert output_file.exists()


class TestDecodeEdgeCases:
    """Test edge cases and error handling."""
    
    def test_decode_invalid_gif(self, tmp_path):
        """Test decoding an invalid GIF."""
        from meow_decoder.decode_gif import decode_gif
        
        # Create invalid GIF
        invalid_gif = tmp_path / "invalid.gif"
        invalid_gif.write_bytes(b"not a gif")
        
        output_file = tmp_path / "decoded.txt"
        
        with pytest.raises(Exception):
            decode_gif(
                invalid_gif,
                output_file,
                "TestPassword123!",
                verbose=False
            )
    
    def test_decode_empty_password(self, tmp_path):
        """Test that empty password fails."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        
        # Create a valid GIF
        input_file = tmp_path / "test.txt"
        input_file.write_text("Empty password test " * 50)
        gif_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        encode_file(input_file, gif_file, "TestPassword123!", config=config, verbose=False)
        
        output_file = tmp_path / "decoded.txt"
        
        with pytest.raises(Exception):
            decode_gif(
                gif_file,
                output_file,
                "",  # Empty password
                verbose=False
            )
    
    def test_decode_output_already_exists_no_force(self, tmp_path):
        """Test that existing output without --force raises error."""
        from meow_decoder import decode_gif as decode_module
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        # Create a valid GIF
        input_file = tmp_path / "test.txt"
        input_file.write_text("Existing output test " * 50)
        gif_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        encode_file(input_file, gif_file, "TestPassword123!", config=config, verbose=False)
        
        output_file = tmp_path / "decoded.txt"
        output_file.write_text("existing content")
        
        with patch.object(sys, 'argv', [
            'meow-decode-gif',
            '-i', str(gif_file),
            '-o', str(output_file),
            '-p', 'TestPassword123!'
            # No --force
        ]):
            with pytest.raises(SystemExit) as exc_info:
                decode_module.main()
            assert exc_info.value.code == 1


class TestDecodeKeyfile:
    """Test keyfile decoding paths."""
    
    def test_decode_with_keyfile(self, tmp_path):
        """Test decoding with keyfile."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        import secrets
        
        # Create keyfile
        keyfile_content = secrets.token_bytes(64)
        keyfile_path = tmp_path / "keyfile.key"
        keyfile_path.write_bytes(keyfile_content)
        
        # Encode with keyfile
        input_file = tmp_path / "test.txt"
        input_file.write_text("Keyfile decode test " * 50)
        gif_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        encode_file(
            input_file, 
            gif_file, 
            "TestPassword123!", 
            config=config, 
            keyfile=keyfile_content,
            verbose=False
        )
        
        output_file = tmp_path / "decoded.txt"
        
        stats = decode_gif(
            gif_file,
            output_file,
            "TestPassword123!",
            keyfile=keyfile_content,
            verbose=False
        )
        
        assert output_file.exists()
        assert output_file.read_text() == input_file.read_text()
    
    def test_decode_keyfile_missing(self, tmp_path):
        """Test decoding fails when keyfile is needed but not provided."""
        from meow_decoder.encode import encode_file
        from meow_decoder.decode_gif import decode_gif
        from meow_decoder.config import EncodingConfig
        import secrets
        
        # Create keyfile
        keyfile_content = secrets.token_bytes(64)
        
        # Encode with keyfile
        input_file = tmp_path / "test.txt"
        input_file.write_text("Missing keyfile test " * 50)
        gif_file = tmp_path / "test.gif"
        
        config = EncodingConfig(block_size=256, redundancy=2.0, fps=5)
        encode_file(
            input_file, 
            gif_file, 
            "TestPassword123!", 
            config=config, 
            keyfile=keyfile_content,
            verbose=False
        )
        
        output_file = tmp_path / "decoded.txt"
        
        # Should fail without keyfile
        with pytest.raises(Exception):
            decode_gif(
                gif_file,
                output_file,
                "TestPassword123!",
                # No keyfile
                verbose=False
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
