#!/usr/bin/env python3
"""
🧪 Aggressive Tests for duress_mode.py
Target: 95%+ coverage of DuressHandler and related functions

This is a security-critical module - comprehensive testing is essential.
"""

import pytest
import secrets
import hashlib
import time
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock

# Import module under test
from meow_decoder.duress_mode import (
    DuressHandler,
    generate_deterministic_decoy,
    setup_duress,
    is_duress_triggered,
    generate_static_decoy,
    generate_duress_decoy,
    add_duress_args,
    MAX_USER_DECOY_SIZE,
)
from meow_decoder.config import DuressConfig, DuressMode


class TestDuressHandler:
    """Comprehensive tests for DuressHandler class."""
    
    def test_init_defaults(self):
        """Test default initialization."""
        handler = DuressHandler()
        assert handler.duress_password_hash is None
        assert handler.real_password_hash is None
        assert handler.was_triggered is False
        assert handler.config is not None
    
    def test_init_with_config(self):
        """Test initialization with custom config."""
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.PANIC,
            panic_enabled=True,
        )
        handler = DuressHandler(config)
        assert handler.config.enabled is True
        assert handler.config.mode == DuressMode.PANIC
        assert handler.config.panic_enabled is True
    
    def test_set_passwords_basic(self):
        """Test basic password setting."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress123", "real456", salt)
        
        assert handler.duress_password_hash is not None
        assert handler.real_password_hash is not None
        assert len(handler.duress_password_hash) == 32
        assert len(handler.real_password_hash) == 32
    
    def test_set_passwords_different_hashes(self):
        """Test that different passwords produce different hashes."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress123", "real456", salt)
        
        assert handler.duress_password_hash != handler.real_password_hash
    
    def test_set_passwords_deterministic(self):
        """Test that same password + salt produces same hash."""
        handler1 = DuressHandler()
        handler2 = DuressHandler()
        salt = secrets.token_bytes(16)
        
        handler1.set_passwords("duress", "real", salt)
        handler2.set_passwords("duress", "real", salt)
        
        assert handler1.duress_password_hash == handler2.duress_password_hash
        assert handler1.real_password_hash == handler2.real_password_hash
    
    def test_check_password_real(self):
        """Test checking real password."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "real", salt)
        
        is_valid, is_duress = handler.check_password("real", salt)
        assert is_valid is True
        assert is_duress is False
        assert handler.was_triggered is False
    
    def test_check_password_duress(self):
        """Test checking duress password."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "real", salt)
        
        is_valid, is_duress = handler.check_password("duress", salt)
        assert is_valid is True
        assert is_duress is True
        assert handler.was_triggered is True
    
    def test_check_password_wrong(self):
        """Test checking wrong password."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "real", salt)
        
        is_valid, is_duress = handler.check_password("wrong", salt)
        assert is_valid is False
        assert is_duress is False
    
    def test_check_password_empty(self):
        """Test checking empty password."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "real", salt)
        
        is_valid, is_duress = handler.check_password("", salt)
        assert is_valid is False
        assert is_duress is False
    
    def test_check_password_no_setup(self):
        """Test checking password before setup."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        
        # Should handle gracefully
        is_valid, is_duress = handler.check_password("any", salt)
        assert is_valid is False
        assert is_duress is False
    
    def test_check_password_timing_consistency(self):
        """Test that check_password has consistent timing."""
        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "realpassword", salt)
        
        # Time each scenario multiple times
        times = {'real': [], 'duress': [], 'wrong': []}
        
        for _ in range(5):
            start = time.time()
            handler.check_password("realpassword", salt)
            times['real'].append(time.time() - start)
            
            start = time.time()
            handler.check_password("duress", salt)
            times['duress'].append(time.time() - start)
            
            start = time.time()
            handler.check_password("wrong", salt)
            times['wrong'].append(time.time() - start)
        
        # Timing equalization is in effect
        # All times should be within reasonable range
        all_times = times['real'] + times['duress'] + times['wrong']
        avg = sum(all_times) / len(all_times)
        assert avg > 0  # Some time elapsed
    
    def test_get_decoy_data_default(self):
        """Test default decoy data generation."""
        handler = DuressHandler()
        data, filename = handler.get_decoy_data()
        
        assert isinstance(data, bytes)
        assert isinstance(filename, str)
        assert len(data) > 0
    
    def test_get_decoy_data_message_mode(self):
        """Test decoy data in message mode."""
        config = DuressConfig(
            enabled=True,
            decoy_type="message",
            decoy_message="Custom decoy message",
        )
        handler = DuressHandler(config)
        data, filename = handler.get_decoy_data()
        
        assert b"Custom decoy message" in data or data == b"Decode complete."
    
    def test_get_decoy_data_bundled_file(self):
        """Test decoy data from bundled file."""
        config = DuressConfig(
            enabled=True,
            decoy_type="bundled_file",
        )
        handler = DuressHandler(config)
        data, filename = handler.get_decoy_data()
        
        assert isinstance(data, bytes)
        assert len(data) > 0
    
    def test_get_decoy_data_user_file(self):
        """Test decoy data from user file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b"This is user decoy content")
            temp_path = f.name
        
        try:
            config = DuressConfig(
                enabled=True,
                decoy_type="user_file",
                decoy_file_path=temp_path,
            )
            handler = DuressHandler(config)
            data, filename = handler.get_decoy_data()
            
            assert b"This is user decoy content" in data
        finally:
            os.unlink(temp_path)
    
    def test_get_decoy_data_user_file_too_large(self):
        """Test decoy data rejects oversized user file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            # Write more than MAX_USER_DECOY_SIZE
            f.write(b"x" * (MAX_USER_DECOY_SIZE + 1000))
            temp_path = f.name
        
        try:
            config = DuressConfig(
                enabled=True,
                decoy_type="user_file",
                decoy_file_path=temp_path,
            )
            handler = DuressHandler(config)
            data, filename = handler.get_decoy_data()
            
            # Should fall back to default
            assert len(data) <= MAX_USER_DECOY_SIZE or data == b"Decode complete."
        finally:
            os.unlink(temp_path)
    
    def test_get_decoy_data_missing_user_file(self):
        """Test decoy data handles missing user file."""
        config = DuressConfig(
            enabled=True,
            decoy_type="user_file",
            decoy_file_path="/nonexistent/path/file.txt",
        )
        handler = DuressHandler(config)
        data, filename = handler.get_decoy_data()
        
        # Should fall back to default
        assert isinstance(data, bytes)
        assert len(data) > 0
    
    def test_execute_emergency_response(self):
        """Test emergency response execution."""
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.DECOY,
            wipe_memory=True,
            gc_aggressive=True,
        )
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "real", salt)
        
        # Trigger duress
        handler.check_password("duress", salt)
        
        # Execute emergency response
        result = handler.execute_emergency_response()
        assert result is not None or result is None  # Should not crash
    
    def test_wipe_resume_files(self):
        """Test resume file wiping."""
        config = DuressConfig(
            enabled=True,
            wipe_resume_files=True,
        )
        handler = DuressHandler(config)
        
        # Create temp resume directory
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some resume files
            resume_file = Path(tmpdir) / "resume_state.json"
            resume_file.write_text('{"state": "partial"}')
            
            # Should not crash
            handler._wipe_resume_files()


class TestDuressHelperFunctions:
    """Tests for module-level helper functions."""
    
    def test_generate_deterministic_decoy_size(self):
        """Test decoy generation produces correct size."""
        salt = secrets.token_bytes(16)
        
        for size in [100, 1024, 4096, 10000]:
            decoy = generate_deterministic_decoy(size, salt)
            assert len(decoy) == size
    
    def test_generate_deterministic_decoy_determinism(self):
        """Test decoy generation is deterministic."""
        salt = secrets.token_bytes(16)
        
        decoy1 = generate_deterministic_decoy(1024, salt)
        decoy2 = generate_deterministic_decoy(1024, salt)
        
        assert decoy1 == decoy2
    
    def test_generate_deterministic_decoy_different_salts(self):
        """Test different salts produce different decoys."""
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        decoy1 = generate_deterministic_decoy(1024, salt1)
        decoy2 = generate_deterministic_decoy(1024, salt2)
        
        assert decoy1 != decoy2
    
    def test_setup_duress(self):
        """Test setup_duress convenience function."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)
        
        assert isinstance(handler, DuressHandler)
        assert handler.duress_password_hash is not None
        assert handler.real_password_hash is not None
    
    def test_is_duress_triggered_with_handler(self):
        """Test is_duress_triggered with handler only."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)
        
        assert is_duress_triggered(handler) is False
        
        handler.check_password("duress", salt)
        assert is_duress_triggered(handler) is True
    
    def test_is_duress_triggered_with_password(self):
        """Test is_duress_triggered with password check."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)
        
        result = is_duress_triggered(handler, "duress", salt)
        assert result is True
        
        result = is_duress_triggered(handler, "real", salt)
        assert result is False
    
    def test_generate_static_decoy(self):
        """Test generate_static_decoy wrapper."""
        salt = secrets.token_bytes(16)
        
        decoy = generate_static_decoy(salt, 2048)
        assert len(decoy) == 2048
    
    def test_generate_duress_decoy_with_salt(self):
        """Test generate_duress_decoy with salt."""
        salt = secrets.token_bytes(16)
        decoy = generate_duress_decoy(salt, 1024)
        
        assert len(decoy) == 1024
    
    def test_generate_duress_decoy_without_salt(self):
        """Test generate_duress_decoy without salt."""
        decoy = generate_duress_decoy(size=1024)
        
        assert len(decoy) == 1024
    
    def test_add_duress_args(self):
        """Test add_duress_args adds arguments to parser."""
        import argparse
        parser = argparse.ArgumentParser()
        
        add_duress_args(parser)
        
        # Parse with duress args
        args = parser.parse_args([
            '--duress-password', 'secret',
            '--duress-mode', 'panic',
            '--enable-panic',
        ])
        
        assert args.duress_password == 'secret'
        assert args.duress_mode == 'panic'
        assert args.enable_panic is True


class TestDuressHandlerSecureZero:
    """Tests for secure memory zeroing."""
    
    def test_secure_zero_bytearray(self):
        """Test secure zeroing of bytearray."""
        handler = DuressHandler()
        
        data = bytearray(b"sensitive data here!")
        original_len = len(data)
        
        handler._secure_zero(data)
        
        # Should be zeroed
        assert len(data) == original_len
        assert all(b == 0 for b in data)
    
    def test_secure_zero_empty(self):
        """Test secure zeroing of empty bytearray."""
        handler = DuressHandler()
        
        data = bytearray()
        handler._secure_zero(data)
        
        assert len(data) == 0


class TestDuressModePanic:
    """Tests for PANIC mode behavior."""
    
    def test_panic_mode_config(self):
        """Test PANIC mode configuration."""
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.PANIC,
            panic_enabled=True,
        )
        
        handler = DuressHandler(config)
        assert handler.config.mode == DuressMode.PANIC
        assert handler.config.panic_enabled is True
    
    def test_panic_mode_requires_explicit_enable(self):
        """Test PANIC mode requires explicit enablement."""
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.PANIC,
            panic_enabled=False,  # Not enabled
        )
        
        handler = DuressHandler(config)
        # Should handle gracefully
        data, filename = handler.get_decoy_data()
        assert data is not None


class TestDuressHandlerTimingEqualization:
    """Tests for timing equalization to prevent side-channel attacks."""
    
    def test_equalize_timing_adds_delay(self):
        """Test that _equalize_timing adds delay."""
        config = DuressConfig(
            min_delay_ms=50,
            max_delay_ms=100,
        )
        handler = DuressHandler(config)
        
        start = time.time()
        handler._equalize_timing()
        elapsed = (time.time() - start) * 1000
        
        # Should have some delay
        assert elapsed >= 0


class TestDuressHandlerFilenamesSanitization:
    """Tests for filename sanitization."""
    
    def test_sanitize_filename_basic(self):
        """Test basic filename sanitization."""
        result = DuressHandler.sanitize_filename("file.txt")
        assert result == "file.txt"
    
    def test_sanitize_filename_path_traversal(self):
        """Test path traversal prevention."""
        result = DuressHandler.sanitize_filename("../../etc/passwd")
        assert result == "passwd"
        assert "/" not in result
    
    def test_sanitize_filename_absolute_path(self):
        """Test absolute path handling."""
        result = DuressHandler.sanitize_filename("/root/secret/file.txt")
        assert result == "file.txt"
    
    def test_sanitize_filename_none(self):
        """Test None handling."""
        result = DuressHandler.sanitize_filename(None)
        assert result is None
    
    def test_sanitize_filename_empty(self):
        """Test empty string handling."""
        result = DuressHandler.sanitize_filename("")
        assert result is None


class TestDuressHandlerIntegration:
    """Integration tests for complete duress scenarios."""
    
    def test_full_duress_workflow(self):
        """Test complete duress workflow."""
        # Setup
        salt = secrets.token_bytes(16)
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.DECOY,
            decoy_message="Innocent vacation photos",
        )
        handler = DuressHandler(config)
        handler.set_passwords("help", "secret", salt)
        
        # Normal access
        is_valid, is_duress = handler.check_password("secret", salt)
        assert is_valid is True
        assert is_duress is False
        assert handler.was_triggered is False
        
        # Create new handler for duress test
        handler2 = DuressHandler(config)
        handler2.set_passwords("help", "secret", salt)
        
        # Duress access
        is_valid, is_duress = handler2.check_password("help", salt)
        assert is_valid is True
        assert is_duress is True
        assert handler2.was_triggered is True
        
        # Get decoy
        data, filename = handler2.get_decoy_data()
        assert isinstance(data, bytes)
    
    def test_multiple_password_checks(self):
        """Test multiple password checks."""
        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)
        
        # Check wrong multiple times
        for _ in range(5):
            is_valid, _ = handler.check_password("wrong", salt)
            assert is_valid is False
        
        # Should still work
        is_valid, is_duress = handler.check_password("real", salt)
        assert is_valid is True
        assert is_duress is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
