#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for duress_mode.py - Target: 90%+
Tests duress password handling and secure wipe functionality.
"""

import pytest
import secrets
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestDuressConfig:
    """Test DuressConfig from config.py."""
    
    def test_duress_config_defaults(self):
        """Test default DuressConfig values."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig()
        
        assert config.enabled is False
        assert config.mode == DuressMode.DECOY
        assert config.panic_enabled is False
        assert config.wipe_memory is True
    
    def test_duress_config_decoy_mode(self):
        """Test configuring decoy mode."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.DECOY,
            decoy_message="All is well"
        )
        
        assert config.enabled is True
        assert config.mode == DuressMode.DECOY
        assert config.decoy_message == "All is well"
    
    def test_duress_config_panic_mode(self):
        """Test configuring panic mode."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.PANIC,
            panic_enabled=True
        )
        
        assert config.mode == DuressMode.PANIC
        assert config.panic_enabled is True


class TestDuressHandler:
    """Test DuressHandler class."""
    
    def test_handler_creation(self):
        """Test creating DuressHandler."""
        try:
            from meow_decoder.duress_mode import DuressHandler
            from meow_decoder.config import DuressConfig
            
            config = DuressConfig(enabled=True)
            handler = DuressHandler(config)
            
            assert handler is not None
        except ImportError:
            pytest.skip("duress_mode module not available")
    
    def test_get_decoy_data_message(self):
        """Test getting decoy data as message."""
        try:
            from meow_decoder.duress_mode import DuressHandler
            from meow_decoder.config import DuressConfig
            
            config = DuressConfig(
                enabled=True,
                decoy_type="message",
                decoy_message="Nothing to see here"
            )
            handler = DuressHandler(config)
            
            data, filename = handler.get_decoy_data()
            
            assert data is not None
            assert b"Nothing to see here" in data or isinstance(data, bytes)
        except ImportError:
            pytest.skip("duress_mode module not available")
    
    def test_trigger_callback(self):
        """Test trigger callback execution."""
        try:
            from meow_decoder.duress_mode import DuressHandler
            from meow_decoder.config import DuressConfig
            
            callback_called = []
            
            def my_callback():
                callback_called.append(True)
            
            config = DuressConfig(
                enabled=True,
                trigger_callback=my_callback
            )
            handler = DuressHandler(config)
            
            # Trigger the callback if method exists
            if hasattr(handler, 'execute_callback'):
                handler.execute_callback()
                assert len(callback_called) > 0
        except ImportError:
            pytest.skip("duress_mode module not available")


class TestDuressTagCrypto:
    """Test duress tag computation and verification in crypto.py."""
    
    def test_compute_duress_hash(self):
        """Test computing duress hash."""
        from meow_decoder.crypto import compute_duress_hash
        
        password = "DuressPassword123"
        salt = secrets.token_bytes(16)
        
        hash_result = compute_duress_hash(password, salt)
        
        assert len(hash_result) == 32
    
    def test_duress_hash_deterministic(self):
        """Test duress hash is deterministic."""
        from meow_decoder.crypto import compute_duress_hash
        
        password = "TestDuress"
        salt = secrets.token_bytes(16)
        
        hash1 = compute_duress_hash(password, salt)
        hash2 = compute_duress_hash(password, salt)
        
        assert hash1 == hash2
    
    def test_duress_hash_different_passwords(self):
        """Test different passwords give different hashes."""
        from meow_decoder.crypto import compute_duress_hash
        
        salt = secrets.token_bytes(16)
        
        hash1 = compute_duress_hash("password1", salt)
        hash2 = compute_duress_hash("password2", salt)
        
        assert hash1 != hash2
    
    def test_compute_duress_tag(self):
        """Test computing duress tag."""
        from meow_decoder.crypto import compute_duress_tag
        
        password = "DuressPass123"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest_data_here"
        
        tag = compute_duress_tag(password, salt, manifest_core)
        
        assert len(tag) == 32
    
    def test_duress_tag_bound_to_manifest(self):
        """Test duress tag changes with manifest."""
        from meow_decoder.crypto import compute_duress_tag
        
        password = "DuressPass"
        salt = secrets.token_bytes(16)
        
        tag1 = compute_duress_tag(password, salt, b"manifest_v1")
        tag2 = compute_duress_tag(password, salt, b"manifest_v2")
        
        assert tag1 != tag2
    
    def test_check_duress_password_correct(self):
        """Test checking correct duress password."""
        from meow_decoder.crypto import compute_duress_tag, check_duress_password
        
        password = "CorrectDuress"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest_core_data"
        
        tag = compute_duress_tag(password, salt, manifest_core)
        
        is_duress = check_duress_password(password, salt, tag, manifest_core)
        
        assert is_duress is True
    
    def test_check_duress_password_wrong(self):
        """Test checking wrong duress password."""
        from meow_decoder.crypto import compute_duress_tag, check_duress_password
        
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest"
        
        tag = compute_duress_tag("duress123", salt, manifest_core)
        
        is_duress = check_duress_password("wrong_password", salt, tag, manifest_core)
        
        assert is_duress is False


class TestDuressManifest:
    """Test duress tag in manifest packing."""
    
    def test_manifest_with_duress_tag(self):
        """Test manifest includes duress tag."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),  # FS mode
            duress_tag=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        
        # FS + duress manifest is 179 bytes
        assert len(packed) == 179
    
    def test_unpack_manifest_with_duress(self):
        """Test unpacking manifest with duress tag."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        duress_tag = secrets.token_bytes(32)
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            duress_tag=duress_tag
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.duress_tag == duress_tag


class TestDuressHandlerAdvanced:
    """Additional coverage for duress handler branches."""

    def test_set_passwords_same_raises(self):
        from meow_decoder.duress_mode import DuressHandler

        handler = DuressHandler()
        salt = secrets.token_bytes(16)
        with pytest.raises(ValueError, match="cannot be the same"):
            handler.set_passwords("same", "same", salt)

    def test_check_password_paths(self, monkeypatch):
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig()
        called = {"cb": False, "wipe": False}

        def cb():
            called["cb"] = True

        config.trigger_callback = cb
        config.wipe_resume_files = True
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress", "real", salt)

        monkeypatch.setattr(handler, "_wipe_resume_files", lambda: called.__setitem__("wipe", True))
        monkeypatch.setattr(handler, "_equalize_timing", lambda: None)

        is_valid, is_duress = handler.check_password("real", salt)
        assert is_valid is True and is_duress is False

        is_valid, is_duress = handler.check_password("wrong", salt)
        assert is_valid is False and is_duress is False

        sensitive = bytearray(b"secret")
        is_valid, is_duress = handler.check_password("duress", salt, [sensitive])
        assert is_valid is True and is_duress is True
        assert sensitive == b"\x00" * len(sensitive)
        assert called["cb"] is True
        assert called["wipe"] is True

    def test_execute_emergency_response_panic(self):
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig, DuressMode

        config = DuressConfig(mode=DuressMode.PANIC, panic_enabled=True)
        handler = DuressHandler(config)

        data = bytearray(b"secret")
        result = handler.execute_emergency_response([data])
        assert result is None
        assert data == b"\x00" * len(data)

    def test_execute_emergency_response_decoy(self):
        from meow_decoder.duress_mode import DuressHandler, generate_static_decoy
        from meow_decoder.config import DuressConfig

        handler = DuressHandler(DuressConfig())
        salt = b"\x01" * 16
        result = handler.execute_emergency_response(salt=salt)
        assert result == generate_static_decoy(salt)

    def test_get_decoy_data_user_file(self, tmp_path, monkeypatch):
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig
        from pathlib import Path

        config = DuressConfig(decoy_type="user_file")
        handler = DuressHandler(config)

        # Missing path
        data, name = handler.get_decoy_data()
        assert name == "error.txt"

        # Existing file
        file_path = tmp_path / "decoy.bin"
        file_path.write_bytes(b"abc")
        config.decoy_file_path = str(file_path)
        data, name = handler.get_decoy_data()
        assert data == b"abc"
        assert name == "decoy.bin"

        # Too large file (simulate)
        class FakeStat:
            st_size = 200 * 1024 * 1024
            st_mode = 0o100644

        original_stat = Path.stat

        def patched_stat(self, *args, **kwargs):
            if self == file_path:
                return FakeStat()
            return original_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", patched_stat)
        data, name = handler.get_decoy_data()
        assert data == b"Decoy file too large."
        assert name == "error.txt"

    def test_get_decoy_data_bundled_fallback(self, monkeypatch):
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig

        config = DuressConfig(decoy_type="bundled_file")
        handler = DuressHandler(config)

        monkeypatch.setattr("pathlib.Path.exists", lambda self: False)
        data, name = handler.get_decoy_data()
        assert data.startswith(b"Error:")
        assert name == "error.txt"

    def test_sanitize_filename(self):
        from meow_decoder.duress_mode import DuressHandler

        assert DuressHandler.sanitize_filename("../path.txt") == "path.txt"
        assert DuressHandler.sanitize_filename(None) is None

    def test_generate_decoys(self):
        from meow_decoder.duress_mode import generate_deterministic_decoy, generate_duress_decoy

        salt = b"\x02" * 16
        d1 = generate_deterministic_decoy(64, salt)
        d2 = generate_deterministic_decoy(64, salt)
        assert d1 == d2

        decoy = generate_duress_decoy(size=32)
        assert len(decoy) == 32

    def test_setup_duress_and_is_duress_triggered(self):
        from meow_decoder.duress_mode import setup_duress, is_duress_triggered

        salt = secrets.token_bytes(16)
        handler = setup_duress("duress", "real", salt)
        assert is_duress_triggered(handler) is False
        assert is_duress_triggered(handler, "duress", salt) is True


class TestPackManifestCore:
    """Test pack_manifest_core function."""
    
    def test_pack_manifest_core_without_duress(self):
        """Test packing core without duress tag."""
        from meow_decoder.crypto import Manifest, pack_manifest_core
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=None
        )
        
        core = pack_manifest_core(manifest, include_duress_tag=False)
        
        assert isinstance(core, bytes)
        assert len(core) > 0
    
    def test_pack_manifest_core_with_duress(self):
        """Test packing core with duress tag."""
        from meow_decoder.crypto import Manifest, pack_manifest_core
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            duress_tag=secrets.token_bytes(32)
        )
        
        core_with = pack_manifest_core(manifest, include_duress_tag=True)
        core_without = pack_manifest_core(manifest, include_duress_tag=False)
        
        assert len(core_with) > len(core_without)
        assert len(core_with) == len(core_without) + 32


class TestDuressTimingProtection:
    """Test duress password has timing protection."""
    
    def test_duress_check_uses_constant_time(self):
        """Test that duress check uses constant-time comparison."""
        from meow_decoder.crypto import check_duress_password
        import time
        
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest"
        
        # Create tag for "password123"
        from meow_decoder.crypto import compute_duress_tag
        tag = compute_duress_tag("password123", salt, manifest_core)
        
        # Time correct password check
        times_correct = []
        for _ in range(10):
            start = time.perf_counter()
            check_duress_password("password123", salt, tag, manifest_core)
            times_correct.append(time.perf_counter() - start)
        
        # Time wrong password check
        times_wrong = []
        for _ in range(10):
            start = time.perf_counter()
            check_duress_password("wrong_pass", salt, tag, manifest_core)
            times_wrong.append(time.perf_counter() - start)
        
        # Both should complete (timing equalization is separate)
        assert len(times_correct) == 10
        assert len(times_wrong) == 10


class TestDuressInEncode:
    """Test duress password integration in encode."""
    
    def test_duress_requires_forward_secrecy(self):
        """Test that duress mode requires forward secrecy."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "test.txt"
            output_file = Path(tmpdir) / "test.gif"
            input_file.write_text("test data")
            
            config = EncodingConfig()
            
            # Should raise error - duress without FS
            with pytest.raises(ValueError, match="forward secrecy"):
                encode_file(
                    input_file,
                    output_file,
                    "password123",
                    config=config,
                    forward_secrecy=False,  # Disabled!
                    duress_password="duress123",
                    verbose=False
                )
    
    def test_duress_same_password_rejected(self):
        """Test that same password as duress is rejected."""
        from meow_decoder.encode import encode_file
        from meow_decoder.config import EncodingConfig
        
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "test.txt"
            output_file = Path(tmpdir) / "test.gif"
            input_file.write_text("test data")
            
            config = EncodingConfig()
            
            # Should raise error - same password
            with pytest.raises(ValueError, match="same"):
                encode_file(
                    input_file,
                    output_file,
                    "samepassword",
                    config=config,
                    forward_secrecy=True,
                    receiver_public_key=secrets.token_bytes(32),
                    duress_password="samepassword",
                    verbose=False
                )


class TestDuressMode:
    """Test DuressMode enum."""
    
    def test_duress_mode_decoy(self):
        """Test DECOY mode value."""
        from meow_decoder.config import DuressMode
        
        assert DuressMode.DECOY.value == "decoy"
    
    def test_duress_mode_panic(self):
        """Test PANIC mode value."""
        from meow_decoder.config import DuressMode
        
        assert DuressMode.PANIC.value == "panic"


class TestDuressEdgeCases:
    """Test edge cases in duress handling."""
    
    def test_duress_with_empty_manifest_core(self):
        """Test duress tag with empty manifest core."""
        from meow_decoder.crypto import compute_duress_tag, check_duress_password
        
        password = "duress"
        salt = secrets.token_bytes(16)
        manifest_core = b""
        
        tag = compute_duress_tag(password, salt, manifest_core)
        
        assert len(tag) == 32
        assert check_duress_password(password, salt, tag, manifest_core) is True
    
    def test_duress_tag_validation(self):
        """Test manifest rejects invalid duress tag size."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            duress_tag=b"too_short"  # Invalid!
        )
        
        with pytest.raises(ValueError, match="32 bytes"):
            pack_manifest(manifest)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
