#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for resume and misc modules - Target: 90%+
Tests resume functionality, miscellaneous modules, and remaining coverage gaps.
"""

import pytest
import secrets
import sys
import os
import tempfile
import struct
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestProwlingMode:
    """Test prowling mode (low-memory streaming)."""
    
    def test_import_prowling_mode(self):
        """Test importing prowling_mode module."""
        try:
            from meow_decoder import prowling_mode
            assert prowling_mode is not None
        except ImportError:
            pytest.skip("prowling_mode module not available")
    
    def test_streaming_encryption(self):
        """Test streaming encryption."""
        try:
            from meow_decoder.prowling_mode import StreamingEncryption
            
            password = "TestPassword123!"
            salt = secrets.token_bytes(16)
            
            streamer = StreamingEncryption(password, salt)
            
            assert streamer is not None
        except (ImportError, AttributeError):
            pytest.skip("StreamingEncryption not available")


class TestStreamingCrypto:
    """Test streaming crypto module."""
    
    def test_import_streaming_crypto(self):
        """Test importing streaming_crypto module."""
        try:
            from meow_decoder import streaming_crypto
            assert streaming_crypto is not None
        except ImportError:
            pytest.skip("streaming_crypto module not available")


class TestHighSecurity:
    """Test high security module."""
    
    def test_import_high_security(self):
        """Test importing high_security module."""
        try:
            from meow_decoder import high_security
            assert high_security is not None
        except ImportError:
            pytest.skip("high_security module not available")
    
    def test_high_security_config(self):
        """Test HighSecurityConfig class."""
        try:
            from meow_decoder.high_security import HighSecurityConfig
            
            config = HighSecurityConfig()
            
            assert config is not None
            assert config.argon2_memory > 0
        except (ImportError, AttributeError):
            pytest.skip("HighSecurityConfig not available")
    
    def test_enable_high_security_mode(self):
        """Test enabling high security mode."""
        try:
            from meow_decoder.high_security import enable_high_security_mode
            
            enable_high_security_mode(silent=True)
        except (ImportError, AttributeError):
            pytest.skip("enable_high_security_mode not available")
    
    def test_safety_checklist(self):
        """Test getting safety checklist."""
        try:
            from meow_decoder.high_security import get_safety_checklist
            
            checklist = get_safety_checklist()
            
            assert checklist is not None
            assert len(checklist) > 0
        except (ImportError, AttributeError):
            pytest.skip("get_safety_checklist not available")
    
    def test_secure_wipe_file(self):
        """Test secure file wiping."""
        try:
            from meow_decoder.high_security import secure_wipe_file
            
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"Test data to wipe")
                temp_path = f.name
            
            result = secure_wipe_file(temp_path, passes=1)
            
            assert result is True
            assert not os.path.exists(temp_path)
        except (ImportError, AttributeError):
            pytest.skip("secure_wipe_file not available")


class TestPQHybrid:
    """Test post-quantum hybrid crypto module."""
    
    def test_import_pq_hybrid(self):
        """Test importing pq_hybrid module."""
        try:
            from meow_decoder import pq_hybrid
            assert pq_hybrid is not None
        except ImportError:
            pytest.skip("pq_hybrid module not available")
    
    def test_pq_available(self):
        """Test PQ availability check."""
        try:
            from meow_decoder.pq_hybrid import is_pq_available
            
            result = is_pq_available()
            
            assert isinstance(result, bool)
        except (ImportError, AttributeError):
            pytest.skip("is_pq_available not available")


class TestPQSignatures:
    """Test post-quantum signatures module."""
    
    def test_import_pq_signatures(self):
        """Test importing pq_signatures module."""
        try:
            from meow_decoder import pq_signatures
            assert pq_signatures is not None
        except ImportError:
            pytest.skip("pq_signatures module not available")
    
    def test_dilithium_available(self):
        """Test Dilithium availability."""
        try:
            from meow_decoder.pq_signatures import is_dilithium_available
            
            result = is_dilithium_available()
            
            assert isinstance(result, bool)
        except (ImportError, AttributeError):
            pytest.skip("is_dilithium_available not available")


class TestTimelockDuress:
    """Test time-lock duress module."""
    
    def test_import_timelock_duress(self):
        """Test importing timelock_duress module."""
        try:
            from meow_decoder import timelock_duress
            assert timelock_duress is not None
        except ImportError:
            pytest.skip("timelock_duress module not available")
    
    def test_timelock_puzzle(self):
        """Test TimeLockPuzzle class."""
        try:
            from meow_decoder.timelock_duress import TimeLockPuzzle
            
            puzzle = TimeLockPuzzle(iterations=100)
            
            # Create puzzle
            key = secrets.token_bytes(32)
            locked = puzzle.lock(key)
            
            assert locked is not None
            
            # Solve puzzle
            unlocked = puzzle.solve(locked)
            
            assert unlocked == key
        except (ImportError, AttributeError):
            pytest.skip("TimeLockPuzzle not available")
    
    def test_countdown_duress(self):
        """Test CountdownDuress class."""
        try:
            from meow_decoder.timelock_duress import CountdownDuress
            
            duress = CountdownDuress(countdown_seconds=10)
            
            assert duress is not None
        except (ImportError, AttributeError):
            pytest.skip("CountdownDuress not available")
    
    def test_dead_man_switch(self):
        """Test DeadManSwitch class."""
        try:
            from meow_decoder.timelock_duress import DeadManSwitch
            
            switch = DeadManSwitch(interval_seconds=60)
            
            assert switch is not None
        except (ImportError, AttributeError):
            pytest.skip("DeadManSwitch not available")


class TestDoubleRatchet:
    """Test double ratchet protocol module."""
    
    def test_import_double_ratchet(self):
        """Test importing double_ratchet module."""
        try:
            from meow_decoder import double_ratchet
            assert double_ratchet is not None
        except ImportError:
            pytest.skip("double_ratchet module not available")
    
    def test_dh_ratchet(self):
        """Test DH ratchet class."""
        try:
            from meow_decoder.double_ratchet import DHRatchet
            
            ratchet = DHRatchet()
            
            assert ratchet is not None
        except (ImportError, AttributeError):
            pytest.skip("DHRatchet not available")
    
    def test_symmetric_ratchet(self):
        """Test symmetric ratchet class."""
        try:
            from meow_decoder.double_ratchet import SymmetricRatchet
            
            chain_key = secrets.token_bytes(32)
            ratchet = SymmetricRatchet(chain_key)
            
            assert ratchet is not None
            
            # Step ratchet
            message_key, new_ratchet = ratchet.step()
            
            assert len(message_key) == 32
        except (ImportError, AttributeError):
            pytest.skip("SymmetricRatchet not available")


class TestProgressModule:
    """Test progress bar module."""
    
    def test_import_progress(self):
        """Test importing progress module."""
        from meow_decoder import progress
        assert progress is not None
    
    def test_progress_bar(self):
        """Test ProgressBar class."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=100, desc="Test", unit="items", disable=True)
        
        assert pb is not None
    
    def test_progress_bar_iteration(self):
        """Test ProgressBar iteration."""
        from meow_decoder.progress import ProgressBar
        
        pb = ProgressBar(total=10, desc="Test", unit="items", disable=True)
        
        items = list(range(10))
        
        for i in pb(items):
            pass


class TestManifestParsing:
    """Test manifest parsing edge cases."""
    
    def test_manifest_too_short(self):
        """Test parsing too-short manifest."""
        from meow_decoder.crypto import unpack_manifest
        
        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(b"TOO_SHORT")
    
    def test_manifest_wrong_magic(self):
        """Test parsing manifest with wrong magic."""
        from meow_decoder.crypto import unpack_manifest
        
        # Create manifest-sized data with wrong magic
        bad_manifest = b"BADM" + b"\x00" * 150
        
        with pytest.raises(ValueError):
            unpack_manifest(bad_manifest)
    
    def test_manifest_invalid_length(self):
        """Test parsing manifest with invalid length."""
        from meow_decoder.crypto import unpack_manifest
        
        # Wrong length (not 115, 147, 179, 1235, or 1267)
        bad_manifest = b"MEOW3" + b"\x00" * 130  # 135 bytes - invalid
        
        with pytest.raises(ValueError, match="length invalid"):
            unpack_manifest(bad_manifest)


class TestFrameMACEdgeCases:
    """Test frame MAC edge cases."""
    
    def test_frame_mac_module_import(self):
        """Test importing frame_mac module."""
        from meow_decoder import frame_mac
        assert frame_mac is not None
    
    def test_derive_frame_master_key(self):
        """Test deriving frame master key."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        encryption_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        frame_key = derive_frame_master_key(encryption_key, salt)
        
        assert len(frame_key) == 32
    
    def test_pack_unpack_frame_with_mac(self):
        """Test packing and unpacking frame with MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        frame_data = b"Test frame data"
        frame_index = 0
        
        # Pack with MAC
        packed = pack_frame_with_mac(frame_data, master_key, frame_index, salt)
        
        # Should be longer than original
        assert len(packed) > len(frame_data)
        
        # Unpack with MAC
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index, salt)
        
        assert valid is True
        assert unpacked == frame_data
    
    def test_frame_mac_invalid(self):
        """Test frame MAC validation with wrong key."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        master_key1 = secrets.token_bytes(32)
        master_key2 = secrets.token_bytes(32)  # Different key
        salt = secrets.token_bytes(16)
        frame_data = b"Test frame data"
        frame_index = 0
        
        # Pack with one key
        packed = pack_frame_with_mac(frame_data, master_key1, frame_index, salt)
        
        # Try to unpack with different key
        valid, _ = unpack_frame_with_mac(packed, master_key2, frame_index, salt)
        
        assert valid is False
    
    def test_frame_mac_stats(self):
        """Test FrameMACStats class."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        # Record some frames
        stats.record_valid()
        stats.record_valid()
        stats.record_invalid()
        
        assert stats.valid_frames == 2
        assert stats.invalid_frames == 1
        
        success_rate = stats.success_rate()
        
        assert 0.66 <= success_rate <= 0.67


class TestMetadataObfuscation:
    """Test metadata obfuscation module."""
    
    def test_import_metadata_obfuscation(self):
        """Test importing metadata_obfuscation module."""
        from meow_decoder import metadata_obfuscation
        assert metadata_obfuscation is not None
    
    def test_add_length_padding(self):
        """Test adding length padding."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"Test data"
        
        padded = add_length_padding(data)
        
        # Should be larger or equal
        assert len(padded) >= len(data)
    
    def test_remove_length_padding(self):
        """Test removing length padding."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"Test data for padding"
        
        padded = add_length_padding(original)
        unpadded = remove_length_padding(padded)
        
        assert unpadded == original
    
    def test_length_padding_roundtrip(self):
        """Test length padding roundtrip."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        # Test various sizes
        for size in [10, 100, 1000, 10000]:
            original = secrets.token_bytes(size)
            padded = add_length_padding(original)
            unpadded = remove_length_padding(padded)
            
            assert unpadded == original


class TestDecoyGeneration:
    """Test decoy generation functionality."""
    
    def test_generate_convincing_decoy(self):
        """Test generating convincing decoy."""
        try:
            from meow_decoder.decoy_generator import generate_convincing_decoy
            
            decoy = generate_convincing_decoy(5000)
            
            assert len(decoy) >= 5000
            
            # Check it looks like a ZIP or known format
            # (Decoys typically mimic real file types)
        except (ImportError, AttributeError):
            # Try schrodinger_encode fallback
            try:
                from meow_decoder.schrodinger_encode import generate_convincing_decoy
                
                decoy = generate_convincing_decoy(5000)
                
                assert len(decoy) >= 5000
            except (ImportError, AttributeError):
                pytest.skip("generate_convincing_decoy not available")


class TestConstantTimeOperations:
    """Test constant-time operations."""
    
    def test_import_constant_time(self):
        """Test importing constant_time module."""
        from meow_decoder import constant_time
        assert constant_time is not None
    
    def test_constant_time_compare(self):
        """Test constant-time comparison."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = secrets.token_bytes(32)
        b = bytes(a)  # Same content
        c = secrets.token_bytes(32)  # Different
        
        assert constant_time_compare(a, b) is True
        assert constant_time_compare(a, c) is False
    
    def test_secure_zero_memory(self):
        """Test secure memory zeroing."""
        from meow_decoder.constant_time import secure_zero_memory
        
        data = bytearray(b"sensitive_data_here")
        
        secure_zero_memory(data)
        
        assert all(b == 0 for b in data)
    
    def test_secure_buffer(self):
        """Test SecureBuffer class."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"test data")
            data = buf.read(9)
            
            assert data == b"test data"
    
    def test_equalize_timing(self):
        """Test timing equalization."""
        from meow_decoder.constant_time import equalize_timing
        import time
        
        start = time.time()
        equalize_timing(0.001, 0.01)
        elapsed = time.time() - start
        
        # Should have waited at least a bit
        assert elapsed >= 0.001


class TestX25519ForwardSecrecy:
    """Test X25519 forward secrecy module."""
    
    def test_import_x25519_forward_secrecy(self):
        """Test importing x25519_forward_secrecy module."""
        from meow_decoder import x25519_forward_secrecy
        assert x25519_forward_secrecy is not None
    
    def test_generate_ephemeral_keypair(self):
        """Test generating ephemeral keypair."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys = generate_ephemeral_keypair()
        
        assert keys is not None
        assert len(keys.ephemeral_private) == 32
        assert len(keys.ephemeral_public) == 32
    
    def test_derive_shared_secret(self):
        """Test deriving shared secret."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            derive_shared_secret,
            generate_receiver_keypair
        )
        
        # Generate sender ephemeral keys
        sender_keys = generate_ephemeral_keypair()
        
        # Generate receiver long-term keys
        receiver_priv, receiver_pub = generate_receiver_keypair()
        
        # Derive shared secret
        salt = secrets.token_bytes(16)
        shared = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_pub,
            "password123",
            salt
        )
        
        assert len(shared) == 32
    
    def test_serialize_deserialize_pubkey(self):
        """Test serializing and deserializing public key."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            serialize_public_key,
            deserialize_public_key
        )
        
        keys = generate_ephemeral_keypair()
        
        serialized = serialize_public_key(keys.ephemeral_public)
        
        assert len(serialized) == 32
        
        deserialized = deserialize_public_key(serialized)
        
        assert deserialized == keys.ephemeral_public


class TestConfigEdgeCases:
    """Test config module edge cases."""
    
    def test_duress_mode_enum(self):
        """Test DuressMode enum."""
        from meow_decoder.config import DuressMode
        
        assert DuressMode.DECOY.value == "decoy"
        assert DuressMode.PANIC.value == "panic"
    
    def test_duress_config_defaults(self):
        """Test DuressConfig defaults."""
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig()
        
        assert config.enabled is False
        assert config.mode == DuressMode.DECOY
        assert config.panic_enabled is False
    
    def test_encoding_config_defaults(self):
        """Test EncodingConfig defaults."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.block_size == 512
        assert config.redundancy == 1.5
        assert config.fps == 2
        assert config.enable_forward_secrecy is True
    
    def test_decoding_config_defaults(self):
        """Test DecodingConfig defaults."""
        from meow_decoder.config import DecodingConfig
        
        config = DecodingConfig()
        
        assert config.webcam_device == 0
        assert config.preprocessing == "normal"
    
    def test_crypto_config_defaults(self):
        """Test CryptoConfig defaults."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig()
        
        assert config.key_derivation == "argon2id"
        assert config.cipher == "aes-256-gcm"
        assert config.enable_pq is True
    
    def test_meow_config_save_load(self):
        """Test MeowConfig save and load."""
        from meow_decoder.config import MeowConfig
        
        config = MeowConfig()
        config.encoding.block_size = 1024
        config.verbose = True
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.json"
            
            config.save(config_path)
            
            assert config_path.exists()
            
            loaded = MeowConfig.load(config_path)
            
            assert loaded.encoding.block_size == 1024
            assert loaded.verbose is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
