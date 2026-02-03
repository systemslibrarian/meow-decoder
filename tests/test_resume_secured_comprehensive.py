#!/usr/bin/env python3
"""
🐱 Comprehensive Test Suite for resume_secured.py 
Meow Decoder - Secure Resume Functionality Tests

Tests for encrypted save/resume of partial decoding operations.
Covers: DecoderState, ResumeManager, AutoSaveDecoder, and helper functions.

Target: 90-95% code coverage with cat-themed test names!
"""

import json
import os
import secrets
import tempfile
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from dataclasses import asdict

import pytest

# Test imports
from meow_decoder.resume_secured import (
    DecoderState,
    ResumeManager,
    AutoSaveDecoder,
    STATE_VERSION,
    resume_from_session,
    create_resumable_decoder,
)
from meow_decoder.crypto import Manifest
from meow_decoder.fountain import FountainDecoder, Droplet


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_state_dir(tmp_path):
    """Create a temporary directory for state files."""
    state_dir = tmp_path / "resume_states"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


@pytest.fixture
def sample_manifest():
    """Create a sample Manifest for testing."""
    return Manifest(
        salt=secrets.token_bytes(16),
        nonce=secrets.token_bytes(12),
        orig_len=1000,
        comp_len=800,
        cipher_len=816,
        sha256=secrets.token_bytes(32),
        block_size=256,
        k_blocks=10,
        hmac=secrets.token_bytes(32),
    )


@pytest.fixture
def sample_decoder():
    """Create a sample FountainDecoder for testing."""
    decoder = FountainDecoder(k_blocks=10, block_size=256, original_length=1000)
    return decoder


@pytest.fixture
def sample_droplet():
    """Create a sample Droplet for testing."""
    return Droplet(
        seed=42,
        block_indices=[0, 1, 2],
        data=secrets.token_bytes(256),
    )


@pytest.fixture
def valid_password():
    """Provide a valid test password."""
    return "test_cat_password_123!@#"


@pytest.fixture
def resume_manager(temp_state_dir):
    """Create a ResumeManager instance for testing."""
    return ResumeManager(state_dir=str(temp_state_dir))


@pytest.fixture
def encrypted_resume_manager(temp_state_dir, valid_password, sample_manifest):
    """Create an encrypted ResumeManager instance."""
    manager = ResumeManager(state_dir=str(temp_state_dir))
    # Store for convenience in tests (not part of class API)
    manager._test_password = valid_password
    manager._test_manifest = sample_manifest
    return manager


# ============================================================================
# Test DecoderState
# ============================================================================

class TestDecoderState:
    """Tests for DecoderState dataclass - the 🐱 collar tag of decoder state."""
    
    def test_cat_creates_decoder_state_with_valid_data(self):
        """Test DecoderState can be created with valid data."""
        state = DecoderState(
            version=STATE_VERSION,
            session_id="session_abc123",
            manifest={'salt': 'aabbccdd'},
            solved_blocks=[(0, '0102030405')],
            pending_droplets=[([1, 2], 'deadbeef')],
            droplets_seen=50,
            timestamp=datetime.now().isoformat(),
            input_source="webcam",
            seed=42069,
        )
        
        assert state.version == STATE_VERSION
        assert state.session_id == "session_abc123"
        assert state.droplets_seen == 50
        assert state.input_source == "webcam"
        assert state.seed == 42069
    
    def test_cat_serializes_decoder_state_to_dict(self):
        """Test DecoderState serialization to dictionary."""
        timestamp = datetime.now().isoformat()
        state = DecoderState(
            version=STATE_VERSION,
            session_id="session_test",
            manifest={'k_blocks': 10},
            solved_blocks=[(0, 'aabb')],
            pending_droplets=[],
            droplets_seen=100,
            timestamp=timestamp,
            input_source="gif",
            seed=12345,
        )
        
        state_dict = state.to_dict()
        
        assert isinstance(state_dict, dict)
        assert state_dict['version'] == STATE_VERSION
        assert state_dict['session_id'] == "session_test"
        assert state_dict['timestamp'] == timestamp
        assert state_dict['droplets_seen'] == 100
    
    def test_cat_deserializes_decoder_state_from_dict(self):
        """Test DecoderState deserialization from dictionary."""
        data = {
            'version': STATE_VERSION,
            'session_id': "session_restored",
            'manifest': {'k_blocks': 5},
            'solved_blocks': [(1, 'beef')],
            'pending_droplets': [],
            'droplets_seen': 75,
            'timestamp': '2026-01-15T12:00:00',
            'input_source': 'webcam',
            'seed': 99999,
        }
        
        state = DecoderState.from_dict(data)
        
        assert state.version == STATE_VERSION
        assert state.session_id == "session_restored"
        assert state.droplets_seen == 75
    
    def test_cat_handles_legacy_state_without_version(self):
        """Test DecoderState handles legacy states without version field."""
        data = {
            'session_id': "legacy_session",
            'manifest': {'k_blocks': 5},
            'solved_blocks': [],
            'pending_droplets': [],
            'droplets_seen': 10,
            'timestamp': '2026-01-01T00:00:00',
            'input_source': 'gif',
            'seed': 42,
        }
        
        state = DecoderState.from_dict(data)
        
        assert state.version == 0
        assert state.session_id == "legacy_session"
    
    def test_cat_roundtrip_serialization(self):
        """Test DecoderState can be serialized and deserialized correctly."""
        original = DecoderState(
            version=STATE_VERSION,
            session_id="roundtrip_session",
            manifest={'test': 'data'},
            solved_blocks=[(0, 'aa'), (5, 'bb')],
            pending_droplets=[([1, 2], 'cc')],
            droplets_seen=42,
            timestamp='2026-01-20T10:30:00',
            input_source='gif',
            seed=777,
        )
        
        state_dict = original.to_dict()
        restored = DecoderState.from_dict(state_dict)
        
        assert restored.version == original.version
        assert restored.session_id == original.session_id
        assert restored.solved_blocks == original.solved_blocks
        assert restored.pending_droplets == original.pending_droplets
        assert restored.droplets_seen == original.droplets_seen


# ============================================================================
# Test ResumeManager Initialization
# ============================================================================

class TestResumeManagerInitialization:
    """Tests for ResumeManager initialization - the 🐱 yarn ball organizer."""
    
    def test_cat_creates_resume_manager_with_defaults(self, temp_state_dir):
        """Test ResumeManager initializes with default values."""
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        assert manager.state_dir == Path(temp_state_dir)
        assert manager.auto_save_interval > 0
        assert manager.cleanup_days > 0
        assert manager.encrypt_state == True  # Default is encrypted
    
    def test_cat_creates_resume_manager_with_custom_config(self, temp_state_dir):
        """Test ResumeManager with custom config object."""
        mock_config = Mock()
        mock_config.resume = Mock()
        mock_config.resume.auto_save_interval = 100
        mock_config.resume.cleanup_days = 14
        mock_config.resume.encrypt_state = False
        
        manager = ResumeManager(
            state_dir=str(temp_state_dir),
            config=mock_config,
        )
        
        assert manager.auto_save_interval == 100
        assert manager.cleanup_days == 14
        assert manager.encrypt_state == False
    
    def test_cat_creates_directory_if_missing(self, tmp_path):
        """Test ResumeManager creates state directory if it doesn't exist."""
        new_dir = tmp_path / "new_resume_dir"
        assert not new_dir.exists()
        
        manager = ResumeManager(state_dir=str(new_dir))
        
        assert new_dir.exists()
        assert new_dir.is_dir()
    
    def test_cat_creates_nested_directory(self, tmp_path):
        """Test ResumeManager creates nested directories."""
        nested_dir = tmp_path / "level1" / "level2" / "resume"
        
        manager = ResumeManager(state_dir=str(nested_dir))
        
        assert nested_dir.exists()
        assert nested_dir.is_dir()
    
    def test_cat_respects_config_object(self, temp_state_dir):
        """Test ResumeManager respects configuration object."""
        mock_config = Mock()
        mock_config.resume = Mock()
        mock_config.resume.auto_save_interval = 200
        mock_config.resume.cleanup_days = 30
        mock_config.resume.encrypt_state = False
        
        manager = ResumeManager(state_dir=str(temp_state_dir), config=mock_config)
        
        assert manager.auto_save_interval == 200
        assert manager.cleanup_days == 30
        assert manager.encrypt_state == False


# ============================================================================
# Test Key Derivation
# ============================================================================

class TestKeyDerivation:
    """Tests for state file key derivation - 🐱 lockpicking skills."""
    
    def test_cat_derives_key_with_correct_length(
        self, resume_manager, sample_manifest, valid_password
    ):
        """Test key derivation returns 32-byte key for Fernet."""
        key = resume_manager._derive_state_key(valid_password, sample_manifest)
        
        # Fernet expects a 32-byte key that gets base64-encoded
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_cat_derives_deterministic_key(
        self, resume_manager, sample_manifest, valid_password
    ):
        """Test key derivation is deterministic."""
        key1 = resume_manager._derive_state_key(valid_password, sample_manifest)
        key2 = resume_manager._derive_state_key(valid_password, sample_manifest)
        
        assert key1 == key2
    
    def test_cat_derives_different_keys_for_different_passwords(
        self, resume_manager, sample_manifest
    ):
        """Test different passwords produce different keys."""
        key1 = resume_manager._derive_state_key("password_one", sample_manifest)
        key2 = resume_manager._derive_state_key("password_two", sample_manifest)
        
        assert key1 != key2
    
    def test_cat_derives_different_keys_for_different_salts(
        self, resume_manager, valid_password
    ):
        """Test different manifest salts produce different keys."""
        manifest1 = Manifest(
            salt=b'A' * 16,
            nonce=secrets.token_bytes(12),
            orig_len=1000, comp_len=800, cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=256, k_blocks=10, hmac=secrets.token_bytes(32),
        )
        manifest2 = Manifest(
            salt=b'B' * 16,
            nonce=secrets.token_bytes(12),
            orig_len=1000, comp_len=800, cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=256, k_blocks=10, hmac=secrets.token_bytes(32),
        )
        
        key1 = resume_manager._derive_state_key(valid_password, manifest1)
        key2 = resume_manager._derive_state_key(valid_password, manifest2)
        
        assert key1 != key2


# ============================================================================
# Test Session ID Generation
# ============================================================================

class TestSessionIdGeneration:
    """Tests for session ID generation - 🐱 unique collar ID."""
    
    def test_cat_generates_session_id_with_correct_format(
        self, resume_manager, sample_manifest
    ):
        """Test session ID has expected format."""
        session_id = resume_manager.generate_session_id(sample_manifest)
        
        assert session_id.startswith("session_")
        # Format: session_<16 hex chars>
        assert len(session_id) == len("session_") + 16
    
    def test_cat_generates_deterministic_session_id(
        self, resume_manager, sample_manifest
    ):
        """Test session ID is deterministic for same manifest."""
        session_id1 = resume_manager.generate_session_id(sample_manifest)
        session_id2 = resume_manager.generate_session_id(sample_manifest)
        
        assert session_id1 == session_id2
    
    def test_cat_generates_different_ids_for_different_manifests(
        self, resume_manager
    ):
        """Test different manifests produce different session IDs."""
        manifest1 = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000, comp_len=800, cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=256, k_blocks=10, hmac=secrets.token_bytes(32),
        )
        manifest2 = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=2000, comp_len=1600, cipher_len=1616,
            sha256=secrets.token_bytes(32),
            block_size=256, k_blocks=20, hmac=secrets.token_bytes(32),
        )
        
        session_id1 = resume_manager.generate_session_id(manifest1)
        session_id2 = resume_manager.generate_session_id(manifest2)
        
        assert session_id1 != session_id2
    
    def test_cat_session_id_only_contains_valid_chars(
        self, resume_manager, sample_manifest
    ):
        """Test session ID only contains valid filename characters."""
        session_id = resume_manager.generate_session_id(sample_manifest)
        
        # Should be safe for filenames
        assert all(c.isalnum() or c == '_' for c in session_id)


# ============================================================================
# Test State File Paths
# ============================================================================

class TestStateFilePaths:
    """Tests for state file path generation - 🐱 finding the yarn ball."""
    
    def test_cat_gets_state_file_path(self, resume_manager, sample_manifest):
        """Test state file path generation."""
        session_id = resume_manager.generate_session_id(sample_manifest)
        state_path = resume_manager._get_state_file_path(session_id)
        
        assert state_path.parent == resume_manager.state_dir
        assert state_path.name == f"{session_id}.meow"
    
    def test_cat_state_file_uses_meow_extension(self, resume_manager, sample_manifest):
        """Test state files use .meow extension."""
        session_id = resume_manager.generate_session_id(sample_manifest)
        state_path = resume_manager._get_state_file_path(session_id)
        
        assert state_path.suffix == ".meow"


# ============================================================================
# Test State Saving (Unencrypted)
# ============================================================================

class TestStateSavingUnencrypted:
    """Tests for unencrypted state saving - 🐱 marking territory."""
    
    def test_cat_saves_decoder_state(self, temp_state_dir, sample_manifest, sample_decoder):
        """Test saving decoder state to file."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="webcam",
        )
        
        state_path = manager._get_state_file_path(session_id)
        assert state_path.exists()
    
    def test_cat_saves_valid_json(self, temp_state_dir, sample_manifest, sample_decoder):
        """Test saved state is valid JSON."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
        )
        
        state_path = manager._get_state_file_path(session_id)
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        assert 'version' in data
        assert 'session_id' in data
        assert 'timestamp' in data
    
    def test_cat_saves_manifest_data(self, temp_state_dir, sample_manifest, sample_decoder):
        """Test saved state includes manifest data."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
        )
        
        state_path = manager._get_state_file_path(session_id)
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        assert 'manifest' in data
        manifest_data = data['manifest']
        assert manifest_data['k_blocks'] == sample_manifest.k_blocks
        assert manifest_data['block_size'] == sample_manifest.block_size
    
    def test_cat_saves_solved_blocks(self, temp_state_dir, sample_manifest):
        """Test saved state includes solved blocks."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        decoder = FountainDecoder(k_blocks=5, block_size=100, original_length=500)
        # Manually add a solved block
        decoder.blocks[0] = b'\xaa\xbb\xcc' + b'\x00' * 97
        decoder.decoded[0] = True
        decoder.decoded_count = 1
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=decoder,
            input_source="gif",
        )
        
        state_path = manager._get_state_file_path(session_id)
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        assert 'solved_blocks' in data
        assert len(data['solved_blocks']) == 1
        block_idx, block_hex = data['solved_blocks'][0]
        assert block_idx == 0
    
    def test_cat_saves_pending_droplets(self, temp_state_dir, sample_manifest):
        """Test saved state includes pending droplets."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        decoder = FountainDecoder(k_blocks=5, block_size=100, original_length=500)
        # Add a pending droplet
        pending = Droplet(seed=123, block_indices=[1, 2], data=b'\xde\xad' + b'\x00' * 98)
        decoder.pending_droplets.append(pending)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=decoder,
            input_source="gif",
        )
        
        state_path = manager._get_state_file_path(session_id)
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        assert 'pending_droplets' in data
        assert len(data['pending_droplets']) >= 1


# ============================================================================
# Test State Saving (Encrypted)
# ============================================================================

class TestStateSavingEncrypted:
    """Tests for encrypted state saving - 🐱 hiding the stash."""
    
    def test_cat_saves_encrypted_state(
        self, temp_state_dir, sample_manifest, sample_decoder, valid_password
    ):
        """Test saving encrypted decoder state."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=True)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
            password=valid_password,
        )
        
        state_path = manager._get_state_file_path(session_id)
        assert state_path.exists()
    
    def test_cat_encrypted_state_not_plaintext_json(
        self, temp_state_dir, sample_manifest, sample_decoder, valid_password
    ):
        """Test encrypted state file is not plaintext JSON."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=True)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
            password=valid_password,
        )
        
        state_path = manager._get_state_file_path(session_id)
        with open(state_path, 'rb') as f:
            content = f.read()
        
        # Should not be valid JSON (encrypted)
        with pytest.raises(json.JSONDecodeError):
            json.loads(content.decode('utf-8', errors='replace'))


# ============================================================================
# Test State Loading (Unencrypted)
# ============================================================================

class TestStateLoadingUnencrypted:
    """Tests for unencrypted state loading - 🐱 finding the yarn ball."""
    
    def test_cat_loads_saved_state(
        self, temp_state_dir, sample_manifest, sample_decoder
    ):
        """Test loading a previously saved state."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="webcam",
        )
        
        state = manager.load_state(session_id)
        
        assert state is not None
        assert state.session_id == session_id
        assert state.input_source == "webcam"
    
    def test_cat_returns_none_for_missing_state(self, resume_manager):
        """Test loading non-existent state returns None."""
        state = resume_manager.load_state("session_nonexistent")
        
        assert state is None
    
    def test_cat_loads_manifest_data(
        self, temp_state_dir, sample_manifest, sample_decoder
    ):
        """Test loaded state contains correct manifest data."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
        )
        
        state = manager.load_state(session_id)
        
        assert state.manifest['k_blocks'] == sample_manifest.k_blocks
        assert state.manifest['block_size'] == sample_manifest.block_size


# ============================================================================
# Test State Loading (Encrypted)
# ============================================================================

class TestStateLoadingEncrypted:
    """Tests for encrypted state loading - 🐱 opening the locked box."""
    
    def test_cat_loads_encrypted_state(
        self, temp_state_dir, sample_manifest, sample_decoder, valid_password
    ):
        """Test loading encrypted state with correct password."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=True)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
            password=valid_password,
        )
        
        state = manager.load_state(
            session_id=session_id,
            password=valid_password,
            manifest=sample_manifest,
        )
        
        assert state is not None
        assert state.session_id == session_id
    
    def test_cat_fails_with_wrong_password(
        self, temp_state_dir, sample_manifest, sample_decoder, valid_password
    ):
        """Test loading encrypted state fails with wrong password."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=True)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
            password=valid_password,
        )
        
        # Try with wrong password
        state = manager.load_state(
            session_id=session_id,
            password="wrong_password",
            manifest=sample_manifest,
        )
        
        assert state is None


# ============================================================================
# Test Decoder Restoration
# ============================================================================

class TestDecoderRestoration:
    """Tests for restoring decoder from state - 🐱 rewinding the yarn."""
    
    def test_cat_restores_decoder_from_state(
        self, temp_state_dir, sample_manifest
    ):
        """Test restoring a FountainDecoder from saved state."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        # Create and configure decoder
        original_decoder = FountainDecoder(k_blocks=5, block_size=100, original_length=500)
        original_decoder.blocks[0] = b'\xaa' * 100
        original_decoder.decoded[0] = True
        original_decoder.decoded_count = 1
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=original_decoder,
            input_source="gif",
        )
        
        state = manager.load_state(session_id)
        restored_decoder = manager.restore_decoder(state)
        
        assert restored_decoder is not None
        assert restored_decoder.decoded_count == 1
        assert restored_decoder.decoded[0] == True
    
    def test_cat_restores_pending_droplets(
        self, temp_state_dir, sample_manifest
    ):
        """Test pending droplets are restored correctly."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        decoder = FountainDecoder(k_blocks=5, block_size=100, original_length=500)
        pending = Droplet(seed=999, block_indices=[2, 3], data=b'\xcc' * 100)
        decoder.pending_droplets.append(pending)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=decoder,
            input_source="gif",
        )
        
        state = manager.load_state(session_id)
        restored_decoder = manager.restore_decoder(state)
        
        assert len(restored_decoder.pending_droplets) >= 1


# ============================================================================
# Test State Cleanup
# ============================================================================

class TestStateCleanup:
    """Tests for old state file cleanup - 🐱 cleaning the litter box."""
    
    def test_cat_cleans_old_state_files(self, temp_state_dir):
        """Test cleanup removes old state files."""
        manager = ResumeManager(state_dir=str(temp_state_dir), cleanup_days=0)
        
        # Create an old state file
        old_file = temp_state_dir / "session_old.meow"
        old_file.write_text('{"old": "state"}')
        
        # Set modification time to past
        old_time = time.time() - (86400 * 10)  # 10 days ago
        os.utime(old_file, (old_time, old_time))
        
        manager.cleanup_old_states()
        
        assert not old_file.exists()
    
    def test_cat_keeps_recent_state_files(self, temp_state_dir):
        """Test cleanup keeps recent state files."""
        manager = ResumeManager(state_dir=str(temp_state_dir), cleanup_days=7)
        
        # Create a recent state file
        recent_file = temp_state_dir / "session_recent.meow"
        recent_file.write_text('{"recent": "state"}')
        
        manager.cleanup_old_states()
        
        assert recent_file.exists()
    
    def test_cat_only_removes_meow_files(self, temp_state_dir):
        """Test cleanup only removes .meow files."""
        manager = ResumeManager(state_dir=str(temp_state_dir), cleanup_days=0)
        
        # Create old files with different extensions
        meow_file = temp_state_dir / "session_old.meow"
        other_file = temp_state_dir / "important.txt"
        
        meow_file.write_text('state')
        other_file.write_text('keep me')
        
        old_time = time.time() - (86400 * 10)
        os.utime(meow_file, (old_time, old_time))
        os.utime(other_file, (old_time, old_time))
        
        manager.cleanup_old_states()
        
        assert not meow_file.exists()
        assert other_file.exists()


# ============================================================================
# Test Session Listing
# ============================================================================

class TestSessionListing:
    """Tests for listing available sessions - 🐱 counting yarn balls."""
    
    def test_cat_lists_available_sessions(
        self, temp_state_dir, sample_manifest, sample_decoder
    ):
        """Test listing available resume sessions."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        
        # Create some sessions
        session1 = manager.generate_session_id(sample_manifest)
        manager.save_state(
            session_id=session1,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
        )
        
        sessions = manager.list_sessions()
        
        assert session1 in sessions
    
    def test_cat_returns_empty_list_when_no_sessions(self, temp_state_dir):
        """Test empty list when no sessions exist."""
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        sessions = manager.list_sessions()
        
        assert sessions == []


# ============================================================================
# Test Session Deletion
# ============================================================================

class TestSessionDeletion:
    """Tests for deleting sessions - 🐱 abandoning the yarn ball."""
    
    def test_cat_deletes_session(
        self, temp_state_dir, sample_manifest, sample_decoder
    ):
        """Test deleting a specific session."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="gif",
        )
        
        assert manager.delete_session(session_id) == True
        assert session_id not in manager.list_sessions()
    
    def test_cat_handles_deleting_nonexistent_session(self, resume_manager):
        """Test deleting non-existent session returns False."""
        result = resume_manager.delete_session("session_does_not_exist")
        
        assert result == False


# ============================================================================
# Test AutoSaveDecoder
# ============================================================================

class TestAutoSaveDecoder:
    """Tests for AutoSaveDecoder wrapper - 🐱 automatic yarn ball saving."""
    
    def test_cat_creates_autosave_decoder(
        self, temp_state_dir, sample_manifest, valid_password
    ):
        """Test AutoSaveDecoder can be created."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        decoder = FountainDecoder(k_blocks=5, block_size=100, original_length=500)
        session_id = manager.generate_session_id(sample_manifest)
        
        auto_decoder = AutoSaveDecoder(
            decoder=decoder,
            resume_manager=manager,
            session_id=session_id,
            manifest=sample_manifest,
            input_source="webcam",
            save_interval=5,
        )
        
        assert auto_decoder is not None
        assert auto_decoder.decoder == decoder
        assert auto_decoder.droplets_seen == 0
    
    def test_cat_autosave_adds_droplet(
        self, temp_state_dir, sample_manifest, sample_droplet
    ):
        """Test AutoSaveDecoder forwards add_droplet calls."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        decoder = FountainDecoder(k_blocks=10, block_size=256, original_length=2560)
        session_id = manager.generate_session_id(sample_manifest)
        
        auto_decoder = AutoSaveDecoder(
            decoder=decoder,
            resume_manager=manager,
            session_id=session_id,
            manifest=sample_manifest,
            input_source="gif",
            save_interval=100,  # High interval so no save triggered
        )
        
        auto_decoder.add_droplet(sample_droplet)
        
        assert auto_decoder.droplets_seen == 1
    
    def test_cat_autosave_triggers_save_at_interval(
        self, temp_state_dir, sample_manifest
    ):
        """Test AutoSaveDecoder saves state at interval."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        decoder = FountainDecoder(k_blocks=10, block_size=100, original_length=1000)
        session_id = manager.generate_session_id(sample_manifest)
        
        auto_decoder = AutoSaveDecoder(
            decoder=decoder,
            resume_manager=manager,
            session_id=session_id,
            manifest=sample_manifest,
            input_source="gif",
            save_interval=3,  # Save every 3 droplets
        )
        
        # Add droplets
        for i in range(5):
            droplet = Droplet(seed=i, block_indices=[i % 10], data=b'\x00' * 100)
            auto_decoder.add_droplet(droplet)
        
        # Check state was saved
        state_path = manager._get_state_file_path(session_id)
        assert state_path.exists()
    
    def test_cat_autosave_delegates_is_complete(
        self, temp_state_dir, sample_manifest
    ):
        """Test AutoSaveDecoder delegates is_complete() to decoder."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        decoder = FountainDecoder(k_blocks=2, block_size=100, original_length=200)
        session_id = manager.generate_session_id(sample_manifest)
        
        auto_decoder = AutoSaveDecoder(
            decoder=decoder,
            resume_manager=manager,
            session_id=session_id,
            manifest=sample_manifest,
            input_source="gif",
            save_interval=100,
        )
        
        assert auto_decoder.is_complete() == False
        
        # Mark all blocks as decoded
        decoder.blocks[0] = b'\x00' * 100
        decoder.blocks[1] = b'\x00' * 100
        decoder.decoded[0] = True
        decoder.decoded[1] = True
        decoder.decoded_count = 2
        
        assert auto_decoder.is_complete() == True


# ============================================================================
# Test Helper Functions
# ============================================================================

class TestHelperFunctions:
    """Tests for helper functions - 🐱 utility claws."""
    
    def test_cat_resume_from_session_creates_decoder(
        self, temp_state_dir, sample_manifest, sample_decoder, valid_password
    ):
        """Test resume_from_session creates a decoder from saved state."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="webcam",
        )
        
        restored_decoder = resume_from_session(
            session_id=session_id,
            resume_manager=manager,
        )
        
        assert restored_decoder is not None
    
    def test_cat_resume_from_session_returns_none_for_missing(
        self, temp_state_dir
    ):
        """Test resume_from_session returns None for missing session."""
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        result = resume_from_session(
            session_id="nonexistent_session",
            resume_manager=manager,
        )
        
        assert result is None
    
    def test_cat_create_resumable_decoder(
        self, temp_state_dir, sample_manifest
    ):
        """Test create_resumable_decoder creates AutoSaveDecoder."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        
        auto_decoder = create_resumable_decoder(
            manifest=sample_manifest,
            resume_manager=manager,
            input_source="gif",
            save_interval=10,
        )
        
        assert isinstance(auto_decoder, AutoSaveDecoder)
        assert auto_decoder.input_source == "gif"


# ============================================================================
# Test Error Handling
# ============================================================================

class TestErrorHandling:
    """Tests for error handling - 🐱 landing on feet."""
    
    def test_cat_handles_corrupted_state_file(self, temp_state_dir):
        """Test graceful handling of corrupted state file."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        
        # Create corrupted state file
        corrupted_file = temp_state_dir / "session_corrupted.meow"
        corrupted_file.write_text("{{{{not valid json")
        
        state = manager.load_state("session_corrupted")
        
        assert state is None
    
    def test_cat_handles_missing_fields_in_state(self, temp_state_dir):
        """Test handling state file with missing fields."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        
        # Create incomplete state file
        incomplete_data = {
            'session_id': 'incomplete',
            # Missing most fields
        }
        incomplete_file = temp_state_dir / "session_incomplete.meow"
        incomplete_file.write_text(json.dumps(incomplete_data))
        
        # Should handle gracefully (return None or raise)
        state = manager.load_state("session_incomplete")
        # Accept either None or exception handling
        assert state is None or isinstance(state, DecoderState)
    
    def test_cat_handles_permission_error_on_save(self, temp_state_dir, sample_manifest, sample_decoder):
        """Test handling permission errors when saving."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        # Make directory read-only
        os.chmod(temp_state_dir, 0o444)
        
        try:
            # Should raise or handle gracefully
            with pytest.raises(PermissionError):
                manager.save_state(
                    session_id=session_id,
                    manifest=sample_manifest,
                    decoder=sample_decoder,
                    input_source="gif",
                )
        finally:
            # Restore permissions
            os.chmod(temp_state_dir, 0o755)


# ============================================================================
# Test Thread Safety
# ============================================================================

class TestThreadSafety:
    """Tests for thread safety - 🐱 multiple cats, one yarn ball."""
    
    def test_cat_concurrent_saves_dont_corrupt(
        self, temp_state_dir, sample_manifest
    ):
        """Test concurrent save operations don't corrupt state."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        errors = []
        
        def save_state_thread(thread_id):
            try:
                decoder = FountainDecoder(k_blocks=5, block_size=100, original_length=500)
                decoder.decoded_count = thread_id
                
                manager.save_state(
                    session_id=session_id,
                    manifest=sample_manifest,
                    decoder=decoder,
                    input_source=f"thread_{thread_id}",
                )
            except Exception as e:
                errors.append(e)
        
        # Run multiple threads
        threads = [threading.Thread(target=save_state_thread, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should not have errors
        assert len(errors) == 0
        
        # State file should exist and be valid
        state = manager.load_state(session_id)
        assert state is not None


# ============================================================================
# Test Edge Cases
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases - 🐱 catching the sneaky mice."""
    
    def test_cat_handles_empty_decoder(self, temp_state_dir, sample_manifest):
        """Test saving and restoring empty decoder."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        decoder = FountainDecoder(k_blocks=10, block_size=256, original_length=2560)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=decoder,
            input_source="gif",
        )
        
        state = manager.load_state(session_id)
        restored = manager.restore_decoder(state)
        
        assert restored.decoded_count == 0
        assert all(not d for d in restored.decoded)
    
    def test_cat_handles_fully_decoded_decoder(self, temp_state_dir, sample_manifest):
        """Test saving and restoring fully decoded decoder."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        decoder = FountainDecoder(k_blocks=3, block_size=100, original_length=300)
        for i in range(3):
            decoder.blocks[i] = b'\xff' * 100
            decoder.decoded[i] = True
        decoder.decoded_count = 3
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=decoder,
            input_source="gif",
        )
        
        state = manager.load_state(session_id)
        restored = manager.restore_decoder(state)
        
        assert restored.decoded_count == 3
        assert restored.is_complete()
    
    def test_cat_handles_large_block_data(self, temp_state_dir, sample_manifest):
        """Test saving decoder with large block data."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        # Large block size
        decoder = FountainDecoder(k_blocks=5, block_size=4096, original_length=20480)
        decoder.blocks[0] = secrets.token_bytes(4096)
        decoder.decoded[0] = True
        decoder.decoded_count = 1
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=decoder,
            input_source="gif",
        )
        
        state = manager.load_state(session_id)
        restored = manager.restore_decoder(state)
        
        assert restored.decoded_count == 1
        assert restored.blocks[0] == decoder.blocks[0]
    
    def test_cat_handles_special_characters_in_input_source(
        self, temp_state_dir, sample_manifest, sample_decoder
    ):
        """Test handling special characters in input source path."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        # Input source with special characters
        input_source = "/path/to/file with spaces/and-dashes_underscores.gif"
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source=input_source,
        )
        
        state = manager.load_state(session_id)
        
        assert state.input_source == input_source
    
    def test_cat_handles_unicode_in_paths(self, tmp_path, sample_manifest, sample_decoder):
        """Test handling unicode in directory paths."""
        unicode_dir = tmp_path / "résumé_状态_🐱"
        manager = ResumeManager(state_dir=str(unicode_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=sample_decoder,
            input_source="test",
        )
        
        state = manager.load_state(session_id)
        
        assert state is not None


# ============================================================================
# Test Integration Scenarios
# ============================================================================

class TestIntegrationScenarios:
    """Integration tests for complete workflows - 🐱 the full hunt."""
    
    def test_cat_full_save_restore_cycle(self, temp_state_dir, sample_manifest):
        """Test complete save-restore cycle."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        session_id = manager.generate_session_id(sample_manifest)
        
        # Create decoder with some progress
        decoder = FountainDecoder(k_blocks=5, block_size=100, original_length=500)
        decoder.blocks[0] = b'\xaa' * 100
        decoder.blocks[2] = b'\xbb' * 100
        decoder.decoded[0] = True
        decoder.decoded[2] = True
        decoder.decoded_count = 2
        
        pending = Droplet(seed=42, block_indices=[1, 3], data=b'\xcc' * 100)
        decoder.pending_droplets.append(pending)
        
        # Save
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=decoder,
            input_source="integration_test",
        )
        
        # Load and restore
        state = manager.load_state(session_id)
        restored = manager.restore_decoder(state)
        
        # Verify
        assert restored.decoded_count == 2
        assert restored.decoded[0] == True
        assert restored.decoded[2] == True
        assert restored.blocks[0] == b'\xaa' * 100
        assert restored.blocks[2] == b'\xbb' * 100
    
    def test_cat_encrypted_full_cycle(
        self, temp_state_dir, sample_manifest, valid_password
    ):
        """Test complete encrypted save-restore cycle."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=True)
        session_id = manager.generate_session_id(sample_manifest)
        
        decoder = FountainDecoder(k_blocks=3, block_size=100, original_length=300)
        decoder.blocks[0] = b'\xde\xad' + b'\x00' * 98
        decoder.decoded[0] = True
        decoder.decoded_count = 1
        
        # Save encrypted
        manager.save_state(
            session_id=session_id,
            manifest=sample_manifest,
            decoder=decoder,
            input_source="encrypted_test",
            password=valid_password,
        )
        
        # Load with password
        state = manager.load_state(
            session_id=session_id,
            password=valid_password,
            manifest=sample_manifest,
        )
        
        assert state is not None
        assert state.session_id == session_id
        
        restored = manager.restore_decoder(state)
        assert restored.decoded_count == 1
    
    def test_cat_autosave_integration(self, temp_state_dir, sample_manifest):
        """Test AutoSaveDecoder full integration."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        
        auto_decoder = create_resumable_decoder(
            manifest=sample_manifest,
            resume_manager=manager,
            input_source="autosave_integration",
            save_interval=5,
        )
        
        # Add several droplets
        for i in range(10):
            droplet = Droplet(
                seed=i,
                block_indices=[i % sample_manifest.k_blocks],
                data=secrets.token_bytes(sample_manifest.block_size),
            )
            auto_decoder.add_droplet(droplet)
        
        # Verify state was saved (at intervals)
        sessions = manager.list_sessions()
        assert len(sessions) >= 1


# ============================================================================
# Test Version Compatibility
# ============================================================================

class TestVersionCompatibility:
    """Tests for state version compatibility - 🐱 old yarn balls still work."""
    
    def test_cat_handles_future_version(self, temp_state_dir):
        """Test handling state file with future version."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        
        # Create state with future version
        future_state = {
            'version': STATE_VERSION + 10,  # Future version
            'session_id': 'future_session',
            'manifest': {'k_blocks': 5},
            'solved_blocks': [],
            'pending_droplets': [],
            'droplets_seen': 0,
            'timestamp': datetime.now().isoformat(),
            'input_source': 'future',
            'seed': 0,
        }
        
        future_file = temp_state_dir / "session_future.meow"
        future_file.write_text(json.dumps(future_state))
        
        # Should handle gracefully
        state = manager.load_state("session_future")
        # Accept loading or rejection of future version
        assert state is None or state.version > STATE_VERSION
    
    def test_cat_handles_version_zero(self, temp_state_dir):
        """Test handling legacy version 0 state."""
        manager = ResumeManager(state_dir=str(temp_state_dir), encrypt_state=False)
        
        legacy_state = {
            'version': 0,
            'session_id': 'legacy_v0',
            'manifest': {'k_blocks': 3},
            'solved_blocks': [(0, 'aabb')],
            'pending_droplets': [],
            'droplets_seen': 10,
            'timestamp': '2020-01-01T00:00:00',
            'input_source': 'legacy',
            'seed': 1234,
        }
        
        legacy_file = temp_state_dir / "session_legacy_v0.meow"
        legacy_file.write_text(json.dumps(legacy_state))
        
        state = manager.load_state("session_legacy_v0")
        
        assert state is not None
        assert state.version == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
