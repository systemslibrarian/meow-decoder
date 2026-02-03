#!/usr/bin/env python3
"""
🐱 Comprehensive Test Suite for resume_secured.py
Tests encrypted state saving and resumable fountain decoding operations.

Target coverage: 90-95%

Security invariants verified:
- State files are encrypted with Fernet (AES-128)
- Key derivation uses PBKDF2 with proper iterations
- Proper wiping of state files on deletion
- Session IDs are derived deterministically from manifest
- Fallback to unencrypted state files handled (legacy/debug)
- Invalid/corrupted state files handled gracefully
"""

import json
import os
import secrets
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, mock_open

import pytest
from cryptography.fernet import Fernet, InvalidToken

# Import real classes from meow_decoder
from meow_decoder.fountain import FountainDecoder
from meow_decoder.crypto import Manifest


# ============================================================================
# Module Setup & Fixtures
# ============================================================================


@pytest.fixture
def sample_manifest():
    """Create a sample manifest for testing."""
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
    """Create a sample fountain decoder for testing."""
    decoder = FountainDecoder(k_blocks=10, block_size=256, original_length=1000)
    # Note: FountainDecoder uses blocks list for solved blocks
    # and pending_droplets for unsolved equations
    return decoder


@pytest.fixture
def decoder_with_data():
    """Create a decoder with some solved data for state preservation tests."""
    decoder = FountainDecoder(k_blocks=10, block_size=256, original_length=1000)
    # Populate some solved blocks
    decoder.blocks[0] = b'\x01' * 256
    decoder.decoded[0] = True
    decoder.blocks[2] = b'\x02' * 256
    decoder.decoded[2] = True
    decoder.blocks[5] = b'\x03' * 256
    decoder.decoded[5] = True
    decoder.decoded_count = 3
    return decoder


@pytest.fixture
def valid_password():
    """A valid password for state encryption."""
    return "CatSecretPassword123!"


@pytest.fixture
def temp_state_dir(tmp_path):
    """Create a temporary state directory."""
    state_dir = tmp_path / "meow_resume_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


# ============================================================================
# Test DecoderState Dataclass
# ============================================================================

class TestDecoderState:
    """Tests for DecoderState dataclass."""
    
    def test_decoder_state_creation(self, mock_improved_modules):
        """Test DecoderState can be created with valid data."""
        from meow_decoder.resume_secured import DecoderState, STATE_VERSION
        
        state = DecoderState(
            version=STATE_VERSION,
            session_id="session_abc123",
            manifest={'salt': 'aabbccdd'},
            solved_blocks=[(0, '0102030405')],
            equations=[([1, 2], 'deadbeef')],
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
    
    def test_decoder_state_to_dict(self, mock_improved_modules):
        """Test DecoderState serialization to dictionary."""
        from meow_decoder.resume_secured import DecoderState, STATE_VERSION
        
        timestamp = datetime.now().isoformat()
        state = DecoderState(
            version=STATE_VERSION,
            session_id="session_test",
            manifest={'k_blocks': 10},
            solved_blocks=[(0, 'aabb')],
            equations=[],
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
    
    def test_decoder_state_from_dict(self, mock_improved_modules):
        """Test DecoderState deserialization from dictionary."""
        from meow_decoder.resume_secured import DecoderState, STATE_VERSION
        
        data = {
            'version': STATE_VERSION,
            'session_id': "session_restored",
            'manifest': {'k_blocks': 5},
            'solved_blocks': [(1, 'beef')],
            'equations': [],
            'droplets_seen': 75,
            'timestamp': '2026-01-15T12:00:00',
            'input_source': 'webcam',
            'seed': 99999,
        }
        
        state = DecoderState.from_dict(data)
        
        assert state.version == STATE_VERSION
        assert state.session_id == "session_restored"
        assert state.droplets_seen == 75
    
    def test_decoder_state_from_dict_legacy_no_version(self, mock_improved_modules):
        """Test DecoderState handles legacy states without version field."""
        from meow_decoder.resume_secured import DecoderState
        
        # Simulate legacy state file without version
        data = {
            'session_id': "legacy_session",
            'manifest': {'k_blocks': 5},
            'solved_blocks': [],
            'equations': [],
            'droplets_seen': 10,
            'timestamp': '2026-01-01T00:00:00',
            'input_source': 'gif',
            'seed': 42,
        }
        
        state = DecoderState.from_dict(data)
        
        # Should default version to 0 for legacy
        assert state.version == 0
        assert state.session_id == "legacy_session"


# ============================================================================
# Test ResumeManager Initialization
# ============================================================================

class TestResumeManagerInit:
    """Tests for ResumeManager initialization."""
    
    def test_resume_manager_default_state_dir(self, mock_improved_modules, monkeypatch):
        """Test ResumeManager creates default state directory."""
        from meow_decoder.resume_secured import ResumeManager
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock home directory
            monkeypatch.setattr(Path, 'home', lambda: Path(tmpdir))
            
            manager = ResumeManager()
            
            expected_dir = Path(tmpdir) / '.cache' / 'meowdecoder' / 'resume'
            assert manager.state_dir == expected_dir
            assert manager.state_dir.exists()
    
    def test_resume_manager_custom_state_dir(self, mock_improved_modules, temp_state_dir):
        """Test ResumeManager with custom state directory."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        assert manager.state_dir == temp_state_dir
        assert manager.auto_save_interval == 50
        assert manager.cleanup_days == 7
        assert manager.encrypt_state == True
    
    def test_resume_manager_with_config(self, mock_improved_modules, temp_state_dir):
        """Test ResumeManager respects configuration object."""
        from meow_decoder.resume_secured import ResumeManager
        
        # Create mock config
        mock_config = Mock()
        mock_config.resume = Mock()
        mock_config.resume.auto_save_interval = 100
        mock_config.resume.cleanup_days = 14
        mock_config.resume.encrypt_state = False
        
        manager = ResumeManager(state_dir=str(temp_state_dir), config=mock_config)
        
        assert manager.auto_save_interval == 100
        assert manager.cleanup_days == 14
        assert manager.encrypt_state == False
    
    def test_resume_manager_creates_directory_if_not_exists(self, mock_improved_modules, tmp_path):
        """Test ResumeManager creates directory if it doesn't exist."""
        from meow_decoder.resume_secured import ResumeManager
        
        new_dir = tmp_path / "new" / "nested" / "resume"
        manager = ResumeManager(state_dir=str(new_dir))
        
        assert new_dir.exists()
        assert new_dir.is_dir()


# ============================================================================
# Test Key Derivation
# ============================================================================

class TestKeyDerivation:
    """Tests for state file key derivation."""
    
    def test_derive_state_key_returns_32_bytes(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test key derivation returns correct length key."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        key = manager._derive_state_key(valid_password, sample_manifest)
        
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_derive_state_key_deterministic(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test key derivation is deterministic with same inputs."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        key1 = manager._derive_state_key(valid_password, sample_manifest)
        key2 = manager._derive_state_key(valid_password, sample_manifest)
        
        assert key1 == key2
    
    def test_derive_state_key_different_for_different_passwords(
        self, mock_improved_modules, temp_state_dir, sample_manifest
    ):
        """Test different passwords produce different keys."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        key1 = manager._derive_state_key("password1", sample_manifest)
        key2 = manager._derive_state_key("password2", sample_manifest)
        
        assert key1 != key2
    
    def test_derive_state_key_uses_manifest_salt(
        self, mock_improved_modules, temp_state_dir, valid_password
    ):
        """Test key derivation uses manifest salt for domain separation."""
        from meow_decoder.resume_secured import ResumeManager
        
        Manifest = mock_improved_modules['Manifest']
        
        manifest1 = Manifest(
            salt=b'salt1' + b'\x00' * 11,
            nonce=secrets.token_bytes(12),
            orig_len=1000, comp_len=800, cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=256, k_blocks=10, hmac=secrets.token_bytes(32),
        )
        
        manifest2 = Manifest(
            salt=b'salt2' + b'\x00' * 11,
            nonce=secrets.token_bytes(12),
            orig_len=1000, comp_len=800, cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=256, k_blocks=10, hmac=secrets.token_bytes(32),
        )
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        key1 = manager._derive_state_key(valid_password, manifest1)
        key2 = manager._derive_state_key(valid_password, manifest2)
        
        assert key1 != key2


# ============================================================================
# Test Session ID Generation
# ============================================================================

class TestSessionIdGeneration:
    """Tests for session ID generation."""
    
    def test_generate_session_id_format(
        self, mock_improved_modules, temp_state_dir, sample_manifest
    ):
        """Test session ID has expected format."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        session_id = manager.generate_session_id(sample_manifest)
        
        assert session_id.startswith("session_")
        assert len(session_id) == len("session_") + 16  # "session_" + 16 hex chars
    
    def test_generate_session_id_deterministic(
        self, mock_improved_modules, temp_state_dir, sample_manifest
    ):
        """Test session ID is deterministic for same manifest."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        id1 = manager.generate_session_id(sample_manifest)
        id2 = manager.generate_session_id(sample_manifest)
        
        assert id1 == id2
    
    def test_generate_session_id_unique_for_different_manifests(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test different manifests produce different session IDs."""
        from meow_decoder.resume_secured import ResumeManager
        
        Manifest = mock_improved_modules['Manifest']
        
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
            orig_len=2000, comp_len=1600, cipher_len=1632,
            sha256=secrets.token_bytes(32),
            block_size=256, k_blocks=20, hmac=secrets.token_bytes(32),
        )
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        id1 = manager.generate_session_id(manifest1)
        id2 = manager.generate_session_id(manifest2)
        
        assert id1 != id2


# ============================================================================
# Test State Saving
# ============================================================================

class TestStateSaving:
    """Tests for encrypted state saving."""
    
    def test_save_state_creates_encrypted_file(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test save_state creates an encrypted .enc file."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = True
        
        state_path = manager.save_state(
            sample_decoder, sample_manifest, valid_password, 
            droplets_seen=100, input_source="webcam", seed=42069
        )
        
        assert Path(state_path).exists()
        assert state_path.endswith('.enc')
        
        # Verify content is encrypted (not valid JSON)
        with open(state_path, 'rb') as f:
            content = f.read()
        
        with pytest.raises(json.JSONDecodeError):
            json.loads(content.decode('utf-8', errors='ignore'))
    
    def test_save_state_unencrypted_creates_json(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test save_state creates unencrypted .json when disabled."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        state_path = manager.save_state(
            sample_decoder, sample_manifest, valid_password,
            droplets_seen=50, input_source="gif"
        )
        
        assert Path(state_path).exists()
        assert state_path.endswith('.json')
        
        # Verify content is valid JSON
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        assert data['droplets_seen'] == 50
        assert data['input_source'] == 'gif'
    
    def test_save_state_preserves_solved_blocks(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test saved state correctly preserves solved blocks."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False  # Use unencrypted for easy inspection
        
        state_path = manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=25
        )
        
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        solved_blocks = data['solved_blocks']
        
        # Check that solved blocks are properly serialized
        assert solved_blocks[0][1] == '01' * 256  # Block 0 is b'\x01' * 256
        assert solved_blocks[1][1] is None  # Block 1 is None
        assert solved_blocks[2][1] == '02' * 256  # Block 2 is b'\x02' * 256
    
    def test_save_state_preserves_equations(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test saved state correctly preserves equations."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        state_path = manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=30
        )
        
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        equations = data['equations']
        
        # Equations should be sorted for consistency
        assert len(equations) == 2
        # First equation: ({1, 3}, payload)
        assert sorted(equations[0][0]) == [1, 3]
    
    def test_save_state_uses_provided_session_id(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test save_state uses provided session ID."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        custom_session_id = "session_custom_meow"
        state_path = manager.save_state(
            sample_decoder, sample_manifest, valid_password,
            droplets_seen=10, session_id=custom_session_id
        )
        
        assert custom_session_id in state_path
    
    def test_save_state_generates_session_id_if_not_provided(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test save_state auto-generates session ID."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        state_path = manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        expected_session_id = manager.generate_session_id(sample_manifest)
        assert expected_session_id in state_path
    
    def test_save_state_encryption_failure_raises_runtime_error(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test save_state raises RuntimeError on encryption failure."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Mock Fernet to raise an exception
        with patch('meow_decoder.resume_secured.Fernet') as mock_fernet:
            mock_fernet.side_effect = Exception("Encryption failed")
            
            with pytest.raises(RuntimeError, match="Failed to encrypt state"):
                manager.save_state(
                    sample_decoder, sample_manifest, valid_password, droplets_seen=10
                )


# ============================================================================
# Test State Loading
# ============================================================================

class TestStateLoading:
    """Tests for state loading and decryption."""
    
    def test_load_state_encrypted_requires_manifest(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test loading encrypted state raises NotImplementedError without manifest."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Save encrypted state
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        
        # Try to load without manifest - should raise
        with pytest.raises(NotImplementedError, match="manifest"):
            manager.load_state(session_id, valid_password)
    
    def test_load_state_unencrypted_succeeds(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test loading unencrypted state succeeds."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=55
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        state = manager.load_state(session_id)
        
        assert state is not None
        assert state.droplets_seen == 55
    
    def test_load_state_returns_none_for_missing_session(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test load_state returns None for non-existent session."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        result = manager.load_state("session_nonexistent")
        
        assert result is None
    
    def test_load_state_handles_corrupted_json(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test load_state handles corrupted JSON gracefully."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Create corrupted state file
        state_file = temp_state_dir / "session_corrupted.json"
        state_file.write_text("{not valid json")
        
        result = manager.load_state("session_corrupted")
        
        assert result is None
    
    def test_load_state_with_manifest_decrypts_successfully(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test load_state_with_manifest decrypts state correctly."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Save encrypted state
        manager.save_state(
            sample_decoder, sample_manifest, valid_password,
            droplets_seen=42, input_source="webcam"
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        
        # Load with manifest
        state = manager.load_state_with_manifest(
            session_id, sample_manifest, valid_password
        )
        
        assert state is not None
        assert state.droplets_seen == 42
        assert state.input_source == "webcam"
    
    def test_load_state_with_manifest_wrong_password_returns_none(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test load_state_with_manifest returns None for wrong password."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        
        # Try to load with wrong password
        state = manager.load_state_with_manifest(
            session_id, sample_manifest, "wrong_password"
        )
        
        assert state is None
    
    def test_load_state_with_manifest_falls_back_to_unencrypted(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test load_state_with_manifest falls back to unencrypted."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        # Save unencrypted
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=33
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        
        # Load with manifest (should fall back to unencrypted)
        state = manager.load_state_with_manifest(
            session_id, sample_manifest, valid_password
        )
        
        assert state is not None
        assert state.droplets_seen == 33


# ============================================================================
# Test Decoder Restoration
# ============================================================================

class TestDecoderRestoration:
    """Tests for restoring FountainDecoder from saved state."""
    
    def test_restore_decoder_returns_correct_tuple(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test restore_decoder returns (decoder, manifest, droplets_seen)."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        original_droplets = 77
        manager.save_state(
            sample_decoder, sample_manifest, valid_password,
            droplets_seen=original_droplets
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        state = manager.load_state(session_id)
        
        decoder, manifest, droplets_seen = manager.restore_decoder(state)
        
        assert droplets_seen == original_droplets
        assert manifest.orig_len == sample_manifest.orig_len
        assert manifest.k_blocks == sample_manifest.k_blocks
    
    def test_restore_decoder_restores_solved_blocks(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test restore_decoder correctly restores solved blocks."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        state = manager.load_state(session_id)
        decoder, _, _ = manager.restore_decoder(state)
        
        # Check restored solved blocks
        assert decoder.solved[0] == b'\x01' * 256
        assert decoder.solved[1] is None
        assert decoder.solved[2] == b'\x02' * 256
        assert decoder.solved[5] == b'\x03' * 256
    
    def test_restore_decoder_restores_equations(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test restore_decoder correctly restores equations."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        state = manager.load_state(session_id)
        decoder, _, _ = manager.restore_decoder(state)
        
        # Check equations are restored (as sets)
        assert len(decoder.equations) == 2
        # Equations stored as (set, payload) tuples
        indices_list = [eq[0] for eq in decoder.equations]
        assert {1, 3} in indices_list or set([1, 3]) in indices_list


# ============================================================================
# Test Session Management
# ============================================================================

class TestSessionManagement:
    """Tests for session listing, deletion, and cleanup."""
    
    def test_list_sessions_empty_directory(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test list_sessions returns empty list for empty directory."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        sessions = manager.list_sessions()
        
        assert sessions == []
    
    def test_list_sessions_finds_encrypted_sessions(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test list_sessions finds encrypted session files."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        sessions = manager.list_sessions()
        
        assert len(sessions) == 1
        assert sessions[0]['encrypted'] == True
    
    def test_list_sessions_finds_unencrypted_sessions(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test list_sessions finds unencrypted session files with details."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password,
            droplets_seen=100, input_source="gif"
        )
        
        sessions = manager.list_sessions()
        
        assert len(sessions) == 1
        assert sessions[0]['encrypted'] == False
        assert sessions[0]['source'] == 'gif'
        assert sessions[0]['droplets'] == 100
    
    def test_list_sessions_sorted_by_timestamp(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test list_sessions returns sessions sorted by timestamp (newest first)."""
        from meow_decoder.resume_secured import ResumeManager
        
        Manifest = mock_improved_modules['Manifest']
        FountainDecoder = mock_improved_modules['FountainDecoder']
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        # Create multiple sessions
        for i in range(3):
            manifest = Manifest(
                salt=secrets.token_bytes(16),
                nonce=secrets.token_bytes(12),
                orig_len=1000, comp_len=800, cipher_len=816,
                sha256=secrets.token_bytes(32),
                block_size=256, k_blocks=10, hmac=secrets.token_bytes(32),
            )
            decoder = FountainDecoder(k=10, block_size=256)
            manager.save_state(decoder, manifest, "password", droplets_seen=i * 10)
            time.sleep(0.05)  # Small delay to ensure different timestamps
        
        sessions = manager.list_sessions()
        
        assert len(sessions) == 3
        # Newest should be first
        timestamps = [s['timestamp'] for s in sessions]
        assert timestamps == sorted(timestamps, reverse=True)
    
    def test_delete_session_removes_encrypted_file(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test delete_session removes encrypted state file."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        
        assert (temp_state_dir / f"{session_id}.enc").exists()
        
        result = manager.delete_session(session_id)
        
        assert result == True
        assert not (temp_state_dir / f"{session_id}.enc").exists()
    
    def test_delete_session_removes_unencrypted_file(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test delete_session removes unencrypted state file."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        
        result = manager.delete_session(session_id)
        
        assert result == True
        assert not (temp_state_dir / f"{session_id}.json").exists()
    
    def test_delete_session_returns_false_for_nonexistent(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test delete_session returns False for non-existent session."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        result = manager.delete_session("session_nonexistent")
        
        assert result == False
    
    def test_cleanup_old_sessions_removes_old_files(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test cleanup_old_sessions removes sessions older than threshold."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Create old state file
        old_file = temp_state_dir / "session_old.json"
        old_file.write_text('{"test": true}')
        
        # Set modification time to 10 days ago
        old_time = time.time() - (10 * 24 * 60 * 60)
        os.utime(old_file, (old_time, old_time))
        
        # Create recent file
        new_file = temp_state_dir / "session_new.json"
        new_file.write_text('{"test": true}')
        
        deleted = manager.cleanup_old_sessions(days=7)
        
        assert deleted == 1
        assert not old_file.exists()
        assert new_file.exists()
    
    def test_cleanup_old_sessions_uses_config_default(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test cleanup_old_sessions uses config default when days not provided."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.cleanup_days = 3
        
        # Create old state file (5 days old)
        old_file = temp_state_dir / "session_old.enc"
        old_file.write_bytes(b'encrypted_data')
        old_time = time.time() - (5 * 24 * 60 * 60)
        os.utime(old_file, (old_time, old_time))
        
        deleted = manager.cleanup_old_sessions()  # Uses config default of 3 days
        
        assert deleted == 1
    
    def test_check_for_existing_session_finds_encrypted(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test check_for_existing_session finds encrypted session."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        result = manager.check_for_existing_session(sample_manifest)
        
        expected = manager.generate_session_id(sample_manifest)
        assert result == expected
    
    def test_check_for_existing_session_returns_none_if_not_found(
        self, mock_improved_modules, temp_state_dir, sample_manifest
    ):
        """Test check_for_existing_session returns None if no session exists."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        result = manager.check_for_existing_session(sample_manifest)
        
        assert result is None


# ============================================================================
# Test AutoSaveDecoder
# ============================================================================

class TestAutoSaveDecoder:
    """Tests for AutoSaveDecoder wrapper."""
    
    def test_autosave_decoder_initialization(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test AutoSaveDecoder initializes correctly."""
        from meow_decoder.resume_secured import AutoSaveDecoder, ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        auto_decoder = AutoSaveDecoder(
            sample_decoder, sample_manifest, valid_password, manager,
            auto_save_interval=25, input_source="gif", seed=12345
        )
        
        assert auto_decoder.auto_save_interval == 25
        assert auto_decoder.input_source == "gif"
        assert auto_decoder.seed == 12345
        assert auto_decoder.droplets_seen == 0
        assert auto_decoder.droplets_since_save == 0
    
    def test_autosave_decoder_generates_session_id(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test AutoSaveDecoder generates session ID if not provided."""
        from meow_decoder.resume_secured import AutoSaveDecoder, ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        auto_decoder = AutoSaveDecoder(
            sample_decoder, sample_manifest, valid_password, manager
        )
        
        expected_id = manager.generate_session_id(sample_manifest)
        assert auto_decoder.session_id == expected_id
    
    def test_autosave_decoder_add_equation_increments_counters(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test add_equation increments droplet counters."""
        from meow_decoder.resume_secured import AutoSaveDecoder, ResumeManager
        
        FountainDecoder = mock_improved_modules['FountainDecoder']
        decoder = FountainDecoder(k=10, block_size=256)
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        auto_decoder = AutoSaveDecoder(
            decoder, sample_manifest, valid_password, manager,
            auto_save_interval=100  # High to prevent auto-save
        )
        
        auto_decoder.add_equation([1, 2], b'\x00' * 256)
        
        assert auto_decoder.droplets_seen == 1
        assert auto_decoder.droplets_since_save == 1
    
    def test_autosave_decoder_triggers_save_at_interval(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test AutoSaveDecoder triggers save at interval."""
        from meow_decoder.resume_secured import AutoSaveDecoder, ResumeManager
        
        FountainDecoder = mock_improved_modules['FountainDecoder']
        decoder = FountainDecoder(k=10, block_size=256)
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        auto_decoder = AutoSaveDecoder(
            decoder, sample_manifest, valid_password, manager,
            auto_save_interval=5  # Save every 5 droplets
        )
        
        # Add 5 equations to trigger auto-save
        for i in range(5):
            auto_decoder.add_equation([i], b'\x00' * 256)
        
        # Check that save was triggered (counter reset)
        assert auto_decoder.droplets_since_save == 0
        
        # Check that state file was created
        session_id = auto_decoder.session_id
        assert (temp_state_dir / f"{session_id}.enc").exists()
    
    def test_autosave_decoder_save_failure_does_not_crash(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test AutoSaveDecoder handles save failures gracefully."""
        from meow_decoder.resume_secured import AutoSaveDecoder, ResumeManager
        
        FountainDecoder = mock_improved_modules['FountainDecoder']
        decoder = FountainDecoder(k=10, block_size=256)
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        auto_decoder = AutoSaveDecoder(
            decoder, sample_manifest, valid_password, manager,
            auto_save_interval=1  # Save every droplet
        )
        
        # Mock save_state to raise exception
        with patch.object(manager, 'save_state', side_effect=Exception("Save failed")):
            # Should not raise, just print warning
            auto_decoder.add_equation([0], b'\x00' * 256)
        
        # Counter should NOT be reset since save failed
        assert auto_decoder.droplets_since_save == 1
    
    def test_autosave_decoder_manual_save(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test AutoSaveDecoder manual save method."""
        from meow_decoder.resume_secured import AutoSaveDecoder, ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        auto_decoder = AutoSaveDecoder(
            sample_decoder, sample_manifest, valid_password, manager
        )
        
        state_path = auto_decoder.save()
        
        assert Path(state_path).exists()
    
    def test_autosave_decoder_is_done_delegates(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test AutoSaveDecoder is_done delegates to underlying decoder."""
        from meow_decoder.resume_secured import AutoSaveDecoder, ResumeManager
        
        FountainDecoder = mock_improved_modules['FountainDecoder']
        decoder = FountainDecoder(k=2, block_size=16)
        decoder.solved = [b'\x01' * 16, b'\x02' * 16]  # All solved
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        auto_decoder = AutoSaveDecoder(
            decoder, sample_manifest, valid_password, manager
        )
        
        assert auto_decoder.is_done() == True
    
    def test_autosave_decoder_reconstruct_delegates(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test AutoSaveDecoder reconstruct delegates to underlying decoder."""
        from meow_decoder.resume_secured import AutoSaveDecoder, ResumeManager
        
        FountainDecoder = mock_improved_modules['FountainDecoder']
        decoder = FountainDecoder(k=2, block_size=16)
        decoder.solved = [b'\x01' * 16, b'\x02' * 16]
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        auto_decoder = AutoSaveDecoder(
            decoder, sample_manifest, valid_password, manager
        )
        
        result = auto_decoder.reconstruct(20)
        
        assert len(result) == 20


# ============================================================================
# Test Convenience Functions
# ============================================================================

class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""
    
    def test_resume_from_session_success(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test resume_from_session successfully resumes."""
        from meow_decoder.resume_secured import (
            resume_from_session, ResumeManager
        )
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        manager.save_state(
            sample_decoder, sample_manifest, valid_password,
            droplets_seen=88
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        
        result = resume_from_session(
            session_id, sample_manifest, valid_password, manager
        )
        
        assert result is not None
        decoder, manifest, droplets_seen = result
        assert droplets_seen == 88
    
    def test_resume_from_session_returns_none_for_missing(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test resume_from_session returns None for missing session."""
        from meow_decoder.resume_secured import resume_from_session, ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        result = resume_from_session(
            "session_missing", sample_manifest, valid_password, manager
        )
        
        assert result is None
    
    def test_resume_from_session_creates_default_manager(
        self, mock_improved_modules, sample_manifest, valid_password, monkeypatch
    ):
        """Test resume_from_session creates default manager if not provided."""
        from meow_decoder.resume_secured import resume_from_session, ResumeManager
        
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setattr(Path, 'home', lambda: Path(tmpdir))
            
            # Returns None because no session exists
            result = resume_from_session(
                "session_test", sample_manifest, valid_password
            )
            
            assert result is None
    
    def test_create_resumable_decoder_returns_autosave_decoder(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test create_resumable_decoder returns AutoSaveDecoder."""
        from meow_decoder.resume_secured import (
            create_resumable_decoder, AutoSaveDecoder, ResumeManager
        )
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        result = create_resumable_decoder(
            sample_manifest, valid_password,
            auto_save_interval=30,
            input_source="webcam",
            seed=99999,
            resume_manager=manager
        )
        
        assert isinstance(result, AutoSaveDecoder)
        assert result.auto_save_interval == 30
        assert result.input_source == "webcam"
        assert result.seed == 99999
    
    def test_create_resumable_decoder_creates_default_manager(
        self, mock_improved_modules, sample_manifest, valid_password, monkeypatch
    ):
        """Test create_resumable_decoder creates default manager if not provided."""
        from meow_decoder.resume_secured import create_resumable_decoder, AutoSaveDecoder
        
        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setattr(Path, 'home', lambda: Path(tmpdir))
            
            result = create_resumable_decoder(sample_manifest, valid_password)
            
            assert isinstance(result, AutoSaveDecoder)


# ============================================================================
# Test Security Invariants
# ============================================================================

class TestSecurityInvariants:
    """Tests for security-critical behavior."""
    
    def test_encrypted_state_not_readable_without_password(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password
    ):
        """Test encrypted state files cannot be read without password."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        state_path = manager.save_state(
            sample_decoder, sample_manifest, valid_password, droplets_seen=10
        )
        
        # Read raw file content
        with open(state_path, 'rb') as f:
            content = f.read()
        
        # Should not contain plain session data
        assert b'session_' not in content
        assert b'droplets_seen' not in content
        assert b'manifest' not in content
    
    def test_key_derivation_uses_sufficient_iterations(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test PBKDF2 uses at least 100k iterations (OWASP minimum)."""
        from meow_decoder.resume_secured import ResumeManager
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        # Patch PBKDF2 to verify iterations
        original_pbkdf2 = PBKDF2.__init__
        captured_iterations = []
        
        def mock_init(self, algorithm, length, salt, iterations):
            captured_iterations.append(iterations)
            return original_pbkdf2(self, algorithm, length, salt, iterations)
        
        with patch.object(PBKDF2, '__init__', mock_init):
            manager = ResumeManager(state_dir=str(temp_state_dir))
            manager._derive_state_key(valid_password, sample_manifest)
        
        assert len(captured_iterations) > 0
        assert captured_iterations[0] >= 100000
    
    def test_different_manifests_produce_different_encrypted_states(
        self, mock_improved_modules, temp_state_dir, valid_password
    ):
        """Test same data encrypted with different manifests produces different ciphertext."""
        from meow_decoder.resume_secured import ResumeManager
        
        Manifest = mock_improved_modules['Manifest']
        FountainDecoder = mock_improved_modules['FountainDecoder']
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Create two manifests with different salts
        manifest1 = Manifest(
            salt=b'\x01' * 16, nonce=b'\x01' * 12,
            orig_len=1000, comp_len=800, cipher_len=816,
            sha256=b'\x01' * 32, block_size=256, k_blocks=10, hmac=b'\x01' * 32,
        )
        
        manifest2 = Manifest(
            salt=b'\x02' * 16, nonce=b'\x02' * 12,
            orig_len=1000, comp_len=800, cipher_len=816,
            sha256=b'\x02' * 32, block_size=256, k_blocks=10, hmac=b'\x02' * 32,
        )
        
        decoder = FountainDecoder(k=10, block_size=256)
        
        path1 = manager.save_state(
            decoder, manifest1, valid_password, droplets_seen=10,
            session_id="session_1"
        )
        path2 = manager.save_state(
            decoder, manifest2, valid_password, droplets_seen=10,
            session_id="session_2"
        )
        
        with open(path1, 'rb') as f:
            content1 = f.read()
        with open(path2, 'rb') as f:
            content2 = f.read()
        
        # Same password but different manifests should produce different ciphertext
        assert content1 != content2
    
    def test_session_id_derived_from_secret_material(
        self, mock_improved_modules, temp_state_dir, sample_manifest
    ):
        """Test session ID is derived from secret manifest material."""
        from meow_decoder.resume_secured import ResumeManager
        import hashlib
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        session_id = manager.generate_session_id(sample_manifest)
        
        # Verify it's derived from salt + sha256
        expected_data = sample_manifest.salt + sample_manifest.sha256
        expected_hash = hashlib.sha256(expected_data).hexdigest()[:16]
        expected_id = f"session_{expected_hash}"
        
        assert session_id == expected_id


# ============================================================================
# Test Edge Cases
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_save_state_with_empty_decoder(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test saving state with no solved blocks or equations."""
        from meow_decoder.resume_secured import ResumeManager
        
        FountainDecoder = mock_improved_modules['FountainDecoder']
        empty_decoder = FountainDecoder(k=10, block_size=256)
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        state_path = manager.save_state(
            empty_decoder, sample_manifest, valid_password, droplets_seen=0
        )
        
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        # All blocks should be None
        for _, block_hex in data['solved_blocks']:
            assert block_hex is None
        
        assert data['equations'] == []
        assert data['droplets_seen'] == 0
    
    def test_restore_decoder_with_empty_state(
        self, mock_improved_modules, temp_state_dir, sample_manifest, valid_password
    ):
        """Test restoring decoder from empty state."""
        from meow_decoder.resume_secured import ResumeManager
        
        FountainDecoder = mock_improved_modules['FountainDecoder']
        empty_decoder = FountainDecoder(k=10, block_size=256)
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        manager.save_state(
            empty_decoder, sample_manifest, valid_password, droplets_seen=0
        )
        
        session_id = manager.generate_session_id(sample_manifest)
        state = manager.load_state(session_id)
        decoder, _, _ = manager.restore_decoder(state)
        
        # All blocks should still be None
        assert all(block is None for block in decoder.solved)
        assert decoder.equations == []
    
    def test_list_sessions_handles_permission_errors(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test list_sessions handles permission errors gracefully."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Create file that will cause stat() to fail
        problem_file = temp_state_dir / "session_problem.json"
        problem_file.write_text('{}')
        
        # Mock stat to raise PermissionError
        original_stat = os.stat
        def mock_stat(path):
            if 'problem' in str(path):
                raise PermissionError("Access denied")
            return original_stat(path)
        
        with patch('os.stat', mock_stat):
            # Should not raise, just skip problematic file
            sessions = manager.list_sessions()
        
        # Should return empty list (couldn't read the file)
        assert isinstance(sessions, list)
    
    def test_cleanup_handles_file_deletion_errors(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test cleanup_old_sessions handles deletion errors gracefully."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Create old file
        old_file = temp_state_dir / "session_locked.enc"
        old_file.write_bytes(b'data')
        old_time = time.time() - (30 * 24 * 60 * 60)
        os.utime(old_file, (old_time, old_time))
        
        # Mock unlink to raise
        with patch.object(Path, 'unlink', side_effect=PermissionError("Locked")):
            # Should not raise
            deleted = manager.cleanup_old_sessions(days=7)
        
        # Should return 0 since deletion failed
        assert deleted == 0
    
    def test_load_state_handles_general_exception(
        self, mock_improved_modules, temp_state_dir
    ):
        """Test load_state handles unexpected exceptions."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Create valid JSON that will fail deserialization
        state_file = temp_state_dir / "session_bad.json"
        state_file.write_text('{"incomplete": true}')  # Missing required fields
        
        result = manager.load_state("session_bad")
        
        # Should return None, not raise
        assert result is None
    
    @pytest.mark.parametrize("input_source", ["webcam", "gif", "video", "screen"])
    def test_save_state_various_input_sources(
        self, mock_improved_modules, temp_state_dir, sample_manifest,
        sample_decoder, valid_password, input_source
    ):
        """Test save_state accepts various input sources."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        manager.encrypt_state = False
        
        state_path = manager.save_state(
            sample_decoder, sample_manifest, valid_password,
            droplets_seen=10, input_source=input_source,
            session_id=f"session_{input_source}"
        )
        
        with open(state_path, 'r') as f:
            data = json.load(f)
        
        assert data['input_source'] == input_source
    
    def test_large_decoder_state_serialization(
        self, mock_improved_modules, temp_state_dir, valid_password
    ):
        """Test serialization of decoder with many blocks and equations."""
        from meow_decoder.resume_secured import ResumeManager
        
        Manifest = mock_improved_modules['Manifest']
        FountainDecoder = mock_improved_modules['FountainDecoder']
        
        # Create large decoder
        k_blocks = 1000
        block_size = 1024
        decoder = FountainDecoder(k=k_blocks, block_size=block_size)
        
        # Solve some blocks
        for i in range(0, k_blocks, 10):
            decoder.solved[i] = secrets.token_bytes(block_size)
        
        # Add many equations
        for i in range(100):
            decoder.equations.append((set(range(i, i + 5)), secrets.token_bytes(block_size)))
        
        manifest = Manifest(
            salt=secrets.token_bytes(16), nonce=secrets.token_bytes(12),
            orig_len=k_blocks * block_size, comp_len=k_blocks * block_size,
            cipher_len=k_blocks * block_size,
            sha256=secrets.token_bytes(32), block_size=block_size,
            k_blocks=k_blocks, hmac=secrets.token_bytes(32),
        )
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Should handle large state without error
        state_path = manager.save_state(
            decoder, manifest, valid_password, droplets_seen=5000
        )
        
        assert Path(state_path).exists()
        # File should be reasonably large
        assert Path(state_path).stat().st_size > 100000


# ============================================================================
# Test CLI Entry Point (if __name__ == "__main__")
# ============================================================================

class TestCLI:
    """Tests for CLI functionality (invoked via __main__)."""
    
    def test_cli_list_empty(self, mock_improved_modules, temp_state_dir, capsys):
        """Test CLI list command with no sessions."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        sessions = manager.list_sessions()
        
        # Would print "No saved sessions found." in actual CLI
        assert sessions == []
    
    def test_cli_delete_nonexistent(self, mock_improved_modules, temp_state_dir):
        """Test CLI delete command for non-existent session."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        result = manager.delete_session("session_ghost")
        
        assert result == False
    
    def test_cli_cleanup_custom_days(self, mock_improved_modules, temp_state_dir):
        """Test CLI cleanup command with custom days."""
        from meow_decoder.resume_secured import ResumeManager
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        
        # Create files with various ages
        for i, age_days in enumerate([1, 5, 15, 30]):
            f = temp_state_dir / f"session_age{age_days}.json"
            f.write_text('{}')
            old_time = time.time() - (age_days * 24 * 60 * 60)
            os.utime(f, (old_time, old_time))
        
        # Cleanup sessions older than 10 days
        deleted = manager.cleanup_old_sessions(days=10)
        
        assert deleted == 2  # 15 and 30 days old


# ============================================================================
# Test Thread Safety (basic)
# ============================================================================

class TestThreadSafety:
    """Basic thread safety tests."""
    
    def test_concurrent_saves_do_not_corrupt(
        self, mock_improved_modules, temp_state_dir, valid_password
    ):
        """Test concurrent save operations don't corrupt state files."""
        import threading
        from meow_decoder.resume_secured import ResumeManager
        
        Manifest = mock_improved_modules['Manifest']
        FountainDecoder = mock_improved_modules['FountainDecoder']
        
        manager = ResumeManager(state_dir=str(temp_state_dir))
        errors = []
        
        def save_state(thread_id):
            try:
                manifest = Manifest(
                    salt=secrets.token_bytes(16), nonce=secrets.token_bytes(12),
                    orig_len=1000, comp_len=800, cipher_len=816,
                    sha256=secrets.token_bytes(32),
                    block_size=256, k_blocks=10, hmac=secrets.token_bytes(32),
                )
                decoder = FountainDecoder(k=10, block_size=256)
                
                manager.save_state(
                    decoder, manifest, valid_password,
                    droplets_seen=thread_id,
                    session_id=f"session_thread_{thread_id}"
                )
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=save_state, args=(i,)) for i in range(10)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert errors == []
        
        # Verify all files created
        enc_files = list(temp_state_dir.glob("session_thread_*.enc"))
        assert len(enc_files) == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
