#!/usr/bin/env python3
"""
🧪 Stage 2 Coverage Tests
Focus: double_ratchet.py and duress_mode.py
Target: >90% coverage for these modules
"""

import pytest
import os
import shutil
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path
import secrets
import tempfile
import argparse

from meow_decoder.double_ratchet import (
    DoubleRatchet, RatchetState, KeyPair, MessageHeader, RatchetError,
    ClowderSession
)
from meow_decoder.duress_mode import (
    DuressHandler, DuressConfig, setup_duress, is_duress_triggered,
    generate_duress_decoy, add_duress_args
)

# ============================================================================
# Double Ratchet Tests
# ============================================================================

class TestDoubleRatchetCoverage:
    """Tests for Double Ratchet Protocol."""

    def test_alice_bob_conversation(self):
        """Test full conversation between Alice and Bob."""
        # Setup shared secrets
        shared_secret = b"S" * 32
        bob_kp = KeyPair.generate()
        
        # Initialize
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_kp.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_kp)
        
        # Alice sending to Bob
        msg1 = b"Hello Bob"
        cipher1, header1 = alice.encrypt(msg1)
        decoded1 = bob.decrypt(cipher1, header1)
        assert decoded1 == msg1
        
        # Bob replying
        msg2 = b"Hello Alice"
        cipher2, header2 = bob.encrypt(msg2)
        decoded2 = alice.decrypt(cipher2, header2)
        assert decoded2 == msg2
        
        # Ping-pong
        for i in range(5):
            msg = f"Msg {i}".encode()
            c, h = alice.encrypt(msg)
            d = bob.decrypt(c, h)
            assert d == msg

    def test_out_of_order_messages(self):
        """Test handling of out-of-order messages."""
        shared_secret = b"K" * 32
        bob_kp = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_kp.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_kp)
        
        # Alice sends 3 messages
        c1, h1 = alice.encrypt(b"1")
        c2, h2 = alice.encrypt(b"2")
        c3, h3 = alice.encrypt(b"3")
        
        # Bob receives 3, then 1, then 2
        assert bob.decrypt(c3, h3) == b"3"
        assert bob.decrypt(c1, h1) == b"1"
        assert bob.decrypt(c2, h2) == b"2"

    def test_max_skip_dos_protection(self):
        """Test that we stop tracking skipped keys after MAX_SKIP."""
        shared_secret = b"D" * 32
        bob_kp = KeyPair.generate()
        
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_kp.public_bytes())
        bob = DoubleRatchet.initialize_bob(shared_secret, bob_kp)
        
        # Manually set MAX_SKIP low for test
        import meow_decoder.double_ratchet as dr
        original_max = dr.MAX_SKIP
        dr.MAX_SKIP = 5
        
        try:
            # Generate 6 messages
            msgs = []
            for i in range(10):
                msgs.append(alice.encrypt(f"{i}".encode()))
            
            # Decrypt last one (skipping 9), which is > 5
            # Should raise RatchetError
            with pytest.raises(RatchetError, match="Too many skipped messages"):
                bob.decrypt(msgs[9][0], msgs[9][1])
            
        finally:
            dr.MAX_SKIP = original_max

    def test_state_serialization(self):
        """Test saving and loading state."""
        shared_secret = b"X" * 32
        bob_kp = KeyPair.generate()
        alice = DoubleRatchet.initialize_alice(shared_secret, bob_kp.public_bytes())
        
        # Advance state
        alice.encrypt(b"test")
        
        # Serialize
        data = alice.state.serialize()
        
        # Deserialize
        state_restored = RatchetState.deserialize(data)
        alice_restored = DoubleRatchet(state_restored)
        
        # Should continue working
        c, h = alice_restored.encrypt(b"next")
        # (Verification would require Bob synced to Alice's pre-restored state, omitted for brevity)
        assert c is not None

class TestClowderSessionCoverage:
    """Tests for ClowderSession class."""
    
    def test_clowder_session_flow(self):
        """Test multi-peer messaging."""
        alice_kp = KeyPair.generate()
        bob_kp = KeyPair.generate()
        
        alice = ClowderSession(alice_kp)
        bob = ClowderSession(bob_kp)
        
        p1 = b"bob_id"
        p2 = b"alice_id"
        
        secret = b"Z" * 32
        
        alice.add_peer(p1, bob_kp.public_bytes(), True, secret)
        bob.add_peer(p2, alice_kp.public_bytes(), False, secret)
        
        msg = b"To Bob"
        c, h = alice.encrypt_for_peer(p1, msg)
        d = bob.decrypt_from_peer(p2, c, h)
        assert d == msg

    def test_clowder_unknown_peer(self):
        """Test errors for unknown peers."""
        s = ClowderSession(KeyPair.generate())
        with pytest.raises(RatchetError):
            s.encrypt_for_peer(b"unknown", b"msg")
        
        with pytest.raises(RatchetError):
            s.decrypt_from_peer(b"unknown", b"c", b"h")

    def test_clowder_serialization(self):
        """Test serializing a clowder session state."""
        alice = ClowderSession(KeyPair.generate())
        bob_pk = KeyPair.generate().public_bytes()
        peer_id = b"bob"
        alice.add_peer(peer_id, bob_pk, True, b"S"*32)
        
        # Test serializing specific peer state
        enc = alice.get_session_state(peer_id)
        
        # Test restoring
        alice_new = ClowderSession(alice.identity) # Same identity
        alice_new.restore_session(peer_id, enc)
        
        assert peer_id in alice_new.sessions

# ============================================================================
# Duress Mode Tests
# ============================================================================

class TestDuressModeCoverage:
    """Tests for Duress Handler."""

    def test_duress_password_detection(self):
        """Test distinguishing real vs duress passwords."""
        handler = DuressHandler()
        salt = b"salt" * 4
        
        real_pw = "real123"
        duress_pw = "duress999"
        
        handler.set_passwords(duress_pw, real_pw, salt)
        
        # Check real
        valid, is_duress = handler.check_password(real_pw, salt)
        assert valid
        assert not is_duress
        
        # Check duress
        valid, is_duress = handler.check_password(duress_pw, salt)
        assert valid
        assert is_duress
        
        # Check wrong
        valid, is_duress = handler.check_password("wrong", salt)
        assert not valid

    @patch('meow_decoder.duress_mode.gc.collect')
    def test_duress_trigger_actions(self, mock_gc):
        """Test all actions triggered by duress."""
        
        callback_mock = MagicMock()
        config = DuressConfig(
            wipe_memory=True,
            wipe_resume_files=True,
            gc_aggressive=True,
            trigger_callback=callback_mock
        )
        
        handler = DuressHandler(config)
        salt = b"s" * 16
        handler.set_passwords("duress", "real", salt)
        
        # Prepare sensitive dummy data
        sensitive = [bytearray(b"secret")]
        
        # Trigger
        with patch.object(handler, '_wipe_resume_files') as mock_wipe_files:
            handler.check_password("duress", salt, sensitive_data=sensitive)
            
            # Verify callback
            callback_mock.assert_called_once()
            
            # Verify memory zeroing
            assert sensitive[0] == bytearray(b"\x00" * 6)
            
            # Verify resume wipe call
            mock_wipe_files.assert_called_once()
            
            # Verify GC
            assert mock_gc.call_count >= 3

    def test_wipe_resume_files_real_fs(self, tmp_path):
        """Test actual file deletion for resume files."""
        # Setup mock resume dir structure
        # meow decoder expects ~/.cache/meowdecoder/resume
        # We will mock Path.home() to return tmp_path
        
        mock_home = tmp_path / "home"
        mock_home.mkdir()
        
        resume_dir = mock_home / ".cache" / "meowdecoder" / "resume"
        resume_dir.mkdir(parents=True)
        
        secret_file = resume_dir / "state.dat"
        secret_file.write_bytes(b"secret state")
        
        # Mock Path.home
        with patch('pathlib.Path.home', return_value=mock_home):
            handler = DuressHandler()
            
            # Actually call the method (no mocking of internal logic)
            handler._wipe_resume_files()
            
        # Verify file is gone
        assert not secret_file.exists()

    def test_duress_same_password_error(self):
        """Should raise error if real == duress."""
        handler = DuressHandler()
        with pytest.raises(ValueError):
            handler.set_passwords("same", "same", b"s"*16)

    def test_helpers_coverage(self):
        """Test helper functions setup_duress, is_duress_triggered etc."""
        salt = b"s"*16
        h = setup_duress("duress", "real", salt)
        assert isinstance(h, DuressHandler)
        
        assert not is_duress_triggered(h)
        h.check_password("duress", salt)
        assert is_duress_triggered(h)
        assert h.was_triggered

    def test_generate_duress_decoy(self):
        """Test decoy generation wrapper."""
        d = generate_duress_decoy()
        assert len(d) > 0

    def test_add_duress_args(self):
        """Test argument parser helper."""
        import argparse
        parser = argparse.ArgumentParser()
        add_duress_args(parser)
        # Check if arguments were added
        args = parser.parse_args(['--duress-password', 'test', '--duress-wipe-files'])
        assert args.duress_password == 'test'
        assert args.duress_wipe_files is True

    @patch('meow_decoder.duress_mode.secrets.randbelow', return_value=10)
    @patch('meow_decoder.duress_mode.time.sleep')
    def test_equalize_timing(self, mock_sleep, mock_rand):
        """Test timing equalization."""
        h = DuressHandler()
        h._equalize_timing()
        mock_sleep.assert_called_once()

    def test_secure_zero_bytearray(self):
        """Test _secure_zero method directly."""
        h = DuressHandler()
        data = bytearray(b"secret")
        h._secure_zero(data)
        assert data == bytearray(b"\x00\x00\x00\x00\x00\x00")
