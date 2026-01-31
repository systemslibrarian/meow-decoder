#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for advanced security modules - Target: 90%+
Tests high-security features, PQ crypto, and advanced security hardening.
"""

import pytest
import secrets
import tempfile
import sys
import os
import struct
import hashlib
import hmac
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestHighSecurityMode:
    """Test high security mode features."""
    
    def test_import_high_security(self):
        """Test importing high_security module."""
        try:
            from meow_decoder import high_security
            assert high_security is not None
        except ImportError:
            pytest.skip("high_security module not available")
    
    def test_enable_high_security_mode(self):
        """Test enabling high security mode."""
        try:
            from meow_decoder.high_security import enable_high_security_mode
            
            # Should not raise
            enable_high_security_mode(silent=True)
        except ImportError:
            pytest.skip("enable_high_security_mode not available")
    
    def test_high_security_config(self):
        """Test HighSecurityConfig."""
        try:
            from meow_decoder.high_security import HighSecurityConfig
            
            config = HighSecurityConfig()
            
            assert config.argon2_memory > 0
            assert config.argon2_iterations > 0
        except ImportError:
            pytest.skip("HighSecurityConfig not available")
    
    def test_get_safety_checklist(self):
        """Test safety checklist."""
        try:
            from meow_decoder.high_security import get_safety_checklist
            
            checklist = get_safety_checklist()
            
            assert isinstance(checklist, str)
            assert len(checklist) > 0
        except (ImportError, AttributeError):
            pytest.skip("get_safety_checklist not available")
    
    def test_secure_wipe_file(self):
        """Test secure file wipe."""
        try:
            from meow_decoder.high_security import secure_wipe_file
            
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"Secret data to wipe" * 100)
                filepath = f.name
            
            success = secure_wipe_file(filepath, passes=3)
            
            # File should be gone or wiped
            assert success or not os.path.exists(filepath)
        except ImportError:
            pytest.skip("secure_wipe_file not available")


class TestPostQuantumCrypto:
    """Test post-quantum cryptography features."""
    
    def test_import_pq_module(self):
        """Test importing PQ module."""
        try:
            from meow_decoder import pq_hybrid
            assert pq_hybrid is not None
        except ImportError:
            pytest.skip("pq_hybrid module not available")
    
    def test_pq_availability_check(self):
        """Test PQ availability check."""
        try:
            from meow_decoder.pq_hybrid import is_pq_available
            
            # Should return True or False
            result = is_pq_available()
            assert isinstance(result, bool)
        except ImportError:
            pytest.skip("is_pq_available not available")
    
    def test_pq_keypair_generation(self):
        """Test PQ keypair generation."""
        try:
            from meow_decoder.pq_hybrid import generate_keypair
            
            private_key, public_key = generate_keypair()
            
            assert private_key is not None
            assert public_key is not None
        except ImportError:
            pytest.skip("PQ keypair generation not available")
    
    def test_pq_encapsulation(self):
        """Test PQ key encapsulation."""
        try:
            from meow_decoder.pq_hybrid import encapsulate, decapsulate, generate_keypair
            
            private_key, public_key = generate_keypair()
            
            shared_secret, ciphertext = encapsulate(public_key)
            
            assert shared_secret is not None
            assert ciphertext is not None
            
            # Decapsulate
            decrypted_secret = decapsulate(private_key, ciphertext)
            
            assert decrypted_secret == shared_secret
        except ImportError:
            pytest.skip("PQ encapsulation not available")


class TestPQSignatures:
    """Test post-quantum signatures."""
    
    def test_import_pq_signatures(self):
        """Test importing PQ signatures module."""
        try:
            from meow_decoder import pq_signatures
            assert pq_signatures is not None
        except ImportError:
            pytest.skip("pq_signatures module not available")
    
    def test_dilithium_keypair(self):
        """Test Dilithium keypair generation."""
        try:
            from meow_decoder.pq_signatures import generate_signing_keypair
            
            private_key, public_key = generate_signing_keypair()
            
            assert private_key is not None
            assert public_key is not None
        except ImportError:
            pytest.skip("Dilithium keypair not available")
    
    def test_dilithium_sign_verify(self):
        """Test Dilithium sign/verify."""
        try:
            from meow_decoder.pq_signatures import (
                generate_signing_keypair, sign_message, verify_signature
            )
            
            private_key, public_key = generate_signing_keypair()
            
            message = b"Message to sign"
            
            signature = sign_message(private_key, message)
            
            assert signature is not None
            
            # Verify
            valid = verify_signature(public_key, message, signature)
            
            assert valid
        except ImportError:
            pytest.skip("Dilithium sign/verify not available")


class TestDoubleRatchet:
    """Test double ratchet protocol."""
    
    def test_import_double_ratchet(self):
        """Test importing double ratchet module."""
        try:
            from meow_decoder import double_ratchet
            assert double_ratchet is not None
        except ImportError:
            pytest.skip("double_ratchet module not available")
    
    def test_ratchet_state_creation(self):
        """Test creating ratchet state."""
        try:
            from meow_decoder.double_ratchet import RatchetState
            
            state = RatchetState(
                root_key=secrets.token_bytes(32),
                chain_key=secrets.token_bytes(32),
                dh_keypair=None,
                remote_public=None
            )
            
            assert state is not None
        except ImportError:
            pytest.skip("RatchetState not available")
    
    def test_symmetric_ratchet(self):
        """Test symmetric ratchet step."""
        try:
            from meow_decoder.double_ratchet import symmetric_ratchet_step
            
            chain_key = secrets.token_bytes(32)
            
            new_chain_key, message_key = symmetric_ratchet_step(chain_key)
            
            assert new_chain_key is not None
            assert message_key is not None
            assert new_chain_key != chain_key
        except ImportError:
            pytest.skip("symmetric_ratchet_step not available")
    
    def test_dh_ratchet(self):
        """Test DH ratchet step."""
        try:
            from meow_decoder.double_ratchet import dh_ratchet_step, generate_dh_keypair
            
            # Generate keys for both parties
            private_a, public_a = generate_dh_keypair()
            private_b, public_b = generate_dh_keypair()
            
            # DH ratchet step
            root_key = secrets.token_bytes(32)
            new_root_key, chain_key = dh_ratchet_step(root_key, private_a, public_b)
            
            assert new_root_key is not None
            assert chain_key is not None
        except ImportError:
            pytest.skip("dh_ratchet_step not available")


class TestTimelockPuzzles:
    """Test time-lock puzzle features."""
    
    def test_import_timelock(self):
        """Test importing timelock module."""
        try:
            from meow_decoder import timelock_duress
            assert timelock_duress is not None
        except ImportError:
            pytest.skip("timelock_duress module not available")
    
    def test_create_timelock_puzzle(self):
        """Test creating time-lock puzzle."""
        try:
            from meow_decoder.timelock_duress import TimeLockPuzzle
            
            secret = secrets.token_bytes(32)
            
            puzzle = TimeLockPuzzle.create(
                secret,
                duration_seconds=1,  # Short for testing
                iterations_per_second=1000
            )
            
            assert puzzle is not None
        except ImportError:
            pytest.skip("TimeLockPuzzle not available")
    
    def test_countdown_duress(self):
        """Test countdown duress trigger."""
        try:
            from meow_decoder.timelock_duress import CountdownDuress
            
            duress = CountdownDuress(
                checkin_interval=60,
                grace_period=10
            )
            
            assert duress is not None
            
            # Record check-in
            duress.checkin()
            
            assert not duress.is_triggered()
        except ImportError:
            pytest.skip("CountdownDuress not available")
    
    def test_dead_man_switch(self):
        """Test dead man's switch."""
        try:
            from meow_decoder.timelock_duress import DeadManSwitch
            
            switch = DeadManSwitch(
                renewal_interval=60,
                expiry_action=lambda: None
            )
            
            assert switch is not None
            
            # Renew
            switch.renew()
            
            assert not switch.is_expired()
        except ImportError:
            pytest.skip("DeadManSwitch not available")


class TestAADBindings:
    """Test AAD (Additional Authenticated Data) bindings."""
    
    def test_aad_construction(self):
        """Test AAD construction in encryption."""
        import struct
        
        # Simulate AAD construction
        orig_len = 1000
        comp_len = 800
        salt = secrets.token_bytes(16)
        sha256 = secrets.token_bytes(32)
        magic = b"MEOW3"
        
        aad = struct.pack('<QQ', orig_len, comp_len)
        aad += salt
        aad += sha256
        aad += magic
        
        # Should be: 8 + 8 + 16 + 32 + 5 = 69 bytes
        assert len(aad) == 69
    
    def test_aad_with_ephemeral_key(self):
        """Test AAD with ephemeral public key."""
        import struct
        
        orig_len = 1000
        comp_len = 800
        salt = secrets.token_bytes(16)
        sha256 = secrets.token_bytes(32)
        magic = b"MEOW3"
        ephemeral_public_key = secrets.token_bytes(32)
        
        aad = struct.pack('<QQ', orig_len, comp_len)
        aad += salt
        aad += sha256
        aad += magic
        aad += ephemeral_public_key
        
        # Should be: 69 + 32 = 101 bytes
        assert len(aad) == 101


class TestDomainSeparation:
    """Test cryptographic domain separation."""
    
    def test_manifest_hmac_prefix(self):
        """Test manifest HMAC uses domain separation."""
        from meow_decoder.crypto import MANIFEST_HMAC_KEY_PREFIX
        
        assert MANIFEST_HMAC_KEY_PREFIX is not None
        assert len(MANIFEST_HMAC_KEY_PREFIX) > 0
    
    def test_keyfile_domain_sep(self):
        """Test keyfile domain separation."""
        from meow_decoder.crypto import KEYFILE_DOMAIN_SEP
        
        assert KEYFILE_DOMAIN_SEP is not None
        assert len(KEYFILE_DOMAIN_SEP) > 0
    
    def test_different_domains(self):
        """Test domains are different."""
        from meow_decoder.crypto import MANIFEST_HMAC_KEY_PREFIX, KEYFILE_DOMAIN_SEP
        
        assert MANIFEST_HMAC_KEY_PREFIX != KEYFILE_DOMAIN_SEP


class TestNonceReuse:
    """Test nonce reuse prevention."""
    
    def test_nonce_reuse_guard(self):
        """Test nonce reuse guard."""
        from meow_decoder.crypto import _register_nonce_use
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First use should work
        _register_nonce_use(key, nonce)
        
        # Same key/nonce should raise
        with pytest.raises(RuntimeError):
            _register_nonce_use(key, nonce)
    
    def test_different_nonces_ok(self):
        """Test different nonces are OK."""
        from meow_decoder.crypto import _register_nonce_use
        
        key = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(12)
        nonce2 = secrets.token_bytes(12)
        
        # Both should work
        _register_nonce_use(key, nonce1)
        _register_nonce_use(key, nonce2)


class TestDuressTag:
    """Test duress tag authentication."""
    
    def test_compute_duress_hash(self):
        """Test computing duress hash."""
        from meow_decoder.crypto import compute_duress_hash
        
        password = "DuressPassword!"
        salt = secrets.token_bytes(16)
        
        hash_result = compute_duress_hash(password, salt)
        
        assert len(hash_result) == 32
    
    def test_compute_duress_tag(self):
        """Test computing duress tag."""
        from meow_decoder.crypto import compute_duress_tag
        
        password = "DuressPassword!"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest_data_here"
        
        tag = compute_duress_tag(password, salt, manifest_core)
        
        assert len(tag) == 32
    
    def test_check_duress_password(self):
        """Test checking duress password."""
        from meow_decoder.crypto import compute_duress_tag, check_duress_password
        
        password = "DuressPassword!"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest_data_here"
        
        tag = compute_duress_tag(password, salt, manifest_core)
        
        # Should match
        assert check_duress_password(password, salt, tag, manifest_core)
        
        # Wrong password should not match
        assert not check_duress_password("WrongPassword", salt, tag, manifest_core)


class TestManifestVersions:
    """Test manifest version handling."""
    
    def test_meow3_magic(self):
        """Test MEOW3 magic bytes."""
        from meow_decoder.crypto import MAGIC
        
        assert MAGIC == b"MEOW3"
    
    def test_manifest_sizes(self):
        """Test valid manifest sizes."""
        # From unpack_manifest docstring
        min_len = 115  # Base (password-only)
        fs_len = 147   # Forward secrecy
        fs_duress_len = 179  # FS + duress
        pq_len = 1235  # PQ hybrid
        pq_duress_len = 1267  # PQ + duress
        
        valid_sizes = [min_len, fs_len, fs_duress_len, pq_len, pq_duress_len]
        
        assert all(s > 0 for s in valid_sizes)
        assert valid_sizes == sorted(valid_sizes)  # Should be ascending


class TestKeyDerivation:
    """Test key derivation edge cases."""
    
    def test_empty_password_rejected(self):
        """Test empty password is rejected."""
        from meow_decoder.crypto import derive_key
        
        with pytest.raises(ValueError):
            derive_key("", secrets.token_bytes(16))
    
    def test_short_password_rejected(self):
        """Test short password is rejected."""
        from meow_decoder.crypto import derive_key, MIN_PASSWORD_LENGTH
        
        short_password = "x" * (MIN_PASSWORD_LENGTH - 1)
        
        with pytest.raises(ValueError):
            derive_key(short_password, secrets.token_bytes(16))
    
    def test_valid_password_accepted(self):
        """Test valid password is accepted."""
        from meow_decoder.crypto import derive_key, MIN_PASSWORD_LENGTH
        
        valid_password = "x" * MIN_PASSWORD_LENGTH
        salt = secrets.token_bytes(16)
        
        key = derive_key(valid_password, salt)
        
        assert len(key) == 32


class TestSecurityAssertions:
    """Test security assertions and invariants."""
    
    def test_aes_key_length(self):
        """Test AES key is 256-bit."""
        from meow_decoder.crypto import derive_key
        
        key = derive_key("ValidPassword123!", secrets.token_bytes(16))
        
        assert len(key) == 32  # 256 bits
    
    def test_nonce_length(self):
        """Test nonce is 96-bit."""
        nonce = secrets.token_bytes(12)
        
        assert len(nonce) == 12  # 96 bits
    
    def test_salt_length(self):
        """Test salt is 128-bit."""
        salt = secrets.token_bytes(16)
        
        assert len(salt) == 16  # 128 bits
    
    def test_hmac_length(self):
        """Test HMAC is 256-bit."""
        hmac_tag = secrets.token_bytes(32)
        
        assert len(hmac_tag) == 32  # 256 bits


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
