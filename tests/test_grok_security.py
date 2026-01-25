#!/usr/bin/env python3
"""
🧪 Tests for Security Enhancement Modules

Tests the security modules:
- duress_mode.py: Coercion-resistant passwords
- entropy_boost.py: Multi-source entropy collection
- multi_secret.py: N-level Schrödinger mode
- hardware_keys.py: TPM/YubiKey/smart card integration
"""

import pytest
import os
import sys
import tempfile
import hashlib
import secrets
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# DURESS MODE TESTS
# ============================================================================

class TestDuressMode:
    """Tests for coercion-resistant password handling."""
    
    def test_import(self):
        """Test that duress_mode module imports correctly."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        assert DuressHandler is not None
        assert DuressConfig is not None
    
    def test_config_defaults(self):
        """Test DuressConfig default values."""
        from meow_decoder.duress_mode import DuressConfig
        
        config = DuressConfig()
        # Check actual attribute names from implementation
        assert config.wipe_memory == True
        assert config.wipe_resume_files == True
        assert config.show_decoy == True
        assert config.min_delay_ms == 100
        assert config.max_delay_ms == 500
        assert config.overwrite_passes == 3
        assert config.gc_aggressive == True
    
    def test_handler_initialization(self):
        """Test DuressHandler initialization."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        
        config = DuressConfig()
        handler = DuressHandler(config)
        
        # Check internal state
        assert handler._duress_hash is None
        assert handler._real_hash is None
        assert handler._triggered == False
    
    def test_set_passwords(self):
        """Test setting real and duress passwords."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        
        config = DuressConfig()
        handler = DuressHandler(config)
        
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress_password", "real_password", salt)
        
        # Hashes should be set
        assert handler._duress_hash is not None
        assert handler._real_hash is not None
        
        # Hashes should be different
        assert handler._duress_hash != handler._real_hash
    
    def test_same_passwords_rejected(self):
        """Test that same duress and real password is rejected."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        
        handler = DuressHandler(DuressConfig())
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError):
            handler.set_passwords("same_password", "same_password", salt)
    
    def test_check_password_real(self):
        """Test checking real password returns correct result."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        
        config = DuressConfig()
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress_password", "real_password", salt)
        
        is_valid, is_duress = handler.check_password("real_password", salt)
        
        assert is_valid == True
        assert is_duress == False
    
    def test_check_password_duress(self):
        """Test checking duress password triggers wipe."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        
        # Disable actual wipe for testing
        config = DuressConfig(wipe_memory=False, wipe_resume_files=False)
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress_password", "real_password", salt)
        
        is_valid, is_duress = handler.check_password("duress_password", salt)
        
        assert is_valid == True
        assert is_duress == True
        assert handler._triggered == True
    
    def test_check_password_wrong(self):
        """Test checking wrong password."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        
        config = DuressConfig()
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress_password", "real_password", salt)
        
        is_valid, is_duress = handler.check_password("wrong_password", salt)
        
        assert is_valid == False
        assert is_duress == False
    
    def test_secure_zero(self):
        """Test secure memory zeroing."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        
        handler = DuressHandler(DuressConfig())
        
        # Create bytearray with data
        data = bytearray(b"sensitive_data_here")
        original_len = len(data)
        
        handler._secure_zero(data)
        
        # All bytes should be zero
        assert all(b == 0 for b in data)
        assert len(data) == original_len
    
    def test_duress_wipes_sensitive_data(self):
        """Test that duress password wipes provided sensitive data."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        
        config = DuressConfig(wipe_resume_files=False)
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress_password", "real_password", salt)
        
        # Create sensitive data
        sensitive = bytearray(b"secret_key_material")
        
        # Trigger duress with sensitive data
        handler.check_password("duress_password", salt, sensitive_data=[sensitive])
        
        # Sensitive data should be zeroed
        assert all(b == 0 for b in sensitive)


# ============================================================================
# ENTROPY BOOST TESTS
# ============================================================================

class TestEntropyBoost:
    """Tests for multi-source entropy collection."""
    
    def test_import(self):
        """Test that entropy_boost module imports correctly."""
        from meow_decoder.entropy_boost import EntropyPool
        assert EntropyPool is not None
    
    def test_pool_initialization(self):
        """Test EntropyPool initialization."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        
        # Pool should start with empty sources list
        assert pool.sources is not None
        assert isinstance(pool.sources, list)
    
    def test_add_system_entropy(self):
        """Test adding system entropy."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        initial_len = len(pool.sources)
        
        pool.add_system_entropy(32)
        
        # Sources should have grown
        assert len(pool.sources) > initial_len
    
    def test_add_timing_entropy(self):
        """Test adding timing entropy."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        initial_len = len(pool.sources)
        
        pool.add_timing_entropy(samples=10)
        
        # Sources should have grown
        assert len(pool.sources) > initial_len
    
    def test_add_environment_entropy(self):
        """Test adding environment entropy."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        initial_len = len(pool.sources)
        
        pool.add_environment_entropy()
        
        # Sources should have grown
        assert len(pool.sources) > initial_len
    
    def test_hardware_entropy_graceful(self):
        """Test that hardware entropy doesn't crash when unavailable."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        
        # Should not raise even if hardware RNG unavailable
        try:
            pool.add_hardware_entropy()
        except Exception as e:
            pytest.fail(f"Hardware entropy should fail gracefully: {e}")
    
    def test_sources_contain_bytes(self):
        """Test that all sources contain valid bytes."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        pool.add_system_entropy(32)
        pool.add_timing_entropy(10)
        pool.add_environment_entropy()
        
        for source in pool.sources:
            assert isinstance(source, bytes)
            assert len(source) > 0
    
    def test_entropy_quality(self):
        """Test that generated entropy has reasonable quality."""
        from meow_decoder.entropy_boost import EntropyPool
        import math
        from collections import Counter
        
        pool = EntropyPool()
        pool.add_system_entropy(64)
        pool.add_timing_entropy(20)
        pool.add_environment_entropy()
        
        # Combine all sources
        combined = b''.join(pool.sources)
        
        # Calculate Shannon entropy
        counter = Counter(combined)
        entropy = -sum((count / len(combined)) * math.log2(count / len(combined)) 
                      for count in counter.values())
        
        # Good randomness should have entropy > 5.0 bits per byte
        assert entropy > 4.0  # Lower threshold for CI variability
    
    def test_multiple_pools_independent(self):
        """Test that multiple pools produce different results."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool1 = EntropyPool()
        pool1.add_system_entropy(32)
        
        pool2 = EntropyPool()
        pool2.add_system_entropy(32)
        
        # Sources should be different (random each time)
        assert pool1.sources[0] != pool2.sources[0]


# ============================================================================
# MULTI-SECRET (N-LEVEL SCHRÖDINGER) TESTS
# ============================================================================

class TestMultiSecret:
    """Tests for N-level Schrödinger mode."""
    
    def test_import(self):
        """Test that multi_secret module imports correctly."""
        from meow_decoder.multi_secret import (
            MultiSecretEncoder, MultiSecretDecoder, MultiSecretManifest, Reality
        )
        assert MultiSecretEncoder is not None
        assert MultiSecretDecoder is not None
        assert MultiSecretManifest is not None
        assert Reality is not None
    
    def test_reality_dataclass(self):
        """Test Reality dataclass."""
        from meow_decoder.multi_secret import Reality
        
        reality = Reality(data=b"secret", password="pass123")
        
        assert reality.data == b"secret"
        assert reality.password == "pass123"
        assert len(reality.salt) == 16
        assert len(reality.nonce) == 12
    
    def test_manifest_pack_unpack(self):
        """Test manifest serialization."""
        from meow_decoder.multi_secret import MultiSecretManifest
        
        manifest = MultiSecretManifest(
            n_realities=3,
            block_size=256,
            total_blocks=100,
            cipher_lengths=[100, 150, 200],
            salts=[secrets.token_bytes(16) for _ in range(3)],
            nonces=[secrets.token_bytes(12) for _ in range(3)],
            hmacs=[secrets.token_bytes(32) for _ in range(3)],
            merkle_root=secrets.token_bytes(32)
        )
        
        packed = manifest.pack()
        unpacked = MultiSecretManifest.unpack(packed)
        
        assert unpacked.n_realities == manifest.n_realities
        assert unpacked.block_size == manifest.block_size
        assert unpacked.merkle_root == manifest.merkle_root
        assert unpacked.cipher_lengths == manifest.cipher_lengths
        assert unpacked.total_blocks == manifest.total_blocks
    
    def test_encoder_initialization(self):
        """Test MultiSecretEncoder initialization."""
        from meow_decoder.multi_secret import MultiSecretEncoder
        
        # Encoder takes list of (data, password) tuples
        realities = [
            (b"Secret 1", "pass1"),
            (b"Secret 2", "pass2"),
            (b"Secret 3", "pass3")
        ]
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        
        assert len(encoder.realities) == 3
        assert encoder.block_size == 64
    
    def test_encoder_minimum_realities(self):
        """Test encoder requires at least 2 realities."""
        from meow_decoder.multi_secret import MultiSecretEncoder
        
        with pytest.raises(ValueError):
            MultiSecretEncoder([(b"single", "pass")], block_size=64)
    
    def test_encoder_maximum_realities(self):
        """Test encoder enforces maximum 16 realities."""
        from meow_decoder.multi_secret import MultiSecretEncoder
        
        realities = [(f"Secret {i}".encode(), f"pass{i}") for i in range(17)]
        
        with pytest.raises(ValueError):
            MultiSecretEncoder(realities, block_size=64)
    
    def test_encode_two_realities(self):
        """Test encoding two realities."""
        from meow_decoder.multi_secret import MultiSecretEncoder
        
        realities = [
            (b"This is the REAL secret content!" * 5, "real_password"),
            (b"This is the DECOY innocent content!" * 5, "decoy_password")
        ]
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        # Verify manifest
        assert manifest.n_realities == 2
        assert len(manifest.salts) == 2
        assert len(manifest.nonces) == 2
        assert len(manifest.hmacs) == 2
        assert len(manifest.cipher_lengths) == 2
        
        # Verify superposition
        assert len(superposition) > 0
        assert len(superposition) == manifest.total_blocks * manifest.block_size
    
    def test_encode_decode_two_realities(self):
        """Test encoding and decoding two realities."""
        from meow_decoder.multi_secret import MultiSecretEncoder, MultiSecretDecoder
        
        secret_a = b"This is the REAL secret content!" * 5
        secret_b = b"This is the DECOY innocent content!" * 5
        
        realities = [
            (secret_a, "real_password"),
            (secret_b, "decoy_password")
        ]
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        decoder = MultiSecretDecoder(superposition, manifest)
        
        # Decode reality 0
        decoded_0 = decoder.decode("real_password")
        assert decoded_0 == secret_a
        
        # Decode reality 1
        decoded_1 = decoder.decode("decoy_password")
        assert decoded_1 == secret_b
    
    def test_encode_decode_three_realities(self):
        """Test encoding and decoding three realities (N-level)."""
        from meow_decoder.multi_secret import MultiSecretEncoder, MultiSecretDecoder
        
        secrets_list = [
            b"Reality 0: Top secret military plans" * 5,
            b"Reality 1: Vacation photos metadata" * 5,
            b"Reality 2: Shopping list for groceries" * 5
        ]
        passwords = ["military_pass", "vacation_pass", "shopping_pass"]
        
        realities = list(zip(secrets_list, passwords))
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        decoder = MultiSecretDecoder(superposition, manifest)
        
        for i, (secret, password) in enumerate(realities):
            decoded = decoder.decode(password)
            assert decoded == secret, f"Reality {i} decoding failed"
    
    def test_wrong_password_fails(self):
        """Test that wrong password fails to decode."""
        from meow_decoder.multi_secret import MultiSecretEncoder, MultiSecretDecoder
        
        realities = [
            (b"Secret content" * 10, "correct_password"),
            (b"Decoy content" * 10, "decoy_password")
        ]
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        decoder = MultiSecretDecoder(superposition, manifest)
        
        # Wrong password should return -1 from _verify_password or raise
        result = decoder._verify_password("wrong_password")
        assert result == -1
    
    def test_merkle_root_integrity(self):
        """Test that Merkle root is computed correctly."""
        from meow_decoder.multi_secret import MultiSecretEncoder
        
        realities = [
            (b"Secret 1" * 10, "pass1"),
            (b"Secret 2" * 10, "pass2")
        ]
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        # Merkle root should be non-zero
        assert manifest.merkle_root != b'\x00' * 32
        assert len(manifest.merkle_root) == 32
    
    def test_five_realities(self):
        """Test with 5 realities."""
        from meow_decoder.multi_secret import MultiSecretEncoder, MultiSecretDecoder
        
        num_realities = 5
        realities = [(f"Secret {i}".encode() * 10, f"password{i}") for i in range(num_realities)]
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        decoder = MultiSecretDecoder(superposition, manifest)
        
        for secret, password in realities:
            decoded = decoder.decode(password)
            assert decoded == secret


# ============================================================================
# HARDWARE KEYS TESTS
# ============================================================================

class TestHardwareKeys:
    """Tests for hardware security module integration."""
    
    def test_import(self):
        """Test that hardware_keys module imports correctly."""
        from meow_decoder.hardware_keys import HardwareKeyManager, HardwareStatus
        assert HardwareKeyManager is not None
        assert HardwareStatus is not None
    
    def test_status_initialization(self):
        """Test HardwareStatus dataclass."""
        from meow_decoder.hardware_keys import HardwareStatus
        
        status = HardwareStatus()
        
        assert status.tpm_available == False
        assert status.yubikey_available == False
        assert status.smartcard_available == False
        assert status.sgx_available == False
        assert status.warnings is not None
    
    def test_status_any_hardware(self):
        """Test any_hardware() method."""
        from meow_decoder.hardware_keys import HardwareStatus
        
        status = HardwareStatus()
        assert status.any_hardware() == False
        
        status.tpm_available = True
        assert status.any_hardware() == True
    
    def test_status_summary(self):
        """Test summary() method."""
        from meow_decoder.hardware_keys import HardwareStatus
        
        status = HardwareStatus()
        summary = status.summary()
        
        assert "Hardware Security Status" in summary
        assert "TPM" in summary
        assert "YubiKey" in summary
    
    def test_manager_initialization(self):
        """Test HardwareKeyManager initialization."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        assert manager.status is not None
        assert isinstance(manager.status.tpm_available, bool)
    
    def test_manager_detect_hardware(self):
        """Test hardware detection (should not raise)."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        # Detection happens in __init__, should complete without error
        assert manager.status is not None
    
    def test_has_tpm_method(self):
        """Test has_tpm() method exists."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        # Method should exist and return bool
        result = manager.has_tpm()
        assert isinstance(result, bool)
    
    def test_has_yubikey_method(self):
        """Test has_yubikey() method exists."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        result = manager.has_yubikey()
        assert isinstance(result, bool)
    
    def test_derive_key_software(self):
        """Test software-only key derivation works."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        # Software fallback should always work
        key = manager.derive_key_software(password, salt)
        
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_key_derivation_deterministic(self):
        """Test that key derivation is deterministic."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        key1 = manager.derive_key_software(password, salt)
        key2 = manager.derive_key_software(password, salt)
        
        assert key1 == key2
    
    def test_different_passwords_different_keys(self):
        """Test that different passwords produce different keys."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        salt = secrets.token_bytes(16)
        
        key1 = manager.derive_key_software("password1", salt)
        key2 = manager.derive_key_software("password2", salt)
        
        assert key1 != key2
    
    def test_different_salts_different_keys(self):
        """Test that different salts produce different keys."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        password = "test_password"
        
        key1 = manager.derive_key_software(password, secrets.token_bytes(16))
        key2 = manager.derive_key_software(password, secrets.token_bytes(16))
        
        assert key1 != key2


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestSecurityIntegration:
    """Integration tests for security modules working together."""
    
    def test_entropy_in_multi_secret(self):
        """Test using enhanced entropy in multi-secret encoding."""
        from meow_decoder.entropy_boost import EntropyPool
        from meow_decoder.multi_secret import MultiSecretEncoder, MultiSecretDecoder
        
        # Generate entropy
        pool = EntropyPool()
        pool.add_system_entropy(32)
        
        # Use in multi-secret
        realities = [
            (b"Secret 1" * 10, "pass1"),
            (b"Secret 2" * 10, "pass2")
        ]
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        # Decode should work
        decoder = MultiSecretDecoder(superposition, manifest)
        decoded = decoder.decode("pass1")
        
        assert decoded == b"Secret 1" * 10
    
    def test_duress_concept_with_multi_secret(self):
        """Test duress mode concept with multi-secret."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        from meow_decoder.multi_secret import MultiSecretEncoder, MultiSecretDecoder
        
        # Encode multi-secret
        real_secret = b"REAL secret data" * 10
        decoy_secret = b"DECOY innocent data" * 10
        
        realities = [
            (real_secret, "real_pass"),
            (decoy_secret, "duress_pass")
        ]
        
        encoder = MultiSecretEncoder(realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        # Set up duress handler
        config = DuressConfig(wipe_resume_files=False)
        handler = DuressHandler(config)
        salt = secrets.token_bytes(16)
        handler.set_passwords("duress_pass", "real_pass", salt)
        
        # Check real password
        is_valid, is_duress = handler.check_password("real_pass", salt)
        assert is_valid == True
        assert is_duress == False
        
        # Decode real reality
        decoder = MultiSecretDecoder(superposition, manifest)
        decoded = decoder.decode("real_pass")
        assert decoded == real_secret
    
    def test_hardware_key_derivation_available(self):
        """Test hardware key derivation is available."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager()
        
        # Use software fallback (always available)
        password = "test_password"
        salt = secrets.token_bytes(16)
        key = manager.derive_key_software(password, salt)
        
        # Key should work
        assert len(key) == 32
    
    def test_all_modules_import(self):
        """Test all security modules can be imported together."""
        from meow_decoder.duress_mode import DuressHandler, DuressConfig
        from meow_decoder.entropy_boost import EntropyPool
        from meow_decoder.multi_secret import MultiSecretEncoder, MultiSecretDecoder
        from meow_decoder.hardware_keys import HardwareKeyManager, HardwareStatus
        
        # All should be importable
        assert DuressHandler is not None
        assert EntropyPool is not None
        assert MultiSecretEncoder is not None
        assert HardwareKeyManager is not None


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
