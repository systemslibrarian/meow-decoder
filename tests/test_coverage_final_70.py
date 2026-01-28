#!/usr/bin/env python3
"""
🧪 Final Coverage Push Tests - Target 70%

Comprehensive tests for modules that still have low coverage.
Focus on duress_mode, entropy_boost, double_ratchet, pq_signatures,
schrodinger_encode/decode, and encode/decode CLI paths.
"""

import pytest
import secrets
import tempfile
import hashlib
import struct
import hmac
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

# Set test mode for faster Argon2
os.environ["MEOW_TEST_MODE"] = "1"


# =============================================================================
# DURESS MODE TESTS
# =============================================================================

class TestDuressModeFull:
    """Full coverage tests for duress_mode.py."""
    
    def test_duress_handler_init_default(self):
        """Test DuressHandler with default config."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig()
        handler = DuressHandler(config)
        
        assert handler is not None
        assert handler._real_hash is None
        assert handler._duress_hash is None
    
    def test_duress_handler_set_passwords(self):
        """Test setting both passwords."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig(enabled=True)
        handler = DuressHandler(config)
        
        handler.set_passwords("real_pwd_12345678", "duress_pwd_12345678")
        
        assert handler._real_hash is not None
        assert handler._duress_hash is not None
        assert handler._real_hash != handler._duress_hash
    
    def test_check_password_all_types(self):
        """Test all password types are correctly identified."""
        from meow_decoder.duress_mode import DuressHandler, PasswordType
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig(enabled=True)
        handler = DuressHandler(config)
        handler.set_passwords("real_password", "duress_password")
        
        assert handler.check_password("real_password") == PasswordType.REAL
        assert handler.check_password("duress_password") == PasswordType.DURESS
        assert handler.check_password("wrong_password") == PasswordType.INVALID
    
    def test_get_decoy_data_message_type(self):
        """Test message-type decoy data generation."""
        from meow_decoder.duress_mode import DuressHandler
        from meow_decoder.config import DuressConfig
        
        config = DuressConfig(
            enabled=True,
            decoy_type="message",
            decoy_message="All is well"
        )
        handler = DuressHandler(config)
        
        data, filename = handler.get_decoy_data()
        assert data is not None
        assert len(data) > 0


# =============================================================================
# ENTROPY BOOST TESTS
# =============================================================================

class TestEntropyBoostFull:
    """Full coverage tests for entropy_boost.py."""
    
    def test_entropy_pool_creation(self):
        """Test creating entropy pool."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        assert pool._pool == b''
    
    def test_add_system_entropy(self):
        """Test adding system entropy."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        pool.add_system_entropy()
        
        assert len(pool._pool) > 0
    
    def test_add_timing_entropy_iterations(self):
        """Test timing entropy with different iterations."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        pool.add_timing_entropy(iterations=5)
        
        assert len(pool._pool) > 0
    
    def test_add_environment_entropy(self):
        """Test environment-based entropy."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        pool.add_environment_entropy()
        
        assert len(pool._pool) > 0
    
    def test_add_custom_entropy(self):
        """Test adding custom entropy data."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        custom = b"my custom entropy data"
        pool.add_entropy(custom)
        
        assert custom in pool._pool
    
    def test_collect_all(self):
        """Test collecting from all sources."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        pool.collect_all()
        
        # Should have collected significant entropy
        assert len(pool._pool) >= 32
    
    def test_get_bytes(self):
        """Test extracting bytes from pool."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        pool.collect_all()
        
        result = pool.get_bytes(32)
        
        assert len(result) == 32
        assert isinstance(result, bytes)
    
    def test_get_bytes_larger_than_pool(self):
        """Test extracting more bytes than available."""
        from meow_decoder.entropy_boost import EntropyPool
        
        pool = EntropyPool()
        pool.add_entropy(b"small")
        
        # Should still work (HKDF expands)
        result = pool.get_bytes(64)
        assert len(result) == 64


# =============================================================================
# DOUBLE RATCHET TESTS
# =============================================================================

class TestDoubleRatchetFull:
    """Full coverage tests for double_ratchet.py."""
    
    def test_keypair_generate(self):
        """Test keypair generation."""
        from meow_decoder.double_ratchet import KeyPair
        
        kp = KeyPair.generate()
        
        assert kp.private_key is not None
        assert kp.public_key is not None
    
    def test_keypair_public_bytes(self):
        """Test getting public bytes."""
        from meow_decoder.double_ratchet import KeyPair
        
        kp = KeyPair.generate()
        pub = kp.public_bytes()
        
        assert len(pub) == 32
    
    def test_keypair_from_public_bytes(self):
        """Test creating keypair from public bytes."""
        from meow_decoder.double_ratchet import KeyPair
        
        kp1 = KeyPair.generate()
        pub = kp1.public_bytes()
        
        kp2 = KeyPair.from_public_bytes(pub)
        assert kp2.public_bytes() == pub
    
    def test_message_header_pack_unpack(self):
        """Test message header serialization."""
        from meow_decoder.double_ratchet import MessageHeader, KeyPair
        
        kp = KeyPair.generate()
        header = MessageHeader(
            dh_public=kp.public_bytes(),
            pn=10,
            n=20
        )
        
        packed = header.pack()
        unpacked = MessageHeader.unpack(packed)
        
        assert unpacked.dh_public == header.dh_public
        assert unpacked.pn == header.pn
        assert unpacked.n == header.n
    
    def test_kdf_rk(self):
        """Test root key KDF."""
        from meow_decoder.double_ratchet import kdf_rk
        
        rk = secrets.token_bytes(32)
        dh_out = secrets.token_bytes(32)
        
        new_rk, ck = kdf_rk(rk, dh_out)
        
        assert len(new_rk) == 32
        assert len(ck) == 32
        assert new_rk != rk
    
    def test_kdf_ck(self):
        """Test chain key KDF."""
        from meow_decoder.double_ratchet import kdf_ck
        
        ck = secrets.token_bytes(32)
        
        new_ck, mk = kdf_ck(ck)
        
        assert len(new_ck) == 32
        assert len(mk) == 32
        assert new_ck != ck
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption/decryption roundtrip."""
        from meow_decoder.double_ratchet import encrypt, decrypt
        
        mk = secrets.token_bytes(32)
        plaintext = b"Secret message here!"
        ad = b"associated data"
        
        ciphertext = encrypt(mk, plaintext, ad)
        decrypted = decrypt(mk, ciphertext, ad)
        
        assert decrypted == plaintext
    
    def test_ratchet_state_init(self):
        """Test RatchetState initialization."""
        from meow_decoder.double_ratchet import RatchetState, KeyPair
        
        dhs = KeyPair.generate()
        rk = secrets.token_bytes(32)
        
        state = RatchetState(
            DHs=dhs,
            DHr=None,
            RK=rk,
            CKs=None,
            CKr=None,
            Ns=0,
            Nr=0,
            PN=0
        )
        
        assert state.RK == rk
        assert state.Ns == 0
        assert state.Nr == 0


# =============================================================================
# PQ SIGNATURES TESTS
# =============================================================================

class TestPQSignaturesFull:
    """Full coverage tests for pq_signatures.py."""
    
    def test_signature_dataclass(self):
        """Test Signature dataclass."""
        from meow_decoder.pq_signatures import Signature, SIG_ED25519
        
        sig = Signature(
            algorithm=SIG_ED25519,
            signature=secrets.token_bytes(64)
        )
        
        assert sig.algorithm == SIG_ED25519
        assert len(sig.signature) == 64
    
    def test_signature_pack_unpack_ed25519(self):
        """Test Ed25519 signature packing."""
        from meow_decoder.pq_signatures import Signature, SIG_ED25519
        
        sig = Signature(
            algorithm=SIG_ED25519,
            signature=secrets.token_bytes(64)
        )
        
        packed = sig.pack()
        unpacked = Signature.unpack(packed)
        
        assert unpacked.algorithm == SIG_ED25519
        assert unpacked.signature == sig.signature
    
    def test_generate_keypair_ed25519(self):
        """Test Ed25519 keypair generation."""
        from meow_decoder.pq_signatures import generate_keypair, SIG_ED25519
        
        kp = generate_keypair(SIG_ED25519)
        
        assert kp.algorithm == SIG_ED25519
        assert kp.private_key is not None
        assert kp.public_key is not None
    
    def test_sign_and_verify_ed25519(self):
        """Test Ed25519 signing and verification."""
        from meow_decoder.pq_signatures import generate_keypair, sign, verify, SIG_ED25519
        
        kp = generate_keypair(SIG_ED25519)
        message = b"Test message to sign"
        
        sig = sign(kp, message)
        valid = verify(kp.public_key, kp.algorithm, message, sig)
        
        assert valid == True
    
    def test_verify_fails_for_wrong_message(self):
        """Test verification fails for wrong message."""
        from meow_decoder.pq_signatures import generate_keypair, sign, verify, SIG_ED25519
        
        kp = generate_keypair(SIG_ED25519)
        message = b"Original message"
        
        sig = sign(kp, message)
        valid = verify(kp.public_key, kp.algorithm, b"Wrong message", sig)
        
        assert valid == False


# =============================================================================
# SCHRODINGER MODE TESTS
# =============================================================================

class TestSchrodingerModeFull:
    """Full coverage tests for schrodinger_encode/decode."""
    
    def test_manifest_init(self):
        """Test SchrodingerManifest initialization."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        manifest = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=secrets.token_bytes(32),
            reality_b_hmac=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            merkle_root=secrets.token_bytes(32),
            shuffle_seed=secrets.token_bytes(8),
            block_count=50,
            block_size=256
        )
        
        assert manifest.block_count == 50
        assert manifest.block_size == 256
    
    def test_manifest_pack_unpack(self):
        """Test manifest serialization."""
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        manifest = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=secrets.token_bytes(32),
            reality_b_hmac=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            merkle_root=secrets.token_bytes(32),
            shuffle_seed=secrets.token_bytes(8),
            block_count=100,
            block_size=512
        )
        
        packed = manifest.pack()
        assert len(packed) == 392
        
        unpacked = SchrodingerManifest.unpack(packed)
        assert unpacked.block_count == manifest.block_count
    
    def test_compute_merkle_root(self):
        """Test Merkle root computation."""
        from meow_decoder.schrodinger_encode import compute_merkle_root
        
        blocks = [secrets.token_bytes(256) for _ in range(8)]
        
        root = compute_merkle_root(blocks)
        
        assert len(root) == 32
        
        # Same blocks = same root
        root2 = compute_merkle_root(blocks)
        assert root == root2
    
    def test_compute_merkle_root_empty(self):
        """Test Merkle root with empty input."""
        from meow_decoder.schrodinger_encode import compute_merkle_root
        
        root = compute_merkle_root([])
        assert len(root) == 32
    
    def test_permute_unpermute(self):
        """Test block permutation is reversible."""
        from meow_decoder.schrodinger_encode import permute_blocks, unpermute_blocks
        
        blocks = [secrets.token_bytes(64) for _ in range(20)]
        seed = secrets.token_bytes(8)
        
        permuted = permute_blocks(blocks, seed)
        unpermuted = unpermute_blocks(permuted, seed)
        
        assert unpermuted == blocks
    
    def test_verify_password_reality(self):
        """Test password reality verification."""
        from meow_decoder.schrodinger_decode import verify_password_reality
        from meow_decoder.schrodinger_encode import SchrodingerManifest
        
        salt_a = secrets.token_bytes(16)
        salt_b = secrets.token_bytes(16)
        nonce_a = secrets.token_bytes(12)
        nonce_b = secrets.token_bytes(12)
        merkle_root = secrets.token_bytes(32)
        shuffle_seed = secrets.token_bytes(8)
        
        manifest_core = salt_a + salt_b + nonce_a + nonce_b + merkle_root + shuffle_seed
        
        key_a = hashlib.sha256(b"pass_a" + salt_a).digest()
        key_b = hashlib.sha256(b"pass_b" + salt_b).digest()
        hmac_a = hmac.new(key_a, manifest_core, hashlib.sha256).digest()
        hmac_b = hmac.new(key_b, manifest_core, hashlib.sha256).digest()
        
        manifest = SchrodingerManifest(
            salt_a=salt_a, salt_b=salt_b,
            nonce_a=nonce_a, nonce_b=nonce_b,
            reality_a_hmac=hmac_a, reality_b_hmac=hmac_b,
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            merkle_root=merkle_root,
            shuffle_seed=shuffle_seed,
            block_count=10, block_size=256
        )
        
        assert verify_password_reality("pass_a", manifest) == 'A'
        assert verify_password_reality("pass_b", manifest) == 'B'
        assert verify_password_reality("wrong", manifest) is None


# =============================================================================
# QUANTUM MIXER TESTS
# =============================================================================

class TestQuantumMixerFull:
    """Full coverage tests for quantum_mixer.py."""
    
    def test_derive_quantum_noise(self):
        """Test quantum noise derivation."""
        from meow_decoder.quantum_mixer import derive_quantum_noise
        
        salt = secrets.token_bytes(16)
        noise = derive_quantum_noise("pass1", "pass2", salt)
        
        assert len(noise) == 32
    
    def test_quantum_noise_different_passwords(self):
        """Test noise differs with different passwords."""
        from meow_decoder.quantum_mixer import derive_quantum_noise
        
        salt = secrets.token_bytes(16)
        
        n1 = derive_quantum_noise("a", "b", salt)
        n2 = derive_quantum_noise("a", "c", salt)
        
        assert n1 != n2
    
    def test_entangle_realities(self):
        """Test reality entanglement."""
        from meow_decoder.quantum_mixer import entangle_realities
        
        a = secrets.token_bytes(100)
        b = secrets.token_bytes(100)
        noise = secrets.token_bytes(32)
        
        entangled = entangle_realities(a, b, noise)
        
        assert len(entangled) == 200  # Interleaved
    
    def test_collapse_to_reality(self):
        """Test reality collapse."""
        from meow_decoder.quantum_mixer import (
            entangle_realities, collapse_to_reality,
            YARN_REALITY_A, YARN_REALITY_B
        )
        
        a = secrets.token_bytes(100)
        b = secrets.token_bytes(100)
        noise = secrets.token_bytes(32)
        
        entangled = entangle_realities(a, b, noise)
        
        collapsed_a = collapse_to_reality(entangled, noise, noise, YARN_REALITY_A)
        collapsed_b = collapse_to_reality(entangled, noise, noise, YARN_REALITY_B)
        
        assert collapsed_a == a
        assert collapsed_b == b
    
    def test_expand_noise(self):
        """Test noise expansion."""
        from meow_decoder.quantum_mixer import expand_noise
        
        seed = secrets.token_bytes(32)
        
        expanded = expand_noise(seed, 100)
        
        assert len(expanded) == 100
    
    def test_verify_indistinguishability(self):
        """Test indistinguishability verification."""
        from meow_decoder.quantum_mixer import verify_indistinguishability
        
        a = secrets.token_bytes(1000)
        b = secrets.token_bytes(1000)
        
        is_indist, results = verify_indistinguishability(a, b)
        
        assert 'entropy_a' in results
        assert 'entropy_b' in results


# =============================================================================
# DECOY GENERATOR TESTS
# =============================================================================

class TestDecoyGeneratorFull:
    """Full coverage tests for decoy_generator.py."""
    
    def test_generate_convincing_decoy(self):
        """Test decoy generation."""
        from meow_decoder.decoy_generator import generate_convincing_decoy
        
        decoy = generate_convincing_decoy(10000)
        
        assert len(decoy) >= 10000
    
    def test_decoy_is_random(self):
        """Test decoys are different."""
        from meow_decoder.decoy_generator import generate_convincing_decoy
        
        d1 = generate_convincing_decoy(1000)
        d2 = generate_convincing_decoy(1000)
        
        assert d1 != d2


# =============================================================================
# CONSTANT TIME TESTS
# =============================================================================

class TestConstantTimeFull:
    """Full coverage tests for constant_time.py."""
    
    def test_constant_time_compare_equal(self):
        """Test comparing equal values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"test_value"
        b = b"test_value"
        
        assert constant_time_compare(a, b) == True
    
    def test_constant_time_compare_not_equal(self):
        """Test comparing different values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"value1"
        b = b"value2"
        
        assert constant_time_compare(a, b) == False
    
    def test_secure_zero_memory(self):
        """Test memory zeroing."""
        from meow_decoder.constant_time import secure_zero_memory
        
        buf = bytearray(b"sensitive")
        secure_zero_memory(buf)
        
        assert all(x == 0 for x in buf)
    
    def test_secure_buffer_context(self):
        """Test SecureBuffer context manager."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"secret_data")
            data = buf.read(11)
            assert data == b"secret_data"
    
    def test_equalize_timing(self):
        """Test timing equalization."""
        from meow_decoder.constant_time import equalize_timing
        import time
        
        start = time.time()
        equalize_timing(0.01, 0.05)
        elapsed = time.time() - start
        
        assert elapsed >= 0.01


# =============================================================================
# FORWARD SECRECY TESTS
# =============================================================================

class TestForwardSecrecyFull:
    """Full coverage tests for forward_secrecy.py."""
    
    def test_manager_init(self):
        """Test ForwardSecrecyManager init."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mgr = ForwardSecrecyManager(key, salt, enable_ratchet=False)
        assert mgr is not None
    
    def test_derive_block_key(self):
        """Test per-block key derivation."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mgr = ForwardSecrecyManager(key, salt, enable_ratchet=False)
        
        k0 = mgr.derive_block_key(0)
        k1 = mgr.derive_block_key(1)
        k0_again = mgr.derive_block_key(0)
        
        assert k0 != k1
        assert k0 == k0_again
    
    def test_encrypt_decrypt_block(self):
        """Test block encryption/decryption."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mgr = ForwardSecrecyManager(key, salt, enable_ratchet=False)
        
        plaintext = b"Block data here"
        nonce, ct = mgr.encrypt_block(plaintext, 0)
        decrypted = mgr.decrypt_block(ct, nonce, 0)
        
        assert decrypted == plaintext
    
    def test_ratchet_enabled(self):
        """Test ratchet mode."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mgr = ForwardSecrecyManager(key, salt, enable_ratchet=True, ratchet_interval=10)
        
        k0 = mgr.derive_block_key(0)
        k10 = mgr.derive_block_key(10)
        k20 = mgr.derive_block_key(20)
        
        assert k0 != k10 != k20
    
    def test_cleanup(self):
        """Test cleanup method."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        mgr = ForwardSecrecyManager(key, salt, enable_ratchet=False)
        mgr.derive_block_key(0)
        mgr.cleanup()  # Should not raise


# =============================================================================
# X25519 FORWARD SECRECY TESTS
# =============================================================================

class TestX25519ForwardSecrecyFull:
    """Full coverage tests for x25519_forward_secrecy.py."""
    
    def test_generate_ephemeral_keypair(self):
        """Test ephemeral key generation."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys = generate_ephemeral_keypair()
        
        assert len(keys.ephemeral_private) == 32
        assert len(keys.ephemeral_public) == 32
    
    def test_generate_receiver_keypair(self):
        """Test receiver key generation."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        priv, pub = generate_receiver_keypair()
        
        assert len(priv) == 32
        assert len(pub) == 32
    
    def test_derive_shared_secret(self):
        """Test shared secret derivation."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair, generate_receiver_keypair,
            derive_shared_secret
        )
        
        recv_priv, recv_pub = generate_receiver_keypair()
        eph = generate_ephemeral_keypair()
        salt = secrets.token_bytes(16)
        
        # Sender derives
        shared1 = derive_shared_secret(
            eph.ephemeral_private, recv_pub, "pass", salt
        )
        
        # Receiver derives
        shared2 = derive_shared_secret(
            recv_priv, eph.ephemeral_public, "pass", salt
        )
        
        assert shared1 == shared2
    
    def test_serialize_deserialize_public(self):
        """Test public key serialization."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            serialize_public_key, deserialize_public_key
        )
        
        keys = generate_ephemeral_keypair()
        
        ser = serialize_public_key(keys.ephemeral_public)
        de = deserialize_public_key(ser)
        
        assert de == keys.ephemeral_public


# =============================================================================
# FRAME MAC TESTS
# =============================================================================

class TestFrameMACFull:
    """Full coverage tests for frame_mac.py."""
    
    def test_pack_unpack_valid(self):
        """Test valid frame MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"Frame data"
        
        packed = pack_frame_with_mac(data, key, 0, salt)
        valid, unpacked = unpack_frame_with_mac(packed, key, 0, salt)
        
        assert valid == True
        assert unpacked == data
    
    def test_invalid_mac(self):
        """Test invalid MAC is rejected."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"Frame data"
        
        packed = pack_frame_with_mac(data, key1, 0, salt)
        valid, _ = unpack_frame_with_mac(packed, key2, 0, salt)
        
        assert valid == False
    
    def test_frame_mac_stats(self):
        """Test FrameMACStats."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        stats.record_valid()
        stats.record_valid()
        stats.record_invalid()
        
        assert stats.valid_frames == 2
        assert stats.invalid_frames == 1
        assert stats.success_rate() == 2/3
    
    def test_derive_frame_master_key(self):
        """Test frame master key derivation."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        enc_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        frame_key = derive_frame_master_key(enc_key, salt)
        
        assert len(frame_key) == 32


# =============================================================================
# CONFIG TESTS
# =============================================================================

class TestConfigFull:
    """Full coverage tests for config.py."""
    
    def test_duress_config_defaults(self):
        """Test DuressConfig defaults."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig()
        
        assert config.enabled == False
        assert config.mode == DuressMode.DECOY
    
    def test_encoding_config_defaults(self):
        """Test EncodingConfig defaults."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.block_size == 512
        assert config.redundancy == 1.5
    
    def test_meow_config_save_load(self):
        """Test MeowConfig persistence."""
        from meow_decoder.config import MeowConfig
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        
        try:
            config = MeowConfig()
            config.encoding.block_size = 1024
            config.verbose = True
            config.save(path)
            
            loaded = MeowConfig.load(path)
            
            assert loaded.encoding.block_size == 1024
            assert loaded.verbose == True
        finally:
            path.unlink()
    
    def test_get_config(self):
        """Test get_config function."""
        from meow_decoder.config import get_config
        
        config = get_config()
        assert config is not None


# =============================================================================
# METADATA OBFUSCATION TESTS
# =============================================================================

class TestMetadataObfuscationFull:
    """Full coverage tests for metadata_obfuscation.py."""
    
    def test_add_remove_padding(self):
        """Test padding add/remove."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        data = b"Test data for padding"
        
        padded = add_length_padding(data)
        unpadded = remove_length_padding(padded)
        
        assert unpadded == data
    
    def test_padding_increases_size(self):
        """Test padding increases size."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"x" * 100
        padded = add_length_padding(data)
        
        assert len(padded) >= len(data)


# =============================================================================
# CRYPTO BACKEND TESTS
# =============================================================================

class TestCryptoBackendFull:
    """Full coverage tests for crypto_backend.py."""
    
    def test_get_backend(self):
        """Test getting backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        assert backend is not None
    
    def test_aes_gcm(self):
        """Test AES-GCM."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        pt = b"Plaintext"
        aad = b"AAD"
        
        ct = backend.aes_gcm_encrypt(key, nonce, pt, aad)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ct, aad)
        
        assert decrypted == pt
    
    def test_hmac(self):
        """Test HMAC."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        msg = b"Message"
        
        mac = backend.hmac_sha256(key, msg)
        
        assert len(mac) == 32
    
    def test_argon2(self):
        """Test Argon2id."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        password = b"password"
        salt = secrets.token_bytes(16)
        
        key = backend.derive_key_argon2id(
            password, salt,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        assert len(key) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
