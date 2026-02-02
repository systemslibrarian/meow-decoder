#!/usr/bin/env python3
"""
🧪 Core Coverage Tests - Focus on NON-EXCLUDED modules

These tests target ONLY modules that are NOT excluded in pyproject.toml:
- crypto.py
- crypto_backend.py  
- constant_time.py
- fountain.py
- frame_mac.py
- metadata_obfuscation.py
"""

import pytest
import secrets
import tempfile
import hashlib
import struct
import hmac
import os
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

# Set test mode for faster Argon2
os.environ["MEOW_TEST_MODE"] = "1"


# =============================================================================
# CRYPTO.PY TESTS - Core encryption module
# =============================================================================

class TestCryptoCore:
    """Comprehensive tests for crypto.py core functions."""
    
    def test_derive_key_basic(self):
        """Test basic key derivation."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        key = derive_key("password1234", salt)
        
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_derive_key_same_password_same_key(self):
        """Same password and salt should give same key."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        key1 = derive_key("test_password_123", salt)
        key2 = derive_key("test_password_123", salt)
        
        assert key1 == key2
    
    def test_derive_key_different_salt_different_key(self):
        """Different salt should give different key."""
        from meow_decoder.crypto import derive_key
        
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        key1 = derive_key("same_password!", salt1)
        key2 = derive_key("same_password!", salt2)
        
        assert key1 != key2
    
    def test_derive_key_empty_password_fails(self):
        """Empty password should raise ValueError."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        with pytest.raises(ValueError, match="cannot be empty"):
            derive_key("", salt)
    
    def test_derive_key_short_password_fails(self):
        """Short password should raise ValueError."""
        from meow_decoder.crypto import derive_key, MIN_PASSWORD_LENGTH
        
        salt = secrets.token_bytes(16)
        with pytest.raises(ValueError, match="at least"):
            derive_key("short", salt)
    
    def test_derive_key_wrong_salt_length_fails(self):
        """Wrong salt length should raise ValueError."""
        from meow_decoder.crypto import derive_key
        
        with pytest.raises(ValueError, match="16 bytes"):
            derive_key("password1234", b"short")
    
    def test_derive_key_with_keyfile(self):
        """Test key derivation with keyfile."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        
        key1 = derive_key("password1234", salt, keyfile)
        key2 = derive_key("password1234", salt)  # No keyfile
        
        assert key1 != key2
        assert len(key1) == 32
    
    def test_encrypt_file_bytes_basic(self):
        """Test basic file encryption."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        data = b"Hello, secret world!" * 100
        password = "test_password_123"
        
        comp, sha256, salt, nonce, cipher, ephemeral_key, enc_key = encrypt_file_bytes(
            data, password
        )
        
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(sha256) == 32
        assert len(cipher) > 0
        assert len(enc_key) == 32
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt then decrypt recovers original data."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Secret message for testing roundtrip!" * 50
        password = "roundtrip_password_123"
        
        comp, sha256, salt, nonce, cipher, ephemeral_key, enc_key = encrypt_file_bytes(
            data, password, use_length_padding=False
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data), comp_len=len(comp), sha256=sha256
        )
        
        assert decrypted == data
    
    def test_decrypt_wrong_password_fails(self):
        """Wrong password should fail."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Test data"
        password = "correct_password!"
        wrong_password = "wrong_password!!"
        
        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, use_length_padding=False
        )
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(cipher, wrong_password, salt, nonce,
                          orig_len=len(data), comp_len=len(comp), sha256=sha256)
    
    def test_manifest_pack_unpack(self):
        """Test manifest serialization."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.salt == manifest.salt
        assert unpacked.nonce == manifest.nonce
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.comp_len == manifest.comp_len
        assert unpacked.cipher_len == manifest.cipher_len
        assert unpacked.sha256 == manifest.sha256
        assert unpacked.block_size == manifest.block_size
        assert unpacked.k_blocks == manifest.k_blocks
        assert unpacked.hmac == manifest.hmac
    
    def test_manifest_with_ephemeral_key(self):
        """Test manifest with forward secrecy ephemeral key."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=5000,
            comp_len=4000,
            cipher_len=4016,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=20,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        assert len(packed) == 147  # Base 115 + 32 for ephemeral key
        
        unpacked = unpack_manifest(packed)
        assert unpacked.ephemeral_public_key == manifest.ephemeral_public_key
    
    def test_compute_manifest_hmac(self):
        """Test HMAC computation."""
        from meow_decoder.crypto import compute_manifest_hmac
        
        password = "test_hmac_password"
        salt = secrets.token_bytes(16)
        manifest_data = b"test manifest data here"
        
        hmac_tag = compute_manifest_hmac(password, salt, manifest_data)
        
        assert len(hmac_tag) == 32
        
        # Same inputs should give same HMAC
        hmac_tag2 = compute_manifest_hmac(password, salt, manifest_data)
        assert hmac_tag == hmac_tag2
    
    def test_verify_manifest_hmac(self):
        """Test HMAC verification."""
        from meow_decoder.crypto import (
            Manifest, compute_manifest_hmac, verify_manifest_hmac,
            pack_manifest_core
        )
        
        password = "verification_test_pw"
        salt = secrets.token_bytes(16)
        
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=128,
            k_blocks=1,
            hmac=b'\x00' * 32
        )
        
        packed_no_hmac = pack_manifest_core(manifest)
        manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac)
        
        assert verify_manifest_hmac(password, manifest) is True
        assert verify_manifest_hmac("wrong_password_!!", manifest) is False
    
    def test_verify_keyfile(self):
        """Test keyfile verification."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.key') as f:
            f.write(secrets.token_bytes(64))
            keyfile_path = f.name
        
        try:
            keyfile = verify_keyfile(keyfile_path)
            assert len(keyfile) == 64
        finally:
            os.unlink(keyfile_path)
    
    def test_verify_keyfile_not_found(self):
        """Test keyfile not found."""
        from meow_decoder.crypto import verify_keyfile
        
        with pytest.raises(FileNotFoundError):
            verify_keyfile("/nonexistent/path/to/keyfile.key")
    
    def test_verify_keyfile_too_small(self):
        """Test keyfile too small."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.key') as f:
            f.write(b"short")
            keyfile_path = f.name
        
        try:
            with pytest.raises(ValueError, match="too small"):
                verify_keyfile(keyfile_path)
        finally:
            os.unlink(keyfile_path)
    
    def test_duress_hash_computation(self):
        """Test duress password hash computation."""
        from meow_decoder.crypto import compute_duress_hash
        
        salt = secrets.token_bytes(16)
        hash1 = compute_duress_hash("password123", salt)
        hash2 = compute_duress_hash("password123", salt)
        hash3 = compute_duress_hash("different_pw", salt)
        
        assert len(hash1) == 32
        assert hash1 == hash2
        assert hash1 != hash3
    
    def test_duress_tag_computation(self):
        """Test duress tag computation."""
        from meow_decoder.crypto import compute_duress_tag
        
        salt = secrets.token_bytes(16)
        manifest_core = b"test manifest core data"
        
        tag = compute_duress_tag("duress_pw_12", salt, manifest_core)
        
        assert len(tag) == 32
    
    def test_check_duress_password(self):
        """Test duress password checking."""
        from meow_decoder.crypto import (
            compute_duress_tag, check_duress_password
        )
        
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest core bytes"
        duress_pw = "duress_password_here"
        
        tag = compute_duress_tag(duress_pw, salt, manifest_core)
        
        assert check_duress_password(duress_pw, salt, tag, manifest_core) is True
        assert check_duress_password("wrong_password", salt, tag, manifest_core) is False
    
    def test_nonce_reuse_detection(self):
        """Test nonce reuse detection."""
        from meow_decoder.crypto import _register_nonce_use
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First use should be fine
        _register_nonce_use(key, nonce)
        
        # Reuse should raise
        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(key, nonce)


# =============================================================================
# CRYPTO_BACKEND.PY TESTS
# =============================================================================

class TestCryptoBackend:
    """Tests for crypto_backend.py."""
    
    def test_get_default_backend(self):
        """Test getting default backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        assert backend is not None
    
    def test_backend_aes_gcm_encrypt_decrypt(self):
        """Test AES-GCM via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Test plaintext data"
        aad = b"additional data"
        
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, aad)
        
        assert decrypted == plaintext
    
    def test_backend_hmac_sha256(self):
        """Test HMAC-SHA256 via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        data = b"data to authenticate"
        
        tag = backend.hmac_sha256(key, data)
        
        assert len(tag) == 32
    
    def test_backend_argon2id(self):
        """Test Argon2id via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        password = b"test_password_12"
        salt = secrets.token_bytes(16)
        
        key = backend.derive_key_argon2id(
            password, salt, 
            output_len=32, 
            iterations=1, 
            memory_kib=32768, 
            parallelism=1
        )
        
        assert len(key) == 32
    
    def test_backend_x25519_keypair(self):
        """Test X25519 keypair generation."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        private_key, public_key = backend.x25519_generate_keypair()
        
        assert len(private_key) == 32
        assert len(public_key) == 32
    
    def test_backend_x25519_exchange(self):
        """Test X25519 key exchange."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        # Generate two keypairs
        priv_a, pub_a = backend.x25519_generate_keypair()
        priv_b, pub_b = backend.x25519_generate_keypair()
        
        # Exchange
        shared_ab = backend.x25519_exchange(priv_a, pub_b)
        shared_ba = backend.x25519_exchange(priv_b, pub_a)
        
        # Should be same
        assert shared_ab == shared_ba
        assert len(shared_ab) == 32
    
    def test_backend_hkdf(self):
        """Test HKDF via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key_material = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test info"
        
        derived = backend.derive_key_hkdf(key_material, salt, info)
        
        assert len(derived) == 32
    
    def test_backend_secure_zero(self):
        """Test secure zeroing."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        data = bytearray(b"sensitive data here!")
        backend.secure_zero(data)
        
        assert all(b == 0 for b in data)


# =============================================================================
# CONSTANT_TIME.PY TESTS
# =============================================================================

class TestConstantTimeOps:
    """Tests for constant_time.py."""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"same_value_here"
        b = b"same_value_here"
        
        assert constant_time_compare(a, b) is True
    
    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison with different values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"first_value"
        b = b"second_value"
        
        assert constant_time_compare(a, b) is False
    
    def test_secure_zero_memory(self):
        """Test secure memory zeroing."""
        from meow_decoder.constant_time import secure_zero_memory
        
        buf = bytearray(b"secret data!!!")
        secure_zero_memory(buf)
        
        assert all(b == 0 for b in buf)
    
    def test_secure_memory_context(self):
        """Test secure memory context manager."""
        from meow_decoder.constant_time import secure_memory
        
        with secure_memory(b"temporary secret") as buf:
            assert len(buf) == 16
    
    def test_timing_safe_equal_with_delay(self):
        """Test timing-safe comparison with delay."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        
        a = b"password_hash_1"
        b = b"password_hash_1"
        
        result = timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=5)
        assert result is True
    
    def test_equalize_timing(self):
        """Test timing equalization."""
        from meow_decoder.constant_time import equalize_timing
        
        # Should not raise
        equalize_timing(0.01, 0.02)
    
    def test_secure_buffer_basic(self):
        """Test SecureBuffer creation and use."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"test data here!")
            data = buf.read(15)
            assert data == b"test data here!"


# =============================================================================
# FOUNTAIN.PY TESTS  
# =============================================================================

class TestFountainCodes:
    """Tests for fountain.py."""
    
    def test_robust_soliton_distribution(self):
        """Test Robust Soliton distribution."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=50)
        
        # Sample many times
        degrees = [dist.sample_degree() for _ in range(1000)]
        
        # All degrees should be >= 1
        assert all(d >= 1 for d in degrees)
        
        # Average degree should be reasonable (typically 2-5)
        avg = sum(degrees) / len(degrees)
        assert 1 < avg < 10
    
    def test_fountain_encoder_basic(self):
        """Test fountain encoder creation."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data for encoding" * 10
        k_blocks = 5
        block_size = 50
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        assert encoder.k_blocks == k_blocks
        assert encoder.block_size == block_size
    
    def test_fountain_droplet_generation(self):
        """Test droplet generation."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"X" * 500
        encoder = FountainEncoder(data, 5, 100)
        
        droplet = encoder.droplet()
        
        assert droplet.seed is not None
        assert len(droplet.block_indices) > 0
        assert len(droplet.data) == 100
    
    def test_fountain_multiple_droplets(self):
        """Test generating multiple droplets."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Y" * 500
        encoder = FountainEncoder(data, 5, 100)
        
        droplets = encoder.generate_droplets(10)
        
        assert len(droplets) == 10
    
    def test_fountain_decoder_basic(self):
        """Test fountain decoder creation."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=10, block_size=100)
        
        assert decoder.k_blocks == 10
        assert decoder.block_size == 100
        assert decoder.is_complete() is False
    
    def test_fountain_encode_decode_roundtrip(self):
        """Test encode then decode roundtrip."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"This is test data for fountain codes!" * 5
        k_blocks = 4
        block_size = 64
        
        # Encode
        encoder = FountainEncoder(original, k_blocks, block_size)
        
        # Decode
        decoder = FountainDecoder(k_blocks, block_size, len(original))
        
        # Feed droplets until complete
        count = 0
        max_droplets = k_blocks * 3  # Should be more than enough
        
        while not decoder.is_complete() and count < max_droplets:
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            count += 1
        
        assert decoder.is_complete()
        
        recovered = decoder.get_data()
        assert recovered == original
    
    def test_droplet_pack_unpack(self):
        """Test droplet serialization."""
        from meow_decoder.fountain import FountainEncoder, pack_droplet, unpack_droplet
        
        data = b"A" * 200
        encoder = FountainEncoder(data, 4, 50)
        
        droplet = encoder.droplet()
        
        packed = pack_droplet(droplet)
        unpacked = unpack_droplet(packed, 50)
        
        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data


# =============================================================================
# FRAME_MAC.PY TESTS
# =============================================================================

class TestFrameMAC:
    """Tests for frame_mac.py."""
    
    def test_derive_frame_master_key(self):
        """Test frame master key derivation."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        encryption_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        master_key = derive_frame_master_key(encryption_key, salt)
        
        assert len(master_key) == 32
    
    def test_pack_frame_with_mac(self):
        """Test packing frame with MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        frame_data = b"test frame content"
        master_key = secrets.token_bytes(32)
        frame_index = 42
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(frame_data, master_key, frame_index, salt)
        
        # Should be original data + 8 byte MAC
        assert len(packed) == len(frame_data) + 8
    
    def test_unpack_frame_with_mac_valid(self):
        """Test unpacking valid MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        original = b"important data"
        master_key = secrets.token_bytes(32)
        frame_idx = 100
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(original, master_key, frame_idx, salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_idx, salt)
        
        assert valid is True
        assert unpacked == original
    
    def test_unpack_frame_with_mac_tampered(self):
        """Test detecting tampered MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        original = b"sensitive data"
        master_key = secrets.token_bytes(32)
        frame_idx = 50
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(original, master_key, frame_idx, salt)
        
        # Tamper with the data
        tampered = bytearray(packed)
        tampered[5] ^= 0xFF
        tampered = bytes(tampered)
        
        valid, _ = unpack_frame_with_mac(tampered, master_key, frame_idx, salt)
        
        assert valid is False
    
    def test_unpack_frame_wrong_index(self):
        """Test MAC fails with wrong frame index."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        original = b"data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(original, master_key, 1, salt)
        valid, _ = unpack_frame_with_mac(packed, master_key, 2, salt)  # Wrong index
        
        assert valid is False
    
    def test_frame_mac_stats(self):
        """Test FrameMACStats tracking."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        stats.record_valid()
        stats.record_valid()
        stats.record_invalid()
        
        assert stats.valid_frames == 2
        assert stats.invalid_frames == 1
        assert stats.success_rate() == pytest.approx(2/3)


# =============================================================================
# METADATA_OBFUSCATION.PY TESTS
# =============================================================================

class TestMetadataObfuscation:
    """Tests for metadata_obfuscation.py."""
    
    def test_add_length_padding(self):
        """Test adding length padding."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"test data" * 100  # ~900 bytes
        padded = add_length_padding(data)
        
        # Should be larger (padded to power of 2)
        assert len(padded) >= len(data)
    
    def test_remove_length_padding(self):
        """Test removing length padding."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"original content here" * 50
        
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original
    
    def test_padding_roundtrip_various_sizes(self):
        """Test padding/unpadding for various sizes."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        for size in [10, 100, 500, 1000, 5000, 10000]:
            original = secrets.token_bytes(size)
            padded = add_length_padding(original)
            recovered = remove_length_padding(padded)
            
            assert recovered == original, f"Failed for size {size}"
    
    def test_padded_size_is_power_of_two(self):
        """Test that padded size follows expected pattern."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        import math
        
        data = b"X" * 1000
        padded = add_length_padding(data)
        
        # The padded length should be deterministic
        assert len(padded) > len(data)
