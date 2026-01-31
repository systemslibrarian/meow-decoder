#!/usr/bin/env python3
"""
🧪 Deep Coverage Tests - Core Crypto & Encode/Decode
Target: 90% coverage for encode.py, decode_gif.py, crypto.py
"""

import pytest
import tempfile
import secrets
import hashlib
import struct
import os
import io
import zlib
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestCryptoModule:
    """Deep tests for crypto.py module."""
    
    def test_magic_bytes(self):
        """Test MAGIC constant."""
        from meow_decoder.crypto import MAGIC
        assert MAGIC == b"MEOW3"
        
    def test_argon2_parameters(self):
        """Test Argon2id parameters."""
        from meow_decoder.crypto import ARGON2_MEMORY, ARGON2_ITERATIONS, ARGON2_PARALLELISM
        
        # Should be reasonable values
        assert ARGON2_MEMORY >= 32768  # At least 32 MiB
        assert ARGON2_ITERATIONS >= 1
        assert ARGON2_PARALLELISM >= 1
        
    def test_manifest_hmac_key_prefix(self):
        """Test HMAC key prefix."""
        from meow_decoder.crypto import MANIFEST_HMAC_KEY_PREFIX
        assert b"meow" in MANIFEST_HMAC_KEY_PREFIX.lower()
        
    def test_manifest_dataclass(self):
        """Test Manifest dataclass."""
        from meow_decoder.crypto import Manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32)
        )
        
        assert manifest.orig_len == 1000
        assert manifest.block_size == 512
        
    def test_manifest_with_ephemeral_key(self):
        """Test Manifest with ephemeral key."""
        from meow_decoder.crypto import Manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32)
        )
        
        assert manifest.ephemeral_public_key is not None
        
    def test_manifest_with_pq_ciphertext(self):
        """Test Manifest with PQ ciphertext."""
        from meow_decoder.crypto import Manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            pq_ciphertext=secrets.token_bytes(1088)
        )
        
        assert manifest.pq_ciphertext is not None
        
    def test_manifest_with_duress_tag(self):
        """Test Manifest with duress tag."""
        from meow_decoder.crypto import Manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            duress_tag=secrets.token_bytes(32)
        )
        
        assert manifest.duress_tag is not None
        
    def test_derive_key(self):
        """Test key derivation."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        
        key1 = derive_key("password123", salt)
        key2 = derive_key("password123", salt)
        key3 = derive_key("different", salt)
        
        assert len(key1) == 32
        assert key1 == key2  # Deterministic
        assert key1 != key3  # Different password
        
    def test_derive_key_empty_password(self):
        """Test derive_key with empty password."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError, match="empty"):
            derive_key("", salt)
            
    def test_derive_key_short_password(self):
        """Test derive_key with short password."""
        from meow_decoder.crypto import derive_key, MIN_PASSWORD_LENGTH
        
        salt = secrets.token_bytes(16)
        short_password = "a" * (MIN_PASSWORD_LENGTH - 1)
        
        with pytest.raises(ValueError, match="at least"):
            derive_key(short_password, salt)
            
    def test_derive_key_wrong_salt_length(self):
        """Test derive_key with wrong salt length."""
        from meow_decoder.crypto import derive_key
        
        with pytest.raises(ValueError, match="16 bytes"):
            derive_key("password123", secrets.token_bytes(8))
            
    def test_derive_key_with_keyfile(self):
        """Test derive_key with keyfile."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        
        key_with = derive_key("password123", salt, keyfile)
        key_without = derive_key("password123", salt)
        
        assert key_with != key_without
        
    def test_encrypt_file_bytes(self):
        """Test encrypt_file_bytes."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        raw_data = b"Test data for encryption" * 100
        password = "TestPassword123"
        
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            raw_data, password
        )
        
        assert len(sha) == 32
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(cipher) > 0
        assert len(key) == 32
        
    def test_encrypt_file_bytes_no_padding(self):
        """Test encrypt without length padding."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        raw_data = b"Short data"
        password = "TestPassword123"
        
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            raw_data, password, use_length_padding=False
        )
        
        assert len(cipher) > 0
        
    def test_encrypt_with_receiver_public_key(self):
        """Test encrypt with forward secrecy."""
        from meow_decoder.crypto import encrypt_file_bytes
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        raw_data = b"Test data" * 50
        password = "TestPassword123"
        
        _, receiver_pub = generate_receiver_keypair()
        
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            raw_data, password, receiver_public_key=receiver_pub
        )
        
        assert ephemeral is not None
        assert len(ephemeral) == 32
        
    def test_decrypt_to_raw(self):
        """Test decrypt_to_raw."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        raw_data = b"Test data for encryption and decryption" * 50
        password = "TestPassword123"
        
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            raw_data, password
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(raw_data),
            comp_len=len(comp),
            sha256=sha
        )
        
        assert decrypted == raw_data
        
    def test_decrypt_wrong_password(self):
        """Test decrypt with wrong password."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        raw_data = b"Secret data"
        password = "CorrectPassword123"
        
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            raw_data, password
        )
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, "WrongPassword456", salt, nonce,
                orig_len=len(raw_data),
                comp_len=len(comp),
                sha256=sha
            )
            
    def test_pack_manifest(self):
        """Test manifest packing."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        
        assert len(packed) == 115  # Base size
        
    def test_pack_manifest_with_ephemeral(self):
        """Test manifest packing with ephemeral key."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        
        assert len(packed) == 147  # Base + ephemeral
        
    def test_pack_manifest_with_duress(self):
        """Test manifest packing with duress tag."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            duress_tag=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        
        assert len(packed) == 179  # Base + ephemeral + duress
        
    def test_unpack_manifest(self):
        """Test manifest unpacking."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.comp_len == manifest.comp_len
        assert unpacked.block_size == manifest.block_size
        assert unpacked.k_blocks == manifest.k_blocks
        
    def test_unpack_manifest_too_short(self):
        """Test unpack with short manifest."""
        from meow_decoder.crypto import unpack_manifest
        
        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(b"short")
            
    def test_unpack_manifest_invalid_magic(self):
        """Test unpack with wrong magic."""
        from meow_decoder.crypto import unpack_manifest
        
        # Create invalid manifest
        invalid = b"XXXX" + secrets.token_bytes(111)
        
        with pytest.raises(ValueError, match="MAGIC"):
            unpack_manifest(invalid)
            
    def test_compute_manifest_hmac(self):
        """Test manifest HMAC computation."""
        from meow_decoder.crypto import (
            compute_manifest_hmac, derive_key, pack_manifest_core, Manifest
        )
        
        salt = secrets.token_bytes(16)
        password = "TestPassword123"
        enc_key = derive_key(password, salt)
        
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=b'\x00' * 32
        )
        
        packed_no_hmac = pack_manifest_core(manifest)
        
        hmac1 = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)
        hmac2 = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)
        
        assert len(hmac1) == 32
        assert hmac1 == hmac2  # Deterministic
        
    def test_verify_manifest_hmac(self):
        """Test manifest HMAC verification."""
        from meow_decoder.crypto import (
            compute_manifest_hmac, verify_manifest_hmac,
            derive_key, pack_manifest_core, Manifest
        )
        
        salt = secrets.token_bytes(16)
        password = "TestPassword123"
        enc_key = derive_key(password, salt)
        
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=b'\x00' * 32
        )
        
        packed_no_hmac = pack_manifest_core(manifest)
        manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)
        
        # Should verify
        assert verify_manifest_hmac(password, manifest) == True
        
        # Wrong password should fail
        assert verify_manifest_hmac("wrongpassword", manifest) == False
        
    def test_verify_keyfile(self):
        """Test keyfile verification."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(64))
            path = f.name
            
        try:
            keyfile = verify_keyfile(path)
            assert len(keyfile) == 64
        finally:
            os.remove(path)
            
    def test_verify_keyfile_not_found(self):
        """Test keyfile not found."""
        from meow_decoder.crypto import verify_keyfile
        
        with pytest.raises(FileNotFoundError):
            verify_keyfile("/nonexistent/path/keyfile.key")
            
    def test_verify_keyfile_too_small(self):
        """Test keyfile too small."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"tiny")
            path = f.name
            
        try:
            with pytest.raises(ValueError, match="too small"):
                verify_keyfile(path)
        finally:
            os.remove(path)
            
    def test_compute_duress_hash(self):
        """Test duress hash computation."""
        from meow_decoder.crypto import compute_duress_hash
        
        salt = secrets.token_bytes(16)
        
        hash1 = compute_duress_hash("duress123", salt)
        hash2 = compute_duress_hash("duress123", salt)
        hash3 = compute_duress_hash("different", salt)
        
        assert len(hash1) == 32
        assert hash1 == hash2
        assert hash1 != hash3
        
    def test_compute_duress_tag(self):
        """Test duress tag computation."""
        from meow_decoder.crypto import compute_duress_tag
        
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest data here"
        
        tag = compute_duress_tag("duress123", salt, manifest_core)
        
        assert len(tag) == 32
        
    def test_check_duress_password(self):
        """Test duress password check."""
        from meow_decoder.crypto import compute_duress_tag, check_duress_password
        
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest data here"
        
        tag = compute_duress_tag("duress123", salt, manifest_core)
        
        # Correct password
        assert check_duress_password("duress123", salt, tag, manifest_core) == True
        
        # Wrong password
        assert check_duress_password("wrong", salt, tag, manifest_core) == False
        
    def test_nonce_reuse_guard(self):
        """Test nonce reuse detection."""
        from meow_decoder.crypto import _register_nonce_use
        
        # Clear cache for clean test
        from meow_decoder.crypto import _nonce_reuse_cache
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First use should be fine
        _register_nonce_use(key, nonce)
        
        # Same key+nonce should raise
        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(key, nonce)
            
        # Different nonce should be fine
        _register_nonce_use(key, secrets.token_bytes(12))


class TestFountainModule:
    """Deep tests for fountain.py module."""
    
    def test_robust_soliton_distribution(self):
        """Test RobustSolitonDistribution."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=100)
        
        # Sample many degrees
        degrees = [dist.sample_degree() for _ in range(1000)]
        
        assert min(degrees) >= 1
        assert max(degrees) <= 100
        
    def test_robust_soliton_small_k(self):
        """Test distribution with small k."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=2)
        degrees = [dist.sample_degree() for _ in range(100)]
        
        assert all(1 <= d <= 2 for d in degrees)
        
    def test_fountain_encoder_init(self):
        """Test FountainEncoder initialization."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        assert encoder.k_blocks == 10
        assert encoder.block_size == 100
        
    def test_fountain_encoder_droplet(self):
        """Test droplet generation."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data for fountain" * 50
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        droplet = encoder.droplet()
        
        assert droplet.seed >= 0
        assert len(droplet.block_indices) >= 1
        assert len(droplet.data) == 100
        
    def test_fountain_encoder_generate_droplets(self):
        """Test batch droplet generation."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        droplets = encoder.generate_droplets(20)
        
        assert len(droplets) == 20
        
    def test_fountain_decoder_init(self):
        """Test FountainDecoder initialization."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=10, block_size=100)
        
        assert decoder.k_blocks == 10
        assert decoder.block_size == 100
        assert not decoder.is_complete()
        
    def test_fountain_encode_decode_roundtrip(self):
        """Test full encode/decode roundtrip."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        original = b"Hello, Fountain Codes! " * 50  # 1150 bytes
        block_size = 100
        # Calculate k_blocks properly: ceil(len(original) / block_size)
        k_blocks = (len(original) + block_size - 1) // block_size  # 12 blocks
        
        # Encode
        encoder = FountainEncoder(original, k_blocks, block_size)
        
        # Decode (don't pass original_length to constructor)
        decoder = FountainDecoder(k_blocks, block_size)
        
        max_droplets = k_blocks * 3
        for _ in range(max_droplets):
            droplet = encoder.droplet()
            if decoder.add_droplet(droplet):
                break
        
        assert decoder.is_complete()
        
        # Pass original_length to get_data() to strip padding
        recovered = decoder.get_data(original_length=len(original))
        assert recovered == original
    
    def test_unpack_droplet(self):
        """Test droplet unpacking."""
        from meow_decoder.fountain import (
            FountainEncoder, pack_droplet, unpack_droplet
        )
        
        data = b"Test data" * 100
        encoder = FountainEncoder(data, k_blocks=10, block_size=100)
        
        droplet = encoder.droplet()
        packed = pack_droplet(droplet)
        unpacked = unpack_droplet(packed, block_size=100)
        
        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data


class TestConstantTimeModule:
    """Deep tests for constant_time.py module."""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"secret data here"
        b = b"secret data here"
        
        assert constant_time_compare(a, b) == True
        
    def test_constant_time_compare_different(self):
        """Test constant-time comparison with different values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"secret data here"
        b = b"different data!!"
        
        assert constant_time_compare(a, b) == False
        
    def test_constant_time_compare_different_lengths(self):
        """Test with different lengths."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"short"
        b = b"much longer string"
        
        assert constant_time_compare(a, b) == False
        
    def test_secure_zero_memory(self):
        """Test secure memory zeroing."""
        from meow_decoder.constant_time import secure_zero_memory
        
        data = bytearray(b"sensitive data")
        secure_zero_memory(data)
        
        assert all(b == 0 for b in data)
        
    def test_secure_memory_context(self):
        """Test secure memory context manager."""
        from meow_decoder.constant_time import secure_memory
        
        with secure_memory(b"secret") as buf:
            assert len(buf) == 6
            # Data accessible inside context
            
        # After context, buffer should be zeroed
        assert all(b == 0 for b in buf)
        
    def test_timing_safe_equal_with_delay(self):
        """Test timing-safe comparison with delay."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        import time
        
        a = b"test"
        b = b"test"
        
        start = time.time()
        result = timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=5)
        elapsed = time.time() - start
        
        assert result == True
        assert elapsed >= 0.002  # At least 2ms (min + min)
        
    def test_equalize_timing(self):
        """Test timing equalization."""
        from meow_decoder.constant_time import equalize_timing
        import time
        
        start = time.time()
        time.sleep(0.01)  # 10ms operation
        elapsed = time.time() - start
        
        equalize_timing(elapsed, target_time=0.05)
        
        total = time.time() - start
        assert total >= 0.04  # Should be close to target
        
    def test_secure_buffer(self):
        """Test SecureBuffer class."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"test data")
            data = buf.read(9)
            assert data == b"test data"


class TestFrameMacModule:
    """Deep tests for frame_mac.py module."""
    
    def test_derive_frame_master_key(self):
        """Test frame master key derivation."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        enc_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(enc_key, salt)
        key2 = derive_frame_master_key(enc_key, salt)
        key3 = derive_frame_master_key(secrets.token_bytes(32), salt)
        
        assert len(key1) == 32
        assert key1 == key2  # Deterministic
        assert key1 != key3  # Different enc_key
        
    def test_pack_frame_with_mac(self):
        """Test frame packing with MAC."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        
        data = b"frame data here"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_index=0, salt=salt)
        
        assert len(packed) == len(data) + 8  # 8-byte MAC prefix
        
    def test_unpack_frame_with_mac_valid(self):
        """Test unpacking valid frame."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"frame data here"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_index=0, salt=salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index=0, salt=salt)
        
        assert valid == True
        assert unpacked == data
        
    def test_unpack_frame_with_mac_invalid(self):
        """Test unpacking tampered frame."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"frame data here"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_index=0, salt=salt)
        
        # Tamper with the packed data
        tampered = bytearray(packed)
        tampered[-1] ^= 0xFF
        
        valid, unpacked = unpack_frame_with_mac(bytes(tampered), master_key, frame_index=0, salt=salt)
        
        assert valid == False
        
    def test_unpack_wrong_frame_id(self):
        """Test unpacking with wrong frame ID."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        
        data = b"frame data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        packed = pack_frame_with_mac(data, master_key, frame_index=0, salt=salt)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index=1, salt=salt)  # Wrong ID
        
        assert valid == False
        
    def test_frame_mac_stats(self):
        """Test FrameMACStats class."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        stats.record_valid()
        stats.record_valid()
        stats.record_invalid()
        
        assert stats.valid_frames == 2
        assert stats.invalid_frames == 1
        assert stats.success_rate() == 2/3


class TestMetadataObfuscation:
    """Deep tests for metadata_obfuscation.py module."""
    
    def test_add_length_padding(self):
        """Test length padding."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        data = b"short data"
        padded = add_length_padding(data)
        
        # Should be larger
        assert len(padded) > len(data)
        
    def test_remove_length_padding(self):
        """Test padding removal."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"test data here" * 10
        padded = add_length_padding(original)
        unpadded = remove_length_padding(padded)
        
        assert unpadded == original
        
    def test_padding_roundtrip_various_sizes(self):
        """Test padding with various data sizes."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        for size in [10, 100, 1000, 5000, 10000]:
            original = secrets.token_bytes(size)
            padded = add_length_padding(original)
            unpadded = remove_length_padding(padded)
            
            assert unpadded == original, f"Failed for size {size}"


class TestDuressFunctionality:
    """Tests for duress password functionality in crypto.py."""
    
    def test_compute_duress_hash(self):
        """Test duress hash computation."""
        from meow_decoder.crypto import compute_duress_hash
        
        password = "duress_password"
        salt = secrets.token_bytes(16)
        
        hash1 = compute_duress_hash(password, salt)
        hash2 = compute_duress_hash(password, salt)
        
        # Same inputs should produce same hash
        assert hash1 == hash2
        assert len(hash1) == 32
        
        # Different password should produce different hash
        hash3 = compute_duress_hash("different", salt)
        assert hash3 != hash1
        
        # Different salt should produce different hash
        hash4 = compute_duress_hash(password, secrets.token_bytes(16))
        assert hash4 != hash1
    
    def test_compute_duress_tag(self):
        """Test duress tag computation."""
        from meow_decoder.crypto import compute_duress_tag
        
        password = "duress_password"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest_core_data_here" * 5
        
        tag1 = compute_duress_tag(password, salt, manifest_core)
        tag2 = compute_duress_tag(password, salt, manifest_core)
        
        # Same inputs should produce same tag
        assert tag1 == tag2
        assert len(tag1) == 32
        
        # Different manifest should produce different tag
        tag3 = compute_duress_tag(password, salt, b"different_manifest")
        assert tag3 != tag1
    
    def test_check_duress_password_correct(self):
        """Test duress password verification - correct password."""
        from meow_decoder.crypto import compute_duress_tag, check_duress_password
        
        password = "duress_password"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest_core_data" * 10
        
        # Compute the tag
        tag = compute_duress_tag(password, salt, manifest_core)
        
        # Check with correct password
        is_duress = check_duress_password(password, salt, tag, manifest_core)
        assert is_duress is True
    
    def test_check_duress_password_wrong(self):
        """Test duress password verification - wrong password."""
        from meow_decoder.crypto import compute_duress_tag, check_duress_password
        
        correct_password = "correct_duress"
        wrong_password = "wrong_duress"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest_core_data" * 10
        
        # Compute tag with correct password
        tag = compute_duress_tag(correct_password, salt, manifest_core)
        
        # Check with wrong password
        is_duress = check_duress_password(wrong_password, salt, tag, manifest_core)
        assert is_duress is False


class TestNonceReuseDetection:
    """Tests for nonce reuse detection in crypto.py."""
    
    def test_register_nonce_use_first_time(self):
        """Test first-time nonce registration."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        
        # Clear cache first
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First registration should succeed
        _register_nonce_use(key, nonce)
        
        # Cache should have one entry
        assert len(_nonce_reuse_cache) == 1
    
    def test_register_nonce_use_reuse_detected(self):
        """Test nonce reuse detection raises error."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        
        # Clear cache first
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First registration should succeed
        _register_nonce_use(key, nonce)
        
        # Second registration with same key+nonce should raise
        with pytest.raises(RuntimeError, match="Nonce reuse detected"):
            _register_nonce_use(key, nonce)
    
    def test_register_nonce_use_different_nonce_ok(self):
        """Test different nonce with same key is OK."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        
        # Clear cache first
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(12)
        nonce2 = secrets.token_bytes(12)
        
        # Both should succeed
        _register_nonce_use(key, nonce1)
        _register_nonce_use(key, nonce2)
        
        assert len(_nonce_reuse_cache) == 2


class TestPrecomputedKeyPaths:
    """Tests for hardware-derived precomputed key paths."""
    
    def test_encrypt_with_precomputed_key(self):
        """Test encryption with precomputed key (HSM/TPM path)."""
        from meow_decoder.crypto import encrypt_file_bytes, _nonce_reuse_cache
        
        # Clear cache to avoid reuse detection
        _nonce_reuse_cache.clear()
        
        raw_data = b"Secret data for hardware key test" * 10
        password = "TestPassword123"
        precomputed_key = secrets.token_bytes(32)
        precomputed_salt = secrets.token_bytes(16)
        
        comp, sha256, salt, nonce, cipher, ephemeral_key, enc_key = encrypt_file_bytes(
            raw_data,
            password,
            precomputed_key=precomputed_key,
            precomputed_salt=precomputed_salt
        )
        
        # Verify outputs
        assert len(cipher) > 0
        assert salt == precomputed_salt  # Should use provided salt
        assert ephemeral_key is None  # Hardware mode is password-only
        assert enc_key == precomputed_key  # Should use provided key
    
    def test_encrypt_with_invalid_precomputed_key_length(self):
        """Test encryption rejects wrong-length precomputed key."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        raw_data = b"test"
        password = "TestPassword123"
        bad_key = secrets.token_bytes(16)  # Wrong length - should be 32
        
        # ValueError is wrapped in RuntimeError
        with pytest.raises(RuntimeError, match="must be 32 bytes"):
            encrypt_file_bytes(
                raw_data,
                password,
                precomputed_key=bad_key,
                precomputed_salt=secrets.token_bytes(16)
            )
    
    def test_decrypt_with_precomputed_key(self):
        """Test decryption with precomputed key."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, _nonce_reuse_cache
        
        # Clear cache
        _nonce_reuse_cache.clear()
        
        raw_data = b"Test data for round trip" * 20
        password = "TestPassword123"
        precomputed_key = secrets.token_bytes(32)
        precomputed_salt = secrets.token_bytes(16)
        
        # Encrypt with precomputed key
        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            raw_data,
            password,
            precomputed_key=precomputed_key,
            precomputed_salt=precomputed_salt
        )
        
        # Decrypt with same precomputed key
        decrypted = decrypt_to_raw(
            cipher,
            password,
            salt,
            nonce,
            orig_len=len(raw_data),
            comp_len=len(comp),
            sha256=sha256,
            precomputed_key=precomputed_key
        )
        
        assert decrypted == raw_data
    
    def test_decrypt_with_invalid_precomputed_key_length(self):
        """Test decryption rejects wrong-length precomputed key."""
        from meow_decoder.crypto import decrypt_to_raw
        
        # ValueError is wrapped in RuntimeError
        with pytest.raises(RuntimeError, match="must be 32 bytes"):
            decrypt_to_raw(
                cipher=b"fake_cipher",
                password="password",
                salt=secrets.token_bytes(16),
                nonce=secrets.token_bytes(12),
                precomputed_key=secrets.token_bytes(16)  # Wrong length
            )


class TestForwardSecrecyPaths:
    """Tests for forward secrecy (X25519) code paths."""
    
    def test_forward_secrecy_key_generation(self):
        """Test ephemeral keypair generation."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys = generate_ephemeral_keypair()
        
        assert len(keys.ephemeral_private) == 32
        assert len(keys.ephemeral_public) == 32
    
    def test_forward_secrecy_shared_secret(self):
        """Test shared secret derivation."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            derive_shared_secret,
            generate_receiver_keypair
        )
        
        # Generate receiver's long-term keys
        receiver_private, receiver_public = generate_receiver_keypair()
        
        # Generate sender's ephemeral keys
        sender_keys = generate_ephemeral_keypair()
        
        password = "TestPassword123"
        salt = secrets.token_bytes(16)
        
        # Sender derives shared secret
        sender_secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt
        )
        
        # Receiver derives same shared secret
        receiver_secret = derive_shared_secret(
            receiver_private,
            sender_keys.ephemeral_public,
            password,
            salt
        )
        
        assert sender_secret == receiver_secret
        assert len(sender_secret) == 32
    
    def test_encrypt_with_forward_secrecy(self):
        """Test encryption with forward secrecy enabled."""
        from meow_decoder.crypto import encrypt_file_bytes, _nonce_reuse_cache
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        _nonce_reuse_cache.clear()
        
        # Generate receiver keys
        receiver_private, receiver_public = generate_receiver_keypair()
        
        raw_data = b"Secret data with forward secrecy" * 10
        password = "TestPassword123"
        
        comp, sha256, salt, nonce, cipher, ephemeral_key, enc_key = encrypt_file_bytes(
            raw_data,
            password,
            receiver_public_key=receiver_public
        )
        
        # Should have ephemeral public key
        assert ephemeral_key is not None
        assert len(ephemeral_key) == 32
        assert len(cipher) > 0
    
    def test_decrypt_with_forward_secrecy(self):
        """Test decryption with forward secrecy."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, _nonce_reuse_cache
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        _nonce_reuse_cache.clear()
        
        # Generate receiver keys
        receiver_private, receiver_public = generate_receiver_keypair()
        
        raw_data = b"Secret data for FS roundtrip" * 20
        password = "TestPassword123"
        
        # Encrypt with forward secrecy
        comp, sha256, salt, nonce, cipher, ephemeral_key, _ = encrypt_file_bytes(
            raw_data,
            password,
            receiver_public_key=receiver_public
        )
        
        # Decrypt with receiver's private key
        decrypted = decrypt_to_raw(
            cipher,
            password,
            salt,
            nonce,
            orig_len=len(raw_data),
            comp_len=len(comp),
            sha256=sha256,
            ephemeral_public_key=ephemeral_key,
            receiver_private_key=receiver_private
        )
        
        assert decrypted == raw_data
    
    def test_decrypt_fs_without_receiver_key_fails(self):
        """Test FS decryption without receiver key fails."""
        from meow_decoder.crypto import decrypt_to_raw
        
        # Try to decrypt with ephemeral key but no receiver private key
        # ValueError is wrapped in RuntimeError
        with pytest.raises(RuntimeError, match="requires receiver private key"):
            decrypt_to_raw(
                cipher=b"fake_cipher",
                password="password",
                salt=secrets.token_bytes(16),
                nonce=secrets.token_bytes(12),
                ephemeral_public_key=secrets.token_bytes(32),
                receiver_private_key=None  # Missing!
            )


class TestManifestVariants:
    """Tests for various manifest size variants."""
    
    def test_pack_unpack_base_manifest(self):
        """Test basic manifest packing (password-only, 115 bytes)."""
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
        assert len(packed) == 115
        
        unpacked = unpack_manifest(packed)
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.salt == manifest.salt
    
    def test_pack_unpack_fs_manifest(self):
        """Test forward secrecy manifest (147 bytes)."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=2000,
            comp_len=1600,
            cipher_len=1616,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=20,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32)  # FS enabled
        )
        
        packed = pack_manifest(manifest)
        assert len(packed) == 147
        
        unpacked = unpack_manifest(packed)
        assert unpacked.ephemeral_public_key == manifest.ephemeral_public_key
    
    def test_pack_unpack_fs_duress_manifest(self):
        """Test forward secrecy + duress manifest (179 bytes)."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=3000,
            comp_len=2400,
            cipher_len=2416,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=30,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            duress_tag=secrets.token_bytes(32)  # Duress enabled
        )
        
        packed = pack_manifest(manifest)
        assert len(packed) == 179
        
        unpacked = unpack_manifest(packed)
        assert unpacked.duress_tag == manifest.duress_tag
    
    def test_unpack_manifest_too_short(self):
        """Test manifest unpacking rejects too-short data."""
        from meow_decoder.crypto import unpack_manifest
        
        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(b"short")
    
    def test_unpack_manifest_invalid_size(self):
        """Test manifest unpacking rejects invalid sizes."""
        from meow_decoder.crypto import unpack_manifest, MAGIC
        
        # Create data with valid magic but wrong total size (130 bytes)
        invalid_data = MAGIC + secrets.token_bytes(125)
        
        with pytest.raises(ValueError, match="length invalid"):
            unpack_manifest(invalid_data)
    
    def test_unpack_manifest_wrong_magic(self):
        """Test manifest unpacking rejects wrong magic."""
        from meow_decoder.crypto import unpack_manifest
        
        # Create 115-byte manifest with wrong magic
        invalid_data = b"BADM" + b"A" + secrets.token_bytes(110)
        
        with pytest.raises(ValueError, match="Invalid MAGIC"):
            unpack_manifest(invalid_data)
    
    def test_unpack_manifest_meow2_backward_compat(self):
        """Test MEOW2 backward compatibility."""
        from meow_decoder.crypto import unpack_manifest
        
        # Create MEOW2 manifest (115 bytes with MEOW2 magic)
        magic = b"MEOW2"
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        lengths = struct.pack(">III", 1000, 800, 816)
        block_info = struct.pack(">HI", 512, 10)
        sha = secrets.token_bytes(32)
        hmac = secrets.token_bytes(32)
        
        meow2_data = magic + salt + nonce + lengths + block_info + sha + hmac
        
        # Should parse successfully (backward compat)
        manifest = unpack_manifest(meow2_data)
        assert manifest.orig_len == 1000


class TestManifestCoreAndHMAC:
    """Tests for pack_manifest_core and HMAC functions."""
    
    def test_pack_manifest_core_no_duress(self):
        """Test manifest core packing without duress tag."""
        from meow_decoder.crypto import Manifest, pack_manifest_core
        
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
        
        core = pack_manifest_core(manifest, include_duress_tag=False)
        
        # Should not include HMAC, should not include duress tag
        assert len(core) > 0
    
    def test_pack_manifest_core_with_duress(self):
        """Test manifest core packing with duress tag."""
        from meow_decoder.crypto import Manifest, pack_manifest_core
        
        duress_tag = secrets.token_bytes(32)
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            duress_tag=duress_tag
        )
        
        core_with = pack_manifest_core(manifest, include_duress_tag=True)
        core_without = pack_manifest_core(manifest, include_duress_tag=False)
        
        # Core with duress should be 32 bytes longer
        assert len(core_with) == len(core_without) + 32
    
    def test_derive_encryption_key_for_manifest(self):
        """Test key derivation for manifest verification."""
        from meow_decoder.crypto import derive_encryption_key_for_manifest
        
        password = "TestPassword123"
        salt = secrets.token_bytes(16)
        
        key = derive_encryption_key_for_manifest(password, salt)
        
        assert len(key) == 32
        
        # Same inputs should give same key
        key2 = derive_encryption_key_for_manifest(password, salt)
        assert key == key2
    
    def test_derive_encryption_key_with_precomputed(self):
        """Test key derivation returns precomputed key directly."""
        from meow_decoder.crypto import derive_encryption_key_for_manifest
        
        precomputed = secrets.token_bytes(32)
        
        key = derive_encryption_key_for_manifest(
            password="ignored",
            salt=secrets.token_bytes(16),
            precomputed_key=precomputed
        )
        
        assert key == precomputed


class TestEncryptDecryptEdgeCases:
    """Tests for edge cases in encryption/decryption."""
    
    def test_encrypt_empty_data(self):
        """Test encrypting empty data."""
        from meow_decoder.crypto import encrypt_file_bytes, _nonce_reuse_cache
        
        _nonce_reuse_cache.clear()
        
        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            b"",
            "TestPassword123"
        )
        
        # Should still work
        assert len(cipher) > 0
    
    def test_encrypt_large_data(self):
        """Test encrypting larger data."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, _nonce_reuse_cache
        
        _nonce_reuse_cache.clear()
        
        large_data = secrets.token_bytes(50000)  # 50 KB
        password = "TestPassword123"
        
        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(large_data, password)
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(large_data),
            comp_len=len(comp),
            sha256=sha256
        )
        
        assert decrypted == large_data
    
    def test_decrypt_wrong_password_fails(self):
        """Test decryption with wrong password fails."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, _nonce_reuse_cache
        
        _nonce_reuse_cache.clear()
        
        raw_data = b"Secret data" * 10
        password = "CorrectPassword123"
        wrong_password = "WrongPassword456"
        
        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(raw_data, password)
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                cipher, wrong_password, salt, nonce,
                orig_len=len(raw_data),
                comp_len=len(comp),
                sha256=sha256
            )
    
    def test_encrypt_without_length_padding(self):
        """Test encryption without length padding."""
        from meow_decoder.crypto import encrypt_file_bytes, _nonce_reuse_cache
        
        _nonce_reuse_cache.clear()
        
        raw_data = b"Test data without padding" * 10
        
        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            raw_data,
            "TestPassword123",
            use_length_padding=False
        )
        
        assert len(cipher) > 0


class TestVerifyManifestHMAC:
    """Tests for manifest HMAC verification."""
    
    def test_verify_manifest_hmac_valid(self):
        """Test HMAC verification with valid HMAC."""
        from meow_decoder.crypto import (
            Manifest, pack_manifest_core, compute_manifest_hmac,
            verify_manifest_hmac, derive_key
        )
        
        password = "TestPassword123"
        salt = secrets.token_bytes(16)
        
        # Create manifest with placeholder HMAC
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32
        )
        
        # Compute correct HMAC
        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=True)
        enc_key = derive_key(password, salt)
        manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)
        
        # Verify should pass
        assert verify_manifest_hmac(password, manifest) is True
    
    def test_verify_manifest_hmac_invalid(self):
        """Test HMAC verification with invalid HMAC."""
        from meow_decoder.crypto import Manifest, verify_manifest_hmac
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32)  # Random HMAC - will be invalid
        )
        
        # Verify should fail
        assert verify_manifest_hmac("WrongPassword", manifest) is False


class TestKeyfileHandling:
    """Tests for keyfile handling."""
    
    def test_verify_keyfile_success(self):
        """Test keyfile verification with valid file."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(256))
            keyfile_path = f.name
        
        try:
            keyfile_data = verify_keyfile(keyfile_path)
            assert len(keyfile_data) == 256
        finally:
            os.unlink(keyfile_path)
    
    def test_verify_keyfile_not_found(self):
        """Test keyfile verification with missing file."""
        from meow_decoder.crypto import verify_keyfile
        
        with pytest.raises(FileNotFoundError):
            verify_keyfile("/nonexistent/path/keyfile.key")
    
    def test_verify_keyfile_too_small(self):
        """Test keyfile verification with too-small file."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"short")  # Less than 32 bytes
            keyfile_path = f.name
        
        try:
            with pytest.raises(ValueError, match="too small"):
                verify_keyfile(keyfile_path)
        finally:
            os.unlink(keyfile_path)
    
    def test_verify_keyfile_too_large(self):
        """Test keyfile verification with too-large file."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(2 * 1024 * 1024))  # 2 MB - over 1 MB limit
            keyfile_path = f.name
        
        try:
            with pytest.raises(ValueError, match="too large"):
                verify_keyfile(keyfile_path)
        finally:
            os.unlink(keyfile_path)
    
    def test_encrypt_with_keyfile(self):
        """Test encryption with keyfile."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, _nonce_reuse_cache
        
        _nonce_reuse_cache.clear()
        
        keyfile = secrets.token_bytes(256)
        raw_data = b"Secret data with keyfile" * 10
        password = "TestPassword123"
        
        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            raw_data,
            password,
            keyfile=keyfile
        )
        
        # Decrypt with same keyfile
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, keyfile,
            orig_len=len(raw_data),
            comp_len=len(comp),
            sha256=sha256
        )
        
        assert decrypted == raw_data
    
    def test_decrypt_wrong_keyfile_fails(self):
        """Test decryption with wrong keyfile fails."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, _nonce_reuse_cache
        
        _nonce_reuse_cache.clear()
        
        keyfile = secrets.token_bytes(256)
        wrong_keyfile = secrets.token_bytes(256)
        raw_data = b"Secret data" * 10
        password = "TestPassword123"
        
        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            raw_data,
            password,
            keyfile=keyfile
        )
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                cipher, password, salt, nonce, wrong_keyfile,
                orig_len=len(raw_data),
                comp_len=len(comp),
                sha256=sha256
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
