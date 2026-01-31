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


# =============================================================================
# CONFIG MODULE TESTS (config.py - 0% coverage)
# =============================================================================

class TestConfigModule:
    """Tests for the config module to improve coverage."""
    
    def test_duress_mode_enum_values(self):
        """Test DuressMode enum has expected values."""
        from meow_decoder.config import DuressMode
        
        assert DuressMode.DECOY.value == "decoy"
        assert DuressMode.PANIC.value == "panic"
        # Verify it's a proper enum
        assert DuressMode("decoy") == DuressMode.DECOY
        assert DuressMode("panic") == DuressMode.PANIC
    
    def test_duress_config_defaults(self):
        """Test DuressConfig default values."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig()
        
        assert config.enabled is False
        assert config.mode == DuressMode.DECOY
        assert config.panic_enabled is False
        assert config.decoy_type == "message"
        assert config.decoy_message == "Decode complete."
        assert config.decoy_file_path is None
        assert config.show_decoy is True
        assert config.wipe_memory is True
        assert config.wipe_resume_files is True
        assert config.exit_after_wipe is False
        assert config.overwrite_passes == 3
        assert config.gc_aggressive is True
        assert config.min_delay_ms == 100
        assert config.max_delay_ms == 500
        assert config.trigger_callback is None
    
    def test_duress_config_custom_values(self):
        """Test DuressConfig with custom values."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.PANIC,
            panic_enabled=True,
            decoy_type="user_file",
            decoy_message="Custom message",
            min_delay_ms=200,
            max_delay_ms=1000
        )
        
        assert config.enabled is True
        assert config.mode == DuressMode.PANIC
        assert config.panic_enabled is True
        assert config.decoy_type == "user_file"
        assert config.decoy_message == "Custom message"
        assert config.min_delay_ms == 200
        assert config.max_delay_ms == 1000
    
    def test_encoding_config_defaults(self):
        """Test EncodingConfig default values."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig()
        
        assert config.block_size == 512
        assert config.redundancy == 1.5
        assert config.qr_error_correction == "H"
        assert config.qr_box_size == 14
        assert config.qr_border == 4
        assert config.fps == 2
        assert config.enable_forward_secrecy is True
        assert config.ratchet_interval == 100
        assert config.enable_stego is False
        assert config.stealth_level == 2
        assert config.enable_animation is False
        assert config.enable_low_memory is False
        assert config.enable_pq is True
        assert config.enable_duress is False
        assert config.enable_hardware_keys is True
        assert config.enable_enhanced_entropy is True
        assert config.enable_chaff_frames is False
        assert config.require_rust is True
        assert config.enable_profiling is False
    
    def test_encoding_config_custom_values(self):
        """Test EncodingConfig with custom values."""
        from meow_decoder.config import EncodingConfig
        
        config = EncodingConfig(
            block_size=256,
            redundancy=2.0,
            qr_error_correction="M",
            fps=10,
            enable_stego=True,
            stealth_level=4
        )
        
        assert config.block_size == 256
        assert config.redundancy == 2.0
        assert config.qr_error_correction == "M"
        assert config.fps == 10
        assert config.enable_stego is True
        assert config.stealth_level == 4
    
    def test_decoding_config_defaults(self):
        """Test DecodingConfig default values."""
        from meow_decoder.config import DecodingConfig
        
        config = DecodingConfig()
        
        assert config.webcam_device == 0
        assert config.frame_skip == 0
        assert config.preprocessing == "normal"
        assert config.enable_resume is True
        assert config.resume_password is None
        assert config.save_interval == 10
        assert config.enable_stego is False
        assert config.aggressive_stego is False
        assert config.max_memory_mb == 500
    
    def test_decoding_config_custom_values(self):
        """Test DecodingConfig with custom values."""
        from meow_decoder.config import DecodingConfig
        
        config = DecodingConfig(
            webcam_device=1,
            preprocessing="aggressive",
            enable_resume=False,
            resume_password="secret",
            max_memory_mb=1000
        )
        
        assert config.webcam_device == 1
        assert config.preprocessing == "aggressive"
        assert config.enable_resume is False
        assert config.resume_password == "secret"
        assert config.max_memory_mb == 1000
    
    def test_crypto_config_defaults(self):
        """Test CryptoConfig default values."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig()
        
        assert config.key_derivation == "argon2id"
        assert config.argon2_memory == 524288  # 512 MiB
        assert config.argon2_iterations == 20
        assert config.argon2_parallelism == 4
        assert config.ultra_hardened is False
        assert config.cipher == "aes-256-gcm"
        assert config.require_rust is True
        assert config.enable_forward_secrecy is True
        assert config.ratchet_interval == 50
        assert config.enable_pq is True
        assert config.kyber_variant == "kyber1024"
    
    def test_crypto_config_custom_values(self):
        """Test CryptoConfig with custom values."""
        from meow_decoder.config import CryptoConfig
        
        config = CryptoConfig(
            argon2_memory=1048576,  # 1 GiB
            argon2_iterations=40,
            ultra_hardened=True,
            kyber_variant="kyber512"
        )
        
        assert config.argon2_memory == 1048576
        assert config.argon2_iterations == 40
        assert config.ultra_hardened is True
        assert config.kyber_variant == "kyber512"
    
    def test_path_config_creates_directories(self):
        """Test PathConfig creates directories on init."""
        from meow_decoder.config import PathConfig
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = Path(tmpdir) / "cache"
            resume = Path(tmpdir) / "resume"
            temp = Path(tmpdir) / "temp"
            
            config = PathConfig(
                cache_dir=cache,
                resume_dir=resume,
                temp_dir=temp
            )
            
            assert config.cache_dir.exists()
            assert config.resume_dir.exists()
            assert config.temp_dir.exists()
    
    def test_meow_config_defaults(self):
        """Test MeowConfig aggregates all sub-configs."""
        from meow_decoder.config import MeowConfig
        
        config = MeowConfig()
        
        assert config.encoding is not None
        assert config.decoding is not None
        assert config.crypto is not None
        assert config.duress is not None
        assert config.paths is not None
        assert config.verbose is False
        assert config.debug is False
    
    def test_meow_config_save_and_load(self):
        """Test MeowConfig JSON serialization."""
        from meow_decoder.config import MeowConfig, DuressMode
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            
            # Create config with some custom values
            config = MeowConfig()
            config.encoding.block_size = 1024
            config.encoding.fps = 15
            config.crypto.argon2_iterations = 5
            config.duress.enabled = True
            config.duress.mode = DuressMode.PANIC
            config.verbose = True
            
            # Save
            config.save(config_path)
            
            assert config_path.exists()
            
            # Load
            loaded = MeowConfig.load(config_path)
            
            assert loaded.encoding.block_size == 1024
            assert loaded.encoding.fps == 15
            assert loaded.crypto.argon2_iterations == 5
            assert loaded.duress.enabled is True
            assert loaded.duress.mode == DuressMode.PANIC
            assert loaded.verbose is True
    
    def test_meow_config_load_with_missing_sections(self):
        """Test MeowConfig.load handles missing sections gracefully."""
        from meow_decoder.config import MeowConfig
        import tempfile
        import json
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "partial.json"
            
            # Write partial config
            partial = {"verbose": True, "debug": True}
            with open(config_path, 'w') as f:
                json.dump(partial, f)
            
            # Load should not crash
            config = MeowConfig.load(config_path)
            
            assert config.verbose is True
            assert config.debug is True
            # Defaults should still work
            assert config.encoding.block_size == 512
    
    def test_get_config_with_no_file(self):
        """Test get_config returns defaults when no config file exists."""
        from meow_decoder.config import get_config
        
        config = get_config()
        
        assert config is not None
        assert config.encoding is not None
        assert config.crypto is not None
    
    def test_duress_mode_invalid_value(self):
        """Test DuressMode rejects invalid values."""
        from meow_decoder.config import DuressMode
        
        with pytest.raises(ValueError):
            DuressMode("invalid")


class TestForwardSecrecyModule:
    """Tests for the forward_secrecy module."""
    
    def test_forward_secrecy_manager_init(self):
        """Test ForwardSecrecyManager initialization."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        assert manager.master_key == master_key
        assert manager.salt == salt
        assert manager.enable_ratchet is False
        assert manager.ratchet_state is None
    
    def test_forward_secrecy_manager_with_ratchet(self):
        """Test ForwardSecrecyManager with ratcheting enabled."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(
            master_key, salt, 
            enable_ratchet=True, 
            ratchet_interval=10
        )
        
        assert manager.enable_ratchet is True
        assert manager.ratchet_state is not None
        assert manager.ratchet_interval == 10
    
    def test_derive_block_key_deterministic(self):
        """Test block key derivation is deterministic."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        key1 = manager.derive_block_key(0)
        key2 = manager.derive_block_key(0)
        key3 = manager.derive_block_key(1)
        
        assert key1 == key2  # Same block = same key
        assert key1 != key3  # Different blocks = different keys
        assert len(key1) == 32
    
    def test_derive_block_key_with_ratchet(self):
        """Test block key derivation with ratcheting."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(
            master_key, salt, 
            enable_ratchet=True, 
            ratchet_interval=10
        )
        
        # Keys at blocks 0 and 10 should trigger ratchet
        key0 = manager.derive_block_key(0)
        key10 = manager.derive_block_key(10)
        key20 = manager.derive_block_key(20)
        
        assert key0 != key10 != key20
        assert manager.ratchet_state.counter >= 2
    
    def test_encrypt_decrypt_block(self):
        """Test block encryption and decryption."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        block_data = b"Test block data for encryption"
        block_id = 5
        
        nonce, ciphertext = manager.encrypt_block(block_data, block_id)
        
        assert len(nonce) == 12
        assert len(ciphertext) > len(block_data)  # Includes auth tag
        
        decrypted = manager.decrypt_block(ciphertext, nonce, block_id)
        
        assert decrypted == block_data
    
    def test_encrypt_block_different_blocks(self):
        """Test that different blocks produce different ciphertexts."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        block_data = b"Same data for both blocks"
        
        nonce1, ct1 = manager.encrypt_block(block_data, 0)
        nonce2, ct2 = manager.encrypt_block(block_data, 1)
        
        # Different block IDs should produce different outputs
        assert ct1 != ct2
        assert nonce1 != nonce2
    
    def test_get_ratchet_state_for_manifest(self):
        """Test ratchet state serialization."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Without ratchet
        manager_no_ratchet = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        assert manager_no_ratchet.get_ratchet_state_for_manifest() is None
        
        # With ratchet
        manager_with_ratchet = ForwardSecrecyManager(
            master_key, salt, 
            enable_ratchet=True, 
            ratchet_interval=10
        )
        manager_with_ratchet.derive_block_key(20)  # Trigger some ratcheting
        
        state = manager_with_ratchet.get_ratchet_state_for_manifest()
        assert state is not None
        assert len(state) == 36  # 4 bytes counter + 32 bytes chain_key
    
    def test_from_ratchet_state(self):
        """Test ForwardSecrecyManager reconstruction from serialized state."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(
            master_key, salt, 
            enable_ratchet=True, 
            ratchet_interval=10
        )
        
        # Derive some keys to advance state
        key20 = manager.derive_block_key(20)
        
        # Serialize state
        state = manager.get_ratchet_state_for_manifest()
        
        # Reconstruct
        restored = ForwardSecrecyManager.from_ratchet_state(
            master_key, salt, state, ratchet_interval=10
        )
        
        # Should derive same key for block 20
        restored_key20 = restored.derive_block_key(20)
        assert key20 == restored_key20
    
    def test_from_ratchet_state_none(self):
        """Test from_ratchet_state with None returns non-ratcheting manager."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager.from_ratchet_state(
            master_key, salt, None, ratchet_interval=10
        )
        
        assert manager.enable_ratchet is False
        assert manager.ratchet_state is None
    
    def test_invalid_master_key_length(self):
        """Test that invalid master key length raises error."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        with pytest.raises(ValueError, match="32 bytes"):
            ForwardSecrecyManager(b"short", secrets.token_bytes(16))
    
    def test_invalid_salt_length(self):
        """Test that invalid salt length raises error."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        with pytest.raises(ValueError, match="16 bytes"):
            ForwardSecrecyManager(secrets.token_bytes(32), b"short")
    
    def test_cleanup(self):
        """Test cleanup method zeros sensitive data."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(
            master_key, salt, 
            enable_ratchet=True, 
            ratchet_interval=10
        )
        
        # Derive a key to populate cache
        manager.derive_block_key(0)
        
        # Cleanup
        manager.cleanup()
        
        # Cache should be empty
        assert len(manager._key_cache) == 0
    
    def test_pack_forward_secrecy_extension(self):
        """Test packing forward secrecy manifest extension."""
        from meow_decoder.forward_secrecy import (
            ForwardSecrecyManager,
            pack_forward_secrecy_extension,
            unpack_forward_secrecy_extension
        )
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(
            master_key, salt, 
            enable_ratchet=True, 
            ratchet_interval=50
        )
        manager.derive_block_key(100)  # Advance ratchet
        
        packed = pack_forward_secrecy_extension(manager)
        
        assert len(packed) > 3  # At least type + length
        
        # Unpack (skip type/length header)
        ext_data = packed[3:]
        enabled, interval, state = unpack_forward_secrecy_extension(ext_data)
        
        assert enabled is True
        assert interval == 50
        assert state is not None
    
    def test_create_forward_secrecy_encoder(self):
        """Test convenience function for creating encoder manager."""
        from meow_decoder.forward_secrecy import create_forward_secrecy_encoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = create_forward_secrecy_encoder(
            master_key, salt, enable_ratchet=True, ratchet_interval=25
        )
        
        assert manager.enable_ratchet is True
        assert manager.ratchet_interval == 25
    
    def test_create_forward_secrecy_decoder(self):
        """Test convenience function for creating decoder manager."""
        from meow_decoder.forward_secrecy import create_forward_secrecy_decoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = create_forward_secrecy_decoder(
            master_key, salt, ratchet_state_bytes=None, ratchet_interval=25
        )
        
        assert manager.enable_ratchet is False  # None state = no ratchet


class TestRatchetState:
    """Tests for RatchetState dataclass."""
    
    def test_ratchet_state_init(self):
        """Test RatchetState initialization."""
        from meow_decoder.forward_secrecy import RatchetState
        
        chain_key = secrets.token_bytes(32)
        state = RatchetState(chain_key=chain_key, counter=5)
        
        assert state.chain_key == chain_key
        assert state.counter == 5
    
    def test_ratchet_state_default_counter(self):
        """Test RatchetState default counter value."""
        from meow_decoder.forward_secrecy import RatchetState
        
        chain_key = secrets.token_bytes(32)
        state = RatchetState(chain_key=chain_key)
        
        assert state.counter == 0
    
    def test_ratchet_state_invalid_chain_key(self):
        """Test RatchetState rejects invalid chain key."""
        from meow_decoder.forward_secrecy import RatchetState
        
        with pytest.raises(ValueError, match="32 bytes"):
            RatchetState(chain_key=b"short")


class TestX25519ForwardSecrecy:
    """Additional tests for x25519_forward_secrecy module."""
    
    def test_save_and_load_receiver_keypair(self):
        """Test saving and loading receiver keypair."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            save_receiver_keypair,
            load_receiver_keypair
        )
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_file = str(Path(tmpdir) / "private.pem")
            pub_file = str(Path(tmpdir) / "public.key")
            password = "TestKeyPassword123"
            
            # Generate
            priv_key, pub_key = generate_receiver_keypair()
            
            # Save
            save_receiver_keypair(priv_key, pub_key, priv_file, pub_file, password)
            
            assert Path(priv_file).exists()
            assert Path(pub_file).exists()
            
            # Load
            loaded_priv, loaded_pub = load_receiver_keypair(priv_file, pub_file, password)
            
            assert loaded_priv == priv_key
            assert loaded_pub == pub_key
    
    def test_save_keypair_without_password(self):
        """Test saving keypair without encryption."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            save_receiver_keypair,
            load_receiver_keypair
        )
        import tempfile
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_file = str(Path(tmpdir) / "private.pem")
            pub_file = str(Path(tmpdir) / "public.key")
            
            priv_key, pub_key = generate_receiver_keypair()
            
            # Save without password
            save_receiver_keypair(priv_key, pub_key, priv_file, pub_file, password=None)
            
            # Load without password
            loaded_priv, loaded_pub = load_receiver_keypair(priv_file, pub_file, password=None)
            
            assert loaded_priv == priv_key
            assert loaded_pub == pub_key
    
    def test_forward_secrecy_keys_dataclass(self):
        """Test ForwardSecrecyKeys dataclass."""
        from meow_decoder.x25519_forward_secrecy import ForwardSecrecyKeys
        
        priv = secrets.token_bytes(32)
        pub = secrets.token_bytes(32)
        receiver = secrets.token_bytes(32)
        
        keys = ForwardSecrecyKeys(
            ephemeral_private=priv,
            ephemeral_public=pub,
            receiver_public=receiver
        )
        
        assert keys.ephemeral_private == priv
        assert keys.ephemeral_public == pub
        assert keys.receiver_public == receiver
    
    def test_forward_secrecy_keys_no_receiver(self):
        """Test ForwardSecrecyKeys without receiver public key."""
        from meow_decoder.x25519_forward_secrecy import ForwardSecrecyKeys
        
        priv = secrets.token_bytes(32)
        pub = secrets.token_bytes(32)
        
        keys = ForwardSecrecyKeys(
            ephemeral_private=priv,
            ephemeral_public=pub
        )
        
        assert keys.receiver_public is None


class TestGIFHandlerModule:
    """Tests for gif_handler.py module."""
    
    def test_gif_encoder_init(self):
        """Test GIFEncoder initialization."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder(fps=10, loop=0)
        
        assert encoder.fps == 10
        assert encoder.loop == 0
        assert encoder.duration == 100  # 1000ms / 10fps
    
    def test_gif_encoder_default_values(self):
        """Test GIFEncoder default values."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder()
        
        assert encoder.fps == 2
        assert encoder.loop == 0
        assert encoder.duration == 500
    
    def test_gif_encoder_create_gif(self):
        """Test GIF creation from frames."""
        from meow_decoder.gif_handler import GIFEncoder
        from PIL import Image
        from pathlib import Path
        import tempfile
        
        encoder = GIFEncoder(fps=5)
        
        # Create test frames
        frames = [
            Image.new("RGB", (100, 100), "red"),
            Image.new("RGB", (100, 100), "green"),
            Image.new("RGB", (100, 100), "blue")
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test.gif"
            
            size = encoder.create_gif(frames, output_path)
            
            assert output_path.exists()
            assert size > 0
    
    def test_gif_encoder_create_gif_empty_frames(self):
        """Test GIF creation with empty frames raises error."""
        from meow_decoder.gif_handler import GIFEncoder
        from pathlib import Path
        import tempfile
        
        encoder = GIFEncoder()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test.gif"
            
            with pytest.raises(ValueError, match="No frames provided"):
                encoder.create_gif([], output_path)
    
    def test_gif_encoder_create_gif_bytes(self):
        """Test GIF creation as bytes."""
        from meow_decoder.gif_handler import GIFEncoder
        from PIL import Image
        
        encoder = GIFEncoder(fps=5)
        
        frames = [
            Image.new("RGB", (100, 100), "red"),
            Image.new("RGB", (100, 100), "green")
        ]
        
        gif_bytes = encoder.create_gif_bytes(frames)
        
        assert isinstance(gif_bytes, bytes)
        assert len(gif_bytes) > 0
        assert gif_bytes[:6] in (b"GIF87a", b"GIF89a")
    
    def test_gif_encoder_create_gif_bytes_empty_frames(self):
        """Test GIF bytes creation with empty frames raises error."""
        from meow_decoder.gif_handler import GIFEncoder
        
        encoder = GIFEncoder()
        
        with pytest.raises(ValueError, match="No frames provided"):
            encoder.create_gif_bytes([])
    
    def test_gif_decoder_init(self):
        """Test GIFDecoder initialization."""
        from meow_decoder.gif_handler import GIFDecoder
        
        decoder = GIFDecoder()
        
        # Just verify it can be instantiated
        assert decoder is not None
    
    def test_gif_decoder_extract_frames(self):
        """Test extracting frames from GIF."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from PIL import Image
        from pathlib import Path
        import tempfile
        
        # Create a test GIF first
        encoder = GIFEncoder(fps=5)
        frames = [
            Image.new("RGB", (100, 100), "red"),
            Image.new("RGB", (100, 100), "green"),
            Image.new("RGB", (100, 100), "blue")
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "test.gif"
            encoder.create_gif(frames, gif_path)
            
            # Now decode
            decoder = GIFDecoder()
            extracted = decoder.extract_frames(gif_path)
            
            assert len(extracted) == 3
            for frame in extracted:
                assert isinstance(frame, Image.Image)
                assert frame.mode == "RGB"
    
    def test_gif_decoder_extract_frames_bytes(self):
        """Test extracting frames from GIF bytes."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from PIL import Image
        
        # Create a test GIF first
        encoder = GIFEncoder(fps=5)
        frames = [
            Image.new("RGB", (100, 100), "red"),
            Image.new("RGB", (100, 100), "green")
        ]
        
        gif_bytes = encoder.create_gif_bytes(frames)
        
        # Now decode from bytes
        decoder = GIFDecoder()
        extracted = decoder.extract_frames_bytes(gif_bytes)
        
        assert len(extracted) == 2
        for frame in extracted:
            assert isinstance(frame, Image.Image)
    
    def test_gif_decoder_get_frame_count(self):
        """Test getting frame count from GIF."""
        from meow_decoder.gif_handler import GIFEncoder, GIFDecoder
        from PIL import Image
        from pathlib import Path
        import tempfile
        
        encoder = GIFEncoder()
        frames = [
            Image.new("RGB", (50, 50), "white"),
            Image.new("RGB", (50, 50), "black"),
            Image.new("RGB", (50, 50), "gray"),
            Image.new("RGB", (50, 50), "red")
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "test.gif"
            encoder.create_gif(frames, gif_path)
            
            decoder = GIFDecoder()
            count = decoder.get_frame_count(gif_path)
            
            assert count == 4
    
    def test_gif_encoder_normalizes_frame_sizes(self):
        """Test that encoder normalizes different frame sizes."""
        from meow_decoder.gif_handler import GIFEncoder
        from PIL import Image
        from pathlib import Path
        import tempfile
        
        encoder = GIFEncoder()
        
        # Create frames with different sizes
        frames = [
            Image.new("RGB", (100, 100), "red"),
            Image.new("RGB", (50, 50), "green"),  # Smaller
            Image.new("RGB", (100, 100), "blue")
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "test.gif"
            size = encoder.create_gif(frames, gif_path)
            
            assert size > 0
    
    def test_gif_encoder_converts_non_rgb_frames(self):
        """Test that encoder converts non-RGB frames."""
        from meow_decoder.gif_handler import GIFEncoder
        from PIL import Image
        from pathlib import Path
        import tempfile
        
        encoder = GIFEncoder()
        
        # Create frames with different modes
        frames = [
            Image.new("L", (100, 100), 128),  # Grayscale
            Image.new("RGBA", (100, 100), (255, 0, 0, 128)),  # RGBA
            Image.new("1", (100, 100), 1)  # Bilevel
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            gif_path = Path(tmpdir) / "test.gif"
            size = encoder.create_gif(frames, gif_path)
            
            assert size > 0


class TestQRCodeModule:
    """Tests for qr_code.py module."""
    
    def test_qr_generator_init_default(self):
        """Test QRCodeGenerator default initialization."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator()
        
        assert gen.box_size == 14
        assert gen.border == 4
    
    def test_qr_generator_init_custom(self):
        """Test QRCodeGenerator custom initialization."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator(error_correction="L", box_size=10, border=2)
        
        assert gen.box_size == 10
        assert gen.border == 2
    
    def test_qr_generator_init_all_error_levels(self):
        """Test QRCodeGenerator with all error correction levels."""
        from meow_decoder.qr_code import QRCodeGenerator
        import qrcode
        
        for level in ["L", "M", "Q", "H"]:
            gen = QRCodeGenerator(error_correction=level)
            expected_map = {
                "L": qrcode.constants.ERROR_CORRECT_L,
                "M": qrcode.constants.ERROR_CORRECT_M,
                "Q": qrcode.constants.ERROR_CORRECT_Q,
                "H": qrcode.constants.ERROR_CORRECT_H
            }
            assert gen.error_correction == expected_map[level]
    
    def test_qr_generator_generate(self):
        """Test QR code generation."""
        from meow_decoder.qr_code import QRCodeGenerator
        from PIL import Image
        
        gen = QRCodeGenerator(box_size=4, border=2)
        
        data = b"Hello World!"
        img = gen.generate(data)
        
        assert isinstance(img, Image.Image)
        assert img.mode == "RGB"
        assert img.size[0] > 0
        assert img.size[1] > 0
    
    def test_qr_generator_generate_binary_data(self):
        """Test QR code generation with binary data."""
        from meow_decoder.qr_code import QRCodeGenerator
        from PIL import Image
        
        gen = QRCodeGenerator(box_size=4)
        
        # Binary data with various byte values
        data = bytes(range(256))
        img = gen.generate(data)
        
        assert isinstance(img, Image.Image)
    
    def test_qr_generator_generate_batch(self):
        """Test batch QR code generation."""
        from meow_decoder.qr_code import QRCodeGenerator
        
        gen = QRCodeGenerator(box_size=4)
        
        data_list = [b"First", b"Second", b"Third"]
        images = gen.generate_batch(data_list)
        
        assert len(images) == 3
        for img in images:
            assert img is not None
    
    def test_qr_reader_init_default(self):
        """Test QRCodeReader default initialization."""
        from meow_decoder.qr_code import QRCodeReader
        
        reader = QRCodeReader()
        
        assert reader.preprocessing == "normal"
    
    def test_qr_reader_init_aggressive(self):
        """Test QRCodeReader with aggressive preprocessing."""
        from meow_decoder.qr_code import QRCodeReader
        
        reader = QRCodeReader(preprocessing="aggressive")
        
        assert reader.preprocessing == "aggressive"
    
    def test_qr_generate_and_read_roundtrip(self):
        """Test QR code generation and reading roundtrip."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator(box_size=10, border=4, error_correction="H")
        reader = QRCodeReader(preprocessing="normal")
        
        # Generate
        original_data = b"Test data for QR roundtrip!"
        qr_image = gen.generate(original_data)
        
        # Read
        decoded = reader.read_image(qr_image)
        
        assert len(decoded) == 1
        assert decoded[0] == original_data
    
    def test_qr_generate_and_read_binary_roundtrip(self):
        """Test QR code roundtrip with binary data."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        
        gen = QRCodeGenerator(box_size=10, border=4, error_correction="H")
        reader = QRCodeReader()
        
        # Binary data
        original_data = secrets.token_bytes(100)
        qr_image = gen.generate(original_data)
        
        # Read
        decoded = reader.read_image(qr_image)
        
        assert len(decoded) == 1
        assert decoded[0] == original_data
    
    def test_qr_reader_read_frame(self):
        """Test QRCodeReader read_frame method."""
        from meow_decoder.qr_code import QRCodeGenerator, QRCodeReader
        import numpy as np
        
        gen = QRCodeGenerator(box_size=10, border=4, error_correction="H")
        reader = QRCodeReader()
        
        # Generate QR
        data = b"Frame test data"
        qr_image = gen.generate(data)
        
        # Convert to numpy array (OpenCV format)
        frame = np.array(qr_image)
        
        # Read from frame
        decoded = reader.read_frame(frame)
        
        assert len(decoded) == 1
        assert decoded[0] == data


class TestMetadataObfuscationExtended:
    """Extended tests for metadata_obfuscation.py module."""
    
    def test_add_padding_minimum_size(self):
        """Test padding with minimum size data."""
        from meow_decoder.metadata_obfuscation import add_length_padding
        
        tiny_data = b"x"
        padded = add_length_padding(tiny_data)
        
        # Should be padded to at least some minimum size
        assert len(padded) >= len(tiny_data)
    
    def test_remove_padding_corrupted_header(self):
        """Test remove_length_padding with corrupted header."""
        from meow_decoder.metadata_obfuscation import remove_length_padding
        
        # Create data that looks like it has padding but is corrupted
        corrupted = b"\xff\xff\xff\xff" + b"some data"
        
        # Should either handle gracefully or raise ValueError
        try:
            result = remove_length_padding(corrupted)
            # If it doesn't raise, result should be something
            assert result is not None
        except ValueError:
            pass  # Expected for corrupted data
    
    def test_padding_size_classes(self):
        """Test that padding uses size classes."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        # Test various sizes
        sizes = [10, 100, 500, 1000, 5000]
        
        for size in sizes:
            data = secrets.token_bytes(size)
            padded = add_length_padding(data)
            
            # Padded should be at least as large as original
            assert len(padded) >= len(data)
            
            # Should be able to recover original
            recovered = remove_length_padding(padded)
            assert recovered == data


class TestCryptoBackendExtended:
    """Extended tests for crypto_backend.py module."""
    
    def test_backend_singleton(self):
        """Test that get_default_backend returns consistent instance."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend1 = get_default_backend()
        backend2 = get_default_backend()
        
        # Should be same backend or at least same type
        assert type(backend1) == type(backend2)
    
    def test_backend_aes_gcm_roundtrip(self):
        """Test AES-GCM encrypt/decrypt via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Backend test plaintext"
        aad = b"Additional data"
        
        # Encrypt
        ciphertext = backend.aes_gcm_encrypt(key, nonce, plaintext, aad)
        
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = backend.aes_gcm_decrypt(key, nonce, ciphertext, aad)
        
        assert decrypted == plaintext
    
    def test_backend_hmac_sha256(self):
        """Test HMAC-SHA256 via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        key = secrets.token_bytes(32)
        message = b"Message to authenticate"
        
        mac = backend.hmac_sha256(key, message)
        
        assert len(mac) == 32  # SHA256 output
        
        # Same input should produce same output
        mac2 = backend.hmac_sha256(key, message)
        assert mac == mac2
        
        # Different message should produce different MAC
        mac3 = backend.hmac_sha256(key, b"Different message")
        assert mac != mac3
    
    def test_backend_x25519_operations(self):
        """Test X25519 operations via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        # Generate keypair
        private_key, public_key = backend.x25519_generate_keypair()
        
        assert len(private_key) == 32
        assert len(public_key) == 32
        
        # Generate another keypair
        private_key2, public_key2 = backend.x25519_generate_keypair()
        
        # Perform key exchange
        shared1 = backend.x25519_exchange(private_key, public_key2)
        shared2 = backend.x25519_exchange(private_key2, public_key)
        
        # Shared secrets should match
        assert shared1 == shared2
    
    def test_backend_hkdf_derive(self):
        """Test HKDF key derivation via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test context"
        
        derived = backend.derive_key_hkdf(ikm, salt, info)
        
        assert len(derived) == 32
        
        # Same inputs should produce same output
        derived2 = backend.derive_key_hkdf(ikm, salt, info)
        assert derived == derived2
        
        # Different info should produce different key
        derived3 = backend.derive_key_hkdf(ikm, salt, b"other context")
        assert derived != derived3


class TestConstantTimeExtended:
    """Extended tests for constant_time.py module to increase coverage."""
    
    def test_secure_memory_context_manager(self):
        """Test secure_memory context manager."""
        from meow_decoder.constant_time import secure_memory
        
        original = b"sensitive password data"
        
        with secure_memory(original) as buf:
            # Should have same content
            assert bytes(buf) == original
            # Should be mutable
            buf[0] = ord('X')
            assert buf[0] == ord('X')
        
        # After context, buffer should be zeroed (best effort)
        # We can't check this directly as buf is out of scope
    
    def test_timing_safe_equal_with_delay(self):
        """Test timing_safe_equal_with_delay function."""
        from meow_decoder.constant_time import timing_safe_equal_with_delay
        import time
        
        a = b"test_value"
        b = b"test_value"
        c = b"other_value"
        
        # Test equal values
        start = time.time()
        result = timing_safe_equal_with_delay(a, b, min_delay_ms=1, max_delay_ms=5)
        elapsed = time.time() - start
        
        assert result is True
        # Should have at least some delay (2ms minimum total)
        assert elapsed >= 0.002
        
        # Test unequal values
        result2 = timing_safe_equal_with_delay(a, c, min_delay_ms=1, max_delay_ms=2)
        assert result2 is False
    
    def test_equalize_timing_sleep(self):
        """Test equalize_timing function."""
        from meow_decoder.constant_time import equalize_timing
        import time
        
        # Simulate fast operation
        start = time.time()
        time.sleep(0.01)  # 10ms operation
        elapsed = time.time() - start
        
        # Equalize to 50ms
        equalize_timing(elapsed, target_time=0.05)
        
        total = time.time() - start
        # Total should be close to 50ms
        assert total >= 0.04  # Allow some margin
    
    def test_equalize_timing_no_sleep_if_exceeded(self):
        """Test equalize_timing does nothing if operation exceeds target."""
        from meow_decoder.constant_time import equalize_timing
        import time
        
        # If operation took longer than target, should not sleep
        start = time.time()
        equalize_timing(operation_time=0.2, target_time=0.1)
        elapsed = time.time() - start
        
        # Should return immediately (no significant delay)
        assert elapsed < 0.05
    
    def test_secure_buffer_basic_operations(self):
        """Test SecureBuffer basic read/write."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(64) as buf:
            # Write data
            buf.write(b"Hello, World!", offset=0)
            
            # Read back
            data = buf.read(13, offset=0)
            assert data == b"Hello, World!"
            
            # Read all
            all_data = buf.read()
            assert len(all_data) == 64
            assert all_data[:13] == b"Hello, World!"
    
    def test_secure_buffer_write_at_offset(self):
        """Test SecureBuffer write at offset."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(32) as buf:
            buf.write(b"First", offset=0)
            buf.write(b"Second", offset=10)
            
            data = buf.read()
            assert data[:5] == b"First"
            assert data[10:16] == b"Second"
    
    def test_secure_buffer_write_overflow_raises(self):
        """Test SecureBuffer raises on overflow."""
        from meow_decoder.constant_time import SecureBuffer
        
        with SecureBuffer(10) as buf:
            with pytest.raises(ValueError, match="too large"):
                buf.write(b"This is way too long for the buffer", offset=0)
    
    def test_secure_buffer_context_manager(self):
        """Test SecureBuffer context manager protocol."""
        from meow_decoder.constant_time import SecureBuffer
        
        buf = SecureBuffer(16)
        assert buf is not None
        
        # Enter context
        result = buf.__enter__()
        assert result is buf
        
        # Write some data
        buf.write(b"test")
        
        # Exit context
        buf.__exit__(None, None, None)
    
    def test_secure_zero_memory_bytearray(self):
        """Test secure_zero_memory on bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        data = bytearray(b"sensitive data here")
        original_len = len(data)
        
        secure_zero_memory(data)
        
        # Should still have same length
        assert len(data) == original_len
        # All bytes should be zero (or at least attempted)
        assert all(b == 0 for b in data)
    
    def test_secure_zero_memory_empty_bytearray(self):
        """Test secure_zero_memory on empty bytearray."""
        from meow_decoder.constant_time import secure_zero_memory
        
        data = bytearray()
        
        # Should not raise
        secure_zero_memory(data)
        
        assert len(data) == 0
    
    def test_constant_time_compare_equal(self):
        """Test constant_time_compare with equal values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"exact_match_value"
        b = b"exact_match_value"
        
        assert constant_time_compare(a, b) is True
    
    def test_constant_time_compare_unequal(self):
        """Test constant_time_compare with unequal values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"value_one"
        b = b"value_two"
        
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_different_lengths(self):
        """Test constant_time_compare with different length values."""
        from meow_decoder.constant_time import constant_time_compare
        
        a = b"short"
        b = b"much_longer_value"
        
        assert constant_time_compare(a, b) is False


class TestFountainExtended:
    """Extended tests for fountain.py to improve coverage."""
    
    def test_robust_soliton_very_small_k(self):
        """Test RobustSolitonDistribution with k=1."""
        from meow_decoder.fountain import RobustSolitonDistribution
        
        dist = RobustSolitonDistribution(k=1)
        
        # Sample multiple times
        for _ in range(10):
            degree = dist.sample_degree()
            assert degree >= 1
    
    def test_fountain_decoder_incomplete(self):
        """Test FountainDecoder when decoding is incomplete."""
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(k_blocks=10, block_size=64)
        
        assert not decoder.is_complete()
        
        # Try to get data before complete - should raise
        with pytest.raises(RuntimeError, match="incomplete"):
            decoder.get_data(original_length=500)
    
    def test_fountain_encoder_droplet_reproducibility(self):
        """Test that droplets with same seed are reproducible."""
        from meow_decoder.fountain import FountainEncoder
        
        data = b"Test data for fountain encoding" * 10
        k_blocks = 5
        block_size = 64
        
        encoder1 = FountainEncoder(data, k_blocks, block_size)
        encoder2 = FountainEncoder(data, k_blocks, block_size)
        
        # Same seed should produce same droplet
        droplet1 = encoder1.droplet(seed=42)
        droplet2 = encoder2.droplet(seed=42)
        
        assert droplet1.seed == droplet2.seed
        assert droplet1.data == droplet2.data
    
    def test_fountain_decoder_redundant_droplet(self):
        """Test decoder handles redundant droplets."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder, Droplet
        
        data = b"Short test data"
        k_blocks = 2
        block_size = 16
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)
        
        # Add some droplets
        droplet1 = encoder.droplet(seed=0)
        droplet2 = encoder.droplet(seed=1)
        
        decoder.add_droplet(droplet1)
        decoder.add_droplet(droplet2)
        
        # Adding same droplet again should be handled gracefully
        decoder.add_droplet(droplet1)
    
    def test_pack_unpack_droplet_roundtrip(self):
        """Test pack_droplet and unpack_droplet roundtrip."""
        from meow_decoder.fountain import FountainEncoder, pack_droplet, unpack_droplet
        
        data = b"Test data for pack/unpack" * 10
        k_blocks = 5
        block_size = 64
        
        encoder = FountainEncoder(data, k_blocks, block_size)
        droplet = encoder.droplet(seed=100)
        
        # Pack
        packed = pack_droplet(droplet)
        assert isinstance(packed, bytes)
        
        # Unpack
        unpacked = unpack_droplet(packed, block_size)
        
        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data


class TestCryptoEnhancedModule:
    """Tests for crypto_enhanced.py module."""
    
    def test_secure_bytes_init_from_data(self):
        """Test SecureBytes initialization from data."""
        from meow_decoder.crypto_enhanced import SecureBytes
        
        data = b"sensitive data"
        secure = SecureBytes(data)
        
        assert len(secure) == len(data)
        assert secure.get_bytes() == data
    
    def test_secure_bytes_init_from_size(self):
        """Test SecureBytes initialization from size."""
        from meow_decoder.crypto_enhanced import SecureBytes
        
        secure = SecureBytes(size=32)
        
        assert len(secure) == 32
    
    def test_secure_bytes_context_manager(self):
        """Test SecureBytes as context manager."""
        from meow_decoder.crypto_enhanced import SecureBytes
        
        with SecureBytes(b"test data") as secure:
            data = secure.get_bytes()
            assert data == b"test data"
            
            # Can get mutable data
            mutable = secure.get_data()
            assert isinstance(mutable, bytearray)
    
    def test_secure_bytes_zero(self):
        """Test SecureBytes explicit zeroing."""
        from meow_decoder.crypto_enhanced import SecureBytes
        
        secure = SecureBytes(b"secret")
        original_len = len(secure)
        
        secure.zero()
        
        # After zeroing, internal data should be cleared
        # (we can't easily verify but at least it shouldn't crash)
    
    def test_secure_key_context(self):
        """Test secure_key_context."""
        from meow_decoder.crypto_enhanced import secure_key_context
        
        key = secrets.token_bytes(32)
        
        with secure_key_context(key) as secure_key:
            assert secure_key == key
            assert len(secure_key) == 32


class TestFrameMacExtended:
    """Extended tests for frame_mac.py module."""
    
    def test_frame_mac_stats_tracking(self):
        """Test FrameMACStats tracking."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        assert stats.valid_frames == 0
        assert stats.invalid_frames == 0
        
        stats.record_valid()
        stats.record_valid()
        stats.record_invalid()
        
        assert stats.valid_frames == 2
        assert stats.invalid_frames == 1
        assert stats.success_rate() == 2/3
    
    def test_frame_mac_stats_empty(self):
        """Test FrameMACStats with no frames."""
        from meow_decoder.frame_mac import FrameMACStats
        
        stats = FrameMACStats()
        
        # Should handle zero division
        rate = stats.success_rate()
        assert rate == 0.0 or rate == 1.0  # Implementation dependent
    
    def test_derive_frame_master_key_consistency(self):
        """Test frame master key derivation is consistent."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        enc_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(enc_key, salt)
        key2 = derive_frame_master_key(enc_key, salt)
        
        assert key1 == key2
        assert len(key1) == 32
    
    def test_derive_frame_master_key_different_inputs(self):
        """Test frame master key differs with different inputs."""
        from meow_decoder.frame_mac import derive_frame_master_key
        
        enc_key = secrets.token_bytes(32)
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        key1 = derive_frame_master_key(enc_key, salt1)
        key2 = derive_frame_master_key(enc_key, salt2)
        
        assert key1 != key2


class TestCryptoEnhancedExtended:
    """Extended tests for crypto_enhanced.py module."""
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt_file_bytes and decrypt_to_raw roundtrip."""
        from meow_decoder.crypto_enhanced import encrypt_file_bytes, decrypt_to_raw
        
        raw_data = b"Sensitive data for enhanced crypto test"
        password = "EnhancedPassword123!"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(raw_data, password)
        
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(sha) == 32
        
        # Decrypt
        decrypted = decrypt_to_raw(cipher, password, salt, nonce)
        
        assert decrypted == raw_data
    
    def test_encrypt_with_keyfile(self):
        """Test encryption with keyfile."""
        from meow_decoder.crypto_enhanced import encrypt_file_bytes, decrypt_to_raw
        
        raw_data = b"Secret data with keyfile"
        password = "TestPassword123!"
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(raw_data, password, keyfile)
        
        # Decrypt with same keyfile
        decrypted = decrypt_to_raw(cipher, password, salt, nonce, keyfile)
        
        assert decrypted == raw_data
    
    def test_decrypt_wrong_password_fails(self):
        """Test decryption with wrong password fails."""
        from meow_decoder.crypto_enhanced import encrypt_file_bytes, decrypt_to_raw
        
        raw_data = b"Secret data"
        password = "RightPassword123"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(raw_data, password)
        
        # Wrong password should fail
        with pytest.raises(RuntimeError):
            decrypt_to_raw(cipher, "WrongPassword456", salt, nonce)
    
    def test_pack_unpack_manifest_roundtrip(self):
        """Test manifest packing and unpacking."""
        from meow_decoder.crypto_enhanced import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=5,
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
    
    def test_unpack_manifest_too_short(self):
        """Test unpacking manifest that's too short."""
        from meow_decoder.crypto_enhanced import unpack_manifest
        
        short_data = b"MEOW2" + b"\x00" * 10
        
        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(short_data)
    
    def test_unpack_manifest_wrong_magic(self):
        """Test unpacking manifest with wrong magic."""
        from meow_decoder.crypto_enhanced import unpack_manifest
        
        # Create data with wrong magic
        bad_data = b"XXXX" + b"\x00" * 120
        
        with pytest.raises(ValueError, match="Invalid MAGIC"):
            unpack_manifest(bad_data)
    
    def test_derive_key_empty_password_fails(self):
        """Test key derivation with empty password fails."""
        from meow_decoder.crypto_enhanced import derive_key
        
        with pytest.raises(ValueError, match="empty"):
            derive_key("", secrets.token_bytes(16))
    
    def test_derive_key_wrong_salt_length_fails(self):
        """Test key derivation with wrong salt length fails."""
        from meow_decoder.crypto_enhanced import derive_key
        
        with pytest.raises(ValueError, match="16 bytes"):
            derive_key("password", b"short")
    
    def test_compute_manifest_hmac(self):
        """Test compute_manifest_hmac function."""
        from meow_decoder.crypto_enhanced import compute_manifest_hmac
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        packed_no_hmac = b"manifest_data_without_hmac_field"
        
        hmac1 = compute_manifest_hmac(password, salt, packed_no_hmac)
        hmac2 = compute_manifest_hmac(password, salt, packed_no_hmac)
        
        assert hmac1 == hmac2
        assert len(hmac1) == 32
    
    def test_verify_manifest_hmac_match(self):
        """Test verify_manifest_hmac with matching HMACs."""
        from meow_decoder.crypto_enhanced import verify_manifest_hmac
        
        hmac1 = secrets.token_bytes(32)
        
        assert verify_manifest_hmac(hmac1, hmac1) is True
    
    def test_verify_manifest_hmac_mismatch(self):
        """Test verify_manifest_hmac with mismatched HMACs."""
        from meow_decoder.crypto_enhanced import verify_manifest_hmac
        
        hmac1 = secrets.token_bytes(32)
        hmac2 = secrets.token_bytes(32)
        
        assert verify_manifest_hmac(hmac1, hmac2) is False
    
    def test_derive_block_key(self):
        """Test derive_block_key for forward secrecy."""
        from meow_decoder.crypto_enhanced import derive_block_key
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key0 = derive_block_key(master_key, block_id=0, salt=salt)
        key1 = derive_block_key(master_key, block_id=1, salt=salt)
        key0_again = derive_block_key(master_key, block_id=0, salt=salt)
        
        assert len(key0) == 32
        assert key0 != key1  # Different blocks should have different keys
        assert key0 == key0_again  # Same block should produce same key


class TestMetadataObfuscationFull:
    """Full tests for metadata_obfuscation.py module."""
    
    def test_add_and_remove_padding_roundtrip(self):
        """Test add_length_padding and remove_length_padding roundtrip."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b"This is the original data to be padded"
        
        padded = add_length_padding(original)
        
        # Padded should be larger or equal
        assert len(padded) >= len(original)
        
        # Should be able to recover original
        recovered = remove_length_padding(padded)
        
        assert recovered == original
    
    def test_padding_various_sizes(self):
        """Test padding with various data sizes."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        for size in [10, 100, 1000, 10000, 50000]:
            original = secrets.token_bytes(size)
            padded = add_length_padding(original)
            recovered = remove_length_padding(padded)
            
            assert recovered == original, f"Failed for size {size}"
    
    def test_padding_empty_data(self):
        """Test padding with empty data."""
        from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding
        
        original = b""
        
        padded = add_length_padding(original)
        recovered = remove_length_padding(padded)
        
        assert recovered == original


class TestX25519ForwardSecrecyExtended:
    """Extended tests for x25519_forward_secrecy.py module."""
    
    def test_generate_ephemeral_keypair(self):
        """Test generate_ephemeral_keypair function."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys = generate_ephemeral_keypair()
        
        assert len(keys.ephemeral_private) == 32
        assert len(keys.ephemeral_public) == 32
        assert keys.ephemeral_private != keys.ephemeral_public
    
    def test_serialize_deserialize_public_key(self):
        """Test serialize and deserialize public key."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            serialize_public_key,
            deserialize_public_key
        )
        
        keys = generate_ephemeral_keypair()
        
        serialized = serialize_public_key(keys.ephemeral_public)
        deserialized = deserialize_public_key(serialized)
        
        assert deserialized == keys.ephemeral_public
    
    def test_deserialize_invalid_length_fails(self):
        """Test deserialize_public_key with invalid length."""
        from meow_decoder.x25519_forward_secrecy import deserialize_public_key
        
        with pytest.raises(ValueError, match="32 bytes"):
            deserialize_public_key(b"short")
    
    def test_derive_shared_secret(self):
        """Test derive_shared_secret function."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            generate_receiver_keypair,
            derive_shared_secret
        )
        
        # Sender generates ephemeral keys
        sender_keys = generate_ephemeral_keypair()
        
        # Receiver has long-term keys
        receiver_private, receiver_public = generate_receiver_keypair()
        
        password = "SharedPassword123!"
        salt = secrets.token_bytes(16)
        
        # Sender derives shared secret
        sender_secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt
        )
        
        # Receiver derives shared secret
        receiver_secret = derive_shared_secret(
            receiver_private,
            sender_keys.ephemeral_public,
            password,
            salt
        )
        
        assert sender_secret == receiver_secret
        assert len(sender_secret) == 32


class TestDuressModeModule:
    """Tests for duress_mode.py module."""
    
    def test_duress_config_defaults(self):
        """Test DuressConfig default values."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig()
        
        assert config.enabled is False
        assert config.mode == DuressMode.DECOY
        assert config.panic_enabled is False
        assert config.wipe_memory is True
    
    def test_duress_config_panic_mode(self):
        """Test DuressConfig with panic mode."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.PANIC,
            panic_enabled=True
        )
        
        assert config.enabled is True
        assert config.mode == DuressMode.PANIC
        assert config.panic_enabled is True
    
    def test_duress_config_custom_values(self):
        """Test DuressConfig with custom values."""
        from meow_decoder.config import DuressConfig, DuressMode
        
        config = DuressConfig(
            enabled=True,
            mode=DuressMode.DECOY,
            decoy_message="Custom decoy message",
            overwrite_passes=5,
            min_delay_ms=200,
            max_delay_ms=1000
        )
        
        assert config.decoy_message == "Custom decoy message"
        assert config.overwrite_passes == 5
        assert config.min_delay_ms == 200
        assert config.max_delay_ms == 1000


class TestForwardSecrecyEncoderModule:
    """Tests for forward_secrecy_encoder.py module (0% coverage target)."""
    
    def test_secure_droplet_dataclass(self):
        """Test SecureDroplet dataclass initialization."""
        from meow_decoder.forward_secrecy_encoder import SecureDroplet
        
        droplet = SecureDroplet(
            seed=12345,
            block_indices=[0, 1, 2],
            encrypted_data=b"encrypted_data_here",
            nonces=[b"nonce_1_____", b"nonce_2_____"],
            block_id=42
        )
        
        assert droplet.seed == 12345
        assert droplet.block_indices == [0, 1, 2]
        assert droplet.encrypted_data == b"encrypted_data_here"
        assert len(droplet.nonces) == 2
        assert droplet.block_id == 42
    
    def test_forward_secrecy_fountain_encoder_init(self):
        """Test ForwardSecrecyFountainEncoder initialization."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        # Create base fountain encoder
        test_data = b"Test data for fountain encoding!" * 10
        k_blocks = 5
        block_size = 64
        fountain = FountainEncoder(test_data, k_blocks, block_size)
        
        # Wrap with forward secrecy
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True,
            ratchet_interval=50
        )
        
        assert fs_encoder.fountain == fountain
        assert fs_encoder.droplet_counter == 0
        assert fs_encoder.fs_manager is not None
    
    def test_forward_secrecy_fountain_encoder_no_ratchet(self):
        """Test ForwardSecrecyFountainEncoder without ratcheting."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"Test data!" * 20
        fountain = FountainEncoder(test_data, 8, 32)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=False
        )
        
        assert fs_encoder.fs_manager is not None
        assert fs_encoder.droplet_counter == 0
    
    def test_forward_secrecy_encoder_get_fs_extension(self):
        """Test getting forward secrecy extension for manifest."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"Data for extension test" * 5
        fountain = FountainEncoder(test_data, 4, 32)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True
        )
        
        extension = fs_encoder.get_fs_extension()
        
        assert isinstance(extension, bytes)
        assert len(extension) > 0
    
    def test_forward_secrecy_encoder_cleanup(self):
        """Test cleanup method."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"Cleanup test data" * 10
        fountain = FountainEncoder(test_data, 5, 32)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True
        )
        
        # Should not raise
        fs_encoder.cleanup()


class TestForwardSecrecyDecoderModule:
    """Tests for forward_secrecy_decoder.py module (0% coverage target)."""
    
    def test_forward_secrecy_fountain_decoder_init(self):
        """Test ForwardSecrecyFountainDecoder initialization."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.fountain import FountainDecoder
        
        k_blocks = 5
        block_size = 64
        decoder = FountainDecoder(k_blocks, block_size)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=decoder,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=None,
            ratchet_interval=100
        )
        
        assert fs_decoder.fountain == decoder
        assert fs_decoder.fs_manager is not None
    
    def test_forward_secrecy_fountain_decoder_with_ratchet_state(self):
        """Test ForwardSecrecyFountainDecoder with ratchet state."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        from meow_decoder.fountain import FountainDecoder
        import struct
        
        k_blocks = 4
        block_size = 32
        decoder = FountainDecoder(k_blocks, block_size)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create ratchet state bytes (counter + chain_key)
        # Format: 4 bytes counter + 32 bytes chain_key
        ratchet_state = struct.pack(">I", 5) + secrets.token_bytes(32)
        
        fs_decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=decoder,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=ratchet_state,
            ratchet_interval=50
        )
        
        assert fs_decoder.fs_manager is not None
    
    def test_forward_secrecy_decoder_is_complete(self):
        """Test is_complete method."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.fountain import FountainDecoder
        
        k_blocks = 3
        block_size = 32
        decoder = FountainDecoder(k_blocks, block_size)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=decoder,
            master_key=master_key,
            salt=salt
        )
        
        # Should not be complete initially
        assert fs_decoder.is_complete() is False
    
    def test_forward_secrecy_decoder_cleanup(self):
        """Test cleanup method."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.fountain import FountainDecoder
        
        decoder = FountainDecoder(5, 32)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=decoder,
            master_key=master_key,
            salt=salt
        )
        
        # Should not raise
        fs_decoder.cleanup()
    
    def test_parse_manifest_v3_forward_secrecy_empty(self):
        """Test parsing empty extension data."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        
        # Empty extensions
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(b"")
        
        assert fs_enabled is False
        assert interval == 100
        assert state is None
    
    def test_parse_manifest_v3_forward_secrecy_too_short(self):
        """Test parsing extension data that's too short."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        
        # Too short
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(b"\x01\x00")
        
        assert fs_enabled is False
        assert interval == 100
        assert state is None
    
    def test_parse_manifest_v3_forward_secrecy_wrong_type(self):
        """Test parsing extension with wrong type."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        import struct
        
        # Type 0x02 (not FS type 0x01)
        ext_data = b"\x02" + struct.pack(">H", 5) + b"\x00" * 5
        
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(ext_data)
        
        assert fs_enabled is False
        assert interval == 100
        assert state is None


class TestForwardSecrecyX25519Module:
    """Tests for forward_secrecy_x25519.py module (0% coverage target)."""
    
    def test_ephemeral_keypair_generate(self):
        """Test EphemeralKeyPair generation."""
        from meow_decoder.forward_secrecy_x25519 import EphemeralKeyPair
        
        keypair = EphemeralKeyPair.generate()
        
        assert keypair.private_key is not None
        assert keypair.public_key is not None
    
    def test_ephemeral_keypair_public_bytes(self):
        """Test public key serialization."""
        from meow_decoder.forward_secrecy_x25519 import EphemeralKeyPair
        
        keypair = EphemeralKeyPair.generate()
        public_bytes = keypair.public_bytes()
        
        assert len(public_bytes) == 32
        assert isinstance(public_bytes, bytes)
    
    def test_ephemeral_keypair_different_keys(self):
        """Test that each generation creates different keys."""
        from meow_decoder.forward_secrecy_x25519 import EphemeralKeyPair
        
        keypair1 = EphemeralKeyPair.generate()
        keypair2 = EphemeralKeyPair.generate()
        
        assert keypair1.public_bytes() != keypair2.public_bytes()
    
    def test_derive_hybrid_key_password_only(self):
        """Test derive_hybrid_key without shared secret."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key
        
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        
        key = derive_hybrid_key(password, salt, shared_secret=None)
        
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_derive_hybrid_key_with_shared_secret(self):
        """Test derive_hybrid_key with shared secret."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key
        
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        shared_secret = secrets.token_bytes(32)
        
        key = derive_hybrid_key(password, salt, shared_secret=shared_secret)
        
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_derive_hybrid_key_different_with_shared_secret(self):
        """Test that shared secret changes the derived key."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key
        
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        shared_secret = secrets.token_bytes(32)
        
        key_without = derive_hybrid_key(password, salt, shared_secret=None)
        key_with = derive_hybrid_key(password, salt, shared_secret=shared_secret)
        
        assert key_without != key_with
    
    def test_derive_hybrid_key_invalid_salt_length(self):
        """Test that invalid salt length raises error."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key
        
        password = "test_password_123"
        salt = secrets.token_bytes(10)  # Wrong length
        
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            derive_hybrid_key(password, salt)
    
    def test_derive_hybrid_key_deterministic(self):
        """Test that same inputs produce same key."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key
        
        password = "test_password_123"
        salt = b"fixed_salt_16b__"  # 16 bytes
        
        key1 = derive_hybrid_key(password, salt)
        key2 = derive_hybrid_key(password, salt)
        
        assert key1 == key2
    
    def test_derive_hybrid_key_custom_info(self):
        """Test derive_hybrid_key with custom info parameter."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key
        
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        shared_secret = secrets.token_bytes(32)
        
        key1 = derive_hybrid_key(password, salt, shared_secret, info=b"custom_info_1")
        key2 = derive_hybrid_key(password, salt, shared_secret, info=b"custom_info_2")
        
        # Different info should produce different keys
        assert key1 != key2
    
    def test_encrypt_with_forward_secrecy_password_only(self):
        """Test encryption without receiver public key (password-only mode)."""
        from meow_decoder.forward_secrecy_x25519 import encrypt_with_forward_secrecy
        
        plaintext = b"Secret message for testing"
        password = "test_password_123"
        
        ciphertext, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
            plaintext, password, receiver_public_key=None
        )
        
        assert len(ciphertext) > 0
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(ephemeral_pub) == 0  # No ephemeral key in password-only mode
    
    def test_encrypt_with_forward_secrecy_full(self):
        """Test encryption with receiver public key (forward secrecy mode)."""
        from meow_decoder.forward_secrecy_x25519 import (
            encrypt_with_forward_secrecy, EphemeralKeyPair
        )
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        
        # Generate receiver keypair
        receiver_private = X25519PrivateKey.generate()
        receiver_public_bytes = receiver_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        plaintext = b"Secret message with forward secrecy!"
        password = "test_password_123"
        
        ciphertext, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
            plaintext, password, receiver_public_key=receiver_public_bytes
        )
        
        assert len(ciphertext) > 0
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(ephemeral_pub) == 32  # Ephemeral public key present
    
    def test_encrypt_decrypt_roundtrip_password_only(self):
        """Test full encryption/decryption roundtrip without FS."""
        from meow_decoder.forward_secrecy_x25519 import (
            encrypt_with_forward_secrecy,
            decrypt_with_forward_secrecy
        )
        
        plaintext = b"Test message for roundtrip!"
        password = "test_password_123"
        
        # Encrypt
        ciphertext, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
            plaintext, password, receiver_public_key=None
        )
        
        # Decrypt
        decrypted = decrypt_with_forward_secrecy(
            ciphertext, password, salt, nonce, ephemeral_pub,
            receiver_private_key=None,
            orig_len=len(plaintext)
        )
        
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_roundtrip_with_forward_secrecy(self):
        """Test full encryption/decryption roundtrip with forward secrecy."""
        from meow_decoder.forward_secrecy_x25519 import (
            encrypt_with_forward_secrecy,
            decrypt_with_forward_secrecy
        )
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        
        # Generate receiver keypair
        receiver_private = X25519PrivateKey.generate()
        receiver_public_bytes = receiver_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        receiver_private_bytes = receiver_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        plaintext = b"Secret message with forward secrecy for roundtrip!"
        password = "test_password_123"
        
        # Encrypt
        ciphertext, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
            plaintext, password, receiver_public_key=receiver_public_bytes
        )
        
        # Decrypt
        decrypted = decrypt_with_forward_secrecy(
            ciphertext, password, salt, nonce, ephemeral_pub,
            receiver_private_key=receiver_private_bytes,
            orig_len=len(plaintext)
        )
        
        assert decrypted == plaintext
    
    def test_decrypt_forward_secrecy_missing_private_key(self):
        """Test that decryption fails without receiver private key in FS mode."""
        from meow_decoder.forward_secrecy_x25519 import (
            encrypt_with_forward_secrecy,
            decrypt_with_forward_secrecy
        )
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        
        # Generate receiver keypair
        receiver_private = X25519PrivateKey.generate()
        receiver_public_bytes = receiver_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        plaintext = b"Secret message"
        password = "test_password_123"
        
        # Encrypt with forward secrecy
        ciphertext, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
            plaintext, password, receiver_public_key=receiver_public_bytes
        )
        
        # Try to decrypt without private key - should fail
        with pytest.raises(ValueError, match="Forward secrecy mode requires receiver private key"):
            decrypt_with_forward_secrecy(
                ciphertext, password, salt, nonce, ephemeral_pub,
                receiver_private_key=None
            )


class TestForwardSecrecyEncoderAdvanced:
    """Advanced tests for forward_secrecy_encoder.py to increase coverage."""
    
    def test_next_secure_droplet(self):
        """Test next_secure_droplet method generates encrypted droplets."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder, SecureDroplet
        from meow_decoder.fountain import FountainEncoder
        
        # Create test data and encoder
        test_data = b"X" * 256  # 256 bytes of test data
        k_blocks = 4
        block_size = 64
        fountain = FountainEncoder(test_data, k_blocks, block_size)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True
        )
        
        # Generate a secure droplet
        droplet = fs_encoder.next_secure_droplet()
        
        assert isinstance(droplet, SecureDroplet)
        assert isinstance(droplet.seed, int)
        assert isinstance(droplet.block_indices, list)
        assert len(droplet.block_indices) > 0
        assert isinstance(droplet.encrypted_data, bytes)
        assert len(droplet.encrypted_data) > 0
        assert isinstance(droplet.nonces, list)
        assert len(droplet.nonces) == 1  # Single nonce per droplet
        assert droplet.block_id == 0  # First droplet
    
    def test_next_secure_droplet_increments_counter(self):
        """Test that droplet counter increments with each call."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"Y" * 512
        fountain = FountainEncoder(test_data, 8, 64)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=False
        )
        
        assert fs_encoder.droplet_counter == 0
        
        droplet1 = fs_encoder.next_secure_droplet()
        assert droplet1.block_id == 0
        assert fs_encoder.droplet_counter == 1
        
        droplet2 = fs_encoder.next_secure_droplet()
        assert droplet2.block_id == 1
        assert fs_encoder.droplet_counter == 2
        
        droplet3 = fs_encoder.next_secure_droplet()
        assert droplet3.block_id == 2
        assert fs_encoder.droplet_counter == 3
    
    def test_create_secure_fountain_encoder_with_fs(self):
        """Test create_secure_fountain_encoder factory function with FS enabled."""
        from meow_decoder.forward_secrecy_encoder import (
            create_secure_fountain_encoder,
            ForwardSecrecyFountainEncoder
        )
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"Factory test data" * 10
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=test_data,
            k_blocks=5,
            block_size=32,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=FountainEncoder,
            enable_forward_secrecy=True,
            ratchet_interval=50
        )
        
        assert isinstance(encoder, ForwardSecrecyFountainEncoder)
    
    def test_create_secure_fountain_encoder_without_fs(self):
        """Test create_secure_fountain_encoder with FS disabled."""
        from meow_decoder.forward_secrecy_encoder import create_secure_fountain_encoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"No FS test data" * 10
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=test_data,
            k_blocks=5,
            block_size=32,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=FountainEncoder,
            enable_forward_secrecy=False
        )
        
        # Should return unwrapped FountainEncoder
        assert isinstance(encoder, FountainEncoder)
    
    def test_encrypt_droplet_data_internal(self):
        """Test _encrypt_droplet_data internal method."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"Z" * 256
        fountain = FountainEncoder(test_data, 4, 64)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True
        )
        
        # Call internal method directly
        xor_data = b"A" * 64
        block_indices = [0, 2]
        droplet_id = 5
        
        ciphertext, nonces = fs_encoder._encrypt_droplet_data(xor_data, block_indices, droplet_id)
        
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) > 0
        assert isinstance(nonces, list)
        assert len(nonces) == 1
        assert len(nonces[0]) == 12  # AES-GCM nonce size
    
    def test_encrypt_droplet_data_empty_indices(self):
        """Test _encrypt_droplet_data with empty block indices."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"W" * 128
        fountain = FountainEncoder(test_data, 2, 64)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Empty indices should fall back to droplet_id
        xor_data = b"B" * 64
        block_indices = []
        droplet_id = 10
        
        ciphertext, nonces = fs_encoder._encrypt_droplet_data(xor_data, block_indices, droplet_id)
        
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) > 0


class TestForwardSecrecyDecoderAdvanced:
    """Advanced tests for forward_secrecy_decoder.py to increase coverage."""
    
    def test_process_secure_droplet(self):
        """Test process_secure_droplet method for decryption."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        # Create matching encoder/decoder with same keys
        test_data = b"Test droplet processing!" * 10
        k_blocks = 5
        block_size = 64
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create encoder
        fountain_enc = FountainEncoder(test_data, k_blocks, block_size)
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain_enc,
            master_key=master_key,
            salt=salt,
            enable_ratchet=False
        )
        
        # Create decoder
        fountain_dec = FountainDecoder(k_blocks, block_size)
        fs_decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=fountain_dec,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=None
        )
        
        # Generate and process secure droplet
        droplet = fs_encoder.next_secure_droplet()
        
        # Process the droplet - should decrypt and pass to fountain decoder
        result = fs_decoder.process_secure_droplet(
            encrypted_data=droplet.encrypted_data,
            nonce=droplet.nonces[0],
            block_indices=droplet.block_indices,
            seed=droplet.seed
        )
        
        # Result depends on whether decoding is complete
        assert isinstance(result, bool)
    
    def test_get_decoded_data_incomplete(self):
        """Test get_decoded_data raises when not complete."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.fountain import FountainDecoder
        
        k_blocks = 5
        block_size = 64
        decoder = FountainDecoder(k_blocks, block_size)
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=decoder,
            master_key=master_key,
            salt=salt
        )
        
        # Should raise because decoding is not complete
        with pytest.raises(RuntimeError):
            fs_decoder.get_decoded_data()
    
    def test_create_secure_fountain_decoder_with_fs(self):
        """Test create_secure_fountain_decoder factory function with FS."""
        from meow_decoder.forward_secrecy_decoder import (
            create_secure_fountain_decoder,
            ForwardSecrecyFountainDecoder
        )
        from meow_decoder.fountain import FountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        decoder = create_secure_fountain_decoder(
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_decoder_class=FountainDecoder,
            ratchet_state_bytes=None,
            ratchet_interval=100,
            enable_forward_secrecy=True
        )
        
        assert isinstance(decoder, ForwardSecrecyFountainDecoder)
    
    def test_create_secure_fountain_decoder_without_fs(self):
        """Test create_secure_fountain_decoder with FS disabled."""
        from meow_decoder.forward_secrecy_decoder import create_secure_fountain_decoder
        from meow_decoder.fountain import FountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        decoder = create_secure_fountain_decoder(
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_decoder_class=FountainDecoder,
            enable_forward_secrecy=False
        )
        
        # Should return unwrapped FountainDecoder
        assert isinstance(decoder, FountainDecoder)
    
    def test_parse_manifest_v3_valid_fs_extension(self):
        """Test parsing valid FS extension."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        from meow_decoder.forward_secrecy import pack_forward_secrecy_extension, ForwardSecrecyManager
        import struct
        
        # Create a real FS manager to generate valid extension
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_manager = ForwardSecrecyManager(
            master_key=master_key,
            salt=salt,
            enable_ratchet=True,
            ratchet_interval=50
        )
        
        # Pack extension
        extension = pack_forward_secrecy_extension(fs_manager)
        
        # Parse it back
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(extension)
        
        assert fs_enabled is True
        assert interval == 50
        assert state is not None
        
        fs_manager.cleanup()
    
    def test_parse_manifest_v3_fs_no_ratchet(self):
        """Test parsing FS extension without ratcheting."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        from meow_decoder.forward_secrecy import pack_forward_secrecy_extension, ForwardSecrecyManager
        
        # Create FS manager without ratcheting
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_manager = ForwardSecrecyManager(
            master_key=master_key,
            salt=salt,
            enable_ratchet=False
        )
        
        # Pack extension
        extension = pack_forward_secrecy_extension(fs_manager)
        
        # Parse it back
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(extension)
        
        # Ratchet disabled means ratchet_enabled = False
        assert fs_enabled is False
        
        fs_manager.cleanup()


class TestForwardSecrecyIntegration:
    """Integration tests for full encode/decode with forward secrecy."""
    
    def test_full_encode_decode_cycle(self):
        """Test complete encode -> decode cycle with forward secrecy (no ratchet)."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        
        # Original data
        original_data = b"This is a secret message for FS testing!" * 5
        k_blocks = 6
        block_size = 64
        
        # Shared key material
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Encoder side - disable ratchet for simpler testing
        fountain_enc = FountainEncoder(original_data, k_blocks, block_size)
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain_enc,
            master_key=master_key,
            salt=salt,
            enable_ratchet=False,  # Disable ratchet for symmetric decode
            ratchet_interval=10
        )
        
        # Decoder side - also no ratchet (ratchet_state_bytes=None means no ratchet)
        fountain_dec = FountainDecoder(k_blocks, block_size, original_length=len(original_data))
        fs_decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=fountain_dec,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=None  # No ratchet means enable_ratchet=False in from_ratchet_state
        )
        
        # Generate and process droplets until complete
        max_droplets = k_blocks * 3  # With redundancy
        
        for i in range(max_droplets):
            droplet = fs_encoder.next_secure_droplet()
            
            complete = fs_decoder.process_secure_droplet(
                encrypted_data=droplet.encrypted_data,
                nonce=droplet.nonces[0],
                block_indices=droplet.block_indices,
                seed=droplet.seed
            )
            
            if complete:
                break
        
        assert fs_decoder.is_complete(), "Decoding should be complete"
        
        # Get decoded data
        decoded_data = fs_decoder.get_decoded_data()
        
        # Verify data matches
        assert decoded_data == original_data, "Decoded data should match original"
        
        # Cleanup
        fs_encoder.cleanup()
        fs_decoder.cleanup()
    
    def test_multiple_droplets_same_block(self):
        """Test handling multiple droplets targeting same blocks."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"A" * 192  # 3 blocks of 64 bytes
        k_blocks = 3
        block_size = 64
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fountain = FountainEncoder(test_data, k_blocks, block_size)
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True
        )
        
        # Generate multiple droplets
        droplets = []
        for _ in range(10):
            droplets.append(fs_encoder.next_secure_droplet())
        
        # All droplets should be valid and unique
        assert len(droplets) == 10
        for d in droplets:
            assert len(d.encrypted_data) > 0
            assert len(d.nonces) == 1
        
        # Block IDs should be sequential
        for i, d in enumerate(droplets):
            assert d.block_id == i
        
        fs_encoder.cleanup()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
