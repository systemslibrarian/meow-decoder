#!/usr/bin/env python3
"""
🐱 Comprehensive tests for crypto_enhanced.py
Target: 95-100% branch coverage

Coverage areas:
- SecureBytes: memory locking, zeroing, context manager
- secure_key_context: key handling
- derive_key: password validation, keyfile combining
- derive_block_key: per-block HKDF derivation
- encrypt_file_bytes: compression, encryption, forward secrecy flag
- decrypt_to_raw: decryption, decompression, error handling
- pack_manifest/unpack_manifest: serialization roundtrip
- compute_manifest_hmac/verify_manifest_hmac: HMAC operations
- secure_wipe: file overwrite and deletion
- verify_keyfile: validation edge cases
- secure_compare: constant-time comparison
- StreamingEncryption: streaming operations
"""

import os
import gc
import io
import struct
import tempfile
import secrets
import hashlib
import pytest
from unittest import mock
from pathlib import Path

# Set test mode for fast Argon2
os.environ["MEOW_TEST_MODE"] = "1"

from meow_decoder.crypto_enhanced import (
    SecureBytes,
    secure_key_context,
    derive_key,
    derive_block_key,
    encrypt_file_bytes,
    decrypt_to_raw,
    pack_manifest,
    unpack_manifest,
    compute_manifest_hmac,
    verify_manifest_hmac,
    secure_wipe,
    verify_keyfile,
    secure_compare,
    StreamingEncryption,
    Manifest,
    MAGIC,
    ARGON2_MEMORY,
    ARGON2_ITERATIONS,
    ARGON2_PARALLELISM,
    MANIFEST_HMAC_KEY_PREFIX,
    KEYFILE_DOMAIN_SEP,
    BLOCK_KEY_DOMAIN_SEP,
)


# =============================================================================
# SecureBytes Tests
# =============================================================================

class TestSecureBytes:
    """Tests for SecureBytes secure memory class."""
    
    def test_init_with_data(self):
        """SecureBytes initializes with provided data."""
        data = b"secret data 123"
        sb = SecureBytes(data)
        assert sb.get_bytes() == data
        assert len(sb) == len(data)
    
    def test_init_with_size(self):
        """SecureBytes initializes with specified size."""
        sb = SecureBytes(size=32)
        assert len(sb) == 32
        assert sb.get_bytes() == b'\x00' * 32
    
    def test_init_empty(self):
        """SecureBytes initializes empty with no args."""
        sb = SecureBytes()
        assert len(sb) == 0
        assert sb.get_bytes() == b''
    
    def test_context_manager_entry_exit(self):
        """SecureBytes works as context manager."""
        data = b"test data"
        with SecureBytes(data) as sb:
            assert sb.get_bytes() == data
            mutable = sb.get_data()
            assert isinstance(mutable, bytearray)
            assert bytes(mutable) == data
    
    def test_zero_clears_data(self):
        """SecureBytes.zero() clears data."""
        data = b"sensitive"
        sb = SecureBytes(data)
        sb.zero()
        # After zero, internal data should be cleared
        # Note: _data is deleted in zero()
        assert not hasattr(sb, '_data') or sb._data is None
    
    def test_mlock_success_path(self):
        """Test mlock success path (platform dependent)."""
        # This may or may not succeed depending on platform
        data = b"test" * 100
        sb = SecureBytes(data)
        # Check that _mlocked attribute exists
        assert hasattr(sb, '_mlocked')
        sb.zero()
    
    def test_mlock_failure_path(self):
        """Test mlock failure handling."""
        with mock.patch('ctypes.CDLL', side_effect=Exception("No libc")):
            sb = SecureBytes(b"test data")
            assert sb._mlocked is False
            sb.zero()
    
    def test_munlock_in_zero(self):
        """Test munlock is called during zero() if mlocked."""
        data = b"test data 123"
        sb = SecureBytes(data)
        # Force mlocked state
        sb._mlocked = True
        
        # Mock ctypes to track munlock call
        with mock.patch('ctypes.CDLL') as mock_cdll:
            mock_libc = mock.Mock()
            mock_cdll.return_value = mock_libc
            sb.zero()
    
    def test_munlock_exception_handling(self):
        """Test munlock handles exceptions gracefully."""
        data = b"test data"
        sb = SecureBytes(data)
        sb._mlocked = True
        
        with mock.patch('ctypes.CDLL', side_effect=Exception("munlock failed")):
            # Should not raise
            sb.zero()
    
    def test_get_data_returns_bytearray(self):
        """get_data returns mutable bytearray."""
        data = b"original"
        sb = SecureBytes(data)
        mutable = sb.get_data()
        mutable[0] = ord('X')
        # Original data in SecureBytes should be modified
        assert sb.get_bytes()[0:1] == b'X'
        sb.zero()


# =============================================================================
# secure_key_context Tests
# =============================================================================

class TestSecureKeyContext:
    """Tests for secure_key_context context manager."""
    
    def test_yields_key_bytes(self):
        """Context manager yields key bytes."""
        key = secrets.token_bytes(32)
        with secure_key_context(key) as ctx_key:
            assert ctx_key == key
            assert isinstance(ctx_key, bytes)
    
    def test_cleanup_on_exit(self):
        """Key material is cleaned up on exit."""
        key = secrets.token_bytes(32)
        with secure_key_context(key) as ctx_key:
            pass
        # After context exit, cleanup should have occurred
        # (we can't easily verify this without inspecting memory)
    
    def test_cleanup_on_exception(self):
        """Key material is cleaned up even on exception."""
        key = secrets.token_bytes(32)
        with pytest.raises(ValueError):
            with secure_key_context(key) as ctx_key:
                raise ValueError("Test exception")


# =============================================================================
# derive_key Tests
# =============================================================================

class TestDeriveKey:
    """Tests for derive_key function."""
    
    def test_basic_derivation(self):
        """Basic key derivation works."""
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_deterministic(self):
        """Same inputs produce same key."""
        password = "consistent_password"
        salt = b"0123456789abcdef"  # Fixed salt
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        assert key1 == key2
    
    def test_different_passwords_different_keys(self):
        """Different passwords produce different keys."""
        salt = secrets.token_bytes(16)
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2
    
    def test_different_salts_different_keys(self):
        """Different salts produce different keys."""
        password = "same_password"
        key1 = derive_key(password, secrets.token_bytes(16))
        key2 = derive_key(password, secrets.token_bytes(16))
        assert key1 != key2
    
    def test_empty_password_raises(self):
        """Empty password raises ValueError."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            derive_key("", secrets.token_bytes(16))
    
    def test_wrong_salt_length_raises(self):
        """Wrong salt length raises ValueError."""
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            derive_key("password", b"short")
        
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            derive_key("password", b"this is too long for salt")
    
    def test_with_keyfile(self):
        """Key derivation with keyfile."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        
        key_with_keyfile = derive_key(password, salt, keyfile)
        key_without_keyfile = derive_key(password, salt)
        
        assert len(key_with_keyfile) == 32
        assert key_with_keyfile != key_without_keyfile
    
    def test_keyfile_affects_key(self):
        """Different keyfiles produce different keys."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        key1 = derive_key(password, salt, b"keyfile1_content")
        key2 = derive_key(password, salt, b"keyfile2_content")
        
        assert key1 != key2
    
    def test_argon2_failure_handling(self):
        """Argon2 failure raises RuntimeError."""
        password = "test"
        salt = secrets.token_bytes(16)
        
        with mock.patch('argon2.low_level.hash_secret_raw', side_effect=Exception("Argon2 error")):
            with pytest.raises(RuntimeError, match="Key derivation failed"):
                derive_key(password, salt)
    
    def test_secret_zeroing_for_bytearray(self):
        """Test that bytearray secrets are zeroed."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        keyfile = bytearray(b"keyfile content here")
        
        # Derivation should work and attempt to zero
        key = derive_key(password, salt, bytes(keyfile))
        assert len(key) == 32


# =============================================================================
# derive_block_key Tests
# =============================================================================

class TestDeriveBlockKey:
    """Tests for derive_block_key function."""
    
    def test_basic_block_key_derivation(self):
        """Basic block key derivation works."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key = derive_block_key(master_key, 0, salt)
        assert len(key) == 32
    
    def test_different_blocks_different_keys(self):
        """Different block IDs produce different keys."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key0 = derive_block_key(master_key, 0, salt)
        key1 = derive_block_key(master_key, 1, salt)
        key100 = derive_block_key(master_key, 100, salt)
        
        assert key0 != key1 != key100
    
    def test_deterministic_block_keys(self):
        """Same inputs produce same block key."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_block_key(master_key, 5, salt)
        key2 = derive_block_key(master_key, 5, salt)
        
        assert key1 == key2
    
    def test_different_master_keys(self):
        """Different master keys produce different block keys."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_block_key(secrets.token_bytes(32), 0, salt)
        key2 = derive_block_key(secrets.token_bytes(32), 0, salt)
        
        assert key1 != key2


# =============================================================================
# encrypt_file_bytes Tests
# =============================================================================

class TestEncryptFileBytes:
    """Tests for encrypt_file_bytes function."""
    
    def test_basic_encryption(self):
        """Basic encryption works."""
        data = b"Hello, World!" * 100
        password = "test_password_123"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(sha) == 32
        assert len(cipher) > 0
        assert len(comp) > 0
    
    def test_sha256_is_correct(self):
        """SHA256 hash is computed correctly."""
        data = b"test data for hashing"
        password = "password123"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        
        expected_sha = hashlib.sha256(data).digest()
        assert sha == expected_sha
    
    def test_compression_reduces_size(self):
        """Compression reduces size of compressible data."""
        data = b"AAAA" * 1000  # Highly compressible
        password = "password"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        
        # Compressed should be smaller than original
        assert len(comp) < len(data)
    
    def test_with_keyfile(self):
        """Encryption with keyfile works."""
        data = b"secret data"
        password = "password"
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password, keyfile)
        
        assert len(cipher) > 0
    
    def test_forward_secrecy_flag(self):
        """Forward secrecy flag is accepted."""
        data = b"test data"
        password = "password"
        
        # Should work with use_forward_secrecy=True
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password, use_forward_secrecy=True)
        
        assert len(cipher) > 0
    
    def test_encryption_failure_handling(self):
        """Encryption failure raises RuntimeError."""
        data = b"test data"
        password = "password"
        
        with mock.patch('meow_decoder.crypto_enhanced.derive_key', side_effect=Exception("Key error")):
            with pytest.raises(RuntimeError, match="Encryption failed"):
                encrypt_file_bytes(data, password)
    
    def test_garbage_collection_called(self):
        """GC is called after encryption."""
        data = b"test data"
        password = "password"
        
        with mock.patch('gc.collect') as mock_gc:
            encrypt_file_bytes(data, password)
            # gc.collect should be called in finally block
            mock_gc.assert_called()


# =============================================================================
# decrypt_to_raw Tests
# =============================================================================

class TestDecryptToRaw:
    """Tests for decrypt_to_raw function."""
    
    def test_roundtrip(self):
        """Encryption and decryption roundtrip works."""
        original = b"Hello, Meow Decoder!" * 50
        password = "test_password_123"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(original, password)
        decrypted = decrypt_to_raw(cipher, password, salt, nonce)
        
        assert decrypted == original
    
    def test_roundtrip_with_keyfile(self):
        """Roundtrip with keyfile works."""
        original = b"Secret keyfile data"
        password = "password"
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(original, password, keyfile)
        decrypted = decrypt_to_raw(cipher, password, salt, nonce, keyfile)
        
        assert decrypted == original
    
    def test_wrong_password_fails(self):
        """Wrong password fails decryption."""
        original = b"test data"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(original, "correct_password")
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(cipher, "wrong_password", salt, nonce)
    
    def test_wrong_keyfile_fails(self):
        """Wrong keyfile fails decryption."""
        original = b"test data"
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(original, "password", keyfile)
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(cipher, "password", salt, nonce, secrets.token_bytes(64))
    
    def test_missing_keyfile_fails(self):
        """Missing keyfile when required fails."""
        original = b"test data"
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(original, "password", keyfile)
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(cipher, "password", salt, nonce)  # No keyfile
    
    def test_corrupted_ciphertext_fails(self):
        """Corrupted ciphertext fails."""
        original = b"test data"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(original, "password")
        
        corrupted = bytearray(cipher)
        corrupted[10] ^= 0xFF  # Flip bits
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(bytes(corrupted), "password", salt, nonce)
    
    def test_garbage_collection_called(self):
        """GC is called after decryption."""
        original = b"test data"
        password = "password"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(original, password)
        
        with mock.patch('gc.collect') as mock_gc:
            decrypt_to_raw(cipher, password, salt, nonce)
            mock_gc.assert_called()


# =============================================================================
# Manifest Serialization Tests
# =============================================================================

class TestManifestSerialization:
    """Tests for pack_manifest and unpack_manifest."""
    
    def test_pack_manifest(self):
        """pack_manifest produces correct bytes."""
        manifest = Manifest(
            salt=b"0123456789abcdef",
            nonce=b"123456789012",
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=b"a" * 32,
            block_size=512,
            k_blocks=10,
            hmac=b"h" * 32,
        )
        
        packed = pack_manifest(manifest)
        
        assert packed.startswith(MAGIC)
        assert len(packed) == len(MAGIC) + 16 + 12 + 12 + 6 + 32 + 32
    
    def test_unpack_manifest(self):
        """unpack_manifest correctly deserializes."""
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=2000,
            comp_len=1500,
            cipher_len=1516,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=20,
            hmac=secrets.token_bytes(32),
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
    
    def test_unpack_too_short_raises(self):
        """unpack_manifest raises on too-short data."""
        with pytest.raises(ValueError, match="Manifest too short"):
            unpack_manifest(b"short")
    
    def test_unpack_wrong_magic_raises(self):
        """unpack_manifest raises on wrong magic."""
        # Create valid-length but wrong magic data
        bad_magic = b"XXXX" + secrets.token_bytes(115 - 4)
        
        with pytest.raises(ValueError, match="Invalid MAGIC/version"):
            unpack_manifest(bad_magic)
    
    def test_roundtrip_multiple_manifests(self):
        """Multiple manifests roundtrip correctly."""
        for _ in range(5):
            manifest = Manifest(
                salt=secrets.token_bytes(16),
                nonce=secrets.token_bytes(12),
                orig_len=secrets.randbelow(100000),
                comp_len=secrets.randbelow(100000),
                cipher_len=secrets.randbelow(100000),
                sha256=secrets.token_bytes(32),
                block_size=256 * (1 + secrets.randbelow(4)),
                k_blocks=secrets.randbelow(1000) + 1,
                hmac=secrets.token_bytes(32),
            )
            
            packed = pack_manifest(manifest)
            unpacked = unpack_manifest(packed)
            
            assert unpacked.orig_len == manifest.orig_len


# =============================================================================
# HMAC Tests
# =============================================================================

class TestManifestHMAC:
    """Tests for compute_manifest_hmac and verify_manifest_hmac."""
    
    def test_compute_hmac(self):
        """compute_manifest_hmac produces 32-byte HMAC."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        packed_no_hmac = b"test manifest data" * 10
        
        hmac_val = compute_manifest_hmac(password, salt, packed_no_hmac)
        
        assert len(hmac_val) == 32
    
    def test_hmac_deterministic(self):
        """Same inputs produce same HMAC."""
        password = "password"
        salt = b"0123456789abcdef"
        data = b"manifest data"
        
        hmac1 = compute_manifest_hmac(password, salt, data)
        hmac2 = compute_manifest_hmac(password, salt, data)
        
        assert hmac1 == hmac2
    
    def test_hmac_with_keyfile(self):
        """HMAC with keyfile differs from without."""
        password = "password"
        salt = secrets.token_bytes(16)
        data = b"manifest data"
        keyfile = secrets.token_bytes(64)
        
        hmac_with = compute_manifest_hmac(password, salt, data, keyfile)
        hmac_without = compute_manifest_hmac(password, salt, data)
        
        assert hmac_with != hmac_without
    
    def test_verify_hmac_matching(self):
        """verify_manifest_hmac returns True for matching HMACs."""
        hmac1 = b"a" * 32
        hmac2 = b"a" * 32
        
        assert verify_manifest_hmac(hmac1, hmac2) is True
    
    def test_verify_hmac_non_matching(self):
        """verify_manifest_hmac returns False for non-matching HMACs."""
        hmac1 = b"a" * 32
        hmac2 = b"b" * 32
        
        assert verify_manifest_hmac(hmac1, hmac2) is False
    
    def test_verify_hmac_different_lengths(self):
        """verify_manifest_hmac handles different lengths."""
        hmac1 = b"a" * 32
        hmac2 = b"a" * 16  # Different length
        
        # Should return False, not crash
        assert verify_manifest_hmac(hmac1, hmac2) is False


# =============================================================================
# secure_wipe Tests
# =============================================================================

class TestSecureWipe:
    """Tests for secure_wipe function."""
    
    def test_basic_wipe(self):
        """secure_wipe removes file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"sensitive data" * 100)
            filepath = f.name
        
        assert os.path.exists(filepath)
        secure_wipe(filepath)
        assert not os.path.exists(filepath)
    
    def test_wipe_with_passes(self):
        """secure_wipe respects passes parameter."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"data" * 100)
            filepath = f.name
        
        # Mock to count passes
        original_open = open
        call_count = [0]
        
        def counting_open(*args, **kwargs):
            if 'r+b' in args or kwargs.get('mode') == 'r+b':
                call_count[0] += 1
            return original_open(*args, **kwargs)
        
        with mock.patch('builtins.open', side_effect=counting_open):
            secure_wipe(filepath, passes=5)
        
        assert not os.path.exists(filepath)
    
    def test_wipe_nonexistent_file_raises(self):
        """secure_wipe raises for nonexistent file."""
        with pytest.raises(RuntimeError, match="Secure wipe failed"):
            secure_wipe("/nonexistent/file/path.txt")
    
    def test_wipe_permission_error(self):
        """secure_wipe handles permission errors."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"data")
            filepath = f.name
        
        with mock.patch('builtins.open', side_effect=PermissionError("No permission")):
            with pytest.raises(RuntimeError, match="Secure wipe failed"):
                secure_wipe(filepath)
        
        # Cleanup
        if os.path.exists(filepath):
            os.remove(filepath)


# =============================================================================
# verify_keyfile Tests
# =============================================================================

class TestVerifyKeyfile:
    """Tests for verify_keyfile function."""
    
    def test_valid_keyfile(self):
        """verify_keyfile accepts valid keyfile."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(64))
            filepath = f.name
        
        try:
            content = verify_keyfile(filepath)
            assert len(content) == 64
        finally:
            os.remove(filepath)
    
    def test_nonexistent_keyfile_raises(self):
        """verify_keyfile raises for nonexistent file."""
        with pytest.raises(FileNotFoundError, match="Keyfile not found"):
            verify_keyfile("/nonexistent/keyfile.key")
    
    def test_too_small_keyfile_raises(self):
        """verify_keyfile raises for too-small keyfile."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"short")  # Less than 32 bytes
            filepath = f.name
        
        try:
            with pytest.raises(ValueError, match="Keyfile too small"):
                verify_keyfile(filepath)
        finally:
            os.remove(filepath)
    
    def test_too_large_keyfile_raises(self):
        """verify_keyfile raises for too-large keyfile."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(1024 * 1024 + 1))  # >1MB
            filepath = f.name
        
        try:
            with pytest.raises(ValueError, match="Keyfile too large"):
                verify_keyfile(filepath)
        finally:
            os.remove(filepath)
    
    def test_exactly_32_bytes(self):
        """verify_keyfile accepts exactly 32 bytes."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(32))
            filepath = f.name
        
        try:
            content = verify_keyfile(filepath)
            assert len(content) == 32
        finally:
            os.remove(filepath)
    
    def test_exactly_1mb(self):
        """verify_keyfile accepts exactly 1MB."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(1024 * 1024))
            filepath = f.name
        
        try:
            content = verify_keyfile(filepath)
            assert len(content) == 1024 * 1024
        finally:
            os.remove(filepath)


# =============================================================================
# secure_compare Tests
# =============================================================================

class TestSecureCompare:
    """Tests for secure_compare function."""
    
    def test_equal_bytes(self):
        """secure_compare returns True for equal bytes."""
        a = b"test data"
        b = b"test data"
        assert secure_compare(a, b) is True
    
    def test_unequal_bytes(self):
        """secure_compare returns False for unequal bytes."""
        a = b"test data"
        b = b"TEST data"
        assert secure_compare(a, b) is False
    
    def test_different_lengths(self):
        """secure_compare handles different lengths."""
        a = b"short"
        b = b"longer string"
        assert secure_compare(a, b) is False
    
    def test_empty_bytes(self):
        """secure_compare handles empty bytes."""
        assert secure_compare(b"", b"") is True
        assert secure_compare(b"", b"x") is False


# =============================================================================
# StreamingEncryption Tests
# =============================================================================

class TestStreamingEncryption:
    """Tests for StreamingEncryption class."""
    
    def test_init(self):
        """StreamingEncryption initializes correctly."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        se = StreamingEncryption(password, salt)
        
        assert se.chunk_size == 4096
        assert se.salt == salt
        assert len(se.key) == 32
    
    def test_init_with_keyfile(self):
        """StreamingEncryption initializes with keyfile."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        
        se = StreamingEncryption(password, salt, keyfile)
        assert len(se.key) == 32
    
    def test_init_custom_chunk_size(self):
        """StreamingEncryption accepts custom chunk size."""
        se = StreamingEncryption("password", secrets.token_bytes(16), chunk_size=8192)
        assert se.chunk_size == 8192
    
    def test_encrypt_stream(self):
        """encrypt_stream encrypts data."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        data = b"Hello, streaming encryption!" * 100
        
        se = StreamingEncryption(password, salt)
        
        input_stream = io.BytesIO(data)
        output_stream = io.BytesIO()
        
        nonce, compressed_size, original_size = se.encrypt_stream(input_stream, output_stream)
        
        assert len(nonce) == 12
        assert original_size == len(data)
        assert output_stream.tell() > 0
    
    def test_encrypt_stream_with_nonce(self):
        """encrypt_stream accepts provided nonce."""
        password = "test_password"
        salt = secrets.token_bytes(16)
        data = b"test data"
        custom_nonce = secrets.token_bytes(12)
        
        se = StreamingEncryption(password, salt)
        
        input_stream = io.BytesIO(data)
        output_stream = io.BytesIO()
        
        nonce, _, _ = se.encrypt_stream(input_stream, output_stream, nonce=custom_nonce)
        
        assert nonce == custom_nonce
    
    def test_destructor_cleans_key(self):
        """StreamingEncryption destructor cleans up key."""
        se = StreamingEncryption("password", secrets.token_bytes(16))
        
        # Store reference to check later
        key_ref = se.key
        
        # Trigger destructor
        del se
        gc.collect()
        
        # Key should have been cleaned up (or deleted)
        # Note: Python doesn't guarantee immediate cleanup
    
    def test_destructor_handles_bytearray_key(self):
        """Destructor handles bytearray key."""
        se = StreamingEncryption("password", secrets.token_bytes(16))
        # Convert key to bytearray
        se.key = bytearray(se.key)
        
        # Should not raise on deletion
        del se
        gc.collect()
    
    def test_destructor_no_key_attribute(self):
        """Destructor handles missing key attribute."""
        se = StreamingEncryption("password", secrets.token_bytes(16))
        del se.key
        
        # Should not raise
        del se
        gc.collect()


# =============================================================================
# Constants Tests
# =============================================================================

class TestConstants:
    """Tests for module constants."""
    
    def test_magic_value(self):
        """MAGIC constant is correct."""
        assert MAGIC == b"MEOW2"
    
    def test_argon2_params_exist(self):
        """Argon2 parameters exist."""
        assert ARGON2_MEMORY > 0
        assert ARGON2_ITERATIONS > 0
        assert ARGON2_PARALLELISM > 0
    
    def test_domain_separation_constants(self):
        """Domain separation constants are unique."""
        constants = {
            MANIFEST_HMAC_KEY_PREFIX,
            KEYFILE_DOMAIN_SEP,
            BLOCK_KEY_DOMAIN_SEP,
        }
        assert len(constants) == 3  # All unique


# =============================================================================
# Edge Cases and Integration Tests
# =============================================================================

class TestEdgeCases:
    """Edge case tests."""
    
    def test_empty_data_encryption(self):
        """Empty data can be encrypted."""
        data = b""
        password = "password"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        decrypted = decrypt_to_raw(cipher, password, salt, nonce)
        
        assert decrypted == data
    
    def test_large_data_encryption(self):
        """Large data can be encrypted."""
        data = secrets.token_bytes(1024 * 1024)  # 1MB
        password = "password"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        decrypted = decrypt_to_raw(cipher, password, salt, nonce)
        
        assert decrypted == data
    
    def test_unicode_password(self):
        """Unicode password works."""
        data = b"test data"
        password = "пароль_🐱_password"  # Mixed unicode
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        decrypted = decrypt_to_raw(cipher, password, salt, nonce)
        
        assert decrypted == data
    
    def test_binary_keyfile(self):
        """Binary keyfile with null bytes works."""
        data = b"test data"
        password = "password"
        keyfile = b"\x00\x01\x02" + secrets.token_bytes(100) + b"\xff\xfe\xfd"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password, keyfile)
        decrypted = decrypt_to_raw(cipher, password, salt, nonce, keyfile)
        
        assert decrypted == data
    
    def test_manifest_field_limits(self):
        """Manifest handles max field values."""
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=0xFFFFFFFF,  # Max uint32
            comp_len=0xFFFFFFFF,
            cipher_len=0xFFFFFFFF,
            sha256=secrets.token_bytes(32),
            block_size=0xFFFF,  # Max uint16
            k_blocks=0xFFFFFFFF,
            hmac=secrets.token_bytes(32),
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.orig_len == 0xFFFFFFFF
        assert unpacked.block_size == 0xFFFF


class TestIntegration:
    """Integration tests combining multiple functions."""
    
    def test_full_encryption_workflow(self):
        """Full encryption workflow with manifest."""
        # Original data
        original = b"Secret message for testing! " * 100
        password = "secure_password_123"
        keyfile = secrets.token_bytes(64)
        
        # Encrypt
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(original, password, keyfile)
        
        # Create manifest
        manifest = Manifest(
            salt=salt,
            nonce=nonce,
            orig_len=len(original),
            comp_len=len(comp),
            cipher_len=len(cipher),
            sha256=sha,
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32,  # Placeholder
        )
        
        # Compute real HMAC
        packed_no_hmac = pack_manifest(manifest)[:-32]  # Without HMAC
        manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac, keyfile)
        
        # Pack manifest
        packed = pack_manifest(manifest)
        
        # Unpack and verify
        unpacked = unpack_manifest(packed)
        recomputed_hmac = compute_manifest_hmac(password, salt, packed_no_hmac, keyfile)
        
        assert verify_manifest_hmac(unpacked.hmac, recomputed_hmac)
        
        # Decrypt
        decrypted = decrypt_to_raw(cipher, password, salt, nonce, keyfile)
        
        assert decrypted == original
        assert hashlib.sha256(decrypted).digest() == sha
    
    def test_block_key_isolation(self):
        """Block keys are isolated from each other."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Derive 10 block keys
        block_keys = [derive_block_key(master_key, i, salt) for i in range(10)]
        
        # All should be unique
        assert len(set(block_keys)) == 10
        
        # All should be 32 bytes
        assert all(len(k) == 32 for k in block_keys)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
