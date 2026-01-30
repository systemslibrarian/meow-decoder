#!/usr/bin/env python3
"""
Tests for crypto_enhanced.py - Enhanced cryptographic operations with secure memory.

Tests cover:
- SecureBytes class (secure memory handling)
- secure_key_context (key context manager)
- derive_key (Argon2id key derivation with keyfile)
- derive_block_key (per-block forward secrecy keys)
- encrypt_file_bytes / decrypt_to_raw (encrypt/decrypt roundtrip)
- pack_manifest / unpack_manifest (manifest serialization)
- compute_manifest_hmac / verify_manifest_hmac (HMAC operations)
- secure_wipe (secure file deletion)
- verify_keyfile (keyfile validation)
- secure_compare (constant-time comparison)
- StreamingEncryption (streaming encrypt class)
"""

import os
import sys
import gc
import secrets
import tempfile
import pytest
from pathlib import Path

# Add parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))

# Set test mode for faster Argon2
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
)


class TestSecureBytes:
    """Tests for SecureBytes secure memory class."""
    
    def test_basic_init_with_data(self):
        """Test SecureBytes initialization with data."""
        data = b"sensitive data here"
        sb = SecureBytes(data)
        assert sb.get_bytes() == data
        assert len(sb) == len(data)
    
    def test_basic_init_with_size(self):
        """Test SecureBytes initialization with size."""
        sb = SecureBytes(size=32)
        assert len(sb) == 32
        # Initial data should be zeros
        assert sb.get_bytes() == b'\x00' * 32
    
    def test_context_manager(self):
        """Test SecureBytes as context manager."""
        data = b"secret key material"
        with SecureBytes(data) as sb:
            assert sb.get_bytes() == data
        # After exit, data should be zeroed (best-effort)
        # We can't easily verify this in Python due to GC
    
    def test_get_data_returns_bytearray(self):
        """Test get_data returns mutable bytearray."""
        data = b"test data"
        sb = SecureBytes(data)
        result = sb.get_data()
        assert isinstance(result, bytearray)
        assert bytes(result) == data
    
    def test_zero_method(self):
        """Test zero() method clears data."""
        data = b"A" * 100
        sb = SecureBytes(data)
        sb.zero()
        # After zeroing, accessing may fail or return zeros
        # The test is that zero() doesn't crash


class TestSecureKeyContext:
    """Tests for secure_key_context context manager."""
    
    def test_yields_key(self):
        """Test that context yields the key."""
        key = b"A" * 32
        with secure_key_context(key) as k:
            assert k == key
    
    def test_context_exits_cleanly(self):
        """Test context manager exits without error."""
        key = secrets.token_bytes(32)
        result = None
        with secure_key_context(key) as k:
            result = k
        assert result is not None


class TestDeriveKey:
    """Tests for derive_key Argon2id key derivation."""
    
    def test_basic_derivation(self):
        """Test basic key derivation returns 32 bytes."""
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        assert len(key) == 32
        assert isinstance(key, bytes)
    
    def test_same_inputs_same_key(self):
        """Test same password/salt produces same key."""
        password = "deterministic_password"
        salt = b"fixed_salt_16byt"
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        assert key1 == key2
    
    def test_different_passwords_different_keys(self):
        """Test different passwords produce different keys."""
        salt = secrets.token_bytes(16)
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2
    
    def test_different_salts_different_keys(self):
        """Test different salts produce different keys."""
        password = "same_password"
        key1 = derive_key(password, secrets.token_bytes(16))
        key2 = derive_key(password, secrets.token_bytes(16))
        assert key1 != key2
    
    def test_with_keyfile(self):
        """Test key derivation with keyfile."""
        password = "password_with_keyfile"
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        
        key_with_kf = derive_key(password, salt, keyfile)
        key_without_kf = derive_key(password, salt, None)
        
        assert len(key_with_kf) == 32
        assert key_with_kf != key_without_kf
    
    def test_empty_password_raises(self):
        """Test empty password raises ValueError."""
        salt = secrets.token_bytes(16)
        with pytest.raises(ValueError, match="empty"):
            derive_key("", salt)
    
    def test_wrong_salt_length_raises(self):
        """Test wrong salt length raises ValueError."""
        with pytest.raises(ValueError, match="16 bytes"):
            derive_key("password", b"short")


class TestDeriveBlockKey:
    """Tests for derive_block_key per-block key derivation."""
    
    def test_returns_32_bytes(self):
        """Test block key is 32 bytes."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        block_key = derive_block_key(master_key, 0, salt)
        assert len(block_key) == 32
    
    def test_different_blocks_different_keys(self):
        """Test different block IDs produce different keys."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key0 = derive_block_key(master_key, 0, salt)
        key1 = derive_block_key(master_key, 1, salt)
        key2 = derive_block_key(master_key, 2, salt)
        
        assert key0 != key1
        assert key1 != key2
        assert key0 != key2
    
    def test_same_block_same_key(self):
        """Test same block ID produces same key."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        key1 = derive_block_key(master_key, 42, salt)
        key2 = derive_block_key(master_key, 42, salt)
        
        assert key1 == key2
    
    def test_different_master_keys(self):
        """Test different master keys produce different block keys."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_block_key(secrets.token_bytes(32), 0, salt)
        key2 = derive_block_key(secrets.token_bytes(32), 0, salt)
        
        assert key1 != key2


class TestEncryptDecrypt:
    """Tests for encrypt_file_bytes and decrypt_to_raw."""
    
    def test_basic_roundtrip(self):
        """Test encrypt then decrypt recovers original."""
        data = b"Hello, Meow Decoder! " * 50
        password = "encrypt_test_password"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        
        # Verify outputs
        assert len(sha) == 32  # SHA256
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(cipher) > 0
        
        # Decrypt
        decrypted = decrypt_to_raw(cipher, password, salt, nonce)
        assert decrypted == data
    
    def test_compressed_smaller(self):
        """Test compression reduces size for compressible data."""
        # Highly compressible data
        data = b"AAAA" * 1000
        password = "compress_test"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        
        # Compressed should be smaller
        assert len(comp) < len(data)
    
    def test_with_keyfile(self):
        """Test encrypt/decrypt with keyfile."""
        data = b"Secret with keyfile"
        password = "keyfile_password"
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password, keyfile)
        decrypted = decrypt_to_raw(cipher, password, salt, nonce, keyfile)
        
        assert decrypted == data
    
    def test_wrong_password_fails(self):
        """Test wrong password raises error."""
        data = b"Test data"
        password = "correct_password"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(cipher, "wrong_password", salt, nonce)
    
    def test_wrong_keyfile_fails(self):
        """Test wrong keyfile raises error."""
        data = b"Test data"
        password = "password"
        keyfile = secrets.token_bytes(64)
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password, keyfile)
        
        wrong_keyfile = secrets.token_bytes(64)
        with pytest.raises(RuntimeError):
            decrypt_to_raw(cipher, password, salt, nonce, wrong_keyfile)
    
    def test_large_data(self):
        """Test with larger data (100KB)."""
        data = secrets.token_bytes(100 * 1024)
        password = "large_data_test"
        
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        decrypted = decrypt_to_raw(cipher, password, salt, nonce)
        
        assert decrypted == data


class TestManifest:
    """Tests for manifest packing and unpacking."""
    
    def test_pack_unpack_roundtrip(self):
        """Test manifest pack/unpack roundtrip."""
        original = Manifest(
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
        
        packed = pack_manifest(original)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.salt == original.salt
        assert unpacked.nonce == original.nonce
        assert unpacked.orig_len == original.orig_len
        assert unpacked.comp_len == original.comp_len
        assert unpacked.cipher_len == original.cipher_len
        assert unpacked.sha256 == original.sha256
        assert unpacked.block_size == original.block_size
        assert unpacked.k_blocks == original.k_blocks
        assert unpacked.hmac == original.hmac
    
    def test_packed_starts_with_magic(self):
        """Test packed manifest starts with MAGIC."""
        manifest = Manifest(
            salt=b"A" * 16,
            nonce=b"B" * 12,
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=b"C" * 32,
            block_size=256,
            k_blocks=5,
            hmac=b"D" * 32
        )
        
        packed = pack_manifest(manifest)
        assert packed[:len(MAGIC)] == MAGIC
    
    def test_short_manifest_raises(self):
        """Test too-short manifest raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(b"short")
    
    def test_wrong_magic_raises(self):
        """Test wrong magic bytes raises ValueError."""
        fake = b"FAKE" + b"A" * 200  # Wrong magic
        with pytest.raises(ValueError, match="MAGIC"):
            unpack_manifest(fake)


class TestManifestHMAC:
    """Tests for manifest HMAC computation and verification."""
    
    def test_compute_hmac_returns_32_bytes(self):
        """Test compute_manifest_hmac returns 32 bytes."""
        password = "hmac_test"
        salt = secrets.token_bytes(16)
        data = b"manifest data without hmac field"
        
        hmac = compute_manifest_hmac(password, salt, data)
        assert len(hmac) == 32
    
    def test_same_inputs_same_hmac(self):
        """Test same inputs produce same HMAC."""
        password = "deterministic"
        salt = b"salt_16_bytes___"
        data = b"test manifest data"
        
        hmac1 = compute_manifest_hmac(password, salt, data)
        hmac2 = compute_manifest_hmac(password, salt, data)
        
        assert hmac1 == hmac2
    
    def test_different_passwords_different_hmacs(self):
        """Test different passwords produce different HMACs."""
        salt = secrets.token_bytes(16)
        data = b"test data"
        
        hmac1 = compute_manifest_hmac("password1", salt, data)
        hmac2 = compute_manifest_hmac("password2", salt, data)
        
        assert hmac1 != hmac2
    
    def test_verify_hmac_matching(self):
        """Test verify_manifest_hmac returns True for match."""
        hmac1 = b"A" * 32
        hmac2 = b"A" * 32
        assert verify_manifest_hmac(hmac1, hmac2) is True
    
    def test_verify_hmac_not_matching(self):
        """Test verify_manifest_hmac returns False for mismatch."""
        hmac1 = b"A" * 32
        hmac2 = b"B" * 32
        assert verify_manifest_hmac(hmac1, hmac2) is False


class TestSecureWipe:
    """Tests for secure_wipe file deletion."""
    
    def test_file_deleted(self):
        """Test file is deleted after wipe."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"sensitive data")
            path = f.name
        
        assert os.path.exists(path)
        secure_wipe(path)
        assert not os.path.exists(path)
    
    def test_nonexistent_file_raises(self):
        """Test nonexistent file raises error."""
        with pytest.raises(RuntimeError, match="failed"):
            secure_wipe("/nonexistent/path/file.txt")
    
    def test_multiple_passes(self):
        """Test multiple overwrite passes."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"X" * 1000)
            path = f.name
        
        # Should work with various pass counts
        secure_wipe(path, passes=5)
        assert not os.path.exists(path)


class TestVerifyKeyfile:
    """Tests for verify_keyfile validation."""
    
    def test_valid_keyfile(self):
        """Test valid keyfile is accepted."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as f:
            f.write(secrets.token_bytes(64))
            path = f.name
        
        try:
            result = verify_keyfile(path)
            assert len(result) == 64
        finally:
            os.unlink(path)
    
    def test_missing_keyfile_raises(self):
        """Test missing keyfile raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            verify_keyfile("/nonexistent/keyfile.key")
    
    def test_too_small_keyfile_raises(self):
        """Test too-small keyfile raises ValueError."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as f:
            f.write(b"short")  # Less than 32 bytes
            path = f.name
        
        try:
            with pytest.raises(ValueError, match="too small"):
                verify_keyfile(path)
        finally:
            os.unlink(path)
    
    def test_too_large_keyfile_raises(self):
        """Test too-large keyfile raises ValueError."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as f:
            f.write(secrets.token_bytes(2 * 1024 * 1024))  # 2 MB
            path = f.name
        
        try:
            with pytest.raises(ValueError, match="too large"):
                verify_keyfile(path)
        finally:
            os.unlink(path)


class TestSecureCompare:
    """Tests for secure_compare constant-time comparison."""
    
    def test_equal_bytes(self):
        """Test equal bytes return True."""
        a = b"test_data_here"
        b = b"test_data_here"
        assert secure_compare(a, b) is True
    
    def test_unequal_bytes(self):
        """Test unequal bytes return False."""
        a = b"data_a"
        b = b"data_b"
        assert secure_compare(a, b) is False
    
    def test_different_lengths(self):
        """Test different lengths return False."""
        a = b"short"
        b = b"much_longer_data"
        assert secure_compare(a, b) is False
    
    def test_empty_bytes_equal(self):
        """Test empty bytes compare as equal."""
        assert secure_compare(b"", b"") is True


class TestStreamingEncryption:
    """Tests for StreamingEncryption class."""
    
    def test_init(self):
        """Test StreamingEncryption initialization."""
        password = "stream_password"
        salt = secrets.token_bytes(16)
        
        enc = StreamingEncryption(password, salt)
        assert enc.chunk_size == 4096
        assert enc.salt == salt
    
    def test_custom_chunk_size(self):
        """Test custom chunk size."""
        password = "stream_password"
        salt = secrets.token_bytes(16)
        
        enc = StreamingEncryption(password, salt, chunk_size=8192)
        assert enc.chunk_size == 8192
    
    def test_encrypt_stream(self):
        """Test encrypt_stream method."""
        import io
        
        password = "stream_test"
        salt = secrets.token_bytes(16)
        data = b"Stream test data " * 100
        
        enc = StreamingEncryption(password, salt)
        
        input_stream = io.BytesIO(data)
        output_stream = io.BytesIO()
        
        nonce, compressed_size, original_size = enc.encrypt_stream(
            input_stream, output_stream
        )
        
        assert len(nonce) == 12
        assert original_size == len(data)
        assert compressed_size <= len(data)  # Compressed
        assert output_stream.tell() > 0  # Data written
    
    def test_with_keyfile(self):
        """Test StreamingEncryption with keyfile."""
        password = "stream_keyfile"
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        
        enc = StreamingEncryption(password, salt, keyfile)
        assert enc.salt == salt


class TestIntegration:
    """Integration tests combining multiple components."""
    
    def test_full_manifest_hmac_flow(self):
        """Test full manifest with HMAC verification."""
        password = "integration_test"
        data = b"Integration test data"
        
        # Encrypt
        comp, sha, salt, nonce, cipher = encrypt_file_bytes(data, password)
        
        # Create manifest
        manifest = Manifest(
            salt=salt,
            nonce=nonce,
            orig_len=len(data),
            comp_len=len(comp),
            cipher_len=len(cipher),
            sha256=sha,
            block_size=512,
            k_blocks=1,
            hmac=b'\x00' * 32  # Placeholder
        )
        
        # Pack without HMAC, compute HMAC, update
        packed_no_hmac = pack_manifest(manifest)[:-(32)]  # Remove placeholder hmac
        hmac = compute_manifest_hmac(password, salt, packed_no_hmac)
        manifest.hmac = hmac
        
        # Verify HMAC
        assert verify_manifest_hmac(hmac, hmac)
        
        # Decrypt
        decrypted = decrypt_to_raw(cipher, password, salt, nonce)
        assert decrypted == data
    
    def test_block_key_isolation(self):
        """Test block keys are cryptographically isolated."""
        password = "block_key_test"
        salt = secrets.token_bytes(16)
        master_key = derive_key(password, salt)
        
        # Generate keys for 10 blocks
        block_keys = [derive_block_key(master_key, i, salt) for i in range(10)]
        
        # All keys should be unique
        assert len(set(block_keys)) == 10
        
        # All keys should be 32 bytes
        for key in block_keys:
            assert len(key) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
