#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for additional crypto paths - Target: 90%+
Tests crypto module paths that haven't been covered yet.
"""

import pytest
import secrets
import sys
import os
import tempfile
import struct
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCryptoKeyDerivation:
    """Test key derivation functions."""
    
    def test_derive_key_basic(self):
        """Test basic key derivation."""
        from meow_decoder.crypto import derive_key
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert len(key) == 32
    
    def test_derive_key_deterministic(self):
        """Test that key derivation is deterministic."""
        from meow_decoder.crypto import derive_key
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        
        assert key1 == key2
    
    def test_derive_key_different_salt(self):
        """Test that different salt gives different key."""
        from meow_decoder.crypto import derive_key
        
        password = "TestPassword123!"
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)
        
        assert key1 != key2
    
    def test_derive_key_empty_password_fails(self):
        """Test that empty password raises error."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError, match="empty"):
            derive_key("", salt)
    
    def test_derive_key_short_password_fails(self):
        """Test that short password raises error."""
        from meow_decoder.crypto import derive_key
        
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError, match="at least"):
            derive_key("short", salt)
    
    def test_derive_key_wrong_salt_length_fails(self):
        """Test that wrong salt length raises error."""
        from meow_decoder.crypto import derive_key
        
        with pytest.raises(ValueError, match="16 bytes"):
            derive_key("TestPassword123!", b"short_salt")
    
    def test_derive_key_with_keyfile(self):
        """Test key derivation with keyfile."""
        from meow_decoder.crypto import derive_key
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(256)
        
        # With keyfile
        key_with_kf = derive_key(password, salt, keyfile)
        
        # Without keyfile
        key_without_kf = derive_key(password, salt, None)
        
        # Keys should be different
        assert key_with_kf != key_without_kf


class TestCryptoEncryption:
    """Test encryption functions."""
    
    def test_encrypt_file_bytes_basic(self):
        """Test basic encryption."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        data = b"Test data to encrypt"
        password = "TestPassword123!"
        
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password
        )
        
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(cipher) > 0
        assert len(key) == 32
    
    def test_encrypt_file_bytes_with_keyfile(self):
        """Test encryption with keyfile."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        data = b"Test data to encrypt"
        password = "TestPassword123!"
        keyfile = secrets.token_bytes(256)
        
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password, keyfile=keyfile
        )
        
        assert len(cipher) > 0
    
    def test_encrypt_file_bytes_no_padding(self):
        """Test encryption without padding."""
        from meow_decoder.crypto import encrypt_file_bytes
        
        data = b"Test data to encrypt"
        password = "TestPassword123!"
        
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password, use_length_padding=False
        )
        
        assert len(cipher) > 0
    
    def test_encrypt_file_bytes_with_receiver_key(self):
        """Test encryption with receiver public key."""
        from meow_decoder.crypto import encrypt_file_bytes
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        data = b"Test data to encrypt"
        password = "TestPassword123!"
        
        # Generate receiver keypair
        priv, pub = generate_receiver_keypair()
        
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password, receiver_public_key=pub
        )
        
        assert ephemeral is not None
        assert len(ephemeral) == 32


class TestCryptoDecryption:
    """Test decryption functions."""
    
    def test_decrypt_to_raw_basic(self):
        """Test basic decryption."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Test data to encrypt"
        password = "TestPassword123!"
        
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data), comp_len=len(comp), sha256=sha256
        )
        
        assert decrypted == data
    
    def test_decrypt_to_raw_with_keyfile(self):
        """Test decryption with keyfile."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Test data to encrypt with keyfile"
        password = "TestPassword123!"
        keyfile = secrets.token_bytes(256)
        
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password, keyfile=keyfile
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, keyfile,
            orig_len=len(data), comp_len=len(comp), sha256=sha256
        )
        
        assert decrypted == data
    
    def test_decrypt_to_raw_wrong_password_fails(self):
        """Test that wrong password fails."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Test data to encrypt"
        password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password
        )
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                cipher, wrong_password, salt, nonce,
                orig_len=len(data), comp_len=len(comp), sha256=sha256
            )
    
    def test_decrypt_to_raw_wrong_keyfile_fails(self):
        """Test that wrong keyfile fails."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Test data to encrypt"
        password = "TestPassword123!"
        keyfile = secrets.token_bytes(256)
        wrong_keyfile = secrets.token_bytes(256)
        
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password, keyfile=keyfile
        )
        
        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                cipher, password, salt, nonce, wrong_keyfile,
                orig_len=len(data), comp_len=len(comp), sha256=sha256
            )


class TestCryptoManifest:
    """Test manifest functions."""
    
    def test_pack_manifest(self):
        """Test packing manifest."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=None
        )
        
        packed = pack_manifest(manifest)
        
        assert len(packed) == 115  # Base size
    
    def test_pack_manifest_with_ephemeral(self):
        """Test packing manifest with ephemeral key."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        
        assert len(packed) == 147  # Base + ephemeral
    
    def test_pack_manifest_with_duress(self):
        """Test packing manifest with duress tag."""
        from meow_decoder.crypto import Manifest, pack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            duress_tag=secrets.token_bytes(32)
        )
        
        packed = pack_manifest(manifest)
        
        assert len(packed) == 179  # Base + ephemeral + duress
    
    def test_unpack_manifest_basic(self):
        """Test unpacking manifest."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=None
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.salt == manifest.salt
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.k_blocks == manifest.k_blocks
    
    def test_unpack_manifest_with_ephemeral(self):
        """Test unpacking manifest with ephemeral key."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        ephemeral = secrets.token_bytes(32)
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=ephemeral
        )
        
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        assert unpacked.ephemeral_public_key == ephemeral


class TestCryptoHMAC:
    """Test HMAC functions."""
    
    def test_compute_manifest_hmac(self):
        """Test computing manifest HMAC."""
        from meow_decoder.crypto import compute_manifest_hmac
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        packed_no_hmac = secrets.token_bytes(100)
        
        hmac_tag = compute_manifest_hmac(password, salt, packed_no_hmac)
        
        assert len(hmac_tag) == 32
    
    def test_compute_manifest_hmac_deterministic(self):
        """Test that HMAC is deterministic."""
        from meow_decoder.crypto import compute_manifest_hmac
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        packed_no_hmac = secrets.token_bytes(100)
        
        hmac1 = compute_manifest_hmac(password, salt, packed_no_hmac)
        hmac2 = compute_manifest_hmac(password, salt, packed_no_hmac)
        
        assert hmac1 == hmac2
    
    def test_verify_manifest_hmac(self):
        """Test verifying manifest HMAC."""
        from meow_decoder.crypto import (
            Manifest, compute_manifest_hmac, verify_manifest_hmac,
            derive_key, pack_manifest_core
        )
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        
        # Create manifest
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32,
            ephemeral_public_key=None
        )
        
        # Compute HMAC
        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)
        enc_key = derive_key(password, salt)
        manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)
        
        # Verify
        result = verify_manifest_hmac(password, manifest)
        
        assert result is True
    
    def test_verify_manifest_hmac_wrong_password(self):
        """Test that wrong password fails HMAC verification."""
        from meow_decoder.crypto import (
            Manifest, compute_manifest_hmac, verify_manifest_hmac,
            derive_key, pack_manifest_core
        )
        
        password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        salt = secrets.token_bytes(16)
        
        # Create manifest
        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=850,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32,
            ephemeral_public_key=None
        )
        
        # Compute HMAC with correct password
        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)
        enc_key = derive_key(password, salt)
        manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)
        
        # Verify with wrong password
        result = verify_manifest_hmac(wrong_password, manifest)
        
        assert result is False


class TestCryptoDuress:
    """Test duress functions."""
    
    def test_compute_duress_hash(self):
        """Test computing duress hash."""
        from meow_decoder.crypto import compute_duress_hash
        
        password = "DuressPassword!"
        salt = secrets.token_bytes(16)
        
        hash_tag = compute_duress_hash(password, salt)
        
        assert len(hash_tag) == 32
    
    def test_compute_duress_tag(self):
        """Test computing duress tag."""
        from meow_decoder.crypto import compute_duress_tag
        
        password = "DuressPassword!"
        salt = secrets.token_bytes(16)
        manifest_core = secrets.token_bytes(100)
        
        tag = compute_duress_tag(password, salt, manifest_core)
        
        assert len(tag) == 32
    
    def test_check_duress_password(self):
        """Test checking duress password."""
        from meow_decoder.crypto import check_duress_password, compute_duress_tag
        
        password = "DuressPassword!"
        wrong_password = "WrongPassword!"
        salt = secrets.token_bytes(16)
        manifest_core = secrets.token_bytes(100)
        
        # Compute tag
        tag = compute_duress_tag(password, salt, manifest_core)
        
        # Check correct password
        assert check_duress_password(password, salt, tag, manifest_core) is True
        
        # Check wrong password
        assert check_duress_password(wrong_password, salt, tag, manifest_core) is False


class TestCryptoKeyfile:
    """Test keyfile functions."""
    
    def test_verify_keyfile_valid(self):
        """Test verifying valid keyfile."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(secrets.token_bytes(256))
            temp_path = f.name
        
        try:
            keyfile = verify_keyfile(temp_path)
            
            assert len(keyfile) == 256
        finally:
            os.unlink(temp_path)
    
    def test_verify_keyfile_too_small(self):
        """Test that too-small keyfile fails."""
        from meow_decoder.crypto import verify_keyfile
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"short")  # Less than 32 bytes
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="too small"):
                verify_keyfile(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_verify_keyfile_not_found(self):
        """Test that non-existent keyfile fails."""
        from meow_decoder.crypto import verify_keyfile
        
        with pytest.raises(FileNotFoundError):
            verify_keyfile("/nonexistent/path/keyfile.key")


class TestCryptoNonceReuse:
    """Test nonce reuse protection."""
    
    def test_nonce_reuse_detection(self):
        """Test that nonce reuse is detected."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        
        # Clear cache
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First use should succeed
        _register_nonce_use(key, nonce)
        
        # Second use with same key/nonce should raise
        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(key, nonce)


class TestCryptoBackendOperations:
    """Test crypto backend operations."""
    
    def test_argon2id_derivation(self):
        """Test Argon2id key derivation via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        password = b"TestPassword123!"
        salt = secrets.token_bytes(16)
        
        key = backend.derive_key_argon2id(
            password, salt,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        assert len(key) == 32
    
    def test_x25519_key_exchange(self):
        """Test X25519 key exchange via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        # Generate keypairs
        priv1, pub1 = backend.x25519_generate_keypair()
        priv2, pub2 = backend.x25519_generate_keypair()
        
        # Exchange
        shared1 = backend.x25519_exchange(priv1, pub2)
        shared2 = backend.x25519_exchange(priv2, pub1)
        
        # Shared secrets should match
        assert shared1 == shared2
    
    def test_hkdf_derivation(self):
        """Test HKDF key derivation via backend."""
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test info"
        
        key = backend.derive_key_hkdf(ikm, salt, info, output_len=32)
        
        assert len(key) == 32


class TestForwardSecrecyRoundtrip:
    """Test forward secrecy encryption roundtrip."""
    
    def test_forward_secrecy_roundtrip(self):
        """Test full forward secrecy roundtrip."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        data = b"Secret data for forward secrecy test"
        password = "TestPassword123!"
        
        # Generate receiver keypair
        receiver_priv, receiver_pub = generate_receiver_keypair()
        
        # Encrypt with receiver public key
        comp, sha256, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password, receiver_public_key=receiver_pub
        )
        
        assert ephemeral is not None
        
        # Decrypt with receiver private key
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data), comp_len=len(comp), sha256=sha256,
            ephemeral_public_key=ephemeral,
            receiver_private_key=receiver_priv
        )
        
        assert decrypted == data


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
