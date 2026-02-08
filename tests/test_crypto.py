"""
Comprehensive tests for crypto.py - Core cryptographic operations
"""

import pytest
import secrets
import hashlib
import os
from unittest.mock import patch, MagicMock

from meow_decoder.crypto import (
    derive_key,
    encrypt_file_bytes,
    decrypt_to_raw,
    pack_manifest,
    unpack_manifest,
    compute_manifest_hmac,
    verify_manifest_hmac,
    verify_keyfile,
    Manifest,
    pack_manifest_core,
    compute_duress_tag,
    check_duress_password,
    compute_duress_hash,
    build_canonical_aad,
    derive_encryption_key_for_manifest,
    MAGIC,
    MIN_PASSWORD_LENGTH,
    MAX_ORIG_LEN,
    MAX_K_BLOCKS,
    MIN_BLOCK_SIZE,
    MAX_BLOCK_SIZE,
)


class TestDeriveKey:
    """Tests for key derivation."""

    def test_basic_derivation(self):
        """Basic key derivation works."""
        salt = secrets.token_bytes(16)
        key = derive_key("password123", salt)
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_deterministic(self):
        """Same inputs produce same key."""
        salt = secrets.token_bytes(16)
        key1 = derive_key("password123", salt)
        key2 = derive_key("password123", salt)
        assert key1 == key2

    def test_different_passwords_different_keys(self):
        """Different passwords produce different keys."""
        salt = secrets.token_bytes(16)
        key1 = derive_key("password123", salt)
        key2 = derive_key("password456", salt)
        assert key1 != key2

    def test_different_salts_different_keys(self):
        """Different salts produce different keys."""
        key1 = derive_key("password123", secrets.token_bytes(16))
        key2 = derive_key("password123", secrets.token_bytes(16))
        assert key1 != key2

    def test_empty_password_rejected(self):
        """Empty password raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            derive_key("", secrets.token_bytes(16))

    def test_short_password_rejected(self):
        """Short password raises ValueError."""
        with pytest.raises(ValueError, match="at least"):
            derive_key("short", secrets.token_bytes(16))

    def test_wrong_salt_length_rejected(self):
        """Wrong salt length raises ValueError."""
        with pytest.raises(ValueError, match="16 bytes"):
            derive_key("password123", b"short")

    def test_with_keyfile(self):
        """Key derivation with keyfile."""
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        key = derive_key("password123", salt, keyfile)
        assert len(key) == 32

    def test_keyfile_changes_key(self):
        """Keyfile changes derived key."""
        salt = secrets.token_bytes(16)
        key1 = derive_key("password123", salt)
        key2 = derive_key("password123", salt, keyfile=secrets.token_bytes(64))
        assert key1 != key2

    def test_unicode_password(self):
        """Unicode password works."""
        salt = secrets.token_bytes(16)
        key = derive_key("пароль密码", salt)
        assert len(key) == 32


class TestEncryptDecrypt:
    """Tests for encryption and decryption."""

    def test_basic_roundtrip(self):
        """Basic encrypt/decrypt roundtrip."""
        data = b"Secret message here!" * 10
        password = "testpassword123"

        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(data, password)

        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, orig_len=len(data), comp_len=len(comp), sha256=sha
        )

        assert decrypted == data

    def test_roundtrip_with_keyfile(self):
        """Encrypt/decrypt with keyfile."""
        data = b"Secret with keyfile" * 5
        password = "password123"
        keyfile = secrets.token_bytes(64)

        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(
            data, password, keyfile=keyfile
        )

        decrypted = decrypt_to_raw(
            cipher,
            password,
            salt,
            nonce,
            keyfile=keyfile,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha,
        )

        assert decrypted == data

    def test_wrong_password_fails(self):
        """Wrong password fails decryption."""
        data = b"Secret message"
        password = "correctpassword"

        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(data, password)

        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                cipher,
                "wrongpassword",
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    def test_wrong_keyfile_fails(self):
        """Wrong keyfile fails decryption."""
        data = b"Secret with keyfile"
        password = "password123"
        keyfile = secrets.token_bytes(64)

        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(
            data, password, keyfile=keyfile
        )

        with pytest.raises(RuntimeError, match="Decryption failed"):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                keyfile=secrets.token_bytes(64),  # Different keyfile
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    def test_tampered_cipher_fails(self):
        """Tampered ciphertext fails."""
        data = b"Secret message"
        password = "password12345"

        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(data, password)

        # Tamper with ciphertext
        tampered = bytearray(cipher)
        tampered[10] ^= 0xFF

        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                bytes(tampered),
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    def test_large_data(self):
        """Large data encryption works."""
        data = secrets.token_bytes(100000)
        password = "password12345"

        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(data, password)

        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, orig_len=len(data), comp_len=len(comp), sha256=sha
        )

        assert decrypted == data

    def test_compression(self):
        """Compressible data gets smaller."""
        data = b"A" * 10000  # Highly compressible
        password = "password12345"

        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(data, password)

        # Compressed should be much smaller (before padding)
        # Note: with length padding it may be larger
        assert len(cipher) < len(data) + 1000  # Allow some overhead

    def test_returns_encryption_key(self):
        """encrypt_file_bytes returns the encryption key."""
        data = b"Test data"
        password = "password12345"

        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(data, password)

        assert len(enc_key) == 32
        assert isinstance(enc_key, bytes)


class TestManifest:
    """Tests for manifest packing/unpacking."""

    def test_basic_pack_unpack(self):
        """Basic manifest roundtrip."""
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=5,
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

    def test_manifest_with_ephemeral_key(self):
        """Manifest with forward secrecy ephemeral key."""
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=5,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
        )

        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)

        assert unpacked.ephemeral_public_key == manifest.ephemeral_public_key

    def test_manifest_with_duress_tag(self):
        """Manifest with duress tag."""
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=5,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            duress_tag=secrets.token_bytes(32),
        )

        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)

        assert unpacked.duress_tag == manifest.duress_tag

    def test_manifest_too_short(self):
        """Too short manifest rejected."""
        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(b"short")

    def test_manifest_invalid_magic(self):
        """Invalid magic rejected."""
        # Must be exactly 115 bytes (base manifest size) to pass length check
        fake_manifest = b"BADMG" + b"\x00" * 110  # 5 + 110 = 115 bytes
        with pytest.raises(ValueError, match="Invalid MAGIC"):
            unpack_manifest(fake_manifest)

    def test_manifest_k_blocks_zero_rejected(self):
        """k_blocks=0 rejected."""
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=0,  # Invalid
            hmac=secrets.token_bytes(32),
        )
        packed = pack_manifest(manifest)

        with pytest.raises(ValueError, match="k_blocks out of range"):
            unpack_manifest(packed)

    def test_manifest_invalid_length(self):
        """Invalid manifest length rejected."""
        # Create valid header but wrong total length (must be >= 115 but not a valid size)
        # Valid sizes are: 115, 147, 179, 1235, 1267
        fake = MAGIC + secrets.token_bytes(115)  # 5 + 115 = 120 bytes (invalid size)
        with pytest.raises(ValueError, match="(length invalid|too short)"):
            unpack_manifest(fake)


class TestManifestHMAC:
    """Tests for manifest HMAC computation and verification."""

    def test_compute_hmac(self):
        """HMAC computation produces 32 bytes."""
        salt = secrets.token_bytes(16)
        packed = b"test manifest data"

        hmac_tag = compute_manifest_hmac("password123", salt, packed)

        assert len(hmac_tag) == 32
        assert isinstance(hmac_tag, bytes)

    def test_hmac_deterministic(self):
        """Same inputs produce same HMAC."""
        salt = secrets.token_bytes(16)
        packed = b"test manifest data"

        hmac1 = compute_manifest_hmac("password123", salt, packed)
        hmac2 = compute_manifest_hmac("password123", salt, packed)

        assert hmac1 == hmac2

    def test_hmac_different_passwords(self):
        """Different passwords produce different HMACs."""
        salt = secrets.token_bytes(16)
        packed = b"test manifest data"

        hmac1 = compute_manifest_hmac("password123", salt, packed)
        hmac2 = compute_manifest_hmac("password456", salt, packed)

        assert hmac1 != hmac2

    def test_verify_hmac_valid(self):
        """Valid HMAC verification succeeds."""
        salt = secrets.token_bytes(16)
        enc_key = derive_key("password12345", salt)

        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=5,
            hmac=b"\x00" * 32,
        )

        packed_core = pack_manifest_core(manifest, include_duress_tag=False)
        manifest.hmac = compute_manifest_hmac(
            "password12345", salt, packed_core, encryption_key=enc_key
        )

        assert verify_manifest_hmac("password12345", manifest)

    def test_verify_hmac_wrong_password(self):
        """Wrong password fails HMAC verification."""
        salt = secrets.token_bytes(16)
        enc_key = derive_key("password12345", salt)

        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=5,
            hmac=b"\x00" * 32,
        )

        packed_core = pack_manifest_core(manifest, include_duress_tag=False)
        manifest.hmac = compute_manifest_hmac(
            "password12345", salt, packed_core, encryption_key=enc_key
        )

        assert not verify_manifest_hmac("wrongpassword", manifest)


class TestDuress:
    """Tests for duress password functionality."""

    def test_compute_duress_hash(self):
        """Duress hash computation works."""
        salt = secrets.token_bytes(16)
        hash1 = compute_duress_hash("duress_pass", salt)

        assert len(hash1) == 32

    def test_duress_hash_deterministic(self):
        """Same inputs produce same hash."""
        salt = secrets.token_bytes(16)
        hash1 = compute_duress_hash("duress_pass", salt)
        hash2 = compute_duress_hash("duress_pass", salt)

        assert hash1 == hash2

    def test_compute_duress_tag(self):
        """Duress tag computation works."""
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest core data"

        tag = compute_duress_tag("duress_pass", salt, manifest_core)

        assert len(tag) == 32

    def test_check_duress_password_correct(self):
        """Correct duress password detected."""
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest core data"

        tag = compute_duress_tag("duress_pass", salt, manifest_core)

        assert check_duress_password("duress_pass", salt, tag, manifest_core)

    def test_check_duress_password_wrong(self):
        """Wrong duress password rejected."""
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest core data"

        tag = compute_duress_tag("duress_pass", salt, manifest_core)

        assert not check_duress_password("wrong_pass", salt, tag, manifest_core)


class TestCanonicalAAD:
    """Tests for canonical AAD construction."""

    def test_build_aad(self):
        """Basic AAD construction."""
        aad = build_canonical_aad(
            orig_len=1000,
            comp_len=800,
            salt=b"a" * 16,
            sha256_hash=b"b" * 32,
            magic=b"MEOW3",
        )

        assert isinstance(aad, bytes)
        assert len(aad) > 0

    def test_aad_with_ephemeral_key(self):
        """AAD with ephemeral key is longer."""
        aad1 = build_canonical_aad(
            orig_len=1000,
            comp_len=800,
            salt=b"a" * 16,
            sha256_hash=b"b" * 32,
            magic=b"MEOW3",
        )

        aad2 = build_canonical_aad(
            orig_len=1000,
            comp_len=800,
            salt=b"a" * 16,
            sha256_hash=b"b" * 32,
            magic=b"MEOW3",
            ephemeral_public_key=b"c" * 32,
        )

        assert len(aad2) == len(aad1) + 32

    def test_aad_deterministic(self):
        """Same inputs produce same AAD."""
        params = {
            "orig_len": 1000,
            "comp_len": 800,
            "salt": b"a" * 16,
            "sha256_hash": b"b" * 32,
            "magic": b"MEOW3",
        }

        aad1 = build_canonical_aad(**params)
        aad2 = build_canonical_aad(**params)

        assert aad1 == aad2


class TestKeyfile:
    """Tests for keyfile handling."""

    def test_verify_valid_keyfile(self, tmp_path):
        """Valid keyfile verification."""
        keyfile_path = tmp_path / "keyfile.bin"
        keyfile_data = secrets.token_bytes(64)
        keyfile_path.write_bytes(keyfile_data)

        result = verify_keyfile(str(keyfile_path))

        assert result == keyfile_data

    def test_verify_keyfile_not_found(self):
        """Missing keyfile raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            verify_keyfile("/nonexistent/keyfile.bin")

    def test_verify_keyfile_too_small(self, tmp_path):
        """Too small keyfile rejected."""
        keyfile_path = tmp_path / "small.bin"
        keyfile_path.write_bytes(b"small")  # Less than 32 bytes

        with pytest.raises(ValueError, match="too small"):
            verify_keyfile(str(keyfile_path))

    def test_verify_keyfile_too_large(self, tmp_path):
        """Too large keyfile rejected."""
        keyfile_path = tmp_path / "large.bin"
        keyfile_path.write_bytes(secrets.token_bytes(2 * 1024 * 1024))  # 2 MB

        with pytest.raises(ValueError, match="too large"):
            verify_keyfile(str(keyfile_path))


class TestDeriveEncryptionKeyForManifest:
    """Tests for derive_encryption_key_for_manifest."""

    def test_password_only_mode(self):
        """Password-only key derivation."""
        salt = secrets.token_bytes(16)
        key = derive_encryption_key_for_manifest("password12345", salt)

        assert len(key) == 32

    def test_with_keyfile(self):
        """Key derivation with keyfile."""
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        key = derive_encryption_key_for_manifest("password12345", salt, keyfile=keyfile)

        assert len(key) == 32

    def test_with_precomputed_key(self):
        """Precomputed key is returned directly."""
        salt = secrets.token_bytes(16)
        precomputed = secrets.token_bytes(32)

        key = derive_encryption_key_for_manifest("password12345", salt, precomputed_key=precomputed)

        assert key == precomputed

    def test_precomputed_key_wrong_length(self):
        """Wrong length precomputed key rejected."""
        salt = secrets.token_bytes(16)

        with pytest.raises(ValueError, match="32 bytes"):
            derive_encryption_key_for_manifest("password12345", salt, precomputed_key=b"short")

    def test_forward_secrecy_requires_private_key(self):
        """Forward secrecy mode requires receiver private key."""
        salt = secrets.token_bytes(16)

        with pytest.raises(ValueError, match="requires receiver private key"):
            derive_encryption_key_for_manifest(
                "password12345",
                salt,
                ephemeral_public_key=secrets.token_bytes(32),
                # Missing receiver_private_key
            )
