#!/usr/bin/env python3
"""
🔐 Comprehensive Crypto Module Tests
Consolidated from: test_crypto.py, test_coverage_90_crypto.py, test_crypto_aggressive.py

Target: 95-100% coverage of meow_decoder/crypto.py

Security-critical tests for:
- Key derivation (Argon2id)
- AES-256-GCM encryption/decryption
- HMAC authentication
- Manifest integrity
- Duress password handling
- Tamper detection
- Error message safety

FAIL-CLOSED PRINCIPLE: Any ambiguity results in test failure.
"""

import os
import sys
import pytest
import secrets
import hashlib
import struct
from unittest.mock import patch, MagicMock

# Enable test mode for faster Argon2id
os.environ["MEOW_TEST_MODE"] = "1"

# Import from meow_decoder
from meow_decoder.crypto import (
    derive_key,
    encrypt_file_bytes,
    decrypt_to_raw,
    pack_manifest,
    unpack_manifest,
    compute_manifest_hmac,
    verify_manifest_hmac,
    Manifest,
    MAGIC,
    MIN_PASSWORD_LENGTH,
)
from meow_decoder.crypto_backend import get_default_backend


class TestAESGCMRoundTrip:
    """Test encrypt → decrypt round-trip integrity."""
    
    def test_roundtrip_returns_identical_bytes(self):
        """CRITICAL: Encrypted data must decrypt to exact original."""
        password = "TestPassword123!"
        test_data = b"Secret message that must survive round-trip perfectly."
        
        # Encrypt
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        # Decrypt
        recovered = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(test_data),
            comp_len=len(comp),
            sha256=sha
        )
        
        # MUST be byte-for-byte identical
        assert recovered == test_data, "Round-trip corruption detected!"
        
    def test_roundtrip_binary_data(self):
        """Binary data (non-UTF-8) must round-trip correctly."""
        password = "BinaryTest123!"
        # Generate random binary data including null bytes
        test_data = secrets.token_bytes(1024)
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        recovered = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(test_data),
            comp_len=len(comp),
            sha256=sha
        )
        
        assert recovered == test_data, "Binary round-trip corruption!"
        
    def test_roundtrip_empty_data(self):
        """Empty data must round-trip correctly."""
        password = "EmptyTest1234!"
        test_data = b""
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        recovered = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(test_data),
            comp_len=len(comp),
            sha256=sha
        )
        
        assert recovered == test_data, "Empty data round-trip failed!"
        
    def test_roundtrip_large_data(self):
        """Large data (1MB) must round-trip correctly."""
        password = "LargeDataTest1!"
        # 1 MB of random data
        test_data = secrets.token_bytes(1024 * 1024)
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        recovered = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(test_data),
            comp_len=len(comp),
            sha256=sha
        )
        
        assert recovered == test_data, "Large data round-trip corruption!"


class TestWrongKeyRejection:
    """Test that wrong keys are ALWAYS rejected."""
    
    def test_wrong_password_rejected(self):
        """Wrong password must fail decryption."""
        correct_password = "CorrectPass123!"
        wrong_password = "WrongPassword1!"
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, correct_password
        )
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, wrong_password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )
            
    def test_similar_password_rejected(self):
        """Password differing by one character must fail."""
        correct_password = "CorrectPass123!"
        wrong_password = "CorrectPass123?"  # Single char difference
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, correct_password
        )
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, wrong_password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )
            
    def test_case_sensitivity(self):
        """Password case differences must fail."""
        correct_password = "CorrectPass123!"
        wrong_password = "correctpass123!"  # All lowercase
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, correct_password
        )
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, wrong_password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )


class TestCiphertextTampering:
    """Test that ANY ciphertext modification is detected."""
    
    def test_single_bit_flip_detected(self):
        """Single bit flip in ciphertext must fail authentication."""
        password = "TamperTest1234!"
        test_data = b"Secret data that must be protected"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        # Flip a single bit in middle of ciphertext
        tampered = bytearray(cipher)
        mid = len(tampered) // 2
        tampered[mid] ^= 0x01  # Flip lowest bit
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                bytes(tampered), password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )
            
    def test_truncated_ciphertext_fails(self):
        """Truncated ciphertext must fail."""
        password = "TruncateTest12!"
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        # Remove last 16 bytes (GCM tag)
        truncated = cipher[:-16]
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                truncated, password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )
            
    def test_extended_ciphertext_fails(self):
        """Extended ciphertext must fail."""
        password = "ExtendTest1234!"
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        # Append garbage
        extended = cipher + b"\x00" * 16
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                extended, password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )


class TestAuthTagTampering:
    """Test authentication tag manipulation detection."""
    
    def test_zeroed_auth_tag_fails(self):
        """Zeroed auth tag must fail."""
        password = "AuthTagTest123!"
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        # Zero out auth tag (last 16 bytes of GCM ciphertext)
        tampered = cipher[:-16] + (b"\x00" * 16)
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                tampered, password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )
            
    def test_random_auth_tag_fails(self):
        """Random auth tag must fail."""
        password = "RandomTag12345!"
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        # Replace auth tag with random bytes
        tampered = cipher[:-16] + secrets.token_bytes(16)
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                tampered, password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )


class TestNonceHandling:
    """Test nonce/IV handling and uniqueness."""
    
    def test_nonce_is_random(self):
        """Each encryption must use unique nonce."""
        password = "NonceTest12345!"
        test_data = b"Same data encrypted twice"
        
        # Encrypt same data twice
        _, _, _, nonce1, _, _, _ = encrypt_file_bytes(test_data, password)
        _, _, _, nonce2, _, _, _ = encrypt_file_bytes(test_data, password)
        
        # Nonces MUST be different
        assert nonce1 != nonce2, "Nonce reuse detected!"
        
    def test_nonce_length(self):
        """Nonce must be exactly 12 bytes for GCM."""
        password = "NonceLenTest12!"
        test_data = b"Test data"
        
        _, _, _, nonce, _, _, _ = encrypt_file_bytes(test_data, password)
        
        assert len(nonce) == 12, f"Nonce must be 12 bytes, got {len(nonce)}"
        
    def test_wrong_nonce_fails_decryption(self):
        """Wrong nonce must fail decryption."""
        password = "WrongNonceTest!"
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        # Use different nonce
        wrong_nonce = secrets.token_bytes(12)
        
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, password, salt, wrong_nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )


class TestKeyLengthValidation:
    """Test that key length requirements are enforced."""
    
    def test_salt_must_be_16_bytes(self):
        """Salt must be exactly 16 bytes."""
        password = "SaltLenTest123!"
        
        # Too short
        with pytest.raises(ValueError):
            derive_key(password, b"short")
            
        # Too long
        with pytest.raises(ValueError):
            derive_key(password, b"x" * 32)
            
        # Correct length works
        key = derive_key(password, b"x" * 16)
        assert len(key) == 32
        
    def test_derived_key_is_32_bytes(self):
        """Derived key must be 32 bytes for AES-256."""
        password = "KeyLenTest1234!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"


class TestPasswordValidation:
    """Test password requirements and validation."""
    
    def test_empty_password_rejected(self):
        """Empty password must be rejected."""
        with pytest.raises(ValueError):
            derive_key("", b"x" * 16)
            
    def test_short_password_rejected(self):
        """Password shorter than minimum must be rejected."""
        salt = b"x" * 16
        
        # Just under minimum
        short_password = "x" * (MIN_PASSWORD_LENGTH - 1)
        with pytest.raises(ValueError):
            derive_key(short_password, salt)
            
    def test_minimum_length_password_accepted(self):
        """Password at minimum length must work."""
        salt = b"x" * 16
        password = "x" * MIN_PASSWORD_LENGTH
        
        key = derive_key(password, salt)
        assert len(key) == 32


class TestErrorMessageSafety:
    """Test that error messages don't leak sensitive info."""
    
    def test_wrong_password_generic_error(self):
        """Wrong password error must not reveal why it failed."""
        password = "CorrectPass123!"
        wrong_password = "WrongPassword1!"
        test_data = b"Secret data"
        
        comp, sha, salt, nonce, cipher, _, key = encrypt_file_bytes(
            test_data, password
        )
        
        try:
            decrypt_to_raw(
                cipher, wrong_password, salt, nonce,
                orig_len=len(test_data),
                comp_len=len(comp),
                sha256=sha
            )
            pytest.fail("Should have raised exception")
        except RuntimeError as e:
            error_msg = str(e).lower()
            # Error should not reveal specifics
            assert "password" not in error_msg or "wrong" in error_msg
            # Should not leak key material
            assert salt.hex() not in error_msg
            assert nonce.hex() not in error_msg
            

class TestManifestIntegrity:
    """Test manifest HMAC authentication."""
    
    def test_manifest_hmac_roundtrip(self):
        """Manifest HMAC must verify correctly."""
        password = "ManifestTest12!"
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        manifest = Manifest(
            salt=salt,
            nonce=nonce,
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32  # Placeholder
        )
        
        # Compute HMAC
        packed = pack_manifest(manifest)[:-32]  # Exclude HMAC placeholder
        manifest.hmac = compute_manifest_hmac(password, salt, packed)
        
        # Verify
        assert verify_manifest_hmac(password, manifest)
        
    def test_manifest_wrong_password_fails(self):
        """Manifest HMAC must fail with wrong password."""
        password = "CorrectPass123!"
        wrong_password = "WrongPassword1!"
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        manifest = Manifest(
            salt=salt,
            nonce=nonce,
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32
        )
        
        # Compute HMAC with correct password
        packed = pack_manifest(manifest)[:-32]
        manifest.hmac = compute_manifest_hmac(password, salt, packed)
        
        # Verify with wrong password
        assert not verify_manifest_hmac(wrong_password, manifest)
        
    def test_manifest_tampered_field_fails(self):
        """Tampered manifest fields must fail HMAC verification."""
        password = "TamperManifest1!"
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        manifest = Manifest(
            salt=salt,
            nonce=nonce,
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=b'\x00' * 32
        )
        
        # Compute HMAC
        packed = pack_manifest(manifest)[:-32]
        manifest.hmac = compute_manifest_hmac(password, salt, packed)
        
        # Tamper with a field
        manifest.orig_len = 9999
        
        # Must fail verification
        assert not verify_manifest_hmac(password, manifest)


class TestManifestPackingUnpacking:
    """Test manifest serialization integrity."""
    
    def test_manifest_roundtrip(self):
        """Packed manifest must unpack to identical values."""
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        sha = secrets.token_bytes(32)
        hmac_tag = secrets.token_bytes(32)
        
        original = Manifest(
            salt=salt,
            nonce=nonce,
            orig_len=12345,
            comp_len=10000,
            cipher_len=10016,
            sha256=sha,
            block_size=512,
            k_blocks=25,
            hmac=hmac_tag
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
        
    def test_manifest_invalid_magic_rejected(self):
        """Invalid magic bytes must be rejected."""
        # Create valid manifest
        packed = b"XXXX" + b"\x00" * 111  # Wrong magic
        
        with pytest.raises(ValueError):
            unpack_manifest(packed)
            
    def test_manifest_truncated_rejected(self):
        """Truncated manifest must be rejected."""
        with pytest.raises(ValueError):
            unpack_manifest(b"MEOW3" + b"\x00" * 50)  # Too short


class TestDuress:
    """Test duress password functions."""
    
    def test_compute_duress_hash(self):
        """Test duress hash computation."""
        from meow_decoder.crypto import compute_duress_hash
        
        password = "DuressPassword123!"
        salt = secrets.token_bytes(16)
        
        hash1 = compute_duress_hash(password, salt)
        hash2 = compute_duress_hash(password, salt)
        
        assert len(hash1) == 32
        assert hash1 == hash2
    
    def test_compute_duress_tag(self):
        """Test duress tag computation."""
        from meow_decoder.crypto import compute_duress_tag
        
        password = "DuressPassword123!"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest core data " * 10
        
        tag = compute_duress_tag(password, salt, manifest_core)
        
        assert len(tag) == 32
    
    def test_check_duress_password(self):
        """Test duress password checking."""
        from meow_decoder.crypto import compute_duress_tag, check_duress_password
        
        password = "DuressPassword123!"
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest core data " * 10
        
        tag = compute_duress_tag(password, salt, manifest_core)
        
        # Correct password should match
        assert check_duress_password(password, salt, tag, manifest_core) == True
        
        # Wrong password should not match
        assert check_duress_password("WrongPassword!", salt, tag, manifest_core) == False
    
    def test_duress_different_passwords_different_tags(self):
        """Different passwords produce different duress tags."""
        from meow_decoder.crypto import compute_duress_tag
        
        salt = secrets.token_bytes(16)
        manifest_core = b"manifest data " * 10
        
        tag1 = compute_duress_tag("Password1234567!", salt, manifest_core)
        tag2 = compute_duress_tag("Password7654321!", salt, manifest_core)
        
        assert tag1 != tag2


class TestKeyfile:
    """Test keyfile functions."""
    
    def test_verify_keyfile_valid(self, tmp_path):
        """Test valid keyfile verification."""
        from meow_decoder.crypto import verify_keyfile
        
        keyfile_path = tmp_path / "keyfile.key"
        keyfile_path.write_bytes(secrets.token_bytes(64))
        
        content = verify_keyfile(str(keyfile_path))
        
        assert len(content) == 64
    
    def test_verify_keyfile_not_found(self):
        """Test missing keyfile."""
        from meow_decoder.crypto import verify_keyfile
        
        with pytest.raises(FileNotFoundError):
            verify_keyfile("/nonexistent/keyfile.key")
    
    def test_verify_keyfile_too_small(self, tmp_path):
        """Test keyfile too small."""
        from meow_decoder.crypto import verify_keyfile
        
        keyfile_path = tmp_path / "small.key"
        keyfile_path.write_bytes(b"tiny")
        
        with pytest.raises(ValueError, match="too small"):
            verify_keyfile(str(keyfile_path))
    
    def test_verify_keyfile_too_large(self, tmp_path):
        """Test keyfile too large."""
        from meow_decoder.crypto import verify_keyfile
        
        keyfile_path = tmp_path / "large.key"
        keyfile_path.write_bytes(secrets.token_bytes(2 * 1024 * 1024))  # 2 MB
        
        with pytest.raises(ValueError, match="too large"):
            verify_keyfile(str(keyfile_path))
    
    def test_keyfile_affects_encryption(self):
        """Keyfile must change encryption output."""
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        data = b"Test data for keyfile encryption"
        password = "TestPassword123!"
        keyfile = secrets.token_bytes(64)
        
        # Encrypt with keyfile
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, keyfile=keyfile)
        
        # Decrypt with keyfile - must work
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce, keyfile,
            orig_len=len(data), comp_len=len(comp), sha256=sha
        )
        assert decrypted == data
        
        # Decrypt WITHOUT keyfile - must fail
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher, password, salt, nonce,
                orig_len=len(data), comp_len=len(comp), sha256=sha
            )


class TestNonceReuse:
    """Test nonce reuse detection."""
    
    def test_nonce_reuse_detection(self):
        """Test that nonce reuse is detected."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        
        # Clear cache
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # First use should be fine
        _register_nonce_use(key, nonce)
        
        # Second use of same key/nonce should raise
        with pytest.raises(RuntimeError, match="Nonce reuse"):
            _register_nonce_use(key, nonce)
    
    def test_different_nonce_allowed(self):
        """Different nonces with same key should work."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        
        _nonce_reuse_cache.clear()
        
        key = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(12)
        nonce2 = secrets.token_bytes(12)
        
        _register_nonce_use(key, nonce1)
        _register_nonce_use(key, nonce2)  # Should not raise


class TestDeriveEncryptionKeyForManifest:
    """Test derive_encryption_key_for_manifest function."""
    
    def test_derive_encryption_key_password_only(self):
        """Test password-only key derivation."""
        from meow_decoder.crypto import derive_encryption_key_for_manifest
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        
        key = derive_encryption_key_for_manifest(password, salt)
        
        assert len(key) == 32
    
    def test_derive_encryption_key_with_keyfile(self):
        """Test key derivation with keyfile."""
        from meow_decoder.crypto import derive_encryption_key_for_manifest
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(64)
        
        key = derive_encryption_key_for_manifest(password, salt, keyfile=keyfile)
        
        assert len(key) == 32
    
    def test_derive_encryption_key_precomputed(self):
        """Test key derivation with precomputed key."""
        from meow_decoder.crypto import derive_encryption_key_for_manifest
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        precomputed = secrets.token_bytes(32)
        
        key = derive_encryption_key_for_manifest(
            password, salt, precomputed_key=precomputed
        )
        
        assert key == precomputed
    
    def test_precomputed_key_wrong_length_fails(self):
        """Precomputed key with wrong length must fail."""
        from meow_decoder.crypto import derive_encryption_key_for_manifest
        
        password = "TestPassword123!"
        salt = secrets.token_bytes(16)
        wrong_size_key = secrets.token_bytes(16)  # Should be 32
        
        with pytest.raises(ValueError, match="32 bytes"):
            derive_encryption_key_for_manifest(
                password, salt, precomputed_key=wrong_size_key
            )


class TestEncryptWithOptions:
    """Test encrypt_file_bytes with various options."""
    
    def test_encrypt_with_length_padding_enabled(self):
        """Test encryption with length padding enabled."""
        password = "PaddingTest123!"
        data = b"Padded data " * 50
        
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password, use_length_padding=True
        )
        
        assert len(cipher) > 0
    
    def test_encrypt_with_length_padding_disabled(self):
        """Test encryption without length padding."""
        password = "NoPaddingTest1!"
        data = b"Unpadded data " * 50
        
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password, use_length_padding=False
        )
        
        assert len(cipher) > 0
    
    def test_encrypt_with_precomputed_key(self):
        """Test encryption with precomputed key (hardware mode)."""
        password = "PrecomputedKey!"
        data = b"Hardware key data " * 50
        precomputed_key = secrets.token_bytes(32)
        precomputed_salt = secrets.token_bytes(16)
        
        comp, sha, salt, nonce, cipher, ephemeral, enc_key = encrypt_file_bytes(
            data, password,
            precomputed_key=precomputed_key,
            precomputed_salt=precomputed_salt
        )
        
        assert len(cipher) > 0
        assert salt == precomputed_salt
    
    def test_sha256_included_in_output(self):
        """SHA256 hash must be computed correctly."""
        password = "SHA256TestPwd1!"
        data = b"Test data for SHA256 verification"
        
        comp, sha, salt, nonce, cipher, ephemeral, key = encrypt_file_bytes(
            data, password
        )
        
        expected_sha = hashlib.sha256(data).digest()
        assert sha == expected_sha


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
