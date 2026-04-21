#!/usr/bin/env python3
"""
🔒 Security Test Suite - Part 1 of 3: Crypto Integrity

Tests tamper detection and authentication failure invariants.
Run consecutively with test_security_frame_mac.py and test_security_manifest.py.

1. Tamper detection (manifest, frames, ciphertext)
2. Authentication failures (wrong password, wrong key, wrong salt)
"""

from meow_decoder.crypto import (
    encrypt_file_bytes,
    decrypt_to_raw,
    Manifest,
    pack_manifest_core,
    compute_manifest_hmac,
    verify_manifest_hmac,
    derive_key,
)
import secrets
import pytest

pytestmark = pytest.mark.security


# =============================================================================
# TAMPER DETECTION TESTS (5 tests)
# =============================================================================


class TestTamperDetection:
    """Test that tampering with data is detected and rejected."""

    def test_tampered_ciphertext_rejected(self):
        """Tampered ciphertext should fail GCM authentication."""
        data = b"Secret message for encryption"
        password = "testpass123"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        # Flip bit in middle of ciphertext
        tampered = bytearray(cipher)
        tampered[len(cipher) // 2] ^= 0xFF

        with pytest.raises(Exception):
            decrypt_to_raw(
                bytes(tampered),
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    def test_tampered_nonce_rejected(self):
        """Tampered nonce should fail decryption."""
        data = b"Secret message"
        password = "testpass123"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        # Flip bit in nonce
        tampered_nonce = bytearray(nonce)
        tampered_nonce[0] ^= 0x01

        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                bytes(tampered_nonce),
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    def test_tampered_aad_sha256_rejected(self):
        """Tampering with AAD (sha256 field) should cause authentication failure."""
        data = b"Secret message"
        password = "testpass123"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        # Tamper SHA256 hash
        tampered_sha = bytearray(sha)
        tampered_sha[0] ^= 0xFF

        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=bytes(tampered_sha),
            )

    def test_tampered_aad_orig_len_rejected(self):
        """Tampering with AAD (orig_len field) should cause authentication failure."""
        data = b"Secret message"
        password = "testpass123"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        # Modify orig_len - should fail AAD check
        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                orig_len=len(data) + 1000,  # Tampered!
                comp_len=len(comp),
                sha256=sha,
            )

    def test_partial_ciphertext_rejected(self):
        """Partial ciphertext should fail GCM authentication."""
        data = b"Secret message that is longer than the usual test data"
        password = "testpass123"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        # Take only first half of ciphertext
        partial = cipher[: len(cipher) // 2]

        with pytest.raises(Exception):
            decrypt_to_raw(
                partial,
                password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )


# =============================================================================
# AUTHENTICATION FAILURE TESTS (5 tests)
# =============================================================================


class TestAuthenticationFailures:
    """Tests for authentication mechanism failures."""

    def test_wrong_password_fails_decrypt(self):
        """Wrong password should fail decryption."""
        data = b"Secret message"
        correct_password = "correct_password123"
        wrong_password = "wrong_password456"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, correct_password, None, None
        )

        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                wrong_password,
                salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    def test_wrong_salt_fails_decrypt(self):
        """Wrong salt should fail key derivation and decryption."""
        data = b"Secret message"
        password = "testpass123"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        # Use different salt
        wrong_salt = secrets.token_bytes(16)

        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password,
                wrong_salt,
                nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    def test_manifest_hmac_wrong_password_fails(self):
        """Manifest HMAC verification should fail with wrong password."""
        password = "correct_password"
        salt = secrets.token_bytes(16)

        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=4,
            hmac=b"\x00" * 32,
        )

        # Compute HMAC with correct password
        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)
        enc_key = derive_key(password, salt)
        hmac_tag = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)
        manifest.hmac = hmac_tag

        # Verify with correct password passes
        assert verify_manifest_hmac(password, manifest) is True

        # Verify with wrong password fails
        assert verify_manifest_hmac("wrong_password", manifest) is False

    def test_manifest_hmac_tampered_manifest_fails(self):
        """Tampered manifest should fail HMAC verification."""
        password = "test_password"
        salt = secrets.token_bytes(16)

        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=4,
            hmac=b"\x00" * 32,
        )

        # Compute valid HMAC
        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)
        enc_key = derive_key(password, salt)
        hmac_tag = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)
        manifest.hmac = hmac_tag

        # Tamper manifest field after HMAC computed
        manifest.orig_len = 9999  # Tampered!

        # Should fail verification
        assert verify_manifest_hmac(password, manifest) is False

    def test_empty_password_rejected(self):
        """Empty password should be rejected."""
        data = b"Secret message"

        # encrypt_file_bytes wraps ValueError in RuntimeError
        with pytest.raises(RuntimeError, match="cannot be empty"):
            encrypt_file_bytes(data, "", None, None)
