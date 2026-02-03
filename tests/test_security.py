#!/usr/bin/env python3
"""
🔒 Security Test Suite - Battle-Hardening Tests

CANONICAL test file for security invariants. DO NOT create numbered variants.

Tests critical security invariants:
1. Tamper detection (manifest, frames, ciphertext)
2. Replay/reorder protection  
3. Authentication failures (wrong password, wrong key)
4. Corruption handling (fail closed)
5. Forward secrecy mode
6. AAD integrity
7. Frame MAC verification

These tests ensure security regressions are caught automatically.
"""

import pytest
import secrets
import struct
from pathlib import Path

from meow_decoder.encode import encode_file
from meow_decoder.decode_gif import decode_gif
from meow_decoder.crypto import (
    encrypt_file_bytes,
    decrypt_to_raw,
    Manifest,
    pack_manifest,
    unpack_manifest,
    compute_manifest_hmac,
    verify_manifest_hmac,
    MAGIC,
    derive_key,
    pack_manifest_core,
    compute_duress_tag,
    check_duress_password,
)
from meow_decoder.config import EncodingConfig
from meow_decoder.fountain import (
    FountainEncoder,
    FountainDecoder,
    pack_droplet,
    unpack_droplet,
)
from meow_decoder.frame_mac import (
    compute_frame_mac,
    verify_frame_mac,
    pack_frame_with_mac,
    unpack_frame_with_mac,
    FrameMACStats,
    MAC_SIZE,
    derive_frame_master_key,
)


# =============================================================================
# TAMPER DETECTION TESTS (5 tests)
# =============================================================================

class TestTamperDetection:
    """Test that tampering with data is detected and rejected."""

    def test_tampered_ciphertext_rejected(self):
        """Tampered ciphertext should fail GCM authentication."""
        data = b"Secret message for encryption"
        password = "testpass123"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
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
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
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
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
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
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
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
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
        # Take only first half of ciphertext
        partial = cipher[:len(cipher) // 2]
        
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
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )
        
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


# =============================================================================
# FRAME MAC SECURITY TESTS (5 tests)
# =============================================================================

class TestFrameMACSecurityInvariants:
    """Test frame MAC security invariants."""

    def test_frame_mac_detects_bit_flip(self):
        """Single bit flip in frame data should be detected."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)
        
        frame_data = b"This is test frame data for MAC verification"
        frame_idx = 5
        
        # Pack with MAC
        packed = pack_frame_with_mac(frame_data, master_key, frame_idx, salt)
        
        # Flip one bit in the data portion (after MAC)
        corrupted = bytearray(packed)
        corrupted[MAC_SIZE + 5] ^= 0x01  # Flip bit in data
        
        # Verification should fail
        is_valid, _ = unpack_frame_with_mac(bytes(corrupted), master_key, frame_idx, salt)
        assert is_valid is False

    def test_frame_mac_detects_wrong_frame_index(self):
        """Frame index mismatch should cause MAC verification to fail."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)
        
        frame_data = b"Test frame data"
        
        # Pack with frame index 5
        packed = pack_frame_with_mac(frame_data, master_key, 5, salt)
        
        # Try to verify with frame index 10 (should fail)
        is_valid, _ = unpack_frame_with_mac(packed, master_key, 10, salt)
        assert is_valid is False

    def test_frame_mac_detects_wrong_salt(self):
        """Wrong salt should cause MAC verification to fail."""
        password = "testpass123"
        salt = secrets.token_bytes(16)
        wrong_salt = secrets.token_bytes(16)
        
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)
        wrong_master_key = derive_frame_master_key(enc_key, wrong_salt)
        
        frame_data = b"Test frame data"
        packed = pack_frame_with_mac(frame_data, master_key, 0, salt)
        
        # Verify with wrong key (derived from wrong salt)
        is_valid, _ = unpack_frame_with_mac(packed, wrong_master_key, 0, wrong_salt)
        assert is_valid is False

    def test_frame_mac_stats_tracks_invalid(self):
        """FrameMACStats should correctly track valid/invalid frames."""
        stats = FrameMACStats()
        
        # Record some valid and invalid
        for _ in range(10):
            stats.record_valid()
        for _ in range(5):
            stats.record_invalid()
        
        assert stats.valid_frames == 10
        assert stats.invalid_frames == 5
        assert abs(stats.success_rate() - 10/15) < 0.001

    def test_frame_mac_prevents_replay_different_salt(self):
        """Frame MAC from one session should not validate in another."""
        password = "testpass123"
        
        # Session 1
        salt1 = secrets.token_bytes(16)
        enc_key1 = derive_key(password, salt1)
        master_key1 = derive_frame_master_key(enc_key1, salt1)
        
        # Session 2 (different salt)
        salt2 = secrets.token_bytes(16)
        enc_key2 = derive_key(password, salt2)
        master_key2 = derive_frame_master_key(enc_key2, salt2)
        
        frame_data = b"Test frame data"
        packed_session1 = pack_frame_with_mac(frame_data, master_key1, 0, salt1)
        
        # Try to verify session 1 MAC with session 2 key
        is_valid, _ = unpack_frame_with_mac(packed_session1, master_key2, 0, salt2)
        assert is_valid is False


# =============================================================================
# DURESS SECURITY TESTS (3 tests)
# =============================================================================

class TestDuressSecurityInvariants:
    """Test duress password security invariants."""

    def test_duress_tag_verifies_correctly(self):
        """Duress tag should verify with correct password."""
        duress_password = "duresspass123"
        salt = secrets.token_bytes(16)
        manifest_core = b"fake_manifest_core_data_for_testing"
        
        # Compute duress tag
        tag = compute_duress_tag(duress_password, salt, manifest_core)
        
        # Should verify correctly
        assert check_duress_password(duress_password, salt, tag, manifest_core) is True

    def test_duress_tag_rejects_wrong_password(self):
        """Duress tag should reject wrong password."""
        duress_password = "duresspass123"
        wrong_password = "wrongpass456"
        salt = secrets.token_bytes(16)
        manifest_core = b"fake_manifest_core_data"
        
        tag = compute_duress_tag(duress_password, salt, manifest_core)
        
        # Wrong password should fail
        assert check_duress_password(wrong_password, salt, tag, manifest_core) is False

    def test_duress_tag_detects_manifest_tampering(self):
        """Duress tag should detect manifest tampering."""
        duress_password = "duresspass123"
        salt = secrets.token_bytes(16)
        original_core = b"original_manifest_core_data"
        tampered_core = b"tampered_manifest_core_data"
        
        tag = compute_duress_tag(duress_password, salt, original_core)
        
        # Tampered manifest should fail verification
        assert check_duress_password(duress_password, salt, tag, tampered_core) is False


# =============================================================================
# MANIFEST PARSING SECURITY TESTS (2 tests)
# =============================================================================

class TestManifestParsingSecurityInvariants:
    """Test manifest parsing security invariants."""

    def test_manifest_too_short_rejected(self):
        """Manifest shorter than minimum should be rejected."""
        short_manifest = b"MEOW3" + b"\x00" * 50  # Too short
        
        with pytest.raises(ValueError, match="too short"):
            unpack_manifest(short_manifest)

    def test_manifest_wrong_magic_rejected(self):
        """Manifest with wrong magic bytes should be rejected."""
        # Valid length but wrong magic
        fake_manifest = b"FAKE" + b"3" + b"\x00" * 110
        
        with pytest.raises(ValueError, match="Invalid MAGIC"):
            unpack_manifest(fake_manifest)
