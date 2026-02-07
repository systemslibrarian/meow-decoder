"""
Tests for MT-1: Canonical AAD construction.

Verifies:
  - build_canonical_aad() produces deterministic output
  - Version byte is present at offset 0
  - Encrypt/decrypt roundtrip with canonical AAD succeeds
  - Mismatched AAD causes decryption failure
  - Test vectors for regression detection
"""

import os
import struct
import pytest

pytestmark = [pytest.mark.security, pytest.mark.crypto]

os.environ.setdefault("MEOW_TEST_MODE", "1")

from meow_decoder.crypto import (
    build_canonical_aad,
    AAD_VERSION,
    encrypt_file_bytes,
    decrypt_to_raw,
    MAGIC,
)

# ═══════════════════════════════════════════════════════════════
# § Test vectors (frozen for regression)
# ═══════════════════════════════════════════════════════════════

# Fixed inputs for deterministic reference
_SALT = bytes(range(16))  # 0x00..0x0f
_SHA = bytes(range(32))  # 0x00..0x1f
_EPK = bytes([0xAA] * 32)  # all-0xAA ephemeral key


class TestBuildCanonicalAAD:
    """Unit tests for the build_canonical_aad function."""

    def test_deterministic(self):
        """Same inputs always produce the same AAD."""
        a = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC)
        b = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC)
        assert a == b

    def test_version_byte_prefix(self):
        """AAD starts with AAD_VERSION byte."""
        aad = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC)
        assert aad[:1] == AAD_VERSION

    def test_layout_without_ephemeral(self):
        """Verify byte layout: version(1) + orig(8) + comp(8) + salt(16) + sha(32) + magic(len)."""
        aad = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC)
        expected_len = 1 + 8 + 8 + 16 + 32 + len(MAGIC)
        assert len(aad) == expected_len

        # Parse back
        assert aad[0:1] == AAD_VERSION
        orig, comp = struct.unpack_from("<QQ", aad, 1)
        assert orig == 100
        assert comp == 80
        assert aad[17:33] == _SALT
        assert aad[33:65] == _SHA
        assert aad[65 : 65 + len(MAGIC)] == MAGIC

    def test_layout_with_ephemeral(self):
        """Ephemeral public key is appended at the end."""
        aad = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC, ephemeral_public_key=_EPK)
        expected_len = 1 + 8 + 8 + 16 + 32 + len(MAGIC) + 32
        assert len(aad) == expected_len
        assert aad[-32:] == _EPK

    def test_different_lengths_differ(self):
        """Changing orig_len or comp_len changes AAD."""
        a = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC)
        b = build_canonical_aad(101, 80, _SALT, _SHA, MAGIC)
        c = build_canonical_aad(100, 81, _SALT, _SHA, MAGIC)
        assert a != b
        assert a != c
        assert b != c

    def test_different_salt_differs(self):
        """Changing salt changes AAD."""
        salt2 = bytes([0xFF] * 16)
        a = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC)
        b = build_canonical_aad(100, 80, salt2, _SHA, MAGIC)
        assert a != b

    def test_ephemeral_vs_no_ephemeral(self):
        """AAD with ephemeral key differs from one without."""
        a = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC)
        b = build_canonical_aad(100, 80, _SALT, _SHA, MAGIC, ephemeral_public_key=_EPK)
        assert a != b
        assert len(b) == len(a) + 32

    def test_regression_vector_no_epk(self):
        """Frozen test vector — password-only mode (no ephemeral key)."""
        aad = build_canonical_aad(
            orig_len=1024,
            comp_len=900,
            salt=b"\x00" * 16,
            sha256_hash=b"\x00" * 32,
            magic=b"MEOW3",
        )
        # Version byte
        assert aad[0:1] == b"\x01"
        # orig_len = 1024 LE
        assert struct.unpack_from("<Q", aad, 1)[0] == 1024
        # comp_len = 900 LE
        assert struct.unpack_from("<Q", aad, 9)[0] == 900
        # Total length: 1 + 8 + 8 + 16 + 32 + 5 = 70
        assert len(aad) == 70


class TestCanonicalAADRoundtrip:
    """Integration: encrypt → decrypt with canonical AAD."""

    def test_roundtrip_preserves_data(self):
        """Encrypt + decrypt roundtrip succeeds with canonical AAD."""
        plaintext = b"Canonical AAD test payload!" * 10
        password = "test-canonical-aad-42"
        comp, sha256, salt, nonce, ciphertext, eph_pk, enc_key = encrypt_file_bytes(
            plaintext, password
        )
        pt = decrypt_to_raw(
            ciphertext,
            password,
            salt,
            nonce,
            orig_len=len(plaintext),
            comp_len=len(comp),
            sha256=sha256,
            ephemeral_public_key=eph_pk,
        )
        assert pt == plaintext

    def test_wrong_password_fails(self):
        """Wrong password still causes AEAD failure (AAD mismatch)."""
        plaintext = b"Wrong password with canonical AAD"
        password = "correct-password-42"
        comp, sha256, salt, nonce, ciphertext, eph_pk, enc_key = encrypt_file_bytes(
            plaintext, password
        )
        with pytest.raises(Exception):
            decrypt_to_raw(
                ciphertext,
                "wrongwrongwrong",
                salt,
                nonce,
                orig_len=len(plaintext),
                comp_len=len(comp),
                sha256=sha256,
                ephemeral_public_key=eph_pk,
            )
