"""
Profile Enforcement Tests

Ensures that:
1. Encoder always sets crypto_profile on manifests.
2. classify_crypto_profile correctly classifies mode bytes.
3. Decoder rejects missing/unknown profiles.
4. Experimental profiles require explicit opt-in.
"""

import os
import pytest

pytestmark = pytest.mark.security

# Force test mode for fast Argon2id
os.environ.setdefault("MEOW_TEST_MODE", "1")

from meow_decoder.crypto import (
    Manifest,
    classify_crypto_profile,
    validate_decode_profile,
    PROFILE_PROD_MIN,
    PROFILE_PQ_EXPERIMENTAL,
    PROFILE_LEGACY,
    MODE_LEGACY,
    MODE_MEOW2,
    MODE_MEOW3,
    MODE_MEOW4,
    MODE_MEOW5,
    MODE_RATCHET,
    MODE_DURESS,
    unpack_manifest,
    pack_manifest,
)


class TestClassifyCryptoProfile:
    """Test profile classification from mode_byte."""

    def test_meow2_is_prod_min(self):
        assert classify_crypto_profile(MODE_MEOW2) == PROFILE_PROD_MIN

    def test_meow3_is_prod_min(self):
        assert classify_crypto_profile(MODE_MEOW3) == PROFILE_PROD_MIN

    def test_meow4_is_pq_experimental(self):
        assert classify_crypto_profile(MODE_MEOW4) == PROFILE_PQ_EXPERIMENTAL

    def test_meow5_is_pq_experimental(self):
        assert classify_crypto_profile(MODE_MEOW5) == PROFILE_PQ_EXPERIMENTAL

    def test_legacy_is_legacy(self):
        assert classify_crypto_profile(MODE_LEGACY) == PROFILE_LEGACY

    def test_meow2_duress_is_prod_min(self):
        assert classify_crypto_profile(MODE_MEOW2 | MODE_DURESS) == PROFILE_PROD_MIN

    def test_meow3_ratchet_is_prod_min(self):
        assert classify_crypto_profile(MODE_MEOW3 | MODE_RATCHET) == PROFILE_PROD_MIN

    def test_meow5_ratchet_duress_is_pq_experimental(self):
        assert (
            classify_crypto_profile(MODE_MEOW5 | MODE_RATCHET | MODE_DURESS)
            == PROFILE_PQ_EXPERIMENTAL
        )


class TestValidateDecodeProfile:
    """Test profile validation for decoding."""

    def test_prod_min_always_accepted(self):
        # Should not raise
        validate_decode_profile(PROFILE_PROD_MIN)

    def test_legacy_rejected_by_default(self):
        with pytest.raises(ValueError, match="legacy"):
            validate_decode_profile(PROFILE_LEGACY)

    def test_legacy_accepted_with_flag(self):
        # Should not raise
        validate_decode_profile(PROFILE_LEGACY, allow_legacy=True)

    def test_pq_experimental_rejected_by_default(self):
        with pytest.raises(ValueError, match="experimental"):
            validate_decode_profile(PROFILE_PQ_EXPERIMENTAL)

    def test_pq_experimental_accepted_with_flag(self):
        # Should not raise
        validate_decode_profile(PROFILE_PQ_EXPERIMENTAL, allow_experimental=True)

    def test_unknown_profile_rejected(self):
        with pytest.raises(ValueError, match="Unknown"):
            validate_decode_profile("INVALID_PROFILE")


class TestManifestHasProfile:
    """Test that packed/unpacked manifests carry crypto_profile."""

    def test_manifest_dataclass_has_profile(self):
        m = Manifest(
            salt=b"\x00" * 16,
            nonce=b"\x00" * 12,
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=b"\x00" * 32,
            block_size=800,
            k_blocks=1,
            hmac=b"\x00" * 32,
            mode_byte=MODE_MEOW2,
            crypto_profile=PROFILE_PROD_MIN,
        )
        assert m.crypto_profile == PROFILE_PROD_MIN

    def test_unpack_manifest_sets_profile(self):
        """unpack_manifest must set crypto_profile based on mode_byte."""
        m = Manifest(
            salt=b"\xaa" * 16,
            nonce=b"\xbb" * 12,
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=b"\xcc" * 32,
            block_size=800,
            k_blocks=1,
            hmac=b"\xdd" * 32,
            mode_byte=MODE_MEOW2,
        )
        packed = pack_manifest(m)
        unpacked = unpack_manifest(packed)
        assert unpacked.crypto_profile == PROFILE_PROD_MIN

    def test_unpack_meow5_is_pq_experimental(self):
        """MEOW5 manifest must be classified as PQ experimental."""
        # MEOW5 requires ephemeral_public_key and pq_ciphertext
        m = Manifest(
            salt=b"\xaa" * 16,
            nonce=b"\xbb" * 12,
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=b"\xcc" * 32,
            block_size=800,
            k_blocks=1,
            hmac=b"\xdd" * 32,
            mode_byte=MODE_MEOW5,
            ephemeral_public_key=b"\xee" * 32,
            pq_ciphertext=b"\xff" * 1088,  # ML-KEM-768
        )
        packed = pack_manifest(m)
        unpacked = unpack_manifest(packed)
        assert unpacked.crypto_profile == PROFILE_PQ_EXPERIMENTAL
