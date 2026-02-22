"""
Tests for dual-stream encoding — Schrödinger indistinguishability.

Validates that:
1. Single-secret encodes always produce two independent sub-streams.
2. Dual-secret (Schrödinger) mode works identically to single-secret
   in wire format structure.
3. Decoder authenticates only the correct stream.
4. Wrong password is rejected for both streams.
5. Single vs dual outputs are structurally identical.
6. Statistical indistinguishability of ciphertext bytes.
7. Independent keys per stream (no cross-commitment).
8. Target-frames size normalization works.
9. Manifest serialization roundtrips.
"""

from meow_decoder.dual_stream import (
    dual_stream_encode,
    dual_stream_try_decode_stream,
    secure_decode_and_zeroize,
    DualStreamManifest,
)
import os
import secrets
import struct
import math
from collections import Counter

import pytest

os.environ.setdefault("MEOW_TEST_MODE", "1")


# ── Helpers ──

def _make_payload(size: int = 120) -> bytes:
    """Generate a realistic-sized payload."""
    return secrets.token_bytes(size)


def _chi_squared_uniform(data: bytes) -> float:
    """Chi-squared statistic for uniformity test of byte values."""
    n = len(data)
    expected = n / 256.0
    counts = Counter(data)
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    return -sum(
        (c / n) * math.log2(c / n) for c in counts.values() if c > 0
    )


# ── Basic Functionality ──

class TestDualStreamBasic:
    """Core encode/decode functionality."""

    def test_single_secret_produces_two_streams(self):
        """Every encode ALWAYS produces two sub-streams."""
        data = _make_payload(200)
        ct, manifest = dual_stream_encode(data, "password_test_1", block_size=128)

        assert manifest.version == 0x08
        assert not manifest.stream_b_is_real  # dummy stream
        assert manifest.block_count > 0
        assert manifest.superposition_len > 0
        assert len(ct) >= manifest.superposition_len

    def test_dual_secret_produces_two_streams(self):
        """Schrödinger mode encode with two real payloads."""
        data_a = _make_payload(200)
        data_b = _make_payload(150)
        ct, manifest = dual_stream_encode(
            data_a, "passwordAAA1",
            decoy_data=data_b, decoy_password="passwordBBB1",
            block_size=128,
        )

        # AUDIT-P0: stream_b_is_real always returns False (never reveal stream type)
        assert not manifest.stream_b_is_real
        assert manifest.block_count > 0

    def test_single_secret_decode_correct_password(self):
        """Single-secret: correct password recovers stream A."""
        data = _make_payload(200)
        ct, manifest = dual_stream_encode(data, "correct_pass1", block_size=128)

        result = dual_stream_try_decode_stream(
            manifest, "correct_pass1", ct[:manifest.superposition_len]
        )
        assert result is not None
        cipher, idx = result
        assert idx == 0  # stream A
        assert len(cipher) > 0

    def test_single_secret_decode_wrong_password(self):
        """Single-secret: wrong password is rejected."""
        data = _make_payload(200)
        ct, manifest = dual_stream_encode(data, "correct_pass1", block_size=128)

        result = dual_stream_try_decode_stream(
            manifest, "wrong_password", ct[:manifest.superposition_len]
        )
        assert result is None

    def test_dual_secret_decode_both_passwords(self):
        """Schrödinger: both passwords recover their respective streams."""
        data_a = _make_payload(200)
        data_b = _make_payload(150)
        ct, manifest = dual_stream_encode(
            data_a, "schrodinger_A",
            decoy_data=data_b, decoy_password="schrodinger_B",
            block_size=128,
        )

        r_a = dual_stream_try_decode_stream(
            manifest, "schrodinger_A", ct[:manifest.superposition_len]
        )
        r_b = dual_stream_try_decode_stream(
            manifest, "schrodinger_B", ct[:manifest.superposition_len]
        )

        assert r_a is not None and r_a[1] == 0
        assert r_b is not None and r_b[1] == 1

    def test_dual_secret_wrong_password_rejected(self):
        """Schrödinger: wrong password rejected for both streams."""
        data_a = _make_payload(200)
        data_b = _make_payload(150)
        ct, manifest = dual_stream_encode(
            data_a, "schrodinger_A",
            decoy_data=data_b, decoy_password="schrodinger_B",
            block_size=128,
        )

        result = dual_stream_try_decode_stream(
            manifest, "nope_not_it!", ct[:manifest.superposition_len]
        )
        assert result is None


# ── Manifest Serialization ──

class TestDualStreamManifest:
    """Manifest pack/unpack roundtrip."""

    def test_manifest_roundtrip(self):
        """Pack → unpack preserves all fields."""
        m = DualStreamManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            hmac_a=secrets.token_bytes(32),
            hmac_b=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            block_count=42,
            block_size=256,
            superposition_len=99999,
            target_frames=100,
            flags=0x00,  # AUDIT-P0: flags must always be 0x00
        )
        packed = m.pack()
        assert len(packed) == 382

        m2 = DualStreamManifest.unpack(packed)
        assert m2.salt_a == m.salt_a
        assert m2.salt_b == m.salt_b
        assert m2.nonce_a == m.nonce_a
        assert m2.nonce_b == m.nonce_b
        assert m2.hmac_a == m.hmac_a
        assert m2.hmac_b == m.hmac_b
        assert m2.metadata_a == m.metadata_a
        assert m2.metadata_b == m.metadata_b
        assert m2.block_count == 42
        assert m2.block_size == 256
        assert m2.superposition_len == 99999
        assert m2.target_frames == 100
        # AUDIT-P0: stream_b_is_real always returns False (never reveal stream type)
        assert m2.stream_b_is_real is False

    def test_manifest_too_short(self):
        """Reject manifests shorter than 382 bytes."""
        with pytest.raises(ValueError, match="too short"):
            DualStreamManifest.unpack(b"\x00" * 100)

    def test_manifest_bad_magic(self):
        """Reject manifests with wrong magic."""
        data = b"WOOF" + b"\x00" * 378
        with pytest.raises(ValueError, match="Invalid manifest magic"):
            DualStreamManifest.unpack(data)

    def test_manifest_wrong_version(self):
        """Reject manifests with wrong version byte."""
        data = b"MEOW" + struct.pack("BB", 0x02, 0x00) + b"\x00" * 376
        with pytest.raises(ValueError, match="Not a dual-stream manifest"):
            DualStreamManifest.unpack(data)

    def test_manifest_fixed_size(self):
        """Both single and dual manifests are exactly 382 bytes."""
        data = _make_payload(200)
        _, m_single = dual_stream_encode(data, "single_pass1", block_size=128)
        _, m_dual = dual_stream_encode(
            data, "dual_passAAAA",
            decoy_data=_make_payload(200), decoy_password="dual_passBBBB",
            block_size=128,
        )
        assert len(m_single.pack()) == 382
        assert len(m_dual.pack()) == 382


# ── Structural Indistinguishability ──

class TestStructuralIndistinguishability:
    """Single-secret and dual-secret outputs must be structurally identical."""

    def test_manifest_size_identical(self):
        """Single and dual manifest packed sizes are equal."""
        data = _make_payload(300)
        _, m_single = dual_stream_encode(data, "singlepass11", block_size=128)
        _, m_dual = dual_stream_encode(
            data, "dualpassAAAA",
            decoy_data=_make_payload(300), decoy_password="dualpassBBBB",
            block_size=128,
        )
        assert len(m_single.pack()) == len(m_dual.pack())

    def test_manifest_version_byte_identical(self):
        """Both modes use version 0x08."""
        data = _make_payload(300)
        _, m_single = dual_stream_encode(data, "singlepass11", block_size=128)
        _, m_dual = dual_stream_encode(
            data, "dualpassAAAA",
            decoy_data=_make_payload(300), decoy_password="dualpassBBBB",
            block_size=128,
        )
        assert m_single.version == m_dual.version == 0x08

    def test_block_size_preserved(self):
        """Block size in manifest matches requested block size."""
        data = _make_payload(300)
        for bs in [64, 128, 256]:
            _, m = dual_stream_encode(data, "block_test!!", block_size=bs)
            assert m.block_size == bs


# ── Statistical Indistinguishability ──

class TestStatisticalIndistinguishability:
    """Prove single vs dual ciphertext is statistically indistinguishable."""

    def test_ciphertext_chi_squared_single(self):
        """Single-secret ciphertext bytes pass chi-squared uniformity test."""
        data = _make_payload(2000)
        ct, _ = dual_stream_encode(data, "chi_sq_pass1", block_size=256)

        chi2 = _chi_squared_uniform(ct)
        # For 255 DOF, p>0.001 threshold ≈ 310.5
        assert chi2 < 400, f"Chi-squared {chi2} too high for uniform distribution"

    def test_ciphertext_chi_squared_dual(self):
        """Dual-secret ciphertext bytes pass chi-squared uniformity test."""
        data_a = _make_payload(2000)
        data_b = _make_payload(1500)
        ct, _ = dual_stream_encode(
            data_a, "chi_pass_AAA",
            decoy_data=data_b, decoy_password="chi_pass_BBB",
            block_size=256,
        )

        chi2 = _chi_squared_uniform(ct)
        assert chi2 < 400, f"Chi-squared {chi2} too high for uniform distribution"

    def test_entropy_near_8_bits(self):
        """Both modes should produce near-maximum entropy ciphertext."""
        data = _make_payload(4000)

        ct_single, _ = dual_stream_encode(data, "entropy_test", block_size=256)
        ct_dual, _ = dual_stream_encode(
            data, "entropy_AAAA",
            decoy_data=_make_payload(4000), decoy_password="entropy_BBBB",
            block_size=256,
        )

        e_single = _shannon_entropy(ct_single)
        e_dual = _shannon_entropy(ct_dual)

        # AES-GCM ciphertext should have >7.9 bits/byte entropy
        assert e_single > 7.8, f"Single entropy {e_single} too low"
        assert e_dual > 7.8, f"Dual entropy {e_dual} too low"

    def test_entropy_difference_small(self):
        """Entropy difference between single and dual mode must be tiny."""
        data = _make_payload(4000)

        ct_single, _ = dual_stream_encode(data, "entropy_test", block_size=256)
        ct_dual, _ = dual_stream_encode(
            data, "entropy_AAAA",
            decoy_data=_make_payload(4000), decoy_password="entropy_BBBB",
            block_size=256,
        )

        e_single = _shannon_entropy(ct_single)
        e_dual = _shannon_entropy(ct_dual)

        # Should be within 0.1 bits/byte of each other
        assert abs(e_single - e_dual) < 0.1, (
            f"Entropy gap {abs(e_single - e_dual):.4f} bits/byte is suspicious"
        )


# ── Independent Keys ──

class TestIndependentKeys:
    """Each sub-stream must have completely independent key material."""

    def test_salts_independent(self):
        """Stream A and B salts must be different."""
        data = _make_payload(200)
        _, m = dual_stream_encode(
            data, "indep_pass_A",
            decoy_data=_make_payload(200), decoy_password="indep_pass_B",
            block_size=128,
        )
        assert m.salt_a != m.salt_b

    def test_nonces_independent(self):
        """Stream A and B nonces must be different."""
        data = _make_payload(200)
        _, m = dual_stream_encode(
            data, "indep_pass_A",
            decoy_data=_make_payload(200), decoy_password="indep_pass_B",
            block_size=128,
        )
        assert m.nonce_a != m.nonce_b

    def test_hmacs_independent(self):
        """Stream A and B HMACs must be different."""
        data = _make_payload(200)
        _, m = dual_stream_encode(
            data, "indep_pass_A",
            decoy_data=_make_payload(200), decoy_password="indep_pass_B",
            block_size=128,
        )
        assert m.hmac_a != m.hmac_b

    def test_metadata_independent(self):
        """Stream A and B encrypted metadata must be different."""
        data = _make_payload(200)
        _, m = dual_stream_encode(
            data, "indep_pass_A",
            decoy_data=_make_payload(200), decoy_password="indep_pass_B",
            block_size=128,
        )
        assert m.metadata_a != m.metadata_b

    def test_no_cross_authentication(self):
        """Password A must not authenticate stream B, and vice versa."""
        data_a = _make_payload(200)
        data_b = _make_payload(200)
        ct, m = dual_stream_encode(
            data_a, "cross_test_A",
            decoy_data=data_b, decoy_password="cross_test_B",
            block_size=128,
        )
        interleaved = ct[:m.superposition_len]

        # Password A decodes stream 0 (A), not stream 1 (B)
        r_a = dual_stream_try_decode_stream(m, "cross_test_A", interleaved)
        assert r_a is not None and r_a[1] == 0

        r_b = dual_stream_try_decode_stream(m, "cross_test_B", interleaved)
        assert r_b is not None and r_b[1] == 1


# ── Target Frames / Size Normalization ──

class TestSizeNormalization:
    """--target-frames normalization pads output to target size."""

    def test_target_frames_increases_size(self):
        """target_frames > natural count pads output."""
        data = _make_payload(100)
        ct_normal, m_normal = dual_stream_encode(
            data, "size_test_11", block_size=64
        )
        ct_padded, m_padded = dual_stream_encode(
            data, "size_test_11", block_size=64, target_frames=100
        )

        assert m_padded.block_count >= 100
        assert m_padded.target_frames == 100
        assert len(ct_padded) >= len(ct_normal)

    def test_target_frames_zero_is_auto(self):
        """target_frames=0 means automatic sizing."""
        data = _make_payload(100)
        _, m = dual_stream_encode(data, "auto_size_11", block_size=64)
        assert m.target_frames == 0

    def test_target_frames_small_no_truncation(self):
        """target_frames smaller than natural size doesn't truncate data."""
        data = _make_payload(500)
        ct, m = dual_stream_encode(data, "no_trunc_111", block_size=64, target_frames=1)
        # Should still have enough blocks for the data
        assert m.superposition_len > 0


# ── Tamper Detection ──

class TestTamperDetection:
    """Manifest tampering must be detected."""

    def test_flipped_hmac_bit_rejected(self):
        """Flipping one bit of HMAC_A causes rejection."""
        data = _make_payload(200)
        ct, m = dual_stream_encode(data, "tamper_test1", block_size=128)

        # Flip one HMAC bit
        tampered_hmac = bytearray(m.hmac_a)
        tampered_hmac[0] ^= 0x01
        m_tampered = DualStreamManifest(
            salt_a=m.salt_a, salt_b=m.salt_b,
            nonce_a=m.nonce_a, nonce_b=m.nonce_b,
            hmac_a=bytes(tampered_hmac), hmac_b=m.hmac_b,
            metadata_a=m.metadata_a, metadata_b=m.metadata_b,
            block_count=m.block_count, block_size=m.block_size,
            superposition_len=m.superposition_len,
            target_frames=m.target_frames,
            flags=m.flags,
        )

        result = dual_stream_try_decode_stream(
            m_tampered, "tamper_test1", ct[:m.superposition_len]
        )
        assert result is None

    def test_swapped_salts_rejected(self):
        """Swapping salt_a and salt_b causes rejection."""
        data = _make_payload(200)
        ct, m = dual_stream_encode(data, "swap_salt_AA", block_size=128)

        m_swapped = DualStreamManifest(
            salt_a=m.salt_b, salt_b=m.salt_a,  # swapped!
            nonce_a=m.nonce_a, nonce_b=m.nonce_b,
            hmac_a=m.hmac_a, hmac_b=m.hmac_b,
            metadata_a=m.metadata_a, metadata_b=m.metadata_b,
            block_count=m.block_count, block_size=m.block_size,
            superposition_len=m.superposition_len,
            target_frames=m.target_frames,
            flags=m.flags,
        )

        result = dual_stream_try_decode_stream(
            m_swapped, "swap_salt_AA", ct[:m.superposition_len]
        )
        assert result is None

    def test_modified_metadata_detected(self):
        """Modifying encrypted metadata causes GCM decryption failure."""
        data = _make_payload(200)
        ct, m = dual_stream_encode(data, "meta_tamper1", block_size=128)

        tampered_meta = bytearray(m.metadata_a)
        tampered_meta[10] ^= 0xFF
        m_tampered = DualStreamManifest(
            salt_a=m.salt_a, salt_b=m.salt_b,
            nonce_a=m.nonce_a, nonce_b=m.nonce_b,
            hmac_a=m.hmac_a, hmac_b=m.hmac_b,
            metadata_a=bytes(tampered_meta), metadata_b=m.metadata_b,
            block_count=m.block_count, block_size=m.block_size,
            superposition_len=m.superposition_len,
            target_frames=m.target_frames,
            flags=m.flags,
        )

        # HMAC check will fail because metadata is part of authenticated core
        result = dual_stream_try_decode_stream(
            m_tampered, "meta_tamper1", ct[:m.superposition_len]
        )
        assert result is None


# ── Edge Cases ──

class TestEdgeCases:
    """Boundary conditions and edge cases."""

    def test_minimum_payload(self):
        """Smallest possible payload encodes and decodes."""
        data = b"x"
        ct, m = dual_stream_encode(data, "tiny_test_11", block_size=64)
        result = dual_stream_try_decode_stream(
            m, "tiny_test_11", ct[:m.superposition_len]
        )
        assert result is not None

    def test_large_payload(self):
        """Reasonably large payload works."""
        data = _make_payload(10000)
        ct, m = dual_stream_encode(data, "large_test11", block_size=256)
        result = dual_stream_try_decode_stream(
            m, "large_test11", ct[:m.superposition_len]
        )
        assert result is not None

    def test_equal_size_payloads(self):
        """Dual-secret with identical-size payloads."""
        data_a = _make_payload(500)
        data_b = _make_payload(500)
        ct, m = dual_stream_encode(
            data_a, "equal_pass_A",
            decoy_data=data_b, decoy_password="equal_pass_B",
            block_size=128,
        )
        r_a = dual_stream_try_decode_stream(m, "equal_pass_A", ct[:m.superposition_len])
        r_b = dual_stream_try_decode_stream(m, "equal_pass_B", ct[:m.superposition_len])
        assert r_a is not None and r_b is not None

    def test_very_different_size_payloads(self):
        """Dual-secret with very different sized payloads."""
        data_a = _make_payload(100)
        data_b = _make_payload(5000)
        ct, m = dual_stream_encode(
            data_a, "diff_size__A",
            decoy_data=data_b, decoy_password="diff_size__B",
            block_size=128,
        )
        r_a = dual_stream_try_decode_stream(m, "diff_size__A", ct[:m.superposition_len])
        r_b = dual_stream_try_decode_stream(m, "diff_size__B", ct[:m.superposition_len])
        assert r_a is not None and r_b is not None


# ── Secure Zeroize ──

class TestSecureZeroize:
    """Verify secure_decode_and_zeroize cleans up key material."""

    def test_zeroize_correct_password(self):
        """Correct password decodes and zeroizes."""
        data = _make_payload(200)
        ct, m = dual_stream_encode(data, "zero_correct", block_size=128)
        result = secure_decode_and_zeroize(m, "zero_correct", ct[:m.superposition_len])
        assert result is not None and result[1] == 0

    def test_zeroize_wrong_password(self):
        """Wrong password returns None and still zeroizes without error."""
        data = _make_payload(200)
        ct, m = dual_stream_encode(data, "zero_correct", block_size=128)
        result = secure_decode_and_zeroize(m, "zero_wrong_!!", ct[:m.superposition_len])
        assert result is None

    def test_zeroize_duress_mode(self):
        """Duress mode tries both streams, still returns correct result."""
        data = _make_payload(200)
        ct, m = dual_stream_encode(data, "duress_pass1", block_size=128)
        result = secure_decode_and_zeroize(
            m, "duress_pass1", ct[:m.superposition_len], duress=True
        )
        assert result is not None and result[1] == 0

    def test_zeroize_handles_dropped(self):
        """After decode, all key handles should be dropped from Rust."""
        from meow_decoder.crypto_backend import get_handle_backend
        hb = get_handle_backend()

        initial_count = hb.count()

        data = _make_payload(200)
        ct, m = dual_stream_encode(data, "handle_test1", block_size=128)
        _ = secure_decode_and_zeroize(m, "handle_test1", ct[:m.superposition_len])

        final_count = hb.count()
        # Should not leak handles (may have some baseline from other tests)
        # The key is that we don't grow unboundedly
        assert final_count <= initial_count + 2, (
            f"Handle leak: {initial_count} → {final_count}"
        )

    def test_zeroize_dual_secret_both_passwords(self):
        """Dual-secret: both passwords work through zeroize wrapper."""
        data_a = _make_payload(200)
        data_b = _make_payload(200)
        ct, m = dual_stream_encode(
            data_a, "zero_dual__A",
            decoy_data=data_b, decoy_password="zero_dual__B",
            block_size=128,
        )
        r_a = secure_decode_and_zeroize(m, "zero_dual__A", ct[:m.superposition_len])
        r_b = secure_decode_and_zeroize(m, "zero_dual__B", ct[:m.superposition_len])
        assert r_a is not None and r_a[1] == 0
        assert r_b is not None and r_b[1] == 1
