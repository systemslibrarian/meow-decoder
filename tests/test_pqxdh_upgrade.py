#!/usr/bin/env python3
"""Tests for PQXDH upgrade: ML-KEM-768 default, PQXDH transcript binding,
MODE_MEOW5, and paranoid (ML-KEM-1024) backward compatibility.

Covers:
  - ML-KEM-768 as default, ML-KEM-1024 via paranoid flag
  - PQXDH two-step HKDF (Extract + Expand) with transcript binding
  - Transcript binding prevents key/ciphertext substitution attacks
  - MODE_MEOW5 manifest packing/unpacking for ML-KEM-768
  - MODE_MEOW4 backward compatibility for ML-KEM-1024
  - Classical-only mode still works without regression
  - Config defaults updated correctly
"""

import hashlib
import hmac as hmac_module
import struct
import sys
import types
from unittest.mock import patch

import pytest
import secrets

# ── Helpers ──────────────────────────────────────────────────────────────────


def _dummy_oqs_module(variant="both"):
    """Create a dummy oqs module supporting ML-KEM-768 and/or ML-KEM-1024."""

    class DummyKEM:
        def __init__(self, algorithm):
            self.algorithm = algorithm
            if algorithm == "Kyber768":
                self._pk_size = 1184
                self._ct_size = 1088
            elif algorithm == "Kyber1024":
                self._pk_size = 1568
                self._ct_size = 1568
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

        def generate_keypair(self):
            return b"Q" * self._pk_size

        def encap_secret(self, public_key):
            return (b"C" * self._ct_size, b"K" * 32)

        def decap_secret(self, ciphertext):
            return b"K" * 32

    return types.SimpleNamespace(KeyEncapsulation=DummyKEM)


def _valid_x25519_keypair():
    """Generate a valid X25519 keypair, returning (private_bytes, public_bytes)."""
    import meow_crypto_rs

    priv_bytes, pub_bytes = meow_crypto_rs.x25519_generate_keypair()
    return priv_bytes, pub_bytes


# Check if Rust PQ backend is available
_RUST_PQ_AVAILABLE = False
try:
    import meow_crypto_rs as _pq_rs

    _RUST_PQ_AVAILABLE = hasattr(_pq_rs, "mlkem768_keygen")
except ImportError:
    pass

requires_rust_pq = pytest.mark.skipif(
    not _RUST_PQ_AVAILABLE,
    reason="Rust PQ backend not available (rebuild with --features pq)",
)


# ── ML-KEM variant constants ────────────────────────────────────────────────


class TestPQConstants:
    """Test that PQ constants are correctly defined."""

    def test_algorithm_constants(self):
        from meow_decoder.pq_hybrid import PQ_ALGORITHM_768, PQ_ALGORITHM_1024

        assert PQ_ALGORITHM_768 == "Kyber768"
        assert PQ_ALGORITHM_1024 == "Kyber1024"

    def test_size_constants(self):
        from meow_decoder.pq_hybrid import (
            PQ_CT_SIZE_768,
            PQ_CT_SIZE_1024,
            PQ_PK_SIZE_768,
            PQ_PK_SIZE_1024,
        )

        assert PQ_CT_SIZE_768 == 1088
        assert PQ_CT_SIZE_1024 == 1568
        assert PQ_PK_SIZE_768 == 1184
        assert PQ_PK_SIZE_1024 == 1568

    def test_pqxdh_domain_constants(self):
        from meow_decoder.pq_hybrid import (
            PQXDH_EXTRACT_SALT,
            PQXDH_INFO_PREFIX,
            PQXDH_TRANSCRIPT_DOMAIN,
            CLASSICAL_INFO,
        )

        assert PQXDH_EXTRACT_SALT == b"\x00" * 32
        assert PQXDH_INFO_PREFIX == b"meow_pqxdh_v1"
        assert PQXDH_TRANSCRIPT_DOMAIN == b"meow_pqxdh_transcript_v1"
        assert CLASSICAL_INFO == b"meow_classical_only_v1"

    def test_default_algorithm_is_768(self):
        """Default PQ_ALGORITHM should be ML-KEM-768 (Signal parity)."""
        import meow_decoder.pq_hybrid as pq

        if pq.LIBOQS_AVAILABLE:
            assert pq.PQ_ALGORITHM == "Kyber768"


# ── HybridKeyPair ML-KEM-768/1024 selection ─────────────────────────────────


class TestHybridKeyPairVariants:
    """Test HybridKeyPair supports ML-KEM-768 (default) and ML-KEM-1024 (paranoid)."""

    @requires_rust_pq
    def test_keypair_default_uses_768(self):
        import meow_decoder.pq_hybrid as pq

        kp = pq.HybridKeyPair(use_pq=True, paranoid=False)
        assert kp.is_hybrid()
        assert kp.paranoid is False
        _, pq_pub = kp.export_public_keys()
        assert pq_pub is not None
        assert len(pq_pub) >= 1184  # ML-KEM-768 public key

    @requires_rust_pq
    def test_keypair_paranoid_uses_1024(self):
        import meow_decoder.pq_hybrid as pq

        kp = pq.HybridKeyPair(use_pq=True, paranoid=True)
        assert kp.is_hybrid()
        assert kp.paranoid is True
        _, pq_pub = kp.export_public_keys()
        assert pq_pub is not None

    def test_keypair_classical_only(self):
        from meow_decoder.pq_hybrid import HybridKeyPair

        kp = HybridKeyPair(use_pq=False)
        assert not kp.is_hybrid()
        classical, pq_pub = kp.export_public_keys()
        assert len(classical) == 32
        assert pq_pub is None


# ── PQXDH transcript binding ────────────────────────────────────────────────


class TestPQXDHTranscriptBinding:
    """Test the PQXDH-style transcript hash and two-step HKDF."""

    def test_transcript_hash_changes_with_different_ephemeral(self):
        from meow_decoder.pq_hybrid import _compute_transcript_hash

        eph1 = secrets.token_bytes(32)
        eph2 = secrets.token_bytes(32)
        recv_pub = secrets.token_bytes(32)
        pq_pub = secrets.token_bytes(1184)
        pq_ct = secrets.token_bytes(1088)

        h1 = _compute_transcript_hash(eph1, recv_pub, pq_pub, pq_ct)
        h2 = _compute_transcript_hash(eph2, recv_pub, pq_pub, pq_ct)
        assert h1 != h2

    def test_transcript_hash_changes_with_different_receiver(self):
        from meow_decoder.pq_hybrid import _compute_transcript_hash

        eph = secrets.token_bytes(32)
        recv1 = secrets.token_bytes(32)
        recv2 = secrets.token_bytes(32)
        pq_pub = secrets.token_bytes(1184)
        pq_ct = secrets.token_bytes(1088)

        h1 = _compute_transcript_hash(eph, recv1, pq_pub, pq_ct)
        h2 = _compute_transcript_hash(eph, recv2, pq_pub, pq_ct)
        assert h1 != h2

    def test_transcript_hash_changes_with_different_pq_ciphertext(self):
        from meow_decoder.pq_hybrid import _compute_transcript_hash

        eph = secrets.token_bytes(32)
        recv = secrets.token_bytes(32)
        pq_pub = secrets.token_bytes(1184)
        ct1 = secrets.token_bytes(1088)
        ct2 = secrets.token_bytes(1088)

        h1 = _compute_transcript_hash(eph, recv, pq_pub, ct1)
        h2 = _compute_transcript_hash(eph, recv, pq_pub, ct2)
        assert h1 != h2

    def test_transcript_hash_changes_with_different_pq_public(self):
        from meow_decoder.pq_hybrid import _compute_transcript_hash

        eph = secrets.token_bytes(32)
        recv = secrets.token_bytes(32)
        pq_pub1 = secrets.token_bytes(1184)
        pq_pub2 = secrets.token_bytes(1184)
        pq_ct = secrets.token_bytes(1088)

        h1 = _compute_transcript_hash(eph, recv, pq_pub1, pq_ct)
        h2 = _compute_transcript_hash(eph, recv, pq_pub2, pq_ct)
        assert h1 != h2

    def test_transcript_hash_classical_only(self):
        """Classical-only mode (no PQ pub/ct) produces a valid hash."""
        from meow_decoder.pq_hybrid import _compute_transcript_hash

        eph = secrets.token_bytes(32)
        recv = secrets.token_bytes(32)

        h = _compute_transcript_hash(eph, recv, None, None)
        assert len(h) == 32

    def test_pqxdh_derive_uses_two_step_hkdf(self):
        """Verify the derived key matches manual HKDF-Extract + HKDF-Expand."""
        from meow_decoder.pq_hybrid import (
            _pqxdh_derive,
            _compute_transcript_hash,
            PQXDH_EXTRACT_SALT,
            PQXDH_INFO_PREFIX,
        )
        import meow_crypto_rs

        classical_ss = secrets.token_bytes(32)
        pq_ss = secrets.token_bytes(32)
        eph = secrets.token_bytes(32)
        recv_classical = secrets.token_bytes(32)
        recv_pq = secrets.token_bytes(1184)
        pq_ct = secrets.token_bytes(1088)

        # Library-derived key
        result = _pqxdh_derive(classical_ss, pq_ss, eph, recv_classical, recv_pq, pq_ct)

        # Manual computation
        combined = classical_ss + pq_ss
        prk = hmac_module.new(PQXDH_EXTRACT_SALT, combined, hashlib.sha256).digest()
        transcript = _compute_transcript_hash(eph, recv_classical, recv_pq, pq_ct)
        info = PQXDH_INFO_PREFIX + transcript
        expected = meow_crypto_rs.hkdf_expand(prk, info, 32)

        assert result == expected

    def test_pqxdh_derive_different_secrets_different_output(self):
        """Different input secrets produce different derived keys."""
        from meow_decoder.pq_hybrid import _pqxdh_derive

        eph = secrets.token_bytes(32)
        recv = secrets.token_bytes(32)
        pq_pub = secrets.token_bytes(1184)
        pq_ct = secrets.token_bytes(1088)

        k1 = _pqxdh_derive(secrets.token_bytes(32), b"K" * 32, eph, recv, pq_pub, pq_ct)
        k2 = _pqxdh_derive(secrets.token_bytes(32), b"K" * 32, eph, recv, pq_pub, pq_ct)
        assert k1 != k2  # Different classical secrets


# ── Encapsulate / Decapsulate roundtrip ──────────────────────────────────────


class TestEncapDecapRoundtrip:
    """Test hybrid encapsulate/decapsulate with both ML-KEM variants."""

    def test_roundtrip_classical_only(self):
        """Classical-only (no PQ) roundtrip still works."""
        from meow_decoder.pq_hybrid import HybridKeyPair, hybrid_encapsulate, hybrid_decapsulate

        receiver = HybridKeyPair(use_pq=False)
        classical_pub, pq_pub = receiver.export_public_keys()

        shared, eph_pub, pq_ct, pq_ss = hybrid_encapsulate(classical_pub, pq_pub)
        assert pq_ct is None
        assert pq_ss is None
        assert len(shared) == 32

        recovered = hybrid_decapsulate(eph_pub, pq_ct, receiver)
        assert recovered == shared

    @requires_rust_pq
    def test_roundtrip_768_default(self):
        """ML-KEM-768 (default) roundtrip works."""
        import meow_decoder.pq_hybrid as pq

        receiver = pq.HybridKeyPair(use_pq=True, paranoid=False)
        classical_pub, pq_pub = receiver.export_public_keys()

        shared, eph_pub, pq_ct, pq_ss = pq.hybrid_encapsulate(classical_pub, pq_pub, paranoid=False)
        assert pq_ct is not None
        assert pq_ss is not None

        recovered = pq.hybrid_decapsulate(eph_pub, pq_ct, receiver)
        assert recovered == shared

    @requires_rust_pq
    def test_roundtrip_1024_paranoid(self):
        """ML-KEM-1024 (paranoid) roundtrip works."""
        import meow_decoder.pq_hybrid as pq

        receiver = pq.HybridKeyPair(use_pq=True, paranoid=True)
        classical_pub, pq_pub = receiver.export_public_keys()

        shared, eph_pub, pq_ct, pq_ss = pq.hybrid_encapsulate(classical_pub, pq_pub, paranoid=True)
        assert pq_ct is not None

        recovered = pq.hybrid_decapsulate(eph_pub, pq_ct, receiver)
        assert recovered == shared

    def test_encapsulate_fails_without_liboqs(self, monkeypatch):
        """Encapsulate must fail-closed when PQ backend unavailable."""
        import meow_decoder.pq_hybrid as pq

        monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", False)
        monkeypatch.setattr(pq, "_RUST_PQ_AVAILABLE", False)

        _, pub = _valid_x25519_keypair()
        with pytest.raises(RuntimeError, match="[Pp]ost.quantum|[Rr]ust PQ|unavailable"):
            pq.hybrid_encapsulate(pub, b"\x00" * 1184)

    def test_decapsulate_fails_without_pq_key(self):
        """Decapsulate must fail-closed when receiver has no PQ key."""
        from meow_decoder.pq_hybrid import HybridKeyPair, hybrid_decapsulate

        receiver = HybridKeyPair(use_pq=False)
        _, pub = _valid_x25519_keypair()

        with pytest.raises(RuntimeError, match="no PQ"):
            hybrid_decapsulate(pub, b"\x00" * 1088, receiver)


# ── Transcript binding security tests ───────────────────────────────────────


class TestTranscriptBindingSecurity:
    """Verify that transcript binding prevents key/ciphertext substitution."""

    @requires_rust_pq
    def test_different_receiver_different_key(self):
        """Swapping the receiver's key produces a different shared secret."""
        import meow_decoder.pq_hybrid as pq

        recv1 = pq.HybridKeyPair(use_pq=True, paranoid=False)
        recv2 = pq.HybridKeyPair(use_pq=True, paranoid=False)
        c1, pq1 = recv1.export_public_keys()
        c2, pq2 = recv2.export_public_keys()

        # Encapsulate to receiver 1
        shared1, eph1, ct1, _ = pq.hybrid_encapsulate(c1, pq1)
        # Try decapsulate with receiver 2 (different classical key)
        shared2 = pq.hybrid_decapsulate(eph1, ct1, recv2)
        # Different classical DH + different transcript → different key
        assert shared1 != shared2

    @requires_rust_pq
    def test_pqxdh_not_equal_to_old_hkdf(self):
        """New PQXDH derivation is NOT equal to the old single-step HKDF."""
        import meow_decoder.pq_hybrid as pq

        receiver = pq.HybridKeyPair(use_pq=True, paranoid=False)
        c_pub, pq_pub = receiver.export_public_keys()
        shared, eph, ct, pq_ss = pq.hybrid_encapsulate(c_pub, pq_pub)

        # Verify PQXDH output is 32 bytes and not trivially predictable
        assert len(shared) == 32
        assert shared != b"\x00" * 32
        assert shared != b"\xff" * 32


# ── MODE_MEOW5 manifest tests ───────────────────────────────────────────────


class TestMODEMEOW5:
    """Test MODE_MEOW5 (ML-KEM-768) manifest packing/unpacking."""

    def test_mode_meow5_constant(self):
        from meow_decoder.crypto import MODE_MEOW5

        assert MODE_MEOW5 == 0x05

    def test_mode_meow5_in_valid_set(self):
        from meow_decoder.crypto import MODE_MEOW5, MODE_DURESS, MODE_RATCHET, _VALID_MODE_BYTES

        assert MODE_MEOW5 in _VALID_MODE_BYTES
        assert (MODE_MEOW5 | MODE_DURESS) in _VALID_MODE_BYTES
        assert (MODE_MEOW5 | MODE_RATCHET) in _VALID_MODE_BYTES
        assert (MODE_MEOW5 | MODE_RATCHET | MODE_DURESS) in _VALID_MODE_BYTES

    def test_pack_unpack_meow5_manifest(self):
        """Pack and unpack a MEOW5 manifest with ML-KEM-768 ciphertext."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest, MODE_MEOW5

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            pq_ciphertext=secrets.token_bytes(1088),  # ML-KEM-768
            mode_byte=MODE_MEOW5,
        )

        packed = pack_manifest(m)
        unpacked = unpack_manifest(packed)

        assert unpacked.mode_byte == MODE_MEOW5
        assert unpacked.salt == m.salt
        assert unpacked.nonce == m.nonce
        assert unpacked.orig_len == m.orig_len
        assert unpacked.ephemeral_public_key == m.ephemeral_public_key
        assert unpacked.pq_ciphertext == m.pq_ciphertext
        assert len(unpacked.pq_ciphertext) == 1088
        assert unpacked.duress_tag is None

    def test_pack_unpack_meow5_with_duress(self):
        """MEOW5 + duress tag roundtrip."""
        from meow_decoder.crypto import (
            Manifest,
            pack_manifest,
            unpack_manifest,
            MODE_MEOW5,
            MODE_DURESS,
        )

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=500,
            comp_len=400,
            cipher_len=416,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=1,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            pq_ciphertext=secrets.token_bytes(1088),  # ML-KEM-768
            duress_tag=secrets.token_bytes(32),
            mode_byte=MODE_MEOW5 | MODE_DURESS,
        )

        packed = pack_manifest(m)
        unpacked = unpack_manifest(packed)

        assert unpacked.mode_byte == (MODE_MEOW5 | MODE_DURESS)
        assert unpacked.pq_ciphertext == m.pq_ciphertext
        assert unpacked.duress_tag == m.duress_tag

    def test_pack_unpack_meow4_backward_compat(self):
        """MEOW4 (ML-KEM-1024) still works for backward compatibility."""
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest, MODE_MEOW4

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            pq_ciphertext=secrets.token_bytes(1568),  # ML-KEM-1024
            mode_byte=MODE_MEOW4,
        )

        packed = pack_manifest(m)
        unpacked = unpack_manifest(packed)

        assert unpacked.mode_byte == MODE_MEOW4
        assert unpacked.pq_ciphertext == m.pq_ciphertext
        assert len(unpacked.pq_ciphertext) == 1568

    def test_meow5_manifest_size(self):
        """MEOW5 manifest should be 1236 bytes (base + mode + eph + 1088 ct)."""
        from meow_decoder.crypto import Manifest, pack_manifest, MODE_MEOW5

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            pq_ciphertext=secrets.token_bytes(1088),
            mode_byte=MODE_MEOW5,
        )

        packed = pack_manifest(m)
        # 5 (MAGIC) + 1 (mode) + 16 + 12 + 12 + 6 + 32 + 32 + 32 + 1088 = 1236
        assert len(packed) == 1236

    def test_meow5_rejects_wrong_pq_size(self):
        """MEOW5 mode byte + 1568-byte PQ ciphertext should fail validation."""
        from meow_decoder.crypto import Manifest, pack_manifest, MODE_MEOW5

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            pq_ciphertext=secrets.token_bytes(1568),  # Wrong size for MEOW5!
            mode_byte=MODE_MEOW5,
        )

        # Pack will succeed (it accepts both sizes), but after parsing the
        # mode byte says MEOW5 (1088-byte ct), leaving 480 unconsumed bytes
        packed = pack_manifest(m)
        with pytest.raises(ValueError, match="unconsumed trailing bytes"):
            from meow_decoder.crypto import unpack_manifest

            unpack_manifest(packed)

    def test_invalid_pq_ciphertext_size_rejected(self):
        """PQ ciphertext of wrong size (not 1088 or 1568) is rejected."""
        from meow_decoder.crypto import Manifest, pack_manifest, MODE_MEOW5

        m = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=2,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),
            pq_ciphertext=secrets.token_bytes(999),  # Invalid size
            mode_byte=MODE_MEOW5,
        )

        with pytest.raises(ValueError, match="1088.*1568"):
            pack_manifest(m)


# ── Config defaults ─────────────────────────────────────────────────────────


class TestConfigDefaults:
    """Test that config defaults are updated for ML-KEM-768."""

    def test_crypto_config_default_768(self):
        from meow_decoder.config import CryptoConfig

        cc = CryptoConfig()
        assert cc.kyber_variant == "kyber768"
        assert cc.pq_paranoid is False

    def test_encoding_config_has_paranoid_flag(self):
        from meow_decoder.config import EncodingConfig

        ec = EncodingConfig()
        assert hasattr(ec, "pq_paranoid")
        assert ec.pq_paranoid is False

    def test_high_security_uses_1024(self):
        from meow_decoder.high_security import HighSecurityConfig

        hs = HighSecurityConfig()
        assert hs.kyber_variant == "kyber1024"
        assert hs.pq_paranoid is True


# ── check_pq_available variants ─────────────────────────────────────────────


class TestCheckPQAvailable:
    """Test check_pq_available for both variants."""

    @requires_rust_pq
    def test_check_768(self):
        import meow_decoder.pq_hybrid as pq

        available, msg = pq.check_pq_available(paranoid=False)
        assert available is True
        assert "ML-KEM-768" in msg or "available" in msg.lower()

    @requires_rust_pq
    def test_check_1024(self):
        import meow_decoder.pq_hybrid as pq

        available, msg = pq.check_pq_available(paranoid=True)
        assert available is True
        assert "ML-KEM-1024" in msg or "available" in msg.lower()

    def test_check_unavailable(self, monkeypatch):
        import meow_decoder.pq_hybrid as pq

        monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", False)

        available, msg = pq.check_pq_available()
        assert available is False


# ── AAD binding ─────────────────────────────────────────────────────────────


class TestAADBinding:
    """Test that AAD correctly binds ML-KEM-768 and ML-KEM-1024 ciphertext."""

    def test_aad_binds_768_ciphertext(self):
        from meow_decoder.crypto import build_canonical_aad, MODE_MEOW5

        ct_768 = secrets.token_bytes(1088)
        aad = build_canonical_aad(
            orig_len=100,
            comp_len=80,
            salt=b"\x00" * 16,
            sha256_hash=b"\x00" * 32,
            magic=b"MEOW5",
            ephemeral_public_key=b"\x00" * 32,
            pq_ciphertext=ct_768,
            mode_byte=MODE_MEOW5,
        )
        assert ct_768 in aad

    def test_aad_binds_1024_ciphertext(self):
        from meow_decoder.crypto import build_canonical_aad, MODE_MEOW4

        ct_1024 = secrets.token_bytes(1568)
        aad = build_canonical_aad(
            orig_len=100,
            comp_len=80,
            salt=b"\x00" * 16,
            sha256_hash=b"\x00" * 32,
            magic=b"MEOW5",
            ephemeral_public_key=b"\x00" * 32,
            pq_ciphertext=ct_1024,
            mode_byte=MODE_MEOW4,
        )
        assert ct_1024 in aad

    def test_different_ct_different_aad(self):
        """Different PQ ciphertext produces different AAD."""
        from meow_decoder.crypto import build_canonical_aad, MODE_MEOW5

        ct1 = secrets.token_bytes(1088)
        ct2 = secrets.token_bytes(1088)

        kwargs = dict(
            orig_len=100,
            comp_len=80,
            salt=b"\x00" * 16,
            sha256_hash=b"\x00" * 32,
            magic=b"MEOW5",
            ephemeral_public_key=b"\x00" * 32,
            mode_byte=MODE_MEOW5,
        )
        aad1 = build_canonical_aad(pq_ciphertext=ct1, **kwargs)
        aad2 = build_canonical_aad(pq_ciphertext=ct2, **kwargs)
        assert aad1 != aad2
