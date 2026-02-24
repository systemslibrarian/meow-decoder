#!/usr/bin/env python3
"""Tests for meow_decoder.pq_hybrid.
Covers classical-only and Rust PQ backend behavior.

After AUDIT-C1: Python oqs is FORBIDDEN. PQ MUST use Rust backend.
Tests that require Rust PQ are skipped if mlkem768_keygen is not available.
"""

import runpy
import sys
import types

import pytest

pytestmark = pytest.mark.security
import secrets

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


def _valid_x25519_public_key_bytes() -> bytes:
    import meow_crypto_rs

    _, pub_bytes = meow_crypto_rs.x25519_generate_keypair()
    return pub_bytes


def test_check_pq_available_false(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", False)
    monkeypatch.setattr(pq, "_RUST_PQ_AVAILABLE", False)
    monkeypatch.setattr(pq, "PQ_ALGORITHM", None)

    available, msg = pq.check_pq_available()
    assert available is False
    assert "not available" in msg.lower()


@requires_rust_pq
def test_check_pq_available_true():
    import meow_decoder.pq_hybrid as pq

    available, msg = pq.check_pq_available()
    assert available is True
    assert "available" in msg.lower()


def test_hybrid_keypair_classical_only():
    from meow_decoder.pq_hybrid import HybridKeyPair

    keypair = HybridKeyPair(use_pq=False)
    classical_pub, pq_pub = keypair.export_public_keys()

    assert len(classical_pub) == 32
    assert pq_pub is None
    assert keypair.is_hybrid() is False


@requires_rust_pq
def test_hybrid_keypair_pq_success():
    import meow_decoder.pq_hybrid as pq

    keypair = pq.HybridKeyPair(use_pq=True)
    assert keypair.is_hybrid() is True
    classical_pub, pq_pub = keypair.export_public_keys()
    assert len(classical_pub) == 32
    assert pq_pub is not None
    assert len(pq_pub) >= 1184  # ML-KEM-768 public key


def test_hybrid_encapsulate_classical_roundtrip():
    from meow_decoder.pq_hybrid import HybridKeyPair, hybrid_encapsulate, hybrid_decapsulate

    receiver = HybridKeyPair(use_pq=False)
    classical_pub, pq_pub = receiver.export_public_keys()

    shared, eph_pub, pq_ct, pq_ss = hybrid_encapsulate(classical_pub, pq_pub)
    assert pq_ct is None
    assert pq_ss is None

    recovered = hybrid_decapsulate(eph_pub, pq_ct, receiver)
    assert recovered == shared


def test_hybrid_encapsulate_fails_if_pq_requested_but_unavailable(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", False)
    monkeypatch.setattr(pq, "_RUST_PQ_AVAILABLE", False)

    with pytest.raises(RuntimeError, match="[Pp]ost.quantum|[Rr]ust PQ"):
        pq.hybrid_encapsulate(
            receiver_classical_public=_valid_x25519_public_key_bytes(),
            receiver_pq_public=b"\x00" * 1568,
        )


def test_hybrid_decapsulate_fails_if_pq_ciphertext_without_pq_key():
    from meow_decoder.pq_hybrid import HybridKeyPair, hybrid_decapsulate

    receiver = HybridKeyPair(use_pq=False)

    with pytest.raises(RuntimeError, match="no PQ"):
        hybrid_decapsulate(
            ephemeral_classical_public=_valid_x25519_public_key_bytes(),
            pq_ciphertext=b"\x00" * 1568,
            receiver_keypair=receiver,
        )


@requires_rust_pq
def test_hybrid_decapsulate_pq_kem_implicit_rejection():
    """ML-KEM uses implicit rejection (FIPS 203 FO transform).

    A tampered ciphertext of the correct length does NOT raise an error;
    instead it decapsulates to a pseudorandom shared secret that differs
    from the legitimate one.  Protocol-level authentication (AES-GCM)
    catches this mismatch — this is the correct security behaviour.
    """
    import meow_decoder.pq_hybrid as pq

    receiver = pq.HybridKeyPair(use_pq=True)
    classical_pub, pq_pub = receiver.export_public_keys()
    legit_ss, eph_pub, pq_ct, _ = pq.hybrid_encapsulate(classical_pub, pq_pub)

    # Corrupt the PQ ciphertext (correct length → implicit rejection)
    corrupted_ct = bytes(len(pq_ct))
    tampered_ss = pq.hybrid_decapsulate(eph_pub, corrupted_ct, receiver)

    # Shared secret MUST differ — proves tampering is detectable
    assert tampered_ss != legit_ss, "Corrupted PQ ciphertext must yield different shared secret"


@requires_rust_pq
def test_hybrid_decapsulate_pq_wrong_length():
    """Wrong-length PQ ciphertext must raise RuntimeError."""
    import meow_decoder.pq_hybrid as pq

    receiver = pq.HybridKeyPair(use_pq=True)
    classical_pub, pq_pub = receiver.export_public_keys()
    _, eph_pub, pq_ct, _ = pq.hybrid_encapsulate(classical_pub, pq_pub)

    # Wrong length ciphertext triggers hard error
    wrong_length_ct = b"\x00" * 42
    with pytest.raises(RuntimeError, match="decapsulation failed|InvalidMlKem"):
        pq.hybrid_decapsulate(eph_pub, wrong_length_ct, receiver)


@requires_rust_pq
def test_hybrid_encapsulate_pq_kem_error():
    """Encapsulation with invalid PQ public key should fail."""
    import meow_decoder.pq_hybrid as pq

    with pytest.raises(RuntimeError, match="encapsulation failed|[Pp]ost.quantum"):
        pq.hybrid_encapsulate(
            receiver_classical_public=_valid_x25519_public_key_bytes(),
            receiver_pq_public=b"\x00" * 10,  # Invalid PQ public key
        )


def test_check_pq_available_not_available(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", False)
    monkeypatch.setattr(pq, "_RUST_PQ_AVAILABLE", False)

    available, msg = pq.check_pq_available()
    assert available is False
    assert "not available" in msg.lower()


def test_hybrid_keypair_pq_fails_without_rust_pq(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", False)
    monkeypatch.setattr(pq, "_RUST_PQ_AVAILABLE", False)
    monkeypatch.setattr(pq, "PRODUCTION_MODE", True)

    with pytest.raises(RuntimeError, match="[Pp]Q|[Rr]ust"):
        pq.HybridKeyPair(use_pq=True)


@requires_rust_pq
def test_hybrid_encapsulate_decapsulate_roundtrip():
    import meow_decoder.pq_hybrid as pq

    receiver = pq.HybridKeyPair(use_pq=True)
    classical_pub, pq_pub = receiver.export_public_keys()

    shared, eph_pub, pq_ct, pq_ss = pq.hybrid_encapsulate(classical_pub, pq_pub)
    assert pq_ct is not None
    assert pq_ss is not None

    recovered = pq.hybrid_decapsulate(eph_pub, pq_ct, receiver)
    assert recovered == shared


def test_pq_hybrid_main_runs(monkeypatch):
    import meow_decoder.security_warnings as warnings_mod

    monkeypatch.setattr(warnings_mod, "warn_pq_experimental", lambda: None)

    runpy.run_module("meow_decoder.pq_hybrid", run_name="__main__")
