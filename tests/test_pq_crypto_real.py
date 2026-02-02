#!/usr/bin/env python3
"""Tests for meow_decoder.pq_crypto_real.
Targets classical-only path and stubbed PQ flows.
"""

import types

import pytest
import secrets


def _dummy_oqs_module():
    class DummyKEM:
        def __init__(self, variant, secret_key=None):
            self.variant = variant
            self.secret_key = secret_key

        def generate_keypair(self):
            return b"Q" * 64

        def export_secret_key(self):
            return b"S" * 64

        def encap_secret(self, public_key):
            return (b"C" * 64, b"K" * 32)

        def decap_secret(self, ciphertext):
            return b"K" * 32

    return types.SimpleNamespace(KeyEncapsulation=DummyKEM)


def test_invalid_variant_raises():
    from meow_decoder.pq_crypto_real import QuantumNineLives

    with pytest.raises(ValueError, match="Unknown variant"):
        QuantumNineLives(variant="kyber999")


def test_keypair_classical_only_when_liboqs_missing(monkeypatch):
    import meow_decoder.pq_crypto_real as pq

    monkeypatch.setattr(pq, "HAS_LIBOQS", False)

    qnl = pq.QuantumNineLives(variant="kyber768")
    keypair = qnl.generate_keypair()

    assert keypair.classical_public is not None
    assert keypair.classical_secret is not None
    assert keypair.quantum_public is None
    assert keypair.quantum_secret is None
    assert keypair.kyber_variant == "kyber768"


def test_classical_encapsulate_decapsulate_roundtrip(monkeypatch):
    import meow_decoder.pq_crypto_real as pq

    monkeypatch.setattr(pq, "HAS_LIBOQS", False)

    qnl = pq.QuantumNineLives(variant="kyber512")
    keypair = qnl.generate_keypair()

    encap = qnl.encapsulate(keypair)
    assert encap.quantum_ciphertext is None
    assert len(encap.shared_secret) == 32

    recovered = qnl.decapsulate(keypair, encap)
    assert recovered == encap.shared_secret


def test_pack_unpack_without_quantum_ciphertext():
    from meow_decoder.pq_crypto_real import pack_quantum_encapsulation, unpack_quantum_encapsulation
    from meow_decoder.pq_crypto_real import QuantumEncapsulation

    encap = QuantumEncapsulation(
        classical_ciphertext=secrets.token_bytes(32),
        quantum_ciphertext=None,
        shared_secret=b"",
        variant="kyber768",
    )

    packed = pack_quantum_encapsulation(encap)
    unpacked = unpack_quantum_encapsulation(packed)

    assert unpacked.variant == "kyber768"
    assert unpacked.classical_ciphertext == encap.classical_ciphertext
    assert unpacked.quantum_ciphertext is None


def test_unpack_wrong_version_raises():
    from meow_decoder.pq_crypto_real import unpack_quantum_encapsulation

    with pytest.raises(ValueError, match="Wrong version"):
        unpack_quantum_encapsulation(b"\x03")


def test_quantum_keygen_failure_disables_quantum(monkeypatch):
    import meow_decoder.pq_crypto_real as pq

    class FailingKEM:
        def __init__(self, variant, secret_key=None):
            self.variant = variant

        def generate_keypair(self):
            raise RuntimeError("boom")

        def export_secret_key(self):
            return b"S" * 64

    monkeypatch.setattr(pq, "HAS_LIBOQS", True)
    monkeypatch.setattr(
        pq,
        "oqs",
        types.SimpleNamespace(KeyEncapsulation=FailingKEM),
        raising=False,
    )

    qnl = pq.QuantumNineLives(variant="kyber768")
    keypair = qnl.generate_keypair()

    assert qnl.has_quantum is False
    assert keypair.quantum_public is None
    assert keypair.quantum_secret is None


def test_quantum_stubbed_encap_decap_roundtrip(monkeypatch):
    import meow_decoder.pq_crypto_real as pq

    monkeypatch.setattr(pq, "HAS_LIBOQS", True)
    monkeypatch.setattr(pq, "oqs", _dummy_oqs_module(), raising=False)

    qnl = pq.QuantumNineLives(variant="kyber1024")

    keypair = qnl.generate_keypair()
    assert keypair.quantum_public is not None
    assert keypair.quantum_secret is not None

    encap = qnl.encapsulate(keypair)
    assert encap.quantum_ciphertext == b"C" * 64

    recovered = qnl.decapsulate(keypair, encap)
    assert recovered == encap.shared_secret
