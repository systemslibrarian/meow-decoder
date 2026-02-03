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


def test_pack_unpack_with_quantum_ciphertext():
    from meow_decoder.pq_crypto_real import pack_quantum_encapsulation, unpack_quantum_encapsulation
    from meow_decoder.pq_crypto_real import QuantumEncapsulation

    encap = QuantumEncapsulation(
        classical_ciphertext=secrets.token_bytes(32),
        quantum_ciphertext=b"Q" * 64,
        shared_secret=b"",
        variant="kyber1024",
    )

    packed = pack_quantum_encapsulation(encap)
    unpacked = unpack_quantum_encapsulation(packed)

    assert unpacked.variant == "kyber1024"
    assert unpacked.classical_ciphertext == encap.classical_ciphertext
    assert unpacked.quantum_ciphertext == b"Q" * 64


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


def test_quantum_encap_failure_falls_back_to_classical(monkeypatch):
    import meow_decoder.pq_crypto_real as pq

    class FailingEncapKEM:
        def __init__(self, variant, secret_key=None):
            self.variant = variant
            self.secret_key = secret_key

        def generate_keypair(self):
            return b"Q" * 64

        def export_secret_key(self):
            return b"S" * 64

        def encap_secret(self, public_key):
            raise RuntimeError("boom")

    monkeypatch.setattr(pq, "HAS_LIBOQS", True)
    monkeypatch.setattr(
        pq,
        "oqs",
        types.SimpleNamespace(KeyEncapsulation=FailingEncapKEM),
        raising=False,
    )

    qnl = pq.QuantumNineLives(variant="kyber768")
    keypair = qnl.generate_keypair()

    encap = qnl.encapsulate(keypair)
    assert encap.quantum_ciphertext is None
    assert len(encap.shared_secret) == 32


def test_quantum_decap_failure_falls_back_to_classical(monkeypatch):
    import meow_decoder.pq_crypto_real as pq
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization

    class FailingDecapKEM:
        def __init__(self, variant, secret_key=None):
            self.variant = variant
            self.secret_key = secret_key

        def decap_secret(self, ciphertext):
            raise RuntimeError("boom")

    monkeypatch.setattr(pq, "HAS_LIBOQS", True)
    monkeypatch.setattr(
        pq,
        "oqs",
        types.SimpleNamespace(KeyEncapsulation=FailingDecapKEM),
        raising=False,
    )

    receiver_priv = x25519.X25519PrivateKey.generate()
    receiver_pub = receiver_priv.public_key()

    receiver_pub_bytes = receiver_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    receiver_priv_bytes = receiver_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    keypair = pq.QuantumKeyPair(
        classical_public=receiver_pub_bytes,
        classical_secret=receiver_priv_bytes,
        quantum_public=b"Q" * 64,
        quantum_secret=b"S" * 64,
        kyber_variant="kyber768",
    )

    sender_priv = x25519.X25519PrivateKey.generate()
    sender_pub = sender_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    encap = pq.QuantumEncapsulation(
        classical_ciphertext=sender_pub,
        quantum_ciphertext=b"C" * 64,
        shared_secret=b"",
        variant="kyber768",
    )

    qnl = pq.QuantumNineLives(variant="kyber768")
    shared = qnl.decapsulate(keypair, encap)
    assert len(shared) == 32


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
