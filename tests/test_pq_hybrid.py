#!/usr/bin/env python3
"""Tests for meow_decoder.pq_hybrid.
Covers classical-only and stubbed PQ behavior.
"""

import types

import pytest
import secrets


def _dummy_oqs_module():
    class DummyKEM:
        def __init__(self, variant):
            self.variant = variant

        def generate_keypair(self):
            return b"Q" * 1568

        def encap_secret(self, public_key):
            return (b"C" * 1568, b"K" * 32)

        def decap_secret(self, ciphertext):
            return b"K" * 32

    return types.SimpleNamespace(KeyEncapsulation=DummyKEM)


def _valid_x25519_public_key_bytes() -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_check_pq_available_false(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", False)
    monkeypatch.setattr(pq, "PQ_ALGORITHM", None)

    available, msg = pq.check_pq_available()
    assert available is False
    assert "liboqs" in msg.lower()


def test_hybrid_keypair_classical_only():
    from meow_decoder.pq_hybrid import HybridKeyPair

    keypair = HybridKeyPair(use_pq=False)
    classical_pub, pq_pub = keypair.export_public_keys()

    assert len(classical_pub) == 32
    assert pq_pub is None
    assert keypair.is_hybrid() is False


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

    with pytest.raises(RuntimeError, match="liboqs"):
        pq.hybrid_encapsulate(
            receiver_classical_public=_valid_x25519_public_key_bytes(),
            receiver_pq_public=b"\x00" * 1568,
        )


def test_hybrid_decapsulate_fails_if_pq_ciphertext_without_pq_key():
    from meow_decoder.pq_hybrid import HybridKeyPair, hybrid_decapsulate

    receiver = HybridKeyPair(use_pq=False)

    with pytest.raises(RuntimeError, match="no PQ key"):
        hybrid_decapsulate(
            ephemeral_classical_public=_valid_x25519_public_key_bytes(),
            pq_ciphertext=b"\x00" * 1568,
            receiver_keypair=receiver,
        )


def test_hybrid_encapsulate_pq_kem_error(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    class FailingKEM:
        def __init__(self, variant):
            self.variant = variant

        def encap_secret(self, public_key):
            raise RuntimeError("boom")

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", True)
    monkeypatch.setattr(pq, "PQ_ALGORITHM", "Kyber1024")
    monkeypatch.setattr(pq, "oqs", types.SimpleNamespace(KeyEncapsulation=FailingKEM), raising=False)

    with pytest.raises(RuntimeError, match="encapsulation failed"):
        pq.hybrid_encapsulate(
            receiver_classical_public=_valid_x25519_public_key_bytes(),
            receiver_pq_public=b"\x00" * 1568,
        )


def test_check_pq_available_oqs_error(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    class FailingKEM:
        def __init__(self, variant):
            raise RuntimeError("boom")

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", True)
    monkeypatch.setattr(pq, "PQ_ALGORITHM", "Kyber1024")
    monkeypatch.setattr(pq, "oqs", types.SimpleNamespace(KeyEncapsulation=FailingKEM), raising=False)

    available, msg = pq.check_pq_available()
    assert available is False
    assert "unavailable" in msg.lower()


def test_hybrid_keypair_pq_generation_failure(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    class FailingKEM:
        def __init__(self, variant):
            self.variant = variant

        def generate_keypair(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", True)
    monkeypatch.setattr(pq, "PQ_ALGORITHM", "Kyber1024")
    monkeypatch.setattr(pq, "oqs", types.SimpleNamespace(KeyEncapsulation=FailingKEM), raising=False)

    keypair = pq.HybridKeyPair(use_pq=True)
    assert keypair.is_hybrid() is False
    assert keypair.pq_public is None


def test_hybrid_encapsulate_decapsulate_stubbed_pq(monkeypatch):
    import meow_decoder.pq_hybrid as pq

    monkeypatch.setattr(pq, "LIBOQS_AVAILABLE", True)
    monkeypatch.setattr(pq, "PQ_ALGORITHM", "Kyber1024")
    monkeypatch.setattr(pq, "oqs", _dummy_oqs_module(), raising=False)

    receiver = pq.HybridKeyPair(use_pq=True)
    classical_pub, pq_pub = receiver.export_public_keys()

    shared, eph_pub, pq_ct, pq_ss = pq.hybrid_encapsulate(classical_pub, pq_pub)
    assert pq_ct == b"C" * 1568
    assert pq_ss == b"K" * 32

    recovered = pq.hybrid_decapsulate(eph_pub, pq_ct, receiver)
    assert recovered == shared
