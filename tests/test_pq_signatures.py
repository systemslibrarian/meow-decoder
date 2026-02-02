#!/usr/bin/env python3
"""Tests for meow_decoder.pq_signatures.
Covers Ed25519 and stubbed Dilithium/hybrid paths.
"""

import types

import pytest
import secrets


def _dummy_oqs_module():
    class DummySignature:
        def __init__(self, alg, private_key=None):
            self.alg = alg
            self.private_key = private_key

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def generate_keypair(self):
            return b"P" * 64

        def export_secret_key(self):
            return b"S" * 64

        def sign(self, data):
            return b"SIG" + data

        def verify(self, data, signature, public_key):
            return signature == b"SIG" + data

    return types.SimpleNamespace(Signature=DummySignature, get_enabled_sig_mechanisms=lambda: ["Dilithium3"])


def test_get_available_algorithms_ed25519_only(monkeypatch):
    import meow_decoder.pq_signatures as pq

    monkeypatch.setattr(pq, "DILITHIUM_AVAILABLE", False)

    algos = pq.get_available_algorithms()
    assert algos == ["ed25519"]


def test_generate_keypair_ed25519_and_sign_verify():
    from meow_decoder.pq_signatures import generate_keypair, sign_manifest, verify_manifest

    keypair = generate_keypair("ed25519")
    msg = b"manifest"

    sig = sign_manifest(msg, keypair)
    assert verify_manifest(msg, sig, keypair.public_key) is True
    assert verify_manifest(msg + b"!", sig, keypair.public_key) is False


def test_sign_manifest_unknown_algorithm_raises():
    from meow_decoder.pq_signatures import SignatureKeyPair, sign_manifest

    keypair = SignatureKeyPair(algorithm=99, private_key=b"x", public_key=b"y")
    with pytest.raises(ValueError, match="Unknown algorithm"):
        sign_manifest(b"data", keypair)


def test_signature_pack_unpack_ed25519():
    from meow_decoder.pq_signatures import Signature, SIG_ED25519

    sig = Signature(algorithm=SIG_ED25519, signature=b"abc")
    packed = sig.pack()
    unpacked = Signature.unpack(packed)

    assert unpacked.algorithm == SIG_ED25519
    assert unpacked.signature == b"abc"


def test_signature_pack_unpack_hybrid():
    from meow_decoder.pq_signatures import Signature, SIG_HYBRID

    sig = Signature(algorithm=SIG_HYBRID, signature=b"", ed25519_sig=b"ed", dilithium_sig=b"pq")
    packed = sig.pack()
    unpacked = Signature.unpack(packed)

    assert unpacked.algorithm == SIG_HYBRID
    assert unpacked.ed25519_sig == b"ed"
    assert unpacked.dilithium_sig == b"pq"


def test_save_load_keypair_roundtrip(tmp_path):
    from meow_decoder.pq_signatures import generate_keypair, save_keypair, load_keypair

    keypair = generate_keypair("ed25519")
    priv = tmp_path / "priv.key"
    pub = tmp_path / "pub.key"

    save_keypair(keypair, str(priv), str(pub), password=None)
    loaded = load_keypair(str(priv), str(pub), password=None)

    assert loaded.algorithm == keypair.algorithm
    assert loaded.public_key == keypair.public_key
    assert loaded.private_key == keypair.private_key


def test_save_load_keypair_encrypted_requires_password(tmp_path):
    from meow_decoder.pq_signatures import generate_keypair, save_keypair, load_keypair

    keypair = generate_keypair("ed25519")
    priv = tmp_path / "priv.key"
    pub = tmp_path / "pub.key"

    save_keypair(keypair, str(priv), str(pub), password="secret")

    with pytest.raises(ValueError, match="password required"):
        load_keypair(str(priv), str(pub), password=None)

    loaded = load_keypair(str(priv), str(pub), password="secret")
    assert loaded.public_key == keypair.public_key


def test_save_load_keypair_encrypted_wrong_password_fails(tmp_path):
    from meow_decoder.pq_signatures import generate_keypair, save_keypair, load_keypair

    keypair = generate_keypair("ed25519")
    priv = tmp_path / "priv.key"
    pub = tmp_path / "pub.key"

    save_keypair(keypair, str(priv), str(pub), password="secret")

    with pytest.raises(Exception):
        load_keypair(str(priv), str(pub), password="wrong")


def test_dilithium_and_hybrid_with_stub(monkeypatch):
    import meow_decoder.pq_signatures as pq

    monkeypatch.setattr(pq, "HAS_LIBOQS", True)
    monkeypatch.setattr(pq, "DILITHIUM_AVAILABLE", True)
    monkeypatch.setattr(pq, "oqs", _dummy_oqs_module(), raising=False)

    # Dilithium only
    keypair = pq.generate_keypair("dilithium3")
    msg = b"data"
    sig = pq.sign_manifest(msg, keypair)
    assert pq.verify_manifest(msg, sig, keypair.public_key) is True

    # Hybrid
    hybrid_keypair = pq.generate_keypair("hybrid")
    hybrid_sig = pq.sign_manifest(msg, hybrid_keypair)
    assert pq.verify_manifest(msg, hybrid_sig, hybrid_keypair.public_key) is True


def test_verify_dilithium_returns_false_when_unavailable(monkeypatch):
    import meow_decoder.pq_signatures as pq

    monkeypatch.setattr(pq, "DILITHIUM_AVAILABLE", False)

    sig = pq.Signature(algorithm=pq.SIG_DILITHIUM3, signature=b"sig")
    assert pq.verify_manifest(b"data", sig, b"pub") is False
