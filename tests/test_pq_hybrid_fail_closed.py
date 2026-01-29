import pytest


def _valid_x25519_public_key_bytes() -> bytes:
    """Generate a valid X25519 public key (raw 32 bytes) for tests."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_hybrid_encapsulate_fails_if_pq_requested_but_unavailable(monkeypatch):
    from meow_decoder import pq_hybrid

    monkeypatch.setattr(pq_hybrid, "LIBOQS_AVAILABLE", False)
    monkeypatch.setattr(pq_hybrid, "PQ_ALGORITHM", None)

    # PQ requested (receiver_pq_public provided) but liboqs unavailable
    with pytest.raises(RuntimeError):
        pq_hybrid.hybrid_encapsulate(
            receiver_classical_public=_valid_x25519_public_key_bytes(),
            receiver_pq_public=b"\x00" * 1568,
        )


def test_hybrid_encapsulate_allows_classical_only_when_pq_not_requested(monkeypatch):
    from meow_decoder import pq_hybrid

    monkeypatch.setattr(pq_hybrid, "LIBOQS_AVAILABLE", False)

    # PQ not requested (receiver_pq_public None) should not raise
    shared_secret, ephemeral_public, pq_ct, pq_ss = pq_hybrid.hybrid_encapsulate(
        receiver_classical_public=_valid_x25519_public_key_bytes(),
        receiver_pq_public=None,
    )

    assert len(shared_secret) == 32
    assert len(ephemeral_public) == 32
    assert pq_ct is None
    assert pq_ss is None


def test_hybrid_decapsulate_fails_if_pq_ciphertext_without_pq_key():
    from meow_decoder.pq_hybrid import HybridKeyPair, hybrid_decapsulate

    receiver = HybridKeyPair(use_pq=False)

    with pytest.raises(RuntimeError):
        hybrid_decapsulate(
            ephemeral_classical_public=_valid_x25519_public_key_bytes(),
            pq_ciphertext=b"\x00" * 1568,
            receiver_keypair=receiver,
        )