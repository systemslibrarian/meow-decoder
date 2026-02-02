#!/usr/bin/env python3
"""Tests for meow_decoder.spec_v12.decode."""

import pytest

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

from meow_decoder.spec_v12 import encode as spec_encode
from meow_decoder.spec_v12 import decode as spec_decode
from meow_decoder.spec_v12 import steganography as spec_stego


def _minimal_gif() -> bytes:
    return b"GIF89a" + b"\x01\x00\x01\x00\x00\x00\x00"


def _ed25519_keypair() -> tuple[bytes, bytes]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes + pub_bytes, pub_bytes


def test_roundtrip_encode_decode(monkeypatch):
    sender_sk, sender_pk = _ed25519_keypair()
    recipient_sk, recipient_pk = _ed25519_keypair()

    # Use X25519 keypair for conversion stubs
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_pub_bytes = x_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x_priv_bytes = x_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    monkeypatch.setattr(spec_encode, "ed25519_pk_to_x25519_pk", lambda _pk: x_pub_bytes)
    monkeypatch.setattr(spec_decode, "ed25519_sk_to_x25519_sk", lambda _sk: x_priv_bytes)

    plaintext = b"spec-v12 test payload"
    gif = spec_encode.encode_file(plaintext, recipient_pk, sender_sk, _minimal_gif())

    recovered = spec_decode.decode_file(gif, sender_pk, recipient_sk)
    assert recovered == plaintext


def test_decode_invalid_payload_size():
    payload = b"X" * 100
    gif = spec_stego.embed_in_gif(_minimal_gif(), payload)

    with pytest.raises(ValueError, match="Decryption failed"):
        spec_decode.decode_file(gif, b"\x00" * 32, b"\x00" * 64)


def test_decode_unsupported_version():
    payload = (0x0003).to_bytes(2, "big") + b"\x00" * (171 - 2)
    gif = spec_stego.embed_in_gif(_minimal_gif(), payload)

    with pytest.raises(ValueError, match="Decryption failed"):
        spec_decode.decode_file(gif, b"\x00" * 32, b"\x00" * 64)


def test_decode_wrong_recipient_key(monkeypatch):
    sender_sk, sender_pk = _ed25519_keypair()
    recipient_sk, recipient_pk = _ed25519_keypair()
    other_recipient_sk, _ = _ed25519_keypair()

    x_priv = x25519.X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x_priv_bytes = x_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    monkeypatch.setattr(spec_encode, "ed25519_pk_to_x25519_pk", lambda _pk: x_pub_bytes)
    monkeypatch.setattr(spec_decode, "ed25519_sk_to_x25519_sk", lambda _sk: x_priv_bytes)

    gif = spec_encode.encode_file(b"hello", recipient_pk, sender_sk, _minimal_gif())

    with pytest.raises(ValueError, match="Decryption failed"):
        spec_decode.decode_file(gif, sender_pk, other_recipient_sk)


def test_decode_signature_failure(monkeypatch):
    sender_sk, sender_pk = _ed25519_keypair()
    recipient_sk, recipient_pk = _ed25519_keypair()
    other_sender_sk, other_sender_pk = _ed25519_keypair()

    x_priv = x25519.X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x_priv_bytes = x_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    monkeypatch.setattr(spec_encode, "ed25519_pk_to_x25519_pk", lambda _pk: x_pub_bytes)
    monkeypatch.setattr(spec_decode, "ed25519_sk_to_x25519_sk", lambda _sk: x_priv_bytes)

    gif = spec_encode.encode_file(b"hello", recipient_pk, sender_sk, _minimal_gif())

    with pytest.raises(ValueError, match="Decryption failed"):
        spec_decode.decode_file(gif, other_sender_pk, recipient_sk)
