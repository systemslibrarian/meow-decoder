#!/usr/bin/env python3
"""Tests for meow_decoder.spec_v12.encode."""

import pytest
import secrets

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

from meow_decoder.spec_v12 import encode as spec_encode
from meow_decoder.spec_v12 import steganography as spec_stego


def _minimal_gif() -> bytes:
    # GIF89a + Logical Screen Descriptor (1x1, no GCT)
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


def test_ed25519_private_from_bytes_short():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        spec_encode._ed25519_private_from_bytes(b"short")


def test_encode_invalid_recipient_pk_length():
    sender_sk, _ = _ed25519_keypair()

    with pytest.raises(ValueError, match="recipient_ed25519_pk must be 32 bytes"):
        spec_encode.encode_file(
            plaintext=b"data",
            recipient_ed25519_pk=b"short",
            sender_ed25519_sk=sender_sk,
            gif_carrier=_minimal_gif(),
        )


def test_encode_embeds_payload_marker(monkeypatch):
    sender_sk, _ = _ed25519_keypair()
    recipient_sk, recipient_pk = _ed25519_keypair()

    # Use X25519 keypair for conversion stubs
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_pub_bytes = x_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    monkeypatch.setattr(spec_encode, "ed25519_pk_to_x25519_pk", lambda _pk: x_pub_bytes)

    out_gif = spec_encode.encode_file(
        plaintext=b"hello",
        recipient_ed25519_pk=recipient_pk,
        sender_ed25519_sk=sender_sk,
        gif_carrier=_minimal_gif(),
    )

    assert spec_stego.MEOW_PAYLOAD_MARKER in out_gif
