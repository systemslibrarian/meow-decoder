"""
Encoder for Meow Decoder spec v1.2/v1.3.1 (single-tier).

Implements sign-header-then-encrypt-payload with AAD binding.
"""

from __future__ import annotations

import gc
import os
from typing import Final

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    _AEAD_CIPHER = XChaCha20Poly1305
    _AES_FALLBACK = False
except ImportError:  # pragma: no cover - fallback for limited builds
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AEAD_CIPHER = AESGCM
    _AES_FALLBACK = True

from .steganography import embed_in_gif
from .key_management import ed25519_pk_to_x25519_pk
from ..crypto_backend import secure_zero_memory

VERSION: Final[bytes] = (0x0002).to_bytes(2, "big")
KDF_INFO: Final[bytes] = b"meow-decoder-v1.2-xchacha20poly1305"
DOMAIN_SEPARATOR: Final[bytes] = b"meow-decoder-v1.2-signature\0\0\0\0\0"


def _ed25519_private_from_bytes(secret_key_64: bytes) -> ed25519.Ed25519PrivateKey:
    if len(secret_key_64) < 32:
        raise ValueError("Ed25519 secret key must be at least 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(secret_key_64[:32])


def encode_file(
    plaintext: bytes,
    recipient_ed25519_pk: bytes,
    sender_ed25519_sk: bytes,
    gif_carrier: bytes,
) -> bytes:
    """
    Encode plaintext into GIF file with encryption.
    """
    if len(recipient_ed25519_pk) != 32:
        raise ValueError("recipient_ed25519_pk must be 32 bytes")

    # Ephemeral X25519 keypair
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Convert recipient Ed25519 pk to X25519 pk
    recipient_x25519_pk = ed25519_pk_to_x25519_pk(recipient_ed25519_pk)
    recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_x25519_pk)

    shared_secret = eph_priv.exchange(recipient_pub)
    if shared_secret == b"\x00" * 32:
        raise ValueError("Invalid recipient public key (low-order point)")

    hkdf_salt = os.urandom(16)
    aead_nonce = os.urandom(24)

    kdf_info_length = len(KDF_INFO).to_bytes(1, "big")
    header_before_sig = (
        VERSION
        + recipient_ed25519_pk
        + eph_pub_bytes
        + hkdf_salt
        + aead_nonce
        + kdf_info_length
        + KDF_INFO
    )

    sender_priv = _ed25519_private_from_bytes(sender_ed25519_sk)
    signature = sender_priv.sign(DOMAIN_SEPARATOR + header_before_sig)

    aad = header_before_sig + signature

    key = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=hkdf_salt,
        info=KDF_INFO,
    ).derive(shared_secret)

    cipher = _AEAD_CIPHER(key)
    nonce = aead_nonce[:12] if _AES_FALLBACK else aead_nonce
    ciphertext = cipher.encrypt(nonce, plaintext, aad)

    payload = header_before_sig + signature + ciphertext
    embedded_gif = embed_in_gif(gif_carrier, payload)

    # Best-effort zeroization
    try:
        secure_zero_memory(bytearray(shared_secret))
        secure_zero_memory(bytearray(key))
        secure_zero_memory(bytearray(plaintext))
    except Exception:
        pass
    gc.collect()

    return embedded_gif


