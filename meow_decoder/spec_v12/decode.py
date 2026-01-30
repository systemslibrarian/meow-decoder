"""
Decoder for Meow Decoder spec v1.2/v1.3.1 (single-tier).

Enforces uniform error messages and AAD binding.
"""

from __future__ import annotations

import gc
from typing import Final

from cryptography.hazmat.primitives import hashes
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

from .steganography import extract_from_gif
from .key_management import ed25519_sk_to_x25519_sk
from ..crypto_backend import secure_zero_memory

VERSION: Final[int] = 0x0002
DOMAIN_SEPARATOR: Final[bytes] = b"meow-decoder-v1.2-signature\0\0\0\0\0"


def _ed25519_public_from_bytes(public_key_32: bytes) -> ed25519.Ed25519PublicKey:
    if len(public_key_32) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(public_key_32)


def decode_file(
    gif_file: bytes,
    sender_ed25519_pk: bytes,
    recipient_ed25519_sk: bytes,
) -> bytes:
    """
    Decode and decrypt payload from GIF file.
    """
    try:
        payload = extract_from_gif(gif_file)
        if len(payload) < 171:
            raise ValueError("Invalid payload size")

        version = int.from_bytes(payload[0:2], "big")
        if version != VERSION:
            raise ValueError("Unsupported protocol version")

        recipient_pk_in_header = payload[2:34]
        ephemeral_pk = payload[34:66]
        hkdf_salt = payload[66:82]
        aead_nonce = payload[82:106]
        kdf_info_length = payload[106]
        kdf_info = payload[107 : 107 + kdf_info_length]
        signature_offset = 107 + kdf_info_length
        signature = payload[signature_offset : signature_offset + 64]
        ciphertext = payload[signature_offset + 64 :]

        header_before_sig = payload[0:signature_offset]

        recipient_ed25519_pk = recipient_ed25519_sk[32:64]
        if recipient_pk_in_header != recipient_ed25519_pk:
            raise ValueError("Decryption failed")

        sender_pub = _ed25519_public_from_bytes(sender_ed25519_pk)
        sender_pub.verify(signature, DOMAIN_SEPARATOR + header_before_sig)

        recipient_x25519_sk = ed25519_sk_to_x25519_sk(recipient_ed25519_sk)
        recipient_priv = x25519.X25519PrivateKey.from_private_bytes(recipient_x25519_sk)
        shared_secret = recipient_priv.exchange(x25519.X25519PublicKey.from_public_bytes(ephemeral_pk))
        if shared_secret == b"\x00" * 32:
            raise ValueError("Invalid ephemeral public key")

        key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=hkdf_salt,
            info=kdf_info,
        ).derive(shared_secret)

        aad = header_before_sig + signature
        cipher = _AEAD_CIPHER(key)
        nonce = aead_nonce[:12] if _AES_FALLBACK else aead_nonce
        plaintext = cipher.decrypt(nonce, ciphertext, aad)

        try:
            secure_zero_memory(bytearray(shared_secret))
            secure_zero_memory(bytearray(key))
        except Exception:
            pass
        gc.collect()

        return plaintext

    except Exception:
        raise ValueError("Decryption failed") from None
