"""
Multi-tier decoy encoder/decoder for Meow Decoder spec v1.2/v1.3.1.

All tiers are padded to identical length and processed in constant order.
"""

from __future__ import annotations

import gc
import os
from typing import List, Final

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

from .steganography import embed_in_gif, extract_from_gif
from .key_management import ed25519_pk_to_x25519_pk, ed25519_sk_to_x25519_sk
from ..crypto_backend import secure_zero_memory

VERSION: Final[bytes] = (0x0002).to_bytes(2, "big")
DOMAIN_SEPARATOR: Final[bytes] = b"meow-decoder-v1.2-signature\0\0\0\0\0"
KDF_INFO: Final[bytes] = b"meow-decoder-v1.2-xchacha20poly1305"


def _ed25519_private_from_bytes(secret_key_64: bytes) -> ed25519.Ed25519PrivateKey:
    if len(secret_key_64) < 32:
        raise ValueError("Ed25519 secret key must be at least 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(secret_key_64[:32])


def _ed25519_public_from_bytes(public_key_32: bytes) -> ed25519.Ed25519PublicKey:
    if len(public_key_32) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(public_key_32)


def encode_multi_tier(
    tier_plaintexts: List[bytes],
    recipient_ed25519_pk: bytes,
    sender_ed25519_sk: bytes,
    gif_carrier: bytes,
) -> bytes:
    tier_count = len(tier_plaintexts)
    if not 1 <= tier_count <= 3:
        raise ValueError("Must have 1-3 tiers")
    if len(recipient_ed25519_pk) != 32:
        raise ValueError("recipient_ed25519_pk must be 32 bytes")

    max_len = max(len(pt) for pt in tier_plaintexts)
    padded_plaintexts = [
        pt + os.urandom(max_len - len(pt)) if len(pt) < max_len else pt
        for pt in tier_plaintexts
    ]

    header = VERSION + recipient_ed25519_pk + tier_count.to_bytes(1, "big")
    recipient_x25519_pk = ed25519_pk_to_x25519_pk(recipient_ed25519_pk)
    recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_x25519_pk)

    sender_priv = _ed25519_private_from_bytes(sender_ed25519_sk)
    tier_payloads = []

    for plaintext in padded_plaintexts:
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        eph_pub_bytes = eph_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        hkdf_salt = os.urandom(16)
        aead_nonce = os.urandom(24)
        kdf_info_len = len(KDF_INFO).to_bytes(1, "big")
        tier_header_before_sig = eph_pub_bytes + hkdf_salt + aead_nonce + kdf_info_len + KDF_INFO

        shared_secret = eph_priv.exchange(recipient_pub)
        if shared_secret == b"\x00" * 32:
            raise ValueError("Invalid key generation")

        key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=hkdf_salt,
            info=KDF_INFO,
        ).derive(shared_secret)

        signature = sender_priv.sign(DOMAIN_SEPARATOR + header + tier_header_before_sig)
        aad = header + tier_header_before_sig + signature

        cipher = _AEAD_CIPHER(key)
        nonce = aead_nonce[:12] if _AES_FALLBACK else aead_nonce
        ciphertext = cipher.encrypt(nonce, plaintext, aad)

        tier_payloads.append(tier_header_before_sig + signature + ciphertext)

        try:
            secure_zero_memory(bytearray(shared_secret))
            secure_zero_memory(bytearray(key))
        except Exception:
            pass

    payload = header + b"".join(tier_payloads)
    embedded_gif = embed_in_gif(gif_carrier, payload)

    try:
        secure_zero_memory(bytearray(b"".join(padded_plaintexts)))
    except Exception:
        pass
    gc.collect()

    return embedded_gif


def decode_multi_tier(
    gif_file: bytes,
    sender_ed25519_pk: bytes,
    recipient_ed25519_sk: bytes,
    tier_index: int = 0,
) -> bytes:
    try:
        payload = extract_from_gif(gif_file)
        if len(payload) < 35:
            raise ValueError("Invalid payload size")

        version = int.from_bytes(payload[0:2], "big")
        if version != int.from_bytes(VERSION, "big"):
            raise ValueError("Not a multi-tier file")

        recipient_pk = payload[2:34]
        tier_count = payload[34]
        if tier_index >= tier_count:
            raise ValueError("Tier index out of range")

        recipient_ed25519_pk = recipient_ed25519_sk[32:64]
        if recipient_pk != recipient_ed25519_pk:
            raise ValueError("Decryption failed")

        header = payload[0:35]
        offset = 35
        tier_plaintexts = [b""] * tier_count
        had_error = False

        # Derive expected kdf_info length from first tier and compute fixed ciphertext length
        if offset + 72 >= len(payload):
            raise ValueError("Decryption failed")
        expected_kdf_info_len = payload[offset + 72]
        tier_header_len = 73 + expected_kdf_info_len
        per_tier_overhead = tier_header_len + 64
        total_cipher_bytes = len(payload) - len(header) - (per_tier_overhead * tier_count)
        if total_cipher_bytes <= 0 or total_cipher_bytes % tier_count != 0:
            raise ValueError("Decryption failed")
        cipher_len = total_cipher_bytes // tier_count

        recipient_x25519_sk = ed25519_sk_to_x25519_sk(recipient_ed25519_sk)
        recipient_priv = x25519.X25519PrivateKey.from_private_bytes(recipient_x25519_sk)
        sender_pub = _ed25519_public_from_bytes(sender_ed25519_pk)

        for i in range(tier_count):
            ephemeral_pk = payload[offset : offset + 32]
            hkdf_salt = payload[offset + 32 : offset + 48]
            aead_nonce = payload[offset + 48 : offset + 72]
            kdf_info_len = payload[offset + 72]
            if kdf_info_len != expected_kdf_info_len:
                had_error = True
                break
            kdf_info = payload[offset + 73 : offset + 73 + kdf_info_len]

            tier_header_len = 73 + expected_kdf_info_len
            tier_header_before_sig = payload[offset : offset + tier_header_len]
            signature = payload[offset + tier_header_len : offset + tier_header_len + 64]

            ciphertext_start = offset + tier_header_len + 64
            if ciphertext_start + cipher_len > len(payload):
                had_error = True
                break

            ciphertext = payload[ciphertext_start : ciphertext_start + cipher_len]
            offset = ciphertext_start + cipher_len

            # Verify signature and decrypt (constant-order processing)
            try:
                sender_pub.verify(signature, DOMAIN_SEPARATOR + header + tier_header_before_sig)
                shared_secret = recipient_priv.exchange(
                    x25519.X25519PublicKey.from_public_bytes(ephemeral_pk)
                )
                if shared_secret == b"\x00" * 32:
                    raise ValueError("Invalid ephemeral public key")

                key = HKDF(
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=hkdf_salt,
                    info=kdf_info,
                ).derive(shared_secret)

                aad = header + tier_header_before_sig + signature
                cipher = _AEAD_CIPHER(key)
                nonce = aead_nonce[:12] if _AES_FALLBACK else aead_nonce
                tier_plaintexts[i] = cipher.decrypt(nonce, ciphertext, aad)

                try:
                    secure_zero_memory(bytearray(shared_secret))
                    secure_zero_memory(bytearray(key))
                except Exception:
                    pass
            except Exception:
                had_error = True
                tier_plaintexts[i] = b""

        if had_error:
            raise ValueError("Decryption failed")

        return tier_plaintexts[tier_index]

    except Exception:
        raise ValueError("Decryption failed") from None


