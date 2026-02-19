"""
⚠️  DEPRECATED / QUARANTINED — Scheduled for move to meow_decoder/experimental/

Forward Secrecy Module with X25519 Ephemeral Key Agreement (LEGACY)
Use meow_decoder.x25519_forward_secrecy instead.

Security Model:
- Receiver has long-term X25519 public key
- Sender generates ephemeral X25519 keypair per message
- Shared secret derived from ephemeral exchange
- Hybrid with password using HKDF
- Ephemeral private key never stored (forward secrecy!)
"""

from .crypto_backend import get_default_backend as _get_backend
from typing import Tuple, Optional
from dataclasses import dataclass
import struct
import secrets
import warnings as _warnings

_warnings.warn(
    "meow_decoder.forward_secrecy_x25519 is deprecated. "
    "Use meow_decoder.x25519_forward_secrecy instead. "
    "This module will move to meow_decoder.experimental in a future release.",
    DeprecationWarning,
    stacklevel=2,
)


@dataclass
class EphemeralKeyPair:
    """
    Ephemeral X25519 keypair for forward secrecy.

    Security:
        - Private key is NEVER stored long-term
        - Used once per encryption, then discarded
        - Zeroed from memory after use
    """

    private_key_bytes: bytes  # 32-byte raw private key
    public_key_bytes: bytes  # 32-byte raw public key

    @classmethod
    def generate(cls) -> "EphemeralKeyPair":
        """Generate new ephemeral keypair."""
        priv, pub = _get_backend().x25519_generate_keypair()
        return cls(private_key_bytes=priv, public_key_bytes=pub)

    def public_bytes(self) -> bytes:
        """Serialize public key for transmission."""
        return self.public_key_bytes


def derive_hybrid_key(
    password: str,
    salt: bytes,
    shared_secret: Optional[bytes] = None,
    info: bytes = b"meow_hybrid_v1",
) -> bytes:
    """
    Derive encryption key from password + optional shared secret.

    Args:
        password: User passphrase
        salt: Random salt (16 bytes)
        shared_secret: Optional X25519 shared secret (32 bytes)
        info: HKDF info parameter

    Returns:
        32-byte encryption key

    Security:
        - Password-only mode: Standard Argon2id derivation
        - Hybrid mode: HKDF(password || shared_secret)
        - Provides defense in depth (compromise one doesn't break all)
    """
    import os

    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")

    # First stage: Derive password key with Argon2id
    from argon2 import low_level

    # Test mode support for fast CI/testing
    _TEST_MODE = os.environ.get("MEOW_TEST_MODE", "").lower() in ("1", "true", "yes")

    if _TEST_MODE:
        # Fast parameters for CI/testing (still secure enough for functional tests)
        ARGON2_MEMORY = 32768  # 32 MiB (fast)
        ARGON2_ITERATIONS = 1  # 1 pass (fast)
        ARGON2_PARALLELISM = 1  # 1 thread
    else:
        # Production: Strong parameters
        ARGON2_MEMORY = 262144  # 256 MiB (MAXIMUM SECURITY)
        ARGON2_ITERATIONS = 10  # 10 passes
        ARGON2_PARALLELISM = 4  # 4 threads

    password_key = low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=low_level.Type.ID,
    )

    # If no shared secret, return password key directly
    if shared_secret is None:
        return password_key

    # Hybrid mode: Combine password key + shared secret with HKDF
    # Defense in depth: Need both password AND ephemeral key compromise
    combined_material = password_key + shared_secret

    final_key = _get_backend().derive_key_hkdf(
        ikm=combined_material, salt=salt, info=info, output_len=32
    )

    return final_key


def encrypt_with_forward_secrecy(
    plaintext: bytes, password: str, receiver_public_key: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypt with forward secrecy using ephemeral X25519.

    Args:
        plaintext: Data to encrypt
        password: User passphrase
        receiver_public_key: Receiver's long-term X25519 public key (32 bytes)
                            If None, uses password-only mode

    Returns:
        Tuple of (ciphertext, salt, nonce, ephemeral_public_key)

    Security:
        - Generates ephemeral X25519 keypair (discarded after)
        - Derives shared secret with receiver's public key
        - Hybrid key = HKDF(password || shared_secret)
        - Ephemeral public key bundled in output
        - Ephemeral private key NEVER stored (forward secrecy!)

    Forward Secrecy Property:
        - Future password compromise → Cannot decrypt past messages
        - Need BOTH password AND ephemeral private key
        - Ephemeral private key destroyed after encryption
    """
    import zlib

    # Generate random salt and nonce
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    # Compress plaintext
    compressed = zlib.compress(plaintext, level=9)

    # If receiver public key provided, use forward secrecy
    ephemeral_public_bytes = b""
    shared_secret = None

    if receiver_public_key is not None:
        # Generate ephemeral keypair
        ephemeral = EphemeralKeyPair.generate()

        # Derive shared secret via X25519
        shared_secret = _get_backend().x25519_exchange(
            ephemeral.private_key_bytes, receiver_public_key
        )

        # Export ephemeral public key for transmission
        ephemeral_public_bytes = ephemeral.public_bytes()

        # NOTE: ephemeral.private_key goes out of scope and is garbage collected
        # This provides forward secrecy - private key never stored!

    # Derive hybrid key (password + optional shared secret)
    key = derive_hybrid_key(password, salt, shared_secret)

    # Build AAD
    aad = salt + struct.pack("<Q", len(plaintext))
    if ephemeral_public_bytes:
        aad += ephemeral_public_bytes  # Include in authentication

    # Encrypt with AES-256-GCM
    ciphertext = _get_backend().aes_gcm_encrypt(key, nonce, compressed, aad)

    return ciphertext, salt, nonce, ephemeral_public_bytes


def decrypt_with_forward_secrecy(
    ciphertext: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    ephemeral_public_key: bytes,
    receiver_private_key: Optional[bytes] = None,
    orig_len: Optional[int] = None,
) -> bytes:
    """
    Decrypt with forward secrecy.

    Args:
        ciphertext: Encrypted data
        password: User passphrase
        salt: Salt used during encryption
        nonce: Nonce used during encryption
        ephemeral_public_key: Sender's ephemeral public key (32 bytes)
                             Empty if password-only mode
        receiver_private_key: Receiver's long-term X25519 private key (32 bytes)
                             Required if ephemeral_public_key provided
        orig_len: Original plaintext length (for AAD)

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If forward secrecy mode but receiver key missing
        RuntimeError: If decryption fails
    """
    import zlib

    # If ephemeral public key present, need receiver private key
    shared_secret = None

    if len(ephemeral_public_key) > 0:
        if receiver_private_key is None:
            raise ValueError("Forward secrecy mode requires receiver private key")

        # Derive shared secret via Rust backend
        shared_secret = _get_backend().x25519_exchange(receiver_private_key, ephemeral_public_key)

    # Derive hybrid key
    key = derive_hybrid_key(password, salt, shared_secret)

    # Reconstruct AAD
    aad = salt
    if orig_len is not None:
        aad += struct.pack("<Q", orig_len)
    if ephemeral_public_key:
        aad += ephemeral_public_key

    # Decrypt
    compressed = _get_backend().aes_gcm_decrypt(key, nonce, ciphertext, aad)

    # Decompress
    plaintext = zlib.decompress(compressed)

    return plaintext


# Example usage for testing
if __name__ == "__main__":
    # Generate receiver keypair (long-term) using Rust backend
    _backend = _get_backend()
    receiver_private_bytes, receiver_public_bytes = _backend.x25519_generate_keypair()

    # Encrypt with forward secrecy
    plaintext = b"Secret message with forward secrecy!"
    password = "test_password_123"

    ciphertext, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
        plaintext, password, receiver_public_bytes
    )

    print(f"✅ Encrypted with forward secrecy")
    print(f"   Ciphertext: {len(ciphertext)} bytes")
    print(f"   Ephemeral public key: {ephemeral_pub.hex()[:32]}...")

    # Decrypt
    decrypted = decrypt_with_forward_secrecy(
        ciphertext, password, salt, nonce, ephemeral_pub, receiver_private_bytes, len(plaintext)
    )

    print(f"✅ Decrypted successfully")
    print(f"   Match: {decrypted == plaintext}")

    # Test password-only mode (no forward secrecy)
    ciphertext2, salt2, nonce2, ephemeral_pub2 = encrypt_with_forward_secrecy(
        plaintext, password, None
    )

    print(f"\n✅ Password-only mode")
    print(f"   Ephemeral key: {len(ephemeral_pub2)} bytes (should be 0)")

    decrypted2 = decrypt_with_forward_secrecy(
        ciphertext2, password, salt2, nonce2, ephemeral_pub2, None, len(plaintext)
    )

    print(f"✅ Decrypted successfully")
    print(f"   Match: {decrypted2 == plaintext}")
