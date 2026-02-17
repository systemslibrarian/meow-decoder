"""
X25519 Forward Secrecy Module for Meow Decoder
Implements ephemeral key agreement for true forward secrecy

Security Properties:
- Sender generates ephemeral X25519 keypair per encryption
- Receiver has long-term X25519 public key
- Shared secret derived from ephemeral + receiver public key
- Ephemeral private key is destroyed after encryption
- Compromise of receiver's long-term key doesn't compromise past messages
"""

import secrets
import struct
from typing import Tuple, Optional
from dataclasses import dataclass

from .crypto_backend import get_default_backend


@dataclass
class ForwardSecrecyKeys:
    """Container for forward secrecy key material (raw bytes)."""

    ephemeral_private: bytes
    ephemeral_public: bytes
    receiver_public: Optional[bytes] = None


def generate_ephemeral_keypair() -> ForwardSecrecyKeys:
    """
    Generate ephemeral X25519 keypair for forward secrecy.

    Returns:
        ForwardSecrecyKeys with ephemeral private and public keys (bytes)
    """
    private_key, public_key = get_default_backend().x25519_generate_keypair()

    return ForwardSecrecyKeys(ephemeral_private=private_key, ephemeral_public=public_key)


def derive_shared_secret(
    ephemeral_private: bytes,
    receiver_public: bytes,
    password: str,
    salt: bytes,
    info: bytes = b"meow_forward_secrecy_v1",
    protocol_version: Optional[int] = None,
    ephemeral_public: Optional[bytes] = None,
    pq_ciphertext_hash: Optional[bytes] = None,
    mode_flags: int = 0,
) -> bytes:
    """
    Derive shared secret using X25519 + password via HKDF.

    Args:
        ephemeral_private: Sender's ephemeral private key (bytes)
        receiver_public: Receiver's long-term public key (bytes)
        password: User password
        salt: Random salt (16 bytes)
        info: HKDF info string for domain separation (legacy fallback)
        protocol_version: Manifest version for transcript binding (FIX-C3).
            When provided, the HKDF info is augmented with full transcript
            context to prevent cross-version and mix-and-match attacks.
        ephemeral_public: Sender's ephemeral public key (32 bytes) for transcript.
        pq_ciphertext_hash: SHA-256 of PQ ciphertext (32 bytes) if PQ mode active.
        mode_flags: Bitmask encoding manifest mode (FS=0x01, PQ=0x02, duress=0x04).

    Returns:
        32-byte shared secret for encryption

    Transcript binding (FIX-C3 v2):
        When protocol_version is provided, HKDF info = concat of:
          \"meow_fs_bound_v2:\" || protocol_version (1B) || mode_flags (1B)
          || SHA-256(receiver_public) (32B)
          || ephemeral_public (32B, if provided)
          || pq_ciphertext_hash (32B, if provided)
        This binds: protocol version, encryption mode, both identities,
        and (if applicable) the PQ ciphertext into the key derivation.
        An attacker stripping PQ, swapping keys, or downgrading the version
        produces a different derived key → GCM decryption fails.
    """
    if len(ephemeral_private) != 32:
        raise ValueError(f"Ephemeral private key must be 32 bytes, got {len(ephemeral_private)}")
    if len(receiver_public) != 32:
        raise ValueError(f"Receiver public key must be 32 bytes, got {len(receiver_public)}")
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")

    backend = get_default_backend()

    # Perform X25519 key exchange
    x25519_shared = backend.x25519_exchange(ephemeral_private, receiver_public)

    # FIX-C3 v2: Full transcript binding — bind protocol version, mode flags,
    # receiver identity, sender ephemeral identity, and PQ ciphertext hash
    # into HKDF context to prevent cross-version, mix-and-match, and
    # downgrade attacks.
    if protocol_version is not None:
        bound_info = b"meow_fs_bound_v2:"
        bound_info += struct.pack(">B", protocol_version)
        bound_info += struct.pack(">B", mode_flags & 0xFF)
        # Bind receiver identity (hash of public key)
        bound_info += backend.sha256(receiver_public)
        # Bind sender ephemeral public key if available
        if ephemeral_public is not None:
            if len(ephemeral_public) != 32:
                raise ValueError(
                    f"Ephemeral public key must be 32 bytes, got {len(ephemeral_public)}"
                )
            bound_info += ephemeral_public
        # Bind PQ ciphertext hash (prevents stripping PQ component)
        if pq_ciphertext_hash is not None:
            if len(pq_ciphertext_hash) != 32:
                raise ValueError(
                    f"PQ ciphertext hash must be 32 bytes, got {len(pq_ciphertext_hash)}"
                )
            bound_info += pq_ciphertext_hash
    else:
        bound_info = info

    # Combine with password (use mutable buffers for best-effort zeroing)
    password_bytes = bytearray(password.encode("utf-8"))
    combined = bytearray(x25519_shared)
    combined.extend(password_bytes)

    try:
        # Derive final key using HKDF
        return backend.derive_key_hkdf(bytes(combined), salt, bound_info)
    finally:
        # Best-effort zeroing of sensitive material
        try:
            backend.secure_zero(password_bytes)
            backend.secure_zero(combined)
        except Exception:
            pass


def serialize_public_key(public_key: bytes) -> bytes:
    """
    Serialize X25519 public key to bytes.

    Args:
        public_key: X25519 public key bytes

    Returns:
        32 bytes representing the public key
    """
    return public_key


def deserialize_public_key(public_key_bytes: bytes) -> bytes:
    """
    Deserialize X25519 public key from bytes.

    Args:
        public_key_bytes: 32 bytes representing the public key

    Returns:
        X25519 public key bytes
    """
    if len(public_key_bytes) != 32:
        raise ValueError(f"X25519 public key must be 32 bytes, got {len(public_key_bytes)}")

    return public_key_bytes


def generate_receiver_keypair() -> Tuple[bytes, bytes]:
    """
    Generate receiver's long-term X25519 keypair.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    return get_default_backend().x25519_generate_keypair()


def save_receiver_keypair(
    private_key: bytes,
    public_key: bytes,
    private_key_file: str,
    public_key_file: str,
    password: Optional[str] = None,
) -> None:
    """
    Save receiver keypair to files.
    """
    # Save public key (raw bytes)
    # Note: original implementation saved Raw bytes for public key
    with open(public_key_file, "wb") as f:
        f.write(public_key)

    # Save private key (optionally encrypted with AES-256-GCM via Rust backend)
    _MAGIC_ENCRYPTED = b"MEOW_X25519\x02"  # 12 bytes
    _MAGIC_PLAIN = b"MEOW_X25519\x01"  # 12 bytes

    if password:
        backend = get_default_backend()
        salt = secrets.token_bytes(16)
        key = backend.derive_key_hkdf(
            ikm=password.encode("utf-8"),
            salt=salt,
            info=b"meow_x25519_key_storage_v2",
            output_len=32,
        )
        nonce = secrets.token_bytes(12)
        encrypted = backend.aes_gcm_encrypt(key, nonce, private_key, None)
        with open(private_key_file, "wb") as f:
            f.write(_MAGIC_ENCRYPTED + salt + nonce + encrypted)
    else:
        with open(private_key_file, "wb") as f:
            f.write(_MAGIC_PLAIN + private_key)


def load_x25519_private_key_pem(pem_data: bytes, password: Optional[str] = None) -> bytes:
    """
    Load X25519 private key from PEM-encoded bytes (legacy) or MEOW_X25519 format.

    Args:
        pem_data: PEM-encoded or MEOW_X25519 private key data
        password: Password if key is encrypted

    Returns:
        Raw 32-byte X25519 private key

    Note:
        Supports both legacy PEM format (via cryptography, if installed)
        and new MEOW_X25519 format (via Rust backend, no cryptography needed).
    """
    _MAGIC_ENCRYPTED = b"MEOW_X25519\x02"
    _MAGIC_PLAIN = b"MEOW_X25519\x01"

    if pem_data[:12] == _MAGIC_ENCRYPTED:
        if not password:
            raise ValueError("Private key is encrypted, password required")
        backend = get_default_backend()
        salt = pem_data[12:28]
        nonce = pem_data[28:40]
        encrypted = pem_data[40:]
        key = backend.derive_key_hkdf(
            ikm=password.encode("utf-8"),
            salt=salt,
            info=b"meow_x25519_key_storage_v2",
            output_len=32,
        )
        return backend.aes_gcm_decrypt(key, nonce, encrypted, None)
    elif pem_data[:12] == _MAGIC_PLAIN:
        return pem_data[12:44]
    else:
        # Legacy PEM format — no longer supported in production.
        # Use legacy_py/x25519_pem_legacy.py to convert PEM keys to MEOW_X25519 format.
        raise ValueError(
            "Unsupported key format. Expected MEOW_X25519 format (magic: MEOW_X25519\\x01 or "
            "MEOW_X25519\\x02). Legacy PEM keys can be converted using:\n"
            "  from legacy_py.x25519_pem_legacy import load_pem_private_key_legacy\n"
            "  raw_key = load_pem_private_key_legacy(pem_data, password)\n"
            "Then re-save with save_receiver_keypair() in MEOW_X25519 format."
        )


def load_receiver_keypair(
    private_key_file: str, public_key_file: str, password: Optional[str] = None
) -> Tuple[bytes, bytes]:
    """
    Load receiver keypair from files.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    # Load public key
    with open(public_key_file, "rb") as f:
        public_bytes = f.read()

    if len(public_bytes) != 32:
        raise ValueError(f"Invalid public key length: {len(public_bytes)}")

    public_key = public_bytes

    # Load private key (supports both MEOW_X25519 and legacy PEM formats)
    with open(private_key_file, "rb") as f:
        private_bytes = f.read()

    private_key = load_x25519_private_key_pem(private_bytes, password)

    return private_key, public_key


# CLI helper functions for key generation


def generate_receiver_keys_cli(output_dir: str = ".", password: Optional[str] = None) -> None:
    """
    CLI helper to generate receiver keypair.

    Args:
        output_dir: Directory to save keys (default: current directory)
        password: Password to encrypt private key (prompts if None)

    Creates:
        receiver_private.pem - Encrypted private key
        receiver_public.key - Public key (32 bytes)
    """
    import os
    import sys
    from getpass import getpass

    if password is None:
        # Non-interactive support (e.g., tests/CI): if stdin is piped, read two lines.
        # This avoids getpass() trying to read from /dev/tty and hanging.
        if sys.stdin is not None and not sys.stdin.isatty():
            password = sys.stdin.readline().rstrip("\n")
            confirm = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass("Enter password to protect private key: ")
            confirm = getpass("Confirm password: ")
        if password != confirm:
            raise ValueError("Passwords don't match")

    private_key, public_key = generate_receiver_keypair()

    private_file = os.path.join(output_dir, "receiver_private.pem")
    public_file = os.path.join(output_dir, "receiver_public.key")

    save_receiver_keypair(private_key, public_key, private_file, public_file, password)

    print(f"✅ Receiver keypair generated!")
    print(f"   Private key (KEEP SECRET): {private_file}")
    print(f"   Public key (share freely): {public_file}")
    print(f"\n🔐 Private key is encrypted with your password.")
    print(f"📤 Share {public_file} with senders.")


if __name__ == "__main__":  # pragma: no cover
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        # Generate receiver keypair
        output_dir = sys.argv[2] if len(sys.argv) > 2 else "."
        generate_receiver_keys_cli(output_dir)
    else:
        print("Usage: python x25519_forward_secrecy.py generate [output_dir]")
        print("\nGenerates receiver keypair for forward secrecy.")
        print("Private key is encrypted and should be kept secret.")
        print("Public key can be shared with senders.")
