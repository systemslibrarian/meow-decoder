"""
Legacy PEM Key Parser for X25519

This module provides PEM-format X25519 private key loading using the Python
`cryptography` library. It is quarantined in legacy_py/ because production
code must not depend on `cryptography`.

Production code uses the MEOW_X25519 format (raw bytes, encrypted via Rust
AES-GCM backend). This module exists only for backward compatibility with
keys saved in PEM format by older versions of Meow Decoder.

Usage (CLI migration only — do NOT import from production code):
    from legacy_py.x25519_pem_legacy import load_pem_private_key_legacy
    raw_bytes = load_pem_private_key_legacy(pem_data, password="mypass")
    # Then re-save using save_receiver_keypair() in MEOW_X25519 format
"""

from typing import Optional


def load_pem_private_key_legacy(pem_data: bytes, password: Optional[str] = None) -> bytes:
    """
    Load X25519 private key from PEM-encoded bytes (legacy format).

    Args:
        pem_data: PEM-encoded private key data
        password: Password if PEM key is encrypted

    Returns:
        Raw 32-byte X25519 private key

    Raises:
        ValueError: If loaded key is not X25519PrivateKey
        ImportError: If cryptography library is not installed
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    password_bytes = password.encode("utf-8") if password else None
    private_key_obj = load_pem_private_key(pem_data, password=password_bytes)

    if not isinstance(private_key_obj, X25519PrivateKey):
        raise ValueError("Loaded key is not X25519PrivateKey")

    # Extract raw bytes
    return private_key_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
