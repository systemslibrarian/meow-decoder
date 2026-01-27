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
from typing import Tuple, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
    
    return ForwardSecrecyKeys(
        ephemeral_private=private_key,
        ephemeral_public=public_key
    )


def derive_shared_secret(
    ephemeral_private: bytes,
    receiver_public: bytes,
    password: str,
    salt: bytes,
    info: bytes = b"meow_forward_secrecy_v1"
) -> bytes:
    """
    Derive shared secret using X25519 + password via HKDF.
    
    Args:
        ephemeral_private: Sender's ephemeral private key (bytes)
        receiver_public: Receiver's long-term public key (bytes)
        password: User password
        salt: Random salt (16 bytes)
        info: HKDF info string for domain separation
        
    Returns:
        32-byte shared secret for encryption
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

    # Combine with password (use mutable buffers for best-effort zeroing)
    password_bytes = bytearray(password.encode('utf-8'))
    combined = bytearray(x25519_shared)
    combined.extend(password_bytes)

    try:
        # Derive final key using HKDF
        return backend.derive_key_hkdf(bytes(combined), salt, info)
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
    password: Optional[str] = None
) -> None:
    """
    Save receiver keypair to files.
    """
    # Save public key (raw bytes)
    # Note: original implementation saved Raw bytes for public key
    with open(public_key_file, 'wb') as f:
        f.write(public_key)
    
    # Save private key (encrypted PEM)
    # We use cryptography library for PEM encoding/encryption
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat
    )
    
    # Wrap bytes in object for serialization
    priv_obj = X25519PrivateKey.from_private_bytes(private_key)

    if password:
        from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
        encryption = BestAvailableEncryption(password.encode('utf-8'))
    else:
        from cryptography.hazmat.primitives.serialization import NoEncryption
        encryption = NoEncryption()
    
    private_bytes = priv_obj.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    with open(private_key_file, 'wb') as f:
        f.write(private_bytes)


def load_receiver_keypair(
    private_key_file: str,
    public_key_file: str,
    password: Optional[str] = None
) -> Tuple[bytes, bytes]:
    """
    Load receiver keypair from files.
    
    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    # Load public key
    with open(public_key_file, 'rb') as f:
        public_bytes = f.read()
    
    if len(public_bytes) != 32:
        raise ValueError(f"Invalid public key length: {len(public_bytes)}")
        
    public_key = public_bytes
    
    # Load private key
    with open(private_key_file, 'rb') as f:
        private_bytes = f.read()
    
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    
    password_bytes = password.encode('utf-8') if password else None
    private_key_obj = load_pem_private_key(private_bytes, password=password_bytes)
    
    if not isinstance(private_key_obj, X25519PrivateKey):
        raise ValueError("Loaded key is not X25519PrivateKey")
    
    # Extract raw bytes
    private_key = private_key_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
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


if __name__ == "__main__":
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
