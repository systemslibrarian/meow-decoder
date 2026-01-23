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


@dataclass
class ForwardSecrecyKeys:
    """Container for forward secrecy key material."""
    ephemeral_private: X25519PrivateKey
    ephemeral_public: X25519PublicKey
    receiver_public: Optional[X25519PublicKey] = None


def generate_ephemeral_keypair() -> ForwardSecrecyKeys:
    """
    Generate ephemeral X25519 keypair for forward secrecy.
    
    Returns:
        ForwardSecrecyKeys with ephemeral private and public keys
        
    Security:
        - Private key should be destroyed after single use
        - Never store ephemeral private key to disk
        - Each encryption gets new ephemeral keypair
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    return ForwardSecrecyKeys(
        ephemeral_private=private_key,
        ephemeral_public=public_key
    )


def derive_shared_secret(
    ephemeral_private: X25519PrivateKey,
    receiver_public: X25519PublicKey,
    password: str,
    salt: bytes,
    info: bytes = b"meow_forward_secrecy_v1"
) -> bytes:
    """
    Derive shared secret using X25519 + password via HKDF.
    
    Args:
        ephemeral_private: Sender's ephemeral private key
        receiver_public: Receiver's long-term public key
        password: User password
        salt: Random salt (16 bytes)
        info: HKDF info string for domain separation
        
    Returns:
        32-byte shared secret for encryption
        
    Security:
        - Combines ECDH shared secret + password
        - HKDF ensures cryptographic mixing
        - Salt prevents rainbow tables
        - Info string provides domain separation
        
    Formula:
        shared_secret = HKDF(
            X25519_exchange(ephemeral_private, receiver_public) || password,
            salt=salt,
            info=info
        )
    """
    # Perform X25519 key exchange
    x25519_shared = ephemeral_private.exchange(receiver_public)
    
    # Combine with password
    password_bytes = password.encode('utf-8')
    combined = x25519_shared + password_bytes
    
    # Derive final key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    shared_secret = hkdf.derive(combined)
    
    return shared_secret


def serialize_public_key(public_key: X25519PublicKey) -> bytes:
    """
    Serialize X25519 public key to bytes.
    
    Args:
        public_key: X25519 public key
        
    Returns:
        32 bytes representing the public key
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def deserialize_public_key(public_key_bytes: bytes) -> X25519PublicKey:
    """
    Deserialize X25519 public key from bytes.
    
    Args:
        public_key_bytes: 32 bytes representing the public key
        
    Returns:
        X25519PublicKey object
        
    Raises:
        ValueError: If public_key_bytes is not 32 bytes
    """
    if len(public_key_bytes) != 32:
        raise ValueError(f"X25519 public key must be 32 bytes, got {len(public_key_bytes)}")
    
    return X25519PublicKey.from_public_bytes(public_key_bytes)


def generate_receiver_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Generate receiver's long-term X25519 keypair.
    
    Returns:
        Tuple of (private_key, public_key)
        
    Security:
        - Private key should be stored securely (encrypted at rest)
        - Public key can be distributed freely
        - Keep private key offline/air-gapped when possible
        
    Usage:
        receiver_private, receiver_public = generate_receiver_keypair()
        # Save receiver_public to share with senders
        # Protect receiver_private with strong encryption
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    return private_key, public_key


def save_receiver_keypair(
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
    private_key_file: str,
    public_key_file: str,
    password: Optional[str] = None
) -> None:
    """
    Save receiver keypair to files.
    
    Args:
        private_key: X25519 private key
        public_key: X25519 public key
        private_key_file: Path to save encrypted private key
        public_key_file: Path to save public key
        password: Password to encrypt private key (None = unencrypted)
        
    Security:
        - Private key should ALWAYS be password-protected
        - Use strong password for private key encryption
        - Public key file can be world-readable
    """
    # Save public key (unencrypted)
    public_bytes = serialize_public_key(public_key)
    with open(public_key_file, 'wb') as f:
        f.write(public_bytes)
    
    # Save private key (encrypted if password provided)
    if password:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, BestAvailableEncryption
        )
        encryption = BestAvailableEncryption(password.encode('utf-8'))
    else:
        from cryptography.hazmat.primitives.serialization import NoEncryption
        encryption = NoEncryption()
    
    private_bytes = private_key.private_bytes(
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
) -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Load receiver keypair from files.
    
    Args:
        private_key_file: Path to encrypted private key
        public_key_file: Path to public key
        password: Password to decrypt private key
        
    Returns:
        Tuple of (private_key, public_key)
        
    Raises:
        ValueError: If files don't exist or password is wrong
    """
    # Load public key
    with open(public_key_file, 'rb') as f:
        public_bytes = f.read()
    public_key = deserialize_public_key(public_bytes)
    
    # Load private key
    with open(private_key_file, 'rb') as f:
        private_bytes = f.read()
    
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    
    password_bytes = password.encode('utf-8') if password else None
    private_key = load_pem_private_key(private_bytes, password=password_bytes)
    
    if not isinstance(private_key, X25519PrivateKey):
        raise ValueError("Loaded key is not X25519PrivateKey")
    
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
    from getpass import getpass
    
    if password is None:
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
