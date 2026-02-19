"""
X25519 Forward Secrecy Module for Meow Decoder
Implements ephemeral key agreement for true forward secrecy

Security Properties:
- Sender generates ephemeral X25519 keypair per encryption
- Receiver has long-term X25519 public key
- Shared secret derived from ephemeral + receiver public key
- Ephemeral private key is destroyed after encryption
- Compromise of receiver's long-term key doesn't compromise past messages

Handle-Based Security (Rule #2):
- X25519 private keys stored as opaque Rust handles (never raw bytes in Python)
- DH shared secrets and HKDF intermediates remain inside Rust
- Only public keys and final derived encryption keys cross the FFI boundary
"""

import secrets
import struct
from typing import Tuple, Optional, Union
from dataclasses import dataclass

from .crypto_backend import get_default_backend, get_handle_backend


@dataclass
class ForwardSecrecyKeys:
    """Container for forward secrecy key material.

    ephemeral_private is an opaque Rust handle (int), NOT raw bytes.
    ephemeral_public and receiver_public are public keys (safe as bytes).
    """

    ephemeral_private: int  # Opaque handle — private key lives in Rust
    ephemeral_public: bytes
    receiver_public: Optional[bytes] = None

    def drop(self) -> None:
        """Drop the ephemeral private key handle (zeroizes inside Rust)."""
        if self.ephemeral_private is not None:
            try:
                get_handle_backend().drop(self.ephemeral_private)
            except Exception:
                pass
            self.ephemeral_private = None


def generate_ephemeral_keypair() -> ForwardSecrecyKeys:
    """
    Generate ephemeral X25519 keypair for forward secrecy.

    Returns:
        ForwardSecrecyKeys with ephemeral private handle (int) and public key (bytes)
    """
    hb = get_handle_backend()
    private_handle, public_key = hb.x25519_generate_keypair()

    return ForwardSecrecyKeys(ephemeral_private=private_handle, ephemeral_public=public_key)


def derive_shared_secret(
    ephemeral_private: Union[int, bytes],
    receiver_public: bytes,
    password: str,
    salt: bytes,
    info: bytes = b"meow_forward_secrecy_v1",
    protocol_version: Optional[int] = None,
    ephemeral_public: Optional[bytes] = None,
    pq_ciphertext_hash: Optional[bytes] = None,
    mode_flags: int = 0,
    static_receiver_public: Optional[bytes] = None,
) -> bytes:
    """
    Derive shared secret using X25519 + password via HKDF.

    Args:
        ephemeral_private: Sender's ephemeral private key — either an opaque
            handle (int) from HandleBackend or raw bytes (legacy callers).
            If bytes, they are imported into a handle and zeroed immediately.
        receiver_public: Receiver's long-term public key (bytes)
        password: User password
        salt: Random salt (16 bytes)
        info: HKDF info string for domain separation (legacy fallback)
        protocol_version: Manifest version for transcript binding (FIX-C3).
        ephemeral_public: Sender's ephemeral public key (32 bytes) for transcript.
        pq_ciphertext_hash: SHA-256 of PQ ciphertext (32 bytes) if PQ mode active.
        mode_flags: Bitmask encoding manifest mode (FS=0x01, PQ=0x02, duress=0x04).
        static_receiver_public: Receiver's static public key for transcript binding
            (FIX-C3v2). When decoding, receiver_public is the sender's ephemeral
            key (for DH), but the transcript hash must use the receiver's static
            public key to match the encode side. If None, receiver_public is used.

    Returns:
        32-byte shared secret for encryption
    """
    if isinstance(ephemeral_private, bytes):
        if len(ephemeral_private) != 32:
            raise ValueError(
                f"Ephemeral private key must be 32 bytes, got {len(ephemeral_private)}"
            )
    if len(receiver_public) != 32:
        raise ValueError(f"Receiver public key must be 32 bytes, got {len(receiver_public)}")
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")

    hb = get_handle_backend()
    backend = get_default_backend()
    imported_handle = None

    try:
        # If caller passed raw bytes, import into a handle
        if isinstance(ephemeral_private, bytes):
            private_handle = hb.import_x25519_private(ephemeral_private)
            imported_handle = private_handle
        else:
            private_handle = ephemeral_private

        # Perform X25519 key exchange — shared secret stays in Rust as handle
        shared_handle = hb.x25519_exchange(private_handle, receiver_public)

        # FIX-C3 v2: Full transcript binding
        # Use static_receiver_public for the transcript hash when provided
        # (decode side), otherwise use receiver_public (encode side).
        # This ensures both sides hash the RECEIVER's static public key.
        receiver_pub_for_binding = static_receiver_public or receiver_public
        if protocol_version is not None:
            bound_info = b"meow_fs_bound_v2:"
            bound_info += struct.pack(">B", protocol_version)
            bound_info += struct.pack(">B", mode_flags & 0xFF)
            bound_info += backend.sha256(receiver_pub_for_binding)
            if ephemeral_public is not None:
                if len(ephemeral_public) != 32:
                    raise ValueError(
                        f"Ephemeral public key must be 32 bytes, got {len(ephemeral_public)}"
                    )
                bound_info += ephemeral_public
            if pq_ciphertext_hash is not None:
                if len(pq_ciphertext_hash) != 32:
                    raise ValueError(
                        f"PQ ciphertext hash must be 32 bytes, got {len(pq_ciphertext_hash)}"
                    )
                bound_info += pq_ciphertext_hash
        else:
            bound_info = info

        # Mix DH shared secret with password inside Rust via HKDF:
        # IKM = shared_secret || password, processed via handle-based mix_hkdf
        password_bytes = password.encode("utf-8")
        derived_handle = hb.mix_hkdf(shared_handle, password_bytes, salt, bound_info, 32)

        # Export final derived key (only this crosses FFI boundary)
        derived_key = hb.export_key(derived_handle)

        # Drop intermediate handles
        hb.drop(shared_handle)
        hb.drop(derived_handle)

        return bytes(derived_key)
    finally:
        # Drop imported handle if we created one
        if imported_handle is not None:
            try:
                hb.drop(imported_handle)
            except Exception:
                pass


def derive_shared_secret_handle(
    ephemeral_private: Union[int, bytes],
    receiver_public: bytes,
    password: str,
    salt: bytes,
    info: bytes = b"meow_forward_secrecy_v1",
    protocol_version: Optional[int] = None,
    ephemeral_public: Optional[bytes] = None,
    pq_ciphertext_hash: Optional[bytes] = None,
    mode_flags: int = 0,
    static_receiver_public: Optional[bytes] = None,
) -> int:
    """
    Derive shared secret using X25519 + password via HKDF — returns opaque handle.

    Identical to derive_shared_secret() but the derived key NEVER enters Python.
    Caller MUST drop the returned handle when done.

    Args:
        static_receiver_public: Receiver's static public key for transcript
            binding (FIX-C3v2). On decode side, receiver_public is the sender's
            ephemeral key (for DH), but the transcript must hash the receiver's
            static public key to match encode. If None, receiver_public is used.

    Returns:
        int handle ID pointing to the 32-byte shared secret inside Rust
    """
    if isinstance(ephemeral_private, bytes):
        if len(ephemeral_private) != 32:
            raise ValueError(
                f"Ephemeral private key must be 32 bytes, got {len(ephemeral_private)}"
            )
    if len(receiver_public) != 32:
        raise ValueError(f"Receiver public key must be 32 bytes, got {len(receiver_public)}")
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")

    hb = get_handle_backend()
    backend = get_default_backend()
    imported_handle = None

    try:
        if isinstance(ephemeral_private, bytes):
            private_handle = hb.import_x25519_private(ephemeral_private)
            imported_handle = private_handle
        else:
            private_handle = ephemeral_private

        shared_handle = hb.x25519_exchange(private_handle, receiver_public)

        # FIX-C3 v2: Full transcript binding
        # Use static_receiver_public for the transcript hash when provided
        # (decode side), otherwise use receiver_public (encode side).
        receiver_pub_for_binding = static_receiver_public or receiver_public
        if protocol_version is not None:
            bound_info = b"meow_fs_bound_v2:"
            bound_info += struct.pack(">B", protocol_version)
            bound_info += struct.pack(">B", mode_flags & 0xFF)
            bound_info += backend.sha256(receiver_pub_for_binding)
            if ephemeral_public is not None:
                if len(ephemeral_public) != 32:
                    raise ValueError(
                        f"Ephemeral public key must be 32 bytes, got {len(ephemeral_public)}"
                    )
                bound_info += ephemeral_public
            if pq_ciphertext_hash is not None:
                if len(pq_ciphertext_hash) != 32:
                    raise ValueError(
                        f"PQ ciphertext hash must be 32 bytes, got {len(pq_ciphertext_hash)}"
                    )
                bound_info += pq_ciphertext_hash
        else:
            bound_info = info

        password_bytes = password.encode("utf-8")
        derived_handle = hb.mix_hkdf(shared_handle, password_bytes, salt, bound_info, 32)

        # Drop intermediate handles but NOT derived_handle — caller owns it
        hb.drop(shared_handle)

        return derived_handle
    finally:
        if imported_handle is not None:
            try:
                hb.drop(imported_handle)
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


def generate_receiver_keypair() -> Tuple[int, bytes]:
    """
    Generate receiver's long-term X25519 keypair.

    Returns:
        Tuple of (private_key_handle: int, public_key_bytes: bytes)
        The private key is an opaque Rust handle.
    """
    hb = get_handle_backend()
    return hb.x25519_generate_keypair()


def save_receiver_keypair(
    private_key: Union[int, bytes],
    public_key: bytes,
    private_key_file: str,
    public_key_file: str,
    password: Optional[str] = None,
) -> None:
    """
    Save receiver keypair to files.

    Args:
        private_key: Either an opaque handle (int) or raw bytes (legacy).
    """
    hb = get_handle_backend()

    # Save public key (raw bytes)
    with open(public_key_file, "wb") as f:
        f.write(public_key)

    # Export private key bytes from handle (brief exposure for serialization)
    if isinstance(private_key, int):
        private_key_bytes = hb.export_key(private_key)
    else:
        private_key_bytes = private_key

    # Save private key (optionally encrypted with AES-256-GCM via handle backend)
    _MAGIC_ENCRYPTED = b"MEOW_X25519\x02"  # 12 bytes
    _MAGIC_PLAIN = b"MEOW_X25519\x01"  # 12 bytes

    try:
        if password:
            salt = secrets.token_bytes(16)
            # Derive storage key entirely inside Rust
            storage_key_handle = hb.derive_key_hkdf_raw(
                password.encode("utf-8"),
                salt,
                b"meow_x25519_key_storage_v2",
                32,
            )
            nonce = secrets.token_bytes(12)
            encrypted = hb.aes_gcm_encrypt(storage_key_handle, nonce, private_key_bytes, None)
            hb.drop(storage_key_handle)
            with open(private_key_file, "wb") as f:
                f.write(_MAGIC_ENCRYPTED + salt + nonce + encrypted)
        else:
            with open(private_key_file, "wb") as f:
                f.write(_MAGIC_PLAIN + private_key_bytes)
    finally:
        # Zero the exported private key bytes
        if isinstance(private_key_bytes, (bytearray, memoryview)):
            for i in range(len(private_key_bytes)):
                private_key_bytes[i] = 0


def load_x25519_private_key_pem(
    pem_data: bytes, password: Optional[str] = None
) -> Union[int, bytes]:
    """
    Load X25519 private key from MEOW_X25519 format.

    Args:
        pem_data: MEOW_X25519 private key data
        password: Password if key is encrypted

    Returns:
        Opaque handle (int) to the X25519 private key in Rust.
        Falls back to raw bytes if HandleBackend is unavailable.
    """
    _MAGIC_ENCRYPTED = b"MEOW_X25519\x02"
    _MAGIC_PLAIN = b"MEOW_X25519\x01"

    hb = get_handle_backend()

    if pem_data[:12] == _MAGIC_ENCRYPTED:
        if not password:
            raise ValueError("Private key is encrypted, password required")
        salt = pem_data[12:28]
        nonce = pem_data[28:40]
        encrypted = pem_data[40:]
        # Derive decryption key inside Rust
        storage_key_handle = hb.derive_key_hkdf_raw(
            password.encode("utf-8"),
            salt,
            b"meow_x25519_key_storage_v2",
            32,
        )
        raw_private = hb.aes_gcm_decrypt(storage_key_handle, nonce, encrypted, None)
        hb.drop(storage_key_handle)
        # Import decrypted private key into Rust handle immediately
        handle = hb.import_x25519_private(raw_private)
        # Zero transient copy
        if isinstance(raw_private, bytearray):
            for i in range(len(raw_private)):
                raw_private[i] = 0
        return handle
    elif pem_data[:12] == _MAGIC_PLAIN:
        raw_private = pem_data[12:44]
        return hb.import_x25519_private(raw_private)
    else:
        raise ValueError(
            "Unsupported key format. Expected MEOW_X25519 format (magic: MEOW_X25519\\x01 or "
            "MEOW_X25519\\x02). Legacy PEM keys are no longer supported. "
            "Please re-generate your keypair with save_receiver_keypair() in MEOW_X25519 format."
        )


def load_receiver_keypair(
    private_key_file: str, public_key_file: str, password: Optional[str] = None
) -> Tuple[Union[int, bytes], bytes]:
    """
    Load receiver keypair from files.

    Returns:
        Tuple of (private_key_handle: int, public_key_bytes: bytes)
    """
    # Load public key
    with open(public_key_file, "rb") as f:
        public_bytes = f.read()

    if len(public_bytes) != 32:
        raise ValueError(f"Invalid public key length: {len(public_bytes)}")

    public_key = public_bytes

    # Load private key (supports MEOW_X25519 formats)
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
