"""
Unified Ed25519 key management for v1.2/v1.3.1 spec.

Provides Ed25519 key generation/signing and RFC 8410 conversion to X25519.
"""

from __future__ import annotations

import logging
import platform
from abc import ABC, abstractmethod
from typing import Tuple


class KeyBackend(ABC):
    """Abstract key backend interface for Ed25519 keys."""

    @abstractmethod
    def generate_ed25519_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 keypair. Returns (secret_key_64, public_key_32)."""
        raise NotImplementedError

    @abstractmethod
    def ed25519_sign(self, message: bytes) -> bytes:
        """Sign message with stored Ed25519 key. Returns signature (64 bytes)."""
        raise NotImplementedError

    @abstractmethod
    def get_ed25519_public_key(self) -> bytes:
        """Retrieve Ed25519 public key (32 bytes)."""
        raise NotImplementedError

    @abstractmethod
    def get_backend_name(self) -> str:
        """Return backend name for logging."""
        raise NotImplementedError


class SecureEnclaveBackend(KeyBackend):
    """macOS/iOS Secure Enclave implementation (stub)."""

    @staticmethod
    def is_available() -> bool:
        return platform.system() == "Darwin" and False

    def generate_ed25519_keypair(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError("Secure Enclave backend not implemented")

    def ed25519_sign(self, message: bytes) -> bytes:
        raise NotImplementedError("Secure Enclave backend not implemented")

    def get_ed25519_public_key(self) -> bytes:
        raise NotImplementedError("Secure Enclave backend not implemented")

    def get_backend_name(self) -> str:
        return "Secure Enclave"


class TPMBackend(KeyBackend):
    """TPM 2.0 implementation (stub)."""

    @staticmethod
    def is_available() -> bool:
        return False

    def generate_ed25519_keypair(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError("TPM backend not implemented")

    def ed25519_sign(self, message: bytes) -> bytes:
        raise NotImplementedError("TPM backend not implemented")

    def get_ed25519_public_key(self) -> bytes:
        raise NotImplementedError("TPM backend not implemented")

    def get_backend_name(self) -> str:
        return "TPM"


class StrongBoxBackend(KeyBackend):
    """Android StrongBox implementation (stub)."""

    @staticmethod
    def is_available() -> bool:
        return False

    def generate_ed25519_keypair(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError("StrongBox backend not implemented")

    def ed25519_sign(self, message: bytes) -> bytes:
        raise NotImplementedError("StrongBox backend not implemented")

    def get_ed25519_public_key(self) -> bytes:
        raise NotImplementedError("StrongBox backend not implemented")

    def get_backend_name(self) -> str:
        return "StrongBox"


class SoftwareBackend(KeyBackend):
    """Software fallback with warning."""

    def __init__(self) -> None:
        logging.warning("⚠️  No hardware key storage available, using software fallback")
        logging.warning("⚠️  Ed25519 keys stored in memory/disk without hardware protection")
        self._private_key = None
        self._public_key = None

    def generate_ed25519_keypair(self) -> Tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        self._private_key = sk
        self._public_key = pk

        sk_bytes = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk_bytes = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return sk_bytes + pk_bytes, pk_bytes

    def ed25519_sign(self, message: bytes) -> bytes:
        if self._private_key is None:
            raise ValueError("No key loaded")
        return self._private_key.sign(message)

    def get_ed25519_public_key(self) -> bytes:
        if self._public_key is None:
            raise ValueError("No key loaded")
        from cryptography.hazmat.primitives import serialization

        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def get_backend_name(self) -> str:
        return "Software"


def get_best_backend() -> KeyBackend:
    """Select best available key storage backend."""
    if SecureEnclaveBackend.is_available():
        logging.info("✓ Using Secure Enclave for Ed25519 key storage")
        return SecureEnclaveBackend()
    if TPMBackend.is_available():
        logging.info("✓ Using TPM 2.0 for key storage")
        return TPMBackend()
    if StrongBoxBackend.is_available():
        logging.info("✓ Using Android StrongBox for key storage")
        return StrongBoxBackend()

    logging.warning("⚠️  Falling back to software Ed25519 key storage")
    return SoftwareBackend()


def ed25519_pk_to_x25519_pk(ed25519_pk: bytes) -> bytes:
    """Convert Ed25519 public key to X25519 public key (RFC 8410)."""
    try:
        from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519
    except ImportError as exc:
        raise ImportError("PyNaCl is required for Ed25519→X25519 conversion") from exc

    return crypto_sign_ed25519_pk_to_curve25519(ed25519_pk)


def ed25519_sk_to_x25519_sk(ed25519_sk: bytes) -> bytes:
    """Convert Ed25519 secret key to X25519 secret key (RFC 8410)."""
    try:
        from nacl.bindings import crypto_sign_ed25519_sk_to_curve25519
    except ImportError as exc:
        raise ImportError("PyNaCl is required for Ed25519→X25519 conversion") from exc

    return crypto_sign_ed25519_sk_to_curve25519(ed25519_sk)
