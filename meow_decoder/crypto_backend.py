"""
Meow Decoder Crypto Backend - Unified Interface

This module provides a unified interface to cryptographic operations,
requiring the Rust backend (meow_crypto_rs) for security.

Usage:
    from meow_decoder.crypto_backend import CryptoBackend
    
    # Rust backend is required
    crypto = CryptoBackend()
    key = crypto.derive_key_argon2id(password, salt)
    ciphertext = crypto.aes_gcm_encrypt(key, nonce, plaintext)
"""

import os
import secrets
from typing import Optional, Tuple, Union, Literal
from dataclasses import dataclass

# Try to import Rust backend
_RUST_AVAILABLE = False
_rust_backend = None

try:
    import meow_crypto_rs as _rust_backend
    _RUST_AVAILABLE = True
except ImportError:
    pass

# Note: Python crypto imports removed (see CRIT-03 in CRYPTO_SECURITY_REVIEW.md)
# The Rust backend is now required for all cryptographic operations.


BackendType = Literal["rust"]


@dataclass
class BackendInfo:
    """Information about the crypto backend."""
    name: str
    version: str
    constant_time: bool
    memory_zeroing: bool
    pq_available: bool
    details: str


# SECURITY NOTE (2026-01-28):
# PythonCryptoBackend has been removed to eliminate dead code risk.
# The Rust backend (RustCryptoBackend) is REQUIRED because:
#   - Constant-time operations (subtle crate) - prevents timing attacks
#   - Automatic memory zeroing (zeroize crate) - prevents memory forensics
#   - No Python GC interference - deterministic security properties
#
# See CRYPTO_SECURITY_REVIEW.md § CRIT-03 for rationale.


class RustCryptoBackend:
    """
    Rust cryptography backend using meow_crypto_rs.
    
    Security Properties:
    - Constant-time operations (subtle crate)
    - Automatic memory zeroing (zeroize crate)
    - Side-channel resistant
    """
    
    NAME = "rust"
    
    def __init__(self):
        if not _RUST_AVAILABLE:
            raise ImportError(
                "Rust crypto backend required. Install with: "
                "pip install maturin && cd rust_crypto && maturin develop --release"
            )
        self._rs = _rust_backend
    
    def get_info(self) -> BackendInfo:
        return BackendInfo(
            name="rust",
            version=self._rs.backend_info(),
            constant_time=True,
            memory_zeroing=True,
            pq_available=False,  # Will be True when pq feature enabled
            details=self._rs.backend_info()
        )
    
    def derive_key_argon2id(
        self,
        password: bytes,
        salt: bytes,
        memory_kib: int = 524288,
        iterations: int = 20,
        parallelism: int = 4,
        output_len: int = 32
    ) -> bytes:
        return self._rs.derive_key_argon2id(
            password, salt, memory_kib, iterations, parallelism, output_len
        )
    
    def derive_key_hkdf(
        self,
        ikm: bytes,
        salt: bytes,
        info: bytes,
        output_len: int = 32
    ) -> bytes:
        return self._rs.derive_key_hkdf(ikm, salt, info, output_len)
    
    def hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        return self._rs.hkdf_extract(salt, ikm)
    
    def hkdf_expand(self, prk: bytes, info: bytes, output_len: int = 32) -> bytes:
        return self._rs.hkdf_expand(prk, info, output_len)

    def derive_key_yubikey(
        self,
        password: bytes,
        salt: bytes,
        slot: str = "9d",
        pin: Optional[str] = None
    ) -> bytes:
        try:
            return self._rs.yubikey_derive_key(password, salt, slot, pin)
        except AttributeError as e:
            raise RuntimeError(
                "YubiKey support not enabled in Rust backend. Rebuild with: "
                "maturin develop --release --features yubikey"
            ) from e
    
    def aes_gcm_encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        return self._rs.aes_gcm_encrypt(key, nonce, plaintext, aad)
    
    def aes_gcm_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        return self._rs.aes_gcm_decrypt(key, nonce, ciphertext, aad)
    
    def hmac_sha256(self, key: bytes, message: bytes) -> bytes:
        return self._rs.hmac_sha256(key, message)
    
    def hmac_sha256_verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        return self._rs.hmac_sha256_verify(key, message, tag)
    
    def sha256(self, data: bytes) -> bytes:
        return self._rs.sha256(data)
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        return self._rs.constant_time_compare(a, b)
    
    def x25519_generate_keypair(self) -> Tuple[bytes, bytes]:
        return self._rs.x25519_generate_keypair()
    
    def x25519_exchange(self, private_key: bytes, public_key: bytes) -> bytes:
        return self._rs.x25519_exchange(private_key, public_key)
    
    def x25519_public_from_private(self, private_key: bytes) -> bytes:
        return self._rs.x25519_public_from_private(private_key)
    
    def random_bytes(self, length: int) -> bytes:
        return self._rs.secure_random(length)
    
    def secure_zero(self, data: bytearray) -> None:
        """
        Securely zero memory using Rust zeroize crate.
        
        Uses volatile writes to prevent compiler optimization.
        """
        try:
            self._rs.secure_zero(data)
        except (TypeError, AttributeError):
            # Fallback if Rust binding can't handle this bytearray
            for i in range(len(data)):
                data[i] = 0


class CryptoBackend:
    """
    Unified crypto backend (Rust-only).
    
    SECURITY NOTE:
        Rust backend is REQUIRED because:
        - Constant-time operations (subtle crate) - prevents timing attacks
        - Automatic memory zeroing (zeroize crate) - prevents memory forensics
        - No Python GC interference - deterministic security properties
    
    Usage:
        crypto = CryptoBackend()  # Rust backend required
        crypto = CryptoBackend(backend="rust")  # Rust only

    Build Rust backend:
        cd rust_crypto && maturin develop --release
    """
    
    def __init__(self, backend: BackendType = "rust"):
        """
        Initialize crypto backend.
        
        Args:
            backend: "rust" only
        """
        # Check environment variable override
        env_backend = os.environ.get("MEOW_CRYPTO_BACKEND", "").lower()
        if env_backend:
            backend = env_backend

        if backend != "rust":
            raise RuntimeError("Rust crypto backend required. Python fallback is disabled.")
        if not _RUST_AVAILABLE:
            raise RuntimeError(
                "Rust crypto backend required. Install with: "
                "pip install maturin && cd rust_crypto && maturin develop --release"
            )

        self._backend = RustCryptoBackend()
    
    @property
    def name(self) -> str:
        """Get backend name."""
        return self._backend.NAME
    
    def get_info(self) -> BackendInfo:
        """Get backend information."""
        return self._backend.get_info()
    
    # Delegate all crypto methods
    def derive_key_argon2id(self, *args, **kwargs) -> bytes:
        return self._backend.derive_key_argon2id(*args, **kwargs)
    
    def derive_key_hkdf(self, *args, **kwargs) -> bytes:
        return self._backend.derive_key_hkdf(*args, **kwargs)
    
    def hkdf_extract(self, *args, **kwargs) -> bytes:
        return self._backend.hkdf_extract(*args, **kwargs)
    
    def hkdf_expand(self, *args, **kwargs) -> bytes:
        return self._backend.hkdf_expand(*args, **kwargs)

    def derive_key_yubikey(self, *args, **kwargs) -> bytes:
        return self._backend.derive_key_yubikey(*args, **kwargs)
    
    def aes_gcm_encrypt(self, *args, **kwargs) -> bytes:
        return self._backend.aes_gcm_encrypt(*args, **kwargs)
    
    def aes_gcm_decrypt(self, *args, **kwargs) -> bytes:
        return self._backend.aes_gcm_decrypt(*args, **kwargs)
    
    def hmac_sha256(self, *args, **kwargs) -> bytes:
        return self._backend.hmac_sha256(*args, **kwargs)
    
    def hmac_sha256_verify(self, *args, **kwargs) -> bool:
        return self._backend.hmac_sha256_verify(*args, **kwargs)
    
    def sha256(self, *args, **kwargs) -> bytes:
        return self._backend.sha256(*args, **kwargs)
    
    def constant_time_compare(self, *args, **kwargs) -> bool:
        return self._backend.constant_time_compare(*args, **kwargs)
    
    def x25519_generate_keypair(self) -> Tuple[bytes, bytes]:
        return self._backend.x25519_generate_keypair()
    
    def x25519_exchange(self, *args, **kwargs) -> bytes:
        return self._backend.x25519_exchange(*args, **kwargs)
    
    def x25519_public_from_private(self, *args, **kwargs) -> bytes:
        return self._backend.x25519_public_from_private(*args, **kwargs)
    
    def random_bytes(self, length: int) -> bytes:
        return self._backend.random_bytes(length)
    
    def secure_zero(self, data: bytearray) -> None:
        return self._backend.secure_zero(data)


# Module-level convenience functions using default backend
_default_backend: Optional[CryptoBackend] = None


def get_default_backend() -> CryptoBackend:
    """Get the default crypto backend (Rust-only)."""
    global _default_backend
    if _default_backend is None:
        _default_backend = CryptoBackend()
    return _default_backend


def secure_zero_memory(buffer: bytearray) -> None:
    """
    Securely zero a memory buffer.
    
    Module-level convenience function that uses the default backend.
    
    Args:
        buffer: Mutable bytearray to zero
    """
    get_default_backend().secure_zero(buffer)


def set_default_backend(backend: BackendType) -> None:
    """Set the default crypto backend."""
    global _default_backend
    _default_backend = CryptoBackend(backend)


def is_rust_available() -> bool:
    """Check if Rust backend is available."""
    return _RUST_AVAILABLE


def get_available_backends() -> list:
    """Get list of available backend names."""
    return ["rust"] if _RUST_AVAILABLE else []


# Quick self-test
if __name__ == "__main__":
    print("🔐 Crypto Backend Test")
    print("=" * 60)
    
    print(f"\nAvailable backends: {get_available_backends()}")
    print(f"Rust available: {is_rust_available()}")
    
    print("\n--- Rust Backend ---")
    rs_crypto = CryptoBackend(backend="rust")
    print(f"Backend: {rs_crypto.name}")

    # Test key derivation
    password = b"test_password_123"
    salt = secrets.token_bytes(16)

    # Use faster params for testing
    key = rs_crypto.derive_key_argon2id(password, salt, memory_kib=32768, iterations=2)
    print(f"Argon2id key: {key.hex()[:32]}...")

    # Test encryption
    nonce = secrets.token_bytes(12)
    plaintext = b"Hello, Meow Decoder!"
    ciphertext = rs_crypto.aes_gcm_encrypt(key, nonce, plaintext)
    decrypted = rs_crypto.aes_gcm_decrypt(key, nonce, ciphertext)
    assert decrypted == plaintext, "Decryption failed!"
    print(f"AES-GCM: OK")
    
    # Test HMAC
    tag = rs_crypto.hmac_sha256(key, plaintext)
    assert rs_crypto.hmac_sha256_verify(key, plaintext, tag)
    print(f"HMAC-SHA256: OK")
    
    # Test X25519
    priv1, pub1 = rs_crypto.x25519_generate_keypair()
    priv2, pub2 = rs_crypto.x25519_generate_keypair()
    shared1 = rs_crypto.x25519_exchange(priv1, pub2)
    shared2 = rs_crypto.x25519_exchange(priv2, pub1)
    assert shared1 == shared2, "X25519 exchange failed!"
    print(f"X25519: OK")
    
    if not is_rust_available():
        print("\n⚠️  Rust backend not installed. Build with:")
        print("   cd rust_crypto && maturin develop")

    print("\n✅ Backend test complete!")
