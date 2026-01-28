"""
Meow Decoder Crypto Backend - Unified Interface

This module provides a unified interface to cryptographic operations,
supporting both Python (cryptography library) and Rust (meow_crypto_rs) backends.

Usage:
    from meow_decoder.crypto_backend import CryptoBackend
    
    # Auto-select best available backend
    crypto = CryptoBackend()
    
    # Force specific backend
    crypto = CryptoBackend(backend="rust")  # or "python"
    
    # Use crypto operations
    key = crypto.derive_key_argon2id(password, salt)
    ciphertext = crypto.aes_gcm_encrypt(key, nonce, plaintext)

CLI Usage:
    meow-encode --crypto-backend rust ...
    meow-encode --crypto-backend python ...
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

# Python backend imports
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import hashlib


BackendType = Literal["python", "rust", "auto"]


@dataclass
class BackendInfo:
    """Information about the crypto backend."""
    name: str
    version: str
    constant_time: bool
    memory_zeroing: bool
    pq_available: bool
    details: str


class PythonCryptoBackend:
    """
    Python cryptography backend using 'cryptography' and 'argon2-cffi' libraries.
    
    Security Notes:
    - NOT guaranteed constant-time (Python GC, JIT)
    - Memory zeroing is best-effort
    - Still uses audited crypto libraries
    """
    
    NAME = "python"
    
    # Default Argon2id parameters (8x OWASP minimum - ULTRA HARDENED)
    ARGON2_MEMORY = 524288      # 512 MiB
    ARGON2_ITERATIONS = 20      # 20 passes
    ARGON2_PARALLELISM = 4      # 4 threads
    
    def get_info(self) -> BackendInfo:
        return BackendInfo(
            name="python",
            version="cryptography + argon2-cffi",
            constant_time=False,
            memory_zeroing=False,
            pq_available=False,
            details="Python backend using cryptography library. Not constant-time."
        )
    
    def derive_key_argon2id(
        self,
        password: bytes,
        salt: bytes,
        memory_kib: int = ARGON2_MEMORY,
        iterations: int = ARGON2_ITERATIONS,
        parallelism: int = ARGON2_PARALLELISM,
        output_len: int = 32
    ) -> bytes:
        """Derive key using Argon2id."""
        if len(salt) != 16:
            raise ValueError(f"Salt must be 16 bytes, got {len(salt)}")
        
        return low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=iterations,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=output_len,
            type=low_level.Type.ID
        )
    
    def derive_key_hkdf(
        self,
        ikm: bytes,
        salt: bytes,
        info: bytes,
        output_len: int = 32
    ) -> bytes:
        """Derive key using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=output_len,
            salt=salt if salt else None,
            info=info
        )
        return hkdf.derive(ikm)
    
    def hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """HKDF extract phase."""
        # Use HMAC for extract
        if not salt:
            salt = b'\x00' * 32
        h = HMAC(salt, hashes.SHA256())
        h.update(ikm)
        return h.finalize()
    
    def hkdf_expand(self, prk: bytes, info: bytes, output_len: int = 32) -> bytes:
        """HKDF expand phase."""
        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=output_len,
            info=info
        )
        return hkdf.derive(prk)

    def derive_key_yubikey(
        self,
        password: bytes,
        salt: bytes,
        slot: str = "9d",
        pin: Optional[str] = None
    ) -> bytes:
        raise RuntimeError(
            "YubiKey derivation requires the Rust backend built with the yubikey feature."
        )
    
    def aes_gcm_encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        """Encrypt using AES-256-GCM."""
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        if len(nonce) != 12:
            raise ValueError(f"Nonce must be 12 bytes, got {len(nonce)}")
        
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, plaintext, aad)
    
    def aes_gcm_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        """Decrypt using AES-256-GCM."""
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        if len(nonce) != 12:
            raise ValueError(f"Nonce must be 12 bytes, got {len(nonce)}")
        
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)
    
    def hmac_sha256(self, key: bytes, message: bytes) -> bytes:
        """Compute HMAC-SHA256."""
        h = HMAC(key, hashes.SHA256())
        h.update(message)
        return h.finalize()
    
    def hmac_sha256_verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        """Verify HMAC-SHA256 (uses constant-time comparison)."""
        expected = self.hmac_sha256(key, message)
        return secrets.compare_digest(expected, tag)
    
    def sha256(self, data: bytes) -> bytes:
        """Compute SHA-256 hash."""
        return hashlib.sha256(data).digest()
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time byte comparison."""
        return secrets.compare_digest(a, b)
    
    def x25519_generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate X25519 keypair. Returns (private_key, public_key)."""
        private = X25519PrivateKey.generate()
        public = private.public_key()
        
        from cryptography.hazmat.primitives import serialization
        
        private_bytes = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return private_bytes, public_bytes
    
    def x25519_exchange(self, private_key: bytes, public_key: bytes) -> bytes:
        """Perform X25519 key exchange."""
        private = X25519PrivateKey.from_private_bytes(private_key)
        public = X25519PublicKey.from_public_bytes(public_key)
        return private.exchange(public)
    
    def x25519_public_from_private(self, private_key: bytes) -> bytes:
        """Get public key from private key."""
        private = X25519PrivateKey.from_private_bytes(private_key)
        public = private.public_key()
        
        from cryptography.hazmat.primitives import serialization
        
        return public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def random_bytes(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return secrets.token_bytes(length)
    
    def secure_zero(self, data: bytearray) -> None:
        """Zero a bytearray (best-effort in Python)."""
        for i in range(len(data)):
            data[i] = 0


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
                "Rust crypto backend not available. "
                "Install with: pip install meow_crypto_rs "
                "or build with: cd rust_crypto && maturin develop"
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
    Unified crypto backend with automatic or manual backend selection.
    
    SECURITY NOTE:
        When available, Rust backend is STRONGLY PREFERRED because:
        - Constant-time operations (subtle crate) - prevents timing attacks
        - Automatic memory zeroing (zeroize crate) - prevents memory forensics
        - No Python GC interference - deterministic security properties
    
    Usage:
        crypto = CryptoBackend()  # Auto-select (prefers Rust if available)
        crypto = CryptoBackend(backend="rust")  # Force Rust (error if unavailable)
        crypto = CryptoBackend(backend="python")  # Force Python fallback
    
    Build Rust backend:
        cd rust_crypto && maturin develop --release
    """
    
    def __init__(self, backend: BackendType = "auto", allow_python_fallback: bool = False):
        """
        Initialize crypto backend.
        
        Args:
            backend: "auto" (default), "rust", or "python"
            allow_python_fallback: Allow Python fallback (requires --python-fallback CLI flag)
        """
        # Check environment variable override
        env_backend = os.environ.get("MEOW_CRYPTO_BACKEND", "").lower()
        if env_backend in ("rust", "python", "auto"):
            backend = env_backend
        
        # Check explicit enable flag (legacy/convenience)
        if os.environ.get("MEOW_USE_RUST", "0") == "1" or os.environ.get("MEOW_RUST", "0") == "1":
            backend = "rust"
        
        # Check fallback environment variable (explicit legacy opt-in)
        if os.environ.get("MEOW_LEGACY_PYTHON", "0") == "1":
            allow_python_fallback = True
        elif os.environ.get("MEOW_ALLOW_PYTHON_FALLBACK", "0") == "1":
            # Backward-compatible env var
            allow_python_fallback = True
        
        if backend == "auto":
            # SECURITY: Rust is REQUIRED by default for constant-time operations
            if _RUST_AVAILABLE:
                self._backend = RustCryptoBackend()
                # Rust is default and ideal - no warning needed
            elif allow_python_fallback:
                # User explicitly allowed Python fallback with --legacy-python flag
                self._backend = PythonCryptoBackend()
                import warnings
                warnings.warn(
                    "⚠️  SECURITY WARNING: Using Python backend (--legacy-python)\n"
                    "Python backend is NOT constant-time and may leak secrets via timing.\n"
                    "DO NOT USE for production/sensitive data.\n"
                    "Build Rust backend: cd rust_crypto && maturin develop --release\n"
                    "Or install via: pip install meow-decoder[rust]",
                    UserWarning,
                    stacklevel=2
                )
            else:
                # FAIL-CLOSED: No Rust, no explicit fallback = abort
                raise RuntimeError(
                    "🔒 SECURITY: Rust crypto backend required for constant-time operations!\n"
                    "\n"
                    "Option 1 (RECOMMENDED): Build Rust backend\n"
                    "  cd rust_crypto && maturin develop --release\n"
                    "\n"
                    "Option 2: Explicit fallback (NOT RECOMMENDED for sensitive data)\n"
                    "  meow-encode --legacy-python ...\n"
                    "\n"
                    "See: https://github.com/systemslibrarian/meow-decoder#rust-backend"
                )
        elif backend == "rust":
            if not _RUST_AVAILABLE:
                raise RuntimeError(
                    "Rust backend explicitly requested but not available.\n"
                    "Build: cd rust_crypto && maturin develop --release"
                )
            self._backend = RustCryptoBackend()
        elif backend == "python":
            if not allow_python_fallback:
                raise RuntimeError(
                    "Python backend requires explicit --legacy-python flag for safety"
                )
            self._backend = PythonCryptoBackend()
        else:
            raise ValueError(f"Unknown backend: {backend}. Use 'auto', 'rust', or 'python'")
    
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
    """Get the default crypto backend (auto-selected)."""
    global _default_backend
    if _default_backend is None:
        _default_backend = CryptoBackend()
    return _default_backend


def set_default_backend(backend: BackendType) -> None:
    """Set the default crypto backend."""
    global _default_backend
    _default_backend = CryptoBackend(backend)


def is_rust_available() -> bool:
    """Check if Rust backend is available."""
    return _RUST_AVAILABLE


def get_available_backends() -> list:
    """Get list of available backend names."""
    backends = ["python"]
    if _RUST_AVAILABLE:
        backends.insert(0, "rust")
    return backends


# Quick self-test
if __name__ == "__main__":
    print("🔐 Crypto Backend Test")
    print("=" * 60)
    
    print(f"\nAvailable backends: {get_available_backends()}")
    print(f"Rust available: {is_rust_available()}")
    
    # Test Python backend
    print("\n--- Python Backend ---")
    py_crypto = CryptoBackend(backend="python")
    print(f"Backend: {py_crypto.name}")
    
    # Test key derivation
    password = b"test_password_123"
    salt = secrets.token_bytes(16)
    
    # Use faster params for testing
    key = py_crypto.derive_key_argon2id(password, salt, memory_kib=32768, iterations=2)
    print(f"Argon2id key: {key.hex()[:32]}...")
    
    # Test encryption
    nonce = secrets.token_bytes(12)
    plaintext = b"Hello, Meow Decoder!"
    ciphertext = py_crypto.aes_gcm_encrypt(key, nonce, plaintext)
    decrypted = py_crypto.aes_gcm_decrypt(key, nonce, ciphertext)
    assert decrypted == plaintext, "Decryption failed!"
    print(f"AES-GCM: OK")
    
    # Test HMAC
    tag = py_crypto.hmac_sha256(key, plaintext)
    assert py_crypto.hmac_sha256_verify(key, plaintext, tag)
    print(f"HMAC-SHA256: OK")
    
    # Test X25519
    priv1, pub1 = py_crypto.x25519_generate_keypair()
    priv2, pub2 = py_crypto.x25519_generate_keypair()
    shared1 = py_crypto.x25519_exchange(priv1, pub2)
    shared2 = py_crypto.x25519_exchange(priv2, pub1)
    assert shared1 == shared2, "X25519 exchange failed!"
    print(f"X25519: OK")
    
    # Test Rust backend if available
    if is_rust_available():
        print("\n--- Rust Backend ---")
        rs_crypto = CryptoBackend(backend="rust")
        print(f"Backend: {rs_crypto.name}")
        
        # Same tests
        key_rs = rs_crypto.derive_key_argon2id(password, salt, memory_kib=32768, iterations=2)
        print(f"Argon2id key: {key_rs.hex()[:32]}...")
        
        # Keys should match!
        if key == key_rs:
            print("✅ Python and Rust produce identical keys!")
        else:
            print("⚠️  Keys differ (check parameters)")
    else:
        print("\n⚠️  Rust backend not installed. Build with:")
        print("   cd rust_crypto && maturin develop")
    
    print("\n✅ Backend test complete!")
