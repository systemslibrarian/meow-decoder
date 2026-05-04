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
import threading
from typing import Optional, Tuple, Union, Literal
from dataclasses import dataclass

# Try to import Rust backend
_RUST_AVAILABLE = False
_rust_backend = None

# Production guard: export_key() is forbidden outside test mode.
_PRODUCTION_MODE = os.environ.get("MEOW_PRODUCTION_MODE", "1") != "0"
_TEST_MODE = os.environ.get("MEOW_TEST_MODE", "").lower() in ("1", "true", "yes")

try:
    import meow_crypto_rs as _rust_backend  # pragma: no cover (module-level import)

    _RUST_AVAILABLE = True  # pragma: no cover (executes before coverage starts)
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
        if not _RUST_AVAILABLE:  # pragma: no cover
            raise ImportError(
                "Rust crypto backend required. Install with: "
                "pip install maturin && cd rust_crypto && maturin develop --release"
            )
        self._rs = _rust_backend  # pragma: no cover

    def get_info(self) -> BackendInfo:
        return BackendInfo(
            name="rust",
            version=self._rs.backend_info(),
            constant_time=True,
            memory_zeroing=True,
            pq_available=False,  # Will be True when pq feature enabled
            details=self._rs.backend_info(),
        )

    def derive_key_argon2id(
        self,
        password: bytes,
        salt: bytes,
        memory_kib: int = 524288,
        iterations: int = 20,
        parallelism: int = 4,
        output_len: int = 32,
    ) -> bytes:
        """PRODUCTION-FORBIDDEN: Returns raw key bytes.

        This method exists only for legacy test tooling and non-production
        diagnostics.  Production code MUST use
        ``HandleBackend.derive_key_argon2id()`` which returns an opaque
        handle and never exposes key bytes to Python.
        """
        return self._rs.derive_key_argon2id(  # type: ignore[no-any-return]
            password, salt, memory_kib, iterations, parallelism, output_len
        )

    def derive_key_hkdf(self, ikm: bytes, salt: bytes, info: bytes, output_len: int = 32) -> bytes:
        return self._rs.derive_key_hkdf(ikm, salt, info, output_len)  # type: ignore[no-any-return]

    def hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:  # pragma: no cover
        return self._rs.hkdf_extract(salt, ikm)  # type: ignore[no-any-return]

    def hkdf_expand(
        self, prk: bytes, info: bytes, output_len: int = 32
    ) -> bytes:  # pragma: no cover
        return self._rs.hkdf_expand(prk, info, output_len)  # type: ignore[no-any-return]

    def derive_key_yubikey(
        self, password: bytes, salt: bytes, slot: str = "9d", pin: Optional[str] = None
    ) -> bytes:  # pragma: no cover
        try:
            return self._rs.yubikey_derive_key(password, salt, slot, pin)  # type: ignore[no-any-return]
        except (AttributeError, ValueError) as e:
            raise RuntimeError(
                "YubiKey support not enabled in Rust backend. Rebuild with: "
                "maturin develop --release --features yubikey"
            ) from e

    def aes_ctr_crypt(self, key: bytes, nonce: bytes, data: bytes, byte_offset: int = 0) -> bytes:
        return self._rs.aes_ctr_crypt(key, nonce, data, byte_offset)  # type: ignore[no-any-return]

    def aes_gcm_encrypt(
        self, key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes] = None
    ) -> bytes:
        return self._rs.aes_gcm_encrypt(key, nonce, plaintext, aad)  # type: ignore[no-any-return]

    def aes_gcm_decrypt(
        self, key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None
    ) -> bytes:
        return self._rs.aes_gcm_decrypt(key, nonce, ciphertext, aad)  # type: ignore[no-any-return]

    def hmac_sha256(self, key: bytes, message: bytes) -> bytes:  # pragma: no cover
        return self._rs.hmac_sha256(key, message)  # type: ignore[no-any-return]

    def hmac_sha256_verify(
        self, key: bytes, message: bytes, tag: bytes
    ) -> bool:  # pragma: no cover
        return self._rs.hmac_sha256_verify(key, message, tag)  # type: ignore[no-any-return]

    def sha256(self, data: bytes) -> bytes:  # pragma: no cover
        return self._rs.sha256(data)  # type: ignore[no-any-return]

    def constant_time_compare(self, a: bytes, b: bytes) -> bool:  # pragma: no cover
        return self._rs.constant_time_compare(a, b)  # type: ignore[no-any-return]

    def x25519_generate_keypair(self) -> Tuple[bytes, bytes]:  # pragma: no cover
        return self._rs.x25519_generate_keypair()  # type: ignore[no-any-return]

    def x25519_exchange(self, private_key: bytes, public_key: bytes) -> bytes:  # pragma: no cover
        return self._rs.x25519_exchange(private_key, public_key)  # type: ignore[no-any-return]

    def x25519_public_from_private(self, private_key: bytes) -> bytes:  # pragma: no cover
        return self._rs.x25519_public_from_private(private_key)  # type: ignore[no-any-return]

    def random_bytes(self, length: int) -> bytes:  # pragma: no cover
        return self._rs.secure_random(length)  # type: ignore[no-any-return]

    def secure_zero(self, data: bytearray) -> None:
        """
        Securely zero memory using Rust zeroize crate.

        Uses volatile writes to prevent compiler optimization.
        Fail-closed: raises RuntimeError rather than falling back to a Python
        loop that may be optimized away and does not carry zeroize guarantees.
        """
        try:
            self._rs.secure_zero(data)
        except (TypeError, AttributeError) as exc:
            # F-5.4 fix: do NOT fall back to a Python loop — Python's GC and
            # interpreter can optimize away plain assignments, providing no
            # volatile-write or zeroize guarantees.  If the Rust binding
            # cannot handle this bytearray the call must fail loudly.
            raise RuntimeError(
                "secure_zero: Rust backend could not zero memory — "
                "refusing Python fallback (unsafe). "
                f"Original error: {exc}"
            ) from exc


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
        if env_backend:  # pragma: no cover
            backend = env_backend

        if backend != "rust":  # pragma: no cover
            raise RuntimeError("Rust crypto backend required. Python fallback is disabled.")
        if not _RUST_AVAILABLE:  # pragma: no cover
            raise RuntimeError(
                "Rust crypto backend required. Install with: "
                "pip install maturin && cd rust_crypto && maturin develop --release"
            )

        self._backend = RustCryptoBackend()

    @property
    def name(self) -> str:  # pragma: no cover
        """Get backend name."""
        return self._backend.NAME

    def get_info(self) -> BackendInfo:  # pragma: no cover
        """Get backend information."""
        return self._backend.get_info()

    # Delegate all crypto methods
    def derive_key_argon2id(self, *args, **kwargs) -> bytes:
        return self._backend.derive_key_argon2id(*args, **kwargs)

    def derive_key_hkdf(self, *args, **kwargs) -> bytes:  # pragma: no cover
        return self._backend.derive_key_hkdf(*args, **kwargs)

    def hkdf_extract(self, *args, **kwargs) -> bytes:  # pragma: no cover
        return self._backend.hkdf_extract(*args, **kwargs)

    def hkdf_expand(self, *args, **kwargs) -> bytes:  # pragma: no cover
        return self._backend.hkdf_expand(*args, **kwargs)

    def derive_key_yubikey(self, *args, **kwargs) -> bytes:  # pragma: no cover
        return self._backend.derive_key_yubikey(*args, **kwargs)

    def aes_ctr_crypt(self, *args, **kwargs) -> bytes:
        return self._backend.aes_ctr_crypt(*args, **kwargs)

    def aes_gcm_encrypt(self, *args, **kwargs) -> bytes:
        return self._backend.aes_gcm_encrypt(*args, **kwargs)

    def aes_gcm_decrypt(self, *args, **kwargs) -> bytes:
        return self._backend.aes_gcm_decrypt(*args, **kwargs)

    def hmac_sha256(self, *args, **kwargs) -> bytes:  # pragma: no cover
        return self._backend.hmac_sha256(*args, **kwargs)

    def hmac_sha256_verify(self, *args, **kwargs) -> bool:  # pragma: no cover
        return self._backend.hmac_sha256_verify(*args, **kwargs)

    def sha256(self, *args, **kwargs) -> bytes:  # pragma: no cover
        return self._backend.sha256(*args, **kwargs)

    def constant_time_compare(self, *args, **kwargs) -> bool:  # pragma: no cover
        return self._backend.constant_time_compare(*args, **kwargs)

    def x25519_generate_keypair(self) -> Tuple[bytes, bytes]:  # pragma: no cover
        return self._backend.x25519_generate_keypair()

    def x25519_exchange(self, *args, **kwargs) -> bytes:  # pragma: no cover
        return self._backend.x25519_exchange(*args, **kwargs)

    def x25519_public_from_private(self, *args, **kwargs) -> bytes:  # pragma: no cover
        return self._backend.x25519_public_from_private(*args, **kwargs)

    def random_bytes(self, length: int) -> bytes:  # pragma: no cover
        return self._backend.random_bytes(length)

    def secure_zero(self, data: bytearray) -> None:
        return self._backend.secure_zero(data)


# Module-level convenience functions using default backend
_default_backend: Optional[CryptoBackend] = None
_default_backend_lock = threading.Lock()


def get_default_backend() -> CryptoBackend:
    """Get the default crypto backend (Rust-only).

    Locked to prevent two callers from simultaneously creating distinct
    CryptoBackend instances under the singleton — the second instance
    would silently leak its initialization work and any subsequent state.
    """
    global _default_backend
    if _default_backend is None:
        with _default_backend_lock:
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


def set_default_backend(backend: BackendType) -> None:  # pragma: no cover
    """Set the default crypto backend."""
    global _default_backend
    _default_backend = CryptoBackend(backend)


def is_rust_available() -> bool:  # pragma: no cover
    """Check if Rust backend is available."""
    return _RUST_AVAILABLE


def get_available_backends() -> list:  # pragma: no cover
    """Get list of available backend names."""
    return ["rust"] if _RUST_AVAILABLE else []


# ─── Opaque Handle API ──────────────────────────────────────────────────────
# All secret material stays inside Rust. Python sees only integer handle IDs
# and non-secret outputs (ciphertext, public keys, tags, plaintext after auth).
# This eliminates Rules #2 and #9 violations.


class HandleBackend:
    """
    Handle-based crypto backend where secrets NEVER enter Python.

    Usage:
        hb = HandleBackend()
        key_h = hb.derive_key_argon2id(password, salt)
        ct = hb.aes_gcm_encrypt(key_h, nonce, plaintext, aad)
        pt = hb.aes_gcm_decrypt(key_h, nonce, ct, aad)
        hb.drop(key_h)
    """

    def __init__(self):
        if not _RUST_AVAILABLE:  # pragma: no cover
            raise ImportError("Rust crypto backend required for handle API")
        self._rs = _rust_backend

    # ── Key derivation (returns handles, not key bytes) ──

    def derive_key_argon2id(
        self,
        password: bytes,
        salt: bytes,
        memory_kib: int = 524288,
        iterations: int = 20,
        parallelism: int = 4,
    ) -> int:
        """Derive key via Argon2id. Returns opaque handle ID."""
        return self._rs.handle_derive_key_argon2id(
            password, salt, memory_kib, iterations, parallelism
        )

    def derive_key_argon2id_with_keyfile(
        self,
        password: bytes,
        keyfile: bytes,
        keyfile_domain_sep: bytes,
        salt: bytes,
        memory_kib: int = 524288,
        iterations: int = 20,
        parallelism: int = 4,
    ) -> int:
        """Derive key via HKDF(password||keyfile) → Argon2id. Returns handle.

        No intermediate secret bytes cross the FFI boundary. The HKDF
        combination and Argon2id derivation are performed entirely in Rust.
        """
        return self._rs.handle_derive_key_argon2id_with_keyfile(
            password,
            keyfile,
            keyfile_domain_sep,
            salt,
            memory_kib,
            iterations,
            parallelism,
        )

    def derive_key_yubikey(
        self,
        password: bytes,
        salt: bytes,
        slot: str = "9d",
        pin: Optional[str] = None,
    ) -> int:
        """Derive key via YubiKey and store as handle. Key never enters Python.

        Returns opaque handle ID. Raises RuntimeError if YubiKey feature
        is not enabled in the Rust backend.
        """
        return self._rs.handle_yubikey_derive_key(password, salt, slot, pin)

    def derive_key_hkdf(
        self, ikm_handle: int, salt: bytes, info: bytes, output_len: int = 32
    ) -> int:
        """Derive key via HKDF from an existing key handle. Returns new handle."""
        return self._rs.handle_derive_hkdf(ikm_handle, salt, info, output_len)

    def derive_key_hkdf_raw(
        self, ikm: bytes, salt: bytes, info: bytes, output_len: int = 32
    ) -> int:
        """Derive key via HKDF from raw IKM bytes. Returns handle."""
        return self._rs.handle_derive_hkdf_raw(ikm, salt, info, output_len)

    def import_key(self, key_bytes: bytes) -> int:
        """Import raw key bytes into an opaque handle. Caller MUST zeroize their copy."""
        return self._rs.handle_import_key(key_bytes)

    def derive_key_hkdf_bytes(
        self, ikm_handle: int, salt: bytes, info: bytes, output_len: int = 32
    ) -> bytes:
        """Derive HKDF from handle, return raw bytes.
        USE ONLY for non-secret derived values (nonces, header masks)."""
        return self._rs.handle_derive_hkdf_bytes(ikm_handle, salt, info, output_len)

    # ── AEAD (key stays in Rust) ──

    def aes_gcm_encrypt(
        self, key_handle: int, nonce: bytes, plaintext: bytes, aad: Optional[bytes] = None
    ) -> bytes:
        """Encrypt via AES-256-GCM using key handle. Returns ciphertext."""
        return self._rs.handle_aes_gcm_encrypt(key_handle, nonce, plaintext, aad)

    def aes_gcm_decrypt(
        self, key_handle: int, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None
    ) -> bytes:
        """Decrypt via AES-256-GCM using key handle. Fail-closed."""
        return self._rs.handle_aes_gcm_decrypt(key_handle, nonce, ciphertext, aad)

    # ── HMAC (key stays in Rust) ──

    def hmac_sha256(self, key_handle: int, message: bytes) -> bytes:
        """Compute HMAC-SHA256 using key handle. Returns tag."""
        return self._rs.handle_hmac_sha256(key_handle, message)

    def hmac_sha256_verify(self, key_handle: int, message: bytes, expected_tag: bytes) -> bool:
        """Verify HMAC-SHA256 constant-time using key handle."""
        return self._rs.handle_hmac_sha256_verify(key_handle, message, expected_tag)

    def hmac_sha256_prefixed(self, key_handle: int, prefix: bytes, message: bytes) -> bytes:
        """Compute HMAC-SHA256 with effective key = prefix || handle_key.
        All key material stays in Rust. No export needed."""
        return self._rs.handle_hmac_sha256_prefixed(key_handle, prefix, message)

    def hmac_sha256_prefixed_verify(
        self, key_handle: int, prefix: bytes, message: bytes, expected_tag: bytes
    ) -> bool:
        """Verify HMAC-SHA256 with prefixed key in constant time."""
        return self._rs.handle_hmac_sha256_prefixed_verify(
            key_handle, prefix, message, expected_tag
        )

    # ── X25519 (private key stays in Rust) ──

    def x25519_generate_keypair(self) -> tuple:
        """Generate X25519 keypair. Returns (handle_id, public_key_bytes).
        Private key NEVER leaves Rust."""
        return self._rs.handle_x25519_generate()

    def x25519_exchange(self, private_handle: int, peer_public: bytes) -> int:
        """X25519 key exchange. Returns handle to shared secret."""
        return self._rs.handle_x25519_exchange(private_handle, peer_public)

    def x25519_public(self, handle: int) -> bytes:
        """Get public key from X25519 private key handle."""
        return self._rs.handle_x25519_public(handle)

    def import_x25519_private(self, private_bytes: bytes) -> int:
        """Import raw X25519 private key bytes into an opaque handle.
        Caller MUST zeroize their copy of private_bytes."""
        return self._rs.handle_import_x25519_private(private_bytes)

    # ── Session / Stream / Ratchet handles ──

    def session_new(self, enc_key_handle: int, mac_key_handle: Optional[int] = None) -> int:
        """Create session from key handles."""
        return self._rs.handle_session_new(enc_key_handle, mac_key_handle)

    def stream_new(self, enc_key_handle: int, nonce: bytes, mac_domain: bytes) -> int:
        """Create stream state for streaming encrypt/decrypt."""
        return self._rs.handle_stream_new(enc_key_handle, nonce, mac_domain)

    def stream_encrypt(self, stream_handle: int, plaintext: bytes) -> tuple:
        """Stream encrypt. Returns (ciphertext, mac_tag)."""
        return self._rs.handle_stream_encrypt(stream_handle, plaintext)

    def stream_decrypt(self, stream_handle: int, ciphertext: bytes, expected_mac: bytes) -> bytes:
        """Stream decrypt. Verifies MAC first (fail-closed)."""
        return self._rs.handle_stream_decrypt(stream_handle, ciphertext, expected_mac)

    def stream_ctr_crypt(self, stream_handle: int, data: bytes) -> bytes:
        """AES-CTR crypt a chunk using stream handle (key stays in Rust)."""
        return self._rs.handle_stream_ctr_crypt(stream_handle, data)

    def stream_hmac(self, stream_handle: int, message: bytes) -> bytes:
        """Compute HMAC-SHA256 using stream handle's MAC key."""
        return self._rs.handle_stream_hmac(stream_handle, message)

    def stream_hmac_verify(self, stream_handle: int, message: bytes, expected_tag: bytes) -> bool:
        """Verify HMAC-SHA256 using stream handle's MAC key (constant-time)."""
        return self._rs.handle_stream_hmac_verify(stream_handle, message, expected_tag)

    def stream_nonce(self, stream_handle: int) -> bytes:
        """Get nonce from stream handle (non-secret metadata)."""
        return self._rs.handle_stream_nonce(stream_handle)

    def stream_reset_offset(self, stream_handle: int) -> None:
        """Reset stream byte offset to 0."""
        return self._rs.handle_stream_reset_offset(stream_handle)

    def aes_ctr_crypt_handle(
        self, key_handle: int, nonce: bytes, data: bytes, byte_offset: int = 0
    ) -> bytes:
        """AES-CTR crypt using any key handle (key stays in Rust)."""
        return self._rs.handle_aes_ctr_crypt(key_handle, nonce, data, byte_offset)

    def ratchet_new(self, root_key_handle: int, salt: bytes, root_info: bytes) -> int:
        """Create ratchet from root key handle."""
        return self._rs.handle_ratchet_new(root_key_handle, salt, root_info)

    def ratchet_step(self, ratchet_handle: int, step_info: bytes, msg_info: bytes) -> int:
        """Advance ratchet chain. Returns message key handle."""
        return self._rs.handle_ratchet_step(ratchet_handle, step_info, msg_info)

    # ── Mixed HKDF (key stays in Rust) ──

    def mix_hkdf(
        self, ikm_handle: int, extra_ikm: bytes, salt: bytes, info: bytes, output_len: int = 32
    ) -> int:
        """HKDF with handle key concatenated with extra IKM. Returns handle.
        Used for beacon mixing: HKDF(message_key || beacon_secret, salt, info)."""
        return self._rs.handle_mix_hkdf(ikm_handle, extra_ikm, salt, info, output_len)

    def hkdf_with_handle_salt(
        self, ikm: bytes, salt_handle: int, info: bytes, output_len: int = 32
    ) -> int:
        """HKDF where salt is a handle's key bytes, IKM is raw bytes. Returns handle.
        Used for asymmetric root rekey: HKDF(IKM=shared, salt=root_key, info=...)."""
        return self._rs.handle_hkdf_with_handle_salt(ikm, salt_handle, info, output_len)

    def hkdf_expand(self, prk_handle: int, info: bytes, output_len: int = 32) -> int:
        """HKDF-Expand only (no Extract). Treats handle key as PRK. Returns handle.
        Used for chain key derivation in double ratchet."""
        return self._rs.handle_hkdf_expand(prk_handle, info, output_len)

    def hkdf_two_handles(
        self, ikm_handle: int, salt_handle: int, info: bytes, output_len: int = 32
    ) -> int:
        """Full HKDF where both IKM and salt come from handles. Returns handle.
        Used for double ratchet root key derivation."""
        return self._rs.handle_hkdf_two_handles(ikm_handle, salt_handle, info, output_len)

    # ── PQXDH Hybrid (all secrets stay in Rust) ──

    def pqxdh_encapsulate(
        self,
        receiver_classical_pub: bytes,
        pq_shared_secret: Optional[bytes],
        extract_salt: bytes,
        info_prefix: bytes,
        transcript_domain: bytes,
        receiver_pq_pub: Optional[bytes] = None,
        pq_ciphertext: Optional[bytes] = None,
    ) -> tuple:
        """PQXDH hybrid encapsulation — full key agreement inside Rust.

        Returns (shared_secret_handle, ephemeral_public_bytes).
        No secret bytes cross the FFI boundary.
        """
        return self._rs.handle_pqxdh_encapsulate(
            receiver_classical_pub,
            pq_shared_secret,
            extract_salt,
            info_prefix,
            transcript_domain,
            receiver_pq_pub,
            pq_ciphertext,
        )

    def pqxdh_decapsulate(
        self,
        ephemeral_classical_pub: bytes,
        receiver_private_handle: int,
        pq_shared_secret: Optional[bytes],
        receiver_classical_pub: bytes,
        extract_salt: bytes,
        info_prefix: bytes,
        transcript_domain: bytes,
        receiver_pq_pub: Optional[bytes] = None,
        pq_ciphertext: Optional[bytes] = None,
    ) -> int:
        """PQXDH hybrid decapsulation — full key agreement inside Rust.

        Returns shared_secret_handle. No secret bytes cross FFI.
        """
        return self._rs.handle_pqxdh_decapsulate(
            ephemeral_classical_pub,
            receiver_private_handle,
            pq_shared_secret,
            receiver_classical_pub,
            extract_salt,
            info_prefix,
            transcript_domain,
            receiver_pq_pub,
            pq_ciphertext,
        )

    # ── Handle lifecycle ──

    def drop(self, handle_id: int) -> None:
        """Zeroize and free a handle."""
        self._rs.handle_drop(handle_id)

    def seal_key(
        self,
        payload_handle: int,
        encryption_key_handle: int,
        nonce: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Seal payload handle's key bytes under encryption_key_handle (AES-256-GCM).

        Both keys remain in Rust; only the AEAD ciphertext (32-byte key + 16-byte
        tag = 48 bytes) crosses the FFI. Use for encrypted-at-rest persistence
        of long-lived keys without ever exposing plaintext to Python.
        """
        return self._rs.handle_seal_key(payload_handle, encryption_key_handle, nonce, aad)

    def unseal_key(
        self,
        ciphertext: bytes,
        encryption_key_handle: int,
        nonce: bytes,
        aad: Optional[bytes] = None,
    ) -> int:
        """Unseal a sealed key blob to a new SymmetricKey handle. Fail-closed."""
        return self._rs.handle_unseal_key(ciphertext, encryption_key_handle, nonce, aad)

    def export_key(self, handle_id: int) -> bytes:
        """PRODUCTION-FORBIDDEN: Export raw key bytes from handle.

        This method is ONLY for test tooling and encrypted-at-rest
        serialization.  Production code MUST NOT call this — use
        handle-based AEAD/HMAC instead.

        FIX: Gate on PRODUCTION_MODE alone — MEOW_TEST_MODE can no longer
        bypass the production guard.  This prevents an env-var attacker
        from setting both MEOW_PRODUCTION_MODE=1 and MEOW_TEST_MODE=1
        to extract raw key bytes.
        """
        if _PRODUCTION_MODE:
            raise RuntimeError(
                "export_key() is PRODUCTION-FORBIDDEN. "
                "Use handle-based AEAD/HMAC operations instead. "
                "Set MEOW_PRODUCTION_MODE=0 to use in tests (MEOW_TEST_MODE "
                "alone is no longer sufficient)."
            )
        return self._rs.handle_export_key(handle_id)

    def exists(self, handle_id: int) -> bool:
        """Check if handle exists."""
        return self._rs.handle_exists(handle_id)

    def count(self) -> int:
        """Get current handle count."""
        return self._rs.handle_count()


_default_handle_backend: Optional[HandleBackend] = None
_default_handle_backend_lock = threading.Lock()


def get_handle_backend() -> HandleBackend:
    """Get the default handle-based crypto backend.

    Same singleton-init race protection as get_default_backend().
    """
    global _default_handle_backend
    if _default_handle_backend is None:
        with _default_handle_backend_lock:
            if _default_handle_backend is None:
                _default_handle_backend = HandleBackend()
    return _default_handle_backend


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
