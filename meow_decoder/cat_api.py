"""
🐾 Cat-Themed Façade API — Personality Layer (Layer 4)

This is the personality façade layer. No cryptographic logic is implemented
here. All primitives live in Rust (Layer 1) and are accessed through
crypto_backend.CryptoBackend (Layer 2).

Every function in this module is a thin, playful wrapper. Arguments are
forwarded without modification and return values are passed through
unchanged. No new cryptographic behavior is introduced.

See docs/ARCHITECTURE.md § "Architectural Layer Boundaries" for the
layer model that governs this module.

Usage:
    from meow_decoder.cat_api import purr_encrypt, nap_and_decrypt

    ciphertext = purr_encrypt(key, nonce, plaintext)
    plaintext  = nap_and_decrypt(key, nonce, ciphertext)
"""

from typing import Optional, Tuple

from meow_decoder.crypto_backend import CryptoBackend, get_default_backend

# ---------------------------------------------------------------------------
# Internal: lazily-initialised shared backend instance
# ---------------------------------------------------------------------------

_backend: Optional[CryptoBackend] = None


def _get_backend() -> CryptoBackend:
    """Return the shared CryptoBackend (Rust-only), creating it on first call."""
    global _backend
    if _backend is None:
        _backend = get_default_backend()
    return _backend


# ---------------------------------------------------------------------------
# 🔐  Symmetric Encryption / Decryption
# ---------------------------------------------------------------------------


def purr_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes] = None
) -> bytes:
    """Encrypt with a contented purr.  (AES-256-GCM)"""
    return _get_backend().aes_gcm_encrypt(key, nonce, plaintext, aad)


def nap_and_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None
) -> bytes:
    """Wake from a cozy nap and decrypt.  (AES-256-GCM)"""
    return _get_backend().aes_gcm_decrypt(key, nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# 🔑  Key Derivation
# ---------------------------------------------------------------------------


def knead_kdf(
    ikm: bytes, salt: bytes, info: bytes, output_len: int = 32
) -> bytes:
    """Knead the dough — derive a key.  (HKDF-SHA256)"""
    return _get_backend().derive_key_hkdf(ikm, salt, info, output_len)


def knead_argon2(
    password: bytes,
    salt: bytes,
    memory_kib: int = 524288,
    iterations: int = 20,
    parallelism: int = 4,
    output_len: int = 32,
) -> bytes:
    """Deep-knead biscuits — heavy key derivation.  (Argon2id)"""
    return _get_backend().derive_key_argon2id(
        password, salt, memory_kib, iterations, parallelism, output_len
    )


def knead_extract(salt: bytes, ikm: bytes) -> bytes:
    """Extract the good stuff.  (HKDF-Extract)"""
    return _get_backend().hkdf_extract(salt, ikm)


def knead_expand(prk: bytes, info: bytes, output_len: int = 32) -> bytes:
    """Stretch the dough further.  (HKDF-Expand)"""
    return _get_backend().hkdf_expand(prk, info, output_len)


# ---------------------------------------------------------------------------
# 🐾  Authentication
# ---------------------------------------------------------------------------


def scratch_mac(key: bytes, message: bytes) -> bytes:
    """Leave a scratch mark — compute a MAC.  (HMAC-SHA256)"""
    return _get_backend().hmac_sha256(key, message)


def sniff_mac(key: bytes, message: bytes, tag: bytes) -> bool:
    """Sniff the scratch mark — verify a MAC.  (HMAC-SHA256 verify)"""
    return _get_backend().hmac_sha256_verify(key, message, tag)


# ---------------------------------------------------------------------------
# 🧶  Hashing
# ---------------------------------------------------------------------------


def whisker_hash(data: bytes) -> bytes:
    """Twitch the whiskers — compute a hash.  (SHA-256)"""
    return _get_backend().sha256(data)


# ---------------------------------------------------------------------------
# 😼  Key Exchange
# ---------------------------------------------------------------------------


def hiss_exchange(private_key: bytes, public_key: bytes) -> bytes:
    """Hiss and exchange secrets.  (X25519 Diffie-Hellman)"""
    return _get_backend().x25519_exchange(private_key, public_key)


def spawn_keypair() -> Tuple[bytes, bytes]:
    """A new kitten is born — generate a keypair.  (X25519)"""
    return _get_backend().x25519_generate_keypair()


def show_public(private_key: bytes) -> bytes:
    """Show your face — derive the public key.  (X25519)"""
    return _get_backend().x25519_public_from_private(private_key)


# ---------------------------------------------------------------------------
# 🎲  Utilities
# ---------------------------------------------------------------------------


def catnip_random(length: int) -> bytes:
    """Scatter some catnip — generate random bytes."""
    return _get_backend().random_bytes(length)


def paw_compare(a: bytes, b: bytes) -> bool:
    """Touch paws — constant-time comparison."""
    return _get_backend().constant_time_compare(a, b)


def shred_yarn(data: bytearray) -> None:
    """Shred the yarn — securely zero memory."""
    return _get_backend().secure_zero(data)
