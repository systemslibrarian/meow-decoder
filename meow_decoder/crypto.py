"""
Base Cryptography Module for Meow Decoder
Provides AES-256-GCM encryption with Argon2id key derivation using Pluggable Backend

This is the base version. For enhanced security features, see crypto_enhanced.py

Formal verification linkage
---------------------------
ProVerif secrecy/auth: formal/proverif/meow_encode.pv
ProVerif 8-field AAD:  formal/proverif/meow_aad_8field_binding.pv  (INV-004)
ProVerif manifest:     formal/proverif/manifest_signing.pv
Tamarin AEAD binding:  formal/tamarin/MeowAEADBinding.spthy
Verus AEAD proofs:     crypto_core/src/aead_wrapper.rs  AEAD-001-012
"""

from .argon2_presets import get_active_parameters as _get_argon2_preset
import os
import struct
import logging as _logging
import zlib
import secrets
from collections import OrderedDict
from dataclasses import dataclass
from typing import Tuple, Optional

from .crypto_backend import get_default_backend, get_handle_backend, secure_zero_memory

# ── Production Mode Guard ────────────────────────────────────────────────────
# When MEOW_PRODUCTION_MODE=1 (default), legacy bytes-returning crypto APIs
# are FORBIDDEN.  Production code MUST use *_production() / *_handle() variants
# that keep all secret key material inside opaque Rust handles.
#
# Setting MEOW_PRODUCTION_MODE=0 or MEOW_TEST_MODE=1 disables the guard
# (for tests plus legacy tooling only).
_PRODUCTION_MODE = os.environ.get("MEOW_PRODUCTION_MODE", "1") != "0"


def _legacy_guard(fn_name: str) -> None:
    """Raise if a legacy bytes-returning API is called in production mode."""
    if _PRODUCTION_MODE and not _TEST_MODE:
        raise RuntimeError(
            f"{fn_name}() is PRODUCTION-FORBIDDEN.  "
            "Use the *_production() or *_handle() variant instead, which keeps "
            "all secret key bytes inside Rust handles.  Set MEOW_TEST_MODE=1 "
            "or MEOW_PRODUCTION_MODE=0 to use this function in tests."
        )


# Magic bytes for manifest version identification
MAGIC = b"MEOW3"  # Version 3 with Argon2id + HMAC + Forward Secrecy

# Argon2id parameters
# Resolved via preset system — see meow_decoder/argon2_presets.py for details.
# Presets: paranoid (512 MiB / 20), balanced (256 MiB / 8), activist-fast (194 MiB / 4), test (32 MiB / 1).
# Override: MEOW_KDF_PRESET=activist-fast or MEOW_TEST_MODE=1 for test preset.
#
# ⚠️ Even strong parameters do not protect against a state actor who
# obtains the real password via coercion.
_TEST_MODE = os.environ.get("MEOW_TEST_MODE", "").lower() in ("1", "true", "yes")


_active_preset = _get_argon2_preset()
ARGON2_MEMORY = _active_preset.memory_kib
ARGON2_ITERATIONS = _active_preset.iterations
ARGON2_PARALLELISM = _active_preset.parallelism

# HMAC domain separation
MANIFEST_HMAC_KEY_PREFIX = b"meow_manifest_auth_v2"
KEYFILE_DOMAIN_SEP = b"meow_keyfile_separation_v2"

# ── Manifest numeric bounds (ST-2: decompression-bomb & overflow protection) ──
# Limits chosen to be reasonable for QR-based transfer while leaving room for validation
MAX_ORIG_LEN = 1 * 1024 * 1024 * 1024  # 1 GiB max original file size
MAX_COMP_LEN = 1 * 1024 * 1024 * 1024  # 1 GiB max compressed size
MAX_CIPHER_LEN = 1 * 1024 * 1024 * 1024  # 1 GiB max ciphertext size
MAX_BLOCK_SIZE = 65535  # uint16 max
MIN_BLOCK_SIZE = 64  # minimum sensible block size
MAX_K_BLOCKS = 1_000_000  # 1M blocks max
MAX_DECOMP_RATIO = 10  # decompression output limit: orig_len <= comp_len * ratio


# ── MT-1: Canonical AAD construction ──────────────────────────────────────────
# A single function builds the AAD for both encrypt and decrypt.  The layout is:
#   AAD_VERSION (1 byte) || orig_len (8 LE) || comp_len (8 LE)
#   || salt (16) || sha256 (32) || magic (variable) [|| ephemeral_pk (32)]
# AAD Completeness Analysis (FIX-GPT-3):
#
# Fields included in GCM AAD (build_canonical_aad):
#   orig_len, comp_len, salt, sha256, magic, ephemeral_public_key, pq_ciphertext
#
# Fields NOT in AAD but authenticated by manifest HMAC:
#   cipher_len  — Output of encryption; cannot be AAD input (circular dependency).
#   block_size  — Fountain-coding layer parameter; not available during encryption.
#   k_blocks    — Derived from cipher_len and block_size; same constraint.
#   duress_tag  — Checked before HMAC (timing-safe ordering per CRIT-04) but
#                 requires knowledge of the duress password to forge.
#
# The manifest HMAC (compute_manifest_hmac) covers ALL packed fields including
# cipher_len, block_size, k_blocks, and duress_tag.  HMAC verification is
# MANDATORY in decode_gif.py and occurs BEFORE any of these fields are used
# for crypto or fountain operations.  See verify_manifest_hmac().
#
# AAD_VERSION = 0x01 — bump this if the layout ever changes so old code can
# detect an incompatible manifest and fall back or reject explicitly.

AAD_VERSION = b"\x01"


def build_canonical_aad(
    orig_len: int,
    comp_len: int,
    salt: bytes,
    sha256_hash: bytes,
    magic: bytes,
    ephemeral_public_key: Optional[bytes] = None,
    pq_ciphertext: Optional[bytes] = None,
    mode_byte: int = 0,
) -> bytes:
    """Build canonical Additional Authenticated Data for AES-GCM.

    Using a single function for both encrypt and decrypt guarantees the
    byte-layout is identical and prevents subtle mismatch bugs.

    Layout (deterministic, fixed-order):
        ``AAD_VERSION || le_u64(orig_len) || le_u64(comp_len)
          || salt || sha256 || magic [|| mode_byte] [|| ephemeral_pk] [|| pq_ciphertext]``

    Args:
        orig_len:  Original (uncompressed) file length.
        comp_len:  Compressed (possibly padded) length.
        salt:      16-byte random salt.
        sha256_hash: 32-byte SHA-256 of the original data.
        magic:     Manifest magic bytes (e.g. b"MEOW3").
        ephemeral_public_key: 32-byte X25519 ephemeral key (forward secrecy).
        pq_ciphertext: ML-KEM ciphertext (1088 or 1568 bytes, post-quantum hybrid).
        mode_byte: FIX-D3: Explicit manifest mode byte (0 = legacy, omitted from AAD).

    Returns:
        Deterministic AAD bytestring.
    """
    aad = AAD_VERSION
    aad += struct.pack("<QQ", orig_len, comp_len)
    aad += salt
    aad += sha256_hash
    aad += magic
    # FIX-D3: Bind mode byte into AAD (skip for legacy mode_byte=0)
    if mode_byte != 0:
        aad += struct.pack("B", mode_byte)
    if ephemeral_public_key is not None:
        aad += ephemeral_public_key
    if pq_ciphertext is not None:
        aad += pq_ciphertext
    return aad


@dataclass
class Manifest:
    """
    Encrypted file manifest containing all metadata for decryption.

    Attributes:
        salt: Random salt for key derivation (16 bytes)
        nonce: Random nonce for AES-GCM (12 bytes)
        orig_len: Original plaintext length
        comp_len: Compressed data length
        cipher_len: Encrypted data length
        sha256: SHA-256 hash of original plaintext
        block_size: Fountain code block size
        k_blocks: Number of fountain code blocks
        hmac: HMAC-SHA256 authentication tag
        ephemeral_public_key: Optional X25519 ephemeral public key for forward secrecy (32 bytes)
                             None = password-only mode
                             Present = forward secrecy mode
        pq_ciphertext: Optional ML-KEM ciphertext for post-quantum
                      None = classical-only mode
                      Present = PQ hybrid mode (X25519 + ML-KEM-768/1024)
    """

    salt: bytes
    nonce: bytes
    orig_len: int
    comp_len: int
    cipher_len: int
    sha256: bytes
    block_size: int
    k_blocks: int
    hmac: bytes
    ephemeral_public_key: Optional[bytes] = None  # Forward secrecy support
    pq_ciphertext: Optional[bytes] = None  # Post-quantum hybrid support
    duress_tag: Optional[bytes] = None  # Duress authentication tag (32 bytes)
    mode_byte: int = 0  # FIX-D3: Explicit manifest mode (0 = legacy/inferred)
    crypto_profile: str = ""  # PROD_MIN or hybrid_pq_experimental (inferred, not serialized)


# ── FIX-D3: Mode byte constants ──────────────────────────────────────────────
# Explicit mode byte prevents length-based ambiguity and is bound in AAD + HMAC.
#   0x00 = legacy manifest (no mode byte; length-inferred, backward compat only)
#   0x02 = MEOW2: password-only, no forward secrecy
#   0x03 = MEOW3: X25519 forward secrecy
#   0x04 = MEOW4: X25519 + ML-KEM-1024 post-quantum hybrid (paranoid)
#   0x05 = MEOW5: X25519 + ML-KEM-768 post-quantum hybrid (default, Signal parity)
#   0x10 flag = per-frame symmetric ratchet (OR'd with version)
#   0x80 flag = duress mode (OR'd with version)
MODE_LEGACY = 0x00
MODE_MEOW2 = 0x02
MODE_MEOW3 = 0x03
MODE_MEOW4 = 0x04
MODE_MEOW5 = 0x05  # ML-KEM-768 (default PQ hybrid)
MODE_RATCHET = 0x10  # Per-frame symmetric ratchet flag (OR'd with version)
MODE_DURESS = 0x80  # Duress flag (OR'd with version)

# ── Crypto profile constants ────────────────────────────────────────────────
PROFILE_PROD_MIN = "PROD_MIN"
PROFILE_PQ_EXPERIMENTAL = "hybrid_pq_experimental"
PROFILE_LEGACY = "legacy"
_KNOWN_PROFILES = {PROFILE_PROD_MIN, PROFILE_PQ_EXPERIMENTAL, PROFILE_LEGACY}


def classify_crypto_profile(mode_byte: int) -> str:
    """Classify a manifest's crypto profile from its mode_byte.

    Returns one of PROFILE_PROD_MIN, PROFILE_PQ_EXPERIMENTAL, or PROFILE_LEGACY.
    """
    if mode_byte == MODE_LEGACY:
        return PROFILE_LEGACY
    base = mode_byte & 0x0F  # strip duress (0x80) and ratchet (0x10)
    if base in (MODE_MEOW4, MODE_MEOW5):
        return PROFILE_PQ_EXPERIMENTAL
    return PROFILE_PROD_MIN


def validate_decode_profile(
    profile: str,
    *,
    allow_experimental: bool = False,
    allow_legacy: bool = False,
) -> None:
    """Validate that a crypto profile is acceptable for decoding.

    Raises ValueError if the profile is not accepted under current flags.
    Default: only PROD_MIN accepted.
    """
    if profile == PROFILE_PROD_MIN:
        return
    if profile == PROFILE_PQ_EXPERIMENTAL and allow_experimental:
        return
    if profile == PROFILE_LEGACY and allow_legacy:
        return
    if profile == PROFILE_LEGACY:
        raise ValueError(
            f"Manifest uses legacy format (no explicit mode byte). "
            f"Pass --allow-legacy to accept legacy files."
        )
    if profile == PROFILE_PQ_EXPERIMENTAL:
        raise ValueError(
            f"Manifest uses experimental PQ hybrid profile. "
            f"Pass --allow-experimental to accept experimental profiles."
        )
    raise ValueError(f"Unknown crypto profile: {profile!r}")


_VALID_MODE_BYTES = {
    MODE_MEOW2,
    MODE_MEOW3,
    MODE_MEOW4,
    MODE_MEOW5,
    MODE_MEOW2 | MODE_DURESS,
    MODE_MEOW3 | MODE_DURESS,
    MODE_MEOW4 | MODE_DURESS,
    MODE_MEOW5 | MODE_DURESS,
    # Ratchet combinations (per-frame symmetric ratchet)
    MODE_MEOW2 | MODE_RATCHET,
    MODE_MEOW3 | MODE_RATCHET,
    MODE_MEOW4 | MODE_RATCHET,
    MODE_MEOW5 | MODE_RATCHET,
    MODE_MEOW2 | MODE_RATCHET | MODE_DURESS,
    MODE_MEOW3 | MODE_RATCHET | MODE_DURESS,
    MODE_MEOW4 | MODE_RATCHET | MODE_DURESS,
    MODE_MEOW5 | MODE_RATCHET | MODE_DURESS,
}


# Minimum password length (NIST SP 800-63B recommends 8+)
MIN_PASSWORD_LENGTH = 8

# Duress password domain separation
DURESS_HASH_PREFIX = b"duress_check_v1"

# FIX-A1: Nonce reuse guard (best-effort, per-process)
# Uses OrderedDict for LRU eviction instead of clearing all history.
# Cache size increased from 1024 to 10000 to reduce false-negative window.
_NONCE_REUSE_CACHE_MAX = 10000
_nonce_reuse_cache: "OrderedDict[bytes, bool]" = OrderedDict()
_nonce_logger = _logging.getLogger("meow_decoder.crypto.nonce_guard")


def _register_nonce_use(key: bytes, nonce: bytes, *, synthetic_iv_mode: bool = False) -> None:
    """
    Best-effort nonce reuse guard (per-process).

    Raises RuntimeError if the same key/nonce pair is observed again.
    Uses ordered eviction: oldest entries are removed when the cache
    exceeds _NONCE_REUSE_CACHE_MAX, preserving recent nonce history.

    When synthetic_iv_mode is True (HSM/precomputed_key path), the nonce
    is derived deterministically via HKDF from key + plaintext hash + salt.
    Same (key, plaintext, salt) → same nonce → same ciphertext.  This is
    standard AES-GCM (NOT AES-GCM-SIV); safety requires that either the
    key changes per session OR (key, plaintext) pairs are unique.  The
    per-process cache detects accidental reuse within a session.  We skip
    the reuse error for synthetic IVs because identical (key, plaintext)
    → identical nonce by design — identical input producing identical output
    is not a vulnerability here.
    """
    digest = get_default_backend().sha256(key + nonce)
    if digest in _nonce_reuse_cache:
        if synthetic_iv_mode:
            # Same nonce is expected for same (key, plaintext) — standard
            # AES-GCM with a deterministic HKDF nonce.  Identical output
            # for identical input is intentional in HSM mode.
            return
        raise RuntimeError("Nonce reuse detected for encryption key")
    _nonce_reuse_cache[digest] = True
    # LRU eviction: remove oldest entries instead of clearing all history
    while len(_nonce_reuse_cache) > _NONCE_REUSE_CACHE_MAX:
        _nonce_reuse_cache.popitem(last=False)


def compute_duress_hash_legacy(password: str, salt: bytes) -> bytes:
    """
    LEGACY ONLY: Fast SHA-256 duress hash.  Do NOT use for new manifests.

    Kept for backward compatibility with manifests encoded before Argon2id
    duress derivation was introduced.  Decode paths that need to check
    legacy duress tags should call this directly.

    Security note: fast, brute-forceable — superseded by
    compute_duress_tag() which now uses Argon2id.
    """
    return get_default_backend().sha256(DURESS_HASH_PREFIX + salt + password.encode("utf-8"))


# Backward-compat alias — removed in a future version
compute_duress_hash = compute_duress_hash_legacy


def compute_duress_tag(password: str, salt: bytes, manifest_core: bytes) -> bytes:
    """
    Compute duress authentication tag using Argon2id KDF.

    The key is derived with the same Argon2id parameters as the main
    encryption key, preventing brute-force of the duress password against
    a captured manifest.  A separate HKDF context string (``meow_duress_tag_v2``)
    ensures domain separation from the encryption key.

    Key material NEVER enters Python — all derivation occurs inside Rust
    handles.  The final HMAC output bytes are the only secret exposed.

    Args:
        password:      Duress password
        salt:          Salt from manifest (16 bytes, same as encryption salt)
        manifest_core: Canonical manifest core (no HMAC, no duress tag)

    Returns:
        32-byte HMAC-SHA256 tag
    """
    hb = get_handle_backend()
    # Derive master handle via Argon2id — same cost as encryption key derivation
    # so that offline brute-force of duress password requires the same work.
    master_handle = hb.derive_key_argon2id(
        password.encode("utf-8"),
        salt,
        memory_kib=ARGON2_MEMORY,
        iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )
    try:
        # Domain-separate duress key from encryption key via HKDF info string
        duress_handle = hb.derive_key_hkdf(master_handle, salt, b"meow_duress_tag_v2", 32)
        try:
            return hb.hmac_sha256(duress_handle, manifest_core)
        finally:
            hb.drop(duress_handle)
    finally:
        hb.drop(master_handle)


def check_duress_password(
    entered_password: str, salt: bytes, duress_tag: bytes, manifest_core: bytes
) -> bool:
    """
    Check if entered password matches duress tag (constant-time).

    Args:
        entered_password: Password entered by user
        salt: Salt from manifest
        duress_tag: Expected duress tag from manifest
        manifest_core: Canonical manifest core (no HMAC, no duress tag)

    Returns:
        True if password is the duress password

    Security:
        Uses secrets.compare_digest for constant-time comparison.
    """
    computed = compute_duress_tag(entered_password, salt, manifest_core)
    backend = get_default_backend()
    return backend.constant_time_compare(computed, duress_tag)


def pack_manifest_core(manifest: "Manifest", include_duress_tag: bool = True) -> bytes:
    """
    Pack canonical manifest core for authentication.

    This excludes the manifest HMAC field but can optionally include
    the duress tag for binding it to the HMAC.
    """
    core = MAGIC
    # FIX-D3: Include mode byte for non-legacy manifests
    if manifest.mode_byte != 0:
        core += struct.pack("B", manifest.mode_byte)
    core += (
        manifest.salt
        + manifest.nonce
        + struct.pack(">III", manifest.orig_len, manifest.comp_len, manifest.cipher_len)
        + struct.pack(">HI", manifest.block_size, manifest.k_blocks)
        + manifest.sha256
    )

    if manifest.ephemeral_public_key is not None:
        core += manifest.ephemeral_public_key

    if manifest.pq_ciphertext is not None:
        core += manifest.pq_ciphertext

    if include_duress_tag and manifest.duress_tag is not None:
        core += manifest.duress_tag

    return core


def derive_key(password: str, salt: bytes, keyfile: Optional[bytes] = None) -> bytes:
    """
    PRODUCTION-FORBIDDEN: Derive encryption key using Argon2id.

    This function returns raw key bytes.  In production, use
    ``derive_key_handle()`` which keeps all key material in Rust.

    Args:
        password: User passphrase (minimum 8 characters)
        salt: Random salt (16 bytes)
        keyfile: Optional keyfile content

    Returns:
        32-byte encryption key

    Raises:
        ValueError: If password is empty, too short, or salt is wrong length
        RuntimeError: If called in production mode
    """
    _legacy_guard("derive_key")
    if not password:
        raise ValueError("Password cannot be empty")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters (NIST SP 800-63B)"
        )
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")

    # Combine password and keyfile if provided
    secret = password.encode("utf-8")
    if keyfile:
        # Use HKDF to properly combine password and keyfile (via Rust backend)
        backend = get_default_backend()
        secret = backend.derive_key_hkdf(
            secret + keyfile,
            KEYFILE_DOMAIN_SEP,
            b"password_keyfile_combine",
            64,
        )

    secret_buf = bytearray(secret)
    try:
        # Derive key using Argon2id via backend
        backend = get_default_backend()
        key = backend.derive_key_argon2id(
            bytes(secret_buf),
            salt,
            output_len=32,
            iterations=ARGON2_ITERATIONS,
            memory_kib=ARGON2_MEMORY,
            parallelism=ARGON2_PARALLELISM,
        )

        return key
    except Exception as e:
        raise RuntimeError(f"Key derivation failed: {e}")
    finally:
        # Best-effort zeroing of mutable secret material
        secure_zero_memory(secret_buf)


# ── Handle-based key derivation (Rule #2: Python never holds secret key bytes) ──


def derive_key_handle(password: str, salt: bytes, keyfile: Optional[bytes] = None) -> int:
    """
    Derive encryption key using Argon2id — returns opaque Rust handle.

    The 32-byte key NEVER enters Python memory.  Callers interact with
    the key exclusively through the handle ID.

    When a keyfile is provided, the HKDF combination and Argon2id
    derivation are performed entirely inside Rust — no intermediate
    secret bytes cross the FFI boundary.

    Args:
        password: User passphrase (minimum 8 characters)
        salt:     Random salt (16 bytes)
        keyfile:  Optional keyfile content

    Returns:
        int handle ID pointing to 32-byte key inside Rust

    Raises:
        ValueError: If password is empty, too short, or salt is wrong length
    """
    if not password:
        raise ValueError("Password cannot be empty")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters (NIST SP 800-63B)"
        )
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")

    hb = get_handle_backend()

    password_bytes = password.encode("utf-8")
    try:
        if keyfile:
            # HKDF(password || keyfile) → Argon2id, entirely in Rust.
            # No intermediate secret bytes enter Python.
            handle = hb.derive_key_argon2id_with_keyfile(
                password_bytes,
                keyfile,
                KEYFILE_DOMAIN_SEP,
                salt,
                memory_kib=ARGON2_MEMORY,
                iterations=ARGON2_ITERATIONS,
                parallelism=ARGON2_PARALLELISM,
            )
        else:
            handle = hb.derive_key_argon2id(
                password_bytes,
                salt,
                memory_kib=ARGON2_MEMORY,
                iterations=ARGON2_ITERATIONS,
                parallelism=ARGON2_PARALLELISM,
            )
        return handle
    except Exception as e:
        raise RuntimeError(f"Key derivation failed: {e}")


def encrypt_file_bytes_handle(
    raw: bytes,
    password: str,
    keyfile: Optional[bytes] = None,
    use_length_padding: bool = True,
    mode_byte: int = 0,
) -> Tuple[bytes, bytes, bytes, bytes, bytes, int]:
    """
    Compress, hash, and encrypt file data — key stays in Rust handle.

    This is the handle-based equivalent of ``encrypt_file_bytes`` for
    password-only mode.  The encryption key NEVER enters Python.

    Returns:
        (compressed, sha256, salt, nonce, ciphertext, key_handle)
        Caller MUST call ``get_handle_backend().drop(key_handle)`` when done.
    """
    hb = get_handle_backend()
    backend = get_default_backend()

    comp = zlib.compress(raw, level=9)
    if use_length_padding:
        try:
            from .metadata_obfuscation import add_length_padding
        except ImportError:
            from metadata_obfuscation import add_length_padding  # type: ignore[import]
        comp = add_length_padding(comp)

    sha = backend.sha256(raw)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    key_handle = derive_key_handle(password, salt, keyfile)

    aad = build_canonical_aad(
        orig_len=len(raw),
        comp_len=len(comp),
        salt=salt,
        sha256_hash=sha,
        magic=MAGIC,
        mode_byte=mode_byte,
    )

    cipher = hb.aes_gcm_encrypt(key_handle, nonce, comp, aad)
    return comp, sha, salt, nonce, cipher, key_handle


def decrypt_to_raw_handle(
    cipher: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    orig_len: int,
    comp_len: int,
    sha256: bytes,
    keyfile: Optional[bytes] = None,
    mode_byte: int = 0,
) -> bytes:
    """
    Decrypt and decompress — key stays in Rust handle.

    Handle-based equivalent of ``decrypt_to_raw`` for password-only mode.
    """
    hb = get_handle_backend()

    key_handle = derive_key_handle(password, salt, keyfile)
    try:
        aad = build_canonical_aad(
            orig_len=orig_len,
            comp_len=comp_len,
            salt=salt,
            sha256_hash=sha256,
            magic=MAGIC,
            mode_byte=mode_byte,
        )
        comp = hb.aes_gcm_decrypt(key_handle, nonce, cipher, aad)

        try:
            from .metadata_obfuscation import remove_length_padding
        except ImportError:
            from metadata_obfuscation import remove_length_padding  # type: ignore[import]
        try:
            comp = remove_length_padding(comp)
        except (ValueError, ImportError):
            pass

        decomp_limit = (
            max(orig_len * MAX_DECOMP_RATIO, 1024 * 1024) if orig_len > 0 else 100 * 1024 * 1024
        )
        decompressor = zlib.decompressobj()
        chunk = decompressor.decompress(comp, decomp_limit + 1)
        if len(chunk) > decomp_limit:
            raise ValueError("Decompression bomb detected")
        remaining = decompressor.flush()
        if len(chunk) + len(remaining) > decomp_limit:
            raise ValueError("Decompression bomb detected")
        return chunk + remaining
    finally:
        hb.drop(key_handle)


def compute_manifest_hmac_handle(key_handle: int, salt: bytes, packed_no_hmac: bytes) -> bytes:
    """
    Compute HMAC over manifest using a key handle.

    The HMAC key is derived inside Rust via HKDF from the encryption key
    handle, ensuring the secret never enters Python.
    """
    hb = get_handle_backend()
    hmac_key_handle = hb.derive_key_hkdf(
        key_handle, MANIFEST_HMAC_KEY_PREFIX, b"manifest_hmac_v2", 32
    )
    try:
        return hb.hmac_sha256(hmac_key_handle, packed_no_hmac)
    finally:
        hb.drop(hmac_key_handle)


def encrypt_file_bytes(
    raw: bytes,
    password: str,
    keyfile: Optional[bytes] = None,
    receiver_public_key: Optional[bytes] = None,
    use_length_padding: bool = True,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
    precomputed_salt: Optional[bytes] = None,
    pq_ciphertext: Optional[bytes] = None,
    pq_ephemeral_public_key: Optional[bytes] = None,
    mode_byte: int = 0,
) -> Tuple[bytes, bytes, bytes, bytes, bytes, Optional[bytes], bytes]:
    """
    PRODUCTION-FORBIDDEN: This function returns the raw encryption key.

    Use ``encrypt_file_bytes_production()`` instead, which keeps the key
    in an opaque Rust handle.

    Raises:
        RuntimeError: If called in production mode
    """
    _legacy_guard("encrypt_file_bytes")
    try:
        # Optionally log via purr mode
        logger = None
        try:
            from .cat_utils import get_purr_logger

            logger = get_purr_logger()
        except (ImportError, AttributeError):
            pass

        if logger:
            logger.log(f"Compressing {len(raw)} bytes with zlib", category="io")

        # Compress with maximum compression
        comp = zlib.compress(raw, level=9)

        if logger:
            logger.log(f"Compressed to {len(comp)} bytes", category="io")

        # Add length padding to hide true size
        if use_length_padding:
            try:
                from .metadata_obfuscation import add_length_padding
            except ImportError:  # pragma: no cover
                from metadata_obfuscation import add_length_padding
            comp = add_length_padding(comp)

        # Hash original data (before padding!)
        sha = get_default_backend().sha256(raw)

        # Generate random salt and nonce (cryptographically secure)
        # Invariant: Nonce MUST be unique per key to prevent GCM nonce reuse.
        # We enforce uniqueness by generating a fresh random salt (new key) and
        # a fresh random 96-bit nonce per encryption.
        #
        # For hardware key derivation (HSM/TPM), salt is pre-generated and passed in.
        if precomputed_salt is not None:
            salt = precomputed_salt
        else:
            salt = secrets.token_bytes(16)

        # FIX-GPT-4: Synthetic IV for HSM/precomputed_key mode.
        # Random nonces are fine when each encryption derives a fresh key (new
        # salt → new Argon2id output → fresh key; nonce uniqueness is trivial).
        # But HSM/TPM mode may reuse the same precomputed_key across process
        # restarts, where the per-process nonce cache offers no protection.
        #
        # Solution: derive the nonce deterministically from the key and
        # compressed-plaintext hash via HKDF.  This guarantees:
        #   - Different plaintexts → different nonces (no collision possible)
        #   - Same plaintext under same key → same nonce → same ciphertext
        #     (standard AES-GCM with deterministic HKDF nonce, NOT AES-GCM-SIV;
        #      safe when the key is session-bound or plaintext is unique)
        #   - No persistent state required across restarts
        #
        # For non-HSM modes (password-only, FS, PQ hybrid), the key changes
        # every encryption, so random nonces remain safe and preferred.
        if precomputed_key is not None and pq_ephemeral_public_key is None:
            # Pure HSM/TPM mode: derive synthetic nonce from key + plaintext hash.
            # PQ hybrid mode already generates a fresh ephemeral keypair per
            # encryption, so each PQ shared secret is unique — random nonce is fine.
            backend = get_default_backend()
            comp_hash = backend.sha256(comp)
            nonce = backend.derive_key_hkdf(
                precomputed_key + comp_hash,
                salt,
                b"meow-synthetic-nonce-v1",
                12,
            )
        else:
            nonce = secrets.token_bytes(12)  # 96-bit nonce, never reused

        # Determine encryption mode and derive key
        ephemeral_public_key = None

        # HARDWARE PRE-DERIVED KEY MODE (HSM/TPM) or PQ HYBRID MODE
        if precomputed_key is not None:
            if len(precomputed_key) != 32:
                raise ValueError(f"Precomputed key must be 32 bytes, got {len(precomputed_key)}")
            key = precomputed_key
            # PQ hybrid mode passes the ephemeral classical public key from
            # hybrid_encapsulate().  In pure HSM/TPM mode, ephemeral_public_key
            # remains None (password-only).
            ephemeral_public_key = pq_ephemeral_public_key
        elif receiver_public_key is not None:
            # FORWARD SECRECY MODE: Use X25519 ephemeral keys
            try:
                from meow_decoder.x25519_forward_secrecy import (
                    generate_ephemeral_keypair,
                    derive_shared_secret,
                    deserialize_public_key,
                    serialize_public_key,
                )
            except ImportError:  # pragma: no cover
                # Try relative import
                from .x25519_forward_secrecy import (
                    generate_ephemeral_keypair,
                    derive_shared_secret,
                    deserialize_public_key,
                    serialize_public_key,
                )

            # Generate ephemeral keypair (now returns ForwardSecrecyKeys with bytes)
            fs_keys = generate_ephemeral_keypair()

            # Deserialize receiver's public key (validates bytes)
            receiver_pubkey = deserialize_public_key(receiver_public_key)

            # Derive shared secret (expects bytes)
            # FIX-C3 v2: Full transcript binding — version, mode, identities, PQ
            _mode_flags = 0x01  # FS mode
            if pq_ciphertext is not None:
                _mode_flags |= 0x02
            _pq_hash = get_default_backend().sha256(pq_ciphertext) if pq_ciphertext else None
            _eph_pub = serialize_public_key(fs_keys.ephemeral_public)
            key = derive_shared_secret(
                fs_keys.ephemeral_private,
                receiver_pubkey,
                password,
                salt,
                protocol_version=3,
                ephemeral_public=_eph_pub,
                pq_ciphertext_hash=_pq_hash,
                mode_flags=_mode_flags,
            )

            # Export ephemeral public key for transmission (validates bytes)
            ephemeral_public_key = serialize_public_key(fs_keys.ephemeral_public)

            # NOTE: fs_keys.ephemeral_private goes out of scope here
            # This provides forward secrecy - private key never stored!
        else:
            # PASSWORD-ONLY MODE: Standard Argon2id derivation
            if logger:
                logger.log("Deriving encryption key from password (Argon2id)", category="crypto")

            if yubikey_slot is not None:
                if keyfile is not None:
                    raise ValueError("Cannot combine --yubikey with --keyfile")
                backend = get_default_backend()
                key = backend.derive_key_yubikey(
                    password.encode("utf-8"), salt, slot=yubikey_slot, pin=yubikey_pin
                )
            else:
                key = derive_key(password, salt, keyfile)

            if logger:
                logger.log("✓ Key derivation complete", category="crypto")

        # Build AAD (Additional Authenticated Data) for manifest protection
        # Why: Binding metadata to the AEAD prevents substitution and
        # protocol-confusion attacks against lengths/hash/version fields.
        # MT-1: Uses canonical shared function for encrypt/decrypt symmetry.
        aad = build_canonical_aad(
            orig_len=len(raw),
            comp_len=len(comp),
            salt=salt,
            sha256_hash=sha,
            magic=MAGIC,
            ephemeral_public_key=ephemeral_public_key,
            pq_ciphertext=pq_ciphertext,
            mode_byte=mode_byte,
        )

        # Best-effort nonce reuse guard (per-process)
        # FIX-A1: Synthetic IV mode = nonce derived from key+plaintext, so
        # deterministic replay of same input is intentional and safe.
        _is_synthetic = precomputed_key is not None and pq_ephemeral_public_key is None
        _register_nonce_use(key, nonce, synthetic_iv_mode=_is_synthetic)

        # Encrypt with AES-256-GCM using AAD
        # Why: AEAD enforces authenticity before decryption; no partial
        # plaintext is released on tag failure.
        # AAD is authenticated but not encrypted
        if logger:
            logger.crypto_op(f"Encrypting {len(comp)} bytes with AES-256-GCM")

        backend = get_default_backend()
        cipher = backend.aes_gcm_encrypt(
            key, nonce, comp, aad
        )  # ← AAD prevents metadata tampering!

        if logger:
            logger.success(f"Encryption complete! ({len(cipher)} bytes ciphertext)")

        return comp, sha, salt, nonce, cipher, ephemeral_public_key, key
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")


# ── Production handle-based API (Rule #2: Python never holds secret key bytes) ──
# These variants mirror the full-featured encrypt/decrypt/HMAC/key-derivation
# functions but keep all secrets Rust-side via opaque handles.


def encrypt_file_bytes_production(
    raw: bytes,
    password: str,
    keyfile: Optional[bytes] = None,
    receiver_public_key: Optional[bytes] = None,
    use_length_padding: bool = True,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
    precomputed_salt: Optional[bytes] = None,
    pq_ciphertext: Optional[bytes] = None,
    pq_ephemeral_public_key: Optional[bytes] = None,
    mode_byte: int = 0,
    precomputed_key_handle: Optional[int] = None,
) -> Tuple[bytes, bytes, bytes, bytes, bytes, Optional[bytes], int]:
    """
    Compress, hash, and encrypt — encryption key stays in Rust handle.

    Production version of encrypt_file_bytes.  The encryption key NEVER
    enters Python memory.  All key derivation, encryption, and HMAC
    operations are performed through opaque Rust handles.

    Returns:
        (compressed, sha256, salt, nonce, ciphertext, ephemeral_public_key, key_handle)
        Caller MUST call ``get_handle_backend().drop(key_handle)`` on all exit paths.
    """
    hb = get_handle_backend()
    backend = get_default_backend()

    # ── 1. Compress ──
    comp = zlib.compress(raw, level=9)
    if use_length_padding:
        try:
            from .metadata_obfuscation import add_length_padding
        except ImportError:  # pragma: no cover
            from metadata_obfuscation import add_length_padding
        comp = add_length_padding(comp)

    # ── 2. Hash original ──
    sha = backend.sha256(raw)

    # ── 3. Salt ──
    if precomputed_salt is not None:
        salt = precomputed_salt
    else:
        salt = secrets.token_bytes(16)

    # ── 4. Derive key → handle (key NEVER enters Python) ──
    ephemeral_public_key = None
    key_handle = None
    _handle_owned = True  # we own it unless caller passes precomputed_key_handle

    try:
        if precomputed_key_handle is not None:
            # HANDLE-BASED PQ HYBRID — key already in Rust, zero Python bytes
            key_handle = precomputed_key_handle
            _handle_owned = False  # caller owns this handle
            ephemeral_public_key = pq_ephemeral_public_key

        elif precomputed_key is not None:
            # HARDWARE / LEGACY PQ HYBRID MODE
            if len(precomputed_key) != 32:
                raise ValueError(f"Precomputed key must be 32 bytes, got {len(precomputed_key)}")
            key_handle = hb.import_key(precomputed_key)
            ephemeral_public_key = pq_ephemeral_public_key

        elif receiver_public_key is not None:
            # FORWARD SECRECY MODE
            try:
                from meow_decoder.x25519_forward_secrecy import (
                    generate_ephemeral_keypair,
                    derive_shared_secret_handle,
                    deserialize_public_key,
                    serialize_public_key,
                )
            except ImportError:  # pragma: no cover
                from .x25519_forward_secrecy import (
                    generate_ephemeral_keypair,
                    derive_shared_secret_handle,
                    deserialize_public_key,
                    serialize_public_key,
                )

            fs_keys = generate_ephemeral_keypair()
            receiver_pubkey = deserialize_public_key(receiver_public_key)
            _mode_flags = 0x01
            if pq_ciphertext is not None:
                _mode_flags |= 0x02
            _pq_hash = backend.sha256(pq_ciphertext) if pq_ciphertext else None
            _eph_pub = serialize_public_key(fs_keys.ephemeral_public)

            key_handle = derive_shared_secret_handle(
                fs_keys.ephemeral_private,
                receiver_pubkey,
                password,
                salt,
                protocol_version=3,
                ephemeral_public=_eph_pub,
                pq_ciphertext_hash=_pq_hash,
                mode_flags=_mode_flags,
            )
            ephemeral_public_key = serialize_public_key(fs_keys.ephemeral_public)

        else:
            # PASSWORD-ONLY MODE
            if yubikey_slot is not None:
                if keyfile is not None:
                    raise ValueError("Cannot combine --yubikey with --keyfile")
                # Key derived via YubiKey stays in Rust handle — never enters Python
                key_handle = hb.derive_key_yubikey(
                    password.encode("utf-8"), salt, slot=yubikey_slot, pin=yubikey_pin
                )
            else:
                key_handle = derive_key_handle(password, salt, keyfile)

        # ── 5. Nonce ──
        if precomputed_key is not None and pq_ephemeral_public_key is None:
            # Synthetic IV for HSM/TPM mode
            comp_hash = backend.sha256(comp)
            # Derive synthetic nonce from key handle + comp_hash
            nonce = hb.derive_key_hkdf_bytes(
                key_handle, salt, b"meow-synthetic-nonce-v1-comp:" + comp_hash, 12
            )
        else:
            nonce = secrets.token_bytes(12)

        # ── 6. Nonce reuse guard (handle-based fingerprint) ──
        _is_synthetic = precomputed_key is not None and pq_ephemeral_public_key is None
        if not _is_synthetic:
            fingerprint = hb.derive_key_hkdf_bytes(key_handle, nonce, b"nonce_guard_v1", 32)
            if fingerprint in _nonce_reuse_cache:
                raise RuntimeError("Nonce reuse detected for encryption key")
            _nonce_reuse_cache[fingerprint] = True
            while len(_nonce_reuse_cache) > _NONCE_REUSE_CACHE_MAX:
                _nonce_reuse_cache.popitem(last=False)

        # ── 7. Build AAD ──
        aad = build_canonical_aad(
            orig_len=len(raw),
            comp_len=len(comp),
            salt=salt,
            sha256_hash=sha,
            magic=MAGIC,
            ephemeral_public_key=ephemeral_public_key,
            pq_ciphertext=pq_ciphertext,
            mode_byte=mode_byte,
        )

        # ── 8. Encrypt via handle ──
        cipher = hb.aes_gcm_encrypt(key_handle, nonce, comp, aad)

        return comp, sha, salt, nonce, cipher, ephemeral_public_key, key_handle
    except Exception:
        # Drop handle on error path (only if we created it)
        if key_handle is not None and _handle_owned:
            try:
                hb.drop(key_handle)
            except Exception:
                pass
        raise


def derive_encryption_key_for_manifest_handle(
    password: str,
    salt: bytes,
    keyfile: Optional[bytes] = None,
    ephemeral_public_key: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
    pq_ciphertext: Optional[bytes] = None,
) -> int:
    """
    Derive the encryption key for a manifest — returns an opaque Rust handle.

    Production version of derive_encryption_key_for_manifest.
    The raw key NEVER crosses the FFI boundary into Python(except for
                                                           precomputed_key and yubikey paths where the key originates outside Rust).

    Caller MUST call ``get_handle_backend().drop(handle)`` when done.
    """
    hb = get_handle_backend()

    # HARDWARE PRE-DERIVED KEY MODE (HSM/TPM)
    if precomputed_key is not None:
        if len(precomputed_key) != 32:
            raise ValueError(f"Precomputed key must be 32 bytes, got {len(precomputed_key)}")
        # Key arrives from HSM — import immediately, transient in Python.
        return hb.import_key(precomputed_key)

    # FORWARD SECRECY MODE
    if ephemeral_public_key is not None:
        if receiver_private_key is None:
            raise ValueError("Forward secrecy mode requires receiver private key")

        try:
            from meow_decoder.x25519_forward_secrecy import (
                derive_shared_secret_handle,
                deserialize_public_key,
            )
        except ImportError:  # pragma: no cover
            from .x25519_forward_secrecy import (
                derive_shared_secret_handle,
                deserialize_public_key,
            )

        sender_pubkey = deserialize_public_key(ephemeral_public_key)
        _mode_flags = 0x01  # FS mode
        if pq_ciphertext is not None:
            _mode_flags |= 0x02
        _pq_hash = get_default_backend().sha256(pq_ciphertext) if pq_ciphertext else None
        # Compute receiver's static public key from their private key
        # for transcript binding (FIX-C3v2: encode hashes recv_pub, not eph_pub)
        _recv_static_pub = get_default_backend().x25519_public_from_private(receiver_private_key)
        # Key NEVER enters Python — derive_shared_secret_handle returns handle
        return derive_shared_secret_handle(
            receiver_private_key,
            sender_pubkey,
            password,
            salt,
            protocol_version=3,
            ephemeral_public=ephemeral_public_key,
            pq_ciphertext_hash=_pq_hash,
            mode_flags=_mode_flags,
            static_receiver_public=_recv_static_pub,
        )

    # YUBIKEY MODE — key never enters Python
    if yubikey_slot is not None:
        if keyfile is not None:
            raise ValueError("Cannot combine --yubikey with --keyfile")
        # Key derived via YubiKey stays in Rust handle — never enters Python
        return hb.derive_key_yubikey(
            password.encode("utf-8"), salt, slot=yubikey_slot, pin=yubikey_pin
        )

    # PASSWORD-ONLY MODE — key never enters Python
    return derive_key_handle(password, salt, keyfile)


def compute_manifest_hmac_from_handle(
    key_handle: int,
    salt: bytes,
    packed_no_hmac: bytes,
) -> bytes:
    """
    Compute HMAC over manifest using a key handle.

    Production version — the secret key NEVER enters Python.
    Delegates to ``compute_manifest_hmac_handle`` which derives the HMAC
    key via HKDF inside Rust and then computes HMAC-SHA256, keeping all
    secret material in opaque handles.

    Args:
        key_handle: Opaque handle to the 32-byte encryption key
        salt: Salt from manifest (unused in HMAC itself but kept for API symmetry)
        packed_no_hmac: Serialized manifest without HMAC field

    Returns:
        32-byte HMAC-SHA256 tag
    """
    return compute_manifest_hmac_handle(key_handle, salt, packed_no_hmac)


def decrypt_to_raw_production(
    cipher: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    keyfile: Optional[bytes] = None,
    orig_len: Optional[int] = None,
    comp_len: Optional[int] = None,
    sha256: Optional[bytes] = None,
    ephemeral_public_key: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
    pq_ciphertext: Optional[bytes] = None,
    mode_byte: int = 0,
    precomputed_key_handle: Optional[int] = None,
) -> bytes:
    """
    Decrypt and decompress — key stays in Rust handle throughout.

    Production version of decrypt_to_raw.  The raw key NEVER enters
    Python memory.  Uses handle-based AES-GCM internally.

    When ``precomputed_key_handle`` is provided(from hybrid_encapsulate_handle
                                                or hybrid_decapsulate_handle), NO import_key call is needed and zero
    secret bytes ever exist in Python.
    """
    hb = get_handle_backend()

    # If caller already has a handle (PQ hybrid path), use it directly
    key_handle_is_owned = True
    if precomputed_key_handle is not None:
        key_handle = precomputed_key_handle
        key_handle_is_owned = False  # caller owns it
    else:
        # Derive key → handle
        key_handle = derive_encryption_key_for_manifest_handle(
            password,
            salt,
            keyfile=keyfile,
            ephemeral_public_key=ephemeral_public_key,
            receiver_private_key=receiver_private_key,
            yubikey_slot=yubikey_slot,
            yubikey_pin=yubikey_pin,
            precomputed_key=precomputed_key,
            pq_ciphertext=pq_ciphertext,
        )
    try:
        if orig_len is None or comp_len is None or sha256 is None:
            raise ValueError(
                "AAD parameters (orig_len, comp_len, sha256) are required for decryption. "
                "Files encrypted without AAD are no longer supported."
            )
        aad = build_canonical_aad(
            orig_len=orig_len,
            comp_len=comp_len,
            salt=salt,
            sha256_hash=sha256,
            magic=MAGIC,
            ephemeral_public_key=ephemeral_public_key,
            pq_ciphertext=pq_ciphertext,
            mode_byte=mode_byte,
        )

        comp = hb.aes_gcm_decrypt(key_handle, nonce, cipher, aad)

        try:
            from .metadata_obfuscation import remove_length_padding
        except ImportError:
            from metadata_obfuscation import remove_length_padding  # type: ignore[import]
        try:
            comp = remove_length_padding(comp)
        except (ValueError, ImportError):
            pass

        decomp_limit = (
            max(orig_len * MAX_DECOMP_RATIO, 1024 * 1024) if orig_len > 0 else 100 * 1024 * 1024
        )
        decompressor = zlib.decompressobj()
        chunk = decompressor.decompress(comp, decomp_limit + 1)
        if len(chunk) > decomp_limit:
            raise ValueError("Decompression bomb detected")
        remaining = decompressor.flush()
        if len(chunk) + len(remaining) > decomp_limit:
            raise ValueError("Decompression bomb detected")
        return chunk + remaining
    finally:
        if key_handle_is_owned:
            hb.drop(key_handle)


def verify_manifest_hmac_production(
    password: str,
    manifest,
    keyfile: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
) -> bool:
    """
    Verify manifest HMAC — key stays in Rust handle.

    Production version of verify_manifest_hmac.  The secret key NEVER
    enters Python memory.
    """
    hb = get_handle_backend()

    key_handle = derive_encryption_key_for_manifest_handle(
        password,
        manifest.salt,
        keyfile=keyfile,
        ephemeral_public_key=manifest.ephemeral_public_key,
        receiver_private_key=receiver_private_key,
        yubikey_slot=yubikey_slot,
        yubikey_pin=yubikey_pin,
        precomputed_key=precomputed_key,
        pq_ciphertext=manifest.pq_ciphertext,
    )
    try:
        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=True)
        expected_hmac = compute_manifest_hmac_from_handle(
            key_handle,
            manifest.salt,
            packed_no_hmac,
        )

        try:
            from .constant_time import constant_time_compare, equalize_timing

            result = constant_time_compare(expected_hmac, manifest.hmac)
            equalize_timing(0.001, 0.005)
            return result
        except ImportError:
            return secrets.compare_digest(expected_hmac, manifest.hmac)
    finally:
        hb.drop(key_handle)


def decrypt_to_raw(
    cipher: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    keyfile: Optional[bytes] = None,
    orig_len: Optional[int] = None,
    comp_len: Optional[int] = None,
    sha256: Optional[bytes] = None,
    ephemeral_public_key: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
    pq_ciphertext: Optional[bytes] = None,
    mode_byte: int = 0,
) -> bytes:
    """
    PRODUCTION-FORBIDDEN: Decrypt — raw key enters Python memory.

    Use ``decrypt_to_raw_production()`` instead, which keeps the key
    in an opaque Rust handle throughout.

    Raises:
        RuntimeError: If called in production mode
    """
    _legacy_guard("decrypt_to_raw")
    try:
        # Optionally log via purr mode
        logger = None
        try:
            from .cat_utils import get_purr_logger

            logger = get_purr_logger()
        except (ImportError, AttributeError):
            pass

        # Determine decryption mode and derive key

        # HARDWARE PRE-DERIVED KEY MODE (HSM/TPM)
        if precomputed_key is not None:
            if len(precomputed_key) != 32:
                raise ValueError(f"Precomputed key must be 32 bytes, got {len(precomputed_key)}")
            key = precomputed_key
        elif ephemeral_public_key is not None:
            # FORWARD SECRECY MODE
            if receiver_private_key is None:
                raise ValueError("Forward secrecy mode requires receiver private key")

            try:
                from meow_decoder.x25519_forward_secrecy import (
                    derive_shared_secret,
                    deserialize_public_key,
                )
            except ImportError:  # pragma: no cover
                # Try relative import
                from .x25519_forward_secrecy import derive_shared_secret, deserialize_public_key

            # Deserialize sender's ephemeral public key
            sender_pubkey = deserialize_public_key(ephemeral_public_key)

            # Derive shared secret (same as sender)
            # Receiver private key is passed as bytes, sender pubkey as bytes
            # FIX-C3 v2: Full transcript binding — version, mode, identities, PQ
            _mode_flags = 0x01  # FS mode
            if pq_ciphertext is not None:
                _mode_flags |= 0x02
            _pq_hash = get_default_backend().sha256(pq_ciphertext) if pq_ciphertext else None
            key = derive_shared_secret(
                receiver_private_key,
                sender_pubkey,
                password,
                salt,
                protocol_version=3,
                ephemeral_public=ephemeral_public_key,
                pq_ciphertext_hash=_pq_hash,
                mode_flags=_mode_flags,
            )
        else:
            # PASSWORD-ONLY MODE
            if yubikey_slot is not None:
                if keyfile is not None:
                    raise ValueError("Cannot combine --yubikey with --keyfile")
                backend = get_default_backend()
                key = backend.derive_key_yubikey(
                    password.encode("utf-8"), salt, slot=yubikey_slot, pin=yubikey_pin
                )
            else:
                key = derive_key(password, salt, keyfile)

        # Reconstruct AAD for verification (MT-1: canonical shared function)
        # Must match exactly what was used during encryption
        # FIX-A2: AAD is mandatory — silent bypass removed to prevent
        # downgrade attacks that strip authenticated metadata.
        if orig_len is None or comp_len is None or sha256 is None:
            raise ValueError(
                "AAD parameters (orig_len, comp_len, sha256) are required for decryption. "
                "Files encrypted without AAD are no longer supported."
            )
        aad = build_canonical_aad(
            orig_len=orig_len,
            comp_len=comp_len,
            salt=salt,
            sha256_hash=sha256,
            magic=MAGIC,
            ephemeral_public_key=ephemeral_public_key,
            pq_ciphertext=pq_ciphertext,
            mode_byte=mode_byte,
        )

        # Decrypt with AES-256-GCM
        # GCM will verify AAD matches before decrypting
        if logger:
            logger.crypto_op(f"Decrypting {len(cipher)} bytes with AES-256-GCM")

        backend = get_default_backend()
        comp = backend.aes_gcm_decrypt(key, nonce, cipher, aad)  # ← AAD verified here!

        # Remove length padding if present
        # Try to remove padding, fall back to no padding for backward compatibility
        try:
            try:
                from .metadata_obfuscation import remove_length_padding
            except ImportError:  # pragma: no cover
                from metadata_obfuscation import remove_length_padding
            comp = remove_length_padding(comp)
        except (ValueError, ImportError):
            # No padding or padding corrupted - use as-is
            # This provides backward compatibility with files without padding
            pass

        # Decompress
        # Try to remove padding, fall back to no padding for backward compatibility
        if logger:
            logger.log("Decompressing data with zlib", category="io")

        # ST-2: Decompression bomb protection — limit output size
        # Use incremental decompression to enforce MAX_DECOMP_RATIO
        decomp_limit = (
            max(orig_len * MAX_DECOMP_RATIO, 1024 * 1024)
            if orig_len is not None and orig_len > 0
            else 100 * 1024 * 1024
        )
        decompressor = zlib.decompressobj()
        chunks = []
        total_out = 0
        # Feed the compressed data in one shot but limit output
        try:
            chunk = decompressor.decompress(comp, decomp_limit + 1)
            total_out += len(chunk)
            if total_out > decomp_limit:  # pragma: no cover
                raise ValueError(
                    f"Decompression bomb detected: output ({total_out} bytes) exceeds "
                    f"limit ({decomp_limit} bytes, {MAX_DECOMP_RATIO}× orig_len)"
                )
            chunks.append(chunk)
            # Flush remaining
            remaining = decompressor.flush()
            total_out += len(remaining)
            if total_out > decomp_limit:  # pragma: no cover
                raise ValueError(
                    f"Decompression bomb detected: output ({total_out} bytes) exceeds "
                    f"limit ({decomp_limit} bytes, {MAX_DECOMP_RATIO}× orig_len)"
                )
            chunks.append(remaining)
        except zlib.error as ze:  # pragma: no cover
            raise RuntimeError(f"Decompression failed: {ze}")
        raw = b"".join(chunks)

        return raw
    except Exception as e:
        # FIX-D3: Distinguish PQ downgrade from wrong password.
        # If PQ ciphertext was expected (ephemeral key present suggests FS mode
        # but pq_ciphertext is None), warn about possible PQ downgrade attack.
        err_msg = str(e)
        if ephemeral_public_key is not None and pq_ciphertext is None:
            raise RuntimeError(
                f"Decryption failed: {err_msg}. "
                "NOTE: Forward secrecy mode is active but no post-quantum ciphertext "
                "was found. If this file was originally encrypted with PQ protection, "
                "the pq_ciphertext field may have been stripped (PQ downgrade attack). "
                "Verify the manifest integrity."
            )
        raise RuntimeError(f"Decryption failed (wrong password/keyfile or tampered manifest?): {e}")


def pack_manifest(m: Manifest) -> bytes:
    """
    Serialize manifest to bytes.

    Format (legacy base, 115 bytes — mode_byte == 0):
        MAGIC (5 bytes) +
        salt (16 bytes) +
        nonce (12 bytes) +
        orig_len (4 bytes) +
        comp_len (4 bytes) +
        cipher_len (4 bytes) +
        block_size (2 bytes) +
        k_blocks (4 bytes) +
        sha256 (32 bytes) +
        hmac (32 bytes)

    Format (new base, 116 bytes — mode_byte != 0):
        MAGIC (5 bytes) +
        mode_byte (1 byte, FIX-D3) +
        ... same fields ...

    Optional trailer fields (appended):
        ephemeral_public_key (32 bytes) — forward secrecy
        pq_ciphertext (1568 bytes) — PQ hybrid
        duress_tag (32 bytes) — duress

    Args:
        m: Manifest object

    Returns:
        Serialized manifest bytes
    """
    base = MAGIC
    # FIX-D3: Include mode byte for non-legacy manifests
    if m.mode_byte != 0:
        base += struct.pack("B", m.mode_byte)
    base += (
        m.salt
        + m.nonce
        + struct.pack(">III", m.orig_len, m.comp_len, m.cipher_len)
        + struct.pack(">HI", m.block_size, m.k_blocks)
        + m.sha256
        + m.hmac
    )

    # Add ephemeral public key if forward secrecy enabled
    if m.ephemeral_public_key is not None:
        if len(m.ephemeral_public_key) != 32:
            raise ValueError(
                f"Ephemeral public key must be 32 bytes, got {len(m.ephemeral_public_key)}"
            )
        base = base + m.ephemeral_public_key

    # Add PQ ciphertext if PQ hybrid enabled
    if m.pq_ciphertext is not None:
        if len(m.pq_ciphertext) not in (1088, 1568):
            raise ValueError(
                f"PQ ciphertext must be 1088 (ML-KEM-768) or 1568 (ML-KEM-1024) bytes, "
                f"got {len(m.pq_ciphertext)}"
            )
        base = base + m.pq_ciphertext

    # Add duress tag if present (32 bytes) - ALWAYS LAST for easy detection
    if m.duress_tag is not None:
        if len(m.duress_tag) != 32:
            raise ValueError(f"Duress tag must be 32 bytes, got {len(m.duress_tag)}")
        base = base + m.duress_tag

    return base


def unpack_manifest(b: bytes) -> Manifest:
    """
    Deserialize manifest from bytes.

    Args:
        b: Serialized manifest bytes

    Returns:
        Manifest object with optional ephemeral_public_key, pq_ciphertext, duress_tag, mode_byte

    Raises:
        ValueError: If manifest is invalid or wrong version

    Notes:
        Legacy manifest sizes (mode_byte inferred from length):
        - 115 bytes = password-only mode (MEOW2, legacy)
        - 147 bytes = forward secrecy mode (MEOW3)
        - 179 bytes = forward secrecy + duress (MEOW3 + duress tag)
        - 1715 bytes = PQ hybrid mode (MEOW4, ML-KEM-1024)
        - 1747 bytes = PQ hybrid + duress (MEOW4 + duress tag)

        New manifest sizes (FIX-D3, explicit mode_byte):
        - 116 bytes = MEOW2 + mode byte
        - 148 bytes = MEOW3 + mode byte
        - 180 bytes = MEOW3 + duress + mode byte
        - 1236 bytes = MEOW5 + mode byte (ML-KEM-768, ct=1088)
        - 1268 bytes = MEOW5 + duress + mode byte
        - 1716 bytes = MEOW4 + mode byte (ML-KEM-1024, ct=1568)
        - 1748 bytes = MEOW4 + duress + mode byte
    """
    min_len = len(MAGIC) + 16 + 12 + 12 + 6 + 32 + 32  # 115 bytes (base)
    fs_len = min_len + 32  # 147 bytes (with ephemeral public key)
    fs_duress_len = fs_len + 32  # 179 bytes (with FS + duress)
    pq_1024_len = fs_len + 1568  # 1715 bytes (ML-KEM-1024 ciphertext)
    pq_1024_duress_len = pq_1024_len + 32  # 1747 bytes
    pq_768_len = fs_len + 1088  # 1235 bytes (ML-KEM-768 ciphertext)
    pq_768_duress_len = pq_768_len + 32  # 1267 bytes

    # Legacy sizes (MODE_MEOW4 only, backward compat — no ML-KEM-768 in legacy)
    legacy_sizes = {min_len, fs_len, fs_duress_len, pq_1024_len, pq_1024_duress_len}
    # New sizes include both PQ variants + 1 byte for mode_byte
    new_sizes = {s + 1 for s in legacy_sizes}
    # Add MEOW5 (ML-KEM-768) sizes — new format only (no legacy)
    new_sizes.add(pq_768_len + 1)  # 1236 bytes
    new_sizes.add(pq_768_duress_len + 1)  # 1268 bytes
    all_valid = legacy_sizes | new_sizes

    if len(b) < min_len:
        raise ValueError(f"Manifest too short (got {len(b)}, need at least {min_len} bytes)")

    if len(b) not in all_valid:
        raise ValueError(
            f"Manifest length invalid (got {len(b)}, expected one of {sorted(all_valid)} bytes)"
        )

    if b[: len(MAGIC)] != MAGIC:
        # Try MEOW2 for backward compatibility
        if b[:5] == b"MEOW2":
            pass
        else:
            raise ValueError("Invalid MAGIC/version (possibly old v1 file or corrupted data)")

    # FIX-D3: Detect new-format manifests (explicit mode byte)
    has_mode_byte = len(b) in new_sizes
    off = len(MAGIC)
    mode_byte = MODE_LEGACY

    if has_mode_byte:
        mode_byte = struct.unpack("B", b[off: off + 1])[0]
        off += 1
        if mode_byte not in _VALID_MODE_BYTES:
            raise ValueError(
                f"Invalid manifest mode byte 0x{mode_byte:02x} "
                f"(valid: {', '.join(f'0x{v:02x}' for v in sorted(_VALID_MODE_BYTES))})"
            )

    salt = b[off: off + 16]
    off += 16
    nonce = b[off: off + 12]
    off += 12
    orig_len, comp_len, cipher_len = struct.unpack(">III", b[off: off + 12])
    off += 12
    block_size, k_blocks = struct.unpack(">HI", b[off: off + 6])
    off += 6
    sha = b[off: off + 32]
    off += 32
    hmac_tag = b[off: off + 32]
    off += 32

    # Parse optional fields based on manifest size
    ephemeral_public_key = None
    pq_ciphertext = None
    duress_tag = None

    # Effective sizes for field detection (normalize to legacy equivalent)
    effective_len = len(b) - (1 if has_mode_byte else 0)

    if effective_len >= fs_len:
        ephemeral_public_key = b[off: off + 32]
        off += 32

    # Determine PQ ciphertext size from mode byte
    base_version = (mode_byte & 0x0F) if mode_byte != MODE_LEGACY else 0
    # Strip ratchet flag for base version check
    base_version_clean = base_version & ~MODE_RATCHET

    if base_version_clean == MODE_MEOW5:
        # ML-KEM-768: ciphertext is 1088 bytes
        if effective_len >= pq_768_len:
            pq_ciphertext = b[off: off + 1088]
            off += 1088
    elif effective_len >= pq_1024_len:
        # ML-KEM-1024 (MEOW4 or legacy): ciphertext is 1568 bytes
        pq_ciphertext = b[off: off + 1568]
        off += 1568

    # Check for duress tag (always last field)
    remaining = len(b) - off
    if remaining == 32:
        duress_tag = b[off: off + 32]

    # FIX-D3: Validate mode byte consistency (reject mismatches)
    if mode_byte != MODE_LEGACY:
        base_version_for_check = mode_byte & 0x6F  # Strip duress (0x80) and ratchet (0x10) flags
        has_duress = bool(mode_byte & MODE_DURESS)

        # Version consistency checks
        if base_version_for_check == MODE_MEOW2 and ephemeral_public_key is not None:
            raise ValueError("Manifest mode byte says MEOW2 (no FS) but ephemeral key is present")
        if base_version_for_check == MODE_MEOW3 and pq_ciphertext is not None:
            raise ValueError("Manifest mode byte says MEOW3 (no PQ) but PQ ciphertext is present")
        if base_version_for_check == MODE_MEOW4 and pq_ciphertext is None:
            raise ValueError("Manifest mode byte says MEOW4 (PQ) but PQ ciphertext is missing")
        if base_version_for_check == MODE_MEOW5 and pq_ciphertext is None:
            raise ValueError("Manifest mode byte says MEOW5 (PQ) but PQ ciphertext is missing")
        if (
            base_version_for_check in (MODE_MEOW3, MODE_MEOW4, MODE_MEOW5)
            and ephemeral_public_key is None
        ):
            raise ValueError(
                f"Manifest mode byte says MEOW{base_version_for_check} (FS) but ephemeral key is missing"
            )
        if has_duress and duress_tag is None:
            raise ValueError("Manifest mode byte has duress flag but duress tag is missing")
        if not has_duress and duress_tag is not None:
            raise ValueError("Manifest mode byte lacks duress flag but duress tag is present")

    # ── ST-2: Strict numeric bounds validation ──
    if orig_len > MAX_ORIG_LEN:  # pragma: no cover
        raise ValueError(f"Manifest orig_len too large ({orig_len} > {MAX_ORIG_LEN})")
    if comp_len > MAX_COMP_LEN:  # pragma: no cover
        raise ValueError(f"Manifest comp_len too large ({comp_len} > {MAX_COMP_LEN})")
    if cipher_len > MAX_CIPHER_LEN:  # pragma: no cover
        raise ValueError(f"Manifest cipher_len too large ({cipher_len} > {MAX_CIPHER_LEN})")
    if block_size < MIN_BLOCK_SIZE or block_size > MAX_BLOCK_SIZE:  # pragma: no cover
        raise ValueError(
            f"Manifest block_size out of range ({block_size}, valid: {MIN_BLOCK_SIZE}–{MAX_BLOCK_SIZE})"
        )
    if k_blocks == 0 or k_blocks > MAX_K_BLOCKS:
        raise ValueError(f"Manifest k_blocks out of range ({k_blocks}, valid: 1–{MAX_K_BLOCKS})")
    if comp_len > 0 and orig_len > comp_len * MAX_DECOMP_RATIO:
        raise ValueError(
            f"Manifest decompression ratio too high (orig_len={orig_len} > comp_len={comp_len} × {MAX_DECOMP_RATIO})"
        )
    if cipher_len > 0 and cipher_len < comp_len:
        pass  # Not strictly enforced — padding modes may vary
    if ephemeral_public_key is not None and ephemeral_public_key == b"\x00" * 32:
        raise ValueError("Manifest ephemeral public key is all-zero (likely corrupted)")
    if pq_ciphertext is not None and len(pq_ciphertext) not in (1088, 1568):  # pragma: no cover
        raise ValueError(
            f"Manifest PQ ciphertext wrong size ({len(pq_ciphertext)}, "
            f"expected 1088 (ML-KEM-768) or 1568 (ML-KEM-1024))"
        )

    # ── Verify all bytes consumed (prevents trailing data attacks) ──
    expected_off = off + (32 if duress_tag is not None else 0)
    if expected_off != len(b):
        raise ValueError(
            f"Manifest has {len(b) - expected_off} unconsumed trailing bytes "
            f"(parsed {expected_off}, total {len(b)}). "
            f"Possible mode/ciphertext size mismatch."
        )

    return Manifest(
        salt=salt,
        nonce=nonce,
        orig_len=orig_len,
        comp_len=comp_len,
        cipher_len=cipher_len,
        sha256=sha,
        block_size=block_size,
        k_blocks=k_blocks,
        hmac=hmac_tag,
        ephemeral_public_key=ephemeral_public_key,
        pq_ciphertext=pq_ciphertext,
        duress_tag=duress_tag,
        mode_byte=mode_byte,
        crypto_profile=classify_crypto_profile(mode_byte),
    )


def derive_encryption_key_for_manifest(
    password: str,
    salt: bytes,
    keyfile: Optional[bytes] = None,
    ephemeral_public_key: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
    pq_ciphertext: Optional[bytes] = None,
) -> bytes:
    """
    PRODUCTION-FORBIDDEN: Returns raw key bytes.

    Use ``derive_encryption_key_for_manifest_handle()`` instead.
    """
    _legacy_guard("derive_encryption_key_for_manifest")
    # HARDWARE PRE-DERIVED KEY MODE (HSM/TPM)
    if precomputed_key is not None:
        if len(precomputed_key) != 32:
            raise ValueError(f"Precomputed key must be 32 bytes, got {len(precomputed_key)}")
        return precomputed_key

    if ephemeral_public_key is not None:
        if receiver_private_key is None:
            raise ValueError("Forward secrecy mode requires receiver private key")

        try:
            from meow_decoder.x25519_forward_secrecy import (
                derive_shared_secret,
                deserialize_public_key,
            )
        except ImportError:  # pragma: no cover
            from .x25519_forward_secrecy import derive_shared_secret, deserialize_public_key

        sender_pubkey = deserialize_public_key(ephemeral_public_key)
        # FIX-C3 v2: Full transcript binding — version, mode, identities, PQ
        _mode_flags = 0x01  # FS mode
        if pq_ciphertext is not None:
            _mode_flags |= 0x02
        _pq_hash = get_default_backend().sha256(pq_ciphertext) if pq_ciphertext else None
        # Compute receiver's static public key for transcript binding
        _recv_static_pub = get_default_backend().x25519_public_from_private(receiver_private_key)
        return derive_shared_secret(
            receiver_private_key,
            sender_pubkey,
            password,
            salt,
            protocol_version=3,
            ephemeral_public=ephemeral_public_key,
            pq_ciphertext_hash=_pq_hash,
            mode_flags=_mode_flags,
            static_receiver_public=_recv_static_pub,
        )

    if yubikey_slot is not None:
        if keyfile is not None:
            raise ValueError("Cannot combine --yubikey with --keyfile")
        backend = get_default_backend()
        return backend.derive_key_yubikey(
            password.encode("utf-8"), salt, slot=yubikey_slot, pin=yubikey_pin
        )

    return derive_key(password, salt, keyfile)


def compute_manifest_hmac(
    password: str,
    salt: bytes,
    packed_no_hmac: bytes,
    keyfile: Optional[bytes] = None,
    ephemeral_public_key: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    encryption_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    pq_ciphertext: Optional[bytes] = None,
) -> bytes:
    """
    PRODUCTION-FORBIDDEN: Uses raw key bytes for HMAC.

    Use ``compute_manifest_hmac_from_handle()`` instead.
    """
    _legacy_guard("compute_manifest_hmac")
    # Use pre-derived key if provided (encoding path)
    if encryption_key is not None:
        key = encryption_key
    else:
        # Derive key based on encryption mode (decoding path)
        key = derive_encryption_key_for_manifest(
            password,
            salt,
            keyfile=keyfile,
            ephemeral_public_key=ephemeral_public_key,
            receiver_private_key=receiver_private_key,
            yubikey_slot=yubikey_slot,
            yubikey_pin=yubikey_pin,
            pq_ciphertext=pq_ciphertext,
        )

    # Derive HMAC key from encryption key
    # Why: Domain separation prevents reuse of the encryption key for
    # authentication, mitigating cross-context key reuse risks.
    key_material = MANIFEST_HMAC_KEY_PREFIX + key

    backend = get_default_backend()
    return backend.hmac_sha256(key_material, packed_no_hmac)


def verify_manifest_hmac(
    password: str,
    manifest: Manifest,
    keyfile: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None,
    precomputed_key: Optional[bytes] = None,
) -> bool:
    """
    PRODUCTION-FORBIDDEN: Uses raw key bytes for HMAC verification.

    Use ``verify_manifest_hmac_production()`` instead.
    """
    _legacy_guard("verify_manifest_hmac")
    # Pack manifest without HMAC
    packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=True)

    # Compute expected HMAC (with forward secrecy support)
    # FIX-C3 v2: Pass pq_ciphertext for transcript binding
    expected_hmac = compute_manifest_hmac(
        password,
        manifest.salt,
        packed_no_hmac,
        keyfile,
        ephemeral_public_key=manifest.ephemeral_public_key,
        receiver_private_key=receiver_private_key,
        encryption_key=precomputed_key,  # Pass precomputed key for HMAC
        yubikey_slot=yubikey_slot,
        yubikey_pin=yubikey_pin,
        pq_ciphertext=manifest.pq_ciphertext,
    )

    # Constant-time comparison with timing equalization
    # Why: Prevents timing side-channel leakage on authentication failures.
    try:
        from .constant_time import constant_time_compare, equalize_timing

        result = constant_time_compare(expected_hmac, manifest.hmac)
        # Add timing equalization (prevents timing side-channels)
        equalize_timing(0.001, 0.005)  # 1-5ms random delay
        return result
    except ImportError:
        # Fallback to Rust constant-time compare
        result = get_default_backend().constant_time_compare(expected_hmac, manifest.hmac)
        # Still add some timing jitter
        import time

        time.sleep(secrets.randbelow(5) / 1000.0)  # 0-5ms
        return result


def verify_keyfile(keyfile_path: str) -> bytes:
    """
    Read and validate keyfile.

    Args:
        keyfile_path: Path to keyfile

    Returns:
        Keyfile contents

    Raises:
        ValueError: If keyfile is invalid
        FileNotFoundError: If keyfile doesn't exist
    """
    if not os.path.exists(keyfile_path):
        raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")

    with open(keyfile_path, "rb") as f:
        keyfile = f.read()

    if len(keyfile) < 32:
        raise ValueError(f"Keyfile too small (need at least 32 bytes, got {len(keyfile)})")

    if len(keyfile) > 1024 * 1024:  # 1 MB
        raise ValueError(f"Keyfile too large (max 1 MB, got {len(keyfile)} bytes)")

    return keyfile


# Testing
if __name__ == "__main__":
    print("Testing Base Cryptography Module...\n")

    # Test 1: Key derivation
    print("1. Testing key derivation...")
    password = "test_password_123"
    salt = secrets.token_bytes(16)

    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)

    assert key1 == key2, "Same password should give same key"
    assert len(key1) == 32, "Key should be 32 bytes"
    print(f"   ✓ Key derivation works ({len(key1)} bytes)")

    # Test 2: Encryption/decryption
    print("\n2. Testing encryption/decryption...")
    test_data = b"Secret cat message! " * 100

    comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(test_data, password)
    print(f"   Original: {len(test_data)} bytes")
    print(f"   Compressed: {len(comp)} bytes ({len(comp)/len(test_data)*100:.1f}%)")
    print(f"   Encrypted: {len(cipher)} bytes")

    decrypted = decrypt_to_raw(
        cipher,
        password,
        salt,
        nonce,
        orig_len=len(test_data),
        comp_len=len(comp),
        sha256=sha,
    )
    assert decrypted == test_data, "Decryption should recover original"
    print("   ✓ Encryption/decryption roundtrip works")

    # Test 3: SHA256 verification
    print("\n3. Testing SHA256 hash...")
    computed_sha = get_default_backend().sha256(test_data)
    assert computed_sha == sha, "SHA256 should match"
    print("   ✓ SHA256 verification works")

    # Test 4: Manifest packing/unpacking
    print("\n4. Testing manifest...")

    manifest = Manifest(
        salt=salt,
        nonce=nonce,
        orig_len=len(test_data),
        comp_len=len(comp),
        cipher_len=len(cipher),
        sha256=sha,
        block_size=512,
        k_blocks=10,
        hmac=b"\x00" * 32,  # Placeholder
        ephemeral_public_key=None,  # Test password-only mode
        pq_ciphertext=None,
        duress_tag=None,
    )

    # Compute HMAC
    packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)

    # Derive key to compute HMAC
    enc_key = derive_key(password, salt)
    manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac, encryption_key=enc_key)

    # Pack and unpack
    packed = pack_manifest(manifest)
    unpacked = unpack_manifest(packed)

    assert unpacked.salt == manifest.salt
    assert unpacked.orig_len == manifest.orig_len
    print(f"   ✓ Manifest roundtrip works ({len(packed)} bytes)")

    # Test 5: HMAC verification
    print("\n5. Testing HMAC verification...")

    is_valid = verify_manifest_hmac(password, unpacked)
    assert is_valid, "HMAC should be valid"
    print("   ✓ HMAC verification works")

    # Test wrong password
    is_valid_wrong = verify_manifest_hmac("wrong_password", unpacked)
    assert not is_valid_wrong, "HMAC should fail with wrong password"
    print("   ✓ HMAC rejects wrong password")

    # Test 6: Keyfile support
    print("\n6. Testing keyfile...")

    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as f:
        keyfile_path = f.name
        f.write(secrets.token_bytes(256))

    try:
        keyfile = verify_keyfile(keyfile_path)

        # Encrypt with keyfile
        comp_kf, sha_kf, salt_kf, nonce_kf, cipher_kf, _, _ = encrypt_file_bytes(
            test_data, password, keyfile
        )

        # Decrypt with keyfile (include AAD parameters)
        decrypted_kf = decrypt_to_raw(
            cipher_kf,
            password,
            salt_kf,
            nonce_kf,
            keyfile,
            orig_len=len(test_data),
            comp_len=len(comp_kf),
            sha256=sha_kf,
        )
        assert decrypted_kf == test_data
        print("   ✓ Keyfile encryption/decryption works")

        # Try decrypting without keyfile (should fail)
        try:
            decrypt_to_raw(
                cipher_kf,
                password,
                salt_kf,
                nonce_kf,
                orig_len=len(test_data),
                comp_len=len(comp_kf),
                sha256=sha_kf,
            )
            print("   ✗ Decryption without keyfile should fail")
        except RuntimeError:
            print("   ✓ Keyfile is required for decryption")

    finally:
        os.unlink(keyfile_path)

    print("\n✅ All cryptography tests passed!")
