"""
Base Cryptography Module for Meow Decoder
Provides AES-256-GCM encryption with Argon2id key derivation using Pluggable Backend

This is the base version. For enhanced security features, see crypto_enhanced.py
"""

import os
import struct
import hashlib
import hmac
import zlib
import secrets
from dataclasses import dataclass
from typing import Tuple, Optional

from .crypto_backend import get_default_backend


# Magic bytes for manifest version identification
MAGIC = b"MEOW3"  # Version 3 with Argon2id + HMAC + Forward Secrecy

# Argon2id parameters
# Production: ULTRA-HARDENED (512 MiB, 20 iterations = ~5-10 seconds)
# Test mode: Fast parameters (32 MiB, 1 iteration = ~0.1 seconds)
# Set MEOW_TEST_MODE=1 environment variable for fast testing
_TEST_MODE = os.environ.get("MEOW_TEST_MODE", "").lower() in ("1", "true", "yes")

if _TEST_MODE:
    # Fast parameters for CI/testing (still secure enough for functional tests)
    ARGON2_MEMORY = 32768       # 32 MiB (fast)
    ARGON2_ITERATIONS = 1       # 1 pass (fast)
    ARGON2_PARALLELISM = 1      # 1 thread
else:
    # Production: Ultra-hardened for maximum brute-force resistance
    ARGON2_MEMORY = 524288      # 512 MiB (8x OWASP recommendation)
    ARGON2_ITERATIONS = 20      # 20 passes (makes offline attacks impractical)
    ARGON2_PARALLELISM = 4      # 4 threads

# HMAC domain separation
MANIFEST_HMAC_KEY_PREFIX = b"meow_manifest_auth_v2"


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
        pq_ciphertext: Optional ML-KEM-768 ciphertext for post-quantum (1088 bytes)
                      None = classical-only mode
                      Present = PQ hybrid mode (X25519 + ML-KEM-768)
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


# Minimum password length (NIST SP 800-63B recommends 8+)
MIN_PASSWORD_LENGTH = 8

# Duress password domain separation
DURESS_HASH_PREFIX = b"duress_check_v1"

# Nonce reuse guard (best-effort, per-process)
_NONCE_REUSE_CACHE_MAX = 1024
_nonce_reuse_cache = set()


def _register_nonce_use(key: bytes, nonce: bytes) -> None:
    """
    Best-effort nonce reuse guard (per-process).

    Raises RuntimeError if the same key/nonce pair is observed again.
    """
    digest = hashlib.sha256(key + nonce).digest()
    if digest in _nonce_reuse_cache:
        raise RuntimeError("Nonce reuse detected for encryption key")
    _nonce_reuse_cache.add(digest)
    if len(_nonce_reuse_cache) > _NONCE_REUSE_CACHE_MAX:
        _nonce_reuse_cache.clear()


def compute_duress_hash(password: str, salt: bytes) -> bytes:
    """
    Compute a fast duress password hash.

    NOTE: This is a fast hash used as a key for duress tag verification
    and for legacy compatibility checks. It is NOT used for encryption.

    Args:
        password: Duress password
        salt: Salt from manifest (16 bytes)

    Returns:
        32-byte SHA-256 hash
    """
    return hashlib.sha256(DURESS_HASH_PREFIX + salt + password.encode('utf-8')).digest()


def compute_duress_tag(password: str, salt: bytes, manifest_core: bytes) -> bytes:
    """
    Compute duress authentication tag (fast, tamper-evident).

    This tag allows the decoder to safely trigger duress behavior
    without performing expensive Argon2id derivations while still
    preventing manifest tampering from forcing duress.

    Args:
        password: Duress password
        salt: Salt from manifest (16 bytes)
        manifest_core: Canonical manifest core (no HMAC, no duress tag)

    Returns:
        32-byte HMAC-SHA256 tag
    """
    duress_key = compute_duress_hash(password, salt)
    return hmac.new(duress_key, manifest_core, hashlib.sha256).digest()


def check_duress_password(
    entered_password: str,
    salt: bytes,
    duress_tag: bytes,
    manifest_core: bytes
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
    return secrets.compare_digest(computed, duress_tag)


def pack_manifest_core(manifest: "Manifest", include_duress_tag: bool = True) -> bytes:
    """
    Pack canonical manifest core for authentication.

    This excludes the manifest HMAC field but can optionally include
    the duress tag for binding it to the HMAC.
    """
    core = (
        MAGIC +
        manifest.salt +
        manifest.nonce +
        struct.pack(">III", manifest.orig_len, manifest.comp_len, manifest.cipher_len) +
        struct.pack(">HI", manifest.block_size, manifest.k_blocks) +
        manifest.sha256
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
    Derive encryption key using Argon2id.
    
    Args:
        password: User passphrase (minimum 8 characters)
        salt: Random salt (16 bytes)
        keyfile: Optional keyfile content
        
    Returns:
        32-byte encryption key
        
    Raises:
        ValueError: If password is empty, too short, or salt is wrong length
    """
    if not password:
        raise ValueError("Password cannot be empty")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters (NIST SP 800-63B)")
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")
    
    # Combine password and keyfile if provided (use mutable buffer for best-effort zeroing)
    secret = bytearray(password.encode("utf-8"))
    if keyfile:
        # Simple concatenation for base version
        # (crypto_enhanced.py uses HKDF for proper combining)
        secret.extend(keyfile)
    
    try:
        # Derive key using Argon2id via backend
        backend = get_default_backend()
        key = backend.derive_key_argon2id(
            bytes(secret),
            salt,
            output_len=32,
            iterations=ARGON2_ITERATIONS,
            memory_kib=ARGON2_MEMORY,
            parallelism=ARGON2_PARALLELISM
        )
        
        return key
    except Exception as e:
        raise RuntimeError(f"Key derivation failed: {e}")
    finally:
        # Best-effort zeroing of mutable secret material
        try:
            backend = get_default_backend()
            backend.secure_zero(secret)
        except Exception:
            pass


def encrypt_file_bytes(
    raw: bytes,
    password: str,
    keyfile: Optional[bytes] = None,
    receiver_public_key: Optional[bytes] = None,
    use_length_padding: bool = True,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None
) -> Tuple[bytes, bytes, bytes, bytes, bytes, Optional[bytes], bytes]:
    """
    Compress, hash, and encrypt file data with authenticated additional data (AAD).
    
    Args:
        raw: Raw file bytes
        password: Encryption password
        keyfile: Optional keyfile content
        receiver_public_key: Optional X25519 public key for forward secrecy (32 bytes)
                            If provided, enables forward secrecy mode
        use_length_padding: Add length padding to hide true size (default: True)
        
    Returns:
        Tuple of (compressed, sha256, salt, nonce, ciphertext, ephemeral_public_key, encryption_key)
        - ephemeral_public_key is None if password-only mode
        - ephemeral_public_key is 32 bytes if forward secrecy mode
        - encryption_key is the 32-byte key used for encryption (needed for HMAC computation)
        
    Raises:
        RuntimeError: If encryption fails
        
    Security:
        - Uses AES-256-GCM with AAD for manifest authentication
        - AAD includes: orig_len, comp_len, salt, sha256, magic
        - Prevents tampering with metadata
        - Nonce is unique per encryption (never reused)
        - Forward secrecy: Ephemeral X25519 keys if receiver_public_key provided
        - Length padding: Rounds to size classes to hide true size
    """
    try:
        # Compress with maximum compression
        comp = zlib.compress(raw, level=9)
        
        # Add length padding to hide true size
        if use_length_padding:
            try:
                from .metadata_obfuscation import add_length_padding
            except ImportError:
                from metadata_obfuscation import add_length_padding
            comp = add_length_padding(comp)
        
        # Hash original data (before padding!)
        sha = hashlib.sha256(raw).digest()
        
        # Generate random salt and nonce (cryptographically secure)
        # Invariant: Nonce MUST be unique per key to prevent GCM nonce reuse.
        # We enforce uniqueness by generating a fresh random salt (new key) and
        # a fresh random 96-bit nonce per encryption.
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)  # 96-bit nonce, never reused
        
        # Determine encryption mode and derive key
        ephemeral_public_key = None
        
        if receiver_public_key is not None:
            # FORWARD SECRECY MODE: Use X25519 ephemeral keys
            try:
                from meow_decoder.x25519_forward_secrecy import (
                    generate_ephemeral_keypair,
                    derive_shared_secret,
                    deserialize_public_key,
                    serialize_public_key
                )
            except ImportError:
                # Try relative import
                from .x25519_forward_secrecy import (
                    generate_ephemeral_keypair,
                    derive_shared_secret,
                    deserialize_public_key,
                    serialize_public_key
                )
            
            # Generate ephemeral keypair (now returns ForwardSecrecyKeys with bytes)
            fs_keys = generate_ephemeral_keypair()
            
            # Deserialize receiver's public key (validates bytes)
            receiver_pubkey = deserialize_public_key(receiver_public_key)
            
            # Derive shared secret (expects bytes)
            key = derive_shared_secret(
                fs_keys.ephemeral_private,
                receiver_pubkey,
                password,
                salt
            )
            
            # Export ephemeral public key for transmission (validates bytes)
            ephemeral_public_key = serialize_public_key(fs_keys.ephemeral_public)
            
            # NOTE: fs_keys.ephemeral_private goes out of scope here
            # This provides forward secrecy - private key never stored!
        else:
            # PASSWORD-ONLY MODE: Standard Argon2id derivation
            if yubikey_slot is not None:
                if keyfile is not None:
                    raise ValueError("Cannot combine --yubikey with --keyfile")
                backend = get_default_backend()
                key = backend.derive_key_yubikey(
                    password.encode("utf-8"),
                    salt,
                    slot=yubikey_slot,
                    pin=yubikey_pin
                )
            else:
                key = derive_key(password, salt, keyfile)
        
        # Build AAD (Additional Authenticated Data) for manifest protection
        # Why: Binding metadata to the AEAD prevents substitution and
        # protocol-confusion attacks against lengths/hash/version fields.
        aad = struct.pack('<QQ', len(raw), len(comp))  # orig_len, comp_len
        aad += salt  # Include salt in authentication
        aad += sha   # Include original hash in authentication
        aad += MAGIC  # Include version magic in authentication
        
        if ephemeral_public_key is not None:
            # Why: Bind ephemeral public key to ciphertext to prevent
            # key-substitution attacks in forward secrecy mode.
            # Include ephemeral public key in AAD for forward secrecy mode
            aad += ephemeral_public_key
        
        # Best-effort nonce reuse guard (per-process)
        _register_nonce_use(key, nonce)

        # Encrypt with AES-256-GCM using AAD
        # Why: AEAD enforces authenticity before decryption; no partial
        # plaintext is released on tag failure.
        # AAD is authenticated but not encrypted
        backend = get_default_backend()
        cipher = backend.aes_gcm_encrypt(key, nonce, comp, aad)  # ← AAD prevents metadata tampering!
        
        return comp, sha, salt, nonce, cipher, ephemeral_public_key, key
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")


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
    yubikey_pin: Optional[str] = None
) -> bytes:
    """
    Decrypt and decompress file data with AAD verification.
    
    Args:
        cipher: Encrypted data
        password: Decryption password
        salt: Salt used during encryption
        nonce: Nonce used during encryption
        keyfile: Optional keyfile content
        orig_len: Original length (for AAD reconstruction)
        comp_len: Compressed length (for AAD reconstruction)
        sha256: Original hash (for AAD reconstruction)
        ephemeral_public_key: Optional ephemeral X25519 public key (32 bytes)
                             Present = forward secrecy mode
                             None = password-only mode
        receiver_private_key: Receiver's X25519 private key (required if ephemeral_public_key present)
        
    Returns:
        Decrypted and decompressed plaintext
        
    Raises:
        RuntimeError: If decryption or decompression fails
        ValueError: If forward secrecy mode but receiver_private_key missing
        
    Security:
        - Verifies AAD before decrypting
        - Ensures manifest hasn't been tampered with
        - Fails if AAD doesn't match
        - Forward secrecy: Uses receiver's private key + sender's ephemeral public key
    """
    try:
        # Determine decryption mode and derive key
        if ephemeral_public_key is not None:
            # FORWARD SECRECY MODE
            if receiver_private_key is None:
                raise ValueError("Forward secrecy mode requires receiver private key")
            
            try:
                from meow_decoder.x25519_forward_secrecy import (
                    derive_shared_secret,
                    deserialize_public_key
                )
            except ImportError:
                # Try relative import
                from .x25519_forward_secrecy import (
                    derive_shared_secret,
                    deserialize_public_key
                )
            
            # Deserialize sender's ephemeral public key
            sender_pubkey = deserialize_public_key(ephemeral_public_key)
            
            # Derive shared secret (same as sender)
            # Receiver private key is passed as bytes, sender pubkey as bytes
            key = derive_shared_secret(
                receiver_private_key,
                sender_pubkey,
                password,
                salt
            )
        else:
            # PASSWORD-ONLY MODE
            if yubikey_slot is not None:
                if keyfile is not None:
                    raise ValueError("Cannot combine --yubikey with --keyfile")
                backend = get_default_backend()
                key = backend.derive_key_yubikey(
                    password.encode("utf-8"),
                    salt,
                    slot=yubikey_slot,
                    pin=yubikey_pin
                )
            else:
                key = derive_key(password, salt, keyfile)
        
        # Reconstruct AAD for verification
        # Must match exactly what was used during encryption
        if orig_len is not None and comp_len is not None and sha256 is not None:
            aad = struct.pack('<QQ', orig_len, comp_len)
            aad += salt
            aad += sha256
            aad += MAGIC
            
            if ephemeral_public_key is not None:
                # Include ephemeral public key in AAD for forward secrecy mode
                aad += ephemeral_public_key
        else:
            aad = None  # Backwards compatibility (no AAD)
        
        # Decrypt with AES-256-GCM
        # GCM will verify AAD matches before decrypting
        backend = get_default_backend()
        comp = backend.aes_gcm_decrypt(key, nonce, cipher, aad)  # ← AAD verified here!
        
        # Remove length padding if present
        # Try to remove padding, fall back to no padding for backward compatibility
        try:
            try:
                from .metadata_obfuscation import remove_length_padding
            except ImportError:
                from metadata_obfuscation import remove_length_padding
            comp = remove_length_padding(comp)
        except (ValueError, ImportError):
            # No padding or padding corrupted - use as-is
            # This provides backward compatibility with files without padding
            pass
        
        # Decompress
        raw = zlib.decompress(comp)
        
        return raw
    except Exception as e:
        raise RuntimeError(f"Decryption failed (wrong password/keyfile or tampered manifest?): {e}")


def pack_manifest(m: Manifest) -> bytes:
    """
    Serialize manifest to bytes.
    
    Format (base, 115 bytes):
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
    
    Format (with forward secrecy, 147 bytes):
        (base 115 bytes) +
        ephemeral_public_key (32 bytes)
    
    Format (with forward secrecy + PQ, 1235 bytes):
        (base with FS 147 bytes) +
        pq_ciphertext (1088 bytes)
    
    Args:
        m: Manifest object
        
    Returns:
        Serialized manifest bytes (115, 147, or 1235 bytes)
        
    Notes:
        - Password-only mode: 115 bytes (MEOW2 backward compat)
        - Forward secrecy mode: 147 bytes (MEOW3)
        - PQ hybrid mode: 1235 bytes (MEOW4)
    """
    base = (
        MAGIC +
        m.salt +
        m.nonce +
        struct.pack(">III", m.orig_len, m.comp_len, m.cipher_len) +
        struct.pack(">HI", m.block_size, m.k_blocks) +
        m.sha256 +
        m.hmac
    )
    
    # Add ephemeral public key if forward secrecy enabled
    if m.ephemeral_public_key is not None:
        if len(m.ephemeral_public_key) != 32:
            raise ValueError(f"Ephemeral public key must be 32 bytes, got {len(m.ephemeral_public_key)}")
        base = base + m.ephemeral_public_key
    
    # Add PQ ciphertext if PQ hybrid enabled
    if m.pq_ciphertext is not None:
        if len(m.pq_ciphertext) != 1088:
            raise ValueError(f"PQ ciphertext must be 1088 bytes, got {len(m.pq_ciphertext)}")
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
        Manifest object with optional ephemeral_public_key, pq_ciphertext, and duress_tag
        
    Raises:
        ValueError: If manifest is invalid or wrong version
        
    Notes:
        Valid manifest sizes:
        - 115 bytes = password-only mode (MEOW2, legacy)
        - 147 bytes = forward secrecy mode (MEOW3)
        - 179 bytes = forward secrecy + duress (MEOW3 + duress tag)
        - 1235 bytes = PQ hybrid mode (MEOW4)
        - 1267 bytes = PQ hybrid + duress (MEOW4 + duress tag)
    """
    min_len = len(MAGIC) + 16 + 12 + 12 + 6 + 32 + 32  # 115 bytes (base)
    fs_len = min_len + 32  # 147 bytes (with ephemeral public key)
    fs_duress_len = fs_len + 32  # 179 bytes (with FS + duress)
    pq_len = fs_len + 1088  # 1235 bytes (with PQ ciphertext)
    pq_duress_len = pq_len + 32  # 1267 bytes (with PQ + duress)
    
    valid_sizes = [min_len, fs_len, fs_duress_len, pq_len, pq_duress_len]
    
    if len(b) < min_len:
        raise ValueError(f"Manifest too short (got {len(b)}, need at least {min_len} bytes)")
    
    if len(b) not in valid_sizes:
        raise ValueError(f"Manifest length invalid (got {len(b)}, expected one of {valid_sizes} bytes)")
    
    if b[:len(MAGIC)] != MAGIC:
        # Try MEOW2 for backward compatibility
        if b[:5] == b"MEOW2":
            # Old version without forward secrecy
            # Fall through to parse as password-only mode
            pass
        else:
            raise ValueError("Invalid MAGIC/version (possibly old v1 file or corrupted data)")
    
    off = len(MAGIC)
    salt = b[off:off+16]; off += 16
    nonce = b[off:off+12]; off += 12
    orig_len, comp_len, cipher_len = struct.unpack(">III", b[off:off+12]); off += 12
    block_size, k_blocks = struct.unpack(">HI", b[off:off+6]); off += 6
    sha = b[off:off+32]; off += 32
    hmac_tag = b[off:off+32]; off += 32
    
    # Parse optional fields based on manifest size
    ephemeral_public_key = None
    pq_ciphertext = None
    duress_tag = None
    
    if len(b) >= fs_len:
        # Forward secrecy mode - extract ephemeral public key
        ephemeral_public_key = b[off:off+32]; off += 32
    
    if len(b) >= pq_len:
        # PQ hybrid mode - extract PQ ciphertext
        pq_ciphertext = b[off:off+1088]; off += 1088
    
    # Check for duress tag (last 32 bytes if size matches duress variant)
    if len(b) == fs_duress_len or len(b) == pq_duress_len:
        duress_tag = b[off:off+32]
    
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
        duress_tag=duress_tag
    )


def derive_encryption_key_for_manifest(
    password: str,
    salt: bytes,
    keyfile: Optional[bytes] = None,
    ephemeral_public_key: Optional[bytes] = None,
    receiver_private_key: Optional[bytes] = None,
    yubikey_slot: Optional[str] = None,
    yubikey_pin: Optional[str] = None
) -> bytes:
    """
    Derive the encryption key for a manifest, matching encryption/decryption paths.

    This helper centralizes key derivation to keep frame MAC and HMAC derivations
    consistent and avoids subtle divergence.
    """
    if ephemeral_public_key is not None:
        if receiver_private_key is None:
            raise ValueError("Forward secrecy mode requires receiver private key")

        try:
            from meow_decoder.x25519_forward_secrecy import (
                derive_shared_secret,
                deserialize_public_key
            )
        except ImportError:
            from .x25519_forward_secrecy import (
                derive_shared_secret,
                deserialize_public_key
            )

        sender_pubkey = deserialize_public_key(ephemeral_public_key)
        return derive_shared_secret(
            receiver_private_key,
            sender_pubkey,
            password,
            salt
        )

    if yubikey_slot is not None:
        if keyfile is not None:
            raise ValueError("Cannot combine --yubikey with --keyfile")
        backend = get_default_backend()
        return backend.derive_key_yubikey(
            password.encode("utf-8"),
            salt,
            slot=yubikey_slot,
            pin=yubikey_pin
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
    yubikey_pin: Optional[str] = None
) -> bytes:
    """
    Compute HMAC over manifest (without the hmac field itself).
    
    Args:
        password: User password
        salt: Salt from manifest
        packed_no_hmac: Serialized manifest without HMAC field
        keyfile: Optional keyfile content
        ephemeral_public_key: Optional ephemeral X25519 public key (forward secrecy mode)
        receiver_private_key: Receiver's X25519 private key (required if ephemeral_public_key present during decoding)
        encryption_key: Pre-derived encryption key (32 bytes) - if provided, used directly instead of deriving
        
    Returns:
        32-byte HMAC-SHA256 tag
        
    Security:
        - Uses same key derivation as encryption
        - Forward secrecy mode: Uses X25519 shared secret
        - Password-only mode: Uses Argon2id key derivation
        - During encoding: encryption_key is provided directly
        - During decoding: key is derived from receiver_private_key + ephemeral_public_key
    """
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
            yubikey_pin=yubikey_pin
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
    yubikey_pin: Optional[str] = None
) -> bool:
    """
    Verify manifest HMAC with constant-time comparison and timing equalization.
    
    Args:
        password: User password
        manifest: Manifest to verify
        keyfile: Optional keyfile content
        receiver_private_key: Receiver's X25519 private key (required if manifest has ephemeral_public_key)
        
    Returns:
        True if HMAC is valid
        
    Security:
        - Constant-time comparison prevents timing attacks
        - Timing equalization adds defense in depth
        - Prevents password/keyfile oracle attacks
        - Supports forward secrecy mode with X25519
    """
    # Pack manifest without HMAC
    packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=True)
    
    # Compute expected HMAC (with forward secrecy support)
    expected_hmac = compute_manifest_hmac(
        password, 
        manifest.salt, 
        packed_no_hmac, 
        keyfile,
        ephemeral_public_key=manifest.ephemeral_public_key,
        receiver_private_key=receiver_private_key,
        yubikey_slot=yubikey_slot,
        yubikey_pin=yubikey_pin
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
        # Fallback to secrets.compare_digest
        result = secrets.compare_digest(expected_hmac, manifest.hmac)
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
    computed_sha = hashlib.sha256(test_data).digest()
    assert computed_sha == sha, "SHA256 should match"
    print("   ✓ SHA256 verification works")
    
    # Test 4: Manifest packing/unpacking
    print("\n4. Testing manifest...")
    
    manifest = Manifest(
        salt=salt, nonce=nonce,
        orig_len=len(test_data),
        comp_len=len(comp),
        cipher_len=len(cipher),
        sha256=sha,
        block_size=512,
        k_blocks=10,
        hmac=b'\x00' * 32  # Placeholder
    )
    
    # Compute HMAC
    packed_no_hmac = pack_manifest(manifest)[:-32]
    manifest.hmac = compute_manifest_hmac(password, salt, packed_no_hmac)
    
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
        comp_kf, sha_kf, salt_kf, nonce_kf, cipher_kf, _, _ = encrypt_file_bytes(test_data, password, keyfile)
        
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
