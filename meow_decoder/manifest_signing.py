"""
Mandatory ML-DSA-65 + Ed25519 Hybrid Manifest Signing.

All manifests MUST be signed. No unsigned manifests are accepted.
Hybrid signatures provide:
- Classical security (Ed25519) if ML-DSA breaks
- Quantum resistance (ML-DSA-65) if Ed25519 breaks
- Defense-in-depth: attacker must break BOTH to forge

Protocol:
1. Generate hybrid keypair (Ed25519 + ML-DSA-65) per session
2. Sign manifest bytes with BOTH algorithms
3. Concatenate signatures: Ed25519_sig || ML-DSA_sig
4. Verification requires BOTH to pass

Security Invariants:
- INV-039: ALL manifests signed (no bypass flag)
- INV-040: Signature verification fail → hard error (no fallback)
- INV-041: Public key bound in manifest HMAC (prevents key substitution)

Cross-platform: Windows, Linux, macOS (pure Python + Rust backend when available)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "SigningKeyPair",
    "ManifestSignature",
    "generate_signing_keypair",
    "sign_manifest",
    "verify_manifest_signature",
    "SIGNING_MANDATORY",
]

# Signing is MANDATORY — no flag to disable
SIGNING_MANDATORY = True

# Signature algorithm identifiers
SIG_ED25519 = 0x01
SIG_MLDSA65 = 0x02
SIG_HYBRID = 0x03  # Ed25519 + ML-DSA-65

# Signature sizes
ED25519_SIG_SIZE = 64
ED25519_PK_SIZE = 32
ED25519_SK_SIZE = 32

# ML-DSA-65 sizes (FIPS 204 / Dilithium3)
MLDSA65_SIG_SIZE = 3293
MLDSA65_PK_SIZE = 1952
# Rust backend (meow_crypto_rs) stores SK as compact 32-byte seed; signing and
# verification both operate on the seed internally.  The OQS/pure-Python path
# would use the full 4000-byte expanded key — but that path is not installed in
# production (ml_dsa / oqs not in requirements).
MLDSA65_SK_SIZE = 32  # compact seed format (Rust backend)

# Domain separation
MANIFEST_SIGN_DOMAIN = b"meow_manifest_sign_v1"
MANIFEST_VERIFY_DOMAIN = b"meow_manifest_verify_v1"

# Check for Rust backend
_RUST_SIGNING_AVAILABLE = False
_RUST_ED25519_AVAILABLE = False
_RUST_MLDSA_AVAILABLE = False
try:
    import meow_crypto_rs as _rs

    _RUST_ED25519_AVAILABLE = hasattr(_rs, "ed25519_sign")
    _RUST_MLDSA_AVAILABLE = hasattr(_rs, "mldsa65_sign")
    _RUST_SIGNING_AVAILABLE = _RUST_ED25519_AVAILABLE
except ImportError:
    pass

# Fallback to cryptography library for Ed25519
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

# Fallback to ml-dsa pure Python or pqcrypto
try:
    from ml_dsa import ML_DSA_65  # type: ignore

    _MLDSA_PURE_AVAILABLE = True
except ImportError:
    _MLDSA_PURE_AVAILABLE = False

# Check for oqs backend
_OQS_SIG_AVAILABLE = False
try:
    import oqs  # type: ignore[import-not-found]

    _OQS_SIG_AVAILABLE = "Dilithium3" in oqs.get_enabled_sig_mechanisms()
except (ImportError, AttributeError):
    pass


@dataclass
class SigningKeyPair:
    """
    Hybrid signing keypair: Ed25519 + ML-DSA-65.

    Always contains BOTH keys for hybrid signing.
    """

    # Ed25519 keys (32 bytes each)
    ed25519_sk: bytes
    ed25519_pk: bytes

    # ML-DSA-65 keys (4000 / 1952 bytes)
    mldsa65_sk: bytes
    mldsa65_pk: bytes

    def export_public_key(self) -> bytes:
        """Export concatenated public keys."""
        return self.ed25519_pk + self.mldsa65_pk

    @classmethod
    def public_key_size(cls) -> int:
        """Return size of concatenated public key."""
        return ED25519_PK_SIZE + MLDSA65_PK_SIZE


@dataclass
class ManifestSignature:
    """
    Hybrid manifest signature.

    Contains BOTH Ed25519 and ML-DSA-65 signatures.
    """

    ed25519_sig: bytes
    mldsa65_sig: bytes

    def to_bytes(self) -> bytes:
        """Serialize signature."""
        # Format: magic(4) | version(1) | ed25519_sig(64) | mldsa65_sig_len(2) | mldsa65_sig
        return (
            b"MSIG"
            + struct.pack(">B", 1)  # version
            + self.ed25519_sig
            + struct.pack(">H", len(self.mldsa65_sig))
            + self.mldsa65_sig
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ManifestSignature":
        """Deserialize signature."""
        if len(data) < 71:  # magic(4) + version(1) + ed25519(64) + len(2)
            raise ValueError("Signature too short")

        if data[:4] != b"MSIG":
            raise ValueError(f"Invalid signature magic: {data[:4]}")

        version = data[4]
        if version != 1:
            raise ValueError(f"Unsupported signature version: {version}")

        ed25519_sig = data[5:69]
        mldsa_len = struct.unpack(">H", data[69:71])[0]

        if len(data) < 71 + mldsa_len:
            raise ValueError("Signature truncated")

        mldsa65_sig = data[71 : 71 + mldsa_len]

        return cls(ed25519_sig=ed25519_sig, mldsa65_sig=mldsa65_sig)

    @classmethod
    def signature_size(cls) -> int:
        """Return typical signature size."""
        # magic(4) + version(1) + ed25519(64) + len(2) + mldsa65(3293)
        return 4 + 1 + 64 + 2 + MLDSA65_SIG_SIZE


def _ed25519_generate() -> Tuple[bytes, bytes]:
    """Generate Ed25519 keypair."""
    if _RUST_ED25519_AVAILABLE:
        import meow_crypto_rs as rs

        return rs.ed25519_keygen()

    if _CRYPTO_AVAILABLE:
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sk_bytes = sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pk_bytes = pk.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return sk_bytes, pk_bytes

    raise RuntimeError("No Ed25519 implementation available")


def _ed25519_sign(sk: bytes, message: bytes) -> bytes:
    """Sign with Ed25519."""
    if _RUST_ED25519_AVAILABLE:
        import meow_crypto_rs as rs

        return rs.ed25519_sign(sk, message)

    if _CRYPTO_AVAILABLE:
        private_key = Ed25519PrivateKey.from_private_bytes(sk)
        return private_key.sign(message)

    raise RuntimeError("No Ed25519 implementation available")


def _ed25519_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """Verify Ed25519 signature."""
    if _RUST_ED25519_AVAILABLE:
        import meow_crypto_rs as rs

        try:
            rs.ed25519_verify(pk, message, signature)
            return True
        except Exception:
            return False

    if _CRYPTO_AVAILABLE:
        try:
            public_key = Ed25519PublicKey.from_public_bytes(pk)
            public_key.verify(signature, message)
            return True
        except Exception:
            return False

    raise RuntimeError("No Ed25519 implementation available")


def _mldsa65_generate() -> Tuple[bytes, bytes]:
    """Generate ML-DSA-65 keypair."""
    if _RUST_MLDSA_AVAILABLE:
        import meow_crypto_rs as rs

        return rs.mldsa65_keygen()

    if _MLDSA_PURE_AVAILABLE:
        mldsa = ML_DSA_65()
        pk, sk = mldsa.keygen()
        return sk, pk

    if _OQS_SIG_AVAILABLE:
        with oqs.Signature("Dilithium3") as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return sk, pk

    raise RuntimeError(
        "No secure ML-DSA-65 implementation available (Rust, ml-dsa, or OQS). "
        "Insecure stubs are permanently disabled."
    )


def _mldsa65_sign(sk: bytes, message: bytes) -> bytes:
    """Sign with ML-DSA-65."""
    if _RUST_MLDSA_AVAILABLE:
        import meow_crypto_rs as rs

        return rs.mldsa65_sign(sk, message)

    if _MLDSA_PURE_AVAILABLE:
        mldsa = ML_DSA_65()
        return mldsa.sign(sk, message)

    if _OQS_SIG_AVAILABLE:
        with oqs.Signature("Dilithium3", secret_key=sk) as sig:
            return sig.sign(message)

    raise RuntimeError(
        "No secure ML-DSA-65 implementation available. " "Insecure stubs are permanently disabled."
    )


def _mldsa65_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """Verify ML-DSA-65 signature."""
    if _RUST_MLDSA_AVAILABLE:
        import meow_crypto_rs as rs

        try:
            return bool(rs.mldsa65_verify(pk, message, signature))
        except Exception:
            return False

    if _MLDSA_PURE_AVAILABLE:
        try:
            mldsa = ML_DSA_65()
            return mldsa.verify(pk, message, signature)
        except Exception:
            return False

    if _OQS_SIG_AVAILABLE:
        try:
            with oqs.Signature("Dilithium3") as sig:
                return sig.verify(message, signature, pk)
        except Exception:
            return False

    raise RuntimeError(
        "No secure ML-DSA-65 implementation available. " "Insecure stubs are permanently disabled."
    )


def generate_signing_keypair() -> SigningKeyPair:
    """
    Generate hybrid Ed25519 + ML-DSA-65 signing keypair.

    Returns:
        SigningKeyPair with both classical and PQ keys.

    Raises:
        RuntimeError: If required crypto libraries not available.
    """
    ed_sk, ed_pk = _ed25519_generate()
    ml_sk, ml_pk = _mldsa65_generate()

    return SigningKeyPair(
        ed25519_sk=ed_sk,
        ed25519_pk=ed_pk,
        mldsa65_sk=ml_sk,
        mldsa65_pk=ml_pk,
    )


def sign_manifest(
    keypair: SigningKeyPair,
    manifest_bytes: bytes,
    context: bytes = b"",
) -> ManifestSignature:
    """
    Sign manifest with hybrid Ed25519 + ML-DSA-65.

    SIGNING IS MANDATORY — this function has no bypass.

    Args:
        keypair: Signing keypair.
        manifest_bytes: Raw manifest bytes to sign.
        context: Optional domain separation context.

    Returns:
        ManifestSignature with both signatures.
    """
    # Compute message hash with domain separation
    message = MANIFEST_SIGN_DOMAIN + context + manifest_bytes

    # Sign with Ed25519
    ed_sig = _ed25519_sign(keypair.ed25519_sk, message)

    # Sign with ML-DSA-65
    ml_sig = _mldsa65_sign(keypair.mldsa65_sk, message)

    return ManifestSignature(ed25519_sig=ed_sig, mldsa65_sig=ml_sig)


def verify_manifest_signature(
    public_key: bytes,
    manifest_bytes: bytes,
    signature: ManifestSignature,
    context: bytes = b"",
) -> bool:
    """
    Verify hybrid manifest signature.

    VERIFICATION IS MANDATORY — both signatures must pass.

    Args:
        public_key: Concatenated Ed25519 + ML-DSA-65 public keys.
        manifest_bytes: Raw manifest bytes that were signed.
        signature: The signature to verify.
        context: Optional domain separation context (must match signing).

    Returns:
        True if BOTH signatures verify.

    Raises:
        ValueError: If signature verification fails (fail-closed).
    """
    if len(public_key) < ED25519_PK_SIZE + MLDSA65_PK_SIZE:
        raise ValueError(
            f"Public key too short: {len(public_key)} bytes, "
            f"expected {ED25519_PK_SIZE + MLDSA65_PK_SIZE}"
        )

    ed_pk = public_key[:ED25519_PK_SIZE]
    ml_pk = public_key[ED25519_PK_SIZE : ED25519_PK_SIZE + MLDSA65_PK_SIZE]

    # Compute message hash with domain separation
    message = MANIFEST_SIGN_DOMAIN + context + manifest_bytes

    # Verify Ed25519 — MUST pass
    if not _ed25519_verify(ed_pk, message, signature.ed25519_sig):
        raise ValueError("Ed25519 signature verification failed")

    # Verify ML-DSA-65 — MUST pass
    if not _mldsa65_verify(ml_pk, message, signature.mldsa65_sig):
        raise ValueError("ML-DSA-65 signature verification failed")

    return True


def compute_public_key_commitment(public_key: bytes) -> bytes:
    """
    Compute commitment to public key for manifest binding.

    The commitment is included in manifest HMAC to prevent
    key substitution attacks.

    Args:
        public_key: Concatenated Ed25519 + ML-DSA-65 public keys.

    Returns:
        32-byte SHA-256 commitment.
    """
    return hashlib.sha256(b"meow_pk_commitment_v1" + public_key).digest()
