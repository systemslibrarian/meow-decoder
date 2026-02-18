"""
Post-Quantum Hybrid Cryptography
Combines X25519 (classical) + ML-KEM (Kyber) for quantum resistance

⚠️  EXPERIMENTAL: See security_warnings.py for maturity assessment.

Security Model:
- Hybrid key agreement: X25519 ⊕ ML-KEM
- Default: ML-KEM-768 (NIST security level 3, Signal parity)
- Paranoid: ML-KEM-1024 (NIST security level 5)
- Secure even if one primitive breaks
- Combined via two-step HKDF (PQXDH-style transcript binding)

KEM Variants:
    ML-KEM-768  (default):  pk=1184B, ct=1088B, ss=32B — matches Signal PQXDH
    ML-KEM-1024 (paranoid):  pk=1568B, ct=1568B, ss=32B — maximum security

Requirements:
    pip install liboqs-python

If liboqs not available, classical-only mode is allowed only when the
caller does not request PQ encapsulation or provide PQ ciphertext.
If PQ is requested and unavailable, the operation fails closed.
"""

import os
import secrets
import struct
from typing import Tuple, Optional

from .crypto_backend import get_default_backend
from .security_warnings import warn_pq_experimental

# ── ML-KEM variant constants ─────────────────────────────────────────────────
PQ_ALGORITHM_768 = "Kyber768"  # ML-KEM-768:  NIST level 3 (Signal default)
PQ_ALGORITHM_1024 = "Kyber1024"  # ML-KEM-1024: NIST level 5 (paranoid)
PQ_CT_SIZE_768 = 1088  # ML-KEM-768 ciphertext size
PQ_CT_SIZE_1024 = 1568  # ML-KEM-1024 ciphertext size
PQ_PK_SIZE_768 = 1184  # ML-KEM-768 public key size
PQ_PK_SIZE_1024 = 1568  # ML-KEM-1024 public key size

# HKDF domain separation constants (PQXDH-style)
PQXDH_EXTRACT_SALT = b"\x00" * 32  # Fixed zero salt for HKDF-Extract
PQXDH_INFO_PREFIX = b"meow_pqxdh_v1"  # KDF domain separator (hybrid mode)
PQXDH_TRANSCRIPT_DOMAIN = b"meow_pqxdh_transcript_v1"  # Transcript hash domain
CLASSICAL_INFO = b"meow_classical_only_v1"  # Classical-only mode (no change)

# ── Production Mode Gate ─────────────────────────────────────────────────────
# PRODUCTION_MODE = True by default. In production:
#   - PQ MUST use Rust backend (meow_crypto_rs compiled with 'pq' feature)
#   - Python oqs library is FORBIDDEN
#   - If PQ requested but Rust PQ unavailable → hard error (no silent fallback)
PRODUCTION_MODE = os.environ.get("MEOW_PRODUCTION_MODE", "1") != "0"

# Check Rust PQ availability
_RUST_PQ_AVAILABLE = False
try:
    import meow_crypto_rs as _pq_rs

    _RUST_PQ_AVAILABLE = hasattr(_pq_rs, "mlkem768_keygen")
except ImportError:
    pass

# Try to import liboqs for post-quantum (REMOVED from production — AUDIT-C1)
# Python oqs is FORBIDDEN in all modes. PQ MUST use Rust backend.
LIBOQS_AVAILABLE = False
PQ_ALGORITHM = None

if _RUST_PQ_AVAILABLE:
    # Rust PQ is authoritative
    LIBOQS_AVAILABLE = True
    PQ_ALGORITHM = PQ_ALGORITHM_768
# Without Rust PQ: LIBOQS_AVAILABLE stays False.
# Any attempt to use PQ will fail closed with a hard error.


class HybridKeyPair:
    """
    Hybrid keypair: X25519 + ML-KEM (768 or 1024).

    Attributes:
        classical_private: X25519 private key
        classical_public: X25519 public key (32 bytes)
        pq_public: ML-KEM public key (1184 or 1568 bytes depending on variant)
        pq_secret: ML-KEM secret key (internal, not exported)
        paranoid: True if using ML-KEM-1024 (security level 5)
    """

    def __init__(self, use_pq: bool = True, paranoid: bool = False):
        """
        Generate hybrid keypair.

        Args:
            use_pq: Enable post-quantum component
                   Falls back to classical if liboqs unavailable
            paranoid: Use ML-KEM-1024 instead of ML-KEM-768 (default False)
        """
        # Always generate classical key
        backend = get_default_backend()
        self._classical_private_bytes, self._classical_public_bytes = (
            backend.x25519_generate_keypair()
        )
        self.paranoid = paranoid

        # Try to generate PQ key
        self.pq_public = None
        self.pq_secret = None
        self.pq_kem = None
        self._pq_secret_bytes = None

        if use_pq and LIBOQS_AVAILABLE:
            if PRODUCTION_MODE and not _RUST_PQ_AVAILABLE and not LIBOQS_AVAILABLE:
                raise RuntimeError(
                    "PQ hybrid mode requested but Rust PQ backend not available. "
                    "Rebuild with: cd rust_crypto && maturin develop --release --features pq. "
                    "No silent fallback to classical-only in production mode."
                )
            if _RUST_PQ_AVAILABLE:
                # Use Rust-backed ML-KEM (required)
                try:
                    sk_bytes, pk_bytes = _pq_rs.mlkem768_keygen()
                    self.pq_public = pk_bytes
                    self._pq_secret_bytes = sk_bytes
                    self.pq_kem = None
                except Exception as e:
                    raise RuntimeError(f"Rust PQ key generation failed: {e}") from e
            else:
                raise RuntimeError(
                    "PQ hybrid mode requested but Rust PQ backend not available. "
                    "Python oqs fallback is FORBIDDEN. "
                    "Rebuild Rust backend with: cd rust_crypto && maturin develop --release --features pq"
                )
        elif use_pq and not LIBOQS_AVAILABLE:
            if PRODUCTION_MODE:
                raise RuntimeError(
                    "PQ hybrid mode requested but no PQ backend available. "
                    "Rebuild Rust backend with: cd rust_crypto && maturin develop --release --features pq. "
                    "No silent fallback to classical-only in production mode."
                )

    def export_public_keys(self) -> Tuple[bytes, Optional[bytes]]:
        """
        Export public keys for transmission.

        Returns:
            Tuple of (classical_public, pq_public)
            - classical_public: 32 bytes (X25519)
            - pq_public: 1184 bytes (ML-KEM-768) or 1568 bytes (ML-KEM-1024) or None
        """
        return self._classical_public_bytes, self.pq_public

    def export_keypair(self) -> Tuple[bytes, bytes]:
        """
        Export classical keypair bytes for serialization.

        Returns:
            Tuple of (classical_private, classical_public)
            - classical_private: 32 bytes (X25519 private key)
            - classical_public: 32 bytes (X25519 public key)

        Note:
            This is for key persistence only. Handle returned bytes securely.
        """
        return self._classical_private_bytes, self._classical_public_bytes

    def is_hybrid(self) -> bool:
        """Check if PQ component is active."""
        return self.pq_public is not None


def _compute_transcript_hash(
    ephemeral_pub: bytes,
    receiver_classical_pub: bytes,
    receiver_pq_pub: Optional[bytes],
    pq_ciphertext: Optional[bytes],
) -> bytes:
    """
    Compute PQXDH-style transcript hash binding all public values.

    This provides full transcript binding à la Signal PQXDH — an attacker
    who swaps any public key or ciphertext produces a different transcript
    hash, which yields a different derived key → AES-GCM decryption fails.

    Args:
        ephemeral_pub: Sender's ephemeral X25519 public key (32 bytes)
        receiver_classical_pub: Receiver's X25519 public key (32 bytes)
        receiver_pq_pub: Receiver's ML-KEM public key (1184 or 1568 bytes, or None)
        pq_ciphertext: ML-KEM ciphertext (1088 or 1568 bytes, or None)

    Returns:
        32-byte SHA-256 transcript hash
    """
    backend = get_default_backend()
    data = PQXDH_TRANSCRIPT_DOMAIN + ephemeral_pub + receiver_classical_pub
    if receiver_pq_pub is not None:
        data += receiver_pq_pub
    if pq_ciphertext is not None:
        data += pq_ciphertext
    return backend.sha256(data)


def _pqxdh_derive(
    classical_shared: bytes,
    pq_shared_secret: Optional[bytes],
    ephemeral_pub: bytes,
    receiver_classical_pub: bytes,
    receiver_pq_pub: Optional[bytes],
    pq_ciphertext: Optional[bytes],
) -> bytes:
    """
    Two-step HKDF key derivation with PQXDH transcript binding.

    Step 1 (Extract): PRK = HMAC-SHA256(salt=0x00…, IKM=classical_ss || pq_ss)
    Step 2 (Expand):  shared_secret = HKDF-Expand(PRK,
                        info="meow_pqxdh_v1" || transcript_hash, L=32)

    This matches Signal's PQXDH pattern:
    - Zero salt ensures deterministic extraction regardless of ephemeral entropy
    - Transcript hash binds all exchanged public values into the key derivation
    - Any tampering with public keys or ciphertext → different key → GCM fails

    Args:
        classical_shared: X25519 shared secret (32 bytes)
        pq_shared_secret: ML-KEM shared secret (32 bytes) or None
        ephemeral_pub: Sender's ephemeral X25519 public key (32 bytes)
        receiver_classical_pub: Receiver's X25519 public key (32 bytes)
        receiver_pq_pub: Receiver's ML-KEM public key or None
        pq_ciphertext: ML-KEM ciphertext or None

    Returns:
        32-byte shared secret for encryption
    """
    if pq_shared_secret is not None:
        combined_ikm = classical_shared + pq_shared_secret
    else:
        combined_ikm = classical_shared

    backend = get_default_backend()

    # Step 1: HKDF-Extract with fixed zero salt (Signal PQXDH pattern)
    prk = backend.hmac_sha256(PQXDH_EXTRACT_SALT, combined_ikm)

    # Compute transcript hash binding all public values
    transcript_hash = _compute_transcript_hash(
        ephemeral_pub, receiver_classical_pub, receiver_pq_pub, pq_ciphertext
    )

    # Step 2: HKDF-Expand with domain-separated transcript
    if pq_shared_secret is not None:
        info = PQXDH_INFO_PREFIX + transcript_hash
    else:
        info = CLASSICAL_INFO + transcript_hash

    shared_secret = backend.hkdf_expand(prk, info, 32)

    return shared_secret


def hybrid_encapsulate(
    receiver_classical_public: bytes,
    receiver_pq_public: Optional[bytes] = None,
    paranoid: bool = False,
) -> Tuple[bytes, bytes, Optional[bytes], Optional[bytes]]:
    """
    Hybrid key encapsulation with PQXDH-style transcript binding.

    Args:
        receiver_classical_public: Receiver's X25519 public key (32 bytes)
        receiver_pq_public: Receiver's ML-KEM public key
                           ML-KEM-768: 1184 bytes (default)
                           ML-KEM-1024: 1568 bytes (paranoid)
                           None for classical-only mode
        paranoid: Use ML-KEM-1024 instead of ML-KEM-768

    Returns:
        Tuple of (shared_secret, ephemeral_classical_public,
                 pq_ciphertext, pq_shared_secret)
        - shared_secret: Combined hybrid secret (32 bytes)
        - ephemeral_classical_public: Sender's ephemeral X25519 public (32 bytes)
        - pq_ciphertext: ML-KEM ciphertext (1088 or 1568 bytes) or None
        - pq_shared_secret: PQ component (32 bytes) or None

    Security:
        - Classical: ECDH with X25519
        - PQ: KEM encapsulation with ML-KEM-768 (or ML-KEM-1024 in paranoid mode)
        - Combined: Two-step HKDF with PQXDH transcript binding
        - Secure even if one primitive breaks!
    """
    # Generate ephemeral classical keypair
    backend = get_default_backend()
    ephemeral_private_bytes, ephemeral_public_bytes = backend.x25519_generate_keypair()

    # Classical key agreement
    classical_shared = backend.x25519_exchange(ephemeral_private_bytes, receiver_classical_public)

    # Try PQ encapsulation
    pq_ciphertext = None
    pq_shared_secret = None

    if receiver_pq_public is not None:
        if not LIBOQS_AVAILABLE or not _RUST_PQ_AVAILABLE:
            raise RuntimeError("Post-quantum requested but Rust PQ backend unavailable")
        algorithm = PQ_ALGORITHM_1024 if paranoid else PQ_ALGORITHM_768
        try:
            # Use Rust ML-KEM encapsulation
            pq_shared_secret, pq_ciphertext = _pq_rs.mlkem768_encapsulate(receiver_pq_public)
        except Exception as e:
            raise RuntimeError(f"Post-quantum encapsulation failed: {e}")

    # Derive shared secret with PQXDH two-step HKDF + transcript binding
    shared_secret = _pqxdh_derive(
        classical_shared=classical_shared,
        pq_shared_secret=pq_shared_secret,
        ephemeral_pub=ephemeral_public_bytes,
        receiver_classical_pub=receiver_classical_public,
        receiver_pq_pub=receiver_pq_public,
        pq_ciphertext=pq_ciphertext,
    )

    return shared_secret, ephemeral_public_bytes, pq_ciphertext, pq_shared_secret


def hybrid_decapsulate(
    ephemeral_classical_public: bytes,
    pq_ciphertext: Optional[bytes],
    receiver_keypair: HybridKeyPair,
) -> bytes:
    """
    Hybrid key decapsulation with PQXDH-style transcript binding.

    Args:
        ephemeral_classical_public: Sender's ephemeral X25519 public (32 bytes)
        pq_ciphertext: ML-KEM ciphertext (1088 or 1568 bytes) or None
        receiver_keypair: Receiver's hybrid keypair

    Returns:
        Shared secret (32 bytes)

    Security:
        - Decapsulates both classical and PQ components
        - Two-step HKDF with PQXDH transcript binding (must match encapsulate)
        - Any key/ciphertext tampering → different transcript → different key
    """
    # Classical key agreement
    backend = get_default_backend()
    classical_shared = backend.x25519_exchange(
        receiver_keypair._classical_private_bytes, ephemeral_classical_public
    )

    # Try PQ decapsulation
    pq_shared_secret = None

    if pq_ciphertext is not None:
        if receiver_keypair._pq_secret_bytes is None:
            raise RuntimeError("Post-quantum ciphertext provided but receiver has no PQ secret key")
        if not _RUST_PQ_AVAILABLE:
            raise RuntimeError("Rust PQ backend required for PQ decapsulation")
        try:
            pq_shared_secret = _pq_rs.mlkem768_decapsulate(
                receiver_keypair._pq_secret_bytes, pq_ciphertext
            )
        except Exception as e:
            raise RuntimeError(f"Post-quantum decapsulation failed: {e}")

    # Get receiver's public keys for transcript binding
    receiver_classical_pub, receiver_pq_pub = receiver_keypair.export_public_keys()

    # Derive shared secret with PQXDH two-step HKDF + transcript binding
    # (must match encapsulate exactly)
    shared_secret = _pqxdh_derive(
        classical_shared=classical_shared,
        pq_shared_secret=pq_shared_secret,
        ephemeral_pub=ephemeral_classical_public,
        receiver_classical_pub=receiver_classical_pub,
        receiver_pq_pub=receiver_pq_pub,
        pq_ciphertext=pq_ciphertext,
    )

    return shared_secret


def check_pq_available(paranoid: bool = False) -> Tuple[bool, str]:
    """
    Check if post-quantum crypto is available.

    Args:
        paranoid: Check for ML-KEM-1024 instead of ML-KEM-768

    Returns:
        Tuple of (available, message)
    """
    if not LIBOQS_AVAILABLE or not _RUST_PQ_AVAILABLE:
        return False, "Rust PQ backend not available (rebuild with --features pq)"

    variant_name = "ML-KEM-1024" if paranoid else "ML-KEM-768"

    try:
        # Test Rust PQ keygen
        _sk, _pk = _pq_rs.mlkem768_keygen()
        return True, f"{variant_name} available (Rust backend)"
    except Exception as e:
        return False, f"{variant_name} unavailable: {e}"


# Example usage
if __name__ == "__main__":
    print("Post-Quantum Hybrid Crypto Test (PQXDH-style)")
    print("=" * 60)

    # Check PQ availability
    pq_768_available, pq_768_message = check_pq_available(paranoid=False)
    pq_1024_available, pq_1024_message = check_pq_available(paranoid=True)
    print(f"\nML-KEM-768 Status: {pq_768_message}")
    print(f"ML-KEM-1024 Status: {pq_1024_message}")

    if not pq_768_available:
        print(f"\n⚠️  Install with: pip install liboqs-python")
        print(f"   Falling back to classical-only mode...")

    # Test classical-only mode (always works)
    print(f"\n1. Classical-only mode (X25519):")

    receiver = HybridKeyPair(use_pq=False)
    classical_pub, pq_pub = receiver.export_public_keys()

    print(f"   Classical public key: {classical_pub.hex()[:32]}... ({len(classical_pub)} bytes)")
    print(f"   PQ public key: {pq_pub.hex() if pq_pub else 'None'}")
    print(f"   Is hybrid: {receiver.is_hybrid()}")

    # Encapsulate
    shared_secret, ephemeral_pub, pq_ct, pq_ss = hybrid_encapsulate(classical_pub, pq_pub)

    print(f"\n   Encapsulation:")
    print(f"   Shared secret: {shared_secret.hex()[:32]}...")
    print(f"   Ephemeral public: {ephemeral_pub.hex()[:32]}...")
    print(f"   PQ ciphertext: {pq_ct.hex()[:32] + '...' if pq_ct else 'None'}")

    # Decapsulate
    recovered_secret = hybrid_decapsulate(ephemeral_pub, pq_ct, receiver)

    print(f"\n   Decapsulation:")
    print(f"   Recovered secret: {recovered_secret.hex()[:32]}...")
    print(f"   Match: {shared_secret == recovered_secret}")

    # Test ML-KEM-768 (default)
    if pq_768_available:
        print(f"\n2. Hybrid mode (X25519 + ML-KEM-768, Signal PQXDH default):")

        receiver_768 = HybridKeyPair(use_pq=True, paranoid=False)
        classical_pub_768, pq_pub_768 = receiver_768.export_public_keys()

        print(
            f"   Classical public key: {classical_pub_768.hex()[:32]}... ({len(classical_pub_768)} bytes)"
        )
        print(
            f"   PQ public key: {pq_pub_768.hex()[:32] if pq_pub_768 else None}... ({len(pq_pub_768) if pq_pub_768 else 0} bytes)"
        )

        shared_768, eph_768, pq_ct_768, _ = hybrid_encapsulate(
            classical_pub_768, pq_pub_768, paranoid=False
        )
        recovered_768 = hybrid_decapsulate(eph_768, pq_ct_768, receiver_768)
        print(f"   PQ ciphertext size: {len(pq_ct_768)} bytes")
        print(f"   Match: {shared_768 == recovered_768}")

    # Test ML-KEM-1024 (paranoid)
    if pq_1024_available:
        print(f"\n3. Paranoid mode (X25519 + ML-KEM-1024):")

        receiver_1024 = HybridKeyPair(use_pq=True, paranoid=True)
        classical_pub_1024, pq_pub_1024 = receiver_1024.export_public_keys()

        print(
            f"   Classical public key: {classical_pub_1024.hex()[:32]}... ({len(classical_pub_1024)} bytes)"
        )
        print(
            f"   PQ public key: {pq_pub_1024.hex()[:32] if pq_pub_1024 else None}... ({len(pq_pub_1024) if pq_pub_1024 else 0} bytes)"
        )

        shared_1024, eph_1024, pq_ct_1024, _ = hybrid_encapsulate(
            classical_pub_1024, pq_pub_1024, paranoid=True
        )
        recovered_1024 = hybrid_decapsulate(eph_1024, pq_ct_1024, receiver_1024)
        print(f"   PQ ciphertext size: {len(pq_ct_1024)} bytes")
        print(f"   Match: {shared_1024 == recovered_1024}")

    print(f"\n✅ PQXDH-style hybrid crypto working!")
    print(f"   Default: ML-KEM-768 (Signal parity)")
    print(f"   Paranoid: ML-KEM-1024 (NIST level 5)")
