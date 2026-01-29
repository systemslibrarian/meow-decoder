"""
Post-Quantum Hybrid Cryptography
Combines X25519 (classical) + ML-KEM-1024 (Kyber) for quantum resistance

⚠️  EXPERIMENTAL: See security_warnings.py for maturity assessment.

Security Model:
- Hybrid key agreement: X25519 ⊕ ML-KEM-1024
- Secure even if one primitive breaks
- Classical: Fast, well-tested
- PQ: Future-proof against Shor's algorithm
- Combined via HKDF for defense in depth

Requirements:
    pip install liboqs-python

If liboqs not available, classical-only mode is allowed only when the
caller does not request PQ encapsulation or provide PQ ciphertext.
If PQ is requested and unavailable, the operation fails closed.
"""

import secrets
import struct
from typing import Tuple, Optional
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

from .security_warnings import warn_pq_experimental


# Try to import liboqs for post-quantum
try:
    import oqs
    LIBOQS_AVAILABLE = True
    PQ_ALGORITHM = "Kyber1024"  # ML-KEM-1024 (NIST FIPS 203 - highest security)
    # Emit warning when PQ crypto is available and will be used
    warn_pq_experimental()
except ImportError:
    LIBOQS_AVAILABLE = False
    PQ_ALGORITHM = None


class HybridKeyPair:
    """
    Hybrid keypair: X25519 + ML-KEM-1024.
    
    Attributes:
        classical_private: X25519 private key
        classical_public: X25519 public key (32 bytes)
        pq_public: ML-KEM-1024 public key (1568 bytes)
        pq_secret: ML-KEM-1024 secret key (internal, not exported)
    """
    
    def __init__(self, use_pq: bool = True):
        """
        Generate hybrid keypair.
        
        Args:
            use_pq: Enable post-quantum component
                   Falls back to classical if liboqs unavailable
        """
        # Always generate classical key
        self.classical_private = X25519PrivateKey.generate()
        self.classical_public = self.classical_private.public_key()
        
        # Try to generate PQ key
        self.pq_public = None
        self.pq_secret = None
        self.pq_kem = None
        
        if use_pq and LIBOQS_AVAILABLE:
            try:
                self.pq_kem = oqs.KeyEncapsulation(PQ_ALGORITHM)
                self.pq_public = self.pq_kem.generate_keypair()
                # Secret key stored in pq_kem object
            except Exception as e:
                print(f"⚠️  PQ key generation failed: {e}")
                self.pq_kem = None
    
    def export_public_keys(self) -> Tuple[bytes, Optional[bytes]]:
        """
        Export public keys for transmission.
        
        Returns:
            Tuple of (classical_public, pq_public)
            - classical_public: 32 bytes (X25519)
            - pq_public: 1568 bytes (ML-KEM-1024) or None if unavailable
        """
        classical = self.classical_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return classical, self.pq_public
    
    def is_hybrid(self) -> bool:
        """Check if PQ component is active."""
        return self.pq_kem is not None


def hybrid_encapsulate(
    receiver_classical_public: bytes,
    receiver_pq_public: Optional[bytes] = None
) -> Tuple[bytes, bytes, Optional[bytes], Optional[bytes]]:
    """
    Hybrid key encapsulation.
    
    Args:
        receiver_classical_public: Receiver's X25519 public key (32 bytes)
        receiver_pq_public: Receiver's ML-KEM-1024 public key (1568 bytes)
                           None for classical-only mode
        
    Returns:
        Tuple of (shared_secret, ephemeral_classical_public, 
                 pq_ciphertext, pq_shared_secret)
        - shared_secret: Combined hybrid secret (32 bytes)
        - ephemeral_classical_public: Sender's ephemeral X25519 public (32 bytes)
        - pq_ciphertext: ML-KEM-1024 encapsulation (1568 bytes) or None
        - pq_shared_secret: PQ component (32 bytes) or None
        
    Security:
        - Classical: ECDH with X25519
        - PQ: KEM encapsulation with ML-KEM-1024
        - Combined: HKDF(classical_secret || pq_secret)
        - Secure even if one primitive breaks!
    """
    # Generate ephemeral classical keypair
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    
    # Classical key agreement
    receiver_pubkey = X25519PublicKey.from_public_bytes(receiver_classical_public)
    classical_shared = ephemeral_private.exchange(receiver_pubkey)
    
    # Export ephemeral public key
    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Try PQ encapsulation
    pq_ciphertext = None
    pq_shared_secret = None
    
    if receiver_pq_public is not None:
        if not LIBOQS_AVAILABLE:
            # Why: Fail closed to prevent silent downgrade when PQ was requested.
            raise RuntimeError("Post-quantum requested but liboqs is unavailable")
        try:
            pq_kem = oqs.KeyEncapsulation(PQ_ALGORITHM)
            pq_ciphertext, pq_shared_secret = pq_kem.encap_secret(receiver_pq_public)
        except Exception as e:
            raise RuntimeError(f"Post-quantum encapsulation failed: {e}")
    
    # Combine secrets with HKDF
    # Why: HKDF provides a conservative KDF to mix classical+PQ material
    # and enforces domain separation from other keys.
    if pq_shared_secret is not None:
        # Hybrid mode: Classical ⊕ PQ
        combined_material = classical_shared + pq_shared_secret
        info = b"meow_hybrid_pq_v1"
    else:
        # Classical-only mode
        combined_material = classical_shared
        info = b"meow_classical_only_v1"
    
    # Derive final shared secret
    shared_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=info
    ).derive(combined_material)
    
    return shared_secret, ephemeral_public_bytes, pq_ciphertext, pq_shared_secret


def hybrid_decapsulate(
    ephemeral_classical_public: bytes,
    pq_ciphertext: Optional[bytes],
    receiver_keypair: HybridKeyPair
) -> bytes:
    """
    Hybrid key decapsulation.
    
    Args:
        ephemeral_classical_public: Sender's ephemeral X25519 public (32 bytes)
        pq_ciphertext: ML-KEM-1024 ciphertext (1568 bytes) or None
        receiver_keypair: Receiver's hybrid keypair
        
    Returns:
        Shared secret (32 bytes)
        
    Security:
        - Decapsulates both classical and PQ components
        - Combines with HKDF (same as encapsulate)
        - Must match sender's derivation exactly
    """
    # Classical key agreement
    sender_pubkey = X25519PublicKey.from_public_bytes(ephemeral_classical_public)
    classical_shared = receiver_keypair.classical_private.exchange(sender_pubkey)
    
    # Try PQ decapsulation
    pq_shared_secret = None
    
    if pq_ciphertext is not None:
        if receiver_keypair.pq_kem is None:
            # Why: Fail closed if PQ ciphertext is present but no PQ key exists.
            raise RuntimeError("Post-quantum ciphertext provided but receiver has no PQ key")
        try:
            pq_shared_secret = receiver_keypair.pq_kem.decap_secret(pq_ciphertext)
        except Exception as e:
            raise RuntimeError(f"Post-quantum decapsulation failed: {e}")
    
    # Combine secrets (must match encapsulate!)
    if pq_shared_secret is not None:
        # Hybrid mode
        combined_material = classical_shared + pq_shared_secret
        info = b"meow_hybrid_pq_v1"
    else:
        # Classical-only mode
        combined_material = classical_shared
        info = b"meow_classical_only_v1"
    
    # Derive final shared secret
    shared_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=info
    ).derive(combined_material)
    
    return shared_secret


def check_pq_available() -> Tuple[bool, str]:
    """
    Check if post-quantum crypto is available.
    
    Returns:
        Tuple of (available, message)
    """
    if not LIBOQS_AVAILABLE:
        return False, "liboqs-python not installed (pip install liboqs-python)"
    
    try:
        # Test KEM creation
        test_kem = oqs.KeyEncapsulation(PQ_ALGORITHM)
        return True, f"ML-KEM-1024 available"
    except Exception as e:
        return False, f"ML-KEM-1024 unavailable: {e}"


# Example usage
if __name__ == "__main__":
    print("Post-Quantum Hybrid Crypto Test")
    print("=" * 50)
    
    # Check PQ availability
    pq_available, pq_message = check_pq_available()
    print(f"\nPost-Quantum Status: {pq_message}")
    print(f"Available: {pq_available}")
    
    if not pq_available:
        print(f"\n⚠️  Install with: pip install liboqs-python")
        print(f"   Falling back to classical-only mode...")
    
    # Test classical-only mode (always works)
    print(f"\n1. Classical-only mode (X25519):")
    
    receiver = HybridKeyPair(use_pq=False)
    classical_pub, pq_pub = receiver.export_public_keys()
    
    print(f"   Classical public key: {classical_pub.hex()[:32]}... ({len(classical_pub)} bytes)")
    print(f"   PQ public key: {pq_pub}")
    print(f"   Is hybrid: {receiver.is_hybrid()}")
    
    # Encapsulate
    shared_secret, ephemeral_pub, pq_ct, pq_ss = hybrid_encapsulate(
        classical_pub, pq_pub
    )
    
    print(f"\n   Encapsulation:")
    print(f"   Shared secret: {shared_secret.hex()[:32]}...")
    print(f"   Ephemeral public: {ephemeral_pub.hex()[:32]}...")
    print(f"   PQ ciphertext: {pq_ct}")
    
    # Decapsulate
    recovered_secret = hybrid_decapsulate(ephemeral_pub, pq_ct, receiver)
    
    print(f"\n   Decapsulation:")
    print(f"   Recovered secret: {recovered_secret.hex()[:32]}...")
    print(f"   Match: {shared_secret == recovered_secret}")
    
    # Test hybrid mode if available
    if pq_available:
        print(f"\n2. Hybrid mode (X25519 + ML-KEM-1024):")
        
        receiver_hybrid = HybridKeyPair(use_pq=True)
        classical_pub_h, pq_pub_h = receiver_hybrid.export_public_keys()
        
        print(f"   Classical public key: {classical_pub_h.hex()[:32]}... ({len(classical_pub_h)} bytes)")
        print(f"   PQ public key: {pq_pub_h.hex()[:32] if pq_pub_h else None}... ({len(pq_pub_h) if pq_pub_h else 0} bytes)")
        print(f"   Is hybrid: {receiver_hybrid.is_hybrid()}")
        
        # Encapsulate
        shared_secret_h, ephemeral_pub_h, pq_ct_h, pq_ss_h = hybrid_encapsulate(
            classical_pub_h, pq_pub_h
        )
        
        print(f"\n   Encapsulation:")
        print(f"   Shared secret: {shared_secret_h.hex()[:32]}...")
        print(f"   Ephemeral public: {ephemeral_pub_h.hex()[:32]}...")
        print(f"   PQ ciphertext: {pq_ct_h.hex()[:32] if pq_ct_h else None}... ({len(pq_ct_h) if pq_ct_h else 0} bytes)")
        
        # Decapsulate
        recovered_secret_h = hybrid_decapsulate(ephemeral_pub_h, pq_ct_h, receiver_hybrid)
        
        print(f"\n   Decapsulation:")
        print(f"   Recovered secret: {recovered_secret_h.hex()[:32]}...")
        print(f"   Match: {shared_secret_h == recovered_secret_h}")
        
        print(f"\n✅ Hybrid post-quantum crypto working!")
    else:
        print(f"\n⚠️  Hybrid mode not tested (liboqs unavailable)")
    
    print(f"\n✅ Post-quantum module functional!")
    print(f"   Note: Falls back gracefully to classical-only if PQ unavailable")
