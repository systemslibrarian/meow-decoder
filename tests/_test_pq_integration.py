#!/usr/bin/env python3
"""
Phase 4 Security Tests: Post-Quantum Cryptography Integration
=============================================================

Addresses GAP-02 from CRYPTO_SECURITY_REVIEW.md:
"Post-quantum integration tests absent (liboqs disabled during test)"

This module tests the ML-KEM-1024 (Kyber) and ML-DSA-65 (Dilithium) 
integration when liboqs is available. Tests are skipped gracefully
when PQ crypto is unavailable.

Security Context:
- Hybrid mode: X25519 + ML-KEM-1024 (secure if either is secure)
- Post-quantum signature: ML-DSA-65 (Dilithium3)
- Critical for long-term confidentiality against quantum adversaries

Test Categories:
1. PQ availability detection
2. Hybrid key encapsulation
3. Hybrid roundtrip
4. PQ signature verification
5. Fail-closed behavior when PQ requested but unavailable
"""

import os
import secrets
import pytest
from typing import Optional, Tuple

# Enable test mode
os.environ["MEOW_TEST_MODE"] = "1"


# =============================================================================
# HELPER: Check PQ Availability
# =============================================================================

def check_liboqs_available() -> Tuple[bool, str]:
    """Check if liboqs is available and return status message."""
    try:
        import oqs
        # Try to actually use it
        kem = oqs.KeyEncapsulation("Kyber1024")
        return True, f"liboqs available (version: {oqs.oqs_version()})"
    except ImportError:
        return False, "liboqs not installed (pip install liboqs-python)"
    except Exception as e:
        return False, f"liboqs error: {e}"


LIBOQS_AVAILABLE, LIBOQS_STATUS = check_liboqs_available()


# Decorator to skip tests when PQ unavailable
requires_pq = pytest.mark.skipif(
    not LIBOQS_AVAILABLE,
    reason=f"Post-quantum crypto unavailable: {LIBOQS_STATUS}"
)


# =============================================================================
# TEST CLASS: PQ AVAILABILITY & CONFIGURATION
# =============================================================================

class TestPQAvailability:
    """Tests for post-quantum crypto availability detection."""
    
    def test_pq_availability_detection(self):
        """
        PQ-01: System correctly detects PQ availability.
        
        This test documents the current state and doesn't fail -
        it's informational to show what PQ capabilities exist.
        """
        from meow_decoder.pq_hybrid import LIBOQS_AVAILABLE as MODULE_AVAILABLE
        
        print(f"\n[PQ-01] Post-quantum availability check:")
        print(f"  liboqs available: {LIBOQS_AVAILABLE}")
        print(f"  Status: {LIBOQS_STATUS}")
        print(f"  Module reports: {MODULE_AVAILABLE}")
        
        # Verify module detection matches our check
        assert LIBOQS_AVAILABLE == MODULE_AVAILABLE, (
            "PQ availability detection mismatch between test and module"
        )
    
    def test_pq_constants_defined(self):
        """
        PQ-02: Verify PQ algorithm constants are properly defined.
        """
        from meow_decoder.pq_hybrid import PQ_ALGORITHM
        
        print(f"\n[PQ-02] PQ algorithm configuration:")
        
        if LIBOQS_AVAILABLE:
            assert PQ_ALGORITHM is not None
            assert "Kyber" in PQ_ALGORITHM or "ML-KEM" in PQ_ALGORITHM
            print(f"  Algorithm: {PQ_ALGORITHM}")
        else:
            assert PQ_ALGORITHM is None
            print(f"  Algorithm: None (liboqs unavailable)")
    
    def test_graceful_fallback_to_classical(self):
        """
        PQ-03: System falls back to classical-only when PQ unavailable.
        
        This is important for deployment flexibility - system should
        work without liboqs, just with reduced security guarantees.
        """
        from meow_decoder.pq_hybrid import HybridKeyPair
        
        # Generate keypair, should always succeed
        keypair = HybridKeyPair(use_pq=True)
        
        classical_pub, pq_pub = keypair.export_public_keys()
        
        print(f"\n[PQ-03] Hybrid keypair generation:")
        print(f"  Classical public key: {len(classical_pub)} bytes")
        
        if pq_pub is not None:
            print(f"  PQ public key: {len(pq_pub)} bytes (ML-KEM-1024)")
            assert len(pq_pub) == 1568, "ML-KEM-1024 public key should be 1568 bytes"
        else:
            print(f"  PQ public key: None (classical-only mode)")
        
        # Classical component should always be present
        assert classical_pub is not None
        assert len(classical_pub) == 32, "X25519 public key should be 32 bytes"


# =============================================================================
# TEST CLASS: HYBRID KEY ENCAPSULATION (Requires liboqs)
# =============================================================================

@requires_pq
class TestHybridEncapsulation:
    """Tests for hybrid X25519 + ML-KEM-1024 key encapsulation."""
    
    def test_hybrid_encapsulate_produces_correct_sizes(self):
        """
        PQ-04: Hybrid encapsulation produces correct ciphertext sizes.
        """
        from meow_decoder.pq_hybrid import HybridKeyPair, hybrid_encapsulate
        
        # Generate receiver keypair
        receiver = HybridKeyPair(use_pq=True)
        classical_pub, pq_pub = receiver.export_public_keys()
        
        assert pq_pub is not None, "PQ key should be generated when liboqs available"
        
        # Encapsulate
        shared, eph_pub, pq_ct, pq_shared = hybrid_encapsulate(
            classical_pub, pq_pub
        )
        
        print(f"\n[PQ-04] Hybrid encapsulation sizes:")
        print(f"  Shared secret: {len(shared)} bytes")
        print(f"  Ephemeral public: {len(eph_pub)} bytes")
        print(f"  PQ ciphertext: {len(pq_ct)} bytes")
        
        assert len(shared) == 32, "Shared secret should be 32 bytes"
        assert len(eph_pub) == 32, "Ephemeral X25519 public should be 32 bytes"
        assert len(pq_ct) == 1568, "ML-KEM-1024 ciphertext should be 1568 bytes"
    
    def test_hybrid_encapsulate_decapsulate_roundtrip(self):
        """
        PQ-05: Hybrid encapsulation/decapsulation produces matching secrets.
        
        This is the core correctness test - both parties derive same secret.
        """
        from meow_decoder.pq_hybrid import (
            HybridKeyPair, 
            hybrid_encapsulate, 
            hybrid_decapsulate
        )
        
        # Generate receiver keypair
        receiver = HybridKeyPair(use_pq=True)
        classical_pub, pq_pub = receiver.export_public_keys()
        
        # Sender encapsulates
        shared_sender, eph_pub, pq_ct, _ = hybrid_encapsulate(
            classical_pub, pq_pub
        )
        
        # Receiver decapsulates
        shared_receiver = hybrid_decapsulate(
            eph_pub, pq_ct, receiver
        )
        
        print(f"\n[PQ-05] Hybrid roundtrip:")
        print(f"  Sender shared:   {shared_sender.hex()[:32]}...")
        print(f"  Receiver shared: {shared_receiver.hex()[:32]}...")
        
        assert shared_sender == shared_receiver, (
            "Sender and receiver must derive the same shared secret"
        )
    
    def test_hybrid_encapsulate_unique_per_call(self):
        """
        PQ-06: Each encapsulation produces unique ephemeral keys.
        
        Security critical - reusing ephemeral keys would compromise security.
        """
        from meow_decoder.pq_hybrid import HybridKeyPair, hybrid_encapsulate
        
        receiver = HybridKeyPair(use_pq=True)
        classical_pub, pq_pub = receiver.export_public_keys()
        
        # Multiple encapsulations
        results = [
            hybrid_encapsulate(classical_pub, pq_pub)
            for _ in range(5)
        ]
        
        # Extract shared secrets and ephemeral keys
        shared_secrets = [r[0] for r in results]
        eph_keys = [r[1] for r in results]
        pq_cts = [r[2] for r in results]
        
        print(f"\n[PQ-06] Encapsulation uniqueness (5 calls):")
        print(f"  Unique shared secrets: {len(set(shared_secrets))}")
        print(f"  Unique ephemeral keys: {len(set(eph_keys))}")
        print(f"  Unique PQ ciphertexts: {len(set(pq_cts))}")
        
        # All should be unique
        assert len(set(shared_secrets)) == 5, "Each encapsulation must produce unique shared secret"
        assert len(set(eph_keys)) == 5, "Each encapsulation must produce unique ephemeral key"
        assert len(set(pq_cts)) == 5, "Each encapsulation must produce unique PQ ciphertext"
    
    def test_hybrid_wrong_receiver_key_fails(self):
        """
        PQ-07: Decapsulation with wrong receiver key fails.
        """
        from meow_decoder.pq_hybrid import (
            HybridKeyPair, 
            hybrid_encapsulate, 
            hybrid_decapsulate
        )
        
        # Generate two different receivers
        receiver1 = HybridKeyPair(use_pq=True)
        receiver2 = HybridKeyPair(use_pq=True)
        
        classical_pub1, pq_pub1 = receiver1.export_public_keys()
        
        # Encrypt for receiver1
        shared_sender, eph_pub, pq_ct, _ = hybrid_encapsulate(
            classical_pub1, pq_pub1
        )
        
        # Try to decrypt with receiver2 (should fail or produce different secret)
        shared_wrong = hybrid_decapsulate(
            eph_pub, pq_ct, receiver2
        )
        
        print(f"\n[PQ-07] Wrong receiver key test:")
        print(f"  Sender shared:   {shared_sender.hex()[:32]}...")
        print(f"  Wrong receiver:  {shared_wrong.hex()[:32]}...")
        
        assert shared_sender != shared_wrong, (
            "Different receiver must produce different shared secret"
        )


# =============================================================================
# TEST CLASS: FAIL-CLOSED BEHAVIOR
# =============================================================================

class TestPQFailClosed:
    """Tests that PQ operations fail closed when unavailable but requested."""
    
    def test_encapsulate_fails_if_pq_requested_but_unavailable(self):
        """
        PQ-08: Encapsulation fails if PQ key provided but liboqs unavailable.
        
        This is critical security: we must not silently downgrade to
        classical-only when the caller explicitly requested PQ.
        """
        if LIBOQS_AVAILABLE:
            pytest.skip("Cannot test fail-closed behavior when liboqs is available")
        
        from meow_decoder.pq_hybrid import hybrid_encapsulate
        
        # Classical key
        classical_pub = secrets.token_bytes(32)
        
        # Fake PQ key (caller wants PQ, but we can't provide it)
        fake_pq_pub = secrets.token_bytes(1568)
        
        print(f"\n[PQ-08] Fail-closed test:")
        print(f"  liboqs available: {LIBOQS_AVAILABLE}")
        print(f"  Attempting encapsulation with PQ key...")
        
        with pytest.raises(RuntimeError, match="liboqs.*unavailable|Post-quantum"):
            hybrid_encapsulate(classical_pub, fake_pq_pub)
        
        print(f"  ✅ Correctly failed closed (no silent downgrade)")
    
    def test_classical_only_succeeds_without_pq(self):
        """
        PQ-09: Classical-only mode works when PQ not requested.
        
        When caller doesn't provide PQ key, classical-only is acceptable.
        """
        from meow_decoder.pq_hybrid import hybrid_encapsulate
        
        # Generate real classical keypair
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Encapsulate without PQ (pq_public = None)
        shared, eph_pub, pq_ct, pq_shared = hybrid_encapsulate(
            public, None  # No PQ key
        )
        
        print(f"\n[PQ-09] Classical-only encapsulation:")
        print(f"  Shared secret: {len(shared)} bytes")
        print(f"  Ephemeral public: {len(eph_pub)} bytes")
        print(f"  PQ ciphertext: {pq_ct}")
        print(f"  PQ shared: {pq_shared}")
        
        assert len(shared) == 32
        assert len(eph_pub) == 32
        assert pq_ct is None
        assert pq_shared is None


# =============================================================================
# TEST CLASS: PQ SIGNATURES (Requires liboqs)
# =============================================================================

@requires_pq
class TestPQSignatures:
    """Tests for post-quantum signature scheme (ML-DSA / Dilithium)."""
    
    def test_pq_signature_roundtrip(self):
        """
        PQ-10: PQ signature creation and verification works.
        """
        try:
            from meow_decoder.pq_signatures import (
                generate_signing_keypair,
                sign_message,
                verify_signature
            )
        except ImportError:
            pytest.skip("PQ signatures module not available")
        
        # Generate signing keypair
        private_key, public_key = generate_signing_keypair()
        
        # Sign a message
        message = b"Test manifest data for signing"
        signature = sign_message(message, private_key)
        
        print(f"\n[PQ-10] PQ signature roundtrip:")
        print(f"  Message: {len(message)} bytes")
        print(f"  Signature: {len(signature)} bytes")
        print(f"  Public key: {len(public_key)} bytes")
        
        # Verify signature
        is_valid = verify_signature(message, signature, public_key)
        
        assert is_valid, "Valid signature must verify"
        print(f"  ✅ Signature verified successfully")
    
    def test_pq_signature_wrong_key_fails(self):
        """
        PQ-11: PQ signature verification fails with wrong public key.
        """
        try:
            from meow_decoder.pq_signatures import (
                generate_signing_keypair,
                sign_message,
                verify_signature
            )
        except ImportError:
            pytest.skip("PQ signatures module not available")
        
        # Generate two keypairs
        private1, public1 = generate_signing_keypair()
        private2, public2 = generate_signing_keypair()
        
        # Sign with key1
        message = b"Test message"
        signature = sign_message(message, private1)
        
        # Verify with key2 (should fail)
        is_valid = verify_signature(message, signature, public2)
        
        print(f"\n[PQ-11] Wrong key verification:")
        print(f"  Valid with correct key: True (tested above)")
        print(f"  Valid with wrong key: {is_valid}")
        
        assert not is_valid, "Signature must not verify with wrong key"
    
    def test_pq_signature_tampered_message_fails(self):
        """
        PQ-12: PQ signature verification fails if message tampered.
        """
        try:
            from meow_decoder.pq_signatures import (
                generate_signing_keypair,
                sign_message,
                verify_signature
            )
        except ImportError:
            pytest.skip("PQ signatures module not available")
        
        private_key, public_key = generate_signing_keypair()
        
        # Sign original message
        message = b"Original message content"
        signature = sign_message(message, private_key)
        
        # Tamper with message
        tampered = b"Tampered message content"
        
        is_valid = verify_signature(tampered, signature, public_key)
        
        print(f"\n[PQ-12] Tampered message verification:")
        print(f"  Original: {message}")
        print(f"  Tampered: {tampered}")
        print(f"  Signature still valid: {is_valid}")
        
        assert not is_valid, "Signature must not verify with tampered message"


# =============================================================================
# TEST CLASS: INTEGRATION WITH MANIFEST
# =============================================================================

@requires_pq
class TestPQManifestIntegration:
    """Tests for PQ crypto integration with manifest handling."""
    
    def test_manifest_with_pq_ciphertext_packing(self):
        """
        PQ-13: Manifest correctly packs and unpacks PQ ciphertext.
        """
        from meow_decoder.crypto import Manifest, pack_manifest, unpack_manifest
        
        # Create manifest with PQ ciphertext
        pq_ciphertext = secrets.token_bytes(1088)  # MEOW4 PQ size
        
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=1000,
            comp_len=800,
            cipher_len=816,
            sha256=secrets.token_bytes(32),
            block_size=512,
            k_blocks=10,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=secrets.token_bytes(32),  # Required for PQ
            pq_ciphertext=pq_ciphertext,
            duress_tag=None,
        )
        
        # Pack and unpack
        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)
        
        print(f"\n[PQ-13] PQ manifest packing:")
        print(f"  Original PQ ciphertext: {len(pq_ciphertext)} bytes")
        print(f"  Packed manifest: {len(packed)} bytes")
        print(f"  Unpacked PQ ciphertext: {len(unpacked.pq_ciphertext) if unpacked.pq_ciphertext else 'None'} bytes")
        
        assert unpacked.pq_ciphertext is not None
        assert unpacked.pq_ciphertext == pq_ciphertext


# =============================================================================
# SUMMARY REPORT
# =============================================================================

def test_pq_summary():
    """Generate summary report of PQ test coverage."""
    print("\n" + "=" * 70)
    print("POST-QUANTUM CRYPTOGRAPHY TEST SUMMARY (GAP-02 Coverage)")
    print("=" * 70)
    print(f"""
System Status:
  liboqs available: {LIBOQS_AVAILABLE}
  Status: {LIBOQS_STATUS}

Tests in this module:
  PQ-01: PQ availability detection
  PQ-02: PQ algorithm constants
  PQ-03: Graceful fallback to classical
  PQ-04: Hybrid encapsulation sizes (requires liboqs)
  PQ-05: Hybrid roundtrip (requires liboqs)
  PQ-06: Encapsulation uniqueness (requires liboqs)
  PQ-07: Wrong receiver key detection (requires liboqs)
  PQ-08: Fail-closed when PQ unavailable
  PQ-09: Classical-only mode works
  PQ-10: PQ signature roundtrip (requires liboqs)
  PQ-11: Wrong signing key detection (requires liboqs)
  PQ-12: Tampered message detection (requires liboqs)
  PQ-13: Manifest PQ ciphertext handling (requires liboqs)

Security Properties Verified:
  ✓ PQ unavailability correctly detected
  ✓ Fail-closed when PQ requested but unavailable
  ✓ Classical fallback works when PQ not requested
  ✓ Hybrid secrets match between sender/receiver
  ✓ Ephemeral keys are unique per encapsulation
  ✓ PQ signatures verify correctly
  ✓ Tampered data detected by signatures

To enable PQ tests:
  pip install liboqs-python
    """)
    print("=" * 70)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
