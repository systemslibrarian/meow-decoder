#!/usr/bin/env python3
"""
🧪 Tests for pq_signatures.py - Post-Quantum Signatures Module

Tests Ed25519, Dilithium3, and hybrid signature operations.
"""

import pytest
import os
import sys
import secrets

# Add parent directory to path
sys.path.insert(0, str(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from meow_decoder.pq_signatures import (
    get_available_algorithms,
    generate_keypair,
    sign_manifest,
    SignatureKeyPair,
    Signature,
    SIG_ED25519,
    SIG_DILITHIUM3,
    SIG_HYBRID,
    DILITHIUM_AVAILABLE,
    HAS_LIBOQS,
)


class TestAvailableAlgorithms:
    """Tests for algorithm availability detection."""
    
    def test_ed25519_always_available(self):
        """Ed25519 should always be available."""
        algos = get_available_algorithms()
        assert "ed25519" in algos
    
    def test_available_algorithms_list(self):
        """Should return a list of available algorithms."""
        algos = get_available_algorithms()
        
        assert isinstance(algos, list)
        assert len(algos) >= 1  # At least ed25519
    
    @pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="liboqs not available")
    def test_dilithium_available_with_liboqs(self):
        """Dilithium should be available when liboqs is installed."""
        algos = get_available_algorithms()
        
        assert "dilithium3" in algos
        assert "hybrid" in algos


class TestEd25519KeyGeneration:
    """Tests for Ed25519 key generation."""
    
    def test_generate_ed25519_keypair(self):
        """Should generate valid Ed25519 keypair."""
        keypair = generate_keypair("ed25519")
        
        assert keypair is not None
        assert keypair.algorithm == SIG_ED25519
        assert len(keypair.private_key) == 32
        assert len(keypair.public_key) == 32
    
    def test_ed25519_keypairs_unique(self):
        """Each generation should produce unique keys."""
        keypair1 = generate_keypair("ed25519")
        keypair2 = generate_keypair("ed25519")
        
        assert keypair1.private_key != keypair2.private_key
        assert keypair1.public_key != keypair2.public_key
    
    def test_ed25519_case_insensitive(self):
        """Algorithm name should be case insensitive."""
        kp1 = generate_keypair("ed25519")
        kp2 = generate_keypair("ED25519")
        kp3 = generate_keypair("Ed25519")
        
        # All should be valid Ed25519 keys
        assert kp1.algorithm == SIG_ED25519
        assert kp2.algorithm == SIG_ED25519
        assert kp3.algorithm == SIG_ED25519


class TestEd25519Signing:
    """Tests for Ed25519 signing operations."""
    
    def test_sign_manifest_ed25519(self):
        """Should sign manifest with Ed25519."""
        keypair = generate_keypair("ed25519")
        manifest = b"test manifest data for signing"
        
        signature = sign_manifest(manifest, keypair)
        
        assert signature is not None
        assert signature.algorithm == SIG_ED25519
        assert len(signature.signature) == 64  # Ed25519 signature size
    
    def test_signature_deterministic(self):
        """Same message should produce same signature with same key."""
        keypair = generate_keypair("ed25519")
        manifest = b"deterministic test"
        
        sig1 = sign_manifest(manifest, keypair)
        sig2 = sign_manifest(manifest, keypair)
        
        assert sig1.signature == sig2.signature
    
    def test_different_messages_different_signatures(self):
        """Different messages should produce different signatures."""
        keypair = generate_keypair("ed25519")
        
        sig1 = sign_manifest(b"message one", keypair)
        sig2 = sign_manifest(b"message two", keypair)
        
        assert sig1.signature != sig2.signature
    
    def test_sign_empty_manifest(self):
        """Should be able to sign empty data."""
        keypair = generate_keypair("ed25519")
        
        signature = sign_manifest(b"", keypair)
        
        assert signature is not None
        assert len(signature.signature) == 64
    
    def test_sign_large_manifest(self):
        """Should be able to sign large data."""
        keypair = generate_keypair("ed25519")
        large_data = secrets.token_bytes(1024 * 1024)  # 1 MB
        
        signature = sign_manifest(large_data, keypair)
        
        assert signature is not None
        assert len(signature.signature) == 64


class TestSignaturePacking:
    """Tests for signature serialization."""
    
    def test_signature_pack_unpack_ed25519(self):
        """Ed25519 signature should roundtrip through pack/unpack."""
        keypair = generate_keypair("ed25519")
        manifest = b"roundtrip test data"
        
        original_sig = sign_manifest(manifest, keypair)
        packed = original_sig.pack()
        unpacked = Signature.unpack(packed)
        
        assert unpacked.algorithm == original_sig.algorithm
        assert unpacked.signature == original_sig.signature
    
    def test_pack_format_ed25519(self):
        """Ed25519 packed signature should have correct format."""
        keypair = generate_keypair("ed25519")
        signature = sign_manifest(b"format test", keypair)
        
        packed = signature.pack()
        
        # Format: algorithm (1) + signature (64)
        assert len(packed) == 1 + 64
        assert packed[0] == SIG_ED25519


class TestSignatureKeyPair:
    """Tests for SignatureKeyPair dataclass."""
    
    def test_keypair_fields(self):
        """KeyPair should have all required fields."""
        keypair = generate_keypair("ed25519")
        
        assert hasattr(keypair, 'algorithm')
        assert hasattr(keypair, 'private_key')
        assert hasattr(keypair, 'public_key')
    
    def test_keypair_optional_fields(self):
        """Optional hybrid fields should default to None."""
        keypair = generate_keypair("ed25519")
        
        # Ed25519 doesn't populate hybrid fields
        assert keypair.ed25519_private is None
        assert keypair.ed25519_public is None


class TestSignatureDataclass:
    """Tests for Signature dataclass."""
    
    def test_signature_fields(self):
        """Signature should have all required fields."""
        keypair = generate_keypair("ed25519")
        sig = sign_manifest(b"test", keypair)
        
        assert hasattr(sig, 'algorithm')
        assert hasattr(sig, 'signature')
    
    def test_signature_optional_fields(self):
        """Hybrid signature fields should default to None for Ed25519."""
        keypair = generate_keypair("ed25519")
        sig = sign_manifest(b"test", keypair)
        
        assert sig.ed25519_sig is None
        assert sig.dilithium_sig is None


@pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="liboqs not available")
class TestDilithiumOperations:
    """Tests for Dilithium3 operations (when available)."""
    
    def test_generate_dilithium_keypair(self):
        """Should generate valid Dilithium3 keypair."""
        keypair = generate_keypair("dilithium3")
        
        assert keypair is not None
        assert keypair.algorithm == SIG_DILITHIUM3
        assert len(keypair.public_key) > 0
        assert len(keypair.private_key) > 0
    
    def test_sign_with_dilithium(self):
        """Should sign manifest with Dilithium3."""
        keypair = generate_keypair("dilithium3")
        manifest = b"dilithium test data"
        
        signature = sign_manifest(manifest, keypair)
        
        assert signature is not None
        assert signature.algorithm == SIG_DILITHIUM3
        assert len(signature.signature) > 0


@pytest.mark.skipif(not DILITHIUM_AVAILABLE, reason="liboqs not available")
class TestHybridOperations:
    """Tests for hybrid Ed25519 + Dilithium3 operations."""
    
    def test_generate_hybrid_keypair(self):
        """Should generate valid hybrid keypair."""
        keypair = generate_keypair("hybrid")
        
        assert keypair is not None
        assert keypair.algorithm == SIG_HYBRID
        
        # Should have both component keys
        assert keypair.ed25519_private is not None
        assert keypair.ed25519_public is not None
        assert keypair.dilithium_private is not None
        assert keypair.dilithium_public is not None
    
    def test_sign_with_hybrid(self):
        """Should sign manifest with hybrid mode."""
        keypair = generate_keypair("hybrid")
        manifest = b"hybrid signature test"
        
        signature = sign_manifest(manifest, keypair)
        
        assert signature is not None
        assert signature.algorithm == SIG_HYBRID
        
        # Should have both component signatures
        assert signature.ed25519_sig is not None
        assert signature.dilithium_sig is not None
    
    def test_hybrid_pack_unpack(self):
        """Hybrid signature should roundtrip through pack/unpack."""
        keypair = generate_keypair("hybrid")
        manifest = b"hybrid roundtrip test"
        
        original_sig = sign_manifest(manifest, keypair)
        packed = original_sig.pack()
        unpacked = Signature.unpack(packed)
        
        assert unpacked.algorithm == SIG_HYBRID
        assert unpacked.ed25519_sig == original_sig.ed25519_sig
        assert unpacked.dilithium_sig == original_sig.dilithium_sig


class TestFallbackBehavior:
    """Tests for graceful fallback behavior."""
    
    def test_hybrid_falls_back_without_liboqs(self):
        """Hybrid should fall back to Ed25519 when liboqs unavailable."""
        if DILITHIUM_AVAILABLE:
            pytest.skip("liboqs is available, cannot test fallback")
        
        # Should not raise, should fall back
        keypair = generate_keypair("hybrid")
        
        # Falls back to Ed25519
        assert keypair.algorithm == SIG_ED25519
    
    def test_dilithium_raises_without_liboqs(self):
        """Dilithium-only should raise when liboqs unavailable."""
        if DILITHIUM_AVAILABLE:
            pytest.skip("liboqs is available, cannot test error case")
        
        with pytest.raises(ValueError, match="not available"):
            generate_keypair("dilithium3")


class TestErrorHandling:
    """Tests for error handling."""
    
    def test_unknown_algorithm_raises(self):
        """Unknown algorithm should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown algorithm"):
            generate_keypair("nonexistent_algo")
    
    def test_invalid_keypair_for_signing(self):
        """Invalid keypair should raise during signing."""
        # Create a malformed keypair
        bad_keypair = SignatureKeyPair(
            algorithm=255,  # Invalid algorithm
            private_key=b"bad",
            public_key=b"keys"
        )
        
        with pytest.raises((ValueError, Exception)):
            sign_manifest(b"test", bad_keypair)


class TestConstants:
    """Tests for module constants."""
    
    def test_algorithm_constants(self):
        """Algorithm constants should have distinct values."""
        assert SIG_ED25519 != SIG_DILITHIUM3
        assert SIG_DILITHIUM3 != SIG_HYBRID
        assert SIG_ED25519 != SIG_HYBRID
    
    def test_has_liboqs_flag(self):
        """HAS_LIBOQS flag should be boolean."""
        assert isinstance(HAS_LIBOQS, bool)
    
    def test_dilithium_available_flag(self):
        """DILITHIUM_AVAILABLE should be boolean."""
        assert isinstance(DILITHIUM_AVAILABLE, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
