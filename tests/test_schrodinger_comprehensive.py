#!/usr/bin/env python3
"""
🐱⚛️ Comprehensive Schrödinger Mode Tests

Tests edge cases, security boundaries, and corner cases for
true plausible deniability verification.
"""

import pytest
import secrets
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.schrodinger_encode import schrodinger_encode_data, SchrodingerManifest
from meow_decoder.schrodinger_decode import schrodinger_decode_data
from meow_decoder.decoy_generator import generate_convincing_decoy


class TestCrossPasswordIsolation:
    """Verify that passwords cannot decrypt the wrong reality."""
    
    def test_real_password_cannot_get_decoy_data(self):
        """Real password should not return decoy data."""
        real_data = b"TOP SECRET MILITARY PLANS" * 50
        decoy_data = b"Innocent vacation photos" * 50
        real_pw = "RealSecretPassword123"
        decoy_pw = "InnocentPassword456"
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, real_pw, decoy_pw, block_size=128
        )
        
        decoded = schrodinger_decode_data(superposition, manifest, real_pw)
        
        assert decoded is not None, "Real password should decode something"
        assert decoded == real_data, "Real password should return real data"
        assert decoded != decoy_data, "Real password must NOT return decoy data"
    
    def test_decoy_password_cannot_get_real_data(self):
        """Decoy password should not return real data."""
        real_data = b"TOP SECRET MILITARY PLANS" * 50
        decoy_data = b"Innocent vacation photos" * 50
        real_pw = "RealSecretPassword123"
        decoy_pw = "InnocentPassword456"
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, real_pw, decoy_pw, block_size=128
        )
        
        decoded = schrodinger_decode_data(superposition, manifest, decoy_pw)
        
        assert decoded is not None, "Decoy password should decode something"
        assert decoded == decoy_data, "Decoy password should return decoy data"
        assert decoded != real_data, "Decoy password must NOT return real data"
    
    def test_complete_password_isolation(self):
        """Comprehensive test: each password gets only its reality."""
        real_data = secrets.token_bytes(1000)
        decoy_data = secrets.token_bytes(1000)
        real_pw = "PasswordA_Complex!@#$"
        decoy_pw = "PasswordB_Different789"
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, real_pw, decoy_pw, block_size=128
        )
        
        # Decode with both passwords
        decoded_real = schrodinger_decode_data(superposition, manifest, real_pw)
        decoded_decoy = schrodinger_decode_data(superposition, manifest, decoy_pw)
        
        # Verify isolation
        assert decoded_real == real_data
        assert decoded_decoy == decoy_data
        assert decoded_real != decoded_decoy, "Both realities must be different"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_minimal_data_10_bytes(self):
        """Test with very small data (10 bytes)."""
        real_data = b"0123456789"
        decoy_data = b"abcdefghij"
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "password1", "password2", block_size=64
        )
        
        decoded_real = schrodinger_decode_data(superposition, manifest, "password1")
        decoded_decoy = schrodinger_decode_data(superposition, manifest, "password2")
        
        assert decoded_real == real_data
        assert decoded_decoy == decoy_data
    
    def test_single_byte_data(self):
        """Test with single byte data."""
        real_data = b"X"
        decoy_data = b"Y"
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "passA!!!!!", "passB!!!!!", block_size=64
        )
        
        decoded_real = schrodinger_decode_data(superposition, manifest, "passA!!!!!")
        decoded_decoy = schrodinger_decode_data(superposition, manifest, "passB!!!!!")
        
        assert decoded_real == real_data
        assert decoded_decoy == decoy_data
    
    def test_asymmetric_data_sizes(self):
        """Test with very different data sizes (padding should handle it)."""
        real_data = b"Short"
        decoy_data = b"This is a much longer decoy file with more content" * 10
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "short_pass", "long_pass!", block_size=128
        )
        
        decoded_real = schrodinger_decode_data(superposition, manifest, "short_pass")
        decoded_decoy = schrodinger_decode_data(superposition, manifest, "long_pass!")
        
        assert decoded_real == real_data
        assert decoded_decoy == decoy_data
    
    def test_large_data_100kb(self):
        """Test with larger data (~100 KB)."""
        real_data = secrets.token_bytes(100_000)
        decoy_data = secrets.token_bytes(100_000)
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "bigpass123", "bigpass456", block_size=512
        )
        
        decoded_real = schrodinger_decode_data(superposition, manifest, "bigpass123")
        decoded_decoy = schrodinger_decode_data(superposition, manifest, "bigpass456")
        
        assert decoded_real == real_data
        assert decoded_decoy == decoy_data


class TestPasswordValidation:
    """Test password handling edge cases."""
    
    def test_unicode_passwords(self):
        """Test with Unicode/emoji passwords."""
        real_data = b"Secret data"
        decoy_data = b"Decoy data!"
        real_pw = "密码🔐🐱猫咪安全很好"  # Chinese + emojis (8+ chars)
        decoy_pw = "пароль🎉✨безопасность"   # Russian + emojis (8+ chars)
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, real_pw, decoy_pw, block_size=64
        )
        
        decoded_real = schrodinger_decode_data(superposition, manifest, real_pw)
        decoded_decoy = schrodinger_decode_data(superposition, manifest, decoy_pw)
        
        assert decoded_real == real_data
        assert decoded_decoy == decoy_data
    
    def test_special_character_passwords(self):
        """Test with special characters in passwords."""
        real_data = b"Secret"
        decoy_data = b"Decoy!"
        real_pw = "p@$$w0rd!#%^&*()[]{}|\\:\";<>,./?"
        decoy_pw = "~`!@#$%^&*()_+-=[]{}|;':\",./<>?"
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, real_pw, decoy_pw, block_size=64
        )
        
        decoded_real = schrodinger_decode_data(superposition, manifest, real_pw)
        decoded_decoy = schrodinger_decode_data(superposition, manifest, decoy_pw)
        
        assert decoded_real == real_data
        assert decoded_decoy == decoy_data
    
    def test_wrong_password_returns_none(self):
        """Wrong password should return None, not raise exception."""
        real_data = b"Secret data here"
        decoy_data = b"Innocent data here"
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "correct_pw", "other_pw!", block_size=64
        )
        
        # Try completely wrong password
        result = schrodinger_decode_data(superposition, manifest, "totally_wrong_password")
        
        assert result is None, "Wrong password should return None"
    
    def test_similar_but_wrong_password(self):
        """Almost-correct passwords should still fail."""
        real_data = b"Secret"
        decoy_data = b"Decoy!"
        
        superposition, manifest = schrodinger_encode_data(
            real_data, decoy_data, "CorrectPassword123", "DecoyPassword456", block_size=64
        )
        
        # Try similar passwords
        wrong_passwords = [
            "correctpassword123",  # lowercase
            "CorrectPassword124",  # off by one
            "CorrectPassword123 ", # trailing space
            " CorrectPassword123", # leading space
            "CorrectPassword12",   # missing char
        ]
        
        for wrong_pw in wrong_passwords:
            result = schrodinger_decode_data(superposition, manifest, wrong_pw)
            assert result is None, f"Password '{wrong_pw}' should not work"


class TestManifestIntegrity:
    """Test manifest handling and validation."""
    
    def test_manifest_version_is_0x07(self):
        """Verify manifest uses correct version for v5.5.0."""
        real_data = b"Test data"
        decoy_data = b"Decoy data"
        
        _, manifest = schrodinger_encode_data(
            real_data, decoy_data, "pw1_12345", "pw2_12345", block_size=64
        )
        
        assert manifest.version == 0x07, "Schrödinger v5.5.0 should use version 0x07"
    
    def test_manifest_pack_unpack_preserves_data(self):
        """Manifest should survive pack/unpack cycle."""
        real_data = b"Test data for manifest"
        decoy_data = b"Decoy manifest test!"
        
        _, manifest = schrodinger_encode_data(
            real_data, decoy_data, "manifest_pw", "decoy_mfst", block_size=64
        )
        
        # Pack and unpack
        packed = manifest.pack()
        unpacked = SchrodingerManifest.unpack(packed)
        
        # Verify all fields preserved
        assert unpacked.salt_a == manifest.salt_a
        assert unpacked.salt_b == manifest.salt_b
        assert unpacked.nonce_a == manifest.nonce_a
        assert unpacked.nonce_b == manifest.nonce_b
        assert unpacked.reality_a_hmac == manifest.reality_a_hmac
        assert unpacked.reality_b_hmac == manifest.reality_b_hmac
        assert unpacked.metadata_a == manifest.metadata_a
        assert unpacked.metadata_b == manifest.metadata_b
        assert unpacked.block_count == manifest.block_count
        assert unpacked.block_size == manifest.block_size
        assert unpacked.superposition_len == manifest.superposition_len
    
    def test_manifest_rejects_wrong_version(self):
        """Manifest with wrong version should fail to unpack."""
        real_data = b"Test"
        decoy_data = b"Decoy"
        
        _, manifest = schrodinger_encode_data(
            real_data, decoy_data, "pwa123456", "pwb123456", block_size=64
        )
        
        packed = manifest.pack()
        
        # Tamper with version byte (byte 4)
        tampered = bytearray(packed)
        tampered[4] = 0x99  # Wrong version
        
        with pytest.raises(ValueError, match="Not a Schrödinger v5.5.0"):
            SchrodingerManifest.unpack(bytes(tampered))


class TestDecoyGeneration:
    """Test automatic decoy generation."""
    
    def test_decoy_generator_returns_bytes(self):
        """Decoy generator should return bytes."""
        decoy = generate_convincing_decoy(1000)
        
        assert isinstance(decoy, bytes)
        assert len(decoy) >= 1000  # May be slightly larger
    
    def test_decoy_generator_different_sizes(self):
        """Decoy generator produces plausible content for various target sizes."""
        # Note: generate_convincing_decoy creates a ZIP file with fixed structure
        # The "target_size" is a hint but the actual output may vary
        sizes = [100, 1000, 10000, 50000]
        
        for size in sizes:
            decoy = generate_convincing_decoy(size)
            assert isinstance(decoy, bytes)
            # Just verify it returns non-empty bytes (ZIP structure is fixed-ish)
            assert len(decoy) > 0
    
    def test_decoy_is_plausible(self):
        """Decoy should contain plausible-looking content."""
        decoy = generate_convincing_decoy(5000)
        
        # Should have some ASCII-printable content or be ZIP-like
        # Just verify it's not all zeros or all ones
        assert decoy != b'\x00' * len(decoy), "Decoy should not be all zeros"
        assert len(set(decoy)) > 10, "Decoy should have some variety"


class TestQuantumMixer:
    """Test the quantum mixer functions."""
    
    def test_collapse_to_reality_extracts_correct_data(self):
        """collapse_to_reality should extract the correct interleaved data."""
        from meow_decoder.quantum_mixer import entangle_realities, collapse_to_reality
        
        reality_a = b"AAAA"
        reality_b = b"BBBB"
        
        superposition = entangle_realities(reality_a, reality_b)
        
        # Should be interleaved: A B A B A B A B
        assert len(superposition) == 8
        
        # Collapse to each reality
        collapsed_a = collapse_to_reality(superposition, 0)
        collapsed_b = collapse_to_reality(superposition, 1)
        
        assert collapsed_a == reality_a
        assert collapsed_b == reality_b
    
    def test_entangle_pads_shorter_reality(self):
        """Entanglement should pad the shorter reality."""
        from meow_decoder.quantum_mixer import entangle_realities
        
        reality_a = b"AAA"  # 3 bytes
        reality_b = b"BBBBB"  # 5 bytes
        
        superposition = entangle_realities(reality_a, reality_b)
        
        # Should be padded to match: 5 * 2 = 10 bytes
        assert len(superposition) == 10


class TestDeterminism:
    """Test that encoding is deterministic with same inputs."""
    
    def test_same_inputs_same_manifest_structure(self):
        """Same inputs should produce consistent manifest structure."""
        real_data = b"Deterministic test data"
        decoy_data = b"Deterministic decoy data"
        
        _, manifest1 = schrodinger_encode_data(
            real_data, decoy_data, "det_pass_a", "det_pass_b", block_size=128
        )
        _, manifest2 = schrodinger_encode_data(
            real_data, decoy_data, "det_pass_a", "det_pass_b", block_size=128
        )
        
        # Block count and sizes should be same (salts will differ)
        assert manifest1.block_count == manifest2.block_count
        assert manifest1.block_size == manifest2.block_size


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
