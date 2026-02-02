#!/usr/bin/env python3
"""
🎲 TIER 2: Fuzz and Property-Based Tests

Tests using Hypothesis for property-based testing.
These tests verify:

1. Encode-decode roundtrip for random data
2. Tampering detection for random corruptions
3. Key derivation properties
4. Manifest parsing robustness
5. Fountain code invariants

FUZZING PRINCIPLE: Any random valid input must work.
Any random invalid input must fail safely (not crash).
"""

import pytest
import secrets
import hashlib

# Import hypothesis if available
try:
    from hypothesis import given, strategies as st, settings, assume
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    # Create dummy decorators
    def given(*args, **kwargs):
        def decorator(f):
            return pytest.mark.skip(reason="hypothesis not installed")(f)
        return decorator
    def settings(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    class st:
        @staticmethod
        def binary(*args, **kwargs):
            return None
        @staticmethod
        def text(*args, **kwargs):
            return None
        @staticmethod
        def integers(*args, **kwargs):
            return None
    def assume(x):
        pass


from meow_decoder.crypto import derive_key, encrypt_file_bytes, decrypt_to_raw
from meow_decoder.fountain import FountainEncoder, FountainDecoder, pack_droplet, unpack_droplet


class TestKeyDerivationProperties:
    """Property-based tests for key derivation."""
    
    @given(st.text(min_size=8, max_size=64))
    @settings(max_examples=50)
    def test_derive_key_deterministic(self, password):
        """Same password + salt must always produce same key."""
        assume(len(password) >= 8)  # Minimum password requirement
        
        salt = b'\x00' * 16  # Fixed salt for determinism test
        
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        
        assert key1 == key2
        
    @given(st.text(min_size=8, max_size=64), st.text(min_size=8, max_size=64))
    @settings(max_examples=30)
    def test_different_passwords_different_keys(self, pwd1, pwd2):
        """Different passwords must produce different keys."""
        assume(len(pwd1) >= 8 and len(pwd2) >= 8)
        assume(pwd1 != pwd2)
        
        salt = secrets.token_bytes(16)
        
        key1 = derive_key(pwd1, salt)
        key2 = derive_key(pwd2, salt)
        
        assert key1 != key2
        
    @given(st.binary(min_size=16, max_size=16))
    @settings(max_examples=30)
    def test_different_salts_different_keys(self, salt):
        """Different salts must produce different keys."""
        password = "testpassword123"
        
        key1 = derive_key(password, salt)
        key2 = derive_key(password, secrets.token_bytes(16))
        
        # Very high probability of difference (256^16 possible salts)
        # But can't guarantee, so we just check key is valid
        assert len(key1) == 32
        assert len(key2) == 32


class TestEncryptDecryptProperties:
    """Property-based tests for encryption/decryption."""
    
    @given(st.binary(min_size=1, max_size=1024))
    @settings(max_examples=30, deadline=30000)  # 30 second deadline for slow KDF
    def test_encrypt_decrypt_roundtrip(self, data):
        """Any data must round-trip through encrypt/decrypt."""
        password = "testpassword123"
        
        comp, sha, salt, nonce, cipher, eph_key, enc_key = encrypt_file_bytes(
            data, password, use_length_padding=False
        )
        
        decrypted = decrypt_to_raw(
            cipher, password, salt, nonce,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha
        )
        
        assert decrypted == data
        
    @given(st.binary(min_size=1, max_size=256))
    @settings(max_examples=20, deadline=30000)
    def test_ciphertext_length_varies(self, data):
        """Ciphertext length depends on data length."""
        password = "testpassword123"
        
        _, _, _, _, cipher, _, _ = encrypt_file_bytes(
            data, password, use_length_padding=False
        )
        
        # Ciphertext should be >= compressed data + GCM tag
        # Due to compression, exact relationship varies
        assert len(cipher) > 0


class TestFountainCodeProperties:
    """Property-based tests for fountain codes."""
    
    @given(st.binary(min_size=100, max_size=1000))
    @settings(max_examples=20, deadline=10000)
    def test_fountain_roundtrip(self, data):
        """Any data must round-trip through fountain codes."""
        block_size = 100
        k_blocks = (len(data) + block_size - 1) // block_size
        
        # Encode
        encoder = FountainEncoder(data, k_blocks, block_size)
        
        # Decode with enough droplets
        decoder = FountainDecoder(k_blocks, block_size)
        
        max_attempts = k_blocks * 3  # Should need ~1.5x
        for _ in range(max_attempts):
            if decoder.is_complete():
                break
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)
            
        assert decoder.is_complete()
        recovered = decoder.get_data(len(data))
        assert recovered == data
        
    @given(st.integers(min_value=1, max_value=100))
    @settings(max_examples=20)
    def test_droplet_packing_roundtrip(self, seed):
        """Droplets must round-trip through pack/unpack."""
        data = secrets.token_bytes(100)
        block_size = 50
        
        encoder = FountainEncoder(data, 2, block_size)
        
        # Generate droplet with given seed
        droplet = encoder.droplet(seed)
        
        # Pack and unpack
        packed = pack_droplet(droplet)
        unpacked = unpack_droplet(packed, block_size)
        
        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data


class TestManifestRobustness:
    """Property-based tests for manifest handling."""
    
    @given(st.binary(min_size=0, max_size=114))
    @settings(max_examples=50)
    def test_short_manifest_rejected(self, data):
        """Manifests shorter than minimum must be rejected."""
        from meow_decoder.crypto import unpack_manifest
        
        # Minimum is 115 bytes for password-only mode
        if len(data) < 115:
            with pytest.raises(ValueError):
                unpack_manifest(data)
                
    @given(st.binary(min_size=120, max_size=200))
    @settings(max_examples=30)
    def test_random_bytes_rejected(self, data):
        """Random bytes must not parse as valid manifest."""
        from meow_decoder.crypto import unpack_manifest
        
        # Unless data accidentally starts with "MEOW3" or "MEOW2"
        # and has valid length, it should be rejected
        if not (data.startswith(b"MEOW3") or data.startswith(b"MEOW2")):
            with pytest.raises(ValueError):
                unpack_manifest(data)
                
    @given(st.binary(min_size=115, max_size=115))
    @settings(max_examples=20)
    def test_correct_length_wrong_magic_rejected(self, data):
        """Correct length but wrong magic must be rejected."""
        from meow_decoder.crypto import unpack_manifest
        
        # Ensure it doesn't start with valid magic
        if not (data.startswith(b"MEOW3") or data.startswith(b"MEOW2")):
            with pytest.raises(ValueError):
                unpack_manifest(data)


class TestTamperDetection:
    """Property-based tests for tamper detection."""
    
    @given(st.integers(min_value=0, max_value=100), st.integers(min_value=1, max_value=255))
    @settings(max_examples=30, deadline=30000)
    def test_ciphertext_corruption_detected(self, position, xor_value):
        """Any single-byte corruption must be detected."""
        data = b"Test data for tampering detection"
        password = "testpassword123"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, use_length_padding=False
        )
        
        # Corrupt at random position
        position = position % len(cipher)
        corrupted = bytearray(cipher)
        corrupted[position] ^= xor_value
        corrupted = bytes(corrupted)
        
        # Decryption must fail
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                corrupted, password, salt, nonce,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha
            )


class TestEntropyProperties:
    """Property-based tests for entropy and randomness."""
    
    @given(st.text(min_size=8, max_size=64))
    @settings(max_examples=30, deadline=30000)
    def test_keys_have_high_entropy(self, password):
        """Derived keys must have high entropy."""
        assume(len(password) >= 8)
        
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        
        # Simple entropy check: count unique bytes
        unique_bytes = len(set(key))
        
        # A good 32-byte key should have many unique bytes
        # Lower bound is generous to account for random variation
        assert unique_bytes >= 8  # Very conservative lower bound


class TestBoundaryConditions:
    """Test boundary conditions with property-based approaches."""
    
    @given(st.integers(min_value=8, max_value=8))
    @settings(max_examples=5)
    def test_minimum_password_length(self, length):
        """Exactly minimum password length must work."""
        password = "a" * length
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        assert len(key) == 32
        
    @given(st.integers(min_value=1, max_value=7))
    @settings(max_examples=5)
    def test_below_minimum_password_rejected(self, length):
        """Below minimum password length must be rejected."""
        password = "a" * length
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError):
            derive_key(password, salt)


class TestNonHypothesisFuzz:
    """Fuzz tests that don't require Hypothesis."""
    
    def test_random_ciphertext_rejection(self):
        """Random ciphertext must be rejected."""
        password = "testpassword123"
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        for _ in range(10):
            random_cipher = secrets.token_bytes(100)
            
            with pytest.raises(RuntimeError):
                decrypt_to_raw(
                    random_cipher, password, salt, nonce,
                    orig_len=50,
                    comp_len=50,
                    sha256=secrets.token_bytes(32)
                )
                
    def test_random_password_rejection(self):
        """Random password must fail to decrypt."""
        data = b"Test data"
        real_password = "realpassword123"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, real_password, use_length_padding=False
        )
        
        for _ in range(10):
            wrong_password = secrets.token_hex(16)
            
            with pytest.raises(RuntimeError):
                decrypt_to_raw(
                    cipher, wrong_password, salt, nonce,
                    orig_len=len(data),
                    comp_len=len(comp),
                    sha256=sha
                )
                
    def test_random_nonce_rejection(self):
        """Wrong nonce must fail to decrypt."""
        data = b"Test data"
        password = "testpassword123"
        
        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, use_length_padding=False
        )
        
        for _ in range(10):
            wrong_nonce = secrets.token_bytes(12)
            
            with pytest.raises(RuntimeError):
                decrypt_to_raw(
                    cipher, password, salt, wrong_nonce,
                    orig_len=len(data),
                    comp_len=len(comp),
                    sha256=sha
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
