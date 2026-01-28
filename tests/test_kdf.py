#!/usr/bin/env python3
"""
🔑 TIER 1: Key Derivation Function Tests

Security-Critical Tests for Argon2id key derivation.
These tests verify:

1. Same password + salt → same key (determinism)
2. Different password → different key
3. Different salt → different key
4. Key length is always 32 bytes
5. Argon2id parameters are correctly applied
6. Keyfile integration works correctly

SECURITY REQUIREMENT: Key derivation must be deterministic
for correct encryption/decryption, but unpredictable without
the exact inputs.
"""

import pytest
import secrets
import os
from unittest.mock import patch

from meow_decoder.crypto import (
    derive_key,
    MIN_PASSWORD_LENGTH,
    ARGON2_MEMORY,
    ARGON2_ITERATIONS,
    ARGON2_PARALLELISM,
)
from meow_decoder.crypto_backend import get_default_backend


class TestKDFDeterminism:
    """Test that key derivation is deterministic."""
    
    def test_same_inputs_same_key(self):
        """Same password + salt must always produce same key."""
        password = "DeterministicTest1!"
        salt = secrets.token_bytes(16)
        
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        
        assert key1 == key2, "KDF is not deterministic!"
        
    def test_repeated_derivations_identical(self):
        """Multiple derivations must be identical."""
        password = "RepeatedTest123!"
        salt = secrets.token_bytes(16)
        
        keys = [derive_key(password, salt) for _ in range(5)]
        
        assert all(k == keys[0] for k in keys), "Keys differ across derivations!"
        
    def test_key_is_32_bytes(self):
        """Derived key must always be 32 bytes."""
        password = "LengthTest12345!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert len(key) == 32, f"Key length must be 32, got {len(key)}"


class TestPasswordVariation:
    """Test that password variations produce different keys."""
    
    def test_different_passwords_different_keys(self):
        """Different passwords must produce different keys."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_key("Password1234567!", salt)
        key2 = derive_key("DifferentPass12!", salt)
        
        assert key1 != key2, "Different passwords produced same key!"
        
    def test_single_char_difference(self):
        """Single character difference must produce different key."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_key("Password123456!", salt)
        key2 = derive_key("Password123456?", salt)  # Last char different
        
        assert key1 != key2, "Single char difference produced same key!"
        
    def test_case_sensitivity(self):
        """Password case must affect derived key."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_key("PasswordTest12!", salt)
        key2 = derive_key("passwordtest12!", salt)  # Lowercase
        
        assert key1 != key2, "Case insensitive derivation is wrong!"
        
    def test_whitespace_matters(self):
        """Whitespace in password must affect key."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_key("Password Test!", salt)  # With space
        key2 = derive_key("PasswordTest!!", salt)  # Without space
        
        assert key1 != key2, "Whitespace ignored in password!"
        
    def test_unicode_passwords(self):
        """Unicode passwords must work correctly."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_key("Pässwörd123!", salt)
        key2 = derive_key("Password123!!", salt)
        
        assert key1 != key2, "Unicode password not handled correctly!"
        assert len(key1) == 32, "Unicode password produced wrong key length!"


class TestSaltVariation:
    """Test that salt variations produce different keys."""
    
    def test_different_salts_different_keys(self):
        """Different salts must produce different keys."""
        password = "SamePa$$word12!"
        
        key1 = derive_key(password, b"salt1" + b"\x00" * 11)
        key2 = derive_key(password, b"salt2" + b"\x00" * 11)
        
        assert key1 != key2, "Different salts produced same key!"
        
    def test_single_bit_salt_difference(self):
        """Single bit salt difference must produce different key."""
        password = "BitFlipTest123!"
        salt1 = b"\x00" * 16
        salt2 = b"\x01" + b"\x00" * 15  # First byte different
        
        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)
        
        assert key1 != key2, "Single bit salt change produced same key!"
        
    def test_salt_length_validation(self):
        """Salt must be exactly 16 bytes."""
        password = "SaltLenTest123!"
        
        # Too short
        with pytest.raises(ValueError):
            derive_key(password, b"short")
            
        # Too long
        with pytest.raises(ValueError):
            derive_key(password, b"x" * 32)
            
        # Empty
        with pytest.raises(ValueError):
            derive_key(password, b"")


class TestKeyfileIntegration:
    """Test keyfile-based key derivation."""
    
    def test_keyfile_changes_key(self):
        """Adding keyfile must change derived key."""
        password = "KeyfileTest123!"
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(256)
        
        key_without = derive_key(password, salt)
        key_with = derive_key(password, salt, keyfile=keyfile)
        
        assert key_without != key_with, "Keyfile did not affect key!"
        
    def test_different_keyfiles_different_keys(self):
        """Different keyfiles must produce different keys."""
        password = "DiffKeyfile123!"
        salt = secrets.token_bytes(16)
        
        keyfile1 = secrets.token_bytes(256)
        keyfile2 = secrets.token_bytes(256)
        
        key1 = derive_key(password, salt, keyfile=keyfile1)
        key2 = derive_key(password, salt, keyfile=keyfile2)
        
        assert key1 != key2, "Different keyfiles produced same key!"
        
    def test_keyfile_determinism(self):
        """Same keyfile must produce same key."""
        password = "KeyfileDet1234!"
        salt = secrets.token_bytes(16)
        keyfile = secrets.token_bytes(256)
        
        key1 = derive_key(password, salt, keyfile=keyfile)
        key2 = derive_key(password, salt, keyfile=keyfile)
        
        assert key1 == key2, "Keyfile derivation not deterministic!"
        
    def test_keyfile_order_matters(self):
        """Keyfile bytes order must matter."""
        password = "OrderTest12345!"
        salt = secrets.token_bytes(16)
        keyfile = b"ABCD" * 64  # 256 bytes
        keyfile_reversed = b"DCBA" * 64
        
        key1 = derive_key(password, salt, keyfile=keyfile)
        key2 = derive_key(password, salt, keyfile=keyfile_reversed)
        
        assert key1 != key2, "Keyfile byte order ignored!"


class TestPasswordRequirements:
    """Test password validation rules."""
    
    def test_empty_password_rejected(self):
        """Empty password must be rejected."""
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError):
            derive_key("", salt)
            
    def test_minimum_length_enforced(self):
        """Password must meet minimum length."""
        salt = secrets.token_bytes(16)
        
        # One char below minimum
        short = "x" * (MIN_PASSWORD_LENGTH - 1)
        with pytest.raises(ValueError):
            derive_key(short, salt)
            
    def test_minimum_length_accepted(self):
        """Minimum length password must work."""
        salt = secrets.token_bytes(16)
        password = "x" * MIN_PASSWORD_LENGTH
        
        key = derive_key(password, salt)
        assert len(key) == 32
        
    def test_long_password_accepted(self):
        """Very long passwords must work."""
        salt = secrets.token_bytes(16)
        password = "x" * 1000  # 1000 character password
        
        key = derive_key(password, salt)
        assert len(key) == 32


class TestArgon2Parameters:
    """Test that Argon2id parameters are correctly configured."""
    
    def test_memory_parameter_set(self):
        """Memory cost must be set to expected value."""
        # For test mode, memory is reduced
        assert ARGON2_MEMORY >= 32768, f"Memory too low: {ARGON2_MEMORY}"
        
    def test_iterations_parameter_set(self):
        """Iteration count must be set."""
        assert ARGON2_ITERATIONS >= 1, f"Iterations too low: {ARGON2_ITERATIONS}"
        
    def test_parallelism_parameter_set(self):
        """Parallelism must be set."""
        assert ARGON2_PARALLELISM >= 1, f"Parallelism too low: {ARGON2_PARALLELISM}"


class TestKeyRandomness:
    """Test that derived keys have good randomness properties."""
    
    def test_key_not_all_zeros(self):
        """Derived key must not be all zeros."""
        password = "NotZeroTest123!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert key != b"\x00" * 32, "Key is all zeros!"
        
    def test_key_not_all_ones(self):
        """Derived key must not be all ones."""
        password = "NotOnesTest123!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        assert key != b"\xff" * 32, "Key is all ones!"
        
    def test_key_not_password_bytes(self):
        """Derived key must not be raw password bytes."""
        password = "NotPasswordByte!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        # Key should not contain password
        assert password.encode() not in key
        
    def test_key_entropy(self):
        """Derived key should have high entropy (rough check)."""
        password = "EntropyTest123!"
        salt = secrets.token_bytes(16)
        
        key = derive_key(password, salt)
        
        # Count unique bytes - should be reasonably high for 32 random bytes
        unique_bytes = len(set(key))
        # With 32 bytes, expect at least 10 unique values typically
        assert unique_bytes >= 8, f"Low entropy: only {unique_bytes} unique bytes"


class TestBackendConsistency:
    """Test that backend produces consistent results."""
    
    def test_backend_available(self):
        """Crypto backend must be available."""
        backend = get_default_backend()
        assert backend is not None, "No crypto backend available!"
        
    def test_backend_argon2id_available(self):
        """Backend must support Argon2id."""
        backend = get_default_backend()
        
        # Derive a key using the backend directly
        key = backend.derive_key_argon2id(
            b"testpassword123!",
            b"x" * 16,
            output_len=32,
            iterations=1,
            memory_kib=32768,
            parallelism=1
        )
        
        assert len(key) == 32


class TestTestModeParameters:
    """Test that test mode uses appropriate parameters."""
    
    def test_test_mode_fast_enough(self):
        """Test mode KDF should complete quickly."""
        import time
        
        password = "SpeedTest12345!"
        salt = secrets.token_bytes(16)
        
        start = time.time()
        derive_key(password, salt)
        elapsed = time.time() - start
        
        # In test mode, should be under 2 seconds
        # In production mode, may take longer (that's expected)
        if os.environ.get("MEOW_TEST_MODE"):
            assert elapsed < 2.0, f"Test mode KDF too slow: {elapsed}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
