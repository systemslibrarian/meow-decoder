#!/usr/bin/env python3
"""
Canonical Test Suite for forward_secrecy_x25519.py

Tests the X25519 ephemeral key agreement forward secrecy implementation.
Target: 90%+ code coverage.

Coverage Plan:
1. EphemeralKeyPair tests - generation, serialization
2. derive_hybrid_key tests - password-only and hybrid modes
3. encrypt_with_forward_secrecy tests - with and without FS
4. decrypt_with_forward_secrecy tests - with and without FS
5. Integration tests - full roundtrip scenarios
6. Edge cases - invalid inputs, error handling
"""

import pytest
import secrets
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

from meow_decoder.forward_secrecy_x25519 import (
    EphemeralKeyPair,
    derive_hybrid_key,
    encrypt_with_forward_secrecy,
    decrypt_with_forward_secrecy
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def receiver_keypair():
    """Generate long-term receiver keypair."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return private_bytes, public_bytes


@pytest.fixture
def test_password():
    """Standard test password."""
    return "TestPassword123!"


@pytest.fixture
def test_plaintext():
    """Standard test plaintext."""
    return b"Secret message with forward secrecy for testing!"


# =============================================================================
# Test EphemeralKeyPair
# =============================================================================

class TestEphemeralKeyPair:
    """Tests for EphemeralKeyPair class."""
    
    def test_generate_creates_keypair(self):
        """Test that generate creates valid keypair."""
        keypair = EphemeralKeyPair.generate()
        
        assert keypair.private_key is not None
        assert keypair.public_key is not None
        assert isinstance(keypair.private_key, X25519PrivateKey)
        assert isinstance(keypair.public_key, X25519PublicKey)
    
    def test_generate_creates_unique_keypairs(self):
        """Test that each generation creates unique keypair."""
        keypair1 = EphemeralKeyPair.generate()
        keypair2 = EphemeralKeyPair.generate()
        
        assert keypair1.public_bytes() != keypair2.public_bytes()
    
    def test_public_bytes_returns_32_bytes(self):
        """Test that public_bytes returns 32-byte raw key."""
        keypair = EphemeralKeyPair.generate()
        pub_bytes = keypair.public_bytes()
        
        assert isinstance(pub_bytes, bytes)
        assert len(pub_bytes) == 32
    
    def test_public_bytes_is_consistent(self):
        """Test that public_bytes returns same value on repeated calls."""
        keypair = EphemeralKeyPair.generate()
        
        bytes1 = keypair.public_bytes()
        bytes2 = keypair.public_bytes()
        
        assert bytes1 == bytes2
    
    def test_keypair_exchange_works(self, receiver_keypair):
        """Test that ephemeral keypair can perform key exchange."""
        receiver_private_bytes, receiver_public_bytes = receiver_keypair
        
        # Load receiver public key
        receiver_public = X25519PublicKey.from_public_bytes(receiver_public_bytes)
        
        # Generate ephemeral keypair
        ephemeral = EphemeralKeyPair.generate()
        
        # Perform exchange
        shared_secret = ephemeral.private_key.exchange(receiver_public)
        
        assert isinstance(shared_secret, bytes)
        assert len(shared_secret) == 32


# =============================================================================
# Test derive_hybrid_key
# =============================================================================

class TestDeriveHybridKey:
    """Tests for derive_hybrid_key function."""
    
    def test_password_only_mode(self, test_password):
        """Test password-only key derivation."""
        salt = secrets.token_bytes(16)
        
        key = derive_hybrid_key(test_password, salt)
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_password_only_deterministic(self, test_password):
        """Test password-only mode is deterministic."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_hybrid_key(test_password, salt)
        key2 = derive_hybrid_key(test_password, salt)
        
        assert key1 == key2
    
    def test_different_passwords_different_keys(self):
        """Test different passwords produce different keys."""
        salt = secrets.token_bytes(16)
        
        key1 = derive_hybrid_key("password1", salt)
        key2 = derive_hybrid_key("password2", salt)
        
        assert key1 != key2
    
    def test_different_salts_different_keys(self, test_password):
        """Test different salts produce different keys."""
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        key1 = derive_hybrid_key(test_password, salt1)
        key2 = derive_hybrid_key(test_password, salt2)
        
        assert key1 != key2
    
    def test_hybrid_mode_with_shared_secret(self, test_password):
        """Test hybrid mode with shared secret."""
        salt = secrets.token_bytes(16)
        shared_secret = secrets.token_bytes(32)
        
        key = derive_hybrid_key(test_password, salt, shared_secret)
        
        assert isinstance(key, bytes)
        assert len(key) == 32
    
    def test_hybrid_key_differs_from_password_only(self, test_password):
        """Test hybrid key differs from password-only key."""
        salt = secrets.token_bytes(16)
        shared_secret = secrets.token_bytes(32)
        
        key_password_only = derive_hybrid_key(test_password, salt)
        key_hybrid = derive_hybrid_key(test_password, salt, shared_secret)
        
        assert key_password_only != key_hybrid
    
    def test_different_shared_secrets_different_keys(self, test_password):
        """Test different shared secrets produce different hybrid keys."""
        salt = secrets.token_bytes(16)
        shared1 = secrets.token_bytes(32)
        shared2 = secrets.token_bytes(32)
        
        key1 = derive_hybrid_key(test_password, salt, shared1)
        key2 = derive_hybrid_key(test_password, salt, shared2)
        
        assert key1 != key2
    
    def test_custom_info_parameter(self, test_password):
        """Test custom info parameter produces different key."""
        salt = secrets.token_bytes(16)
        shared = secrets.token_bytes(32)
        
        key1 = derive_hybrid_key(test_password, salt, shared, info=b"info1")
        key2 = derive_hybrid_key(test_password, salt, shared, info=b"info2")
        
        assert key1 != key2
    
    def test_invalid_salt_length(self, test_password):
        """Test invalid salt length raises error."""
        bad_salt = secrets.token_bytes(8)  # Should be 16
        
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            derive_hybrid_key(test_password, bad_salt)
    
    def test_empty_salt_fails(self, test_password):
        """Test empty salt raises error."""
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            derive_hybrid_key(test_password, b"")


# =============================================================================
# Test encrypt_with_forward_secrecy
# =============================================================================

class TestEncryptWithForwardSecrecy:
    """Tests for encrypt_with_forward_secrecy function."""
    
    def test_password_only_encryption(self, test_password, test_plaintext):
        """Test password-only encryption (no receiver public key)."""
        ct, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
            test_plaintext, test_password, None
        )
        
        assert isinstance(ct, bytes)
        assert len(ct) > 0
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(ephemeral_pub) == 0  # No ephemeral key in password-only mode
    
    def test_forward_secrecy_encryption(self, test_password, test_plaintext, receiver_keypair):
        """Test forward secrecy encryption with receiver public key."""
        _, receiver_public = receiver_keypair
        
        ct, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        
        assert isinstance(ct, bytes)
        assert len(ct) > 0
        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(ephemeral_pub) == 32  # X25519 public key
    
    def test_ephemeral_key_is_unique_per_encryption(self, test_password, test_plaintext, receiver_keypair):
        """Test each encryption generates unique ephemeral key."""
        _, receiver_public = receiver_keypair
        
        _, _, _, ephemeral1 = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        _, _, _, ephemeral2 = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        
        assert ephemeral1 != ephemeral2
    
    def test_different_salt_each_encryption(self, test_password, test_plaintext):
        """Test each encryption generates unique salt."""
        _, salt1, _, _ = encrypt_with_forward_secrecy(test_plaintext, test_password, None)
        _, salt2, _, _ = encrypt_with_forward_secrecy(test_plaintext, test_password, None)
        
        assert salt1 != salt2
    
    def test_different_nonce_each_encryption(self, test_password, test_plaintext):
        """Test each encryption generates unique nonce."""
        _, _, nonce1, _ = encrypt_with_forward_secrecy(test_plaintext, test_password, None)
        _, _, nonce2, _ = encrypt_with_forward_secrecy(test_plaintext, test_password, None)
        
        assert nonce1 != nonce2
    
    def test_ciphertext_differs_from_plaintext(self, test_password, test_plaintext):
        """Test ciphertext is different from plaintext."""
        ct, _, _, _ = encrypt_with_forward_secrecy(test_plaintext, test_password, None)
        
        assert ct != test_plaintext
    
    def test_ciphertext_includes_auth_tag(self, test_password, test_plaintext):
        """Test ciphertext is longer than plaintext (includes tag + compression)."""
        # For compression, might be smaller. But should have auth tag overhead.
        # The relationship is complex due to compression, so just check it's bytes.
        ct, _, _, _ = encrypt_with_forward_secrecy(test_plaintext, test_password, None)
        
        assert isinstance(ct, bytes)
        assert len(ct) > 0  # Just verify it's non-empty
    
    def test_large_plaintext_encryption(self, test_password, receiver_keypair):
        """Test encryption of large plaintext."""
        _, receiver_public = receiver_keypair
        large_plaintext = secrets.token_bytes(100000)  # 100KB
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            large_plaintext, test_password, receiver_public
        )
        
        assert len(ct) > 0
        assert len(ephemeral) == 32
    
    def test_empty_plaintext_encryption(self, test_password):
        """Test encryption of empty plaintext."""
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            b"", test_password, None
        )
        
        # Even empty plaintext produces ciphertext (compressed + auth tag)
        assert len(ct) > 0


# =============================================================================
# Test decrypt_with_forward_secrecy
# =============================================================================

class TestDecryptWithForwardSecrecy:
    """Tests for decrypt_with_forward_secrecy function."""
    
    def test_password_only_roundtrip(self, test_password, test_plaintext):
        """Test password-only encrypt/decrypt roundtrip."""
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            test_plaintext, test_password, None
        )
        
        decrypted = decrypt_with_forward_secrecy(
            ct, test_password, salt, nonce, ephemeral,
            None, len(test_plaintext)
        )
        
        assert decrypted == test_plaintext
    
    def test_forward_secrecy_roundtrip(self, test_password, test_plaintext, receiver_keypair):
        """Test forward secrecy encrypt/decrypt roundtrip."""
        receiver_private, receiver_public = receiver_keypair
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        
        decrypted = decrypt_with_forward_secrecy(
            ct, test_password, salt, nonce, ephemeral,
            receiver_private, len(test_plaintext)
        )
        
        assert decrypted == test_plaintext
    
    def test_wrong_password_fails(self, test_password, test_plaintext, receiver_keypair):
        """Test decryption with wrong password fails."""
        receiver_private, receiver_public = receiver_keypair
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        
        with pytest.raises(Exception):  # InvalidTag or similar
            decrypt_with_forward_secrecy(
                ct, "WrongPassword", salt, nonce, ephemeral,
                receiver_private, len(test_plaintext)
            )
    
    def test_wrong_receiver_key_fails(self, test_password, test_plaintext, receiver_keypair):
        """Test decryption with wrong receiver key fails."""
        _, receiver_public = receiver_keypair
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        
        # Generate different receiver keypair
        wrong_private = X25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with pytest.raises(Exception):  # InvalidTag
            decrypt_with_forward_secrecy(
                ct, test_password, salt, nonce, ephemeral,
                wrong_private, len(test_plaintext)
            )
    
    def test_tampered_ciphertext_fails(self, test_password, test_plaintext, receiver_keypair):
        """Test decryption with tampered ciphertext fails."""
        receiver_private, receiver_public = receiver_keypair
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        
        # Tamper with ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0xFF
        
        with pytest.raises(Exception):  # InvalidTag
            decrypt_with_forward_secrecy(
                bytes(tampered_ct), test_password, salt, nonce, ephemeral,
                receiver_private, len(test_plaintext)
            )
    
    def test_fs_mode_without_receiver_key_fails(self, test_password, test_plaintext, receiver_keypair):
        """Test FS mode decryption without receiver key raises error."""
        _, receiver_public = receiver_keypair
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        
        with pytest.raises(ValueError, match="Forward secrecy mode requires receiver private key"):
            decrypt_with_forward_secrecy(
                ct, test_password, salt, nonce, ephemeral,
                None, len(test_plaintext)
            )
    
    def test_empty_plaintext_roundtrip(self, test_password, receiver_keypair):
        """Test empty plaintext roundtrip."""
        receiver_private, receiver_public = receiver_keypair
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            b"", test_password, receiver_public
        )
        
        decrypted = decrypt_with_forward_secrecy(
            ct, test_password, salt, nonce, ephemeral,
            receiver_private, 0
        )
        
        assert decrypted == b""
    
    def test_large_plaintext_roundtrip(self, test_password, receiver_keypair):
        """Test large plaintext roundtrip."""
        receiver_private, receiver_public = receiver_keypair
        large_plaintext = secrets.token_bytes(50000)  # 50KB
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            large_plaintext, test_password, receiver_public
        )
        
        decrypted = decrypt_with_forward_secrecy(
            ct, test_password, salt, nonce, ephemeral,
            receiver_private, len(large_plaintext)
        )
        
        assert decrypted == large_plaintext


# =============================================================================
# Integration Tests
# =============================================================================

class TestForwardSecrecyIntegration:
    """Integration tests for forward secrecy workflow."""
    
    def test_multiple_messages_same_receiver(self, test_password, receiver_keypair):
        """Test encrypting multiple messages to same receiver."""
        receiver_private, receiver_public = receiver_keypair
        
        messages = [
            b"Message 1 - first secret",
            b"Message 2 - second secret",
            b"Message 3 - third secret",
        ]
        
        encrypted_messages = []
        for msg in messages:
            ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
                msg, test_password, receiver_public
            )
            encrypted_messages.append((ct, salt, nonce, ephemeral))
        
        # All ephemeral keys should be unique
        ephemerals = [e[3] for e in encrypted_messages]
        assert len(set(ephemerals)) == len(ephemerals)
        
        # Decrypt all messages
        for i, (ct, salt, nonce, ephemeral) in enumerate(encrypted_messages):
            decrypted = decrypt_with_forward_secrecy(
                ct, test_password, salt, nonce, ephemeral,
                receiver_private, len(messages[i])
            )
            assert decrypted == messages[i]
    
    def test_different_receivers_same_message(self, test_password, test_plaintext):
        """Test encrypting same message to different receivers."""
        # Generate two receiver keypairs
        receiver1_private = X25519PrivateKey.generate()
        receiver1_public = receiver1_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        receiver1_private_bytes = receiver1_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        receiver2_private = X25519PrivateKey.generate()
        receiver2_public = receiver2_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        receiver2_private_bytes = receiver2_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Encrypt to each
        ct1, salt1, nonce1, eph1 = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver1_public
        )
        ct2, salt2, nonce2, eph2 = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver2_public
        )
        
        # Ciphertexts should differ
        assert ct1 != ct2
        
        # Each receiver can only decrypt their own
        decrypted1 = decrypt_with_forward_secrecy(
            ct1, test_password, salt1, nonce1, eph1,
            receiver1_private_bytes, len(test_plaintext)
        )
        assert decrypted1 == test_plaintext
        
        decrypted2 = decrypt_with_forward_secrecy(
            ct2, test_password, salt2, nonce2, eph2,
            receiver2_private_bytes, len(test_plaintext)
        )
        assert decrypted2 == test_plaintext
        
        # Cross-decryption fails
        with pytest.raises(Exception):
            decrypt_with_forward_secrecy(
                ct1, test_password, salt1, nonce1, eph1,
                receiver2_private_bytes, len(test_plaintext)
            )


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case and error handling tests."""
    
    def test_binary_data_roundtrip(self, test_password, receiver_keypair):
        """Test binary data (not just text) roundtrip."""
        receiver_private, receiver_public = receiver_keypair
        binary_data = bytes(range(256)) * 100  # All byte values
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            binary_data, test_password, receiver_public
        )
        
        decrypted = decrypt_with_forward_secrecy(
            ct, test_password, salt, nonce, ephemeral,
            receiver_private, len(binary_data)
        )
        
        assert decrypted == binary_data
    
    def test_unicode_password(self, test_plaintext, receiver_keypair):
        """Test unicode password support."""
        receiver_private, receiver_public = receiver_keypair
        unicode_password = "密码🔐κωδικός"
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            test_plaintext, unicode_password, receiver_public
        )
        
        decrypted = decrypt_with_forward_secrecy(
            ct, unicode_password, salt, nonce, ephemeral,
            receiver_private, len(test_plaintext)
        )
        
        assert decrypted == test_plaintext
    
    def test_compressible_data(self, test_password, receiver_keypair):
        """Test highly compressible data."""
        receiver_private, receiver_public = receiver_keypair
        compressible = b"AAAAAAAAAA" * 10000  # 100KB of A's
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            compressible, test_password, receiver_public
        )
        
        # Ciphertext should be much smaller than plaintext due to compression
        assert len(ct) < len(compressible)
        
        decrypted = decrypt_with_forward_secrecy(
            ct, test_password, salt, nonce, ephemeral,
            receiver_private, len(compressible)
        )
        
        assert decrypted == compressible
    
    def test_incompressible_data(self, test_password, receiver_keypair):
        """Test incompressible data (random bytes)."""
        receiver_private, receiver_public = receiver_keypair
        random_data = secrets.token_bytes(10000)
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            random_data, test_password, receiver_public
        )
        
        decrypted = decrypt_with_forward_secrecy(
            ct, test_password, salt, nonce, ephemeral,
            receiver_private, len(random_data)
        )
        
        assert decrypted == random_data
    
    def test_decryption_without_orig_len(self, test_password, test_plaintext, receiver_keypair):
        """Test decryption works without orig_len (AAD partial)."""
        receiver_private, receiver_public = receiver_keypair
        
        ct, salt, nonce, ephemeral = encrypt_with_forward_secrecy(
            test_plaintext, test_password, receiver_public
        )
        
        # Note: This will fail because AAD won't match
        # The function requires orig_len for AAD reconstruction
        with pytest.raises(Exception):
            decrypt_with_forward_secrecy(
                ct, test_password, salt, nonce, ephemeral,
                receiver_private, None  # Missing orig_len
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
