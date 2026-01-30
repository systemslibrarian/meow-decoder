#!/usr/bin/env python3
"""
🐱 Comprehensive Coverage Tests for x25519_forward_secrecy.py - Target: 90%+
Tests all X25519 forward secrecy paths including key generation, derivation, and serialization.
"""

import pytest
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestGenerateEphemeralKeypair:
    """Test generate_ephemeral_keypair function."""
    
    def test_basic_generation(self):
        """Test basic keypair generation."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys = generate_ephemeral_keypair()
        
        assert keys.ephemeral_private is not None
        assert keys.ephemeral_public is not None
        assert len(keys.ephemeral_private) == 32
        assert len(keys.ephemeral_public) == 32
    
    def test_unique_generation(self):
        """Test each generation is unique."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys1 = generate_ephemeral_keypair()
        keys2 = generate_ephemeral_keypair()
        
        assert keys1.ephemeral_private != keys2.ephemeral_private
        assert keys1.ephemeral_public != keys2.ephemeral_public
    
    def test_private_public_different(self):
        """Test private and public are different."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys = generate_ephemeral_keypair()
        
        assert keys.ephemeral_private != keys.ephemeral_public


class TestDeriveSharedSecret:
    """Test derive_shared_secret function."""
    
    def test_basic_derivation(self):
        """Test basic shared secret derivation."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair, derive_shared_secret
        
        sender_keys = generate_ephemeral_keypair()
        receiver_keys = generate_ephemeral_keypair()
        
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        
        # Sender derives with receiver's public key
        sender_secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_keys.ephemeral_public,
            password,
            salt
        )
        
        # Receiver derives with sender's public key
        receiver_secret = derive_shared_secret(
            receiver_keys.ephemeral_private,
            sender_keys.ephemeral_public,
            password,
            salt
        )
        
        assert sender_secret == receiver_secret
        assert len(sender_secret) == 32
    
    def test_different_passwords_different_secrets(self):
        """Test different passwords give different secrets."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair, derive_shared_secret
        
        keys1 = generate_ephemeral_keypair()
        keys2 = generate_ephemeral_keypair()
        salt = secrets.token_bytes(16)
        
        secret1 = derive_shared_secret(
            keys1.ephemeral_private,
            keys2.ephemeral_public,
            "password1",
            salt
        )
        
        secret2 = derive_shared_secret(
            keys1.ephemeral_private,
            keys2.ephemeral_public,
            "password2",
            salt
        )
        
        assert secret1 != secret2
    
    def test_different_salts_different_secrets(self):
        """Test different salts give different secrets."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair, derive_shared_secret
        
        keys1 = generate_ephemeral_keypair()
        keys2 = generate_ephemeral_keypair()
        password = "same_password"
        
        secret1 = derive_shared_secret(
            keys1.ephemeral_private,
            keys2.ephemeral_public,
            password,
            secrets.token_bytes(16)
        )
        
        secret2 = derive_shared_secret(
            keys1.ephemeral_private,
            keys2.ephemeral_public,
            password,
            secrets.token_bytes(16)
        )
        
        assert secret1 != secret2
    
    def test_invalid_private_key_length(self):
        """Test error on invalid private key length."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair, derive_shared_secret
        
        keys = generate_ephemeral_keypair()
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError, match="32 bytes"):
            derive_shared_secret(
                b"short",  # Invalid length
                keys.ephemeral_public,
                "password",
                salt
            )
    
    def test_invalid_public_key_length(self):
        """Test error on invalid public key length."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair, derive_shared_secret
        
        keys = generate_ephemeral_keypair()
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError, match="32 bytes"):
            derive_shared_secret(
                keys.ephemeral_private,
                b"short",  # Invalid length
                "password",
                salt
            )
    
    def test_invalid_salt_length(self):
        """Test error on invalid salt length."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair, derive_shared_secret
        
        keys1 = generate_ephemeral_keypair()
        keys2 = generate_ephemeral_keypair()
        
        with pytest.raises(ValueError, match="16 bytes"):
            derive_shared_secret(
                keys1.ephemeral_private,
                keys2.ephemeral_public,
                "password",
                b"short_salt"  # Invalid length
            )


class TestSerializePublicKey:
    """Test serialize_public_key function."""
    
    def test_basic_serialization(self):
        """Test basic public key serialization."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair, serialize_public_key
        
        keys = generate_ephemeral_keypair()
        serialized = serialize_public_key(keys.ephemeral_public)
        
        assert len(serialized) == 32
        assert serialized == keys.ephemeral_public
    
    def test_identity(self):
        """Test serialization is identity for bytes."""
        from meow_decoder.x25519_forward_secrecy import serialize_public_key
        
        data = secrets.token_bytes(32)
        serialized = serialize_public_key(data)
        
        assert serialized == data


class TestDeserializePublicKey:
    """Test deserialize_public_key function."""
    
    def test_basic_deserialization(self):
        """Test basic public key deserialization."""
        from meow_decoder.x25519_forward_secrecy import deserialize_public_key
        
        key_bytes = secrets.token_bytes(32)
        deserialized = deserialize_public_key(key_bytes)
        
        assert deserialized == key_bytes
    
    def test_invalid_length(self):
        """Test error on invalid length."""
        from meow_decoder.x25519_forward_secrecy import deserialize_public_key
        
        with pytest.raises(ValueError, match="32 bytes"):
            deserialize_public_key(b"short")
    
    def test_roundtrip(self):
        """Test serialization roundtrip."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            serialize_public_key,
            deserialize_public_key
        )
        
        keys = generate_ephemeral_keypair()
        serialized = serialize_public_key(keys.ephemeral_public)
        deserialized = deserialize_public_key(serialized)
        
        assert deserialized == keys.ephemeral_public


class TestGenerateReceiverKeypair:
    """Test generate_receiver_keypair function."""
    
    def test_basic_generation(self):
        """Test basic receiver keypair generation."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        private_key, public_key = generate_receiver_keypair()
        
        assert len(private_key) == 32
        assert len(public_key) == 32
    
    def test_unique_generation(self):
        """Test each generation is unique."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        priv1, pub1 = generate_receiver_keypair()
        priv2, pub2 = generate_receiver_keypair()
        
        assert priv1 != priv2
        assert pub1 != pub2


class TestSaveAndLoadReceiverKeypair:
    """Test save_receiver_keypair and load_receiver_keypair functions."""
    
    def test_save_and_load_with_password(self):
        """Test saving and loading keypair with password."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            save_receiver_keypair,
            load_receiver_keypair
        )
        
        private_key, public_key = generate_receiver_keypair()
        password = "key_password_123"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_file = Path(tmpdir) / "private.pem"
            pub_file = Path(tmpdir) / "public.key"
            
            save_receiver_keypair(
                private_key,
                public_key,
                str(priv_file),
                str(pub_file),
                password
            )
            
            assert priv_file.exists()
            assert pub_file.exists()
            
            # Load back
            loaded_priv, loaded_pub = load_receiver_keypair(
                str(priv_file),
                str(pub_file),
                password
            )
            
            assert loaded_priv == private_key
            assert loaded_pub == public_key
    
    def test_save_without_password(self):
        """Test saving without password."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            save_receiver_keypair,
            load_receiver_keypair
        )
        
        private_key, public_key = generate_receiver_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_file = Path(tmpdir) / "private.pem"
            pub_file = Path(tmpdir) / "public.key"
            
            save_receiver_keypair(
                private_key,
                public_key,
                str(priv_file),
                str(pub_file),
                None
            )
            
            loaded_priv, loaded_pub = load_receiver_keypair(
                str(priv_file),
                str(pub_file),
                None
            )
            
            assert loaded_priv == private_key
            assert loaded_pub == public_key
    
    def test_public_key_raw_bytes(self):
        """Test public key is saved as raw bytes."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            save_receiver_keypair
        )
        
        private_key, public_key = generate_receiver_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            priv_file = Path(tmpdir) / "private.pem"
            pub_file = Path(tmpdir) / "public.key"
            
            save_receiver_keypair(
                private_key,
                public_key,
                str(priv_file),
                str(pub_file),
                None
            )
            
            # Public key should be raw 32 bytes
            saved_pub = pub_file.read_bytes()
            assert saved_pub == public_key
            assert len(saved_pub) == 32


class TestX25519ForwardSecrecyIntegration:
    """Integration tests for X25519 forward secrecy."""
    
    def test_full_encryption_flow(self):
        """Test full forward secrecy encryption flow."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            generate_receiver_keypair,
            derive_shared_secret
        )
        
        # Receiver generates long-term keypair
        receiver_priv, receiver_pub = generate_receiver_keypair()
        
        # Sender generates ephemeral keypair
        sender_keys = generate_ephemeral_keypair()
        
        password = "shared_password"
        salt = secrets.token_bytes(16)
        
        # Sender derives shared secret
        sender_secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_pub,
            password,
            salt
        )
        
        # Receiver derives same shared secret
        receiver_secret = derive_shared_secret(
            receiver_priv,
            sender_keys.ephemeral_public,
            password,
            salt
        )
        
        assert sender_secret == receiver_secret
    
    def test_forward_secrecy_property(self):
        """Test that different ephemeral keys give different secrets."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            generate_receiver_keypair,
            derive_shared_secret
        )
        
        # Same receiver
        receiver_priv, receiver_pub = generate_receiver_keypair()
        
        password = "same_password"
        salt = secrets.token_bytes(16)
        
        # First message with ephemeral key 1
        sender1 = generate_ephemeral_keypair()
        secret1 = derive_shared_secret(
            sender1.ephemeral_private,
            receiver_pub,
            password,
            salt
        )
        
        # Second message with ephemeral key 2
        sender2 = generate_ephemeral_keypair()
        secret2 = derive_shared_secret(
            sender2.ephemeral_private,
            receiver_pub,
            password,
            salt
        )
        
        # Different ephemeral keys should give different secrets
        assert secret1 != secret2
    
    def test_with_crypto_module(self):
        """Test integration with main crypto module."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            generate_receiver_keypair
        )
        from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
        
        # Generate receiver keypair
        receiver_priv, receiver_pub = generate_receiver_keypair()
        
        password = "test_password_123"
        test_data = b"Secret message for forward secrecy test!" * 50
        
        # Encrypt with forward secrecy
        comp, sha, salt, nonce, cipher, ephemeral_pub, _ = encrypt_file_bytes(
            test_data,
            password,
            receiver_public_key=receiver_pub
        )
        
        assert ephemeral_pub is not None  # Should have ephemeral key
        
        # Decrypt with receiver's private key
        decrypted = decrypt_to_raw(
            cipher,
            password,
            salt,
            nonce,
            orig_len=len(test_data),
            comp_len=len(comp),
            sha256=sha,
            ephemeral_public_key=ephemeral_pub,
            receiver_private_key=receiver_priv
        )
        
        assert decrypted == test_data


class TestGenerateReceiverKeysCLI:
    """Test generate_receiver_keys_cli function."""
    
    def test_cli_key_generation(self):
        """Test CLI key generation."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keys_cli
        import io
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate password input
            import sys
            old_stdin = sys.stdin
            sys.stdin = io.StringIO("test_password\ntest_password\n")
            
            try:
                generate_receiver_keys_cli(tmpdir, password=None)
            finally:
                sys.stdin = old_stdin
            
            priv_file = Path(tmpdir) / "receiver_private.pem"
            pub_file = Path(tmpdir) / "receiver_public.key"
            
            assert priv_file.exists()
            assert pub_file.exists()
    
    def test_cli_with_password(self):
        """Test CLI with provided password."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keys_cli
        
        with tempfile.TemporaryDirectory() as tmpdir:
            generate_receiver_keys_cli(tmpdir, password="direct_password")
            
            priv_file = Path(tmpdir) / "receiver_private.pem"
            pub_file = Path(tmpdir) / "receiver_public.key"
            
            assert priv_file.exists()
            assert pub_file.exists()


class TestForwardSecrecyKeys:
    """Test ForwardSecrecyKeys dataclass."""
    
    def test_dataclass_creation(self):
        """Test dataclass creation."""
        from meow_decoder.x25519_forward_secrecy import ForwardSecrecyKeys
        
        priv = secrets.token_bytes(32)
        pub = secrets.token_bytes(32)
        
        keys = ForwardSecrecyKeys(
            ephemeral_private=priv,
            ephemeral_public=pub
        )
        
        assert keys.ephemeral_private == priv
        assert keys.ephemeral_public == pub
        assert keys.receiver_public is None
    
    def test_with_receiver_public(self):
        """Test dataclass with receiver public key."""
        from meow_decoder.x25519_forward_secrecy import ForwardSecrecyKeys
        
        priv = secrets.token_bytes(32)
        pub = secrets.token_bytes(32)
        recv = secrets.token_bytes(32)
        
        keys = ForwardSecrecyKeys(
            ephemeral_private=priv,
            ephemeral_public=pub,
            receiver_public=recv
        )
        
        assert keys.receiver_public == recv


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
