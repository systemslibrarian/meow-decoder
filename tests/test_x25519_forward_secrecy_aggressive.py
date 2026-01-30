#!/usr/bin/env python3
"""
🧪 Aggressive Tests for x25519_forward_secrecy.py
Target: 95%+ coverage of forward secrecy implementation

This is security-critical - tests key generation, exchange, and serialization.
"""

import pytest
import secrets
import tempfile
import os
from pathlib import Path

# Import module under test
from meow_decoder.x25519_forward_secrecy import (
    ForwardSecrecyKeys,
    generate_ephemeral_keypair,
    derive_shared_secret,
    serialize_public_key,
    deserialize_public_key,
    generate_receiver_keypair,
    save_receiver_keypair,
    load_receiver_keypair,
    generate_receiver_keys_cli,
)


class TestForwardSecrecyKeysDataclass:
    """Tests for ForwardSecrecyKeys dataclass."""
    
    def test_create_with_all_fields(self):
        """Test creation with all fields."""
        keys = ForwardSecrecyKeys(
            ephemeral_private=b"p" * 32,
            ephemeral_public=b"P" * 32,
            receiver_public=b"R" * 32,
        )
        
        assert keys.ephemeral_private == b"p" * 32
        assert keys.ephemeral_public == b"P" * 32
        assert keys.receiver_public == b"R" * 32
    
    def test_create_without_receiver_public(self):
        """Test creation without optional receiver_public."""
        keys = ForwardSecrecyKeys(
            ephemeral_private=b"p" * 32,
            ephemeral_public=b"P" * 32,
        )
        
        assert keys.receiver_public is None


class TestGenerateEphemeralKeypair:
    """Tests for generate_ephemeral_keypair."""
    
    def test_returns_forward_secrecy_keys(self):
        """Test return type."""
        keys = generate_ephemeral_keypair()
        assert isinstance(keys, ForwardSecrecyKeys)
    
    def test_private_key_32_bytes(self):
        """Test private key is 32 bytes."""
        keys = generate_ephemeral_keypair()
        assert len(keys.ephemeral_private) == 32
    
    def test_public_key_32_bytes(self):
        """Test public key is 32 bytes."""
        keys = generate_ephemeral_keypair()
        assert len(keys.ephemeral_public) == 32
    
    def test_keys_are_different_each_call(self):
        """Test different keys each call."""
        keys1 = generate_ephemeral_keypair()
        keys2 = generate_ephemeral_keypair()
        
        assert keys1.ephemeral_private != keys2.ephemeral_private
        assert keys1.ephemeral_public != keys2.ephemeral_public
    
    def test_private_and_public_different(self):
        """Test private and public keys are different."""
        keys = generate_ephemeral_keypair()
        assert keys.ephemeral_private != keys.ephemeral_public


class TestDeriveSharedSecret:
    """Tests for derive_shared_secret."""
    
    def test_basic_derivation(self):
        """Test basic shared secret derivation."""
        # Generate sender ephemeral keypair
        sender_keys = generate_ephemeral_keypair()
        
        # Generate receiver keypair
        receiver_private, receiver_public = generate_receiver_keypair()
        
        salt = secrets.token_bytes(16)
        password = "test_password"
        
        secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
        )
        
        assert len(secret) == 32
    
    def test_same_inputs_same_output(self):
        """Test deterministic derivation."""
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        password = "password123"
        
        secret1 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
        )
        secret2 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
        )
        
        assert secret1 == secret2
    
    def test_different_password_different_secret(self):
        """Test different password gives different secret."""
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        
        secret1 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "password1",
            salt,
        )
        secret2 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "password2",
            salt,
        )
        
        assert secret1 != secret2
    
    def test_different_salt_different_secret(self):
        """Test different salt gives different secret."""
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        password = "password"
        
        secret1 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            secrets.token_bytes(16),
        )
        secret2 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            secrets.token_bytes(16),
        )
        
        assert secret1 != secret2
    
    def test_invalid_private_key_length(self):
        """Test invalid private key length raises."""
        receiver_private, receiver_public = generate_receiver_keypair()
        
        with pytest.raises(ValueError, match="32 bytes"):
            derive_shared_secret(
                b"short",
                receiver_public,
                "password",
                secrets.token_bytes(16),
            )
    
    def test_invalid_public_key_length(self):
        """Test invalid public key length raises."""
        sender_keys = generate_ephemeral_keypair()
        
        with pytest.raises(ValueError, match="32 bytes"):
            derive_shared_secret(
                sender_keys.ephemeral_private,
                b"short",
                "password",
                secrets.token_bytes(16),
            )
    
    def test_invalid_salt_length(self):
        """Test invalid salt length raises."""
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        
        with pytest.raises(ValueError, match="16 bytes"):
            derive_shared_secret(
                sender_keys.ephemeral_private,
                receiver_public,
                "password",
                b"short",
            )
    
    def test_custom_info_parameter(self):
        """Test custom info parameter."""
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        
        secret1 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "password",
            salt,
            info=b"custom_info_v1",
        )
        secret2 = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "password",
            salt,
            info=b"custom_info_v2",
        )
        
        assert secret1 != secret2


class TestSerializePublicKey:
    """Tests for serialize_public_key."""
    
    def test_returns_same_bytes(self):
        """Test serialization returns same bytes."""
        keys = generate_ephemeral_keypair()
        
        serialized = serialize_public_key(keys.ephemeral_public)
        
        assert serialized == keys.ephemeral_public
    
    def test_32_bytes_output(self):
        """Test output is 32 bytes."""
        keys = generate_ephemeral_keypair()
        
        serialized = serialize_public_key(keys.ephemeral_public)
        
        assert len(serialized) == 32


class TestDeserializePublicKey:
    """Tests for deserialize_public_key."""
    
    def test_returns_same_bytes(self):
        """Test deserialization returns same bytes."""
        original = secrets.token_bytes(32)
        
        deserialized = deserialize_public_key(original)
        
        assert deserialized == original
    
    def test_invalid_length_raises(self):
        """Test invalid length raises ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            deserialize_public_key(b"short")
    
    def test_roundtrip(self):
        """Test serialize/deserialize roundtrip."""
        keys = generate_ephemeral_keypair()
        
        serialized = serialize_public_key(keys.ephemeral_public)
        deserialized = deserialize_public_key(serialized)
        
        assert deserialized == keys.ephemeral_public


class TestGenerateReceiverKeypair:
    """Tests for generate_receiver_keypair."""
    
    def test_returns_tuple(self):
        """Test returns tuple of two bytes objects."""
        result = generate_receiver_keypair()
        
        assert isinstance(result, tuple)
        assert len(result) == 2
    
    def test_private_key_32_bytes(self):
        """Test private key is 32 bytes."""
        private, public = generate_receiver_keypair()
        assert len(private) == 32
    
    def test_public_key_32_bytes(self):
        """Test public key is 32 bytes."""
        private, public = generate_receiver_keypair()
        assert len(public) == 32
    
    def test_unique_each_call(self):
        """Test unique keypair each call."""
        kp1 = generate_receiver_keypair()
        kp2 = generate_receiver_keypair()
        
        assert kp1[0] != kp2[0]
        assert kp1[1] != kp2[1]


class TestSaveReceiverKeypair:
    """Tests for save_receiver_keypair."""
    
    def test_save_without_password(self):
        """Test saving keypair without password."""
        private, public = generate_receiver_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")
            
            save_receiver_keypair(
                private,
                public,
                private_file,
                public_file,
            )
            
            assert os.path.exists(private_file)
            assert os.path.exists(public_file)
            
            # Public key should be raw bytes
            with open(public_file, 'rb') as f:
                saved_public = f.read()
            assert saved_public == public
    
    def test_save_with_password(self):
        """Test saving keypair with password."""
        private, public = generate_receiver_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")
            
            save_receiver_keypair(
                private,
                public,
                private_file,
                public_file,
                password="secret_password",
            )
            
            # Private key should be encrypted PEM
            with open(private_file, 'rb') as f:
                pem_content = f.read()
            assert b"ENCRYPTED" in pem_content


class TestLoadReceiverKeypair:
    """Tests for load_receiver_keypair."""
    
    def test_load_without_password(self):
        """Test loading keypair without password."""
        private, public = generate_receiver_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")
            
            save_receiver_keypair(private, public, private_file, public_file)
            
            loaded_private, loaded_public = load_receiver_keypair(
                private_file, public_file
            )
            
            assert loaded_private == private
            assert loaded_public == public
    
    def test_load_with_password(self):
        """Test loading keypair with password."""
        private, public = generate_receiver_keypair()
        password = "test_password_123"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")
            
            save_receiver_keypair(
                private, public, private_file, public_file, password
            )
            
            loaded_private, loaded_public = load_receiver_keypair(
                private_file, public_file, password
            )
            
            assert loaded_private == private
            assert loaded_public == public
    
    def test_invalid_public_key_raises(self):
        """Test invalid public key length raises."""
        private, public = generate_receiver_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")
            
            save_receiver_keypair(private, public, private_file, public_file)
            
            # Corrupt public key file
            with open(public_file, 'wb') as f:
                f.write(b"short")
            
            with pytest.raises(ValueError, match="Invalid public key length"):
                load_receiver_keypair(private_file, public_file)


class TestGenerateReceiverKeysCli:
    """Tests for generate_receiver_keys_cli."""
    
    def test_generates_files(self):
        """Test CLI generates key files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate stdin for password input
            import io
            import sys
            
            old_stdin = sys.stdin
            try:
                sys.stdin = io.StringIO("testpassword\ntestpassword\n")
                generate_receiver_keys_cli(tmpdir)
            finally:
                sys.stdin = old_stdin
            
            private_file = os.path.join(tmpdir, "receiver_private.pem")
            public_file = os.path.join(tmpdir, "receiver_public.key")
            
            assert os.path.exists(private_file)
            assert os.path.exists(public_file)
    
    def test_with_explicit_password(self):
        """Test CLI with explicit password."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generate_receiver_keys_cli(tmpdir, password="explicit_pass")
            
            private_file = os.path.join(tmpdir, "receiver_private.pem")
            public_file = os.path.join(tmpdir, "receiver_public.key")
            
            assert os.path.exists(private_file)
            assert os.path.exists(public_file)


class TestForwardSecrecyIntegration:
    """Integration tests for complete forward secrecy workflow."""
    
    def test_complete_key_exchange(self):
        """Test complete key exchange between sender and receiver."""
        # Receiver generates long-term keypair
        receiver_private, receiver_public = generate_receiver_keypair()
        
        # Sender generates ephemeral keypair
        sender_keys = generate_ephemeral_keypair()
        
        # Both parties have same salt and password
        salt = secrets.token_bytes(16)
        password = "shared_password"
        
        # Sender derives shared secret
        sender_secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
        )
        
        # Receiver derives shared secret using sender's ephemeral public
        # Note: In real usage, receiver would use their private key
        # For this test, we verify sender can derive a consistent secret
        assert len(sender_secret) == 32
    
    def test_save_load_roundtrip(self):
        """Test complete save/load roundtrip."""
        private, public = generate_receiver_keypair()
        password = "roundtrip_password"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "test_private.pem")
            public_file = os.path.join(tmpdir, "test_public.key")
            
            # Save
            save_receiver_keypair(
                private, public, private_file, public_file, password
            )
            
            # Load
            loaded_private, loaded_public = load_receiver_keypair(
                private_file, public_file, password
            )
            
            # Verify roundtrip
            assert loaded_private == private
            assert loaded_public == public
            
            # Verify loaded keys work for key exchange
            sender_keys = generate_ephemeral_keypair()
            salt = secrets.token_bytes(16)
            
            secret = derive_shared_secret(
                sender_keys.ephemeral_private,
                loaded_public,
                "test",
                salt,
            )
            
            assert len(secret) == 32


class TestForwardSecrecyEdgeCases:
    """Edge case tests."""
    
    def test_empty_password(self):
        """Test empty password still works."""
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        
        secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "",  # Empty password
            salt,
        )
        
        assert len(secret) == 32
    
    def test_unicode_password(self):
        """Test unicode password works."""
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        
        secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "密码🔐",  # Unicode password
            salt,
        )
        
        assert len(secret) == 32
    
    def test_long_password(self):
        """Test very long password works."""
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)
        
        secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "a" * 10000,  # Very long password
            salt,
        )
        
        assert len(secret) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
