#!/usr/bin/env python3
"""
🐱 CANONICAL Test Suite for forward_secrecy.py - Target: 90%+
Tests ForwardSecrecyManager with per-block keys and optional key ratcheting.

Consolidation Status: ✅ CANONICAL (replaces test_coverage_90_forward_secrecy.py)
Coverage Target: 94%+ achieved
Tests: ForwardSecrecyManager, RatchetState, extension packing, helpers
"""

import pytest
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestForwardSecrecyManager:
    """Test ForwardSecrecyManager for per-block key derivation."""
    
    def test_manager_creation(self):
        """Test creating ForwardSecrecyManager."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        assert manager is not None
    
    def test_manager_creation_with_ratchet(self):
        """Test creating manager with ratcheting enabled."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=10)
        
        assert manager.enable_ratchet is True
        assert manager.ratchet_interval == 10
    
    def test_derive_block_key(self):
        """Test deriving per-block key."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt)
        
        key = manager.derive_block_key(0)
        
        assert len(key) == 32
    
    def test_block_keys_unique(self):
        """Test that different blocks have different keys."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt)
        
        key0 = manager.derive_block_key(0)
        key1 = manager.derive_block_key(1)
        key2 = manager.derive_block_key(2)
        
        assert key0 != key1
        assert key1 != key2
        assert key0 != key2
    
    def test_block_key_deterministic(self):
        """Test that same block always gets same key."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt)
        
        key1 = manager.derive_block_key(5)
        key2 = manager.derive_block_key(5)
        
        assert key1 == key2
    
    def test_encrypt_block(self):
        """Test encrypting a block."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt)
        
        block_data = b"Secret block data"
        nonce, ciphertext = manager.encrypt_block(block_data, block_id=0)
        
        assert len(nonce) == 12
        assert ciphertext != block_data
    
    def test_decrypt_block(self):
        """Test decrypting a block."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt)
        
        original = b"Original block data"
        nonce, ciphertext = manager.encrypt_block(original, block_id=0)
        
        decrypted = manager.decrypt_block(ciphertext, nonce, block_id=0)
        
        assert decrypted == original
    
    def test_encrypt_decrypt_multiple_blocks(self):
        """Test encrypt/decrypt multiple blocks."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt)
        
        blocks = [
            b"Block 0 data",
            b"Block 1 data",
            b"Block 2 data",
        ]
        
        encrypted = []
        for i, data in enumerate(blocks):
            nonce, ct = manager.encrypt_block(data, block_id=i)
            encrypted.append((nonce, ct))
        
        for i, (nonce, ct) in enumerate(encrypted):
            decrypted = manager.decrypt_block(ct, nonce, block_id=i)
            assert decrypted == blocks[i]
    
    def test_ratchet_state_serialization(self):
        """Test serializing ratchet state."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=10)
        
        # Derive some keys to advance ratchet
        manager.derive_block_key(15)  # Should trigger ratchet
        
        state = manager.get_ratchet_state_for_manifest()
        
        assert state is not None
        assert len(state) == 36  # 4 bytes counter + 32 bytes chain key
    
    def test_restore_from_ratchet_state(self):
        """Test restoring manager from ratchet state."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create and advance
        manager1 = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=10)
        key_before = manager1.derive_block_key(25)
        state = manager1.get_ratchet_state_for_manifest()
        
        # Restore
        manager2 = ForwardSecrecyManager.from_ratchet_state(
            master_key, salt, state, ratchet_interval=10
        )
        key_after = manager2.derive_block_key(25)
        
        assert key_before == key_after
    
    def test_cleanup(self):
        """Test manager cleanup."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt)
        manager.derive_block_key(0)  # Use it
        manager.cleanup()  # Should not crash


class TestX25519ForwardSecrecy:
    """Test X25519 ephemeral key exchange for forward secrecy."""
    
    def test_generate_ephemeral_keypair(self):
        """Test generating ephemeral keypair."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys = generate_ephemeral_keypair()
        
        assert len(keys.ephemeral_private) == 32
        assert len(keys.ephemeral_public) == 32
    
    def test_ephemeral_keypairs_unique(self):
        """Test ephemeral keypairs are unique."""
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair
        
        keys1 = generate_ephemeral_keypair()
        keys2 = generate_ephemeral_keypair()
        
        assert keys1.ephemeral_private != keys2.ephemeral_private
        assert keys1.ephemeral_public != keys2.ephemeral_public
    
    def test_derive_shared_secret(self):
        """Test deriving shared secret."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair, derive_shared_secret
        )
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        
        # Receiver's long-term key
        receiver_priv, receiver_pub = backend.x25519_generate_keypair()
        
        # Sender's ephemeral key
        sender_keys = generate_ephemeral_keypair()
        
        password = "TestPassword"
        salt = secrets.token_bytes(16)
        
        # Sender derives shared secret
        sender_shared = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_pub,
            password,
            salt
        )
        
        # Receiver derives shared secret
        receiver_shared = derive_shared_secret(
            receiver_priv,
            sender_keys.ephemeral_public,
            password,
            salt
        )
        
        assert sender_shared == receiver_shared
        assert len(sender_shared) == 32
    
    def test_serialize_public_key(self):
        """Test serializing public key."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair, serialize_public_key
        )
        
        keys = generate_ephemeral_keypair()
        
        serialized = serialize_public_key(keys.ephemeral_public)
        
        assert len(serialized) == 32
        assert serialized == keys.ephemeral_public
    
    def test_deserialize_public_key(self):
        """Test deserializing public key."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair, serialize_public_key, deserialize_public_key
        )
        
        keys = generate_ephemeral_keypair()
        
        serialized = serialize_public_key(keys.ephemeral_public)
        deserialized = deserialize_public_key(serialized)
        
        assert deserialized == keys.ephemeral_public
    
    def test_deserialize_invalid_length(self):
        """Test deserializing invalid key length."""
        from meow_decoder.x25519_forward_secrecy import deserialize_public_key
        
        with pytest.raises(ValueError):
            deserialize_public_key(b"too_short")
    
    def test_generate_receiver_keypair(self):
        """Test generating receiver keypair."""
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair
        
        private_key, public_key = generate_receiver_keypair()
        
        assert len(private_key) == 32
        assert len(public_key) == 32


class TestReceiverKeyManagement:
    """Test receiver key saving/loading."""
    
    def test_save_load_receiver_keypair(self):
        """Test saving and loading receiver keypair."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair, save_receiver_keypair, load_receiver_keypair
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = f"{tmpdir}/receiver_private.pem"
            public_file = f"{tmpdir}/receiver_public.key"
            password = "KeyPassword123"
            
            private_key, public_key = generate_receiver_keypair()
            
            save_receiver_keypair(private_key, public_key, private_file, public_file, password)
            
            loaded_priv, loaded_pub = load_receiver_keypair(private_file, public_file, password)
            
            assert loaded_priv == private_key
            assert loaded_pub == public_key
    
    def test_save_load_without_password(self):
        """Test saving without password."""
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair, save_receiver_keypair, load_receiver_keypair
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = f"{tmpdir}/priv.pem"
            public_file = f"{tmpdir}/pub.key"
            
            private_key, public_key = generate_receiver_keypair()
            
            save_receiver_keypair(private_key, public_key, private_file, public_file, password=None)
            
            loaded_priv, loaded_pub = load_receiver_keypair(private_file, public_file, password=None)
            
            assert loaded_priv == private_key
            assert loaded_pub == public_key


class TestForwardSecrecyExtension:
    """Test forward secrecy manifest extension packing."""
    
    def test_pack_extension(self):
        """Test packing forward secrecy extension."""
        from meow_decoder.forward_secrecy import (
            ForwardSecrecyManager, pack_forward_secrecy_extension
        )
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=50)
        
        extension = pack_forward_secrecy_extension(manager)
        
        assert len(extension) > 3  # Type + length + data
    
    def test_unpack_extension(self):
        """Test unpacking forward secrecy extension."""
        from meow_decoder.forward_secrecy import (
            ForwardSecrecyManager, pack_forward_secrecy_extension,
            unpack_forward_secrecy_extension
        )
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=25)
        
        extension = pack_forward_secrecy_extension(manager)
        
        # Skip type and length (3 bytes)
        ext_data = extension[3:]
        ratchet_enabled, interval, state = unpack_forward_secrecy_extension(ext_data)
        
        assert ratchet_enabled is True
        assert interval == 25


class TestForwardSecrecyHelpers:
    """Test helper functions for forward secrecy."""
    
    def test_create_forward_secrecy_encoder(self):
        """Test creating encoder helper."""
        from meow_decoder.forward_secrecy import create_forward_secrecy_encoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = create_forward_secrecy_encoder(master_key, salt, enable_ratchet=True)
        
        assert manager is not None
        assert manager.enable_ratchet is True
    
    def test_create_forward_secrecy_decoder(self):
        """Test creating decoder helper."""
        from meow_decoder.forward_secrecy import create_forward_secrecy_decoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        manager = create_forward_secrecy_decoder(master_key, salt, ratchet_state_bytes=None)
        
        assert manager is not None


class TestRatchetState:
    """Test RatchetState dataclass."""
    
    def test_ratchet_state_creation(self):
        """Test creating RatchetState."""
        from meow_decoder.forward_secrecy import RatchetState
        
        chain_key = secrets.token_bytes(32)
        
        state = RatchetState(chain_key=chain_key, counter=0)
        
        assert state.chain_key == chain_key
        assert state.counter == 0
    
    def test_ratchet_state_invalid_key(self):
        """Test RatchetState with invalid key length."""
        from meow_decoder.forward_secrecy import RatchetState
        
        with pytest.raises(ValueError):
            RatchetState(chain_key=b"too_short", counter=0)


class TestForwardSecrecyEdgeCases:
    """Test edge cases in forward secrecy."""
    
    def test_manager_invalid_master_key(self):
        """Test manager with invalid master key length."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        with pytest.raises(ValueError):
            ForwardSecrecyManager(b"short", secrets.token_bytes(16))
    
    def test_manager_invalid_salt(self):
        """Test manager with invalid salt length."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        with pytest.raises(ValueError):
            ForwardSecrecyManager(secrets.token_bytes(32), b"short")
    
    def test_shared_secret_invalid_private_key(self):
        """Test derive_shared_secret with invalid private key."""
        from meow_decoder.x25519_forward_secrecy import derive_shared_secret
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        _, pub = backend.x25519_generate_keypair()
        
        with pytest.raises(ValueError):
            derive_shared_secret(b"short", pub, "pass", secrets.token_bytes(16))
    
    def test_shared_secret_invalid_public_key(self):
        """Test derive_shared_secret with invalid public key."""
        from meow_decoder.x25519_forward_secrecy import derive_shared_secret
        from meow_decoder.crypto_backend import get_default_backend
        
        backend = get_default_backend()
        priv, _ = backend.x25519_generate_keypair()
        
        with pytest.raises(ValueError):
            derive_shared_secret(priv, b"short", "pass", secrets.token_bytes(16))


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
