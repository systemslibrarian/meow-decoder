#!/usr/bin/env python3
"""Tests for forward secrecy implementation."""

import pytest
import secrets

from meow_decoder.forward_secrecy import (
    ForwardSecrecyManager,
    RatchetState,
    pack_forward_secrecy_extension,
    unpack_forward_secrecy_extension,
    create_forward_secrecy_encoder,
    create_forward_secrecy_decoder,
)


class TestRatchetState:
    """Tests for RatchetState dataclass."""

    def test_ratchet_state_creation(self):
        """Test creating a ratchet state."""
        chain_key = secrets.token_bytes(32)
        state = RatchetState(chain_key=chain_key, counter=0)

        assert state.chain_key == chain_key
        assert state.counter == 0

    def test_ratchet_state_invalid_key(self):
        """Test that invalid key length raises error."""
        with pytest.raises(ValueError):
            RatchetState(chain_key=b"too short")


class TestForwardSecrecyManager:
    """Tests for ForwardSecrecyManager class."""

    def test_manager_creation(self):
        """Test creating a forward secrecy manager."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)

        assert manager is not None

    def test_manager_invalid_key_length(self):
        """Test that invalid master key length raises error."""
        with pytest.raises(ValueError):
            ForwardSecrecyManager(b"short", secrets.token_bytes(16))

    def test_manager_invalid_salt_length(self):
        """Test that invalid salt length raises error."""
        with pytest.raises(ValueError):
            ForwardSecrecyManager(secrets.token_bytes(32), b"short")

    def test_derive_block_key(self):
        """Test per-block key derivation."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt)

        key0 = manager.derive_block_key(0)
        key1 = manager.derive_block_key(1)
        key0_again = manager.derive_block_key(0)

        assert len(key0) == 32
        assert key0 != key1
        assert key0 == key0_again

    def test_encrypt_decrypt_block(self):
        """Test block encryption and decryption."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt)

        plaintext = b"Secret block data here!"
        nonce, ciphertext = manager.encrypt_block(plaintext, block_id=0)

        decrypted = manager.decrypt_block(ciphertext, nonce, block_id=0)

        assert decrypted == plaintext

    def test_encrypt_decrypt_multiple_blocks(self):
        """Test encrypting/decrypting multiple blocks."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt)

        blocks = [b"Block 0", b"Block 1", b"Block 2"]
        encrypted = []

        for i, block in enumerate(blocks):
            nonce, cipher = manager.encrypt_block(block, block_id=i)
            encrypted.append((nonce, cipher))

        for i, (nonce, cipher) in enumerate(encrypted):
            decrypted = manager.decrypt_block(cipher, nonce, block_id=i)
            assert decrypted == blocks[i]

    def test_ratchet_enabled(self):
        """Test key ratcheting."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=10)

        key0 = manager.derive_block_key(0)
        key10 = manager.derive_block_key(10)
        key20 = manager.derive_block_key(20)

        assert key0 != key10
        assert key10 != key20

    def test_get_ratchet_state_for_manifest(self):
        """Test getting ratchet state for storage."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True)

        manager.derive_block_key(100)

        state = manager.get_ratchet_state_for_manifest()

        assert state is not None
        assert len(state) == 36

    def test_from_ratchet_state(self):
        """Test restoring manager from saved state."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager1 = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=10)
        key100 = manager1.derive_block_key(100)
        state = manager1.get_ratchet_state_for_manifest()

        manager2 = ForwardSecrecyManager.from_ratchet_state(
            master_key, salt, state, ratchet_interval=10
        )
        key100_restored = manager2.derive_block_key(100)

        assert key100 == key100_restored

    def test_cleanup(self):
        """Test secure cleanup."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt)
        manager.derive_block_key(0)

        manager.cleanup()


class TestExtensionPacking:
    """Tests for extension packing/unpacking."""

    def test_pack_extension(self):
        """Test packing forward secrecy extension."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=50)

        packed = pack_forward_secrecy_extension(manager)

        assert len(packed) > 3

    def test_unpack_extension(self):
        """Test unpacking forward secrecy extension."""
        ext_data = b"\x01\x00\x32" + secrets.token_bytes(36)

        enabled, interval, state = unpack_forward_secrecy_extension(ext_data)

        assert enabled is True
        assert interval == 50
        assert len(state) == 36


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_create_encoder(self):
        """Test create_forward_secrecy_encoder helper."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = create_forward_secrecy_encoder(master_key, salt)

        assert manager is not None

    def test_create_decoder(self):
        """Test create_forward_secrecy_decoder helper."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = create_forward_secrecy_decoder(master_key, salt)

        assert manager is not None


class TestForwardSecrecyCoverageGaps:
    """Tests for coverage gaps in forward_secrecy.py."""

    def test_export_ratchet_state_disabled(self):
        """Test export_ratchet_state returns None when ratcheting disabled (line 230)."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        # Create manager with ratcheting DISABLED
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)

        # Export should return None
        state = manager.get_ratchet_state_for_manifest()
        assert state is None

    def test_invalid_ratchet_state_length(self):
        """Test from_ratchet_state with invalid length raises (line 261)."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        # Invalid length (should be 36 = 4 + 32)
        invalid_state = b"\x00" * 10

        with pytest.raises(ValueError, match="Invalid ratchet state length"):
            ForwardSecrecyManager.from_ratchet_state(
                master_key, salt, invalid_state, ratchet_interval=10
            )

    def test_cleanup_no_master_key(self):
        """Test cleanup when master_key is None (line 275->281)."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        # Manually set master_key to None to test branch
        manager.master_key = None
        manager.cleanup()  # Should not raise

    def test_cleanup_no_ratchet_state(self):
        """Test cleanup when ratchet_state is None (line 288)."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        # Ratcheting disabled means no ratchet state
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        manager.cleanup()  # Should not raise

    def test_cleanup_with_none_in_cache(self):
        """Test cleanup when _key_cache has None values (line 288->287 branch)."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        # Inject a None value into the cache
        manager._key_cache[0] = None
        manager.cleanup()  # Should handle None gracefully

    def test_pack_extension_no_ratchet_state(self):
        """Test pack_forward_secrecy_extension when no ratchet state (line 332->336)."""
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        # Ratcheting disabled means no ratchet state to pack
        manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)

        packed = pack_forward_secrecy_extension(manager)

        # Should still pack basic data (type, length, flags, interval)
        assert len(packed) >= 6  # type(1) + length(2) + flags(1) + interval(2)

    def test_unpack_extension_too_short(self):
        """Test unpack_forward_secrecy_extension with too short data (line 351)."""
        with pytest.raises(ValueError, match="Extension data too short"):
            unpack_forward_secrecy_extension(b"\x01\x02")  # Only 2 bytes, need 3

    def test_unpack_extension_ratchet_enabled_short_data(self):
        """Test unpack when ratchet enabled but data < 39 bytes (line 357->360)."""
        # ratchet_enabled flag set (0x01), interval=10, but no ratchet state bytes
        ext_data = b"\x01\x00\x0a"  # 3 bytes: flags=1, interval=10

        enabled, interval, state = unpack_forward_secrecy_extension(ext_data)

        assert enabled is True
        assert interval == 10
        assert state is None  # Not enough data for ratchet state
