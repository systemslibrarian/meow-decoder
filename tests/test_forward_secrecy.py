#!/usr/bin/env python3
"""Tests for meow_decoder.forward_secrecy and x25519_forward_secrecy.
Target: 95%+ branch coverage
"""

import secrets
import tempfile

import pytest


class TestForwardSecrecyManager:
    def test_manager_creation(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(
            secrets.token_bytes(32), secrets.token_bytes(16), enable_ratchet=False
        )
        assert manager is not None

    def test_manager_creation_with_ratchet(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(
            secrets.token_bytes(32),
            secrets.token_bytes(16),
            enable_ratchet=True,
            ratchet_interval=10,
        )
        assert manager.enable_ratchet is True
        assert manager.ratchet_interval == 10

    def test_derive_block_key(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16))
        key = manager.derive_block_key(0)
        assert len(key) == 32

    def test_block_keys_unique(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16))
        key0 = manager.derive_block_key(0)
        key1 = manager.derive_block_key(1)
        key2 = manager.derive_block_key(2)
        assert key0 != key1
        assert key1 != key2
        assert key0 != key2

    def test_block_key_deterministic(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16))
        key1 = manager.derive_block_key(5)
        key2 = manager.derive_block_key(5)
        assert key1 == key2

    def test_encrypt_decrypt_block(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16))
        original = b"Original block data"
        nonce, ciphertext = manager.encrypt_block(original, block_id=0)
        assert len(nonce) == 12
        assert ciphertext != original
        decrypted = manager.decrypt_block(ciphertext, nonce, block_id=0)
        assert decrypted == original

    def test_encrypt_decrypt_multiple_blocks(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16))
        blocks = [b"Block 0 data", b"Block 1 data", b"Block 2 data"]
        encrypted = []
        for i, data in enumerate(blocks):
            nonce, ct = manager.encrypt_block(data, block_id=i)
            encrypted.append((nonce, ct))
        for i, (nonce, ct) in enumerate(encrypted):
            assert manager.decrypt_block(ct, nonce, block_id=i) == blocks[i]

    def test_ratchet_state_serialization(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(
            secrets.token_bytes(32),
            secrets.token_bytes(16),
            enable_ratchet=True,
            ratchet_interval=10,
        )
        manager.derive_block_key(15)
        state = manager.get_ratchet_state_for_manifest()
        assert state is not None
        assert len(state) == 36

    def test_ratchet_state_none_when_disabled(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(
            secrets.token_bytes(32), secrets.token_bytes(16), enable_ratchet=False
        )
        assert manager.get_ratchet_state_for_manifest() is None

    def test_restore_from_ratchet_state(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        manager1 = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=10)
        key_before = manager1.derive_block_key(25)
        state = manager1.get_ratchet_state_for_manifest()

        manager2 = ForwardSecrecyManager.from_ratchet_state(
            master_key, salt, state, ratchet_interval=10
        )
        key_after = manager2.derive_block_key(25)
        assert key_before == key_after

    def test_restore_invalid_ratchet_state_length(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        with pytest.raises(ValueError):
            ForwardSecrecyManager.from_ratchet_state(
                secrets.token_bytes(32),
                secrets.token_bytes(16),
                ratchet_state_bytes=b"short",
                ratchet_interval=10,
            )

    def test_cleanup(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        manager = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16))
        manager.derive_block_key(0)
        manager.cleanup()


class TestX25519ForwardSecrecy:
    def test_generate_ephemeral_keypair(self):
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair

        keys = generate_ephemeral_keypair()
        assert len(keys.ephemeral_private) == 32
        assert len(keys.ephemeral_public) == 32

    def test_ephemeral_keypairs_unique(self):
        from meow_decoder.x25519_forward_secrecy import generate_ephemeral_keypair

        keys1 = generate_ephemeral_keypair()
        keys2 = generate_ephemeral_keypair()
        assert keys1.ephemeral_private != keys2.ephemeral_private
        assert keys1.ephemeral_public != keys2.ephemeral_public

    def test_derive_shared_secret(self):
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            derive_shared_secret,
        )
        from meow_decoder.crypto_backend import get_default_backend

        backend = get_default_backend()
        receiver_priv, receiver_pub = backend.x25519_generate_keypair()
        sender_keys = generate_ephemeral_keypair()
        password = "TestPassword"
        salt = secrets.token_bytes(16)

        sender_shared = derive_shared_secret(
            sender_keys.ephemeral_private, receiver_pub, password, salt
        )
        receiver_shared = derive_shared_secret(
            receiver_priv, sender_keys.ephemeral_public, password, salt
        )

        assert sender_shared == receiver_shared
        assert len(sender_shared) == 32

    def test_serialize_public_key(self):
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            serialize_public_key,
        )

        keys = generate_ephemeral_keypair()
        serialized = serialize_public_key(keys.ephemeral_public)
        assert len(serialized) == 32
        assert serialized == keys.ephemeral_public

    def test_deserialize_public_key(self):
        from meow_decoder.x25519_forward_secrecy import (
            generate_ephemeral_keypair,
            serialize_public_key,
            deserialize_public_key,
        )

        keys = generate_ephemeral_keypair()
        serialized = serialize_public_key(keys.ephemeral_public)
        deserialized = deserialize_public_key(serialized)
        assert deserialized == keys.ephemeral_public

    def test_deserialize_invalid_length(self):
        from meow_decoder.x25519_forward_secrecy import deserialize_public_key

        with pytest.raises(ValueError):
            deserialize_public_key(b"too_short")

    def test_generate_receiver_keypair(self):
        from meow_decoder.x25519_forward_secrecy import generate_receiver_keypair

        private_key, public_key = generate_receiver_keypair()
        assert len(private_key) == 32
        assert len(public_key) == 32


class TestReceiverKeyManagement:
    def test_save_load_receiver_keypair(self):
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            save_receiver_keypair,
            load_receiver_keypair,
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
        from meow_decoder.x25519_forward_secrecy import (
            generate_receiver_keypair,
            save_receiver_keypair,
            load_receiver_keypair,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = f"{tmpdir}/priv.pem"
            public_file = f"{tmpdir}/pub.key"

            private_key, public_key = generate_receiver_keypair()
            save_receiver_keypair(private_key, public_key, private_file, public_file, password=None)
            loaded_priv, loaded_pub = load_receiver_keypair(
                private_file, public_file, password=None
            )

            assert loaded_priv == private_key
            assert loaded_pub == public_key


class TestForwardSecrecyExtension:
    def test_pack_extension(self):
        from meow_decoder.forward_secrecy import (
            ForwardSecrecyManager,
            pack_forward_secrecy_extension,
        )

        manager = ForwardSecrecyManager(
            secrets.token_bytes(32),
            secrets.token_bytes(16),
            enable_ratchet=True,
            ratchet_interval=50,
        )
        extension = pack_forward_secrecy_extension(manager)
        assert len(extension) > 3

    def test_pack_extension_no_ratchet(self):
        from meow_decoder.forward_secrecy import (
            ForwardSecrecyManager,
            pack_forward_secrecy_extension,
        )

        manager = ForwardSecrecyManager(
            secrets.token_bytes(32), secrets.token_bytes(16), enable_ratchet=False
        )
        extension = pack_forward_secrecy_extension(manager)
        # Should only contain flags + interval (no ratchet state)
        assert len(extension) == 3 + 3

    def test_unpack_extension(self):
        from meow_decoder.forward_secrecy import (
            ForwardSecrecyManager,
            pack_forward_secrecy_extension,
            unpack_forward_secrecy_extension,
        )

        manager = ForwardSecrecyManager(
            secrets.token_bytes(32),
            secrets.token_bytes(16),
            enable_ratchet=True,
            ratchet_interval=25,
        )
        extension = pack_forward_secrecy_extension(manager)
        ext_data = extension[3:]
        ratchet_enabled, interval, state = unpack_forward_secrecy_extension(ext_data)
        assert ratchet_enabled is True
        assert interval == 25

    def test_unpack_extension_too_short(self):
        from meow_decoder.forward_secrecy import unpack_forward_secrecy_extension

        with pytest.raises(ValueError):
            unpack_forward_secrecy_extension(b"\x00\x01")

    def test_unpack_extension_no_state_bytes(self):
        from meow_decoder.forward_secrecy import unpack_forward_secrecy_extension

        # flags indicate ratchet enabled, but no state bytes present
        ratchet_enabled, interval, state = unpack_forward_secrecy_extension(b"\x01\x00\x05")
        assert ratchet_enabled is True
        assert interval == 5
        assert state is None


class TestForwardSecrecyHelpers:
    def test_create_forward_secrecy_encoder(self):
        from meow_decoder.forward_secrecy import create_forward_secrecy_encoder

        manager = create_forward_secrecy_encoder(
            secrets.token_bytes(32), secrets.token_bytes(16), enable_ratchet=True
        )
        assert manager is not None
        assert manager.enable_ratchet is True

    def test_create_forward_secrecy_decoder(self):
        from meow_decoder.forward_secrecy import create_forward_secrecy_decoder

        manager = create_forward_secrecy_decoder(
            secrets.token_bytes(32), secrets.token_bytes(16), ratchet_state_bytes=None
        )
        assert manager is not None


class TestRatchetState:
    def test_ratchet_state_creation(self):
        from meow_decoder.forward_secrecy import RatchetState

        chain_key = secrets.token_bytes(32)
        state = RatchetState(chain_key=chain_key, counter=0)
        assert state.chain_key == chain_key
        assert state.counter == 0

    def test_ratchet_state_invalid_key(self):
        from meow_decoder.forward_secrecy import RatchetState

        with pytest.raises(ValueError):
            RatchetState(chain_key=b"too_short", counter=0)


class TestForwardSecrecyEdgeCases:
    def test_manager_invalid_master_key(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        with pytest.raises(ValueError):
            ForwardSecrecyManager(b"short", secrets.token_bytes(16))

    def test_manager_invalid_salt(self):
        from meow_decoder.forward_secrecy import ForwardSecrecyManager

        with pytest.raises(ValueError):
            ForwardSecrecyManager(secrets.token_bytes(32), b"short")

    def test_shared_secret_invalid_private_key(self):
        from meow_decoder.x25519_forward_secrecy import derive_shared_secret
        from meow_decoder.crypto_backend import get_default_backend

        backend = get_default_backend()
        _, pub = backend.x25519_generate_keypair()

        with pytest.raises(ValueError):
            derive_shared_secret(b"short", pub, "pass", secrets.token_bytes(16))

    def test_shared_secret_invalid_public_key(self):
        from meow_decoder.x25519_forward_secrecy import derive_shared_secret
        from meow_decoder.crypto_backend import get_default_backend

        backend = get_default_backend()
        priv, _ = backend.x25519_generate_keypair()

        with pytest.raises(ValueError):
            derive_shared_secret(priv, b"short", "pass", secrets.token_bytes(16))
