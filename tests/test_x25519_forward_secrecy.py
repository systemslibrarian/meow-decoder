#!/usr/bin/env python3
"""Tests for meow_decoder.x25519_forward_secrecy.
Target: 95%+ branch coverage
"""

from meow_decoder.crypto_backend import get_handle_backend
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
import os
import secrets
import tempfile

import pytest

pytestmark = pytest.mark.security


class TestForwardSecrecyKeysDataclass:
    def test_create_with_all_fields(self):
        hb = get_handle_backend()
        handle = hb.import_x25519_private(b"p" * 32)
        keys = ForwardSecrecyKeys(
            ephemeral_private=handle,
            ephemeral_public=b"P" * 32,
            receiver_public=b"R" * 32,
        )
        assert isinstance(keys.ephemeral_private, int)
        assert keys.ephemeral_public == b"P" * 32
        assert keys.receiver_public == b"R" * 32

    def test_create_without_receiver_public(self):
        hb = get_handle_backend()
        handle = hb.import_x25519_private(b"p" * 32)
        keys = ForwardSecrecyKeys(
            ephemeral_private=handle,
            ephemeral_public=b"P" * 32,
        )
        assert keys.receiver_public is None


class TestGenerateEphemeralKeypair:
    def test_returns_forward_secrecy_keys(self):
        keys = generate_ephemeral_keypair()
        assert isinstance(keys, ForwardSecrecyKeys)

    def test_private_key_is_handle(self):
        keys = generate_ephemeral_keypair()
        assert isinstance(keys.ephemeral_private, int)
        hb = get_handle_backend()
        assert hb.exists(keys.ephemeral_private)

    def test_public_key_32_bytes(self):
        keys = generate_ephemeral_keypair()
        assert len(keys.ephemeral_public) == 32

    def test_keys_are_different_each_call(self):
        keys1 = generate_ephemeral_keypair()
        keys2 = generate_ephemeral_keypair()
        assert keys1.ephemeral_private != keys2.ephemeral_private
        assert keys1.ephemeral_public != keys2.ephemeral_public

    def test_private_and_public_different(self):
        keys = generate_ephemeral_keypair()
        assert keys.ephemeral_private != keys.ephemeral_public


class TestDeriveSharedSecret:
    def test_basic_derivation(self):
        sender_keys = generate_ephemeral_keypair()
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
        receiver_private, receiver_public = generate_receiver_keypair()

        with pytest.raises(ValueError, match="32 bytes"):
            derive_shared_secret(
                b"short",
                receiver_public,
                "password",
                secrets.token_bytes(16),
            )

    def test_invalid_public_key_length(self):
        sender_keys = generate_ephemeral_keypair()

        with pytest.raises(ValueError, match="32 bytes"):
            derive_shared_secret(
                sender_keys.ephemeral_private,
                b"short",
                "password",
                secrets.token_bytes(16),
            )

    def test_invalid_salt_length(self):
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

    def test_invalid_protocol_version_range(self):
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)

        with pytest.raises(ValueError, match="0..255"):
            derive_shared_secret(
                sender_keys.ephemeral_private,
                receiver_public,
                "password",
                salt,
                protocol_version=256,
            )

    def test_derive_uses_handle_backend(self):
        """Verify derive_shared_secret uses handle-based operations."""
        hb = get_handle_backend()
        private_handle, public = hb.x25519_generate_keypair()
        _, receiver_public = hb.x25519_generate_keypair()
        salt = secrets.token_bytes(16)
        # Should work with handle input (not raw bytes)
        secret = derive_shared_secret(private_handle, receiver_public, "pw", salt)
        assert isinstance(secret, bytes)
        assert len(secret) == 32


class TestSerializePublicKey:
    def test_returns_same_bytes(self):
        keys = generate_ephemeral_keypair()
        serialized = serialize_public_key(keys.ephemeral_public)
        assert serialized == keys.ephemeral_public

    def test_32_bytes_output(self):
        keys = generate_ephemeral_keypair()
        serialized = serialize_public_key(keys.ephemeral_public)
        assert len(serialized) == 32


class TestDeserializePublicKey:
    def test_returns_same_bytes(self):
        original = secrets.token_bytes(32)
        deserialized = deserialize_public_key(original)
        assert deserialized == original

    def test_invalid_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            deserialize_public_key(b"short")

    def test_roundtrip(self):
        keys = generate_ephemeral_keypair()
        serialized = serialize_public_key(keys.ephemeral_public)
        deserialized = deserialize_public_key(serialized)
        assert deserialized == keys.ephemeral_public


class TestGenerateReceiverKeypair:
    def test_returns_tuple(self):
        result = generate_receiver_keypair()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_private_key_is_handle(self):
        private, public = generate_receiver_keypair()
        assert isinstance(private, int)
        hb = get_handle_backend()
        assert hb.exists(private)

    def test_public_key_32_bytes(self):
        private, public = generate_receiver_keypair()
        assert len(public) == 32

    def test_unique_each_call(self):
        hb = get_handle_backend()
        kp1 = generate_receiver_keypair()
        kp2 = generate_receiver_keypair()
        # Handles are different
        assert kp1[0] != kp2[0]
        # Public keys are different
        assert kp1[1] != kp2[1]
        # Underlying key material is different
        assert hb.export_key(kp1[0]) != hb.export_key(kp2[0])


class TestSaveReceiverKeypair:
    def test_save_without_password(self):
        private, public = generate_receiver_keypair()

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            save_receiver_keypair(private, public, private_file, public_file)

            assert os.path.exists(private_file)
            assert os.path.exists(public_file)

            with open(public_file, "rb") as f:
                saved_public = f.read()
            assert saved_public == public

    def test_save_with_password(self):
        private, public = generate_receiver_keypair()

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            save_receiver_keypair(
                private, public, private_file, public_file, password="secret_password"
            )

            with open(private_file, "rb") as f:
                file_content = f.read()
            # SECURITY (M7): encrypted-at-rest keys now use Argon2id (marker \x03).
            assert file_content[:12] == b"MEOW_X25519\x03"
            # Must be longer than header (12) + salt (16) + nonce (12) + raw key (32)
            assert len(file_content) > 72


class TestLoadReceiverKeypair:
    def test_load_without_password(self):
        hb = get_handle_backend()
        private, public = generate_receiver_keypair()

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            save_receiver_keypair(private, public, private_file, public_file)
            loaded_private, loaded_public = load_receiver_keypair(private_file, public_file)

            # Compare underlying key material (handles differ, bytes match)
            assert hb.export_key(loaded_private) == hb.export_key(private)
            assert loaded_public == public

    def test_load_with_password(self):
        hb = get_handle_backend()
        private, public = generate_receiver_keypair()
        password = "test_password_123"

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            save_receiver_keypair(private, public, private_file, public_file, password)
            loaded_private, loaded_public = load_receiver_keypair(
                private_file, public_file, password
            )

            # Compare underlying key material (handles differ, bytes match)
            assert hb.export_key(loaded_private) == hb.export_key(private)
            assert loaded_public == public

    def test_invalid_public_key_raises(self):
        private, public = generate_receiver_keypair()

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            save_receiver_keypair(private, public, private_file, public_file)

            with open(public_file, "wb") as f:
                f.write(b"short")

            with pytest.raises(ValueError, match="Invalid public key length"):
                load_receiver_keypair(private_file, public_file)

    def test_corrupted_private_key_raises(self):
        """Corrupted MEOW_X25519 file should raise on load."""
        private, public = generate_receiver_keypair()

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            save_receiver_keypair(private, public, private_file, public_file, password="pw")

            # Corrupt the ciphertext bytes
            with open(private_file, "rb") as f:
                data = bytearray(f.read())
            data[-1] ^= 0xFF  # flip last byte
            with open(private_file, "wb") as f:
                f.write(data)

            with pytest.raises(Exception):
                load_receiver_keypair(private_file, public_file, password="pw")

    def test_legacy_pem_invalid_type_raises(self):
        """Legacy PEM path rejects non-X25519 keys."""
        # Frozen Ed25519 PEM — wrong key type, used to verify rejection.
        # Generated once with Ed25519PrivateKey.generate() and frozen here
        # to eliminate the cryptography import from test code.
        _ED25519_WRONG_TYPE_PEM = (
            b"-----BEGIN PRIVATE KEY-----\n"
            b"MC4CAQAwBQYDK2VwBCIEIPdy2V7ko8eC/XTbXRDvD4xHGUFRKkvrBf0Ie2wmfvDm\n"
            b"-----END PRIVATE KEY-----\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            with open(private_file, "wb") as f:
                f.write(_ED25519_WRONG_TYPE_PEM)

            _, public = generate_receiver_keypair()
            with open(public_file, "wb") as f:
                f.write(public)

            with pytest.raises(ValueError, match="Unsupported key format"):
                load_receiver_keypair(private_file, public_file)


class TestGenerateReceiverKeysCli:
    def test_generates_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
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
        with tempfile.TemporaryDirectory() as tmpdir:
            generate_receiver_keys_cli(tmpdir, password="explicit_pass")

            private_file = os.path.join(tmpdir, "receiver_private.pem")
            public_file = os.path.join(tmpdir, "receiver_public.key")

            assert os.path.exists(private_file)
            assert os.path.exists(public_file)

    def test_password_mismatch_raises(self, monkeypatch):
        import io
        import sys

        old_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO("pw1\npw2\n")
            with pytest.raises(ValueError, match="Passwords don't match"):
                generate_receiver_keys_cli(".")
        finally:
            sys.stdin = old_stdin

    def test_getpass_path(self, monkeypatch):
        import sys
        import getpass as gp

        with tempfile.TemporaryDirectory() as tmpdir:
            monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
            monkeypatch.setattr(gp, "getpass", lambda _prompt: "pw")

            generate_receiver_keys_cli(tmpdir)

            private_file = os.path.join(tmpdir, "receiver_private.pem")
            public_file = os.path.join(tmpdir, "receiver_public.key")

            assert os.path.exists(private_file)
            assert os.path.exists(public_file)


class TestForwardSecrecyIntegration:
    def test_complete_key_exchange(self):
        receiver_private, receiver_public = generate_receiver_keypair()
        sender_keys = generate_ephemeral_keypair()
        salt = secrets.token_bytes(16)
        password = "shared_password"

        sender_secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            password,
            salt,
        )

        assert len(sender_secret) == 32

    def test_save_load_roundtrip(self):
        hb = get_handle_backend()
        private, public = generate_receiver_keypair()
        password = "roundtrip_password"

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "test_private.pem")
            public_file = os.path.join(tmpdir, "test_public.key")

            save_receiver_keypair(private, public, private_file, public_file, password)

            loaded_private, loaded_public = load_receiver_keypair(
                private_file, public_file, password
            )

            # Compare underlying key material (handles differ, bytes match)
            assert hb.export_key(loaded_private) == hb.export_key(private)
            assert loaded_public == public

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
    def test_empty_password(self):
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)

        secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "",
            salt,
        )

        assert len(secret) == 32

    def test_unicode_password(self):
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)

        secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "密码🔐",
            salt,
        )

        assert len(secret) == 32

    def test_long_password(self):
        sender_keys = generate_ephemeral_keypair()
        receiver_private, receiver_public = generate_receiver_keypair()
        salt = secrets.token_bytes(16)

        secret = derive_shared_secret(
            sender_keys.ephemeral_private,
            receiver_public,
            "a" * 10000,
            salt,
        )

        assert len(secret) == 32
