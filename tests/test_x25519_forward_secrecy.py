#!/usr/bin/env python3
"""Tests for meow_decoder.x25519_forward_secrecy.
Target: 95%+ branch coverage
"""

import os
import secrets
import tempfile

import pytest

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
    def test_create_with_all_fields(self):
        keys = ForwardSecrecyKeys(
            ephemeral_private=b"p" * 32,
            ephemeral_public=b"P" * 32,
            receiver_public=b"R" * 32,
        )
        assert keys.ephemeral_private == b"p" * 32
        assert keys.ephemeral_public == b"P" * 32
        assert keys.receiver_public == b"R" * 32

    def test_create_without_receiver_public(self):
        keys = ForwardSecrecyKeys(
            ephemeral_private=b"p" * 32,
            ephemeral_public=b"P" * 32,
        )
        assert keys.receiver_public is None


class TestGenerateEphemeralKeypair:
    def test_returns_forward_secrecy_keys(self):
        keys = generate_ephemeral_keypair()
        assert isinstance(keys, ForwardSecrecyKeys)

    def test_private_key_32_bytes(self):
        keys = generate_ephemeral_keypair()
        assert len(keys.ephemeral_private) == 32

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

    def test_secure_zero_exception_ignored(self, monkeypatch):
        import meow_decoder.x25519_forward_secrecy as xfs

        class _Backend:
            def x25519_exchange(self, _priv, _pub):
                return b"\x01" * 32

            def derive_key_hkdf(self, _combined, _salt, _info):
                return b"\x02" * 32

            def secure_zero(self, _buf):
                raise RuntimeError("secure_zero failed")

        monkeypatch.setattr(xfs, "get_default_backend", lambda: _Backend())

        secret = xfs.derive_shared_secret(b"a" * 32, b"b" * 32, "pw", b"c" * 16)
        assert secret == b"\x02" * 32


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

    def test_private_key_32_bytes(self):
        private, public = generate_receiver_keypair()
        assert len(private) == 32

    def test_public_key_32_bytes(self):
        private, public = generate_receiver_keypair()
        assert len(public) == 32

    def test_unique_each_call(self):
        kp1 = generate_receiver_keypair()
        kp2 = generate_receiver_keypair()
        assert kp1[0] != kp2[0]
        assert kp1[1] != kp2[1]


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
            # New MEOW_X25519 format: encrypted marker byte is \x02
            assert file_content[:12] == b"MEOW_X25519\x02"
            # Must be longer than header (12) + salt (16) + nonce (12) + raw key (32)
            assert len(file_content) > 72


class TestLoadReceiverKeypair:
    def test_load_without_password(self):
        private, public = generate_receiver_keypair()

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            save_receiver_keypair(private, public, private_file, public_file)
            loaded_private, loaded_public = load_receiver_keypair(private_file, public_file)

            assert loaded_private == private
            assert loaded_public == public

    def test_load_with_password(self):
        private, public = generate_receiver_keypair()
        password = "test_password_123"

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            save_receiver_keypair(private, public, private_file, public_file, password)
            loaded_private, loaded_public = load_receiver_keypair(
                private_file, public_file, password
            )

            assert loaded_private == private
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
        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "private.pem")
            public_file = os.path.join(tmpdir, "public.key")

            # Write a fake PEM that isn't X25519 — use Ed25519 PEM
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from cryptography.hazmat.primitives import serialization

                ed_key = Ed25519PrivateKey.generate()
                pem_data = ed_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                with open(private_file, "wb") as f:
                    f.write(pem_data)

                _, public = generate_receiver_keypair()
                with open(public_file, "wb") as f:
                    f.write(public)

                with pytest.raises(ValueError, match="Loaded key is not X25519PrivateKey"):
                    load_receiver_keypair(private_file, public_file)
            except ImportError:
                pytest.skip("cryptography not installed — legacy PEM test skipped")


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
        private, public = generate_receiver_keypair()
        password = "roundtrip_password"

        with tempfile.TemporaryDirectory() as tmpdir:
            private_file = os.path.join(tmpdir, "test_private.pem")
            public_file = os.path.join(tmpdir, "test_public.key")

            save_receiver_keypair(private, public, private_file, public_file, password)

            loaded_private, loaded_public = load_receiver_keypair(
                private_file, public_file, password
            )

            assert loaded_private == private
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


# --- Merged from test_coverage_boost_extras.py ---


# =====================================================
# forward_secrecy_x25519.py — push from 94.52% higher
# =====================================================
class TestForwardSecrecyX25519Extras:
    """Extra forward_secrecy_x25519 tests for uncovered branches."""

    def test_derive_hybrid_key_basic(self):
        """Test derive_hybrid_key basic roundtrip."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key

        salt = os.urandom(16)
        key = derive_hybrid_key("test_password_long_enough", salt=salt)
        assert len(key) == 32

    def test_derive_hybrid_key_with_shared_secret(self):
        """Test derive_hybrid_key with shared_secret parameter."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key

        salt = os.urandom(16)
        shared_secret = os.urandom(32)
        key = derive_hybrid_key("password_long_enough", salt=salt, shared_secret=shared_secret)
        assert len(key) == 32

    def test_derive_hybrid_key_consistency(self):
        """Same password + salt = same key."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key

        salt = os.urandom(16)
        k1 = derive_hybrid_key("same_password_here", salt=salt)
        k2 = derive_hybrid_key("same_password_here", salt=salt)
        assert k1 == k2

    def test_derive_hybrid_key_different_passwords(self):
        """Different passwords = different keys."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key

        salt = os.urandom(16)
        k1 = derive_hybrid_key("password_alpha_1", salt=salt)
        k2 = derive_hybrid_key("password_beta_22", salt=salt)
        assert k1 != k2


# =====================================================
# crypto.py — push from 95.58% higher
# =====================================================

# --- Merged from test_coverage_boost_remaining.py ---


# =====================================================
# forward_secrecy_x25519.py small gaps
# =====================================================
class TestForwardSecrecyX25519Boost:
    def test_derive_hybrid_key_wrong_salt_length(self):
        """Salt must be 16 bytes."""
        from meow_decoder.forward_secrecy_x25519 import derive_hybrid_key

        with pytest.raises(ValueError, match="16 bytes"):
            derive_hybrid_key("password_long_enough", salt=b"short")


# =====================================================
# multi_secret.py small gaps
# =====================================================
