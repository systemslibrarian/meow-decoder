#!/usr/bin/env python3
"""
🔐 X25519 Forward Secrecy Tests
"""

import io
import os
import sys
import secrets
import tempfile
import pytest

from meow_decoder import x25519_forward_secrecy as xfs


def test_generate_ephemeral_keypair_lengths():
    keys = xfs.generate_ephemeral_keypair()
    assert len(keys.ephemeral_private) == 32
    assert len(keys.ephemeral_public) == 32


def test_derive_shared_secret_symmetric():
    receiver_priv, receiver_pub = xfs.generate_receiver_keypair()
    sender = xfs.generate_ephemeral_keypair()
    salt = secrets.token_bytes(16)

    shared1 = xfs.derive_shared_secret(sender.ephemeral_private, receiver_pub, "pw", salt)
    shared2 = xfs.derive_shared_secret(receiver_priv, sender.ephemeral_public, "pw", salt)

    assert shared1 == shared2
    assert len(shared1) == 32


def test_derive_shared_secret_zeroize_failure(monkeypatch):
    class FakeBackend:
        def x25519_exchange(self, private_key, public_key):
            return b"Z" * 32

        def derive_key_hkdf(self, ikm, salt, info):
            return b"K" * 32

        def secure_zero(self, data):
            raise RuntimeError("zeroize failed")

    monkeypatch.setattr(xfs, "get_default_backend", lambda: FakeBackend())
    salt = secrets.token_bytes(16)
    key = xfs.derive_shared_secret(b"p" * 32, b"P" * 32, "pw", salt)
    assert key == b"K" * 32


def test_derive_shared_secret_invalid_lengths():
    salt = secrets.token_bytes(16)
    with pytest.raises(ValueError):
        xfs.derive_shared_secret(b"short", b"x" * 32, "pw", salt)
    with pytest.raises(ValueError):
        xfs.derive_shared_secret(b"x" * 32, b"short", "pw", salt)
    with pytest.raises(ValueError):
        xfs.derive_shared_secret(b"x" * 32, b"y" * 32, "pw", b"bad")


def test_serialize_deserialize_public_key():
    _, pub = xfs.generate_receiver_keypair()
    assert xfs.serialize_public_key(pub) == pub
    assert xfs.deserialize_public_key(pub) == pub

    with pytest.raises(ValueError):
        xfs.deserialize_public_key(b"short")


def test_save_and_load_receiver_keypair(tmp_path):
    priv, pub = xfs.generate_receiver_keypair()
    priv_path = tmp_path / "receiver_private.pem"
    pub_path = tmp_path / "receiver_public.key"

    xfs.save_receiver_keypair(priv, pub, str(priv_path), str(pub_path), password="pw")
    loaded_priv, loaded_pub = xfs.load_receiver_keypair(str(priv_path), str(pub_path), password="pw")

    assert loaded_pub == pub
    assert loaded_priv == priv


def test_load_receiver_keypair_invalid_public_length(tmp_path):
    priv, pub = xfs.generate_receiver_keypair()
    priv_path = tmp_path / "receiver_private.pem"
    pub_path = tmp_path / "receiver_public.key"

    xfs.save_receiver_keypair(priv, pub, str(priv_path), str(pub_path))
    pub_path.write_bytes(b"short")

    with pytest.raises(ValueError, match="Invalid public key length"):
        xfs.load_receiver_keypair(str(priv_path), str(pub_path))


def test_load_receiver_keypair_wrong_private_type(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_path = tmp_path / "receiver_private.pem"
    pub_path = tmp_path / "receiver_public.key"

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(b"\x00" * 32)

    with pytest.raises(ValueError, match="Loaded key is not X25519PrivateKey"):
        xfs.load_receiver_keypair(str(priv_path), str(pub_path))


def test_generate_receiver_keys_cli_non_interactive(tmp_path, monkeypatch):
    stdin = io.StringIO("pw\npw\n")
    monkeypatch.setattr(sys, "stdin", stdin)

    xfs.generate_receiver_keys_cli(str(tmp_path))

    assert (tmp_path / "receiver_private.pem").exists()
    assert (tmp_path / "receiver_public.key").exists()


def test_generate_receiver_keys_cli_interactive_mismatch(tmp_path, monkeypatch):
    class FakeStdin(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", FakeStdin(""))

    calls = []

    def fake_getpass(prompt):
        calls.append(prompt)
        return "pw1" if len(calls) == 1 else "pw2"

    import getpass as gp
    monkeypatch.setattr(gp, "getpass", fake_getpass)

    with pytest.raises(ValueError, match="Passwords don't match"):
        xfs.generate_receiver_keys_cli(str(tmp_path))
