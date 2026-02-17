#!/usr/bin/env python3
"""Coverage tests for forward_secrecy_x25519.py (target 95%+)."""

import os

import pytest
import runpy
import meow_crypto_rs

from meow_decoder.forward_secrecy_x25519 import (
    EphemeralKeyPair,
    derive_hybrid_key,
    encrypt_with_forward_secrecy,
    decrypt_with_forward_secrecy,
)


def test_ephemeral_keypair_generate_and_public_bytes():
    pair = EphemeralKeyPair.generate()
    public_bytes = pair.public_bytes()
    assert isinstance(public_bytes, bytes)
    assert len(public_bytes) == 32


def test_derive_hybrid_key_password_only(monkeypatch):
    monkeypatch.setenv("MEOW_TEST_MODE", "1")
    key = derive_hybrid_key("password", b"1" * 16, shared_secret=None)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_derive_hybrid_key_with_shared_secret(monkeypatch):
    monkeypatch.setenv("MEOW_TEST_MODE", "1")
    key = derive_hybrid_key("password", b"2" * 16, shared_secret=b"s" * 32)
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_encrypt_decrypt_forward_secrecy_roundtrip(monkeypatch):
    monkeypatch.setenv("MEOW_TEST_MODE", "1")
    receiver_private_bytes, receiver_public_bytes = meow_crypto_rs.x25519_generate_keypair()

    plaintext = b"hello forward secrecy"

    cipher, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
        plaintext, "password", receiver_public_bytes
    )

    decrypted = decrypt_with_forward_secrecy(
        cipher,
        "password",
        salt,
        nonce,
        ephemeral_pub,
        receiver_private_bytes,
        orig_len=len(plaintext),
    )

    assert decrypted == plaintext


def test_encrypt_decrypt_password_only_roundtrip(monkeypatch):
    monkeypatch.setenv("MEOW_TEST_MODE", "1")
    plaintext = b"password only"
    cipher, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(plaintext, "password", None)

    assert ephemeral_pub == b""

    decrypted = decrypt_with_forward_secrecy(
        cipher, "password", salt, nonce, ephemeral_pub, None, orig_len=len(plaintext)
    )

    assert decrypted == plaintext


def test_decrypt_requires_receiver_key(monkeypatch):
    monkeypatch.setenv("MEOW_TEST_MODE", "1")
    plaintext = b"data"
    _, receiver_public_bytes = meow_crypto_rs.x25519_generate_keypair()

    cipher, salt, nonce, ephemeral_pub = encrypt_with_forward_secrecy(
        plaintext, "password", receiver_public_bytes
    )

    with pytest.raises(ValueError):
        decrypt_with_forward_secrecy(
            cipher, "password", salt, nonce, ephemeral_pub, None, orig_len=len(plaintext)
        )


def test_module_main_runs():
    runpy.run_module("meow_decoder.forward_secrecy_x25519", run_name="__main__")
