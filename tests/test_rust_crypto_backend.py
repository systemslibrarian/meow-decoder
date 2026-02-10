"""Tests for the Rust crypto backend (meow_crypto_rs)."""

import secrets

import pytest

import meow_crypto_rs


def test_argon2id_key_derivation():
    password = b"correct horse battery staple"
    salt = secrets.token_bytes(16)
    key = meow_crypto_rs.derive_key_argon2id(password, salt, 1024, 1, 1, 32)
    assert isinstance(key, (bytes, bytearray))
    assert len(key) == 32


def test_argon2id_invalid_salt():
    with pytest.raises(ValueError, match="Salt must be exactly 16 bytes"):
        meow_crypto_rs.derive_key_argon2id(b"pw", b"short", 1024, 1, 1, 32)


def test_hkdf_extract_expand_roundtrip():
    ikm = b"input material"
    salt = b"salt"
    info = b"info"

    prk = meow_crypto_rs.hkdf_extract(salt, ikm)
    okm = meow_crypto_rs.hkdf_expand(prk, info, 42)
    assert len(okm) == 42

    okm2 = meow_crypto_rs.derive_key_hkdf(ikm, salt, info, 42)
    assert okm == okm2


def test_aes_gcm_encrypt_decrypt_roundtrip():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    plaintext = b"meow secret data"
    aad = b"aad"

    cipher = meow_crypto_rs.aes_gcm_encrypt(key, nonce, plaintext, aad)
    decrypted = meow_crypto_rs.aes_gcm_decrypt(key, nonce, cipher, aad)
    assert decrypted == plaintext

    with pytest.raises(ValueError, match="Decryption failed"):
        meow_crypto_rs.aes_gcm_decrypt(key, nonce, cipher, b"wrong")


def test_hmac_sha256_verify():
    key = b"key"
    data = b"message"

    tag = meow_crypto_rs.hmac_sha256(key, data)
    assert meow_crypto_rs.hmac_sha256_verify(key, data, tag) is True

    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0xFF
    assert meow_crypto_rs.hmac_sha256_verify(key, data, bytes(bad_tag)) is False


def test_sha256():
    digest = meow_crypto_rs.sha256(b"abc")
    assert len(digest) == 32


def test_x25519_key_exchange():
    priv_a, pub_a = meow_crypto_rs.x25519_generate_keypair()
    priv_b, pub_b = meow_crypto_rs.x25519_generate_keypair()

    shared_a = meow_crypto_rs.x25519_exchange(priv_a, pub_b)
    shared_b = meow_crypto_rs.x25519_exchange(priv_b, pub_a)
    assert shared_a == shared_b

    derived_pub = meow_crypto_rs.x25519_public_from_private(priv_a)
    assert derived_pub == pub_a


def test_constant_time_compare():
    assert meow_crypto_rs.constant_time_compare(b"abc", b"abc") is True
    assert meow_crypto_rs.constant_time_compare(b"abc", b"abd") is False
    assert meow_crypto_rs.constant_time_compare(b"abc", b"abcd") is False


def test_secure_zero_and_random():
    data = bytearray(b"secret")
    meow_crypto_rs.secure_zero(data)
    assert data == b"\x00" * len(data)

    rnd = meow_crypto_rs.secure_random(24)
    assert isinstance(rnd, (bytes, bytearray))
    assert len(rnd) == 24


def test_backend_info():
    info = meow_crypto_rs.backend_info()
    assert "meow_crypto_rs" in info


def test_mlkem_roundtrip():
    if not hasattr(meow_crypto_rs, "mlkem768_keygen"):
        pytest.skip("meow_crypto_rs built without pq feature (mlkem768 not available)")
    sk, pk = meow_crypto_rs.mlkem768_keygen()
    ss1, ct = meow_crypto_rs.mlkem768_encapsulate(pk)
    ss2 = meow_crypto_rs.mlkem768_decapsulate(sk, ct)
    assert ss1 == ss2


def test_yubikey_derive_key_error():
    try:
        meow_crypto_rs.yubikey_derive_key(b"pw", secrets.token_bytes(16))
    except ValueError as exc:
        message = str(exc)
        assert (
            "YubiKey support not enabled" in message
            or "YubiKey connection failed" in message
            or "YubiKey derivation failed" in message
        )
    else:
        pytest.skip("YubiKey available; skipping error-path check")
