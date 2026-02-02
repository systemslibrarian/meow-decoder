#!/usr/bin/env python3
"""
🔐 Forward Secrecy Manager Tests
"""

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


def test_block_key_determinism_and_uniqueness():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fs = ForwardSecrecyManager(master, salt, enable_ratchet=False)

    k1 = fs.derive_block_key(0)
    k2 = fs.derive_block_key(0)
    k3 = fs.derive_block_key(1)

    assert k1 == k2
    assert k1 != k3


def test_encrypt_decrypt_block_roundtrip():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fs = ForwardSecrecyManager(master, salt, enable_ratchet=False)

    data = b"block-data-123"
    nonce, ct = fs.encrypt_block(data, block_id=0)
    pt = fs.decrypt_block(ct, nonce, block_id=0)

    assert pt == data


def test_ratchet_advances_over_interval():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fs = ForwardSecrecyManager(master, salt, enable_ratchet=True, ratchet_interval=2)

    fs.derive_block_key(0)
    fs.derive_block_key(2)
    fs.derive_block_key(4)

    assert fs.ratchet_state.counter >= 2


def test_ratchet_state_roundtrip():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fs = ForwardSecrecyManager(master, salt, enable_ratchet=True, ratchet_interval=3)

    key_before = fs.derive_block_key(9)
    state_bytes = fs.get_ratchet_state_for_manifest()

    restored = ForwardSecrecyManager.from_ratchet_state(master, salt, state_bytes, ratchet_interval=3)
    key_after = restored.derive_block_key(9)

    assert key_before == key_after


def test_pack_unpack_extension():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fs = ForwardSecrecyManager(master, salt, enable_ratchet=True, ratchet_interval=5)

    packed = pack_forward_secrecy_extension(fs)
    ext_data = packed[3:]

    ratchet_enabled, interval, state = unpack_forward_secrecy_extension(ext_data)

    assert ratchet_enabled is True
    assert interval == 5
    assert state is not None


def test_pack_extension_no_ratchet_state():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fs = ForwardSecrecyManager(master, salt, enable_ratchet=False)

    packed = pack_forward_secrecy_extension(fs)
    # ext_type + length + flags/interval
    assert packed[0] == 0x01
    ratchet_enabled, interval, state = unpack_forward_secrecy_extension(packed[3:])
    assert ratchet_enabled is False
    assert interval == 0
    assert state is None


def test_unpack_extension_invalid_length():
    with pytest.raises(ValueError, match="too short"):
        unpack_forward_secrecy_extension(b"\x00")


def test_from_ratchet_state_invalid_length():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    with pytest.raises(ValueError, match="Invalid ratchet state length"):
        ForwardSecrecyManager.from_ratchet_state(master, salt, b"short")


def test_from_ratchet_state_none():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fs = ForwardSecrecyManager.from_ratchet_state(master, salt, None)
    assert fs.enable_ratchet is False


def test_cleanup_clears_cache():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fs = ForwardSecrecyManager(master, salt, enable_ratchet=False)
    fs.derive_block_key(0)
    assert fs._key_cache
    fs.cleanup()
    assert fs._key_cache == {}


def test_invalid_master_key_and_salt_lengths():
    with pytest.raises(ValueError, match="Master key must be 32 bytes"):
        ForwardSecrecyManager(b"short", secrets.token_bytes(16))
    with pytest.raises(ValueError, match="Salt must be 16 bytes"):
        ForwardSecrecyManager(secrets.token_bytes(32), b"short")


def test_ratchet_state_post_init_length_check():
    with pytest.raises(ValueError, match="Chain key must be 32 bytes"):
        RatchetState(chain_key=b"short")


def test_get_ratchet_state_none_when_disabled():
    fs = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16), enable_ratchet=False)
    assert fs.get_ratchet_state_for_manifest() is None


def test_cleanup_with_ratchet_state():
    fs = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16), enable_ratchet=True)
    fs.derive_block_key(0)
    fs.cleanup()
    assert fs._key_cache == {}


def test_create_forward_secrecy_encoder_decoder():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    enc = create_forward_secrecy_encoder(master, salt, enable_ratchet=True, ratchet_interval=7)
    state = enc.get_ratchet_state_for_manifest()

    dec = create_forward_secrecy_decoder(master, salt, ratchet_state_bytes=state, ratchet_interval=7)
    assert dec.derive_block_key(3) == enc.derive_block_key(3)
