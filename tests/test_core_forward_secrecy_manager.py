import secrets

from meow_decoder.forward_secrecy import (
    ForwardSecrecyManager,
    pack_forward_secrecy_extension,
    unpack_forward_secrecy_extension,
)


def test_forward_secrecy_per_block_keys_differ():
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    mgr = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)

    k0 = mgr.derive_block_key(0)
    k1 = mgr.derive_block_key(1)
    assert k0 != k1


def test_forward_secrecy_encrypt_decrypt_block_roundtrip():
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    mgr = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=5)

    pt = b"block-data" * 10
    nonce, ct = mgr.encrypt_block(pt, block_id=3)
    out = mgr.decrypt_block(ct, nonce, block_id=3)
    assert out == pt


def test_forward_secrecy_extension_pack_unpack():
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    mgr = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=7)

    ext = pack_forward_secrecy_extension(mgr)
    # First 3 bytes are type+length, ext_data is the remainder
    ext_data = ext[3:]
    enabled, interval, state = unpack_forward_secrecy_extension(ext_data)
    assert enabled is True
    assert interval == 7
    assert state is not None
