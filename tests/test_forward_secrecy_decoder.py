#!/usr/bin/env python3
"""Coverage tests for forward_secrecy_decoder.py (target 95%+)."""

import secrets

from meow_decoder.forward_secrecy import ForwardSecrecyManager, pack_forward_secrecy_extension
from meow_decoder.forward_secrecy_decoder import (
    ForwardSecrecyFountainDecoder,
    create_secure_fountain_decoder,
    parse_manifest_v3_forward_secrecy,
)


class MockFountainDecoder:
    def __init__(self, k_blocks, block_size):
        self.k_blocks = k_blocks
        self.block_size = block_size
        self.last_droplet = None
        self.complete = False

    def add_droplet(self, droplet):
        self.last_droplet = droplet
        self.complete = True
        return True

    def is_complete(self):
        return self.complete

    def get_data(self):
        return b"decoded_data"


def test_forward_secrecy_decoder_process_secure_droplet():
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    decoder = ForwardSecrecyFountainDecoder(
        MockFountainDecoder(1, 8), master_key=master_key, salt=salt
    )

    manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
    plaintext = b"block_data"
    nonce, ciphertext = manager.encrypt_block(plaintext, block_id=0)

    complete = decoder.process_secure_droplet(
        encrypted_data=ciphertext,
        nonce=nonce,
        block_indices=[0],
        seed=7,
    )

    assert complete is True
    assert decoder.fountain.last_droplet.data == plaintext
    assert decoder.is_complete() is True

    decoder.cleanup()
    manager.cleanup()


def test_parse_manifest_v3_forward_secrecy_paths():
    assert parse_manifest_v3_forward_secrecy(b"") == (False, 100, None)
    assert parse_manifest_v3_forward_secrecy(b"\x02\x00\x00") == (False, 100, None)

    manager = ForwardSecrecyManager(secrets.token_bytes(32), secrets.token_bytes(16))
    extension = pack_forward_secrecy_extension(manager)

    enabled, interval, state = parse_manifest_v3_forward_secrecy(extension)
    assert enabled is False
    assert interval == 0
    assert state is None


def test_create_secure_fountain_decoder_toggle():
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    plain = create_secure_fountain_decoder(
        k_blocks=1,
        block_size=8,
        master_key=master_key,
        salt=salt,
        fountain_decoder_class=MockFountainDecoder,
        enable_forward_secrecy=False,
    )
    assert isinstance(plain, MockFountainDecoder)

    wrapped = create_secure_fountain_decoder(
        k_blocks=1,
        block_size=8,
        master_key=master_key,
        salt=salt,
        fountain_decoder_class=MockFountainDecoder,
        enable_forward_secrecy=True,
    )
    assert isinstance(wrapped, ForwardSecrecyFountainDecoder)
