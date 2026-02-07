#!/usr/bin/env python3
"""Coverage tests for forward_secrecy_encoder.py (target 95%+)."""

import secrets

from meow_decoder.fountain import Droplet
from meow_decoder.forward_secrecy_encoder import (
    ForwardSecrecyFountainEncoder,
    create_secure_fountain_encoder,
)


class MockFountainEncoder:
    def __init__(self, data, k_blocks, block_size):
        self.data = data
        self.k_blocks = k_blocks
        self.block_size = block_size
        self.counter = 0

    def droplet(self):
        droplet = Droplet(
            seed=self.counter,
            block_indices=[self.counter % self.k_blocks],
            data=b"xor_data_" + str(self.counter).encode(),
        )
        self.counter += 1
        return droplet


def test_forward_secrecy_encoder_generates_secure_droplet():
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    fountain = MockFountainEncoder(b"data", k_blocks=3, block_size=8)

    encoder = ForwardSecrecyFountainEncoder(
        fountain, master_key=master_key, salt=salt, enable_ratchet=False
    )

    droplet = encoder.next_secure_droplet()
    assert droplet.seed == 0
    assert droplet.block_indices == [0]
    assert droplet.encrypted_data != b"xor_data_0"
    assert len(droplet.nonces) == 1

    extension = encoder.get_fs_extension()
    assert isinstance(extension, bytes)
    assert len(extension) > 0

    encoder.cleanup()


def test_create_secure_fountain_encoder_toggle():
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    plain = create_secure_fountain_encoder(
        data=b"data",
        k_blocks=2,
        block_size=8,
        master_key=master_key,
        salt=salt,
        fountain_encoder_class=MockFountainEncoder,
        enable_forward_secrecy=False,
    )
    assert isinstance(plain, MockFountainEncoder)

    wrapped = create_secure_fountain_encoder(
        data=b"data",
        k_blocks=2,
        block_size=8,
        master_key=master_key,
        salt=salt,
        fountain_encoder_class=MockFountainEncoder,
        enable_forward_secrecy=True,
    )
    assert isinstance(wrapped, ForwardSecrecyFountainEncoder)

# --- Merged from test_coverage_boost_remaining.py ---

# =====================================================
# forward_secrecy_encoder.py small gaps
# =====================================================
class TestForwardSecrecyEncoder:
    def test_example_encode_integration(self):
        """Test example_encode_integration returns code string."""
        from meow_decoder.forward_secrecy_encoder import example_encode_integration

        result = example_encode_integration()
        assert isinstance(result, str)
        assert len(result) > 0


# =====================================================
# gif_handler.py small gaps
# =====================================================

