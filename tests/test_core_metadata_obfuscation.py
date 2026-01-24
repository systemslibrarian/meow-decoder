import secrets
import pytest

from meow_decoder.metadata_obfuscation import add_length_padding, remove_length_padding


def test_length_padding_roundtrip_various_sizes():
    for size in [1, 15, 16, 31, 32, 255, 256, 1023, 1024]:
        raw = secrets.token_bytes(size)
        padded = add_length_padding(raw)
        assert len(padded) >= len(raw)
        unpadded = remove_length_padding(padded)
        assert unpadded == raw


def test_remove_length_padding_rejects_garbage():
    # Not a padded blob; should raise ValueError.
    with pytest.raises(ValueError):
        remove_length_padding(b"not-a-valid-padding-format")
