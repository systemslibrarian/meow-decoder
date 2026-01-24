import secrets

from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac, FrameMACStats


def test_frame_mac_valid_roundtrip():
    key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    payload = b"hello"

    packed = pack_frame_with_mac(payload, key, frame_index=7, salt=salt)
    valid, out = unpack_frame_with_mac(packed, key, frame_index=7, salt=salt)

    assert valid is True
    assert out == payload


def test_frame_mac_tamper_detected():
    key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    payload = b"hello"

    packed = bytearray(pack_frame_with_mac(payload, key, frame_index=1, salt=salt))
    packed[-1] ^= 0x01

    valid, out = unpack_frame_with_mac(bytes(packed), key, frame_index=1, salt=salt)
    assert valid is False
    # Implementation currently returns empty bytes on failure; treat any falsy payload as rejected.
    assert not out


def test_frame_mac_stats():
    s = FrameMACStats()
    s.record_valid()
    s.record_invalid()
    assert s.valid_frames == 1
    assert s.invalid_frames == 1
    assert 0.0 < s.success_rate() < 1.0
