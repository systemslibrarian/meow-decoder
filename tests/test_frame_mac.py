#!/usr/bin/env python3
"""Tests for meow_decoder.frame_mac."""

import pytest

pytestmark = [pytest.mark.security, pytest.mark.crypto]

import runpy
import secrets

from meow_decoder import frame_mac


def test_derive_frame_master_key_deterministic():
    master = b"m" * 32
    salt = b"s" * 16

    key1 = frame_mac.derive_frame_master_key(master, salt)
    key2 = frame_mac.derive_frame_master_key(master, salt)

    assert key1 == key2
    assert len(key1) == 32


def test_derive_frame_master_key_legacy():
    key = frame_mac.derive_frame_master_key_legacy("pw", b"s" * 16)
    assert len(key) == 32


def test_derive_frame_key_unique():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    key1 = frame_mac.derive_frame_key(master, 1, salt)
    key2 = frame_mac.derive_frame_key(master, 2, salt)

    assert key1 != key2


def test_compute_verify_mac():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    data = b"frame-data"

    mac = frame_mac.compute_frame_mac(data, master, 0, salt)
    assert len(mac) == frame_mac.MAC_SIZE

    assert frame_mac.verify_frame_mac(data, mac, master, 0, salt) is True
    assert frame_mac.verify_frame_mac(data, mac, master, 1, salt) is False
    assert frame_mac.verify_frame_mac(data, mac + b"x", master, 0, salt) is False


def test_verify_frame_mac_bad_length():
    assert frame_mac.verify_frame_mac(b"data", b"", b"k" * 32, 0, b"s" * 16) is False


def test_pack_unpack_frame_with_mac():
    master = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    data = b"payload"

    packed = frame_mac.pack_frame_with_mac(data, master, 5, salt)
    valid, out = frame_mac.unpack_frame_with_mac(packed, master, 5, salt)
    assert valid is True
    assert out == data

    valid, out = frame_mac.unpack_frame_with_mac(packed, master, 6, salt)
    assert valid is False
    assert out == b""

    tampered = packed[: frame_mac.MAC_SIZE] + b"TAMPER" + packed[frame_mac.MAC_SIZE + 6 :]
    valid, out = frame_mac.unpack_frame_with_mac(tampered, master, 5, salt)
    assert valid is False
    assert out == b""


def test_unpack_frame_with_mac_short():
    valid, out = frame_mac.unpack_frame_with_mac(b"", b"k" * 32, 0, b"s" * 16)
    assert valid is False
    assert out == b""


def test_frame_mac_stats():
    stats = frame_mac.FrameMACStats()
    assert stats.success_rate() == 0.0

    stats.record_valid()
    stats.record_invalid()
    assert stats.total_frames == 2
    assert stats.valid_frames == 1
    assert stats.invalid_frames == 1
    assert stats.injection_attempts == 1
    assert "Success rate" in stats.report()

    stats.record_valid()
    assert stats.success_rate() == 2 / 3


def test_frame_mac_main_runs():
    runpy.run_module("meow_decoder.frame_mac", run_name="__main__")

# --- Merged from test_coverage_boost_remaining.py ---

# =====================================================
# frame_mac.py coverage
# =====================================================
class TestFrameMac:
    def test_pack_unpack_frame_mac(self):
        """Test frame MAC pack/unpack roundtrip."""
        from meow_decoder.frame_mac import pack_frame_with_mac, unpack_frame_with_mac
        import secrets

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"Test frame data for MAC verification"

        packed = pack_frame_with_mac(data, master_key, 0, salt)
        assert len(packed) > len(data)

        # Unpack returns (is_valid, data)
        valid, unpacked = unpack_frame_with_mac(packed, master_key, 0, salt)
        assert valid is True
        assert unpacked == data

    def test_pack_frame_mac_different_indices(self):
        """Different frame indices produce different MACs."""
        from meow_decoder.frame_mac import pack_frame_with_mac
        import secrets

        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        data = b"Same data different index"

        packed0 = pack_frame_with_mac(data, master_key, 0, salt)
        packed1 = pack_frame_with_mac(data, master_key, 1, salt)
        assert packed0 != packed1


# =====================================================
# quantum_mixer.py coverage
# =====================================================

