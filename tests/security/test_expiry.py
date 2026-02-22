"""
Tests for expiry module.

Tests timed content expiry: encode/decode timestamps, check expiry,
self-destruct, policies.
"""

import os
import struct
import time
from pathlib import Path

import pytest

from meow_decoder.expiry import (
    ContentExpiredError,
    ExpiryManager,
    ExpiryPolicy,
    EXPIRY_FIELD_SIZE,
)


class TestEncodeExpiry:
    """Test expiry timestamp encoding."""

    def test_no_expiry(self):
        """TTL=0 should produce all-zero bytes."""
        result = ExpiryManager.encode_expiry(0)
        assert result == b"\x00" * 8

    def test_negative_ttl_is_no_expiry(self):
        """Negative TTL should be treated as no expiry."""
        result = ExpiryManager.encode_expiry(-100)
        assert result == b"\x00" * 8

    def test_positive_ttl_encodes_future_time(self):
        """Positive TTL should encode a future timestamp."""
        before = int(time.time())
        result = ExpiryManager.encode_expiry(3600)
        after = int(time.time())

        ts = struct.unpack(">Q", result)[0]
        assert before + 3600 <= ts <= after + 3600

    def test_encoding_is_8_bytes(self):
        """Result should always be 8 bytes."""
        for ttl in [0, 1, 60, 3600, 86400, 604800]:
            assert len(ExpiryManager.encode_expiry(ttl)) == EXPIRY_FIELD_SIZE

    def test_big_endian(self):
        """Encoding should be big-endian."""
        result = ExpiryManager.encode_expiry(1)
        ts = struct.unpack(">Q", result)[0]
        # Should be close to current time + 1
        assert abs(ts - (time.time() + 1)) < 2


class TestEncodeAbsolute:
    """Test absolute timestamp encoding."""

    def test_zero_is_no_expiry(self):
        result = ExpiryManager.encode_absolute(0)
        assert result == b"\x00" * 8

    def test_specific_timestamp(self):
        ts = 1700000000  # A specific Unix timestamp
        result = ExpiryManager.encode_absolute(ts)
        decoded = struct.unpack(">Q", result)[0]
        assert decoded == ts


class TestDecodeExpiry:
    """Test expiry timestamp decoding."""

    def test_roundtrip(self):
        """Encode then decode should return original timestamp."""
        original = ExpiryManager.encode_expiry(3600)
        decoded = ExpiryManager.decode_expiry(original)
        assert abs(decoded - (time.time() + 3600)) < 2

    def test_no_expiry_decodes_to_zero(self):
        decoded = ExpiryManager.decode_expiry(b"\x00" * 8)
        assert decoded == 0

    def test_wrong_size_raises(self):
        with pytest.raises(ValueError, match="8 bytes"):
            ExpiryManager.decode_expiry(b"\x00" * 4)

    def test_wrong_size_too_long(self):
        with pytest.raises(ValueError, match="8 bytes"):
            ExpiryManager.decode_expiry(b"\x00" * 16)


class TestCheckExpiry:
    """Test expiry checking."""

    def test_no_expiry_always_valid(self):
        """No-expiry content should always be valid."""
        assert ExpiryManager.check_expiry(b"\x00" * 8) is True

    def test_future_expiry_is_valid(self):
        """Content expiring in the future should be valid."""
        expiry = ExpiryManager.encode_expiry(3600)
        assert ExpiryManager.check_expiry(expiry) is True

    def test_past_expiry_is_invalid(self):
        """Content that has expired should be invalid."""
        # Encode a timestamp 100 seconds in the past
        past = int(time.time()) - 100
        expiry = struct.pack(">Q", past)
        assert ExpiryManager.check_expiry(expiry, clock_skew_tolerance=0) is False

    def test_clock_skew_tolerance(self):
        """Slightly expired content within tolerance should still be valid."""
        # Expired 30 seconds ago, but tolerance is 60 seconds
        past = int(time.time()) - 30
        expiry = struct.pack(">Q", past)
        assert ExpiryManager.check_expiry(expiry, clock_skew_tolerance=60) is True

    def test_clock_skew_tolerance_exceeded(self):
        """Content expired beyond tolerance should be invalid."""
        past = int(time.time()) - 120
        expiry = struct.pack(">Q", past)
        assert ExpiryManager.check_expiry(expiry, clock_skew_tolerance=60) is False


class TestTimeRemaining:
    """Test time remaining calculation."""

    def test_no_expiry_returns_none(self):
        result = ExpiryManager.time_remaining(b"\x00" * 8)
        assert result is None

    def test_future_expiry_positive(self):
        expiry = ExpiryManager.encode_expiry(3600)
        remaining = ExpiryManager.time_remaining(expiry)
        assert remaining is not None
        assert 3598 < remaining < 3602

    def test_past_expiry_negative(self):
        past = int(time.time()) - 100
        expiry = struct.pack(">Q", past)
        remaining = ExpiryManager.time_remaining(expiry)
        assert remaining is not None
        assert remaining < 0


class TestIsPermanent:
    """Test permanent content detection."""

    def test_zero_is_permanent(self):
        assert ExpiryManager.is_permanent(b"\x00" * 8) is True

    def test_nonzero_is_not_permanent(self):
        expiry = ExpiryManager.encode_expiry(3600)
        assert ExpiryManager.is_permanent(expiry) is False


class TestNoExpiry:
    """Test no_expiry sentinel."""

    def test_no_expiry_is_zeros(self):
        assert ExpiryManager.no_expiry() == b"\x00" * 8

    def test_no_expiry_is_permanent(self):
        assert ExpiryManager.is_permanent(ExpiryManager.no_expiry()) is True


class TestSelfDestruct:
    """Test secure file destruction."""

    def test_destroy_existing_file(self, tmp_path):
        """Should overwrite and delete an existing file."""
        f = tmp_path / "target.gif"
        f.write_bytes(b"secret" * 1000)
        assert f.exists()

        result = ExpiryManager.self_destruct(f)
        assert result is True
        assert not f.exists()

    def test_destroy_nonexistent_file(self, tmp_path):
        """Should return False for non-existent file."""
        f = tmp_path / "no_such_file.gif"
        assert ExpiryManager.self_destruct(f) is False

    def test_destroy_empty_file(self, tmp_path):
        """Should handle empty files."""
        f = tmp_path / "empty.gif"
        f.write_bytes(b"")
        result = ExpiryManager.self_destruct(f)
        assert result is True
        assert not f.exists()

    def test_custom_passes(self, tmp_path):
        """Should accept custom pass count."""
        f = tmp_path / "multi.gif"
        f.write_bytes(b"X" * 4096)
        result = ExpiryManager.self_destruct(f, passes=5)
        assert result is True
        assert not f.exists()


class TestCheckAndDestroy:
    """Test the combined check + destroy method."""

    def test_valid_content_returns_true(self, tmp_path):
        """Valid content should return True without destroying."""
        f = tmp_path / "valid.gif"
        f.write_bytes(b"valid content")
        expiry = ExpiryManager.encode_expiry(3600)

        result = ExpiryManager.check_and_destroy(expiry, f)
        assert result is True
        assert f.exists()  # File should still be there

    def test_expired_content_raises(self, tmp_path):
        """Expired content should raise ContentExpiredError and destroy file."""
        f = tmp_path / "expired.gif"
        f.write_bytes(b"expired content" * 100)
        past = int(time.time()) - 200
        expiry = struct.pack(">Q", past)

        with pytest.raises(ContentExpiredError, match="expired"):
            ExpiryManager.check_and_destroy(expiry, f, clock_skew_tolerance=0)

        assert not f.exists()  # File should be destroyed

    def test_permanent_content_always_valid(self, tmp_path):
        """Permanent content should never expire."""
        f = tmp_path / "permanent.gif"
        f.write_bytes(b"forever content")
        expiry = ExpiryManager.no_expiry()

        result = ExpiryManager.check_and_destroy(expiry, f)
        assert result is True
        assert f.exists()


class TestExpiryPolicy:
    """Test named expiry policies."""

    def test_ephemeral_is_5_minutes(self):
        assert ExpiryPolicy.EPHEMERAL.ttl_seconds == 300

    def test_short_is_1_hour(self):
        assert ExpiryPolicy.SHORT.ttl_seconds == 3600

    def test_medium_is_24_hours(self):
        assert ExpiryPolicy.MEDIUM.ttl_seconds == 86400

    def test_long_is_7_days(self):
        assert ExpiryPolicy.LONG.ttl_seconds == 604800

    def test_permanent_is_zero(self):
        assert ExpiryPolicy.PERMANENT.ttl_seconds == 0

    def test_get_policy_by_name(self):
        policy = ExpiryManager.get_policy("medium")
        assert policy.ttl_seconds == 86400

    def test_get_policy_case_insensitive(self):
        policy = ExpiryManager.get_policy("EPHEMERAL")
        assert policy.ttl_seconds == 300

    def test_get_policy_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown expiry policy"):
            ExpiryManager.get_policy("nonexistent")

    def test_policy_repr(self):
        repr_str = repr(ExpiryPolicy.EPHEMERAL)
        assert "ephemeral" in repr_str
        assert "300" in repr_str

    def test_policy_with_encode(self):
        """Policies should work with encode_expiry."""
        for policy in [ExpiryPolicy.EPHEMERAL, ExpiryPolicy.SHORT,
                       ExpiryPolicy.MEDIUM, ExpiryPolicy.LONG]:
            expiry = ExpiryManager.encode_expiry(policy.ttl_seconds)
            assert len(expiry) == 8
            assert ExpiryManager.check_expiry(expiry) is True

    def test_permanent_policy_with_encode(self):
        expiry = ExpiryManager.encode_expiry(ExpiryPolicy.PERMANENT.ttl_seconds)
        assert expiry == b"\x00" * 8
        assert ExpiryManager.is_permanent(expiry) is True
