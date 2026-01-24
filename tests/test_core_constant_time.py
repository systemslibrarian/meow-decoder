import pytest

from meow_decoder.constant_time import (
    constant_time_compare,
    secure_memory,
    secure_zero_memory,
    timing_safe_equal_with_delay,
    equalize_timing,
)


def test_constant_time_compare_basic():
    assert constant_time_compare(b"abc", b"abc") is True
    assert constant_time_compare(b"abc", b"abd") is False


def test_secure_zero_memory_bytearray():
    buf = bytearray(b"secret")
    secure_zero_memory(buf)
    assert buf == bytearray(b"\x00" * 6)


def test_secure_memory_context_zeros_after_exit():
    original = b"super_secret_password"
    with secure_memory(original) as protected:
        assert bytes(protected) == original
        protected[0] ^= 0xFF
        assert bytes(protected) != original

    # Buffer should be zeroed by the context manager
    assert bytes(protected) == b"\x00" * len(original)


def test_equalize_timing_does_not_raise():
    # It may sleep, but should not raise.
    equalize_timing(operation_time=0.0, target_time=0.0)


def test_timing_safe_equal_with_delay_returns_bool_fast():
    # Keep delays tiny so the test stays fast.
    out = timing_safe_equal_with_delay(b"a", b"a", min_delay_ms=0, max_delay_ms=1)
    assert isinstance(out, bool)
