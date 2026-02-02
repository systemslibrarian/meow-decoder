#!/usr/bin/env python3
"""
Tests for meow_decoder.constant_time
Target: 95%+ branch coverage
"""

import ctypes
import os
import secrets
import time

import pytest


# =============================================================================
# constant_time_compare
# =============================================================================

class TestConstantTimeCompare:
    def test_equal_bytes(self):
        from meow_decoder.constant_time import constant_time_compare

        assert constant_time_compare(b"secret", b"secret") is True

    def test_unequal_bytes(self):
        from meow_decoder.constant_time import constant_time_compare

        assert constant_time_compare(b"secret", b"wrong") is False

    def test_different_lengths(self):
        from meow_decoder.constant_time import constant_time_compare

        assert constant_time_compare(b"short", b"much_longer") is False

    def test_empty_strings(self):
        from meow_decoder.constant_time import constant_time_compare

        assert constant_time_compare(b"", b"") is True
        assert constant_time_compare(b"", b"data") is False

    def test_null_bytes(self):
        from meow_decoder.constant_time import constant_time_compare

        assert constant_time_compare(b"a\x00b", b"a\x00b") is True

    def test_random_bytes(self):
        from meow_decoder.constant_time import constant_time_compare

        a = secrets.token_bytes(32)
        b = bytes(a)
        assert constant_time_compare(a, b) is True

    def test_single_byte_strings(self):
        from meow_decoder.constant_time import constant_time_compare

        assert constant_time_compare(b"a", b"a") is True
        assert constant_time_compare(b"a", b"b") is False
        assert constant_time_compare(b"\x00", b"\x00") is True
        assert constant_time_compare(b"\x00", b"\x01") is False


# =============================================================================
# secure_zero_memory
# =============================================================================

class TestSecureZeroMemory:
    def test_zero_bytearray(self):
        from meow_decoder.constant_time import secure_zero_memory

        buf = bytearray(b"sensitive_data")
        secure_zero_memory(buf)
        assert all(b == 0 for b in buf)

    def test_zero_empty_bytearray(self):
        from meow_decoder.constant_time import secure_zero_memory

        buf = bytearray()
        secure_zero_memory(buf)
        assert len(buf) == 0

    def test_zero_ctypes_array(self):
        from meow_decoder.constant_time import secure_zero_memory

        arr = (ctypes.c_char * 4)()
        arr.raw = b"ABCD"
        secure_zero_memory(arr)
        assert bytes(arr) == b"\x00" * 4

    def test_zero_large_bytearray(self):
        from meow_decoder.constant_time import secure_zero_memory

        buf = bytearray(os.urandom(4096))
        secure_zero_memory(buf)
        assert all(b == 0 for b in buf)

    def test_preserves_length(self):
        from meow_decoder.constant_time import secure_zero_memory

        buf = bytearray(b"x" * 128)
        secure_zero_memory(buf)
        assert len(buf) == 128
        assert all(b == 0 for b in buf)

    def test_zero_unsupported_type(self):
        from meow_decoder.constant_time import secure_zero_memory

        secure_zero_memory("immutable")
        secure_zero_memory(b"bytes")

    def test_fallback_when_no_libc(self, monkeypatch):
        import meow_decoder.constant_time as ct

        monkeypatch.setattr(ct, "_libc", None)
        buf = bytearray(b"secret")
        ct.secure_zero_memory(buf)
        assert buf == bytearray(b"\x00" * 6)

    def test_fallback_unsupported_type(self, monkeypatch):
        import meow_decoder.constant_time as ct

        monkeypatch.setattr(ct, "_libc", None)
        ct.secure_zero_memory(b"immutable")

    def test_memset_failure_falls_back(self, monkeypatch):
        import meow_decoder.constant_time as ct

        buf = bytearray(b"secret")

        def _boom(_addr, _val, _size):
            raise OSError("memset failed")

        monkeypatch.setattr(ct.ctypes, "memset", _boom)
        ct.secure_zero_memory(buf)
        assert buf == bytearray(b"\x00" * len(buf))


# =============================================================================
# secure_memory context manager
# =============================================================================

class TestSecureMemory:
    def test_basic_usage(self):
        from meow_decoder.constant_time import secure_memory

        data = b"super_secret"
        with secure_memory(data) as buf:
            assert bytes(buf) == data
        assert bytes(buf) == b"\x00" * len(data)

    def test_modification(self):
        from meow_decoder.constant_time import secure_memory

        data = b"abcdef"
        with secure_memory(data) as buf:
            buf[0] = ord("x")
            assert bytes(buf) != data
        assert bytes(buf) == b"\x00" * len(data)

    def test_empty(self):
        from meow_decoder.constant_time import secure_memory

        with secure_memory(b"") as buf:
            assert len(buf) == 0

    def test_large_data(self):
        from meow_decoder.constant_time import secure_memory

        data = secrets.token_bytes(1024 * 1024)
        with secure_memory(data) as buf:
            assert len(buf) == len(data)

    def test_lock_and_unlock_exceptions(self, monkeypatch):
        import meow_decoder.constant_time as ct

        class _LibcLockFails:
            def mlock(self, *_args, **_kwargs):
                raise OSError("mlock failed")

        class _LibcUnlockFails:
            def mlock(self, *_args, **_kwargs):
                return 0

            def munlock(self, *_args, **_kwargs):
                raise OSError("munlock failed")

        monkeypatch.setattr(ct, "_libc", _LibcLockFails())
        with ct.secure_memory(b"pw") as buf:
            assert bytes(buf) == b"pw"

        monkeypatch.setattr(ct, "_libc", _LibcUnlockFails())
        with ct.secure_memory(b"pw") as buf2:
            assert bytes(buf2) == b"pw"


# =============================================================================
# timing_safe_equal_with_delay
# =============================================================================

class TestTimingSafeEqualWithDelay:
    def test_equal_with_deterministic_delay(self, monkeypatch):
        from meow_decoder.constant_time import timing_safe_equal_with_delay

        sleep_calls = []

        def _sleep(seconds):
            sleep_calls.append(seconds)

        monkeypatch.setattr(time, "sleep", _sleep)
        monkeypatch.setattr(secrets, "randbelow", lambda _n: 0)

        result = timing_safe_equal_with_delay(b"pw", b"pw", min_delay_ms=5, max_delay_ms=5)
        assert result is True
        assert sleep_calls == [0.005, 0.005]

    def test_unequal_with_deterministic_delay(self, monkeypatch):
        from meow_decoder.constant_time import timing_safe_equal_with_delay

        sleep_calls = []

        def _sleep(seconds):
            sleep_calls.append(seconds)

        monkeypatch.setattr(time, "sleep", _sleep)
        monkeypatch.setattr(secrets, "randbelow", lambda _n: 0)

        result = timing_safe_equal_with_delay(b"pw", b"nope", min_delay_ms=2, max_delay_ms=2)
        assert result is False
        assert sleep_calls == [0.002, 0.002]

    def test_returns_bool_fast(self):
        from meow_decoder.constant_time import timing_safe_equal_with_delay

        out = timing_safe_equal_with_delay(b"a", b"a", min_delay_ms=0, max_delay_ms=1)
        assert isinstance(out, bool)

    def test_delay_adds_variance(self):
        from meow_decoder.constant_time import timing_safe_equal_with_delay

        times = []
        for _ in range(5):
            start = time.time()
            timing_safe_equal_with_delay(b"x", b"x", min_delay_ms=1, max_delay_ms=5)
            times.append(time.time() - start)

        assert max(times) > min(times)


# =============================================================================
# equalize_timing
# =============================================================================

class TestEqualizeTiming:
    def test_sleeps_when_needed(self, monkeypatch):
        from meow_decoder.constant_time import equalize_timing

        sleep_calls = []

        def _sleep(seconds):
            sleep_calls.append(seconds)

        monkeypatch.setattr(time, "sleep", _sleep)

        equalize_timing(operation_time=0.02, target_time=0.1)
        assert sleep_calls == [pytest.approx(0.08, rel=1e-3)]

    def test_no_sleep_when_exceeded(self, monkeypatch):
        from meow_decoder.constant_time import equalize_timing

        sleep_calls = []

        def _sleep(seconds):
            sleep_calls.append(seconds)

        monkeypatch.setattr(time, "sleep", _sleep)

        equalize_timing(operation_time=0.2, target_time=0.1)
        assert sleep_calls == []

    def test_exact_time_no_sleep(self, monkeypatch):
        from meow_decoder.constant_time import equalize_timing

        sleep_calls = []

        def _sleep(seconds):
            sleep_calls.append(seconds)

        monkeypatch.setattr(time, "sleep", _sleep)
        equalize_timing(operation_time=0.1, target_time=0.1)
        assert sleep_calls == []

    def test_zero_target(self, monkeypatch):
        from meow_decoder.constant_time import equalize_timing

        sleep_calls = []

        def _sleep(seconds):
            sleep_calls.append(seconds)

        monkeypatch.setattr(time, "sleep", _sleep)
        equalize_timing(operation_time=0.01, target_time=0.0)
        assert sleep_calls == []


# =============================================================================
# SecureBuffer
# =============================================================================

class TestSecureBuffer:
    def test_creation(self):
        from meow_decoder.constant_time import SecureBuffer

        with SecureBuffer(16) as buf:
            assert len(buf.buffer) == 16
            assert buf.size == 16
            assert isinstance(buf.locked, bool)

    def test_write_and_read(self):
        from meow_decoder.constant_time import SecureBuffer

        with SecureBuffer(32) as buf:
            buf.write(b"test_data")
            assert buf.read(9) == b"test_data"

    def test_write_with_offset(self):
        from meow_decoder.constant_time import SecureBuffer

        with SecureBuffer(16) as buf:
            buf.write(b"hello", offset=5)
            assert buf.read(5, offset=5) == b"hello"

    def test_read_all(self):
        from meow_decoder.constant_time import SecureBuffer

        with SecureBuffer(8) as buf:
            buf.write(b"12345678")
            assert buf.read() == b"12345678"

    def test_read_with_offset(self):
        from meow_decoder.constant_time import SecureBuffer

        with SecureBuffer(16) as buf:
            buf.write(b"0123456789")
            assert buf.read(4, offset=5) == b"5678"

    def test_write_too_large(self):
        from meow_decoder.constant_time import SecureBuffer

        with SecureBuffer(4) as buf:
            with pytest.raises(ValueError, match="too large"):
                buf.write(b"toolong")

    def test_context_manager_exit(self):
        from meow_decoder.constant_time import SecureBuffer

        buf = SecureBuffer(8)
        buf.__enter__()
        buf.write(b"data")
        buf.__exit__(None, None, None)

    def test_lock_exceptions(self, monkeypatch):
        import meow_decoder.constant_time as ct

        class _LibcMlockRaises:
            def mlock(self, *_args, **_kwargs):
                raise OSError("mlock failed")

        class _LibcUnlockRaises:
            def mlock(self, *_args, **_kwargs):
                return 0

            def munlock(self, *_args, **_kwargs):
                raise OSError("munlock failed")

        monkeypatch.setattr(ct, "_libc", _LibcMlockRaises())
        buf = ct.SecureBuffer(8)
        buf.write(b"hi")
        assert buf.read(2) == b"hi"
        buf.__del__()

        monkeypatch.setattr(ct, "_libc", _LibcUnlockRaises())
        buf2 = ct.SecureBuffer(8)
        buf2.write(b"hello")
        buf2.locked = True
        buf2.__del__()


# =============================================================================
# _get_libc platform detection
# =============================================================================

class TestLibcLoading:
    def test_get_libc(self):
        from meow_decoder.constant_time import _get_libc

        libc = _get_libc()
        assert libc is None or hasattr(libc, "mlock")

    def test_platform_branches(self, monkeypatch):
        import meow_decoder.constant_time as ct

        monkeypatch.setattr(ct.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(ct.ctypes, "CDLL", lambda _name: object())
        assert ct._get_libc() is not None

        monkeypatch.setattr(ct.platform, "system", lambda: "Windows")
        monkeypatch.setattr(ct.ctypes, "CDLL", lambda _name: object())
        assert ct._get_libc() is not None

        monkeypatch.setattr(ct.platform, "system", lambda: "Plan9")
        assert ct._get_libc() is None

        monkeypatch.setattr(ct.platform, "system", lambda: "Darwin")

        def _boom(_name):
            raise OSError("nope")

        monkeypatch.setattr(ct.ctypes, "CDLL", _boom)
        assert ct._get_libc() is None

    def test_libc_module_variable(self):
        from meow_decoder import constant_time

        assert constant_time._libc is None or callable(getattr(constant_time._libc, "mlock", None))
