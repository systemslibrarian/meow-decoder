#!/usr/bin/env python3
"""
⏱️ Constant-Time Operations Tests

Covers constant_time.py branches:
- libc detection
- secure zeroing paths
- secure_memory context
- timing equalization
- SecureBuffer behavior
"""

import ctypes
import types
import time
import pytest

from meow_decoder import constant_time


def test_constant_time_compare_true_false():
    assert constant_time.constant_time_compare(b"abc", b"abc") is True
    assert constant_time.constant_time_compare(b"abc", b"abd") is False


def test_get_libc_branches(monkeypatch):
    # Force Darwin branch
    monkeypatch.setattr(constant_time.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(constant_time.ctypes, "CDLL", lambda name: object())
    assert constant_time._get_libc() is not None

    # Force Windows branch
    monkeypatch.setattr(constant_time.platform, "system", lambda: "Windows")
    monkeypatch.setattr(constant_time.ctypes, "CDLL", lambda name: object())
    assert constant_time._get_libc() is not None

    # Unknown system -> None
    monkeypatch.setattr(constant_time.platform, "system", lambda: "UnknownOS")
    assert constant_time._get_libc() is None

    # CDLL failure path
    monkeypatch.setattr(constant_time.platform, "system", lambda: "Linux")
    def _raise(_):
        raise OSError("no libc")
    monkeypatch.setattr(constant_time.ctypes, "CDLL", _raise)
    assert constant_time._get_libc() is None


def test_secure_zero_memory_fallback_bytearray(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", None)
    buf = bytearray(b"secret")
    constant_time.secure_zero_memory(buf)
    assert buf == b"\x00" * len(buf)


def test_secure_zero_memory_ctypes_array(monkeypatch):
    # Provide fake libc and let ctypes.memset execute
    monkeypatch.setattr(constant_time, "_libc", object())
    cbuf = ctypes.create_string_buffer(b"secret")
    constant_time.secure_zero_memory(cbuf)
    assert cbuf.raw == b"\x00" * len(cbuf.raw)


def test_secure_zero_memory_memset_exception(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", object())
    monkeypatch.setattr(constant_time.ctypes, "memset", lambda *args, **kwargs: (_ for _ in ()).throw(Exception("boom")))
    buf = bytearray(b"secret")
    constant_time.secure_zero_memory(buf)
    assert buf == b"\x00" * len(buf)


def test_secure_zero_memory_memset_exception_ctypes(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", object())
    monkeypatch.setattr(constant_time.ctypes, "memset", lambda *args, **kwargs: (_ for _ in ()).throw(Exception("boom")))
    cbuf = ctypes.create_string_buffer(b"secret")
    constant_time.secure_zero_memory(cbuf)


def test_secure_zero_memory_empty_buffer(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", object())
    zero_array = (ctypes.c_char * 0)()
    constant_time.secure_zero_memory(zero_array)


def test_secure_zero_memory_empty_bytearray(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", object())
    buf = bytearray()
    constant_time.secure_zero_memory(buf)


def test_secure_zero_memory_unsupported_with_libc(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", object())
    constant_time.secure_zero_memory(object())


def test_secure_zero_memory_unsupported_type(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", None)
    # Should be a no-op with unsupported type
    constant_time.secure_zero_memory(b"immutable")


def test_secure_memory_context_zeroes(monkeypatch):
    class FakeLibc:
        def __init__(self):
            self.mlock_called = False
            self.munlock_called = False

        def mlock(self, addr, length):
            self.mlock_called = True
            return 0

        def munlock(self, addr, length):
            self.munlock_called = True
            return 0

    fake = FakeLibc()
    monkeypatch.setattr(constant_time, "_libc", fake)
    buf_ref = None
    with constant_time.secure_memory(b"topsecret") as buf:
        buf_ref = buf
        assert bytes(buf[:3]) == b"top"
    assert buf_ref == b"\x00" * len(buf_ref)
    assert fake.mlock_called is True
    assert fake.munlock_called is True


def test_secure_memory_without_libc(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", None)
    with constant_time.secure_memory(b"data") as buf:
        assert buf[:4] == b"data"


def test_secure_memory_mlock_exception(monkeypatch):
    class FakeLibc:
        def mlock(self, addr, length):
            raise RuntimeError("mlock failed")

    monkeypatch.setattr(constant_time, "_libc", FakeLibc())
    with constant_time.secure_memory(b"data") as buf:
        assert buf[:4] == b"data"


def test_secure_memory_munlock_exception(monkeypatch):
    class FakeLibc:
        def mlock(self, addr, length):
            return 0

        def munlock(self, addr, length):
            raise RuntimeError("munlock failed")

    monkeypatch.setattr(constant_time, "_libc", FakeLibc())
    with constant_time.secure_memory(b"data") as buf:
        assert buf[:4] == b"data"


def test_timing_safe_equal_with_delay(monkeypatch):
    calls = []
    monkeypatch.setattr(constant_time.time, "sleep", lambda s: calls.append(s))
    assert constant_time.timing_safe_equal_with_delay(b"a", b"a", min_delay_ms=1, max_delay_ms=1) is True
    assert len(calls) == 2


def test_equalize_timing(monkeypatch):
    calls = []
    monkeypatch.setattr(constant_time.time, "sleep", lambda s: calls.append(s))
    constant_time.equalize_timing(0.01, target_time=0.02)
    assert calls

    calls.clear()
    constant_time.equalize_timing(0.05, target_time=0.02)
    assert calls == []


def test_secure_buffer_read_write_and_overflow(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", None)
    buf = constant_time.SecureBuffer(4)
    buf.write(b"ab")
    assert buf.read(2) == b"ab"
    with pytest.raises(ValueError):
        buf.write(b"toolong")


def test_secure_buffer_context_manager(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", None)
    with constant_time.SecureBuffer(4) as buf:
        buf.write(b"ab")
        assert buf.read(2) == b"ab"


def test_secure_buffer_with_mlock(monkeypatch):
    class FakeLibc:
        def __init__(self):
            self.mlock_called = False
            self.munlock_called = False

        def mlock(self, addr, length):
            self.mlock_called = True
            return 0

        def munlock(self, addr, length):
            self.munlock_called = True
            return 0

    fake = FakeLibc()
    monkeypatch.setattr(constant_time, "_libc", fake)
    buf = constant_time.SecureBuffer(4)
    buf.write(b"ab")
    assert buf.read(2) == b"ab"
    buf.__del__()
    assert fake.mlock_called is True
    assert fake.munlock_called is True


def test_secure_buffer_mlock_exception_and_read_none(monkeypatch):
    class FakeLibc:
        def mlock(self, addr, length):
            raise RuntimeError("mlock failed")

    monkeypatch.setattr(constant_time, "_libc", FakeLibc())
    buf = constant_time.SecureBuffer(4)
    buf.write(b"ab")
    assert buf.read() == b"ab\x00\x00"


def test_secure_buffer_del_without_buffer(monkeypatch):
    monkeypatch.setattr(constant_time, "_libc", None)
    buf = constant_time.SecureBuffer(4)
    del buf.buffer
    buf.__del__()


def test_secure_buffer_munlock_exception(monkeypatch):
    class FakeLibc:
        def mlock(self, addr, length):
            return 0

        def munlock(self, addr, length):
            raise RuntimeError("munlock failed")

    monkeypatch.setattr(constant_time, "_libc", FakeLibc())
    buf = constant_time.SecureBuffer(4)
    buf.write(b"ab")
    buf.__del__()
