import ctypes

import pytest


def test_get_libc_platform_branches(monkeypatch):
    import meow_decoder.constant_time as ct

    # Darwin branch
    monkeypatch.setattr(ct.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(ct.ctypes, "CDLL", lambda _name: object())
    assert ct._get_libc() is not None

    # Windows branch
    monkeypatch.setattr(ct.platform, "system", lambda: "Windows")
    monkeypatch.setattr(ct.ctypes, "CDLL", lambda _name: object())
    assert ct._get_libc() is not None

    # Unknown platform branch
    monkeypatch.setattr(ct.platform, "system", lambda: "Plan9")
    assert ct._get_libc() is None

    # Exception path
    monkeypatch.setattr(ct.platform, "system", lambda: "Darwin")

    def _boom(_name):
        raise OSError("nope")

    monkeypatch.setattr(ct.ctypes, "CDLL", _boom)
    assert ct._get_libc() is None


def test_secure_zero_memory_fallback_and_other_types(monkeypatch):
    import meow_decoder.constant_time as ct

    # Force the manual fallback path.
    monkeypatch.setattr(ct, "_libc", None)

    buf = bytearray(b"secret")
    ct.secure_zero_memory(buf)
    assert buf == bytearray(b"\x00" * 6)

    # Non-bytearray should be a no-op in fallback mode.
    ct.secure_zero_memory(b"immutable")


def test_secure_zero_memory_ctypes_array_branch(monkeypatch):
    import meow_decoder.constant_time as ct

    # Ensure we take the ctypes.Array branch.
    arr = (ctypes.c_char * 4)()
    arr.raw = b"ABCD"

    ct.secure_zero_memory(arr)
    assert bytes(arr) == b"\x00" * 4


def test_secure_memory_lock_and_unlock_exceptions(monkeypatch):
    import meow_decoder.constant_time as ct

    real_libc = ctypes.CDLL("libc.so.6")

    class _LibcLockFails:
        def mlock(self, *_args, **_kwargs):
            raise OSError("mlock failed")

        def memset(self, *args, **kwargs):
            return real_libc.memset(*args, **kwargs)

    monkeypatch.setattr(ct, "_libc", _LibcLockFails())

    with ct.secure_memory(b"pw") as buf:
        assert bytes(buf) == b"pw"

    class _LibcUnlockFails:
        def mlock(self, *_args, **_kwargs):
            return 0

        def munlock(self, *_args, **_kwargs):
            raise OSError("munlock failed")

        def memset(self, *args, **kwargs):
            return real_libc.memset(*args, **kwargs)

    monkeypatch.setattr(ct, "_libc", _LibcUnlockFails())

    with ct.secure_memory(b"pw") as buf2:
        assert bytes(buf2) == b"pw"


def test_secure_buffer_lock_exception_and_cleanup_paths(monkeypatch):
    import meow_decoder.constant_time as ct

    real_libc = ctypes.CDLL("libc.so.6")

    class _LibcMlockRaises:
        def mlock(self, *_args, **_kwargs):
            raise OSError("mlock failed")

        def memset(self, *args, **kwargs):
            return real_libc.memset(*args, **kwargs)

    monkeypatch.setattr(ct, "_libc", _LibcMlockRaises())

    buf = ct.SecureBuffer(8)
    buf.write(b"hi")
    assert buf.read()[:2] == b"hi"

    # Raise on oversize write.
    with pytest.raises(ValueError):
        buf.write(b"0123456789")

    # Force __del__ paths (unlock may not run when not locked).
    buf.__del__()

    class _LibcUnlockRaises:
        def mlock(self, *_args, **_kwargs):
            return 0

        def munlock(self, *_args, **_kwargs):
            raise OSError("munlock failed")

        def memset(self, *args, **kwargs):
            return real_libc.memset(*args, **kwargs)

    monkeypatch.setattr(ct, "_libc", _LibcUnlockRaises())

    buf2 = ct.SecureBuffer(8)
    buf2.write(b"hello")
    # Read with length=None branch.
    assert buf2.read().startswith(b"hello")
    buf2.locked = True
    buf2.__del__()
