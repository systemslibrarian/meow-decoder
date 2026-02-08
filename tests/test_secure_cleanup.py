#!/usr/bin/env python3
"""Tests for meow_decoder.secure_cleanup.
Target: 95%+ branch coverage
"""

import signal

import pytest


def _reset_state(sc_module):
    sc_module._sensitive_buffers.clear()
    sc_module._buffer_data.clear()
    sc_module._handlers_registered = False


class TestSecureCleanupBasics:
    def test_buffer_registration_and_zeroing(self):
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)
        secret = b"super_secret_key_12345"
        mutable = sc.register_sensitive_buffer(secret)

        assert mutable == bytearray(secret)
        assert id(mutable) in sc._sensitive_buffers
        assert sc._buffer_data[id(mutable)] is mutable

        sc.unregister_and_zero(mutable)
        assert all(b == 0 for b in mutable)
        assert id(mutable) not in sc._sensitive_buffers
        assert id(mutable) not in sc._buffer_data

    def test_unregister_unknown_is_noop(self):
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)
        sc.unregister_and_zero(bytearray(b"not-registered"))

    def test_cleanup_all_zeroes_buffers(self):
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)
        a = sc.register_sensitive_buffer(b"aaa")
        b = sc.register_sensitive_buffer(b"bbb")

        sc._cleanup_all()
        assert all(x == 0 for x in a)
        assert all(x == 0 for x in b)
        assert len(sc._sensitive_buffers) == 0
        assert len(sc._buffer_data) == 0

    def test_zero_buffer_memoryview(self):
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)
        backing = bytearray(b"abc")
        mv = memoryview(backing)
        buf_id = id(mv)
        sc._sensitive_buffers.add(buf_id)
        sc._buffer_data[buf_id] = mv

        sc._zero_buffer(buf_id)
        assert backing == bytearray(b"\x00" * 3)
        assert buf_id not in sc._sensitive_buffers
        assert buf_id not in sc._buffer_data

    def test_zero_buffer_readonly_memoryview(self):
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)
        mv = memoryview(b"abc")
        buf_id = id(mv)
        sc._sensitive_buffers.add(buf_id)
        sc._buffer_data[buf_id] = mv

        # Should not raise even though memoryview is read-only
        sc._zero_buffer(buf_id)
        assert buf_id not in sc._sensitive_buffers
        assert buf_id not in sc._buffer_data


class TestHandlers:
    def test_register_handlers_idempotent(self, monkeypatch):
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)
        calls = {"atexit": 0, "signal": 0}

        monkeypatch.setattr(
            sc.atexit, "register", lambda _fn: calls.__setitem__("atexit", calls["atexit"] + 1)
        )

        def _sig(_sig, _handler):
            calls["signal"] += 1

        monkeypatch.setattr(sc.signal, "signal", _sig)

        sc._register_handlers()
        sc._register_handlers()

        assert calls["atexit"] == 1
        # SIGTERM + SIGINT
        assert calls["signal"] == 2
        assert sc._handlers_registered is True

    def test_signal_handler_invokes_cleanup(self, monkeypatch):
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)
        called = {"cleanup": 0, "raised": 0, "set": 0}

        monkeypatch.setattr(
            sc, "_cleanup_all", lambda: called.__setitem__("cleanup", called["cleanup"] + 1)
        )
        monkeypatch.setattr(
            sc.signal, "signal", lambda *_a, **_k: called.__setitem__("set", called["set"] + 1)
        )
        monkeypatch.setattr(
            sc.signal, "raise_signal", lambda _s: called.__setitem__("raised", called["raised"] + 1)
        )

        sc._signal_handler(signal.SIGTERM, None)

        assert called["cleanup"] == 1
        assert called["set"] == 1
        assert called["raised"] == 1


class TestContextManagers:
    def test_cleanup_manager_zeroes(self):
        from meow_decoder.secure_cleanup import SecureCleanupManager

        with SecureCleanupManager() as cleanup:
            key = cleanup.register(b"encryption_key_here_123")
            assert len(key) == 23

        assert all(b == 0 for b in key)

    def test_secure_password_context(self):
        from meow_decoder.secure_cleanup import secure_password_context

        with secure_password_context("MySecretPassword") as pwd:
            assert pwd == bytearray(b"MySecretPassword")

        assert all(b == 0 for b in pwd)

    def test_register_triggers_handlers(self):
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)
        buf = sc.register_sensitive_buffer(b"test")
        assert sc._handlers_registered is True
        sc.unregister_and_zero(buf)


# --- Merged from test_coverage_boost_extras.py ---


# =====================================================
# secure_cleanup.py — push from 96.25% higher
# =====================================================
class TestSecureCleanupExtras:
    """Extra secure_cleanup tests for uncovered branches."""

    def test_register_sensitive_buffer(self):
        """Register a sensitive buffer for cleanup."""
        from meow_decoder import secure_cleanup

        data = b"sensitive key material"
        buf = secure_cleanup.register_sensitive_buffer(data)
        assert isinstance(buf, bytearray)
        assert bytes(buf) == data

    def test_cleanup_all_runs(self):
        """_cleanup_all should zero registered buffers."""
        from meow_decoder import secure_cleanup

        buf = secure_cleanup.register_sensitive_buffer(b"secret")
        secure_cleanup._cleanup_all()
        # After cleanup, buffer should be zeroed
        assert buf == bytearray(len(b"secret"))


# =====================================================
# qr_code.py — push from 96.4% higher
# =====================================================

# --- Merged from test_coverage_boost_remaining.py ---


# =====================================================
# secure_cleanup.py small gaps
# =====================================================
class TestSecureCleanupBoost:
    def test_register_handlers_from_thread(self):
        """Signal handlers from non-main thread should be handled gracefully."""
        import threading
        from meow_decoder import secure_cleanup

        secure_cleanup._handlers_registered = False

        def worker():
            secure_cleanup._register_handlers()

        t = threading.Thread(target=worker)
        t.start()
        t.join()

    def test_double_check_locking_path(self):
        """Test the double-check locking return path (line 87).

        This tests when two threads race to register handlers.
        The second thread should hit the inner return.
        """
        import threading
        import time
        from meow_decoder import secure_cleanup as sc

        # Reset state completely
        _reset_state(sc)

        results = []

        def worker():
            sc._register_handlers()
            results.append(sc._handlers_registered)

        # Spawn multiple threads to try to trigger the race
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should complete, handlers should be registered
        assert all(results)
        assert sc._handlers_registered is True

        # Reset for other tests
        _reset_state(sc)

    def test_signal_handler_exception_path(self, monkeypatch):
        """Test when signal.signal raises ValueError/OSError."""
        from meow_decoder import secure_cleanup as sc

        _reset_state(sc)

        def _raise_signal(*args, **kwargs):
            raise ValueError("Can't set signal handler from this thread")

        monkeypatch.setattr(sc.signal, "signal", _raise_signal)
        monkeypatch.setattr(sc.atexit, "register", lambda fn: None)

        # Should not raise, just silently skip signal registration
        sc._register_handlers()
        assert sc._handlers_registered is True


# =====================================================
# constant_time.py small gaps
# =====================================================
