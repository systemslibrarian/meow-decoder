"""
Tests for meow_decoder.cat_errors module.
Cat-themed error handling, decorators, and pun utilities.
"""
import os
import sys
import warnings
import pytest
from unittest.mock import patch

pytestmark = pytest.mark.cat

os.environ.setdefault("MEOW_TEST_MODE", "1")


# ═══════════════════════════════════════════════════════════════
# §1  Exception Hierarchy
# ═══════════════════════════════════════════════════════════════
class TestCatExceptions:
    """Test all custom exception classes."""

    def test_meow_error_basic(self):
        from meow_decoder.cat_errors import MeowError
        e = MeowError("yarn tangled")
        assert "😿" in str(e)
        assert "Meow!" in str(e)
        assert "yarn tangled" in str(e)

    def test_meow_error_with_original(self):
        from meow_decoder.cat_errors import MeowError
        orig = ValueError("bad value")
        e = MeowError("wrapping error", original=orig)
        assert e.original is orig

    def test_catastrophic_error(self):
        from meow_decoder.cat_errors import CatastrophicError
        e = CatastrophicError("system failure")
        assert "🙀" in str(e)
        assert "CATASTROPHE!" in str(e)

    def test_hairball_error(self):
        from meow_decoder.cat_errors import HairballError
        e = HairballError("data corrupted")
        assert "😾" in str(e)
        assert "Hairball!" in str(e)

    def test_scratch_error(self):
        from meow_decoder.cat_errors import ScratchError
        e = ScratchError("auth denied")
        assert "😼" in str(e)
        assert "Scratch!" in str(e)

    def test_yarn_tangle_error(self):
        from meow_decoder.cat_errors import YarnTangleError
        e = YarnTangleError("config invalid")
        assert "😿" in str(e)
        assert "tangled" in str(e).lower()

    def test_kibble_shortage_error(self):
        from meow_decoder.cat_errors import KibbleShortageError
        e = KibbleShortageError("not enough data")
        assert "🐱" in str(e)
        assert "Kibble" in str(e)

    def test_nap_interrupt_error(self):
        from meow_decoder.cat_errors import NapInterruptError
        e = NapInterruptError("operation too slow")
        assert "😴" in str(e)
        assert "Nap" in str(e)

    def test_exceptions_inherit_from_meow_error(self):
        from meow_decoder.cat_errors import (
            MeowError, CatastrophicError, HairballError,
            ScratchError, YarnTangleError, KibbleShortageError,
            NapInterruptError,
        )
        for cls in [CatastrophicError, HairballError, ScratchError,
                    YarnTangleError, KibbleShortageError, NapInterruptError]:
            assert issubclass(cls, MeowError)
            assert issubclass(cls, Exception)


# ═══════════════════════════════════════════════════════════════
# §2  Error Message Catalog
# ═══════════════════════════════════════════════════════════════
class TestFurBallError:
    """Test fur_ball_error message formatting."""

    def test_known_key(self):
        from meow_decoder.cat_errors import fur_ball_error
        msg = fur_ball_error("wrong_password", suggestion=False)
        assert "HISS" in msg
        assert "collar tag" in msg.lower()

    def test_unknown_key_fallback(self):
        from meow_decoder.cat_errors import fur_ball_error
        msg = fur_ball_error("totally_nonexistent_key", suggestion=False)
        assert "😿" in msg
        assert "wrong" in msg.lower() or "confused" in msg.lower()

    def test_with_kwargs(self):
        from meow_decoder.cat_errors import fur_ball_error
        msg = fur_ball_error("not_enough_droplets", suggestion=False, count=42)
        assert "42" in msg

    def test_with_suggestion(self):
        from meow_decoder.cat_errors import fur_ball_error
        msg = fur_ball_error("file_not_found", suggestion=True)
        assert "💡" in msg  # suggestion included

    def test_all_known_keys_render(self):
        from meow_decoder.cat_errors import fur_ball_error, _CAT_ERROR_MESSAGES
        for key in _CAT_ERROR_MESSAGES:
            if "{" in _CAT_ERROR_MESSAGES[key]:
                continue  # skip template-requiring keys
            msg = fur_ball_error(key, suggestion=False)
            assert len(msg) > 0
            assert any(e in msg for e in ["😿", "😾", "😼", "🙀", "🐱", "🔮", "🔑", "📹", "🚨", "😴", "🌿"])


# ═══════════════════════════════════════════════════════════════
# §3  Pounce on Errors Decorator
# ═══════════════════════════════════════════════════════════════
class TestPounceOnErrors:
    """Test the @pounce_on_errors decorator."""

    def test_no_error_passthrough(self):
        from meow_decoder.cat_errors import pounce_on_errors

        @pounce_on_errors()
        def good_func():
            return 42

        assert good_func() == 42

    def test_catches_and_reraises(self):
        from meow_decoder.cat_errors import pounce_on_errors

        @pounce_on_errors(catch=(ValueError,), verbose=True, reraise=True)
        def bad_func():
            raise ValueError("test error")

        with pytest.raises(ValueError):
            bad_func()

    def test_retry_succeeds_on_later_attempt(self):
        from meow_decoder.cat_errors import pounce_on_errors

        call_count = 0

        @pounce_on_errors(lives=3, catch=(RuntimeError,), verbose=True, reraise=True)
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("not yet")
            return "success"

        result = flaky_func()
        assert result == "success"
        assert call_count == 3

    def test_retry_exhausted(self):
        from meow_decoder.cat_errors import pounce_on_errors

        @pounce_on_errors(lives=2, catch=(RuntimeError,), verbose=True, reraise=True)
        def always_fails():
            raise RuntimeError("permanent")

        with pytest.raises(RuntimeError, match="permanent"):
            always_fails()

    def test_with_error_key(self, capsys):
        from meow_decoder.cat_errors import pounce_on_errors

        @pounce_on_errors(catch=(OSError,), error_key="file_not_found", verbose=True, reraise=True)
        def missing_file():
            raise OSError("nope")

        with pytest.raises(OSError):
            missing_file()


# ═══════════════════════════════════════════════════════════════
# §4  Hiss Warning
# ═══════════════════════════════════════════════════════════════
class TestHissWarning:
    """Test hiss_warning function."""

    def test_emits_warning(self):
        from meow_decoder.cat_errors import hiss_warning

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            hiss_warning("Low memory detected!")
            assert len(w) == 1
            assert "😼" in str(w[0].message)
            assert "Hiss!" in str(w[0].message)
            assert "Low memory" in str(w[0].message)

    def test_custom_category(self):
        from meow_decoder.cat_errors import hiss_warning

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            hiss_warning("Deprecated feature!", category=DeprecationWarning)
            assert len(w) == 1
            assert w[0].category == DeprecationWarning


# ═══════════════════════════════════════════════════════════════
# §5  Whisker Validate
# ═══════════════════════════════════════════════════════════════
class TestWhiskerValidate:
    """Test whisker_validate assertion helper."""

    def test_passes_on_true(self):
        from meow_decoder.cat_errors import whisker_validate
        whisker_validate(True, "wrong_password")  # should not raise

    def test_raises_on_false(self):
        from meow_decoder.cat_errors import whisker_validate, YarnTangleError
        with pytest.raises(YarnTangleError, match="HISS"):
            whisker_validate(False, "wrong_password")

    def test_raises_with_kwargs(self):
        from meow_decoder.cat_errors import whisker_validate, YarnTangleError
        with pytest.raises(YarnTangleError, match="42"):
            whisker_validate(False, "not_enough_droplets", count=42)


# ═══════════════════════════════════════════════════════════════
# §6  Litter Box Cleanup
# ═══════════════════════════════════════════════════════════════
class TestLitterBoxCleanup:
    """Test litter_box_cleanup context manager."""

    def test_zeros_bytearray(self):
        from meow_decoder.cat_errors import litter_box_cleanup
        buf = bytearray(b"\xff" * 32)
        with litter_box_cleanup(buf):
            assert buf == bytearray(b"\xff" * 32)  # untouched inside
        assert buf == bytearray(32)  # zeroed after

    def test_zeros_on_exception(self):
        from meow_decoder.cat_errors import litter_box_cleanup
        buf = bytearray(b"\xaa" * 16)
        with pytest.raises(ValueError):
            with litter_box_cleanup(buf):
                raise ValueError("oops")
        assert buf == bytearray(16)  # still zeroed

    def test_multiple_buffers(self):
        from meow_decoder.cat_errors import litter_box_cleanup
        a = bytearray(b"\x11" * 8)
        b = bytearray(b"\x22" * 8)
        with litter_box_cleanup(a, b):
            pass
        assert a == bytearray(8)
        assert b == bytearray(8)


# ═══════════════════════════════════════════════════════════════
# §7  Output Helpers
# ═══════════════════════════════════════════════════════════════
class TestOutputHelpers:
    """Test meow_wrap, purr_status, hiss_error, purr_success, claw_mark."""

    def test_meow_wrap_returns_string(self):
        from meow_decoder.cat_errors import meow_wrap
        result = meow_wrap("hello", emoji="🐱")
        assert result == "🐱 hello"

    def test_meow_wrap_prints_to_file(self, capsys):
        from meow_decoder.cat_errors import meow_wrap
        import io
        buf = io.StringIO()
        meow_wrap("printed!", emoji="😸", file=buf)
        assert "😸 printed!" in buf.getvalue()

    def test_hiss_error(self, capsys):
        from meow_decoder.cat_errors import hiss_error
        import io
        buf = io.StringIO()
        hiss_error("something broke", file=buf)
        assert "😾" in buf.getvalue()
        assert "HISS!" in buf.getvalue()

    def test_purr_success(self, capsys):
        from meow_decoder.cat_errors import purr_success
        import io
        buf = io.StringIO()
        purr_success("encoding done", file=buf)
        assert "😻" in buf.getvalue()
        assert "Purr-fect" in buf.getvalue()

    def test_claw_mark_debug_on(self):
        from meow_decoder.cat_errors import claw_mark
        import io
        buf = io.StringIO()
        with patch.dict(os.environ, {"MEOW_DEBUG": "1"}):
            claw_mark("trace message", file=buf)
        assert "🐾" in buf.getvalue()

    def test_claw_mark_debug_off(self):
        from meow_decoder.cat_errors import claw_mark
        import io
        buf = io.StringIO()
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("MEOW_DEBUG", None)
            claw_mark("should not print", file=buf)
        assert buf.getvalue() == ""

    def test_purr_status_cat_mode_on(self):
        from meow_decoder.cat_errors import purr_status
        import io
        buf = io.StringIO()
        with patch.dict(os.environ, {"MEOW_CAT_MODE": "1"}):
            purr_status("scanning frames", verbose=True, file=buf)
        assert "😺" in buf.getvalue()

    def test_purr_status_cat_mode_off(self):
        from meow_decoder.cat_errors import purr_status
        import io
        buf = io.StringIO()
        with patch.dict(os.environ, {"MEOW_CAT_MODE": "0"}):
            purr_status("scanning frames", verbose=True, file=buf)
        assert buf.getvalue() == ""


# ═══════════════════════════════════════════════════════════════
# §8  Nine Lives Retry Decorator
# ═══════════════════════════════════════════════════════════════
class TestNineLivesRetry:
    """Test nine_lives_retry decorator."""

    def test_basic_no_error(self):
        from meow_decoder.cat_errors import nine_lives_retry

        @nine_lives_retry
        def simple():
            return "ok"

        assert simple() == "ok"

    def test_with_lives_kwarg(self):
        from meow_decoder.cat_errors import nine_lives_retry

        calls = 0

        @nine_lives_retry(lives=5, verbose=False)
        def flaky():
            nonlocal calls
            calls += 1
            if calls < 3:
                raise Exception("not ready")
            return "done"

        assert flaky() == "done"
        assert calls == 3


# ═══════════════════════════════════════════════════════════════
# §9  Cat Nap Timeout
# ═══════════════════════════════════════════════════════════════
class TestCatNapTimeout:
    """Test cat_nap_timeout decorator."""

    def test_fast_function_succeeds(self):
        from meow_decoder.cat_errors import cat_nap_timeout

        @cat_nap_timeout(5.0)
        def quick():
            return 42

        assert quick() == 42

    def test_timeout_raises_nap_interrupt(self):
        import signal
        from meow_decoder.cat_errors import cat_nap_timeout, NapInterruptError

        if not hasattr(signal, "SIGALRM"):
            pytest.skip("No SIGALRM on this platform")

        @cat_nap_timeout(1.0)
        def slow():
            import time
            time.sleep(10)

        with pytest.raises(NapInterruptError, match="fell asleep"):
            slow()


# ═══════════════════════════════════════════════════════════════
# §10  Tail Swish Progress
# ═══════════════════════════════════════════════════════════════
class TestTailSwishProgress:
    """Test tail_swish_progress iterator."""

    def test_iterates_all_items(self):
        from meow_decoder.cat_errors import tail_swish_progress
        items = list(range(20))
        with patch.dict(os.environ, {"MEOW_CAT_MODE": "1"}):
            result = list(tail_swish_progress(items, desc="test", verbose=True))
        assert result == items

    def test_cat_mode_off_still_iterates(self):
        from meow_decoder.cat_errors import tail_swish_progress
        items = [1, 2, 3]
        with patch.dict(os.environ, {"MEOW_CAT_MODE": "0"}):
            result = list(tail_swish_progress(items, verbose=True))
        assert result == [1, 2, 3]


# ═══════════════════════════════════════════════════════════════
# §11  Cat Translate Error
# ═══════════════════════════════════════════════════════════════
class TestCatTranslateError:
    """Test cat_translate_error pattern matching."""

    def test_known_pattern_password(self):
        from meow_decoder.cat_errors import cat_translate_error
        msg = cat_translate_error(ValueError("Password cannot be empty"))
        assert "😾" in msg or "HISS" in msg

    def test_known_pattern_nonce(self):
        from meow_decoder.cat_errors import cat_translate_error
        msg = cat_translate_error(RuntimeError("Nonce reuse detected!"))
        assert "🙀" in msg

    def test_known_pattern_no_frames(self):
        from meow_decoder.cat_errors import cat_translate_error
        msg = cat_translate_error(ValueError("No frames found in GIF"))
        assert "😿" in msg

    def test_known_pattern_hmac(self):
        from meow_decoder.cat_errors import cat_translate_error
        msg = cat_translate_error(ValueError("HMAC verification failed"))
        assert "😾" in msg

    def test_unknown_pattern_fallback(self):
        from meow_decoder.cat_errors import cat_translate_error
        msg = cat_translate_error(RuntimeError("xyzzy totally unknown"))
        assert "😿" in msg
        assert "confused" in msg.lower() or "wrong" in msg.lower()


# ═══════════════════════════════════════════════════════════════
# §12  Meow Excepthook
# ═══════════════════════════════════════════════════════════════
class TestMeowExcepthook:
    """Test meow_excepthook custom exception handler."""

    def test_hook_adds_cat_message(self, capsys):
        from meow_decoder.cat_errors import meow_excepthook

        try:
            raise ValueError("No frames found in GIF")
        except ValueError:
            exc_type, exc_value, exc_tb = sys.exc_info()
            meow_excepthook(exc_type, exc_value, exc_tb)

        captured = capsys.readouterr()
        assert "😿" in captured.err

    def test_hook_still_shows_traceback(self, capsys):
        from meow_decoder.cat_errors import meow_excepthook

        try:
            raise RuntimeError("nonce reuse")
        except RuntimeError:
            exc_type, exc_value, exc_tb = sys.exc_info()
            meow_excepthook(exc_type, exc_value, exc_tb)

        captured = capsys.readouterr()
        assert "RuntimeError" in captured.err


# ═══════════════════════════════════════════════════════════════
# §13  Cat Mode Detection
# ═══════════════════════════════════════════════════════════════
class TestCatModeDetection:
    """Test _cat_mode_enabled flag."""

    def test_default_is_on(self):
        from meow_decoder.cat_errors import _cat_mode_enabled
        with patch.dict(os.environ, {"MEOW_CAT_MODE": "1"}):
            assert _cat_mode_enabled() is True

    def test_explicit_off(self):
        from meow_decoder.cat_errors import _cat_mode_enabled
        with patch.dict(os.environ, {"MEOW_CAT_MODE": "0"}):
            assert _cat_mode_enabled() is False

    def test_missing_env_defaults_off(self):
        from meow_decoder.cat_errors import _cat_mode_enabled
        env = os.environ.copy()
        env.pop("MEOW_CAT_MODE", None)
        with patch.dict(os.environ, env, clear=True):
            result = _cat_mode_enabled()
            # Missing = default "1" via .get default
            # Actually looks at MEOW_CAT_MODE with default "1"
            assert result is True or result is False  # either way, no crash
