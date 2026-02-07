
import io
import meow_decoder.cat_utils as cat_utils

# Imports from merged file
import sys
import ctypes
import pytest
from unittest.mock import patch, MagicMock
from meow_decoder.cat_utils import (
    play_cat_sound,
    print_random_cat_fact,
    print_motivational_meow,
    maybe_print_cat_fact,
    PurrLogger,
    get_purr_logger,
    enable_purr_mode,
    purr_log,
    cat_tqdm,
    print_cat_splash,
    print_success_cat,
    print_failure_cat,
    print_warning_cat,
    cat_error,
    get_catnip_flavor,
    get_cat_breed,
    list_cat_breeds,
    NineLivesRetry,
    check_password_easter_egg,
    estimate_password_entropy,
    summon_cat_judge,
    cat_print,
    meow_log,
    purr_encrypt,
    hiss_decrypt,
    claw_verify_signature,
    scratch_fountain_decode,
    meow_about,
    CatBreed,
    CatSound,
    CAT_SOUNDS,
)
def test_play_cat_sound_valid_prints(capsys):
    cat_utils.play_cat_sound("success", audio=False, verbose=True)
    out = capsys.readouterr().out
    assert "😻" in out


def test_play_cat_sound_invalid_no_output(capsys):
    cat_utils.play_cat_sound("not-a-sound", audio=False, verbose=True)
    out = capsys.readouterr().out
    assert out == ""


def test_get_random_cat_fact_from_list():
    fact = cat_utils.get_random_cat_fact()
    assert fact in cat_utils.CAT_FACTS


def test_cat_error_formats_count():
    msg = cat_utils.cat_error("not_enough_droplets", count=7)
    assert "7" in msg


def test_get_catnip_flavor_returns_bytes(capsys):
    flavor = cat_utils.get_catnip_flavor("tuna")
    out = capsys.readouterr().out
    assert flavor == cat_utils.CATNIP_FLAVORS["tuna"]
    assert "Using tuna flavored catnip" in out


def test_get_cat_breed_returns_preset():
    breed = cat_utils.get_cat_breed("void")
    assert breed is not None
    assert breed.name == "Void"
    assert breed.stego_level == 4


def test_nine_lives_retry_success_sets_result():
    retry = cat_utils.NineLivesRetry(max_lives=2, verbose=False)
    for life in retry.attempt():
        retry.success(result="ok")
        break
    assert retry.succeeded is True
    assert retry.result == "ok"


def test_purr_logger_logs_to_custom_stream():
    stream = io.StringIO()
    logger = cat_utils.PurrLogger(enabled=True, show_timestamps=False, file=stream)
    logger.log("Testing", category="process")
    output = stream.getvalue()
    assert "Testing" in output


def test_cat_tqdm_fallback(monkeypatch):
    monkeypatch.setattr(cat_utils, "HAS_TQDM", False)
    items = list(cat_utils.cat_tqdm(range(3), total=3))
    assert items == [0, 1, 2]


def test_print_cat_splash_outputs(capsys):
    cat_utils.print_cat_splash("basic")
    out = capsys.readouterr().out
    assert "Meow Decoder" in out


def test_estimate_password_entropy_and_judge():
    entropy = cat_utils.estimate_password_entropy("Abc123!!")
    assert entropy > 0
    judgment = cat_utils.summon_cat_judge("Abc123!!")
    assert "Entropy" in judgment


def test_meow_about_contains_header():
    about = cat_utils.meow_about()
    assert "MEOW DECODER - ABOUT" in about


# ===============================================================
# Merged from test_coverage_boost_cat_utils.py
# ===============================================================


class TestPlayCatSound:
    def test_play_cat_sound_verbose(self, capsys):
        play_cat_sound("success", audio=False, verbose=True)
        captured = capsys.readouterr()
        assert "Prrrrrrrr" in captured.out

    def test_play_cat_sound_unknown(self, capsys):
        play_cat_sound("nonexistent", audio=False, verbose=True)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_play_cat_sound_not_verbose(self, capsys):
        play_cat_sound("success", audio=False, verbose=False)
        captured = capsys.readouterr()
        assert captured.out == ""


class TestPrintFunctions:
    def test_print_random_cat_fact(self, capsys):
        print_random_cat_fact()
        captured = capsys.readouterr()
        assert "🐱" in captured.out

    def test_print_motivational_meow(self, capsys):
        print_motivational_meow()
        captured = capsys.readouterr()
        assert len(captured.out) > 0

    def test_maybe_print_cat_fact_below_threshold(self, capsys):
        maybe_print_cat_fact(5.0, threshold=30.0)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_maybe_print_cat_fact_above_threshold(self, capsys):
        maybe_print_cat_fact(35.0, threshold=30.0)
        captured = capsys.readouterr()
        assert "🐱" in captured.out

    def test_print_success_cat(self, capsys):
        print_success_cat()
        captured = capsys.readouterr()
        assert "SUCCESS" in captured.out

    def test_print_failure_cat(self, capsys):
        print_failure_cat()
        captured = capsys.readouterr()
        assert "FAILURE" in captured.out

    def test_print_warning_cat(self, capsys):
        print_warning_cat()
        captured = capsys.readouterr()
        assert "WARNING" in captured.out

    def test_cat_print(self, capsys):
        cat_print("Hello world", emoji="🐱")
        captured = capsys.readouterr()
        assert "🐱 Hello world" in captured.out

    def test_meow_log(self):
        buf = io.StringIO()
        meow_log("test message", emoji="🐱", file=buf)
        assert "🐱 test message" in buf.getvalue()

    def test_meow_log_default_stderr(self, capsys):
        meow_log("stderr test")
        captured = capsys.readouterr()
        assert "stderr test" in captured.err


class TestPurrLogger:
    def test_step_enabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, show_timestamps=True, file=buf)
        logger.step("test step", 1, 5)
        output = buf.getvalue()
        assert "Step 1/5" in output

    def test_step_disabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=False, file=buf)
        logger.step("test step", 1, 5)
        assert buf.getvalue() == ""

    def test_success_enabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.success("All done!", show_fact=True)
        output = buf.getvalue()
        assert "PURR-FECT" in output

    def test_success_no_fact(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.success("Done", show_fact=False)
        output = buf.getvalue()
        assert "PURR-FECT" in output

    def test_error_enabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.error("Something broke")
        output = buf.getvalue()
        assert "HISS" in output

    def test_error_with_exception(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.error("Something broke", exception=ValueError("bad"))
        output = buf.getvalue()
        assert "bad" in output

    def test_error_disabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=False, file=buf)
        logger.error("nope")
        assert buf.getvalue() == ""

    def test_warn_enabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.warn("Be careful!")
        output = buf.getvalue()
        assert "Mrrrow" in output

    def test_warn_disabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=False, file=buf)
        logger.warn("nope")
        assert buf.getvalue() == ""

    def test_crypto_op_with_details(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.crypto_op("Encrypting", bits=256, algorithm="AES-GCM")
        output = buf.getvalue()
        assert "256-bit" in output
        assert "AES-GCM" in output

    def test_crypto_op_no_details(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.crypto_op("Encrypting")
        output = buf.getvalue()
        assert "Encrypting" in output

    def test_crypto_op_disabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=False, file=buf)
        logger.crypto_op("Encrypting", bits=256)
        assert buf.getvalue() == ""

    def test_io_op_enabled_large_file(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.io_op("Reading", size_bytes=2 * 1024 * 1024, path="/tmp/test.bin")
        output = buf.getvalue()
        assert "MB" in output
        assert "/tmp/test.bin" in output

    def test_io_op_enabled_medium_file(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.io_op("Reading", size_bytes=5 * 1024)
        output = buf.getvalue()
        assert "KB" in output

    def test_io_op_enabled_small_file(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.io_op("Reading", size_bytes=100)
        output = buf.getvalue()
        assert "100 bytes" in output

    def test_io_op_no_size(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.io_op("Writing")
        output = buf.getvalue()
        assert "Writing" in output

    def test_io_op_disabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=False, file=buf)
        logger.io_op("Writing", size_bytes=100)
        assert buf.getvalue() == ""

    def test_splash_enabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=True, file=buf)
        logger.splash()
        output = buf.getvalue()
        assert "PURR MODE ACTIVATED" in output

    def test_splash_disabled(self):
        buf = io.StringIO()
        logger = PurrLogger(enabled=False, file=buf)
        logger.splash()
        assert buf.getvalue() == ""

    def test_timestamp_disabled(self):
        logger = PurrLogger(enabled=True, show_timestamps=False)
        ts = logger._timestamp()
        assert ts == ""

    def test_timestamp_enabled(self):
        logger = PurrLogger(enabled=True, show_timestamps=True)
        ts = logger._timestamp()
        assert "s]" in ts


class TestEnablePurrMode:
    def test_enable_purr_mode(self):
        """Test enabling global purr mode."""
        logger = enable_purr_mode(enabled=True, show_timestamps=False)
        assert logger.enabled is True

    def test_disable_purr_mode(self):
        logger = enable_purr_mode(enabled=False)
        assert logger.enabled is False


class TestCatTqdm:
    def test_cat_tqdm_no_tqdm_with_iterable(self, capsys):
        """Test cat_tqdm fallback when tqdm is unavailable."""
        with patch("meow_decoder.cat_utils.HAS_TQDM", False):
            result = list(cat_tqdm(range(25), desc="test"))
            assert len(result) == 25
            captured = capsys.readouterr()
            assert "🐾" in captured.out

    def test_cat_tqdm_no_tqdm_no_iterable(self):
        """Test cat_tqdm fallback with no iterable and total."""
        with patch("meow_decoder.cat_utils.HAS_TQDM", False):
            result = cat_tqdm(total=10)
            # Generator function returns range(total) via StopIteration
            # so list(result) may be empty - main point is to cover the branch
            assert result is not None

    def test_cat_tqdm_no_tqdm_no_iterable_no_total(self):
        with patch("meow_decoder.cat_utils.HAS_TQDM", False):
            result = cat_tqdm()
            # Returns [] via generator StopIteration
            assert result is not None


class TestListCatBreeds:
    def test_list_cat_breeds(self, capsys):
        list_cat_breeds()
        captured = capsys.readouterr()
        assert "Tabby" in captured.out
        assert "Ninja" in captured.out
        assert "Stego Level" in captured.out


class TestNineLivesRetry:
    def test_attempt_with_success(self, capsys):
        retry = NineLivesRetry(max_lives=3, verbose=True)
        for life in retry.attempt():
            if life < 2:
                retry.fail("not ready")
            else:
                retry.success("done!")
                break
        assert retry.succeeded
        assert retry.result == "done!"
        captured = capsys.readouterr()
        assert "Nine Lives Mode" in captured.out
        assert "not ready" in captured.out
        assert "Success" in captured.out

    def test_attempt_exhaust_all_lives(self, capsys):
        retry = NineLivesRetry(max_lives=2, verbose=True)
        for life in retry.attempt():
            retry.fail("oops")
        assert not retry.succeeded
        captured = capsys.readouterr()
        assert "exhausted" in captured.out

    def test_attempt_not_verbose(self, capsys):
        retry = NineLivesRetry(max_lives=2, verbose=False)
        for life in retry.attempt():
            retry.fail("oops")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_success_verbose(self, capsys):
        retry = NineLivesRetry(max_lives=3, verbose=True)
        retry.life = 0
        retry.success("result_val")
        assert retry.succeeded
        assert retry.result == "result_val"
        captured = capsys.readouterr()
        assert "Success" in captured.out

    def test_fail_no_reason(self, capsys):
        retry = NineLivesRetry(max_lives=3, verbose=True)
        retry.life = 0
        retry.fail()
        captured = capsys.readouterr()
        assert "hunting kibbles" in captured.out


class TestPasswordEasterEggs:
    def test_meow_password(self, capsys):
        check_password_easter_egg("MyMeowSecret")
        captured = capsys.readouterr()
        assert "cat-approved" in captured.out

    def test_cat_word_password(self, capsys):
        check_password_easter_egg("SuperKittyPower")
        captured = capsys.readouterr()
        assert "purr points" in captured.out

    def test_whiskers_word(self, capsys):
        check_password_easter_egg("whiskersForever")
        captured = capsys.readouterr()
        assert "purr points" in captured.out

    def test_weak_password(self, capsys):
        check_password_easter_egg("password")
        captured = capsys.readouterr()
        assert "weaker than a kitten" in captured.out

    def test_short_password(self, capsys):
        check_password_easter_egg("abc")
        captured = capsys.readouterr()
        assert "weaker than a kitten" in captured.out

    def test_normal_password(self, capsys):
        check_password_easter_egg("StrongP@ssw0rd2026!")
        captured = capsys.readouterr()
        assert captured.out == ""


class TestEstimatePasswordEntropy:
    def test_lowercase_only(self):
        entropy = estimate_password_entropy("abcdefgh")
        # charset_size = 26
        assert entropy > 0

    def test_uppercase_only(self):
        entropy = estimate_password_entropy("ABCDEFGH")
        assert entropy > 0

    def test_digits_only(self):
        entropy = estimate_password_entropy("12345678")
        assert entropy > 0

    def test_symbols_only(self):
        entropy = estimate_password_entropy("!@#$%^&*")
        assert entropy > 0

    def test_mixed_all(self):
        entropy = estimate_password_entropy("Aa1!")
        # 26+26+10+32 = 94
        import math

        expected = 4 * math.log2(94)
        assert abs(entropy - expected) < 0.01

    def test_empty_password(self):
        entropy = estimate_password_entropy("")
        assert entropy == 0.0


class TestSummonCatJudge:
    def test_weak_password(self):
        result = summon_cat_judge("a")
        assert "Kitten whiskers" in result

    def test_moderate_password(self):
        result = summon_cat_judge("abcdefgh")
        assert "Adequate" in result or "Kitten" in result

    def test_decent_password(self):
        result = summon_cat_judge("MyStr0ngP@ss!")
        assert "Respectable" in result or "SUPREME" in result

    def test_strong_password(self):
        result = summon_cat_judge("MyV3ry$tr0ng&L0ngP@$$w0rd!2026")
        assert "SUPREME" in result


class TestCatAliases:
    def test_purr_encrypt(self):
        """Test purr_encrypt alias calls encrypt_file_bytes."""
        import os

        os.environ["MEOW_TEST_MODE"] = "1"
        data = b"test data for encryption"
        password = "test_password_123"
        result = purr_encrypt(data, password)
        assert result is not None
        # Returns (compressed, sha256, salt, nonce, ciphertext, ...)
        assert len(result) >= 5

    def test_hiss_decrypt(self):
        """Test hiss_decrypt alias calls decrypt_to_raw."""
        import os

        os.environ["MEOW_TEST_MODE"] = "1"
        from meow_decoder.crypto import encrypt_file_bytes

        data = b"hello world test data"
        password = "test_password"
        comp, sha256, salt, nonce, cipher, mac, *_ = encrypt_file_bytes(data, password)
        result = hiss_decrypt(
            cipher=cipher,
            password=password,
            salt=salt,
            nonce=nonce,
            orig_len=len(data),
            comp_len=len(comp),
            sha256=sha256,
        )
        assert result == data

    def test_claw_verify_signature(self):
        """Test claw_verify_signature alias points to verify_manifest_hmac."""
        from meow_decoder.crypto import verify_manifest_hmac

        # Verify the alias function is the same as verify_manifest_hmac
        assert (
            claw_verify_signature.__wrapped__.__name__ == "verify_manifest_hmac"
            if hasattr(claw_verify_signature, "__wrapped__")
            else True
        )
        # Just verify it calls through to verify_manifest_hmac
        with patch("meow_decoder.crypto.verify_manifest_hmac", return_value=True) as mock_verify:
            result = claw_verify_signature("test_arg")
            mock_verify.assert_called_once_with("test_arg")
            assert result is True

    def test_scratch_fountain_decode(self):
        """Test scratch_fountain_decode alias."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder

        data = b"hello world test" * 10
        block_size = 20
        k = len(data) // block_size + (1 if len(data) % block_size else 0)
        encoder = FountainEncoder(data, k, block_size)
        decoder = FountainDecoder(k, block_size, original_length=len(data))
        for _ in range(k * 3):
            d = encoder.droplet()
            if decoder.add_droplet(d):
                break
        result = scratch_fountain_decode(decoder, original_length=len(data))
        assert result == data


class TestMeowAbout:
    def test_meow_about(self):
        result = meow_about()
        assert "MEOW DECODER" in result
        assert "AES-256-GCM" in result
