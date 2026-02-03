import io

import meow_decoder.cat_utils as cat_utils


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
