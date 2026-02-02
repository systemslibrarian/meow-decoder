#!/usr/bin/env python3
"""Tests for meow_decoder.duress_mode.
Target: 95%+ coverage of DuressHandler and helpers.
"""

import argparse
import os
from pathlib import Path

import pytest
import secrets

from meow_decoder.config import DuressConfig, DuressMode
from meow_decoder.duress_mode import (
    DuressHandler,
    add_duress_args,
    generate_deterministic_decoy,
    generate_duress_decoy,
    generate_static_decoy,
)


def test_set_passwords_same_raises():
    handler = DuressHandler()
    salt = secrets.token_bytes(16)

    with pytest.raises(ValueError, match="cannot be the same"):
        handler.set_passwords("same", "same", salt)


def test_check_password_real_and_duress(monkeypatch):
    called = {"cb": 0, "wipe": 0}

    def _cb():
        called["cb"] += 1

    config = DuressConfig(trigger_callback=_cb, wipe_resume_files=True)
    handler = DuressHandler(config)
    salt = secrets.token_bytes(16)
    handler.set_passwords("duress", "real", salt)

    monkeypatch.setattr(handler, "_equalize_timing", lambda: None)
    monkeypatch.setattr(handler, "_wipe_resume_files", lambda: called.__setitem__("wipe", called["wipe"] + 1))

    valid, is_duress = handler.check_password("real", salt)
    assert valid is True
    assert is_duress is False
    assert handler.was_triggered is False

    sensitive = bytearray(b"secret")
    valid, is_duress = handler.check_password("duress", salt, sensitive_data=[sensitive])
    assert valid is True
    assert is_duress is True
    assert handler.was_triggered is True
    assert called["cb"] == 1
    assert called["wipe"] == 1
    assert sensitive == bytearray(b"\x00" * len(sensitive))

    valid, is_duress = handler.check_password("wrong", salt)
    assert valid is False
    assert is_duress is False


def test_execute_emergency_response_decoy_and_panic():
    salt = secrets.token_bytes(16)

    handler_decoy = DuressHandler(DuressConfig(mode=DuressMode.DECOY))
    out = handler_decoy.execute_emergency_response([bytearray(b"abc")], salt=salt)
    assert out == generate_static_decoy(salt)

    handler_panic = DuressHandler(DuressConfig(mode=DuressMode.PANIC, panic_enabled=True))
    out = handler_panic.execute_emergency_response([bytearray(b"abc")], salt=salt)
    assert out is None


def test_get_decoy_data_message_mode():
    config = DuressConfig(decoy_type="message", decoy_message="hello", decoy_output_name="x.txt")
    handler = DuressHandler(config)

    data, filename = handler.get_decoy_data()
    assert data == b"hello"
    assert filename == "x.txt"


def test_get_decoy_data_user_file_branches(tmp_path):
    # No user file configured
    handler = DuressHandler(DuressConfig(decoy_type="user_file"))
    data, filename = handler.get_decoy_data()
    assert data == b"Error: No user file specified."
    assert filename == "error.txt"

    # Missing file
    handler = DuressHandler(DuressConfig(decoy_type="user_file", decoy_file_path="/nope.txt"))
    data, filename = handler.get_decoy_data()
    assert data == b"Operation successful."
    assert filename == "output.txt"

    # Too large file
    large = tmp_path / "large.bin"
    large.write_bytes(b"x" * (100 * 1024 * 1024 + 1))
    handler = DuressHandler(DuressConfig(decoy_type="user_file", decoy_file_path=str(large)))
    data, filename = handler.get_decoy_data()
    assert data == b"Decoy file too large."
    assert filename == "error.txt"

    # Valid user file + sanitize
    user = tmp_path / "..evil.txt"
    user.write_bytes(b"hello")
    handler = DuressHandler(DuressConfig(decoy_type="user_file", decoy_file_path=str(user), decoy_output_name="../out.txt"))
    data, filename = handler.get_decoy_data()
    assert data == b"hello"
    assert filename == "out.txt"


def test_sanitize_filename():
    assert DuressHandler.sanitize_filename(None) is None
    assert DuressHandler.sanitize_filename("../a.txt") == "a.txt"


def test_generate_deterministic_decoy():
    salt = secrets.token_bytes(16)
    out1 = generate_deterministic_decoy(128, salt)
    out2 = generate_deterministic_decoy(128, salt)
    assert out1 == out2
    assert len(out1) == 128


def test_generate_duress_decoy():
    salt = secrets.token_bytes(16)
    out1 = generate_duress_decoy(salt=salt, size=64)
    out2 = generate_duress_decoy(salt=salt, size=64)
    assert out1 == out2
    assert len(out1) == 64

    out3 = generate_duress_decoy(size=64)
    assert len(out3) == 64


def test_add_duress_args():
    parser = argparse.ArgumentParser()
    add_duress_args(parser)

    args = parser.parse_args([
        "--duress-password", "secret",
        "--duress-mode", "panic",
        "--enable-panic",
        "--duress-wipe-files",
    ])

    assert args.duress_password == "secret"
    assert args.duress_mode == "panic"
    assert args.enable_panic is True
    assert args.duress_wipe_files is True


def test_wipe_resume_files_no_dir(monkeypatch, tmp_path):
    handler = DuressHandler()

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    assert handler._wipe_resume_files() == 0


def test_wipe_resume_files_with_file(monkeypatch, tmp_path):
    handler = DuressHandler(DuressConfig(overwrite_passes=1))

    resume_dir = tmp_path / ".cache" / "meowdecoder" / "resume"
    resume_dir.mkdir(parents=True)
    resume_file = resume_dir / "state.bin"
    resume_file.write_bytes(b"data")

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    wiped = handler._wipe_resume_files()
    assert wiped == 1
    assert not resume_file.exists()
