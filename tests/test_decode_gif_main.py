#!/usr/bin/env python3
"""CLI coverage tests for meow_decoder.decode_gif main()."""

from pathlib import Path
from unittest.mock import patch

import pytest

import meow_decoder.decode_gif as decode_mod


def test_main_help_exits():
    with patch("sys.argv", ["meow-decode-gif", "--help"]):
        with pytest.raises(SystemExit) as exc:
            decode_mod.main()
        assert exc.value.code == 0


def test_main_about_exits(monkeypatch):
    monkeypatch.setattr("meow_decoder.cat_utils.meow_about", lambda: "meow", raising=False)
    with patch("sys.argv", ["meow-decode-gif", "--about"]):
        with pytest.raises(SystemExit) as exc:
            decode_mod.main()
        assert exc.value.code == 0


def test_main_hardware_status_exits(monkeypatch):
    class _Caps:
        def summary(self):
            return "ok"

    class _Provider:
        def __init__(self, verbose=False):
            self.verbose = verbose

        def detect_all(self):
            return _Caps()

    monkeypatch.setattr(decode_mod, "HardwareSecurityProvider", _Provider)
    with patch("sys.argv", ["meow-decode-gif", "--hardware-status"]):
        with pytest.raises(SystemExit) as exc:
            decode_mod.main()
        assert exc.value.code == 0


def test_main_missing_args_exits():
    with patch("sys.argv", ["meow-decode-gif"]):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_input_missing_exits(tmp_path):
    out_path = tmp_path / "out.txt"
    with patch(
        "sys.argv",
        ["meow-decode-gif", "-i", "missing.gif", "-o", str(out_path), "-p", "password123"],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_input_is_directory_exits(tmp_path):
    input_path = tmp_path / "dir"
    input_path.mkdir()
    output_path = tmp_path / "out.txt"

    with patch(
        "sys.argv",
        ["meow-decode-gif", "-i", str(input_path), "-o", str(output_path), "-p", "password123"],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_output_exists_without_force(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    output_path.write_text("exists")

    with patch(
        "sys.argv",
        ["meow-decode-gif", "-i", str(input_path), "-o", str(output_path), "-p", "password123"],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_empty_password_exits(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    with patch(
        "sys.argv", ["meow-decode-gif", "-i", str(input_path), "-o", str(output_path), "-p", ""]
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_success_calls_decode(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    def _fake_decode(*args, **kwargs):
        return {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        }

    monkeypatch.setattr(decode_mod, "decode_gif", _fake_decode)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
        ],
    ):
        decode_mod.main()


def test_main_password_prompt_path(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )
    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "password123")

    with patch(
        "sys.argv", ["meow-decode-gif", "-i", str(input_path), "-o", str(output_path), "--force"]
    ):
        decode_mod.main()


def test_main_receiver_privkey_invalid(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "bad_priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--receiver-privkey",
            str(privkey_path),
            "--receiver-privkey-password",
            "pass",
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_keyfile_error_exits(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "verify_keyfile",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad")),
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--keyfile",
            str(tmp_path / "missing.bin"),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_keyfile_verbose_load(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"keyfile")

    monkeypatch.setattr(decode_mod, "verify_keyfile", lambda *args, **kwargs: b"K" * 32)
    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--verbose",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        decode_mod.main()


def test_main_purr_mode_nine_lives_success(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        "meow_decoder.cat_utils.enable_purr_mode", lambda enabled=True: None, raising=False
    )

    class _Retry:
        def __init__(self, max_lives=9, verbose=True):
            self.succeeded = False

        def attempt(self):
            yield 1

        def success(self, stats):
            self.succeeded = True

        def fail(self, msg):
            pass

    monkeypatch.setattr("meow_decoder.cat_utils.NineLivesRetry", _Retry, raising=False)
    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--purr-mode",
            "--nine-lives",
        ],
    ):
        decode_mod.main()


def test_main_hsm_slot_branch(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )
    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "1234")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--hsm-slot",
            "1",
        ],
    ):
        decode_mod.main()


def test_main_hsm_slot_with_keyfile_error(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"K" * 32)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--hsm-slot",
            "1",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_tpm_derive_branch(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--tpm-derive",
        ],
    ):
        decode_mod.main()


def test_main_tpm_receiver_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--tpm-derive",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_hardware_auto_branch(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--hardware-auto",
        ],
    ):
        decode_mod.main()


def test_main_hardware_auto_with_keyfile_error(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"K" * 32)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--hardware-auto",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_yubikey_conflicts(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"K" * 32)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--yubikey",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_yubikey_receiver_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--yubikey",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_yubikey_pin_prompt(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )
    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "1234")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--yubikey",
        ],
    ):
        decode_mod.main()


def test_main_duress_config_passed(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    captured = {}

    def _fake_decode(*args, **kwargs):
        captured.update(kwargs)
        return {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        }

    monkeypatch.setattr(decode_mod, "decode_gif", _fake_decode)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--duress-mode",
            "panic",
            "--enable-panic",
        ],
    ):
        decode_mod.main()

    assert "duress_config" in captured


def test_main_decode_exception_verbose(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    def _fail(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(decode_mod, "decode_gif", _fail)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--verbose",
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_receiver_privkey_success(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    privkey = X25519PrivateKey.generate()
    privkey_pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_bytes(privkey_pem)

    monkeypatch.setattr(
        decode_mod,
        "decode_gif",
        lambda *args, **kwargs: {
            "input_frames": 1,
            "qr_codes_read": 1,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.1,
        },
    )
    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--receiver-privkey",
            str(privkey_path),
            "--verbose",
        ],
    ):
        decode_mod.main()


def test_main_hsm_receiver_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--hsm-slot",
            "1",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_tpm_keyfile_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    keyfile_path = tmp_path / "keyfile.bin"
    keyfile_path.write_bytes(b"K" * 32)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--tpm-derive",
            "--keyfile",
            str(keyfile_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_hardware_auto_receiver_conflict(tmp_path):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "priv.pem"
    privkey_path.write_text("not-a-key")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--hardware-auto",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_receiver_privkey_wrong_type(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    privkey = Ed25519PrivateKey.generate()
    privkey_pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    privkey_path = tmp_path / "ed.pem"
    privkey_path.write_bytes(privkey_pem)

    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--receiver-privkey",
            str(privkey_path),
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_receiver_privkey_invalid_verbose(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"
    privkey_path = tmp_path / "bad_priv.pem"
    privkey_path.write_text("not-a-key")

    monkeypatch.setattr(decode_mod, "getpass", lambda *args, **kwargs: "")

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--receiver-privkey",
            str(privkey_path),
            "--verbose",
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()


def test_main_module_entrypoint_help():
    import runpy
    import sys

    with patch.object(sys, "argv", ["meow-decode-gif", "--help"]):
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("meow_decoder.decode_gif", run_name="__main__")
        assert exc.value.code == 0


def test_main_nine_lives_failure(tmp_path, monkeypatch):
    input_path = tmp_path / "in.gif"
    input_path.write_bytes(b"GIF89a")
    output_path = tmp_path / "out.txt"

    class _Retry:
        def __init__(self, max_lives=9, verbose=True):
            self.succeeded = False

        def attempt(self):
            yield 1

        def success(self, stats):
            self.succeeded = False

        def fail(self, msg):
            pass

    def _fail(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("meow_decoder.cat_utils.NineLivesRetry", _Retry, raising=False)
    monkeypatch.setattr(decode_mod, "decode_gif", _fail)

    with patch(
        "sys.argv",
        [
            "meow-decode-gif",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "-p",
            "password123",
            "--force",
            "--nine-lives",
        ],
    ):
        with pytest.raises(SystemExit):
            decode_mod.main()
