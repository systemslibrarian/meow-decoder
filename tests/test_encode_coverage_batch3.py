#!/usr/bin/env python3
"""Coverage batch for meow_decoder.encode (CLI validation + error paths).
Ported/adapted patterns from tests-archved/test_core_cli_encode_main.py and
tests-archved/test_encode_main_aggressive.py.
"""

from pathlib import Path
import sys
import types

import pytest

import meow_decoder.encode as enc


def _install_module(monkeypatch, name: str, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def _write_input(tmp_path: Path, name: str = "in.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(b"data")
    return path


def _patch_encode_file(monkeypatch):
    def _fake_encode_file(*args, **kwargs):
        return {
            "input_size": 4,
            "compressed_size": 4,
            "encrypted_size": 4,
            "output_size": 10,
            "compression_ratio": 1.0,
            "k_blocks": 1,
            "num_droplets": 1,
            "redundancy": 1.5,
            "qr_frames": 1,
            "qr_size": (64, 64),
            "gif_duration": 0.1,
            "elapsed_time": 0.01,
        }

    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)


def test_main_about_exits_zero(monkeypatch):
    _install_module(monkeypatch, "meow_decoder.cat_utils", meow_about=lambda: "about")
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--about"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0


def test_main_hardware_status_exits_zero(monkeypatch):
    class _Caps:
        def summary(self):
            return "ok"

    class _Provider:
        def __init__(self, verbose=False):
            self.verbose = verbose

        def detect_all(self):
            return _Caps()

    _install_module(monkeypatch, "meow_decoder.hardware_integration", HardwareSecurityProvider=_Provider)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--hardware-status"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0


def test_main_non_tty_requires_password(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    class _StdIn:
        def isatty(self):
            return False

    monkeypatch.setattr(sys, "stdin", _StdIn())
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(out_gif)])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_empty_password_arg_rejected(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_duress_password_prompt_mismatch(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    pw_iter = iter(["pass", "pass", "duress1", "duress2"])
    monkeypatch.setattr(enc, "getpass", lambda prompt="": next(pw_iter))
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "--duress-password-prompt",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_duress_password_same_as_password_arg(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "samepw",
        "--duress-password", "samepw",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_duress_password_requires_forward_secrecy(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--duress-password", "duress",
        "--no-forward-secrecy",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_receiver_pubkey_valid_passed_to_encode(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    pub = tmp_path / "receiver_public.key"
    pub.write_bytes(b"k" * 32)

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["receiver_public_key"] = kwargs.get("receiver_public_key")
        return {
            "input_size": 4,
            "compressed_size": 4,
            "encrypted_size": 4,
            "output_size": 10,
            "compression_ratio": 1.0,
            "k_blocks": 1,
            "num_droplets": 1,
            "redundancy": 1.5,
            "qr_frames": 1,
            "qr_size": (64, 64),
            "gif_duration": 0.1,
            "elapsed_time": 0.01,
        }

    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--receiver-pubkey", str(pub),
    ])

    enc.main()
    assert seen["receiver_public_key"] == b"k" * 32


def test_main_keyfile_too_small_exits(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"123")

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--keyfile", str(keyfile),
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_yubikey_with_keyfile_exits(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"k" * 64)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--keyfile", str(keyfile),
        "--yubikey",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_yubikey_with_receiver_pubkey_exits(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    pub = tmp_path / "receiver_public.key"
    pub.write_bytes(b"k" * 32)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--yubikey",
        "--receiver-pubkey", str(pub),
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_hsm_with_keyfile_exits(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"k" * 64)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--keyfile", str(keyfile),
        "--hsm-slot", "1",
        "--hsm-pin", "1234",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_tpm_with_keyfile_exits(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"k" * 64)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--keyfile", str(keyfile),
        "--tpm-derive",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_hardware_auto_with_receiver_pubkey_exits(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    pub = tmp_path / "receiver_public.key"
    pub.write_bytes(b"k" * 32)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hardware-auto",
        "--receiver-pubkey", str(pub),
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_yubikey_pin_prompt_sets_pin(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(enc, "getpass", lambda prompt="": "123456")
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--yubikey",
    ])

    enc.main()
    assert enc.argparse is not None


def test_main_missing_input_output_errors(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--password", "pw"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 2
