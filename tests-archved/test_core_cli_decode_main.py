from pathlib import Path
import sys

import pytest

import meow_decoder.decode_gif as dec


def test_decode_main_rejects_existing_output_without_force(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.gif"
    inp.write_bytes(b"GIF89a")

    outp = tmp_path / "out.bin"
    outp.write_bytes(b"existing")

    monkeypatch.setattr(sys, "argv", ["meow-decode-gif", "-i", str(inp), "-o", str(outp), "-p", "pw"])

    with pytest.raises(SystemExit) as e:
        dec.main()
    assert e.value.code == 1


def test_decode_main_happy_path_calls_decode_gif(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.gif"
    inp.write_bytes(b"GIF89a")

    outp = tmp_path / "out.bin"

    called = {"ok": False}

    def fake_decode_gif(*args, **kwargs):
        called["ok"] = True
        outp.write_bytes(b"data")
        return {
            "input_frames": 2,
            "qr_codes_read": 2,
            "droplets_processed": 1,
            "blocks_decoded": 1,
            "output_size": 4,
            "efficiency": 1.0,
            "elapsed_time": 0.01,
        }

    monkeypatch.setattr(dec, "decode_gif", fake_decode_gif)

    monkeypatch.setattr(sys, "argv", ["meow-decode-gif", "-i", str(inp), "-o", str(outp), "-p", "pw", "--force"])

    dec.main()
    assert called["ok"] is True
    assert outp.exists()


def test_decode_main_missing_input_file_exits(monkeypatch, tmp_path: Path):
    inp = tmp_path / "missing.gif"
    outp = tmp_path / "out.bin"

    monkeypatch.setattr(sys, "argv", ["meow-decode-gif", "-i", str(inp), "-o", str(outp), "-p", "pw"])
    with pytest.raises(SystemExit) as e:
        dec.main()
    assert e.value.code == 1


def test_decode_main_empty_password_prompt_exits(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.gif"
    inp.write_bytes(b"GIF89a")
    outp = tmp_path / "out.bin"

    monkeypatch.setattr(dec, "getpass", lambda prompt="": "")
    monkeypatch.setattr(sys, "argv", ["meow-decode-gif", "-i", str(inp), "-o", str(outp)])

    with pytest.raises(SystemExit) as e:
        dec.main()
    assert e.value.code == 1


def test_decode_main_receiver_privkey_load_error(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.gif"
    inp.write_bytes(b"GIF89a")
    outp = tmp_path / "out.bin"

    priv = tmp_path / "receiver_private.pem"
    priv.write_text("not-a-pem")

    monkeypatch.setattr(dec, "getpass", lambda prompt="": "secret")
    monkeypatch.setattr(sys, "argv", [
        "meow-decode-gif",
        "-i", str(inp),
        "-o", str(outp),
        "-p", "pw",
        "--receiver-privkey", str(priv),
    ])

    with pytest.raises(SystemExit) as e:
        dec.main()
    assert e.value.code == 1
