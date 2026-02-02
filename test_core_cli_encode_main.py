from pathlib import Path
import sys

import pytest

import meow_decoder.encode as enc


def test_encode_main_generate_keys_branch(monkeypatch, tmp_path: Path, capsys):
    # Patch key generation helper.
    called = {"ok": False}

    def fake_generate(out_dir: str):
        called["ok"] = True

    monkeypatch.setattr(enc, "MeowConfig", object)
    monkeypatch.setattr(enc, "EncodingConfig", object)
    import meow_decoder.x25519_forward_secrecy as fs
    monkeypatch.setattr(fs, "generate_receiver_keys_cli", fake_generate)

    monkeypatch.setattr(sys, "argv", ["meow-encode", "--generate-keys", "--key-output-dir", str(tmp_path)])
    rc = enc.main()
    assert rc == 0
    assert called["ok"] is True


def test_encode_main_rejects_missing_input(monkeypatch, tmp_path: Path):
    out_gif = tmp_path / "out.gif"
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(tmp_path / "nope.bin"), "-o", str(out_gif), "-p", "pw"])

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_password_prompt_mismatch(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    # No --password triggers getpass prompt twice.
    pw = iter(["a", "b"])
    monkeypatch.setattr(enc, "getpass", lambda prompt="": next(pw))
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(out_gif)])

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_happy_path_calls_encode_file(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    called = {"ok": False}

    def fake_encode_file(*args, **kwargs):
        called["ok"] = True
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

    monkeypatch.setattr(enc, "encode_file", fake_encode_file)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(out_gif), "-p", "pw", "--no-forward-secrecy"])

    # Should not raise.
    enc.main()
    assert called["ok"] is True


def test_encode_main_summon_void_cat_exits_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--summon-void-cat"])
    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 0


def test_encode_main_receiver_pubkey_wrong_length(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    bad_pub = tmp_path / "bad.key"
    bad_pub.write_bytes(b"X" * 31)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--receiver-pubkey", str(bad_pub),
    ])

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_receiver_pubkey_missing_file(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    missing = tmp_path / "missing.key"

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--receiver-pubkey", str(missing),
    ])

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_void_mode_forces_silent(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    called = {"verbose": None}

    def fake_encode_file(*args, **kwargs):
        called["verbose"] = kwargs.get("verbose")
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

    monkeypatch.setattr(enc, "encode_file", fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "--mode", "void",
        "-v",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert called["verbose"] is False
