#!/usr/bin/env python3
"""Additional coverage batch for meow_decoder.encode (Batch 2)."""

from pathlib import Path
import sys
import types

import pytest

import meow_decoder.encode as enc


class _DummyQR:
    size = (64, 64)


class _DummyQRCodeGenerator:
    def __init__(self, *args, **kwargs):
        pass

    def generate(self, payload: bytes):
        return _DummyQR()


class _DummyGIFEncoder:
    def __init__(self, *args, **kwargs):
        pass

    def create_gif(self, frames, output_path: Path, optimize: bool = True):
        output_path.write_bytes(b"GIF89a")
        return output_path.stat().st_size


class _DummyDroplet:
    def __init__(self):
        self.seed = 0
        self.block_indices = [0]
        self.data = b"x" * 4


class _DummyFountainEncoder:
    def __init__(self, *args, **kwargs):
        pass

    def droplet(self):
        return _DummyDroplet()


class _DummyProgressBar:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, it):
        return it


class _DummyFrameMACStats:
    def __init__(self):
        self.valid_frames = 0

    def record_valid(self):
        self.valid_frames += 1


def _patch_encode_pipeline(monkeypatch):
    monkeypatch.setattr(enc, "QRCodeGenerator", _DummyQRCodeGenerator)
    monkeypatch.setattr(enc, "GIFEncoder", _DummyGIFEncoder)
    monkeypatch.setattr(enc, "FountainEncoder", _DummyFountainEncoder)
    monkeypatch.setattr(enc, "ProgressBar", _DummyProgressBar)
    monkeypatch.setattr(enc, "pack_droplet", lambda droplet: b"droplet")

    import meow_decoder.frame_mac as frame_mac
    monkeypatch.setattr(frame_mac, "pack_frame_with_mac", lambda payload, *a, **k: payload)
    monkeypatch.setattr(frame_mac, "derive_frame_master_key", lambda *a, **k: b"k" * 32)
    monkeypatch.setattr(frame_mac, "FrameMACStats", _DummyFrameMACStats)


def _stats_stub():
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


def test_encode_file_duress_tag_is_computed(monkeypatch, tmp_path):
    _patch_encode_pipeline(monkeypatch)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {"duress": None, "manifest": None}

    def _fake_encrypt_file_bytes(**kwargs):
        return (
            b"comp",
            b"s" * 32,
            b"1" * 16,
            b"2" * 12,
            b"cipher",
            b"e" * 32,
            b"k" * 32,
        )

    def _fake_duress_tag(password, salt, manifest_core):
        seen["duress"] = (password, salt, manifest_core)
        return b"d" * 32

    def _fake_pack_manifest(manifest):
        seen["manifest"] = manifest
        return b"manifest"

    monkeypatch.setattr(enc, "encrypt_file_bytes", _fake_encrypt_file_bytes)
    monkeypatch.setattr(enc, "compute_duress_tag", _fake_duress_tag)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "compute_manifest_hmac", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest", _fake_pack_manifest)

    enc.encode_file(
        input_path,
        out_gif,
        password="pw",
        duress_password="duress",
        receiver_public_key=b"r" * 32,
        verbose=True,
    )

    assert seen["duress"] == ("duress", b"1" * 16, b"core")
    assert seen["manifest"].duress_tag == b"d" * 32


def test_main_cat_mode_sets_carrier_and_stego_level(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["carrier_images"] = kwargs.get("carrier_images")
        seen["stego_level"] = kwargs.get("stego_level")
        return _stats_stub()

    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--cat-mode",
        "--no-forward-secrecy",
    ])

    enc.main()

    assert seen["carrier_images"]
    assert Path(seen["carrier_images"][0]).name == "demo_logo_eyes.gif"
    assert seen["stego_level"] == 2


def test_main_purr_mode_forces_verbose(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["verbose"] = kwargs.get("verbose")
        return _stats_stub()

    mod = types.SimpleNamespace(enable_purr_mode=lambda enabled=True: object())
    monkeypatch.setitem(sys.modules, "meow_decoder.cat_utils", mod)
    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--purr-mode",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert seen["verbose"] is True


def test_main_yubikey_pin_prompted(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["yubikey"] = kwargs.get("yubikey")
        seen["yubikey_pin"] = kwargs.get("yubikey_pin")
        return _stats_stub()

    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(enc, "getpass", lambda prompt="": "1234")
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--yubikey",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert seen["yubikey"] is True
    assert seen["yubikey_pin"] == "1234"


def test_main_hardware_auto_success_passes_keys(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["hardware_key"] = kwargs.get("hardware_key")
        seen["hardware_salt"] = kwargs.get("hardware_salt")
        return _stats_stub()

    monkeypatch.setattr(enc, "process_hardware_args", lambda *a, **k: (b"k" * 32, "auto"))
    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hardware-auto",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert seen["hardware_key"] == b"k" * 32
    assert isinstance(seen["hardware_salt"], (bytes, bytearray))
    assert len(seen["hardware_salt"]) == 16


def test_main_receiver_pubkey_success(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"
    pub = tmp_path / "receiver_public.key"
    pub.write_bytes(b"r" * 32)

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["receiver_public_key"] = kwargs.get("receiver_public_key")
        return _stats_stub()

    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--receiver-pubkey", str(pub),
    ])

    enc.main()
    assert seen["receiver_public_key"] == b"r" * 32


def test_main_duress_password_cli_passed(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"
    pub = tmp_path / "receiver_public.key"
    pub.write_bytes(b"r" * 32)

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["duress_password"] = kwargs.get("duress_password")
        return _stats_stub()

    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--duress-password", "duress",
        "--receiver-pubkey", str(pub),
    ])

    enc.main()
    assert seen["duress_password"] == "duress"


def test_main_void_mode_sets_stego_level(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["stego_level"] = kwargs.get("stego_level")
        seen["verbose"] = kwargs.get("verbose")
        return _stats_stub()

    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--mode", "void",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert seen["stego_level"] == 4
    assert seen["verbose"] is False


def test_main_high_security_wipe_source(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {"passes": None}

    def _fake_encode_file(*args, **kwargs):
        return _stats_stub()

    def _secure_wipe_file(path, passes=7):
        seen["passes"] = passes
        Path(path).unlink(missing_ok=True)
        return True

    hs_mod = types.SimpleNamespace(
        enable_high_security_mode=lambda silent=False: None,
        HighSecurityConfig=lambda: types.SimpleNamespace(
            argon2_memory=1,
            argon2_iterations=1,
            kyber_variant="kyber1024",
            secure_wipe_passes=7,
        ),
        secure_wipe_file=_secure_wipe_file,
    )

    monkeypatch.setitem(sys.modules, "meow_decoder.high_security", hs_mod)
    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--high-security",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert seen["passes"] == 7
    assert not inp.exists()


def test_encode_file_use_pq_verbose(monkeypatch, tmp_path):
    _patch_encode_pipeline(monkeypatch)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    def _fake_encrypt_file_bytes(**kwargs):
        return (
            b"comp",
            b"s" * 32,
            b"1" * 16,
            b"2" * 12,
            b"cipher",
            None,
            b"k" * 32,
        )

    monkeypatch.setattr(enc, "encrypt_file_bytes", _fake_encrypt_file_bytes)
    monkeypatch.setattr(enc, "compute_manifest_hmac", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    stats = enc.encode_file(
        input_path,
        out_gif,
        password="pw",
        use_pq=True,
        verbose=True,
    )

    assert stats["output_size"] > 0


def test_main_safety_checklist_success(monkeypatch):
    hs_mod = types.SimpleNamespace(get_safety_checklist=lambda: "ok")
    monkeypatch.setitem(sys.modules, "meow_decoder.high_security", hs_mod)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--safety-checklist"])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0


def test_main_forward_secrecy_password_only_verbose(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(enc, "encode_file", lambda *a, **k: _stats_stub())
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--verbose",
    ])

    enc.main()


def test_main_forward_secrecy_disabled_pq_catnip_verbose(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(enc, "encode_file", lambda *a, **k: _stats_stub())
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--no-forward-secrecy",
        "--pq",
        "--catnip", "tuna",
        "--verbose",
    ])

    enc.main()


def test_main_cat_judge_invoked(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    called = {"ok": False}

    def _judge(_password):
        called["ok"] = True
        return "purr"

    mod = types.SimpleNamespace(summon_cat_judge=_judge)
    monkeypatch.setitem(sys.modules, "cat_utils", mod)
    monkeypatch.setattr(enc, "encode_file", lambda *a, **k: _stats_stub())
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert called["ok"] is True


def test_main_hardware_auto_returns_none(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["hardware_key"] = kwargs.get("hardware_key")
        seen["hardware_salt"] = kwargs.get("hardware_salt")
        return _stats_stub()

    monkeypatch.setattr(enc, "process_hardware_args", lambda *a, **k: (None, "auto"))
    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hardware-auto",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert seen["hardware_key"] is None
    assert seen["hardware_salt"] is None


def test_main_hardware_auto_exception_fallback(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["hardware_key"] = kwargs.get("hardware_key")
        seen["hardware_salt"] = kwargs.get("hardware_salt")
        return _stats_stub()

    monkeypatch.setattr(enc, "process_hardware_args", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hardware-auto",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert seen["hardware_key"] is None
    assert seen["hardware_salt"] is None


def test_main_duress_password_prompt_success(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encode_file(*args, **kwargs):
        seen["duress_password"] = kwargs.get("duress_password")
        return _stats_stub()

    pw = iter(["duress", "duress"])
    monkeypatch.setattr(enc, "encode_file", _fake_encode_file)
    monkeypatch.setattr(enc, "getpass", lambda prompt="": next(pw))
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--duress-password-prompt",
        "--receiver-pubkey", str(tmp_path / "receiver_public.key"),
    ])

    (tmp_path / "receiver_public.key").write_bytes(b"r" * 32)

    enc.main()
    assert seen["duress_password"] == "duress"


def test_main_input_is_directory_exits(monkeypatch, tmp_path):
    inp = tmp_path / "dir"
    inp.mkdir()
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_yubikey_with_receiver_pubkey_conflict(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"
    pub = tmp_path / "receiver_public.key"
    pub.write_bytes(b"r" * 32)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--receiver-pubkey", str(pub),
        "--yubikey",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_wipe_source_fallback_import_error(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    import builtins
    real_import = __import__

    def _fake_import(name, *args, **kwargs):
        if name == "meow_decoder.high_security":
            raise ImportError("nope")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(enc, "encode_file", lambda *a, **k: _stats_stub())
    monkeypatch.setattr(builtins, "__import__", _fake_import)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--wipe-source",
        "--no-forward-secrecy",
    ])

    enc.main()
    assert not inp.exists()


def test_main_error_during_encoding_verbose(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(enc, "encode_file", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--verbose",
        "--no-forward-secrecy",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_nine_lives_success(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    class _Retry:
        def __init__(self, max_lives=9, verbose=True):
            self.succeeded = False

        def attempt(self):
            for _ in range(1):
                yield 1

        def success(self, *a, **k):
            self.succeeded = True

        def fail(self, *a, **k):
            self.succeeded = False

    mod = types.SimpleNamespace(NineLivesRetry=_Retry)
    monkeypatch.setitem(sys.modules, "meow_decoder.cat_utils", mod)
    monkeypatch.setattr(enc, "encode_file", lambda *a, **k: _stats_stub())
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--nine-lives",
        "--no-forward-secrecy",
    ])

    enc.main()
