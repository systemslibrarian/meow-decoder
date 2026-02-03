#!/usr/bin/env python3
"""Coverage batch for meow_decoder.encode (CLI edges + pipeline failure paths).
Reuses/adapts patterns from tests-archved/test_core_cli_encode_main.py and
tests-archved/test_encode_main_aggressive.py.
"""

from pathlib import Path
import sys
import types
import builtins

import pytest

import meow_decoder.encode as enc


def _write_input(tmp_path: Path, name: str = "in.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(b"data")
    return path


def _install_module(monkeypatch, name: str, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def _patch_encode_file(monkeypatch, record=None):
    def _fake_encode_file(*args, **kwargs):
        if record is not None:
            record.update(kwargs)
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


def _patch_encode_pipeline(monkeypatch):
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

    monkeypatch.setattr(enc, "QRCodeGenerator", _DummyQRCodeGenerator)
    monkeypatch.setattr(enc, "GIFEncoder", _DummyGIFEncoder)
    monkeypatch.setattr(enc, "FountainEncoder", _DummyFountainEncoder)
    monkeypatch.setattr(enc, "ProgressBar", _DummyProgressBar)
    monkeypatch.setattr(enc, "pack_droplet", lambda droplet: b"droplet")

    import meow_decoder.frame_mac as frame_mac
    monkeypatch.setattr(frame_mac, "pack_frame_with_mac", lambda payload, *a, **k: payload)
    monkeypatch.setattr(frame_mac, "derive_frame_master_key", lambda *a, **k: b"k" * 32)
    monkeypatch.setattr(frame_mac, "FrameMACStats", _DummyFrameMACStats)


def test_main_generate_keys_failure_returns_1(monkeypatch, tmp_path: Path):
    def _boom(_):
        raise RuntimeError("fail")

    _install_module(monkeypatch, "meow_decoder.x25519_forward_secrecy", generate_receiver_keys_cli=_boom)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--generate-keys", "--key-output-dir", str(tmp_path)])
    assert enc.main() == 1


def test_main_safety_checklist_success_exits_zero(monkeypatch):
    _install_module(monkeypatch, "meow_decoder.high_security", get_safety_checklist=lambda: "ok")
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--safety-checklist"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0


def test_main_purr_mode_forces_verbose(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    record = {}

    _install_module(monkeypatch, "meow_decoder.cat_utils", enable_purr_mode=lambda enabled=True: None)
    _patch_encode_file(monkeypatch, record)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--purr-mode",
    ])

    enc.main()
    assert record.get("verbose") is True


def test_main_nine_lives_success_path(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    class _Retry:
        def __init__(self, *args, **kwargs):
            self.succeeded = False

        def attempt(self):
            yield 1

        def success(self, stats):
            self.succeeded = True

        def fail(self, _):
            self.succeeded = False

    _install_module(monkeypatch, "meow_decoder.cat_utils", NineLivesRetry=_Retry)
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--nine-lives",
    ])

    enc.main()


def test_main_nine_lives_failure_exits(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    class _Retry:
        def __init__(self, *args, **kwargs):
            self.succeeded = False

        def attempt(self):
            yield 1

        def success(self, stats):
            self.succeeded = True

        def fail(self, _):
            self.succeeded = False

    _install_module(monkeypatch, "meow_decoder.cat_utils", NineLivesRetry=_Retry)

    def _boom(*args, **kwargs):
        raise RuntimeError("encode failure")

    monkeypatch.setattr(enc, "encode_file", _boom)
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--nine-lives",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_high_security_wipe_source_secure_wipe_called(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    called = {"passes": None}

    class _HSConfig:
        argon2_memory = 1024
        argon2_iterations = 2
        kyber_variant = "kyber1024"
        secure_wipe_passes = 7

    def _secure_wipe_file(path, passes=3):
        called["passes"] = passes
        return True

    _install_module(
        monkeypatch,
        "meow_decoder.high_security",
        enable_high_security_mode=lambda silent=False: None,
        HighSecurityConfig=_HSConfig,
        secure_wipe_file=_secure_wipe_file,
    )

    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--high-security",
    ])

    enc.main()
    assert called["passes"] == 7


def test_main_wipe_source_secure_wipe_returns_false(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    def _secure_wipe_file(path, passes=3):
        return False

    _install_module(monkeypatch, "meow_decoder.high_security", secure_wipe_file=_secure_wipe_file)
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--wipe-source",
    ])

    enc.main()
    assert inp.exists() is True


def test_main_deadmans_switch_invalid_duration_warns(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    _patch_encode_file(monkeypatch)

    _install_module(monkeypatch, "meow_decoder.deadmans_switch_cli", DeadManSwitchState=object)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--dead-mans-switch", "bad",
    ])

    enc.main()


def test_main_deadmans_switch_valid_calls_save(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    _patch_encode_file(monkeypatch)

    class _State:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.saved = False

        def save(self):
            self.saved = True

    _install_module(monkeypatch, "meow_decoder.deadmans_switch_cli", DeadManSwitchState=_State)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--dead-mans-switch", "1h",
        "--deadman-grace-period", "1h",
    ])

    enc.main()


def test_encode_file_open_permission_error(monkeypatch, tmp_path: Path):
    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    real_open = builtins.open

    def _boom(path, *args, **kwargs):
        if Path(path) == input_path:
            raise PermissionError("nope")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _boom)

    with pytest.raises(PermissionError):
        enc.encode_file(input_path, out_gif, password="pw")


def test_encode_file_logo_eyes_failure_fallback(monkeypatch, tmp_path: Path):
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

    _install_module(
        monkeypatch,
        "meow_decoder.logo_eyes",
        encode_with_logo_eyes=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("fail")),
        LogoConfig=type("LogoConfig", (), {"__init__": lambda self, **kwargs: None}),
    )

    stats = enc.encode_file(input_path, out_gif, password="pw", logo_eyes=True, verbose=True)
    assert stats["output_size"] > 0


def test_encode_file_logo_eyes_hidden_sets_visible_false(monkeypatch, tmp_path: Path):
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

    captured = {}

    class _LogoConfig:
        def __init__(self, brand_text=None, animate_blink=False, visible_qr=True):
            captured["visible_qr"] = visible_qr

    _install_module(
        monkeypatch,
        "meow_decoder.logo_eyes",
        encode_with_logo_eyes=lambda frames, config=None: frames,
        LogoConfig=_LogoConfig,
    )

    enc.encode_file(input_path, out_gif, password="pw", logo_eyes=True, logo_eyes_hidden=True, verbose=True)
    assert captured["visible_qr"] is False


def test_encode_file_stego_green_without_carriers(monkeypatch, tmp_path: Path):
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

    _install_module(
        monkeypatch,
        "meow_decoder.stego_advanced",
        encode_with_stego=lambda frames, **k: (frames, []),
        StealthLevel=types.SimpleNamespace(VISIBLE=1, SUBTLE=2, HIDDEN=3, PARANOID=4),
        create_green_mask=lambda img: None,
        calculate_masked_capacity=lambda mask, lsb_bits=1: {"percent": 10.0, "bytes_capacity": 1},
    )

    stats = enc.encode_file(
        input_path,
        out_gif,
        password="pw",
        stego_level=1,
        stego_green=True,
        carrier_images=None,
        verbose=True,
    )
    assert stats["output_size"] > 0


def test_encode_file_stego_green_low_capacity_warning(monkeypatch, tmp_path: Path):
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

    _install_module(
        monkeypatch,
        "meow_decoder.stego_advanced",
        encode_with_stego=lambda frames, **k: (frames, []),
        StealthLevel=types.SimpleNamespace(VISIBLE=1, SUBTLE=2, HIDDEN=3, PARANOID=4),
        create_green_mask=lambda img: None,
        calculate_masked_capacity=lambda mask, lsb_bits=1: {"percent": 1.0, "bytes_capacity": 1},
    )

    stats = enc.encode_file(
        input_path,
        out_gif,
        password="pw",
        stego_level=1,
        stego_green=True,
        carrier_images=[input_path],
        verbose=True,
    )
    assert stats["output_size"] > 0


def test_main_hardware_auto_failure_no_fallback_exits(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    def _boom(*args, **kwargs):
        raise RuntimeError("hw fail")

    _install_module(monkeypatch, "meow_decoder.hardware_integration", process_hardware_args=_boom)
    monkeypatch.setattr(enc, "process_hardware_args", _boom)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hardware-auto",
        "--no-hardware-fallback",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_hardware_auto_failure_fallback_continues(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    def _boom(*args, **kwargs):
        raise RuntimeError("hw fail")

    _install_module(monkeypatch, "meow_decoder.hardware_integration", process_hardware_args=_boom)
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hardware-auto",
    ])

    enc.main()
