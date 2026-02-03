#!/usr/bin/env python3
"""Coverage batch for meow_decoder.encode (remaining branches).
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


def test_encode_file_verbose_meow2_manifest_print(monkeypatch, tmp_path: Path):
    _patch_encode_pipeline(monkeypatch)

    input_path = _write_input(tmp_path)
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

    stats = enc.encode_file(input_path, out_gif, password="pw", forward_secrecy=False, verbose=True)
    assert stats["output_size"] > 0


def test_encode_file_verbose_meow4_manifest_print(monkeypatch, tmp_path: Path):
    _patch_encode_pipeline(monkeypatch)

    input_path = _write_input(tmp_path)
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

    stats = enc.encode_file(input_path, out_gif, password="pw", use_pq=True, verbose=True)
    assert stats["output_size"] > 0


def test_encode_file_verbose_forward_secrecy_pubkey_print(monkeypatch, tmp_path: Path):
    _patch_encode_pipeline(monkeypatch)

    input_path = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    def _fake_encrypt_file_bytes(**kwargs):
        return (
            b"comp",
            b"s" * 32,
            b"1" * 16,
            b"2" * 12,
            b"cipher",
            b"p" * 32,
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
        receiver_public_key=b"r" * 32,
        verbose=True,
    )
    assert stats["output_size"] > 0


def test_main_safety_checklist_import_error_exits_zero(monkeypatch):
    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name.endswith("meow_decoder.high_security"):
            raise ImportError("no module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--safety-checklist"])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0


def test_main_high_security_import_error_warning(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name.endswith("meow_decoder.high_security"):
            raise ImportError("no module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--high-security",
    ])

    enc.main()


def test_main_cat_judge_runs(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    _install_module(monkeypatch, "cat_utils", summon_cat_judge=lambda pw: "ok")
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
    ])

    enc.main()


def test_main_keyfile_loads_verbose(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"k" * 64)

    monkeypatch.setattr(enc, "verify_keyfile", lambda path: b"k" * 64)
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--keyfile", str(keyfile),
        "--verbose",
    ])

    enc.main()


def test_main_keyfile_not_found_exit(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"
    keyfile = tmp_path / "key.bin"

    def _boom(_):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(enc, "verify_keyfile", _boom)

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


def test_main_duress_prompt_empty_skips(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    pw_iter = iter(["pw", "pw", ""])
    monkeypatch.setattr(enc, "getpass", lambda prompt="": next(pw_iter))
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "--duress-password-prompt",
    ])

    enc.main()


def test_main_hsm_pin_prompted(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(enc, "getpass", lambda prompt="": "1234")
    monkeypatch.setattr(enc, "process_hardware_args", lambda *a, **k: (None, "desc"))
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hsm-slot", "1",
    ])

    enc.main()


def test_main_tpm_derive_sets_method(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(enc, "process_hardware_args", lambda *a, **k: (None, "desc"))
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--tpm-derive",
        "--tpm-seal", "0,2,7",
    ])

    enc.main()


def test_main_hardware_auto_none_key_fallback(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(enc, "process_hardware_args", lambda *a, **k: (None, "desc"))
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hardware-auto",
    ])

    enc.main()


def test_main_hardware_auto_success_verbose_prints(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(enc, "process_hardware_args", lambda *a, **k: (b"k" * 32, "desc"))
    _patch_encode_file(monkeypatch)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hardware-auto",
        "--verbose",
    ])

    enc.main()


def test_main_encode_file_exception_verbose_traceback(monkeypatch, tmp_path: Path):
    inp = _write_input(tmp_path)
    out_gif = tmp_path / "out.gif"

    def _boom(*args, **kwargs):
        raise RuntimeError("fail")

    monkeypatch.setattr(enc, "encode_file", _boom)

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--verbose",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_encode_file_secure_zero_exception_swallowed(monkeypatch, tmp_path: Path):
    _patch_encode_pipeline(monkeypatch)

    input_path = _write_input(tmp_path)
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

    class _Backend:
        def secure_zero(self, _buf):
            raise RuntimeError("zero fail")

    import meow_decoder.crypto_backend as cb

    monkeypatch.setattr(enc, "encrypt_file_bytes", _fake_encrypt_file_bytes)
    monkeypatch.setattr(enc, "compute_manifest_hmac", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")
    monkeypatch.setattr(cb, "get_default_backend", lambda: _Backend())

    stats = enc.encode_file(input_path, out_gif, password="pw", verbose=True)
    assert stats["output_size"] > 0


def test_encode_file_uses_verbose_password_only_message(monkeypatch, tmp_path: Path):
    _patch_encode_pipeline(monkeypatch)

    input_path = _write_input(tmp_path)
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

    stats = enc.encode_file(input_path, out_gif, password="pw", verbose=True)
    assert stats["output_size"] > 0


def test_main_duress_password_cli_requires_forward_secrecy(monkeypatch, tmp_path: Path):
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
