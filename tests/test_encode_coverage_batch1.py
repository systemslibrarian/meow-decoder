#!/usr/bin/env python3
"""Aggressive coverage batch for meow_decoder.encode.
Ported/adapted patterns from tests-archved/test_encode_main_aggressive.py and
tests-archved/test_core_cli_encode_main.py.
"""

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


def test_encode_file_duress_same_password_rejected(tmp_path):
    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    with pytest.raises(ValueError, match="Duress password cannot be the same"):
        enc.encode_file(
            input_path,
            out_gif,
            password="pw",
            duress_password="pw",
        )


def test_encode_file_duress_requires_forward_secrecy(tmp_path):
    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    with pytest.raises(ValueError, match="Duress mode requires forward secrecy"):
        enc.encode_file(
            input_path,
            out_gif,
            password="pw",
            duress_password="duress",
            forward_secrecy=False,
        )


def test_encode_file_duress_requires_pubkey_or_pq(tmp_path):
    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    with pytest.raises(ValueError, match="Duress mode requires a distinct manifest format"):
        enc.encode_file(
            input_path,
            out_gif,
            password="pw",
            duress_password="duress",
            forward_secrecy=True,
            receiver_public_key=None,
            use_pq=False,
        )


def test_encode_file_forward_secrecy_with_pubkey(monkeypatch, tmp_path):
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
            b"epk" * 10 + b"!!",
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

    assert out_gif.exists()
    assert stats["output_size"] > 0


def test_encode_file_hardware_precomputed_key_passed(monkeypatch, tmp_path):
    _patch_encode_pipeline(monkeypatch)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encrypt_file_bytes(**kwargs):
        seen["precomputed_key"] = kwargs.get("precomputed_key")
        seen["precomputed_salt"] = kwargs.get("precomputed_salt")
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

    enc.encode_file(
        input_path,
        out_gif,
        password="pw",
        hardware_key=b"k" * 32,
        hardware_salt=b"s" * 16,
    )

    assert seen["precomputed_key"] == b"k" * 32
    assert seen["precomputed_salt"] == b"s" * 16


def test_encode_file_yubikey_kwargs_passed(monkeypatch, tmp_path):
    _patch_encode_pipeline(monkeypatch)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encrypt_file_bytes(**kwargs):
        seen["yubikey_slot"] = kwargs.get("yubikey_slot")
        seen["yubikey_pin"] = kwargs.get("yubikey_pin")
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

    enc.encode_file(
        input_path,
        out_gif,
        password="pw",
        yubikey=True,
        yubikey_slot="9a",
        yubikey_pin="123456",
    )

    assert seen["yubikey_slot"] == "9a"
    assert seen["yubikey_pin"] == "123456"


def test_encode_file_manifest_hmac_uses_encryption_key(monkeypatch, tmp_path):
    _patch_encode_pipeline(monkeypatch)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    seen = {}

    def _fake_encrypt_file_bytes(**kwargs):
        return (
            b"comp",
            b"s" * 32,
            b"1" * 16,
            b"2" * 12,
            b"cipher",
            None,
            b"e" * 32,
        )

    def _fake_compute_hmac(password, salt, packed, keyfile=None, encryption_key=None, **kwargs):
        seen["encryption_key"] = encryption_key
        return b"h" * 32

    monkeypatch.setattr(enc, "encrypt_file_bytes", _fake_encrypt_file_bytes)
    monkeypatch.setattr(enc, "compute_manifest_hmac", _fake_compute_hmac)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    enc.encode_file(input_path, out_gif, password="pw")
    assert seen["encryption_key"] == b"e" * 32


def test_encode_file_secure_zero_fails_gracefully(monkeypatch, tmp_path):
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

    import meow_decoder.crypto_backend as cb
    monkeypatch.setattr(cb, "get_default_backend", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    stats = enc.encode_file(input_path, out_gif, password="pw")
    assert stats["output_size"] > 0


def test_main_about_exits_zero(monkeypatch):
    mod = types.SimpleNamespace(meow_about=lambda: "ABOUT")
    monkeypatch.setitem(sys.modules, "meow_decoder.cat_utils", mod)

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

    monkeypatch.setattr(enc, "HardwareSecurityProvider", _Provider)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--hardware-status"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0


def test_main_safety_checklist_import_error_exits_zero(monkeypatch):
    real_import = __import__

    def _fake_import(name, *args, **kwargs):
        if name == "meow_decoder.high_security":
            raise ImportError("nope")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(sys, "argv", ["meow-encode", "--safety-checklist"])
    monkeypatch.setattr(__builtins__, "__import__", _fake_import)

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0


def test_main_noninteractive_requires_password(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    class _Stdin:
        def isatty(self):
            return False

    monkeypatch.setattr(sys, "stdin", _Stdin())
    monkeypatch.setattr(sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(out_gif)])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_keyfile_validation_error(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"x")

    monkeypatch.setattr(enc, "verify_keyfile", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad")))
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


def test_main_yubikey_keyfile_conflict(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"x" * 64)

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


def test_main_duress_prompt_mismatch(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    pw = iter(["pw", "pw", "duress", "nope"])
    monkeypatch.setattr(enc, "getpass", lambda prompt="": next(pw))
    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "--duress-password-prompt",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_hardware_derivation_failure_no_fallback(monkeypatch, tmp_path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--hsm-slot", "1",
        "--hsm-pin", "1234",
        "--no-hardware-fallback",
    ])

    monkeypatch.setattr(enc, "process_hardware_args", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_nine_lives_failure_exits(monkeypatch, tmp_path):
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
    monkeypatch.setattr(enc, "encode_file", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("nope")))

    monkeypatch.setattr(sys, "argv", [
        "meow-encode",
        "-i", str(inp),
        "-o", str(out_gif),
        "-p", "pw",
        "--nine-lives",
        "--no-forward-secrecy",
    ])

    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1
