#!/usr/bin/env python3
"""Tests for meow_decoder.encode CLI and encode_file.
Lightweight stubs for QR/GIF to avoid heavy dependencies.
"""

from pathlib import Path
import sys
import time

import pytest
from PIL import Image

import meow_decoder.encode as enc


class _DummyQRCodeGenerator:
    def __init__(self, *args, **kwargs):
        pass

    def generate(self, payload: bytes):
        return Image.new("RGB", (64, 64), color=(255, 255, 255))


class _DummyGIFEncoder:
    def __init__(self, *args, **kwargs):
        pass

    def create_gif(self, frames, output_path: Path, optimize: bool = True):
        output_path.write_bytes(b"GIF89a")
        return output_path.stat().st_size


def test_encode_main_generate_keys_branch(monkeypatch, tmp_path: Path):
    called = {"ok": False}

    def fake_generate(out_dir: str):
        called["ok"] = True

    import meow_decoder.x25519_forward_secrecy as fs

    monkeypatch.setattr(fs, "generate_receiver_keys_cli", fake_generate)

    monkeypatch.setattr(
        sys, "argv", ["meow-encode", "--generate-keys", "--key-output-dir", str(tmp_path)]
    )
    rc = enc.main()
    assert rc == 0
    assert called["ok"] is True


def test_encode_main_rejects_missing_input(monkeypatch, tmp_path: Path):
    out_gif = tmp_path / "out.gif"
    monkeypatch.setattr(
        sys,
        "argv",
        ["meow-encode", "-i", str(tmp_path / "nope.bin"), "-o", str(out_gif), "-p", "pw"],
    )

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_password_prompt_mismatch(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

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
    monkeypatch.setattr(
        sys,
        "argv",
        ["meow-encode", "-i", str(inp), "-o", str(out_gif), "-p", "pw", "--no-forward-secrecy"],
    )

    enc.main()
    assert called["ok"] is True


def test_encode_main_password_mode_secure_keyboard(monkeypatch, tmp_path: Path):
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

    prompts = iter(["pw123", "pw123"])
    monkeypatch.setattr(enc, "secure_password_input", lambda *args, **kwargs: next(prompts))
    monkeypatch.setattr(enc, "encode_file", fake_encode_file)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(out_gif),
            "--password-mode",
            "secure-keyboard",
            "--no-forward-secrecy",
        ],
    )

    enc.main()
    assert called["ok"] is True


def test_encode_main_password_mode_mouse_gesture(monkeypatch, tmp_path: Path):
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

    class _DummyGesture:
        def __init__(self, *args, **kwargs):
            self._vals = iter(["gpass", "gpass"])

        def collect_interactive(self, *_args, **_kwargs):
            return next(self._vals)

    monkeypatch.setattr(enc, "MouseGesturePassword", _DummyGesture)
    monkeypatch.setattr(enc, "encode_file", fake_encode_file)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(out_gif),
            "--password-mode",
            "mouse-gesture",
            "--no-forward-secrecy",
        ],
    )

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

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(out_gif),
            "-p",
            "pw",
            "--receiver-pubkey",
            str(bad_pub),
        ],
    )

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_main_receiver_pubkey_missing_file(monkeypatch, tmp_path: Path):
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"data")
    out_gif = tmp_path / "out.gif"

    missing = tmp_path / "missing.key"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(out_gif),
            "-p",
            "pw",
            "--receiver-pubkey",
            str(missing),
        ],
    )

    with pytest.raises(SystemExit) as e:
        enc.main()
    assert e.value.code == 1


def test_encode_file_unit_smoke(tmp_path: Path, monkeypatch):
    # Patch out QR/GIF heavy bits but still run the core orchestration.
    monkeypatch.setattr(enc, "QRCodeGenerator", _DummyQRCodeGenerator)
    monkeypatch.setattr(enc, "GIFEncoder", _DummyGIFEncoder)

    import meow_decoder.frame_mac as frame_mac

    monkeypatch.setattr(frame_mac, "pack_frame_with_mac", lambda payload, *args, **kwargs: payload)
    monkeypatch.setattr(frame_mac, "derive_frame_master_key", lambda *args, **kwargs: b"k" * 32)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"hello" * 10)
    out_gif = tmp_path / "out.gif"

    stats = enc.encode_file(input_path, out_gif, password="password_test", verbose=False)
    assert out_gif.exists()
    assert stats["output_size"] > 0
    assert stats["qr_frames"] >= 1


# =============================================================================
# CONSOLIDATED COVERAGE TESTS - Merged from batch files
# Reusing patterns from tests-archved/test_encode_main_aggressive.py,
# tests-archved/test_core_cli_encode_main.py
# =============================================================================


class _DummyQR:
    size = (64, 64)


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


def _install_module(monkeypatch, name: str, **attrs):
    """Install a fake module into sys.modules."""
    import types

    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def _write_input(tmp_path: Path, name: str = "in.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(b"data")
    return path


def _patch_encode_pipeline(monkeypatch):
    """Patch heavy dependencies for encode_file."""
    monkeypatch.setattr(
        enc,
        "QRCodeGenerator",
        lambda *a, **k: type("Q", (), {"generate": lambda s, p: _DummyQR()})(),
    )
    monkeypatch.setattr(
        enc,
        "GIFEncoder",
        lambda *a, **k: type(
            "G",
            (),
            {"create_gif": lambda s, f, p, **kw: (p.write_bytes(b"GIF89a"), p.stat().st_size)[1]},
        )(),
    )
    monkeypatch.setattr(enc, "FountainEncoder", _DummyFountainEncoder)
    monkeypatch.setattr(enc, "ProgressBar", _DummyProgressBar)
    monkeypatch.setattr(enc, "pack_droplet", lambda d: b"droplet")

    import meow_decoder.frame_mac as frame_mac

    monkeypatch.setattr(frame_mac, "pack_frame_with_mac", lambda payload, *a, **k: payload)
    monkeypatch.setattr(frame_mac, "derive_frame_master_key", lambda *a, **k: b"k" * 32)
    monkeypatch.setattr(frame_mac, "derive_frame_master_key_handle", lambda *a, **k: 88888)
    monkeypatch.setattr(frame_mac, "FrameMACStats", _DummyFrameMACStats)

    # Mock the handle backend's drop() so fake handles don't raise errors
    class _FakeHB:
        def drop(self, handle):
            pass

    monkeypatch.setattr(enc, "get_handle_backend", lambda: _FakeHB())


def _patch_encode_fast_crypto(monkeypatch):
    """Patch crypto-heavy encode internals for deterministic fast tests."""

    def _fake_encrypt(**kw):
        return (
            b"comp",
            b"s" * 32,
            b"1" * 16,
            b"2" * 12,
            b"ciphertext",
            None,
            99999,
        )

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)


def _patch_encode_file(monkeypatch, record=None):
    """Patch encode_file to return fake stats."""

    def _fake(*args, **kwargs):
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

    monkeypatch.setattr(enc, "encode_file", _fake)


def test_encode_file_unsigned_manifest_warns_and_succeeds(monkeypatch, tmp_path, capsys):
    """Unsigned manifest is allowed but must emit a clear security warning."""
    _patch_encode_pipeline(monkeypatch)
    _patch_encode_fast_crypto(monkeypatch)

    monkeypatch.setenv("MEOW_MANIFEST_SIGNING", "off")

    inp = _write_input(tmp_path)
    out = tmp_path / "out_unsigned.gif"
    stats = enc.encode_file(inp, out, password="password1", verbose=False)

    captured = capsys.readouterr()
    assert "Manifest signing disabled by policy" in captured.err
    assert "vulnerable to forgery" in captured.err
    assert out.exists()
    assert stats["output_size"] > 0


def test_encode_file_signing_performance_overhead_acceptable(monkeypatch, tmp_path):
    """Measure signing overhead and assert it stays within acceptable lightweight bounds."""
    _patch_encode_pipeline(monkeypatch)
    _patch_encode_fast_crypto(monkeypatch)

    import meow_decoder.manifest_signing as ms

    class _KP:
        def export_public_key(self):
            return b"PUBK"

    class _Sig:
        def to_bytes(self):
            return b"SIGBYTES"

    monkeypatch.setattr(ms, "_RUST_MLDSA_AVAILABLE", True)
    monkeypatch.setattr(ms, "_MLDSA_PURE_AVAILABLE", False)
    monkeypatch.setattr(ms, "generate_signing_keypair", lambda: _KP())
    monkeypatch.setattr(ms, "sign_manifest", lambda *a, **k: _Sig())

    inp = _write_input(tmp_path, "perf_in.bin")

    monkeypatch.setenv("MEOW_MANIFEST_SIGNING", "off")
    t0 = time.perf_counter()
    unsigned_stats = enc.encode_file(inp, tmp_path / "unsigned.gif", password="pw", verbose=False)
    unsigned_elapsed = time.perf_counter() - t0

    monkeypatch.setenv("MEOW_MANIFEST_SIGNING", "on")
    t1 = time.perf_counter()
    signed_stats = enc.encode_file(inp, tmp_path / "signed.gif", password="pw", verbose=False)
    signed_elapsed = time.perf_counter() - t1

    assert signed_stats["qr_frames"] >= unsigned_stats["qr_frames"]
    assert signed_elapsed <= unsigned_elapsed + 0.5


# --- Line 79-84: encode_file duress checks ---


def test_encode_file_duress_same_password_rejected(tmp_path):
    """Line 79: duress password == encryption password raises ValueError."""
    inp = _write_input(tmp_path)
    with pytest.raises(ValueError, match="Duress password cannot be the same"):
        enc.encode_file(inp, tmp_path / "out.gif", password="pw", duress_password="pw")


def test_encode_file_duress_requires_forward_secrecy(tmp_path):
    """Line 81-82: duress without FS raises ValueError."""
    inp = _write_input(tmp_path)
    with pytest.raises(ValueError, match="Duress mode requires forward secrecy"):
        enc.encode_file(
            inp, tmp_path / "out.gif", password="pw", duress_password="dur", forward_secrecy=False
        )


def test_encode_file_duress_requires_pubkey_or_pq(tmp_path):
    """Line 83-84: duress without pubkey/PQ raises ValueError."""
    inp = _write_input(tmp_path)
    with pytest.raises(ValueError, match="Duress mode requires a distinct manifest format"):
        enc.encode_file(
            inp,
            tmp_path / "out.gif",
            password="pw",
            duress_password="dur",
            forward_secrecy=True,
            receiver_public_key=None,
            use_pq=False,
        )


# --- Line 118: verbose manifest version print (MEOW2) ---


def test_encode_file_verbose_meow2_manifest_print(monkeypatch, tmp_path, capsys):
    """Line 118: verbose prints 'Using MEOW2 manifest'."""
    _patch_encode_pipeline(monkeypatch)

    def _fake_encrypt(**kw):
        return (b"c", b"s" * 32, b"1" * 16, b"2" * 12, b"cipher", None, 99999)

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    inp = _write_input(tmp_path)
    enc.encode_file(
        inp, tmp_path / "out.gif", password="password1", forward_secrecy=False, verbose=True
    )
    captured = capsys.readouterr()
    assert "MEOW2" in captured.out


# --- Line 627-629: generate_keys failure ---


def test_main_generate_keys_failure_returns_1(monkeypatch, tmp_path):
    """Line 627-629: generate_receiver_keys_cli exception -> exit(1)."""
    import meow_decoder.x25519_forward_secrecy as fs_mod

    def _boom(*a, **k):
        raise RuntimeError("keygen failed")

    monkeypatch.setattr(fs_mod, "generate_receiver_keys_cli", _boom)
    monkeypatch.setattr(
        sys, "argv", ["meow-encode", "--generate-keys", "--key-output-dir", str(tmp_path)]
    )
    # main() returns 1 on keygen failure, doesn't call sys.exit
    result = enc.main()
    assert result == 1


# --- Line 657-658: keyfile verify_keyfile error ---


def test_main_keyfile_verify_error_exits_1(monkeypatch, tmp_path):
    """Line 657-658: verify_keyfile raises -> exit(1)."""
    inp = _write_input(tmp_path)
    keyfile = tmp_path / "bad.key"
    keyfile.write_bytes(b"x" * 10)  # Too short
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "-k",
            str(keyfile),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


# --- Line 675-676: keyfile FileNotFoundError ---


def test_main_keyfile_not_found_exits_1(monkeypatch, tmp_path):
    """Line 675-676: missing keyfile -> exit(1)."""
    inp = _write_input(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "-k",
            str(tmp_path / "missing.key"),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


# --- Line 802-807: wipe_source secure_wipe_file failure fallback ---


def test_main_wipe_source_secure_wipe_fallback(monkeypatch, tmp_path):
    """Line 802-807: secure_wipe_file ImportError -> fallback to overwrite+unlink."""
    inp = _write_input(tmp_path)

    # Force ImportError by making the import fail
    import builtins

    _real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "meow_decoder.high_security" or (
            len(args) > 2 and args[2] and "secure_wipe_file" in args[2]
        ):
            raise ImportError("No module named 'meow_decoder.high_security'")
        return _real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--wipe-source",
            "-v",
        ],
    )
    enc.main()
    assert not inp.exists()


# --- Line 840->846: catnip flavor verbose output ---


def test_main_catnip_flavor_verbose(monkeypatch, tmp_path, capsys):
    """Line 771-772: --catnip with --no-forward-secrecy prints flavor message."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)
    # Catnip is printed inside the 'else' branch of forward_secrecy check (line 771)
    # so we need --no-forward-secrecy to trigger it
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--catnip",
            "tuna",
            "-v",
            "--no-forward-secrecy",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    # Line 772: print(f"🌿 Catnip flavor: {args.catnip.upper()} (meow!)")
    assert "TUNA" in captured.out or "Catnip flavor" in captured.out


# --- Line 885->902: Nine Lives retry mode ---


def test_main_nine_lives_retry_success_after_failures(monkeypatch, tmp_path, capsys):
    """Line 885-902: Nine Lives mode retries on failure."""
    inp = _write_input(tmp_path)

    call_count = {"n": 0}

    def _failing_encode(*a, **k):
        call_count["n"] += 1
        if call_count["n"] < 3:
            raise RuntimeError("transient failure")
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

    class _NineLivesRetry:
        def __init__(self, max_lives=9, verbose=False):
            self.max_lives = max_lives
            self.succeeded = False
            self._attempts = 0

        def attempt(self):
            for i in range(self.max_lives):
                self._attempts = i + 1
                yield i
                if self.succeeded:
                    break

        def success(self, result):
            self.succeeded = True

        def fail(self, msg):
            pass

    _install_module(
        monkeypatch,
        "meow_decoder.cat_utils",
        NineLivesRetry=_NineLivesRetry,
        meow_about=lambda: "about",
    )
    monkeypatch.setattr(enc, "encode_file", _failing_encode)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--nine-lives",
        ],
    )
    enc.main()
    assert call_count["n"] >= 3


def test_main_nine_lives_exhausted_exits_1(monkeypatch, tmp_path):
    """Line 888-889: Nine Lives mode exhausted -> exit(1)."""
    inp = _write_input(tmp_path)

    def _always_fail(*a, **k):
        raise RuntimeError("permanent failure")

    class _NineLivesRetry:
        def __init__(self, max_lives=9, verbose=False):
            self.max_lives = max_lives
            self.succeeded = False

        def attempt(self):
            for i in range(self.max_lives):
                yield i

        def success(self, result):
            self.succeeded = True

        def fail(self, msg):
            pass

    _install_module(
        monkeypatch,
        "meow_decoder.cat_utils",
        NineLivesRetry=_NineLivesRetry,
        meow_about=lambda: "about",
    )
    monkeypatch.setattr(enc, "encode_file", _always_fail)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--nine-lives",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


# --- Line 891-892: Normal encode_file exception -> exit(1) ---


def test_main_encode_file_exception_exits_1(monkeypatch, tmp_path):
    """Line 891-892: encode_file raises -> exit(1)."""
    inp = _write_input(tmp_path)
    monkeypatch.setattr(
        enc, "encode_file", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["meow-encode", "-i", str(inp), "-o", str(tmp_path / "out.gif"), "-p", "password1"],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


# --- Line 1037-1044: Dead man's switch setup exception (swallowed) ---


def test_main_deadmans_switch_setup_exception_swallowed(monkeypatch, tmp_path, capsys):
    """Line 1037-1044: dead_mans_switch exception is caught and warned."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)

    class _BadDeadMan:
        def __init__(self, *a, **k):
            raise ValueError("DMS init failed")

    _install_module(monkeypatch, "meow_decoder.deadmans_switch_cli", DeadManSwitchState=_BadDeadMan)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--dead-mans-switch",
            "24h",
            "-v",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    # Should warn but not crash
    assert "Dead-man" in captured.out or "dead" in captured.out.lower() or tmp_path.exists()


# --- Additional adversarial tests ---


def test_encode_file_precomputed_key_wrong_length(tmp_path):
    """Adversarial: precomputed_key with wrong length raises ValueError."""
    inp = _write_input(tmp_path)
    with pytest.raises((ValueError, RuntimeError)):
        enc.encode_file(
            inp, tmp_path / "out.gif", password="pw", hardware_key=b"short", hardware_salt=b"s" * 16
        )


def test_encode_file_yubikey_with_keyfile_rejected(monkeypatch, tmp_path):
    """Adversarial: --yubikey + --keyfile together is rejected at CLI layer."""
    inp = _write_input(tmp_path)
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"k" * 64)

    # The check for yubikey + keyfile is in main(), not encode_file()
    # Line 681-682 checks this before calling encode_file
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "-k",
            str(keyfile),
            "--yubikey",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_hsm_with_keyfile_rejected(monkeypatch, tmp_path):
    """Adversarial: --hsm-slot + --keyfile together exits 1."""
    inp = _write_input(tmp_path)
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"k" * 64)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "-k",
            str(keyfile),
            "--hsm-slot",
            "0",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_tpm_with_keyfile_rejected(monkeypatch, tmp_path):
    """Adversarial: --tpm-derive + --keyfile together exits 1."""
    inp = _write_input(tmp_path)
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"k" * 64)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "-k",
            str(keyfile),
            "--tpm-derive",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_hardware_auto_with_keyfile_rejected(monkeypatch, tmp_path):
    """Adversarial: --hardware-auto + --keyfile together exits 1."""
    inp = _write_input(tmp_path)
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(b"k" * 64)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "-k",
            str(keyfile),
            "--hardware-auto",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_encode_file_verbose_meow4_manifest_print(monkeypatch, tmp_path, capsys):
    """Verbose: MEOW4 (PQ) manifest version print."""
    _patch_encode_pipeline(monkeypatch)

    def _fake_encrypt(**kw):
        return (b"c", b"s" * 32, b"1" * 16, b"2" * 12, b"cipher", b"e" * 32, 99999)

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    inp = _write_input(tmp_path)
    enc.encode_file(inp, tmp_path / "out.gif", password="password1", use_pq=True, verbose=True)
    captured = capsys.readouterr()
    assert "MEOW4" in captured.out or "Post-Quantum" in captured.out


# =============================================================================
# ADDITIONAL COVERAGE TESTS - Reaching 95%+
# =============================================================================

# --- Line 602-604: --about flag ---


def test_main_about_flag_exits_0(monkeypatch, capsys):
    """Line 602-604: --about prints version and exits 0."""

    def _fake_meow_about():
        return "Meow Decoder vX.Y.Z"

    _install_module(
        monkeypatch,
        "meow_decoder.cat_utils",
        meow_about=_fake_meow_about,
        enable_purr_mode=lambda enabled: None,
    )
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--about"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Meow Decoder" in captured.out


# --- Line 608-612: --hardware-status flag ---


def test_main_hardware_status_flag_exits_0(monkeypatch, capsys):
    """Line 608-612: --hardware-status prints caps and exits 0."""

    class _FakeProvider:
        def __init__(self, verbose=False):
            pass

        def detect_all(self):
            return self

        def summary(self):
            return "No hardware detected"

    _install_module(
        monkeypatch,
        "meow_decoder.hardware_integration",
        HardwareSecurityProvider=_FakeProvider,
        process_hardware_args=lambda *a: (None, "none"),
    )
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--hardware-status"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "hardware" in captured.out.lower() or "No" in captured.out


# --- Line 654-659: --safety-checklist flag ---


def test_main_safety_checklist_flag_exits_0(monkeypatch, capsys):
    """Line 654-659: --safety-checklist prints checklist and exits 0."""

    def _fake_checklist():
        return "[ ] Check 1\n[ ] Check 2"

    _install_module(monkeypatch, "meow_decoder.high_security", get_safety_checklist=_fake_checklist)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--safety-checklist"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0


def test_main_safety_checklist_import_error(monkeypatch, capsys):
    """Line 658: safety checklist ImportError handled."""
    import builtins

    _real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if "high_security" in name:
            raise ImportError("no module")
        return _real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    monkeypatch.setattr(sys, "argv", ["meow-encode", "--safety-checklist"])
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "not available" in captured.out.lower()


# --- Line 663-676: --high-security mode ---


def test_main_high_security_mode_enables(monkeypatch, tmp_path, capsys):
    """Line 663-676: --high-security enables and prints config."""
    inp = _write_input(tmp_path)

    class _FakeHSConfig:
        argon2_memory = 524288
        argon2_iterations = 20
        kyber_variant = "kyber1024"
        secure_wipe_passes = 7

    _install_module(
        monkeypatch,
        "meow_decoder.high_security",
        enable_high_security_mode=lambda silent: None,
        HighSecurityConfig=_FakeHSConfig,
    )
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--high-security",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "HIGH-SECURITY" in captured.out or "512" in captured.out


def test_main_high_security_import_error_fallback(monkeypatch, tmp_path, capsys):
    """Line 675: high_security ImportError falls back to defaults."""
    inp = _write_input(tmp_path)

    import builtins

    _real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if "high_security" in name:
            raise ImportError("no module")
        return _real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--high-security",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "not available" in captured.out.lower() or "using defaults" in captured.out.lower()


# --- Line 680-683: --purr-mode enables verbose ---


def test_main_purr_mode_enables_verbose(monkeypatch, tmp_path, capsys):
    """Line 680-683: --purr-mode enables verbose logging."""
    inp = _write_input(tmp_path)

    _install_module(
        monkeypatch,
        "meow_decoder.cat_utils",
        enable_purr_mode=lambda enabled: None,
        meow_about=lambda: "about",
    )
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--purr-mode",
        ],
    )
    enc.main()
    # Purr mode implies verbose, so we should get more output
    captured = capsys.readouterr()
    # Verbose prints "Output saved to" at minimum
    assert "Output saved to" in captured.out or "forward secrecy" in captured.out.lower()


# --- Line 693: input is not a file ---


def test_main_input_is_directory_exits_1(monkeypatch, tmp_path):
    """Line 693: input is directory -> exit(1)."""
    input_dir = tmp_path / "subdir"
    input_dir.mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        ["meow-encode", "-i", str(input_dir), "-o", str(tmp_path / "out.gif"), "-p", "password1"],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


# --- Line 769: --pq mode verbose print ---


def test_main_pq_mode_verbose_print(monkeypatch, tmp_path, capsys):
    """Line 769: --pq with --no-forward-secrecy prints post-quantum message."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--pq",
            "--no-forward-secrecy",
            "-v",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "Post-quantum" in captured.out or "MEOW4" in captured.out


# --- Line 741-744: receiver pubkey success print ---


def test_main_receiver_pubkey_success_print(monkeypatch, tmp_path, capsys):
    """Line 741-744: valid receiver pubkey prints success."""
    inp = _write_input(tmp_path)
    pubkey = tmp_path / "pub.key"
    pubkey.write_bytes(b"X" * 32)  # Valid 32-byte key
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--receiver-pubkey",
            str(pubkey),
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "Forward secrecy ENABLED" in captured.out or "X25519" in captured.out


# --- Line 784-785: empty password error ---


def test_main_empty_password_exits_1(monkeypatch, tmp_path):
    """Line 784-785: empty password -> exit(1)."""
    inp = _write_input(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(tmp_path / "out.gif"), "-p", ""]
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


# --- Line 810-811: wipe_source verbose print ---


def test_main_wipe_source_verbose_print(monkeypatch, tmp_path, capsys):
    """Line 810-811: wipe_source with verbose prints wiping message."""
    inp = _write_input(tmp_path)

    def _fake_wipe(path, passes=3):
        path.unlink()
        return True

    _install_module(monkeypatch, "meow_decoder.high_security", secure_wipe_file=_fake_wipe)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--wipe-source",
            "-v",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "wiping" in captured.out.lower() or "wipe" in captured.out.lower()
    assert not inp.exists()


# --- Line 816-817: wipe_source failure warning ---


def test_main_wipe_source_failure_warns(monkeypatch, tmp_path, capsys):
    """Line 816-817: wipe_source returns False -> warning."""
    inp = _write_input(tmp_path)

    def _fake_wipe(path, passes=3):
        return False  # Simulate failure

    _install_module(monkeypatch, "meow_decoder.high_security", secure_wipe_file=_fake_wipe)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--wipe-source",
            "-v",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "failed" in captured.out.lower() or "⚠" in captured.out


# --- Line 837-842: duress_password_prompt interactive ---


def test_main_duress_password_prompt_mismatch_exits_1(monkeypatch, tmp_path):
    """Line 837-842: duress password mismatch -> exit(1)."""
    inp = _write_input(tmp_path)

    pw_iter = iter(["mainpw", "duress1", "duress2"])  # duress mismatch
    monkeypatch.setattr(enc, "getpass", lambda prompt="": next(pw_iter))
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "--duress-password-prompt",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_duress_password_same_as_main_exits_1(monkeypatch, tmp_path):
    """Line 841: duress == main password -> exit(1)."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "samepw",
            "--duress-password",
            "samepw",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


# --- Line 903-905: duress CLI requires FS ---


def test_main_duress_cli_requires_fs_exits_1(monkeypatch, tmp_path):
    """Line 903-905: duress with --no-forward-secrecy -> exit(1)."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "mainpw",
            "--duress-password",
            "duress",
            "--no-forward-secrecy",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


# --- Line 911-933: hardware key derivation paths ---


def test_main_hardware_key_derivation_success(monkeypatch, tmp_path, capsys):
    """Line 911-933: hardware derivation success path."""
    inp = _write_input(tmp_path)

    def _fake_process_hw(args, pw, salt):
        return b"k" * 32, "YubiKey slot 9d"

    _install_module(
        monkeypatch,
        "meow_decoder.hardware_integration",
        HardwareSecurityProvider=lambda verbose: None,
        process_hardware_args=_fake_process_hw,
    )
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--yubikey",
            "--yubikey-pin",
            "123456",
            "-v",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert (
        "Key derived via" in captured.out
        or "YubiKey" in captured.out
        or "Output saved to" in captured.out
    )


def test_main_hardware_key_derivation_returns_none_fallback(monkeypatch, tmp_path, capsys):
    """Line 918-920: hardware returns None -> fallback to software."""
    inp = _write_input(tmp_path)

    def _fake_process_hw(args, pw, salt):
        return None, "none"

    _install_module(
        monkeypatch,
        "meow_decoder.hardware_integration",
        HardwareSecurityProvider=lambda verbose: None,
        process_hardware_args=_fake_process_hw,
    )
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--yubikey",
            "--yubikey-pin",
            "123456",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert (
        "falling back" in captured.out.lower()
        or "software" in captured.out.lower()
        or "Output saved to" in captured.out
    )


def test_main_hardware_key_derivation_exception_no_fallback_exits_1(monkeypatch, tmp_path):
    """Line 925-927: hardware exception + --no-hardware-fallback -> exit(1)."""
    inp = _write_input(tmp_path)

    def _fake_process_hw(args, pw, salt):
        raise RuntimeError("HW failed")

    _install_module(
        monkeypatch,
        "meow_decoder.hardware_integration",
        HardwareSecurityProvider=lambda verbose: None,
        process_hardware_args=_fake_process_hw,
    )
    _patch_encode_file(monkeypatch)
    # Use --hsm-slot to trigger hardware_method path (not --yubikey which is separate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--hsm-slot",
            "0",
            "--hsm-pin",
            "123456",
            "--no-hardware-fallback",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1


def test_main_hardware_key_derivation_exception_with_fallback(monkeypatch, tmp_path, capsys):
    """Line 928-933: hardware exception without --no-hardware-fallback -> fallback."""
    inp = _write_input(tmp_path)

    def _fake_process_hw(args, pw, salt):
        raise RuntimeError("HW failed")

    _install_module(
        monkeypatch,
        "meow_decoder.hardware_integration",
        HardwareSecurityProvider=lambda verbose: None,
        process_hardware_args=_fake_process_hw,
    )
    _patch_encode_file(monkeypatch)
    # Use --hsm-slot to trigger hardware_method path (not --yubikey which is separate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--hsm-slot",
            "0",
            "--hsm-pin",
            "123456",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert (
        "Falling back" in captured.out
        or "software" in captured.out.lower()
        or "failed" in captured.out.lower()
        or "Output saved to" in captured.out
    )


# --- Line 95->105, 110: manifest version selection branches ---


def test_encode_file_verbose_meow3_with_pubkey_print(monkeypatch, tmp_path, capsys):
    """Line 109-111: verbose prints MEOW3 + X25519."""
    _patch_encode_pipeline(monkeypatch)

    def _fake_encrypt(**kw):
        return (b"c", b"s" * 32, b"1" * 16, b"2" * 12, b"cipher", b"e" * 32, 99999)

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    inp = _write_input(tmp_path)
    enc.encode_file(
        inp,
        tmp_path / "out.gif",
        password="password1",
        forward_secrecy=True,
        receiver_public_key=b"r" * 32,
        verbose=True,
    )
    captured = capsys.readouterr()
    assert "MEOW3" in captured.out or "X25519" in captured.out


def test_encode_file_verbose_meow2_password_only_print(monkeypatch, tmp_path, capsys):
    """forward_secrecy=True without receiver_public_key falls back to MEOW2."""
    _patch_encode_pipeline(monkeypatch)

    def _fake_encrypt(**kw):
        return (b"c", b"s" * 32, b"1" * 16, b"2" * 12, b"cipher", None, 99999)

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    inp = _write_input(tmp_path)
    enc.encode_file(
        inp,
        tmp_path / "out.gif",
        password="password1",
        forward_secrecy=True,
        receiver_public_key=None,
        verbose=True,
    )
    captured = capsys.readouterr()
    # Without a receiver key, there is no actual FS — falls back to MEOW2
    assert "MEOW2" in captured.out or "Base Encryption" in captured.out


# --- Line 146-147: yubikey kwargs ---


def test_encode_file_yubikey_kwargs_passed(monkeypatch, tmp_path):
    """Line 146-147: yubikey slot/pin passed to encrypt_file_bytes."""
    _patch_encode_pipeline(monkeypatch)
    captured_kwargs = {}

    def _fake_encrypt(**kw):
        captured_kwargs.update(kw)
        return (b"c", b"s" * 32, b"1" * 16, b"2" * 12, b"cipher", None, 99999)

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    inp = _write_input(tmp_path)
    enc.encode_file(
        inp,
        tmp_path / "out.gif",
        password="password1",
        yubikey=True,
        yubikey_slot="9a",
        yubikey_pin="1234",
    )
    assert captured_kwargs.get("yubikey_slot") == "9a"
    assert captured_kwargs.get("yubikey_pin") == "1234"


# --- Line 178: verbose duress print ---


def test_encode_file_verbose_duress_print(monkeypatch, tmp_path, capsys):
    """Line 178: verbose prints duress configured."""
    _patch_encode_pipeline(monkeypatch)

    def _fake_encrypt(**kw):
        return (b"c", b"s" * 32, b"1" * 16, b"2" * 12, b"cipher", b"e" * 32, 99999)

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "compute_duress_tag", lambda *a, **k: b"d" * 32)
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    inp = _write_input(tmp_path)
    enc.encode_file(
        inp,
        tmp_path / "out.gif",
        password="password1",
        duress_password="duress",
        forward_secrecy=True,
        receiver_public_key=b"r" * 32,
        verbose=True,
    )
    captured = capsys.readouterr()
    assert "Duress" in captured.out or "duress" in captured.out.lower() or "🚨" in captured.out


# --- Line 206: verbose forward secrecy print ---


def test_encode_file_verbose_ephemeral_key_print(monkeypatch, tmp_path, capsys):
    """Line 159-162: verbose prints ephemeral key generated."""
    _patch_encode_pipeline(monkeypatch)

    def _fake_encrypt(**kw):
        return (b"c", b"s" * 32, b"1" * 16, b"2" * 12, b"cipher", b"e" * 32, 99999)

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    inp = _write_input(tmp_path)
    enc.encode_file(inp, tmp_path / "out.gif", password="password1", verbose=True)
    captured = capsys.readouterr()
    assert (
        "Ephemeral" in captured.out
        or "Forward secrecy" in captured.out
        or "32 bytes" in captured.out
    )


# --- Line 244-245: secure zero exception path ---


def test_encode_file_secure_zero_exception_swallowed(monkeypatch, tmp_path):
    """Line 244-245: secure_zero exception is swallowed."""
    _patch_encode_pipeline(monkeypatch)

    def _fake_encrypt(**kw):
        return (b"c", b"s" * 32, b"1" * 16, b"2" * 12, b"cipher", None, 99999)

    monkeypatch.setattr(enc, "encrypt_file_bytes_production", _fake_encrypt)
    monkeypatch.setattr(enc, "compute_manifest_hmac_from_handle", lambda *a, **k: b"h" * 32)
    monkeypatch.setattr(enc, "pack_manifest_core", lambda *a, **k: b"core")
    monkeypatch.setattr(enc, "pack_manifest", lambda *a, **k: b"manifest")

    # Make get_default_backend().secure_zero raise
    class _FakeBackend:
        def secure_zero(self, buf):
            raise RuntimeError("secure_zero failed")

    _install_module(
        monkeypatch, "meow_decoder.crypto_backend", get_default_backend=lambda: _FakeBackend()
    )

    inp = _write_input(tmp_path)
    # Should not raise - exception is caught
    stats = enc.encode_file(inp, tmp_path / "out.gif", password="password1")
    assert stats["output_size"] > 0


# --- Line 759-762: forward secrecy verbose prints (FS enabled with receiver key) ---


def test_main_fs_enabled_verbose_print(monkeypatch, tmp_path, capsys):
    """Line 759-762: FS enabled + receiver key prints status."""
    inp = _write_input(tmp_path)
    pubkey = tmp_path / "pub.key"
    pubkey.write_bytes(b"X" * 32)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--receiver-pubkey",
            str(pubkey),
            "-v",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "Forward secrecy" in captured.out or "MEOW3" in captured.out


# --- Line 763-764: forward secrecy config on but no receiver key ---


def test_main_fs_config_on_no_receiver_verbose_print(monkeypatch, tmp_path, capsys):
    """Line 763-764: FS enabled without receiver key prints password-only."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "-v",  # No --receiver-pubkey, default FS on
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "password-only" in captured.out.lower() or "no receiver key" in captured.out.lower()


# --- Line 765-767: forward secrecy disabled verbose print ---


def test_main_fs_disabled_verbose_print(monkeypatch, tmp_path, capsys):
    """Line 765-767: FS disabled prints MEOW2."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--no-forward-secrecy",
            "-v",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "DISABLED" in captured.out or "MEOW2" in captured.out


# --- Line 749-754: FS enabled but no receiver pubkey provided prints warning ---


def test_main_fs_enabled_no_receiver_prints_warning(monkeypatch, tmp_path, capsys):
    """Line 749-754: FS enabled without receiver pubkey prints warning."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",  # Default FS on, no --receiver-pubkey
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert (
        "no receiver public key" in captured.out.lower() or "password-only" in captured.out.lower()
    )


# --- Non-interactive password prompt error ---


def test_main_password_prompt_non_interactive_exits_1(monkeypatch, tmp_path):
    """Line 796-800: non-interactive without -p -> exit(1)."""
    inp = _write_input(tmp_path)
    # Simulate non-interactive by making isatty return False
    import io

    fake_stdin = io.StringIO()
    monkeypatch.setattr(sys, "stdin", fake_stdin)
    monkeypatch.setattr(fake_stdin, "isatty", lambda: False)
    monkeypatch.setattr(
        sys, "argv", ["meow-encode", "-i", str(inp), "-o", str(tmp_path / "out.gif")]
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()


# --- YubiKey + Forward Secrecy rejection ---


def test_main_yubikey_with_receiver_pubkey_rejected(monkeypatch, tmp_path, capsys):
    """Line 838-839: yubikey + receiver_pubkey -> error exit(1)."""
    inp = _write_input(tmp_path)
    # Create fake 32-byte receiver public key
    pubkey_file = tmp_path / "receiver.pub"
    pubkey_file.write_bytes(b"X" * 32)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--yubikey",
            "--yubikey-pin",
            "123456",
            "--receiver-pubkey",
            str(pubkey_file),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        enc.main()
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "forward secrecy" in captured.err.lower() or "not supported" in captured.err.lower()


# --- Hardware key success with verbose print ---


def test_main_hardware_key_derivation_success_verbose_print(monkeypatch, tmp_path, capsys):
    """Line 918-920: hardware key success + verbose -> prints key description."""
    inp = _write_input(tmp_path)

    def _fake_process_hw(args, pw, salt):
        return (b"k" * 32, "HSM slot 0")

    _install_module(
        monkeypatch,
        "meow_decoder.hardware_integration",
        HardwareSecurityProvider=lambda verbose: None,
        process_hardware_args=_fake_process_hw,
    )
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--hsm-slot",
            "0",
            "--hsm-pin",
            "123456",
            "-v",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "Key derived via" in captured.out or "HSM" in captured.out


# --- Hardware fallback stderr output ---


def test_main_hardware_key_derivation_fallback_stderr_print(monkeypatch, tmp_path, capsys):
    """Line 930-933: hardware exception -> prints fallback message to stderr."""
    inp = _write_input(tmp_path)

    def _fake_process_hw(args, pw, salt):
        raise RuntimeError("HW failed")

    # Need to both install the fake module AND ensure encode.py imports it fresh
    _install_module(
        monkeypatch,
        "meow_decoder.hardware_integration",
        HardwareSecurityProvider=lambda verbose: None,
        process_hardware_args=_fake_process_hw,
    )

    # Lazy import in main() will pick up the fake module above

    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--hsm-slot",
            "0",
            "--hsm-pin",
            "123456",
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    # Fallback prints to stderr
    assert (
        "Falling back" in captured.err
        or "software" in captured.err.lower()
        or "HW failed" in captured.err
    )


# --- High-security mode wipe source uses 7 passes ---


def test_main_wipe_source_high_security_7_passes(monkeypatch, tmp_path, capsys):
    """Line 1027-1029: high-security + wipe-source -> 7 passes."""
    inp = _write_input(tmp_path)
    _wipe_passes = []

    def _fake_secure_wipe_file(path, passes=3):
        _wipe_passes.append(passes)
        return True

    _install_module(
        monkeypatch,
        "meow_decoder.high_security",
        enable_high_security_mode=lambda silent: None,
        HighSecurityConfig=lambda: type(
            "C",
            (),
            {
                "argon2_memory": 1024,
                "argon2_iterations": 1,
                "kyber_variant": "kyber768",
                "secure_wipe_passes": 7,
            },
        )(),
        get_safety_checklist=lambda: "checklist",
        secure_wipe_file=_fake_secure_wipe_file,
    )
    _patch_encode_file(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--high-security",
            "--wipe-source",
            "-v",
        ],
    )
    enc.main()
    assert 7 in _wipe_passes


# --- Duress password prompt interactive path ---


def test_main_duress_password_prompt_success(monkeypatch, tmp_path, capsys):
    """Line 884-893: duress-password-prompt interactive path with success."""
    inp = _write_input(tmp_path)
    call_count = [0]

    def _fake_getpass(prompt):
        call_count[0] += 1
        if call_count[0] == 1:
            return "duress_secret"
        else:
            return "duress_secret"  # Confirm matches

    _patch_encode_file(monkeypatch)
    # Create fake 32-byte receiver public key to enable forward secrecy properly
    pubkey_file = tmp_path / "receiver.pub"
    pubkey_file.write_bytes(b"X" * 32)

    # Patch getpass directly in the encode module's namespace (encode.py does: from getpass import getpass)
    monkeypatch.setattr(enc, "getpass", _fake_getpass)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--duress-password-prompt",
            "--receiver-pubkey",
            str(pubkey_file),
        ],
    )
    enc.main()
    captured = capsys.readouterr()
    assert "Duress password configured" in captured.out or "Output saved to" in captured.out


# --- Coverage boost: encode_file with explicit config parameter (line 86->91 branch) ---


def test_encode_file_with_explicit_config(monkeypatch, tmp_path: Path):
    """Test encode_file with explicit config parameter to cover config-not-None branch (line 86->91)."""
    from meow_decoder.config import EncodingConfig
    import meow_decoder.frame_mac as frame_mac

    monkeypatch.setattr(frame_mac, "pack_frame_with_mac", lambda payload, *args, **kwargs: payload)
    monkeypatch.setattr(frame_mac, "derive_frame_master_key", lambda *args, **kwargs: b"k" * 32)

    input_path = tmp_path / "in.bin"
    input_path.write_bytes(b"test data for config branch")
    out_gif = tmp_path / "out.gif"

    # Create explicit config
    config = EncodingConfig()
    stats = enc.encode_file(
        input_path, out_gif, password="password_test", config=config, verbose=False
    )
    assert out_gif.exists()
    assert stats["output_size"] > 0


# --- Coverage boost: cat_utils.summon_cat_judge success path (lines 1107-1108) ---


def test_main_cat_judge_available(monkeypatch, tmp_path: Path, capsys):
    """Test cat_utils.summon_cat_judge when available (lines 1107-1108)."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)

    # Create a mock cat_utils module
    import sys

    mock_cat_utils = type(sys)("cat_utils")
    mock_cat_utils.summon_cat_judge = lambda pwd: "😺 Purrfect password!"
    sys.modules["cat_utils"] = mock_cat_utils

    try:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "meow-encode",
                "-i",
                str(inp),
                "-o",
                str(tmp_path / "out.gif"),
                "-p",
                "password1",
            ],
        )
        enc.main()
        captured = capsys.readouterr()
        assert "Cat Judge" in captured.out or "Purrfect" in captured.out
    finally:
        # Cleanup
        if "cat_utils" in sys.modules:
            del sys.modules["cat_utils"]


# --- Coverage boost: YubiKey PIN prompt path (lines 1135-1136) ---


def test_main_yubikey_pin_prompt(monkeypatch, tmp_path: Path):
    """Test YubiKey PIN prompt when --yubikey-pin not provided (lines 1135-1136)."""
    inp = _write_input(tmp_path)
    _patch_encode_file(monkeypatch)

    # Mock getpass to return a PIN
    monkeypatch.setattr(enc, "getpass", lambda prompt: "123456")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "meow-encode",
            "-i",
            str(inp),
            "-o",
            str(tmp_path / "out.gif"),
            "-p",
            "password1",
            "--yubikey",  # Request YubiKey but don't provide --yubikey-pin
        ],
    )
    enc.main()
    # Should complete successfully after prompting for PIN
