"""Tests for hardware integration utilities."""

import argparse
from pathlib import Path
import runpy
import types
from types import SimpleNamespace
import warnings

import pytest

import meow_decoder.hardware_integration as hw


def _caps(**kwargs):
    caps = hw.HardwareCapabilities()
    for key, value in kwargs.items():
        setattr(caps, key, value)
    return caps


class TestHardwareCapabilities:
    def test_best_available_priority(self):
        caps = _caps(hsm_available=True)
        assert caps.best_available() == hw.HardwareType.HSM

        caps = _caps(yubikey_available=True)
        assert caps.best_available() == hw.HardwareType.YUBIKEY_PIV

        caps = _caps(tpm_available=True)
        assert caps.best_available() == hw.HardwareType.TPM

        caps = _caps()
        assert caps.best_available() == hw.HardwareType.SOFTWARE

    def test_summary_no_hardware(self):
        caps = _caps()
        summary = caps.summary()
        assert "Software-only" in summary
        assert "Not detected" in summary

    def test_any_hardware(self):
        assert _caps().any_hardware() is False
        assert _caps(hsm_available=True).any_hardware() is True
        assert _caps(yubikey_available=True).any_hardware() is True
        assert _caps(tpm_available=True).any_hardware() is True

    def test_summary_with_warnings_and_recommendation(self):
        caps = _caps(yubikey_available=True, yubikey_version="5.7", yubikey_serial="1234")
        caps.yubikey_piv_slots = ["9a", "9d"]
        caps.warnings.append("YubiKey detected but ykman not available")
        summary = caps.summary()
        assert "Warnings" in summary
        assert "Recommended" in summary

    def test_summary_with_hsm_tpm(self):
        caps = _caps(hsm_available=True, tpm_available=True)
        caps.hsm_slots = [0]
        caps.tpm_version = "2.0"
        caps.tpm_manufacturer = "TEST"
        caps.tpm_pcrs = list(range(24))
        summary = caps.summary()
        assert "✅ HSM" in summary
        assert "✅ TPM" in summary
        assert "Recommended" in summary


class TestDetectionHelpers:
    def test_detect_hsm_parses_slots(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_exists(path):
            return path == "/usr/lib/softhsm/libsofthsm2.so"

        def fake_run_cmd(cmd, timeout=5):
            if cmd[:2] == ["pkcs11-tool", "--list-slots"]:
                return True, "Slot 0\nSlot 1\n"
            return False, ""

        monkeypatch.setattr(hw.os.path, "exists", fake_exists)
        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        provider._detect_hsm(caps)
        assert caps.hsm_available is True
        assert caps.hsm_slots == [0, 1]

    def test_detect_hsm_without_slots(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_exists(path):
            return path == "/usr/lib/softhsm/libsofthsm2.so"

        def fake_run_cmd(cmd, timeout=5):
            if cmd[:2] == ["pkcs11-tool", "--list-slots"]:
                return False, "error"
            return False, ""

        monkeypatch.setattr(hw.os.path, "exists", fake_exists)
        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        provider._detect_hsm(caps)
        assert caps.hsm_available is True
        assert caps.hsm_library_path
        assert caps.hsm_slots == []

    def test_detect_yubikey_parses_info(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_run_cmd(cmd, timeout=5):
            if cmd == ["ykman", "info"]:
                return True, "Serial number: 123456\nFirmware version: 5.7.8\n"
            if cmd == ["ykman", "piv", "info"]:
                return True, "PIV OK"
            if cmd == ["ykman", "fido", "info"]:
                return False, ""
            return False, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        provider._detect_yubikey(caps)

        assert caps.yubikey_available is True
        assert caps.yubikey_serial == "123456"
        assert caps.yubikey_version == "5.7.8"
        assert caps.yubikey_piv_slots == ["9a", "9c", "9d", "9e"]
        assert caps.yubikey_fido2_available is False

    def test_detect_yubikey_lsusb_fallback(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_run_cmd(cmd, timeout=5):
            if cmd == ["ykman", "info"]:
                return False, "ykman missing"
            if cmd == ["lsusb"]:
                return True, "Bus 001 Device 002: ID 1050:0407 Yubico.com"
            return False, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        provider._detect_yubikey(caps)

        assert caps.yubikey_available is True
        assert "ykman not available" in " ".join(caps.warnings)

    def test_detect_tpm_parses_properties(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_exists(path):
            return path in {"/dev/tpm0", "/dev/tpmrm0"}

        tpm_output = (
            'TPM2_PT_FAMILY_INDICATOR: value: "2.0"\n' 'TPM2_PT_MANUFACTURER: value: "TEST"\n'
        )

        def fake_run_cmd(cmd, timeout=5):
            if cmd == ["tpm2_getcap", "properties-fixed"]:
                return True, tpm_output
            return False, ""

        monkeypatch.setattr(hw.os.path, "exists", fake_exists)
        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        provider._detect_tpm(caps)
        assert caps.tpm_available is True
        assert caps.tpm_version == "2.0"
        assert caps.tpm_manufacturer == "TEST"
        assert len(caps.tpm_pcrs) == 24

    def test_detect_tpm_no_tools_warning(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_exists(path):
            return path == "/dev/tpm0"

        def fake_run_cmd(cmd, timeout=5):
            return False, "tpm2_getcap missing"

        monkeypatch.setattr(hw.os.path, "exists", fake_exists)
        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        provider._detect_tpm(caps)
        assert caps.tpm_available is True
        assert caps.tpm_version == "2.0"
        assert caps.tpm_manufacturer == "Unknown"
        assert caps.warnings

    def test_run_cmd_exception(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()

        def boom(*args, **kwargs):
            raise OSError("boom")

        monkeypatch.setattr(hw.subprocess, "run", boom)
        ok, output = provider._run_cmd(["anything"])
        assert ok is False
        assert "boom" in output

    def test_run_cmd_success(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()

        class DummyResult:
            returncode = 0
            stdout = "ok"
            stderr = ""

        monkeypatch.setattr(hw.subprocess, "run", lambda *args, **kwargs: DummyResult())
        ok, output = provider._run_cmd(["cmd"])
        assert ok is True
        assert output == "ok"

    def test_detect_all_cached(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        sentinel = _caps(hsm_available=True)
        provider._capabilities = sentinel

        monkeypatch.setattr(
            provider,
            "_detect_hsm",
            lambda caps: (_ for _ in ()).throw(RuntimeError("should not run")),
        )
        assert provider.detect_all() is sentinel

    def test_detect_all_runs_detectors(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        called = {"hsm": False, "yk": False, "tpm": False}

        def mark_hsm(caps):
            called["hsm"] = True

        def mark_yk(caps):
            called["yk"] = True

        def mark_tpm(caps):
            called["tpm"] = True

        monkeypatch.setattr(provider, "_detect_hsm", mark_hsm)
        monkeypatch.setattr(provider, "_detect_yubikey", mark_yk)
        monkeypatch.setattr(provider, "_detect_tpm", mark_tpm)

        caps = provider.detect_all()
        assert caps is provider._capabilities
        assert all(called.values())

    def test_provider_init_with_rust_backend(self, monkeypatch):
        dummy = types.SimpleNamespace()

        import builtins

        original_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "meow_crypto_rs":
                return dummy
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        provider = hw.HardwareSecurityProvider()
        assert provider._rust_backend is dummy

    def test_detect_yubikey_fido2_true(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_run_cmd(cmd, timeout=5):
            if cmd == ["ykman", "info"]:
                return True, "Serial number: 1\nFirmware version: 5.0.0\n"
            if cmd == ["ykman", "piv", "info"]:
                return False, ""
            if cmd == ["ykman", "fido", "info"]:
                return True, "OK"
            return False, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        provider._detect_yubikey(caps)
        assert caps.yubikey_available is True
        assert caps.yubikey_fido2_available is True

    def test_detect_yubikey_missing_serial_version(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_run_cmd(cmd, timeout=5):
            if cmd == ["ykman", "info"]:
                return True, "No serial here\n"
            if cmd == ["ykman", "piv", "info"]:
                return True, "PIV OK"
            if cmd == ["ykman", "fido", "info"]:
                return True, "OK"
            return False, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        provider._detect_yubikey(caps)
        assert caps.yubikey_available is True
        assert caps.yubikey_serial == ""
        assert caps.yubikey_version == ""

    def test_detect_yubikey_no_lsusb_match(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_run_cmd(cmd, timeout=5):
            if cmd == ["ykman", "info"]:
                return False, ""
            if cmd == ["lsusb"]:
                return True, "Other Device"
            return False, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        provider._detect_yubikey(caps)
        assert caps.yubikey_available is False

    def test_detect_yubikey_lsusb_not_ok(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_run_cmd(cmd, timeout=5):
            if cmd == ["ykman", "info"]:
                return False, ""
            if cmd == ["lsusb"]:
                return False, ""
            return False, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        provider._detect_yubikey(caps)
        assert caps.yubikey_available is False

    def test_detect_hsm_no_paths(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        monkeypatch.setattr(hw.os.path, "exists", lambda path: False)
        provider._detect_hsm(caps)
        assert caps.hsm_available is False

    def test_detect_tpm_no_regex_matches(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_exists(path):
            return path == "/dev/tpmrm0"

        def fake_run_cmd(cmd, timeout=5):
            return True, 'TPM2_PT_FAMILY_INDICATOR: value: ""\n'

        monkeypatch.setattr(hw.os.path, "exists", fake_exists)
        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        provider._detect_tpm(caps)
        assert caps.tpm_available is True
        assert caps.tpm_pcrs == list(range(24))


class TestDerivationFallbacks:
    def test_yubikey_fallback_to_software(self, monkeypatch):
        provider = hw.HardwareSecurityProvider(allow_software_fallback=True)
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())
        monkeypatch.setattr(provider, "_derive_key_software", lambda p, s: b"k" * 32)

        with pytest.warns(hw.SoftwareFallbackWarning):
            key = provider.derive_key_yubikey_piv(b"pw", b"s" * 16)
        assert key == b"k" * 32

    def test_yubikey_no_fallback_raises(self, monkeypatch):
        provider = hw.HardwareSecurityProvider(allow_software_fallback=False)
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())

        with pytest.raises(hw.HardwareNotFoundError):
            provider.derive_key_yubikey_piv(b"pw", b"s" * 16)

    def test_tpm_fallback_to_software(self, monkeypatch):
        provider = hw.HardwareSecurityProvider(allow_software_fallback=True)
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())
        monkeypatch.setattr(provider, "_derive_key_software", lambda p, s: b"t" * 32)

        with pytest.warns(hw.SoftwareFallbackWarning):
            key = provider.derive_key_tpm(b"pw", b"s" * 16)
        assert key == b"t" * 32

    def test_yubikey_chalresp_success(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = _caps(yubikey_available=True)

        monkeypatch.setattr(provider, "detect_all", lambda: caps)
        monkeypatch.setattr(provider, "_rust_backend", None)

        def fake_run_cmd(cmd, timeout=5):
            if cmd[:1] == ["ykchalresp"]:
                return True, "".join(["aa"] * 20)
            return False, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        key = provider.derive_key_yubikey_piv(b"pw", b"s" * 16)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_yubikey_chalresp_failure(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = _caps(yubikey_available=True)

        monkeypatch.setattr(provider, "detect_all", lambda: caps)
        monkeypatch.setattr(provider, "_rust_backend", None)
        monkeypatch.setattr(provider, "_run_cmd", lambda *args, **kwargs: (False, "fail"))

        with pytest.raises(hw.HardwareOperationError):
            provider.derive_key_yubikey_piv(b"pw", b"s" * 16)

    def test_yubikey_rust_backend(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = _caps(yubikey_available=True)

        class DummyRust:
            def yubikey_derive_key(self, password, salt, slot, pin):
                return b"y" * 32

        provider._rust_backend = DummyRust()
        monkeypatch.setattr(provider, "detect_all", lambda: caps)
        key = provider.derive_key_yubikey_piv(b"pw", b"s" * 16)
        assert key == b"y" * 32


class TestDeriveKeyAuto:
    def test_prefer_hsm(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(hsm_available=True))
        monkeypatch.setattr(provider, "hsm_derive_key", lambda *args, **kwargs: b"h" * 32)

        key, hw_type = provider.derive_key_auto(b"pw", b"s" * 16, prefer=hw.HardwareType.HSM)
        assert key == b"h" * 32
        assert hw_type == hw.HardwareType.HSM

    def test_auto_falls_back_to_software(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())
        monkeypatch.setattr(provider, "_derive_key_software", lambda p, s: b"s" * 32)

        key, hw_type = provider.derive_key_auto(b"pw", b"s" * 16)
        assert key == b"s" * 32
        assert hw_type == hw.HardwareType.SOFTWARE

    def test_auto_prefers_yubikey(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(yubikey_available=True))
        monkeypatch.setattr(provider, "derive_key_yubikey_piv", lambda *args, **kwargs: b"y" * 32)

        key, hw_type = provider.derive_key_auto(
            b"pw", b"s" * 16, prefer=hw.HardwareType.YUBIKEY_PIV
        )
        assert key == b"y" * 32
        assert hw_type == hw.HardwareType.YUBIKEY_PIV

    def test_auto_prefers_tpm(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        monkeypatch.setattr(provider, "derive_key_tpm", lambda *args, **kwargs: b"t" * 32)

        key, hw_type = provider.derive_key_auto(b"pw", b"s" * 16, prefer=hw.HardwareType.TPM)
        assert key == b"t" * 32
        assert hw_type == hw.HardwareType.TPM


class TestProcessHardwareArgs:
    def test_hsm_args_routing(self, monkeypatch):
        class DummyProvider:
            def __init__(self, verbose=False, allow_software_fallback=True):
                pass

            def hsm_derive_key(self, password, salt, slot, pin, key_label):
                return b"d" * 32

        monkeypatch.setattr(hw, "HardwareSecurityProvider", DummyProvider)

        args = SimpleNamespace(
            verbose=False,
            no_hardware_fallback=False,
            hardware_status=False,
            hsm_slot=1,
            hsm_pin="1234",
            hsm_key_label="meow-master",
            yubikey_piv=False,
            yubikey=False,
            tpm_derive=False,
            tpm_seal=None,
            hardware_auto=False,
        )

        key, method = hw.process_hardware_args(args, b"pw", b"s" * 16)
        assert key == b"d" * 32
        assert method == "HSM slot 1"

    def test_hardware_status_exits(self, monkeypatch):
        class DummyProvider:
            def __init__(self, verbose=False, allow_software_fallback=True):
                pass

            def detect_all(self):
                return _caps()

        monkeypatch.setattr(hw, "HardwareSecurityProvider", DummyProvider)

        args = SimpleNamespace(
            verbose=False,
            no_hardware_fallback=False,
            hardware_status=True,
            hsm_slot=None,
            hsm_pin=None,
            hsm_key_label="meow-master",
            yubikey_piv=False,
            yubikey=False,
            tpm_derive=False,
            tpm_seal=None,
            hardware_auto=False,
        )

        with pytest.raises(SystemExit):
            hw.process_hardware_args(args, b"pw", b"s" * 16)

    def test_yubikey_args_prompt_pin(self, monkeypatch):
        class DummyProvider:
            def __init__(self, verbose=False, allow_software_fallback=True):
                pass

            def derive_key_yubikey_piv(self, password, salt, slot, pin):
                assert pin == "0000"
                return b"y" * 32

        monkeypatch.setattr(hw, "HardwareSecurityProvider", DummyProvider)
        import getpass

        monkeypatch.setattr(getpass, "getpass", lambda prompt: "0000")

        args = SimpleNamespace(
            verbose=False,
            no_hardware_fallback=False,
            hardware_status=False,
            hsm_slot=None,
            hsm_pin=None,
            hsm_key_label="meow-master",
            yubikey_piv=True,
            yubikey=True,
            yubikey_slot="9d",
            yubikey_pin=None,
            tpm_derive=False,
            tpm_seal=None,
            hardware_auto=False,
        )

        key, method = hw.process_hardware_args(args, b"pw", b"s" * 16)
        assert key == b"y" * 32
        assert method == "YubiKey PIV slot 9d"

    def test_tpm_args_with_pcrs(self, monkeypatch):
        class DummyProvider:
            def __init__(self, verbose=False, allow_software_fallback=True):
                pass

            def derive_key_tpm(self, password, salt, pcrs):
                assert pcrs == [0, 2, 7]
                return b"t" * 32

        monkeypatch.setattr(hw, "HardwareSecurityProvider", DummyProvider)

        args = SimpleNamespace(
            verbose=False,
            no_hardware_fallback=False,
            hardware_status=False,
            hsm_slot=None,
            hsm_pin=None,
            hsm_key_label="meow-master",
            yubikey_piv=False,
            yubikey=False,
            tpm_derive=True,
            tpm_seal="0,2,7",
            hardware_auto=False,
        )

        key, method = hw.process_hardware_args(args, b"pw", b"s" * 16)
        assert key == b"t" * 32
        assert method == "TPM (PCRs: [0, 2, 7])"

    def test_hardware_auto_args(self, monkeypatch):
        class DummyProvider:
            def __init__(self, verbose=False, allow_software_fallback=True):
                pass

            def derive_key_auto(self, password, salt):
                return b"a" * 32, hw.HardwareType.SOFTWARE

        monkeypatch.setattr(hw, "HardwareSecurityProvider", DummyProvider)

        args = SimpleNamespace(
            verbose=False,
            no_hardware_fallback=False,
            hardware_status=False,
            hsm_slot=None,
            hsm_pin=None,
            hsm_key_label="meow-master",
            yubikey_piv=False,
            yubikey=False,
            tpm_derive=False,
            tpm_seal=None,
            hardware_auto=True,
        )

        key, method = hw.process_hardware_args(args, b"pw", b"s" * 16)
        assert key == b"a" * 32
        assert method == "Auto (software)"


class TestHardwareOperations:
    def test_tpm_seal_invalid_pcr(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))

        with pytest.raises(ValueError):
            provider.tpm_seal(b"data", pcrs=[99])

    def test_tpm_seal_not_available(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())

        with pytest.raises(hw.HardwareNotFoundError):
            provider.tpm_seal(b"data")

    def test_tpm_seal_unseal_rust_backend(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))

        class DummyRust:
            def tpm_seal(self, data, pcrs, auth_password):
                return b"sealed"

            def tpm_unseal(self, sealed_blob, auth_password):
                assert sealed_blob == b"sealed"
                return b"unsealed"

        provider._rust_backend = DummyRust()

        sealed = provider.tpm_seal(b"data", pcrs=[0, 2, 7])
        assert sealed == b"sealed"
        unsealed = provider.tpm_unseal(sealed)
        assert unsealed == b"unsealed"

    def test_tpm_seal_fallback_success(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_create":
                pub_path = cmd[cmd.index("-u") + 1]
                priv_path = cmd[cmd.index("-r") + 1]
                Path(pub_path).write_bytes(b"pub")
                Path(priv_path).write_bytes(b"priv")
                return True, ""
            if cmd and cmd[0] == "tpm2_load":
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        sealed = provider.tpm_seal(b"data", pcrs=[0, 2, 7])
        assert sealed.startswith(b"\x00\x00\x00")

    def test_tpm_seal_with_auth_password(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_create":
                assert "-p" in cmd
                pub_path = cmd[cmd.index("-u") + 1]
                priv_path = cmd[cmd.index("-r") + 1]
                Path(pub_path).write_bytes(b"pub")
                Path(priv_path).write_bytes(b"priv")
                return True, ""
            if cmd and cmd[0] == "tpm2_load":
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        sealed = provider.tpm_seal(b"data", pcrs=[0, 2, 7], auth_password="secret")
        assert sealed

    def test_tpm_seal_fallback_fail_create(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        monkeypatch.setattr(provider, "_run_cmd", lambda *args, **kwargs: (False, "fail"))

        with pytest.raises(hw.HardwareOperationError, match="TPM seal failed"):
            provider.tpm_seal(b"data", pcrs=[0, 2, 7])

    def test_tpm_seal_fallback_fail_load(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_create":
                pub_path = cmd[cmd.index("-u") + 1]
                priv_path = cmd[cmd.index("-r") + 1]
                Path(pub_path).write_bytes(b"pub")
                Path(priv_path).write_bytes(b"priv")
                return True, ""
            if cmd and cmd[0] == "tpm2_load":
                return False, "load fail"
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        with pytest.raises(hw.HardwareOperationError, match="TPM load failed"):
            provider.tpm_seal(b"data", pcrs=[0, 2, 7])

    def test_tpm_seal_rust_backend_attribute_error(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))

        class DummyRust:
            pass

        provider._rust_backend = DummyRust()
        monkeypatch.setattr(provider, "_run_cmd", lambda *args, **kwargs: (False, "fail"))

        with pytest.raises(hw.HardwareOperationError):
            provider.tpm_seal(b"data", pcrs=[0, 2, 7])

    def test_tpm_unseal_success(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] in {"tpm2_load", "tpm2_startauthsession", "tpm2_policypcr"}:
                return True, ""
            if cmd and cmd[0] == "tpm2_unseal":
                out_path = cmd[cmd.index("-o") + 1]
                Path(out_path).write_bytes(b"unsealed")
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        sealed = b"\x00\x00\x00\x03pub\x00\x00\x00\x04priv\x00\x02\x07"
        assert provider.tpm_unseal(sealed) == b"unsealed"

    def test_tpm_unseal_auth_password(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] in {"tpm2_load", "tpm2_startauthsession", "tpm2_policypcr"}:
                return True, ""
            if cmd and cmd[0] == "tpm2_unseal":
                assert cmd[-1] == "secret"
                ctx_path = Path(cmd[cmd.index("-c") + 1])
                out_path = ctx_path.parent / "unsealed.bin"
                out_path.write_bytes(b"unsealed")
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        sealed = b"\x00\x00\x00\x03pub\x00\x00\x00\x04priv\x00\x02\x07"
        assert provider.tpm_unseal(sealed, auth_password="secret") == b"unsealed"

    def test_tpm_unseal_not_available(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())

        with pytest.raises(hw.HardwareNotFoundError):
            provider.tpm_unseal(b"sealed")

    def test_tpm_unseal_rust_backend_attribute_error(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))

        class DummyRust:
            pass

        provider._rust_backend = DummyRust()

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] in {"tpm2_load", "tpm2_startauthsession", "tpm2_policypcr"}:
                return True, ""
            if cmd and cmd[0] == "tpm2_unseal":
                out_path = cmd[cmd.index("-o") + 1]
                Path(out_path).write_bytes(b"unsealed")
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        sealed = b"\x00\x00\x00\x03pub\x00\x00\x00\x04priv\x00\x02\x07"
        assert provider.tpm_unseal(sealed) == b"unsealed"

    def test_tpm_unseal_failures(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        sealed = b"\x00\x00\x00\x03pub\x00\x00\x00\x04priv\x00\x02\x07"

        def fail_load(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_load":
                return False, "load fail"
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fail_load)
        with pytest.raises(hw.HardwareOperationError, match="TPM load failed"):
            provider.tpm_unseal(sealed)

        def fail_session(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_startauthsession":
                return False, "session fail"
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fail_session)
        with pytest.raises(hw.HardwareOperationError, match="TPM session failed"):
            provider.tpm_unseal(sealed)

        def fail_policy(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_policypcr":
                return False, "policy fail"
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fail_policy)
        with pytest.raises(hw.HardwareOperationError, match="TPM PCR policy failed"):
            provider.tpm_unseal(sealed)

        def fail_unseal(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_unseal":
                return False, "other fail"
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fail_unseal)
        with pytest.raises(hw.HardwareOperationError, match="TPM unseal failed"):
            provider.tpm_unseal(sealed)

    def test_tpm_unseal_pcr_failure(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] in {"tpm2_load", "tpm2_startauthsession", "tpm2_policypcr"}:
                return True, ""
            if cmd and cmd[0] == "tpm2_unseal":
                return False, "PCR mismatch"
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)

        sealed = b"\x00\x00\x00\x03pub\x00\x00\x00\x04priv\x00\x02\x07"
        with pytest.raises(hw.HardwareOperationError, match="PCR values have changed"):
            provider.tpm_unseal(sealed)

    def test_derive_key_tpm_fallback_success(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_hmac":
                out_path = cmd[cmd.index("-o") + 1]
                Path(out_path).write_bytes(b"hmac")
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        key = provider.derive_key_tpm(b"pw", b"s" * 16)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_derive_key_tpm_rust_backend(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))

        class DummyRust:
            def tpm_derive_key(self, combined, salt, pcrs):
                return b"r" * 32

        provider._rust_backend = DummyRust()
        key = provider.derive_key_tpm(b"pw", b"s" * 16)
        assert key == b"r" * 32

    def test_derive_key_tpm_rust_backend_attribute_error(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))

        class DummyRust:
            pass

        provider._rust_backend = DummyRust()

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_hmac":
                out_path = cmd[cmd.index("-o") + 1]
                Path(out_path).write_bytes(b"hmac")
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        key = provider.derive_key_tpm(b"pw", b"s" * 16)
        assert len(key) == 32

    def test_derive_key_tpm_run_cmd_fail(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(tpm_available=True))
        provider._rust_backend = None
        monkeypatch.setattr(provider, "_run_cmd", lambda *args, **kwargs: (False, "fail"))

        with pytest.raises(hw.HardwareOperationError, match="TPM HMAC failed"):
            provider.derive_key_tpm(b"pw", b"s" * 16)

    def test_derive_key_tpm_no_fallback_raises(self, monkeypatch):
        provider = hw.HardwareSecurityProvider(allow_software_fallback=False)
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())

        with pytest.raises(hw.HardwareNotFoundError):
            provider.derive_key_tpm(b"pw", b"s" * 16)

    def test_hsm_generate_key_success(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(
            provider,
            "detect_all",
            lambda: _caps(hsm_available=True, hsm_library_path="/tmp/lib.so"),
        )
        monkeypatch.setattr(provider, "_run_cmd", lambda *args, **kwargs: (True, "ok"))

        key_id = provider.hsm_generate_key(slot=0, pin="1234")
        assert key_id == "meow-master"

    def test_hsm_generate_key_aes128(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(
            provider,
            "detect_all",
            lambda: _caps(hsm_available=True, hsm_library_path="/tmp/lib.so"),
        )
        monkeypatch.setattr(provider, "_run_cmd", lambda *args, **kwargs: (True, "ok"))

        key_id = provider.hsm_generate_key(slot=0, pin="1234", key_type="aes128")
        assert key_id == "meow-master"

    def test_hsm_generate_key_not_available(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())

        with pytest.raises(hw.HardwareNotFoundError):
            provider.hsm_generate_key(slot=0, pin="1234")

    def test_hsm_generate_key_failure(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(
            provider,
            "detect_all",
            lambda: _caps(hsm_available=True, hsm_library_path="/tmp/lib.so"),
        )
        monkeypatch.setattr(provider, "_run_cmd", lambda *args, **kwargs: (False, "fail"))

        with pytest.raises(hw.HardwareOperationError):
            provider.hsm_generate_key(slot=0, pin="1234")

    def test_hsm_derive_key_fallback_success(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(
            provider,
            "detect_all",
            lambda: _caps(hsm_available=True, hsm_library_path="/tmp/lib.so"),
        )
        provider._rust_backend = None

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] == "pkcs11-tool":
                out_path = cmd[cmd.index("-o") + 1]
                Path(out_path).write_bytes(b"hmac")
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        key = provider.hsm_derive_key(b"pw", b"s" * 16, slot=0, pin="1234")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_hsm_derive_key_fallback_failure(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(
            provider,
            "detect_all",
            lambda: _caps(hsm_available=True, hsm_library_path="/tmp/lib.so"),
        )
        provider._rust_backend = None

        monkeypatch.setattr(provider, "_run_cmd", lambda *args, **kwargs: (False, "fail"))

        with pytest.raises(hw.HardwareOperationError, match="HSM HMAC failed"):
            provider.hsm_derive_key(b"pw", b"s" * 16, slot=0, pin="1234")

    def test_hsm_derive_key_rust_backend(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(provider, "detect_all", lambda: _caps(hsm_available=True))

        class DummyRust:
            def hsm_derive_key(self, password, salt, slot, pin, key_label):
                return b"h" * 32

        provider._rust_backend = DummyRust()
        key = provider.hsm_derive_key(b"pw", b"s" * 16, slot=0, pin="1234")
        assert key == b"h" * 32

    def test_hsm_derive_key_rust_backend_attribute_error(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        monkeypatch.setattr(
            provider,
            "detect_all",
            lambda: _caps(hsm_available=True, hsm_library_path="/tmp/lib.so"),
        )

        class DummyRust:
            pass

        provider._rust_backend = DummyRust()

        def fake_run_cmd(cmd, timeout=5):
            if cmd and cmd[0] == "pkcs11-tool":
                out_path = cmd[cmd.index("-o") + 1]
                Path(out_path).write_bytes(b"hmac")
                return True, ""
            return True, ""

        monkeypatch.setattr(provider, "_run_cmd", fake_run_cmd)
        key = provider.hsm_derive_key(b"pw", b"s" * 16, slot=0, pin="1234")
        assert len(key) == 32

    def test_hsm_derive_key_software_fallback(self, monkeypatch):
        provider = hw.HardwareSecurityProvider(allow_software_fallback=True)
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())
        monkeypatch.setattr(provider, "_derive_key_software", lambda p, s: b"s" * 32)

        with pytest.warns(hw.SoftwareFallbackWarning):
            key = provider.hsm_derive_key(b"pw", b"s" * 16, slot=0, pin="1234")
        assert key == b"s" * 32

    def test_derive_key_software_via_backend(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()

        class DummyBackend:
            def derive_key_argon2id(self, password, salt):
                return b"k" * 32

        import meow_decoder.crypto_backend as crypto_backend

        monkeypatch.setattr(crypto_backend, "get_default_backend", lambda: DummyBackend())
        key = provider._derive_key_software(b"pw", b"s" * 16)
        assert key == b"k" * 32

    def test_derive_key_software_import_error(self, monkeypatch):
        """When the Rust backend is unavailable AND the argon2 fallback
        module doesn't exist, _derive_key_software should propagate the
        ImportError since there is no viable fallback."""
        provider = hw.HardwareSecurityProvider()

        import meow_decoder.crypto_backend as crypto_backend

        def raise_import_error():
            raise ImportError("no backend")

        monkeypatch.setattr(crypto_backend, "get_default_backend", raise_import_error)

        # Also block the argon2 fallback
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "argon2.low_level" or name == "argon2":
                raise ImportError("no argon2")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        with pytest.raises(ImportError):
            provider._derive_key_software(b"pw", b"s" * 16)

    def test_hsm_derive_key_unavailable_raises(self, monkeypatch):
        provider = hw.HardwareSecurityProvider(allow_software_fallback=False)
        monkeypatch.setattr(provider, "detect_all", lambda: _caps())

        with pytest.raises(hw.HardwareNotFoundError):
            provider.hsm_derive_key(b"pw", b"s" * 16, slot=0, pin="1234")


class TestAddHardwareArgs:
    def test_add_hardware_args(self):
        parser = argparse.ArgumentParser()
        hw.add_hardware_args(parser)
        args = parser.parse_args([])
        assert hasattr(args, "hsm_slot")
        assert hasattr(args, "yubikey_piv")
        assert hasattr(args, "tpm_derive")
        assert hasattr(args, "hardware_auto")


class TestHardwareIntegrationMain:
    def test_main_runs(self, monkeypatch):
        class DummyProvider:
            def __init__(self, verbose=False):
                pass

            def detect_all(self):
                return _caps()

            def derive_key_auto(self, password, salt):
                return b"k" * 32, hw.HardwareType.SOFTWARE

        monkeypatch.setattr(hw, "HardwareSecurityProvider", DummyProvider)

        runpy.run_module("meow_decoder.hardware_integration", run_name="__main__")
