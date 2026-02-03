"""Tests for hardware_keys module."""

import argparse
import runpy
from pathlib import Path

import pytest

import meow_decoder.hardware_keys as hk


class TestHardwareStatus:
    def test_any_hardware(self):
        status = hk.HardwareStatus(tpm_available=True)
        assert status.any_hardware() is True

        status = hk.HardwareStatus()
        assert status.any_hardware() is False

    def test_summary_includes_warnings(self):
        status = hk.HardwareStatus()
        status.warnings.append("warn")
        summary = status.summary()
        assert "Warnings" in summary
        assert "warn" in summary

    def test_summary_with_hardware(self):
        status = hk.HardwareStatus(
            tpm_available=True,
            tpm_version="2.0",
            tpm_manufacturer="TEST",
            yubikey_available=True,
            yubikey_serial="123",
            smartcard_available=True,
            smartcard_reader="Reader",
            sgx_available=True,
            sgx_version="1.0",
        )
        summary = status.summary()
        assert "✅ TPM" in summary
        assert "✅ YubiKey" in summary
        assert "✅ Smart card" in summary
        assert "✅ Intel SGX" in summary

    def test_post_init_with_existing_warnings(self):
        status = hk.HardwareStatus(warnings=["keep"])
        assert status.warnings == ["keep"]


class TestDetectionHelpers:
    def test_check_tpm_device_present_tools_missing(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_exists(self):
            return str(self) in {"/dev/tpm0", "/dev/tpmrm0"}

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(manager, "_run_command", lambda *args, **kwargs: (False, ""))

        available, info = manager._check_tpm()
        assert available is True
        assert "2.0" in info.get("version", "")

    def test_check_tpm_no_device(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        monkeypatch.setattr(Path, "exists", lambda self: False)

        available, info = manager._check_tpm()
        assert available is False
        assert info == {}

    def test_check_tpm_parses_properties(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_exists(self):
            return str(self) in {"/dev/tpm0", "/dev/tpmrm0"}

        def fake_run(cmd, timeout=5):
            return True, "TPM2_PT_MANUFACTURER: ACME\nTPM2_PT_FIRMWARE_VERSION: 7.1\n"

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(manager, "_run_command", fake_run)

        available, info = manager._check_tpm()
        assert available is True
        assert info["manufacturer"] == "ACME"
        assert info["version"] == "7.1"

    def test_check_tpm_defaults_version(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_exists(self):
            return str(self) in {"/dev/tpm0", "/dev/tpmrm0"}

        def fake_run(cmd, timeout=5):
            return True, "TPM2_PT_MANUFACTURER: ACME\n"

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(manager, "_run_command", fake_run)

        available, info = manager._check_tpm()
        assert available is True
        assert info["version"] == "2.0"

    def test_check_yubikey_from_ykman(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_run(cmd, timeout=5):
            if cmd == ["ykman", "info"]:
                return True, "Serial: 12345\nFirmware: 5.4.3\n"
            return False, ""

        monkeypatch.setattr(manager, "_run_command", fake_run)
        available, info = manager._check_yubikey()
        assert available is True
        assert info["serial"] == "12345"
        assert info["version"] == "5.4.3"

    def test_check_yubikey_pkcs11_fallback(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_run(cmd, timeout=5):
            if cmd == ["ykman", "info"]:
                return False, ""
            if cmd == ["pkcs11-tool", "--list-slots"]:
                return True, "Yubico"
            return False, ""

        monkeypatch.setattr(manager, "_run_command", fake_run)
        available, info = manager._check_yubikey()
        assert available is True
        assert info["serial"] == "via PKCS#11"

    def test_check_yubikey_not_found(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_run(cmd, timeout=5):
            return False, ""

        monkeypatch.setattr(manager, "_run_command", fake_run)
        available, info = manager._check_yubikey()
        assert available is False
        assert info == {}

    def test_check_smartcard(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_run(cmd, timeout=5):
            if cmd == ["pcsc_scan", "-r"]:
                return True, "Reader 0: MockReader"
            return False, ""

        monkeypatch.setattr(manager, "_run_command", fake_run)
        available, info = manager._check_smartcard()
        assert available is True
        assert "MockReader" in info["reader"]

    def test_check_smartcard_opensc_fallback(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_run(cmd, timeout=5):
            if cmd == ["pcsc_scan", "-r"]:
                return False, ""
            if cmd == ["opensc-tool", "-l"]:
                return True, "OpenSC Reader"
            return False, ""

        monkeypatch.setattr(manager, "_run_command", fake_run)
        available, info = manager._check_smartcard()
        assert available is True
        assert "OpenSC" in info["reader"]

    def test_check_smartcard_not_found(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        monkeypatch.setattr(manager, "_run_command", lambda *args, **kwargs: (False, ""))

        available, info = manager._check_smartcard()
        assert available is False
        assert info == {}

    def test_check_sgx_from_cpuinfo(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_exists(self):
            return False

        def fake_read_text(self):
            return "flags: sgx"

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        assert manager._check_sgx() is True

    def test_check_sgx_device_present(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_exists(self):
            return str(self) in {"/dev/sgx", "/dev/sgx_enclave"}

        monkeypatch.setattr(Path, "exists", fake_exists)
        assert manager._check_sgx() is True

    def test_check_sgx_read_error(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_exists(self):
            return False

        def fake_read_text(self):
            raise OSError("boom")

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        assert manager._check_sgx() is False


class TestMockHardwareKeyManager:
    def test_mock_detects_hardware(self):
        manager = hk.MockHardwareKeyManager(use_tpm=True, use_yubikey=False)
        assert manager.has_tpm() is True
        assert manager.has_yubikey() is False

    def test_mock_derive_key_tpm(self):
        manager = hk.MockHardwareKeyManager(use_tpm=True, use_yubikey=False)
        key = manager.derive_key_tpm("password", b"s" * 16)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_mock_derive_key_yubikey(self):
        manager = hk.MockHardwareKeyManager(use_tpm=False, use_yubikey=True)
        key = manager.derive_key_yubikey("password", slot=2)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_mock_derive_key_auto_prefers_yubikey(self):
        manager = hk.MockHardwareKeyManager(use_tpm=True, use_yubikey=True)
        key, method = manager.derive_key_auto("password", b"s" * 16)
        assert method == "YubiKey"
        assert len(key) == 32

    def test_mock_no_hardware_warning(self):
        manager = hk.MockHardwareKeyManager(use_tpm=False, use_yubikey=False)
        assert manager.status.warnings

    def test_mock_missing_tpm_raises(self):
        manager = hk.MockHardwareKeyManager(use_tpm=False, use_yubikey=False)
        with pytest.raises(RuntimeError):
            manager.derive_key_tpm("password", b"s" * 16)

    def test_mock_missing_yubikey_raises(self):
        manager = hk.MockHardwareKeyManager(use_tpm=False, use_yubikey=False)
        with pytest.raises(RuntimeError):
            manager.derive_key_yubikey("password", slot=2)


class TestUtilityHelpers:
    def test_check_hardware_security_returns_status(self, monkeypatch):
        class DummyManager:
            def __init__(self):
                self.status = hk.HardwareStatus()

        monkeypatch.setattr(hk, "HardwareKeyManager", DummyManager)
        status = hk.check_hardware_security()
        assert isinstance(status, hk.HardwareStatus)

    def test_print_security_status(self, monkeypatch, capsys):
        class DummyManager:
            def __init__(self):
                self.status = hk.HardwareStatus()

        monkeypatch.setattr(hk, "HardwareKeyManager", DummyManager)
        hk.print_security_status()
        captured = capsys.readouterr()
        assert "Hardware Security Status" in captured.out


class TestKeyDerivation:
    def test_run_command_success(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        class DummyResult:
            returncode = 0
            stdout = "ok"
            stderr = ""

        monkeypatch.setattr(hk.subprocess, "run", lambda *args, **kwargs: DummyResult())
        ok, output = manager._run_command(["cmd"])
        assert ok is True
        assert output == "ok"

    def test_run_command_failure(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        monkeypatch.setattr(hk.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("no")))

        ok, output = manager._run_command(["cmd"])
        assert ok is False
        assert "no" in output

    def test_detect_hardware_no_devices_adds_warnings(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        monkeypatch.setattr(manager, "_check_tpm", lambda: (False, {}))
        monkeypatch.setattr(manager, "_check_yubikey", lambda: (False, {}))
        monkeypatch.setattr(manager, "_check_smartcard", lambda: (False, {}))
        monkeypatch.setattr(manager, "_check_sgx", lambda: False)

        status = manager._detect_hardware()
        assert status.warnings

    def test_detect_hardware_with_devices(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        monkeypatch.setattr(manager, "_check_tpm", lambda: (True, {"version": "2.0", "manufacturer": "ACME"}))
        monkeypatch.setattr(manager, "_check_yubikey", lambda: (True, {"serial": "123", "version": "5.0"}))
        monkeypatch.setattr(manager, "_check_smartcard", lambda: (True, {"reader": "Reader"}))
        monkeypatch.setattr(manager, "_check_sgx", lambda: True)

        status = manager._detect_hardware()
        assert status.tpm_available is True
        assert status.yubikey_available is True
        assert status.smartcard_available is True
        assert status.sgx_available is True

    def test_has_helpers(self):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(tpm_available=True, yubikey_available=True)
        assert manager.has_tpm() is True
        assert manager.has_yubikey() is True
        assert manager.has_hardware() is True

    def test_derive_key_tpm_not_available(self):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(tpm_available=False)
        with pytest.raises(RuntimeError):
            manager.derive_key_tpm("password", b"s" * 16)

    def test_derive_key_tpm_success(self, monkeypatch, tmp_path):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(tpm_available=True)

        def fake_run(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_createprimary":
                return True, "ok"
            if cmd and cmd[0] == "tpm2_getrandom":
                return True, "".join(["ab"] * 32)
            return True, ""

        monkeypatch.setattr(manager, "_run_command", fake_run)
        key = manager.derive_key_tpm("password", b"s" * 16)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_derive_key_tpm_fail_createprimary(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(tpm_available=True)
        monkeypatch.setattr(manager, "_run_command", lambda *args, **kwargs: (False, "fail"))

        with pytest.raises(RuntimeError, match="createprimary failed"):
            manager.derive_key_tpm("password", b"s" * 16)

    def test_derive_key_tpm_fail_getrandom(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(tpm_available=True)

        def fake_run(cmd, timeout=5):
            if cmd and cmd[0] == "tpm2_createprimary":
                return True, "ok"
            if cmd and cmd[0] == "tpm2_getrandom":
                return False, "fail"
            return True, ""

        monkeypatch.setattr(manager, "_run_command", fake_run)

        with pytest.raises(RuntimeError, match="getrandom failed"):
            manager.derive_key_tpm("password", b"s" * 16)

    def test_derive_key_yubikey_not_available(self):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(yubikey_available=False)

        with pytest.raises(RuntimeError):
            manager.derive_key_yubikey("password")

    def test_derive_key_yubikey_failure(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(yubikey_available=True)
        monkeypatch.setattr(manager, "_run_command", lambda *args, **kwargs: (False, "fail"))

        with pytest.raises(RuntimeError, match="challenge-response failed"):
            manager.derive_key_yubikey("password")

    def test_derive_key_yubikey_success(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(yubikey_available=True)

        monkeypatch.setattr(manager, "_run_command", lambda *args, **kwargs: (True, "".join(["aa"] * 20)))
        key = manager.derive_key_yubikey("password")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_derive_key_software(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        import argon2.low_level as low_level

        class DummyType:
            ID = object()

        monkeypatch.setattr(low_level, "Type", DummyType)
        monkeypatch.setattr(low_level, "hash_secret_raw", lambda **kwargs: b"k" * 32)
        key = manager.derive_key_software("password", b"s" * 16)
        assert key == b"k" * 32

    def test_derive_key_auto_paths(self, monkeypatch, capsys):
        manager = hk.HardwareKeyManager(verbose=True)
        manager.status = hk.HardwareStatus(yubikey_available=True, tpm_available=True)

        def fail_yk(*args, **kwargs):
            raise RuntimeError("yk fail")

        def fail_tpm(*args, **kwargs):
            raise RuntimeError("tpm fail")

        monkeypatch.setattr(manager, "derive_key_yubikey", fail_yk)
        monkeypatch.setattr(manager, "derive_key_tpm", fail_tpm)
        monkeypatch.setattr(manager, "derive_key_software", lambda *args, **kwargs: b"s" * 32)

        key, method = manager.derive_key_auto("password", b"s" * 16)
        assert method == "Software"
        assert key == b"s" * 32
        assert "YubiKey failed" in capsys.readouterr().out

    def test_derive_key_auto_yubikey_success(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(yubikey_available=True)
        monkeypatch.setattr(manager, "derive_key_yubikey", lambda *args, **kwargs: b"y" * 32)

        key, method = manager.derive_key_auto("password", b"s" * 16)
        assert method == "YubiKey"
        assert key == b"y" * 32

    def test_derive_key_auto_tpm_success(self, monkeypatch):
        manager = hk.HardwareKeyManager()
        manager.status = hk.HardwareStatus(tpm_available=True)
        monkeypatch.setattr(manager, "derive_key_tpm", lambda *args, **kwargs: b"t" * 32)

        key, method = manager.derive_key_auto("password", b"s" * 16)
        assert method == "TPM"
        assert key == b"t" * 32


class TestArgHelpers:
    def test_add_hardware_key_args(self):
        parser = argparse.ArgumentParser()
        hk.add_hardware_key_args(parser)
        args = parser.parse_args([])
        assert hasattr(args, "yubikey")
        assert hasattr(args, "tpm")
        assert hasattr(args, "check_hardware")


class TestHardwareKeysMain:
    def test_main_runs(self, monkeypatch):
        import argon2.low_level as low_level

        monkeypatch.setattr(low_level, "hash_secret_raw", lambda **kwargs: b"k" * 32)
        monkeypatch.setattr(hk.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("no")))

        runpy.run_module("meow_decoder.hardware_keys", run_name="__main__")
