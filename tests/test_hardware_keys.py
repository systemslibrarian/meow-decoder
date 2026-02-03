"""Tests for hardware_keys module."""

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

    def test_check_sgx_from_cpuinfo(self, monkeypatch):
        manager = hk.HardwareKeyManager()

        def fake_exists(self):
            return False

        def fake_read_text(self):
            return "flags: sgx"

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        assert manager._check_sgx() is True


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


class TestUtilityHelpers:
    def test_check_hardware_security_returns_status(self, monkeypatch):
        class DummyManager:
            def __init__(self):
                self.status = hk.HardwareStatus()

        monkeypatch.setattr(hk, "HardwareKeyManager", DummyManager)
        status = hk.check_hardware_security()
        assert isinstance(status, hk.HardwareStatus)
