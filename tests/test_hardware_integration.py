"""Tests for hardware integration utilities."""

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

    def test_detect_tpm_parses_properties(self, monkeypatch):
        provider = hw.HardwareSecurityProvider()
        caps = hw.HardwareCapabilities()

        def fake_exists(path):
            return path in {"/dev/tpm0", "/dev/tpmrm0"}

        tpm_output = (
            "TPM2_PT_FAMILY_INDICATOR: value: \"2.0\"\n"
            "TPM2_PT_MANUFACTURER: value: \"TEST\"\n"
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
