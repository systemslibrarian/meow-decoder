"""Tests for hardware integration modules."""

import pytest
import argparse


class TestHardwareIntegration:
    def test_hardware_integration_import(self):
        from meow_decoder.hardware_integration import HardwareSecurityProvider

        assert HardwareSecurityProvider is not None

    def test_hardware_security_provider_init(self):
        from meow_decoder.hardware_integration import HardwareSecurityProvider

        provider = HardwareSecurityProvider(verbose=False)
        assert provider is not None

    def test_hardware_security_provider_verbose(self):
        from meow_decoder.hardware_integration import HardwareSecurityProvider

        provider = HardwareSecurityProvider(verbose=True)
        assert provider is not None

    def test_detect_all_capabilities(self):
        from meow_decoder.hardware_integration import HardwareSecurityProvider

        provider = HardwareSecurityProvider(verbose=False)
        caps = provider.detect_all()
        assert caps is not None
        assert hasattr(caps, "summary")

    def test_process_hardware_args_none(self):
        from meow_decoder.hardware_integration import process_hardware_args

        args = argparse.Namespace(
            hsm_slot=None,
            hsm_pin=None,
            hsm_key_label="meow-master",
            tpm_derive=False,
            hardware_auto=False,
            no_hardware_fallback=False,
        )
        result = process_hardware_args(args, b"password", b"salt" * 2)
        assert result is not None

    def test_process_hardware_args_auto_no_hardware(self):
        from meow_decoder.hardware_integration import process_hardware_args

        args = argparse.Namespace(
            hsm_slot=None,
            hsm_pin=None,
            hsm_key_label="meow-master",
            tpm_derive=False,
            hardware_auto=True,
            no_hardware_fallback=False,
        )
        try:
            result = process_hardware_args(args, b"password", b"salt" * 2)
        except Exception:
            pass


class TestHardwareKeys:
    def test_hardware_keys_import(self):
        try:
            from meow_decoder import hardware_keys

            assert hardware_keys is not None
        except ImportError:
            pytest.skip("hardware_keys module not available")


class TestDeadMansSwitch:
    def test_deadmans_switch_import(self):
        try:
            from meow_decoder import deadmans_switch_cli

            assert deadmans_switch_cli is not None
        except ImportError:
            pytest.skip("deadmans_switch_cli module not available")
