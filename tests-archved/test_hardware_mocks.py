#!/usr/bin/env python3
"""
Tests for mock hardware key providers.

These tests ensure CI can validate hardware key derivation without
real devices or external tooling.
"""

from meow_decoder.hardware_keys import MockHardwareKeyManager


def test_mock_hardware_auto_prefers_yubikey():
    manager = MockHardwareKeyManager(use_tpm=True, use_yubikey=True)
    key, method = manager.derive_key_auto("password", b"\x00" * 16)
    assert method == "YubiKey"
    assert len(key) == 32


def test_mock_hardware_auto_falls_back_to_tpm():
    manager = MockHardwareKeyManager(use_tpm=True, use_yubikey=False)
    key, method = manager.derive_key_auto("password", b"\x01" * 16)
    assert method == "TPM"
    assert len(key) == 32


def test_mock_tpm_deterministic():
    manager = MockHardwareKeyManager(use_tpm=True, use_yubikey=False)
    salt = b"\x02" * 16
    key1 = manager.derive_key_tpm("password", salt)
    key2 = manager.derive_key_tpm("password", salt)
    assert key1 == key2


def test_mock_tpm_changes_with_salt():
    manager = MockHardwareKeyManager(use_tpm=True, use_yubikey=False)
    key1 = manager.derive_key_tpm("password", b"\x03" * 16)
    key2 = manager.derive_key_tpm("password", b"\x04" * 16)
    assert key1 != key2


def test_mock_yubikey_deterministic():
    manager = MockHardwareKeyManager(use_tpm=False, use_yubikey=True)
    key1 = manager.derive_key_yubikey("password", slot=2)
    key2 = manager.derive_key_yubikey("password", slot=2)
    assert key1 == key2


def test_mock_yubikey_changes_with_password():
    manager = MockHardwareKeyManager(use_tpm=False, use_yubikey=True)
    key1 = manager.derive_key_yubikey("password", slot=2)
    key2 = manager.derive_key_yubikey("different", slot=2)
    assert key1 != key2
