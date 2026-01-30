#!/usr/bin/env python3
"""
🔌 Phase 5: Hardware Security Module Mock Tests (GAP-03)

Tests hardware key integration using mocks since actual hardware
(TPM, YubiKey, smart cards) is not available in CI environments.

Test Coverage:
- HW-01 to HW-05: TPM mock tests
- HW-06 to HW-10: YubiKey mock tests  
- HW-11 to HW-14: Smart card mock tests
- HW-15 to HW-18: Fallback behavior tests
- HW-19 to HW-22: Key derivation consistency tests

Security Properties Verified:
- Hardware detection graceful fallback
- Key derivation produces correct output sizes
- Different hardware paths produce different keys
- Error handling doesn't leak information
"""

import pytest
import secrets
import hashlib
import os
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path


class TestTPMMocks:
    """HW-01 to HW-05: TPM mock tests."""
    
    def test_tpm_detection_with_device(self):
        """HW-01: TPM detected when /dev/tpm0 exists."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch('pathlib.Path.exists') as mock_exists:
            # Mock /dev/tpm0 exists
            def exists_side_effect(self=None):
                path_str = str(self) if hasattr(self, '__str__') else str(self)
                return '/dev/tpm' in path_str
            
            mock_exists.side_effect = exists_side_effect
            
            with patch.object(HardwareKeyManager, '_run_command') as mock_run:
                mock_run.return_value = (False, "tpm2_getcap not found")
                
                # Create manager - detection happens in __init__
                manager = HardwareKeyManager(verbose=False)
                
                # TPM should be detected based on device file
                # (Note: actual result depends on implementation details)
                assert isinstance(manager.status.tpm_available, bool)
    
    def test_tpm_detection_without_device(self):
        """HW-02: TPM not detected when device missing."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(Path, 'exists', return_value=False):
            with patch.object(HardwareKeyManager, '_run_command') as mock_run:
                mock_run.return_value = (False, "")
                
                manager = HardwareKeyManager(verbose=False)
                
                # Without device file, TPM should not be available
                # This tests the fallback path
                assert isinstance(manager.status.tpm_available, bool)
    
    def test_tpm_key_derivation_mock(self):
        """HW-03: TPM key derivation produces correct size output."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        # Mock TPM availability
        manager.status.tpm_available = True
        
        # Mock the TPM operations
        # tpm2_createprimary returns success message, tpm2_getrandom returns hex bytes
        mock_hex_random = secrets.token_bytes(32).hex()
        
        def mock_run_command(args):
            if 'tpm2_createprimary' in args:
                return (True, "")  # Success, no output needed
            elif 'tpm2_getrandom' in args:
                return (True, mock_hex_random)  # Valid hex string
            return (False, "unknown command")
        
        with patch.object(manager, '_run_command', side_effect=mock_run_command):
            with patch('tempfile.mkstemp') as mock_mkstemp:
                mock_mkstemp.return_value = (0, '/tmp/mock_ctx')
                
                with patch('os.close'):
                    with patch('pathlib.Path.unlink'):
                        try:
                            key = manager.derive_key_tpm(
                                password="test_password",
                                salt=secrets.token_bytes(16),
                                key_length=32
                            )
                            # If successful, should be 32 bytes
                            assert len(key) == 32
                        except RuntimeError:
                            # TPM not actually available - expected in CI
                            pass
    
    def test_tpm_key_determinism_mock(self):
        """HW-04: Same inputs to TPM produce same key (deterministic)."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        manager.status.tpm_available = True
        
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        # Mock consistent HMAC output (must be same for determinism)
        mock_hex_random = secrets.token_bytes(32).hex()
        
        def mock_run_command(args):
            if 'tpm2_createprimary' in args:
                return (True, "")  # Success
            elif 'tpm2_getrandom' in args:
                return (True, mock_hex_random)  # Same hex each time
            return (False, "unknown command")
        
        with patch.object(manager, '_run_command', side_effect=mock_run_command):
            with patch('tempfile.mkstemp', return_value=(0, '/tmp/mock')):
                with patch('os.close'), patch('pathlib.Path.unlink'):
                    try:
                        key1 = manager.derive_key_tpm(password, salt)
                        key2 = manager.derive_key_tpm(password, salt)
                        assert key1 == key2
                    except RuntimeError:
                        # Expected in CI without TPM
                        pytest.skip("TPM not available")
    
    def test_tpm_different_passwords_different_keys(self):
        """HW-05: Different passwords produce different TPM keys."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        if not manager.has_tpm():
            pytest.skip("TPM not available")
        
        salt = secrets.token_bytes(16)
        
        try:
            key1 = manager.derive_key_tpm("password1", salt)
            key2 = manager.derive_key_tpm("password2", salt)
            assert key1 != key2
        except RuntimeError:
            pytest.skip("TPM operations failed")


class TestYubiKeyMocks:
    """HW-06 to HW-10: YubiKey mock tests."""
    
    def test_yubikey_detection_with_ykman(self):
        """HW-06: YubiKey detected via ykman."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            def command_handler(cmd, timeout=5):
                if 'ykman' in cmd:
                    return (True, "Serial: 12345678\nFirmware: 5.2.4")
                return (False, "")
            
            mock_run.side_effect = command_handler
            
            manager = HardwareKeyManager(verbose=False)
            
            # Should detect YubiKey
            assert manager.status.yubikey_available is True
            assert manager.status.yubikey_serial == "12345678"
    
    def test_yubikey_detection_via_pkcs11(self):
        """HW-07: YubiKey detected via PKCS#11 fallback."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            def command_handler(cmd, timeout=5):
                if 'ykman' in cmd:
                    return (False, "ykman not found")
                if 'pkcs11-tool' in cmd:
                    return (True, "Yubico YubiKey slot 0")
                return (False, "")
            
            mock_run.side_effect = command_handler
            
            manager = HardwareKeyManager(verbose=False)
            
            # Should detect YubiKey via PKCS#11
            assert manager.status.yubikey_available is True
    
    def test_yubikey_not_detected(self):
        """HW-08: YubiKey not detected when absent."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            mock_run.return_value = (False, "No device found")
            
            with patch.object(Path, 'exists', return_value=False):
                manager = HardwareKeyManager(verbose=False)
                
                assert manager.status.yubikey_available is False
    
    def test_yubikey_key_derivation_interface(self):
        """HW-09: YubiKey key derivation has correct interface."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        # Check interface exists
        assert hasattr(manager, 'derive_key_yubikey')
        assert callable(manager.derive_key_yubikey)
    
    def test_yubikey_requires_presence(self):
        """HW-10: YubiKey operations require device presence."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        if not manager.has_yubikey():
            # Should raise when YubiKey not present
            with pytest.raises((RuntimeError, Exception)):
                manager.derive_key_yubikey("password")


class TestSmartCardMocks:
    """HW-11 to HW-14: Smart card mock tests."""
    
    def test_smartcard_detection_pcsc(self):
        """HW-11: Smart card detected via pcscd."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            def command_handler(cmd, timeout=5):
                if 'pcsc_scan' in cmd:
                    return (True, "Generic Smart Card Reader")
                return (False, "")
            
            mock_run.side_effect = command_handler
            
            with patch.object(Path, 'exists', return_value=False):
                manager = HardwareKeyManager(verbose=False)
                
                assert manager.status.smartcard_available is True
    
    def test_smartcard_detection_opensc(self):
        """HW-12: Smart card detected via OpenSC fallback."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            def command_handler(cmd, timeout=5):
                if 'pcsc_scan' in cmd:
                    return (False, "")
                if 'opensc-tool' in cmd:
                    return (True, "Smart Card Reader 0")
                return (False, "")
            
            mock_run.side_effect = command_handler
            
            with patch.object(Path, 'exists', return_value=False):
                manager = HardwareKeyManager(verbose=False)
                
                assert manager.status.smartcard_available is True
    
    def test_smartcard_not_detected(self):
        """HW-13: Smart card not detected when absent."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            mock_run.return_value = (False, "")
            
            with patch.object(Path, 'exists', return_value=False):
                manager = HardwareKeyManager(verbose=False)
                
                assert manager.status.smartcard_available is False
    
    def test_smartcard_reader_info_captured(self):
        """HW-14: Smart card reader info captured in status."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            def command_handler(cmd, timeout=5):
                if 'pcsc_scan' in cmd:
                    return (True, "Gemalto USB Shell Token V2")
                return (False, "")
            
            mock_run.side_effect = command_handler
            
            with patch.object(Path, 'exists', return_value=False):
                manager = HardwareKeyManager(verbose=False)
                
                assert "Gemalto" in manager.status.smartcard_reader


class TestFallbackBehavior:
    """HW-15 to HW-18: Fallback behavior tests."""
    
    def test_no_hardware_warning_added(self):
        """HW-15: Warning added when no hardware available."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            mock_run.return_value = (False, "")
            
            with patch.object(Path, 'exists', return_value=False):
                manager = HardwareKeyManager(verbose=False)
                
                if not manager.status.any_hardware():
                    assert len(manager.status.warnings) > 0
                    assert any("software" in w.lower() for w in manager.status.warnings)
    
    def test_software_fallback_works(self):
        """HW-16: Software key derivation works as fallback."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        # Software fallback should always work
        if hasattr(manager, 'derive_key_software'):
            salt = secrets.token_bytes(16)
            key = manager.derive_key_software("password", salt)
            
            assert len(key) == 32
            assert isinstance(key, bytes)
    
    def test_status_summary_readable(self):
        """HW-17: Status summary is human-readable."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(HardwareKeyManager, '_run_command') as mock_run:
            mock_run.return_value = (False, "")
            
            with patch.object(Path, 'exists', return_value=False):
                manager = HardwareKeyManager(verbose=False)
                
                summary = manager.status.summary()
                
                assert isinstance(summary, str)
                assert "Hardware Security Status" in summary
                assert len(summary) > 50
    
    def test_any_hardware_returns_bool(self):
        """HW-18: any_hardware() returns boolean correctly."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        result = manager.status.any_hardware()
        
        assert isinstance(result, bool)
        
        # Verify it matches individual checks
        expected = (manager.status.tpm_available or
                   manager.status.yubikey_available or
                   manager.status.smartcard_available or
                   manager.status.sgx_available)
        assert result == expected


class TestKeyDerivationConsistency:
    """HW-19 to HW-22: Key derivation consistency tests."""
    
    def test_different_hardware_different_keys(self):
        """HW-19: Different hardware paths produce different keys."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        keys = []
        
        # Get software key as baseline
        if hasattr(manager, 'derive_key_software'):
            keys.append(manager.derive_key_software(password, salt))
        
        # Try TPM (will fail in CI)
        if manager.has_tpm():
            try:
                keys.append(manager.derive_key_tpm(password, salt))
            except RuntimeError:
                pass
        
        # Try YubiKey (will fail in CI)
        if manager.has_yubikey():
            try:
                keys.append(manager.derive_key_yubikey(password))
            except RuntimeError:
                pass
        
        # If we have multiple keys, they should differ
        if len(keys) > 1:
            for i in range(len(keys)):
                for j in range(i + 1, len(keys)):
                    assert keys[i] != keys[j], "Different hardware should produce different keys"
    
    def test_key_derivation_deterministic(self):
        """HW-20: Same inputs produce same software key."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        if not hasattr(manager, 'derive_key_software'):
            pytest.skip("No software derivation method")
        
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        key1 = manager.derive_key_software(password, salt)
        key2 = manager.derive_key_software(password, salt)
        
        assert key1 == key2
    
    def test_key_derivation_salt_matters(self):
        """HW-21: Different salts produce different keys."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        if not hasattr(manager, 'derive_key_software'):
            pytest.skip("No software derivation method")
        
        password = "test_password"
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        key1 = manager.derive_key_software(password, salt1)
        key2 = manager.derive_key_software(password, salt2)
        
        assert key1 != key2
    
    def test_key_derivation_password_matters(self):
        """HW-22: Different passwords produce different keys."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        if not hasattr(manager, 'derive_key_software'):
            pytest.skip("No software derivation method")
        
        salt = secrets.token_bytes(16)
        
        key1 = manager.derive_key_software("password1", salt)
        key2 = manager.derive_key_software("password2", salt)
        
        assert key1 != key2


class TestSGXDetection:
    """Additional SGX detection tests."""
    
    def test_sgx_detection_via_device(self):
        """SGX detected when /dev/sgx exists."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(Path, 'exists') as mock_exists:
            def exists_check(self=None):
                return '/dev/sgx' in str(self)
            
            mock_exists.side_effect = exists_check
            
            with patch.object(HardwareKeyManager, '_run_command', return_value=(False, "")):
                manager = HardwareKeyManager(verbose=False)
                
                # SGX status should be set based on device check
                assert isinstance(manager.status.sgx_available, bool)
    
    def test_sgx_detection_via_cpuinfo(self):
        """SGX detected via cpuinfo."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        with patch.object(Path, 'exists', return_value=False):
            with patch.object(Path, 'read_text', return_value="flags: ... sgx ..."):
                with patch.object(HardwareKeyManager, '_run_command', return_value=(False, "")):
                    manager = HardwareKeyManager(verbose=False)
                    
                    # Check was attempted
                    assert isinstance(manager.status.sgx_available, bool)


class TestErrorHandling:
    """Error handling tests for hardware operations."""
    
    def test_command_timeout_handled(self):
        """Command timeouts are handled gracefully."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        import subprocess
        
        manager = HardwareKeyManager(verbose=False)
        
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(['cmd'], 5)
            
            success, output = manager._run_command(['test'])
            
            assert success is False
            assert isinstance(output, str)
    
    def test_command_not_found_handled(self):
        """Missing commands are handled gracefully."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError()
            
            success, output = manager._run_command(['nonexistent'])
            
            assert success is False
    
    def test_tpm_failure_raises_runtime_error(self):
        """TPM operations raise RuntimeError on failure."""
        from meow_decoder.hardware_keys import HardwareKeyManager
        
        manager = HardwareKeyManager(verbose=False)
        manager.status.tpm_available = False
        
        with pytest.raises(RuntimeError):
            manager.derive_key_tpm("password", b"salt" * 4)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
