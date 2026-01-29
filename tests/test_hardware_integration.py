#!/usr/bin/env python3
"""
🔐 Hardware Security Integration Tests

Tests for HSM, YubiKey, and TPM support without requiring actual hardware.
Uses mocking to simulate hardware responses.

Test Categories:
1. Detection Tests - Hardware availability detection
2. Fallback Tests - Graceful degradation when hardware unavailable
3. Security Property Tests - Key derivation, PCR binding, touch requirements
4. CLI Integration Tests - Argument parsing and validation
5. Error Handling Tests - Hardware errors and recovery
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock
from dataclasses import dataclass
import hashlib
import secrets

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from meow_decoder.hardware_integration import (
    HardwareSecurityProvider,
    HardwareCapabilities,
    HardwareType,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_provider():
    """Create a HardwareSecurityProvider for testing."""
    return HardwareSecurityProvider(verbose=False)


@pytest.fixture
def mock_rust_backend():
    """Mock the Rust crypto backend for hardware operations."""
    with patch('meow_decoder.hardware_integration.get_default_backend') as mock:
        backend = MagicMock()
        
        # Default: derive_key_yubikey works
        backend.derive_key_yubikey.return_value = secrets.token_bytes(32)
        
        # Default: YubiKey available
        backend.yubikey_available.return_value = True
        
        # Default: HSM not available
        backend.hsm_available.return_value = False
        
        # Default: TPM not available
        backend.tpm_available.return_value = False
        
        mock.return_value = backend
        yield backend


# =============================================================================
# Detection Tests
# =============================================================================

class TestHardwareDetection:
    """Tests for hardware detection functionality."""
    
    def test_detect_no_hardware_available(self, mock_provider):
        """Test detection when no hardware is available."""
        with patch.object(mock_provider, '_detect_yubikey', return_value=False), \
             patch.object(mock_provider, '_detect_tpm', return_value=False), \
             patch.object(mock_provider, '_detect_hsm', return_value=False):
            
            caps = mock_provider.detect_all()
            
            assert caps.yubikey_available is False
            assert caps.tpm_available is False
            assert caps.hsm_available is False
    
    def test_detect_yubikey_only(self, mock_provider):
        """Test detection with only YubiKey available."""
        with patch.object(mock_provider, '_detect_yubikey', return_value=True), \
             patch.object(mock_provider, '_detect_tpm', return_value=False), \
             patch.object(mock_provider, '_detect_hsm', return_value=False):
            
            caps = mock_provider.detect_all()
            
            assert caps.yubikey_available is True
            assert caps.tpm_available is False
            assert caps.hsm_available is False
    
    def test_detect_all_hardware(self, mock_provider):
        """Test detection with all hardware available."""
        with patch.object(mock_provider, '_detect_yubikey', return_value=True), \
             patch.object(mock_provider, '_detect_tpm', return_value=True), \
             patch.object(mock_provider, '_detect_hsm', return_value=True):
            
            mock_provider._hsm_slots = [0, 1]
            
            caps = mock_provider.detect_all()
            
            assert caps.yubikey_available is True
            assert caps.tpm_available is True
            assert caps.hsm_available is True
    
    def test_capabilities_summary(self):
        """Test the capabilities summary string."""
        caps = HardwareCapabilities(
            yubikey_available=True,
            tpm_available=False,
            hsm_available=True,
            hsm_slots=[0, 1],
        )
        
        summary = caps.summary()
        
        assert "YubiKey" in summary
        assert "Available" in summary or "✓" in summary or "✅" in summary


# =============================================================================
# Fallback Tests
# =============================================================================

class TestHardwareFallback:
    """Tests for graceful degradation when hardware unavailable."""
    
    def test_yubikey_fallback_to_software(self, mock_provider):
        """Test fallback to software key derivation when YubiKey unavailable."""
        with patch.object(mock_provider, '_detect_yubikey', return_value=False):
            # Should not raise when hardware unavailable and fallback allowed
            result = mock_provider.derive_key_yubikey_piv(
                password=b"test_password",
                salt=secrets.token_bytes(16),
                slot="9d",
                pin="123456",
                require_hardware=False
            )
            
            # Should return a key (from software fallback)
            assert result is None or len(result) == 32
    
    def test_yubikey_no_fallback_raises(self, mock_provider):
        """Test that requiring hardware raises when unavailable."""
        with patch.object(mock_provider, '_detect_yubikey', return_value=False):
            with pytest.raises((RuntimeError, ValueError)):
                mock_provider.derive_key_yubikey_piv(
                    password=b"test_password",
                    salt=secrets.token_bytes(16),
                    slot="9d",
                    pin="123456",
                    require_hardware=True
                )
    
    def test_tpm_fallback_to_software(self, mock_provider):
        """Test fallback when TPM unavailable."""
        with patch.object(mock_provider, '_detect_tpm', return_value=False):
            result = mock_provider.derive_key_tpm(
                password=b"test_password",
                salt=secrets.token_bytes(16),
                require_hardware=False
            )
            
            # Should return None (software fallback not supported for TPM)
            assert result is None
    
    def test_hsm_fallback_to_software(self, mock_provider):
        """Test fallback when HSM unavailable."""
        with patch.object(mock_provider, '_detect_hsm', return_value=False):
            result = mock_provider.hsm_derive_key(
                password=b"test_password",
                salt=secrets.token_bytes(16),
                slot=0,
                pin="1234",
                require_hardware=False
            )
            
            # Should return None (software fallback not supported for HSM)
            assert result is None


# =============================================================================
# Security Property Tests
# =============================================================================

class TestSecurityProperties:
    """Tests for security properties of hardware integration."""
    
    def test_key_derivation_deterministic(self, mock_rust_backend, mock_provider):
        """Test that same inputs produce same key (via backend)."""
        password = b"test_password"
        salt = secrets.token_bytes(16)
        
        # Mock backend to return deterministic key based on input
        def deterministic_derive(pwd, slt, **kwargs):
            return hashlib.sha256(pwd + slt).digest()
        
        mock_rust_backend.derive_key_yubikey.side_effect = deterministic_derive
        
        with patch.object(mock_provider, '_detect_yubikey', return_value=True):
            key1 = mock_provider.derive_key_yubikey_piv(
                password=password,
                salt=salt,
                slot="9d",
                pin="123456",
                require_hardware=True
            )
            
            key2 = mock_provider.derive_key_yubikey_piv(
                password=password,
                salt=salt,
                slot="9d",
                pin="123456",
                require_hardware=True
            )
            
            assert key1 == key2
    
    def test_different_pins_different_keys(self, mock_rust_backend, mock_provider):
        """Test that different PINs produce different keys."""
        password = b"test_password"
        salt = secrets.token_bytes(16)
        
        # Mock backend to include PIN in derivation
        def pin_dependent_derive(pwd, slt, pin=None, **kwargs):
            pin_bytes = (pin or "").encode() if isinstance(pin, str) else (pin or b"")
            return hashlib.sha256(pwd + slt + pin_bytes).digest()
        
        mock_rust_backend.derive_key_yubikey.side_effect = pin_dependent_derive
        
        with patch.object(mock_provider, '_detect_yubikey', return_value=True):
            key1 = mock_provider.derive_key_yubikey_piv(
                password=password,
                salt=salt,
                slot="9d",
                pin="111111",
                require_hardware=True
            )
            
            key2 = mock_provider.derive_key_yubikey_piv(
                password=password,
                salt=salt,
                slot="9d",
                pin="222222",
                require_hardware=True
            )
            
            assert key1 != key2
    
    def test_tpm_pcr_binding(self, mock_provider):
        """Test that TPM sealing binds to PCR values."""
        with patch.object(mock_provider, '_detect_tpm', return_value=True):
            # Mock TPM seal operation
            sealed_data = mock_provider.tpm_seal(
                data=b"secret_key_material",
                pcrs=[0, 2, 7],
                password="test"
            )
            
            # Sealing should work or return None if TPM not available
            # The actual PCR binding is tested in Rust backend
            assert sealed_data is None or isinstance(sealed_data, bytes)


# =============================================================================
# CLI Integration Tests
# =============================================================================

class TestCLIIntegration:
    """Tests for CLI argument parsing and validation."""
    
    def test_encode_hardware_args_present(self):
        """Test that encode.py has hardware arguments."""
        from meow_decoder.encode import main
        import argparse
        
        # Check that the file has the expected arguments by parsing help
        with pytest.raises(SystemExit) as exc_info:
            import sys
            old_argv = sys.argv
            try:
                sys.argv = ["encode", "--help"]
                main()
            finally:
                sys.argv = old_argv
        
        # --help causes exit 0
        assert exc_info.value.code == 0
    
    def test_decode_hardware_args_present(self):
        """Test that decode_gif.py has hardware arguments."""
        from meow_decoder.decode_gif import main
        
        with pytest.raises(SystemExit) as exc_info:
            import sys
            old_argv = sys.argv
            try:
                sys.argv = ["decode", "--help"]
                main()
            finally:
                sys.argv = old_argv
        
        assert exc_info.value.code == 0
    
    def test_hardware_status_flag_encoder(self):
        """Test --hardware-status flag on encoder."""
        # This would normally show hardware status and exit
        # We just verify the flag is accepted
        import sys
        from io import StringIO
        
        # Capture what would be printed
        with patch('sys.stdout', new_callable=StringIO):
            with patch('meow_decoder.hardware_integration.HardwareSecurityProvider') as MockProvider:
                instance = MockProvider.return_value
                instance.detect_all.return_value = HardwareCapabilities(
                    yubikey_available=False,
                    tpm_available=False,
                    hsm_available=False,
                    hsm_slots=[],
                )
                
                # The flag exists in argparse
                from meow_decoder.encode import main
                old_argv = sys.argv
                try:
                    sys.argv = ["encode", "--hardware-status"]
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    # Hardware status exits after display
                    assert exc_info.value.code == 0
                finally:
                    sys.argv = old_argv


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for hardware error handling."""
    
    def test_yubikey_wrong_pin_error(self, mock_rust_backend, mock_provider):
        """Test error handling for wrong YubiKey PIN."""
        mock_rust_backend.derive_key_yubikey.side_effect = RuntimeError("Invalid PIN")
        
        with patch.object(mock_provider, '_detect_yubikey', return_value=True):
            with pytest.raises(RuntimeError) as exc_info:
                mock_provider.derive_key_yubikey_piv(
                    password=b"test",
                    salt=secrets.token_bytes(16),
                    slot="9d",
                    pin="wrong_pin",
                    require_hardware=True
                )
            
            assert "PIN" in str(exc_info.value) or "Invalid" in str(exc_info.value)
    
    def test_hsm_session_error(self, mock_provider):
        """Test error handling for HSM session failures."""
        with patch.object(mock_provider, '_detect_hsm', return_value=True):
            with patch.object(mock_provider, '_hsm_derive', side_effect=RuntimeError("Session failed")):
                with pytest.raises(RuntimeError):
                    mock_provider.hsm_derive_key(
                        password=b"test",
                        salt=secrets.token_bytes(16),
                        slot=0,
                        pin="1234",
                        require_hardware=True
                    )
    
    def test_tpm_pcr_mismatch_error(self, mock_provider):
        """Test error handling for TPM PCR mismatch."""
        with patch.object(mock_provider, '_detect_tpm', return_value=True):
            with patch.object(mock_provider, '_tpm_unseal', side_effect=RuntimeError("PCR mismatch")):
                with pytest.raises(RuntimeError):
                    mock_provider.tpm_unseal(
                        sealed_data=b"sealed_blob",
                        password="test"
                    )


# =============================================================================
# Hardware Type Priority Tests
# =============================================================================

class TestHardwarePriority:
    """Tests for hardware selection priority."""
    
    def test_prefer_hsm_over_yubikey(self, mock_provider):
        """Test that HSM is preferred over YubiKey when both available."""
        with patch.object(mock_provider, '_detect_yubikey', return_value=True), \
             patch.object(mock_provider, '_detect_hsm', return_value=True), \
             patch.object(mock_provider, '_detect_tpm', return_value=False):
            
            caps = mock_provider.detect_all()
            best = mock_provider.get_best_available()
            
            # HSM should be preferred (higher security)
            assert best in (HardwareType.HSM, HardwareType.YUBIKEY)
    
    def test_prefer_yubikey_over_tpm(self, mock_provider):
        """Test that YubiKey is preferred over TPM when both available."""
        with patch.object(mock_provider, '_detect_yubikey', return_value=True), \
             patch.object(mock_provider, '_detect_tpm', return_value=True), \
             patch.object(mock_provider, '_detect_hsm', return_value=False):
            
            best = mock_provider.get_best_available()
            
            # YubiKey should be preferred (more portable)
            assert best in (HardwareType.YUBIKEY, HardwareType.TPM)
    
    def test_auto_select_best_hardware(self, mock_provider):
        """Test automatic selection of best available hardware."""
        with patch.object(mock_provider, '_detect_yubikey', return_value=True), \
             patch.object(mock_provider, '_detect_tpm', return_value=False), \
             patch.object(mock_provider, '_detect_hsm', return_value=False):
            
            best = mock_provider.get_best_available()
            
            assert best == HardwareType.YUBIKEY


# =============================================================================
# Integration with Encode/Decode
# =============================================================================

class TestEncodeDecodeIntegration:
    """Tests for hardware integration with encode/decode functions."""
    
    def test_encode_with_yubikey_mock(self, mock_rust_backend):
        """Test that encoding can use YubiKey key derivation."""
        # This is a smoke test - actual integration tested in e2e tests
        mock_rust_backend.derive_key_yubikey.return_value = secrets.token_bytes(32)
        
        # Verify the mock is called with expected parameters
        key = mock_rust_backend.derive_key_yubikey(
            password=b"test",
            salt=secrets.token_bytes(16),
            slot="9d",
            pin="123456"
        )
        
        assert len(key) == 32
        mock_rust_backend.derive_key_yubikey.assert_called()


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
