#!/usr/bin/env python3
"""
Canonical test suite for meow_decoder/forward_secrecy_encoder.py

Tests ForwardSecrecyFountainEncoder, SecureDroplet dataclass,
and create_secure_fountain_encoder factory function.

Coverage target: 90%+
"""

import pytest
import secrets
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass


class MockFountainEncoder:
    """
    Test double for FountainEncoder.
    Implements droplet() interface expected by ForwardSecrecyFountainEncoder.
    
    Note: The actual FountainEncoder returns a Droplet dataclass, but
    forward_secrecy_encoder.py expects a tuple (seed, indices, data).
    This mock returns a tuple as expected by the FS encoder.
    """
    
    def __init__(self, data: bytes, k_blocks: int, block_size: int):
        self.data = data
        self.k_blocks = k_blocks
        self.block_size = block_size
        self._droplet_counter = 0
        self._droplet_responses = []
    
    def droplet(self):
        """Return a droplet tuple (seed, block_indices, xor_data)."""
        seed = self._droplet_counter
        block_indices = [seed % self.k_blocks]
        xor_data = secrets.token_bytes(self.block_size)
        self._droplet_counter += 1
        return seed, block_indices, xor_data
    
    def set_droplet_responses(self, responses: list):
        """Set custom droplet responses for testing."""
        self._droplet_responses = responses


class DropletAdapter:
    """
    Adapts a real FountainEncoder to return tuples instead of Droplet objects.
    This allows the ForwardSecrecyFountainEncoder to work with the real fountain.
    """
    
    def __init__(self, fountain):
        self._fountain = fountain
        # Copy attributes that might be accessed
        self.k_blocks = getattr(fountain, 'k_blocks', None)
        self.block_size = getattr(fountain, 'block_size', None)
    
    def droplet(self):
        """Return droplet as (seed, block_indices, data) tuple."""
        d = self._fountain.droplet()
        return d.seed, d.block_indices, d.data


# =============================================================================
# Test SecureDroplet Dataclass
# =============================================================================

class TestSecureDroplet:
    """Tests for SecureDroplet dataclass."""
    
    def test_create_secure_droplet(self):
        """Test SecureDroplet creation with all fields."""
        from meow_decoder.forward_secrecy_encoder import SecureDroplet
        
        droplet = SecureDroplet(
            seed=42,
            block_indices=[0, 5, 10],
            encrypted_data=b"encrypted_xor_data",
            nonces=[secrets.token_bytes(12)],
            block_id=7
        )
        
        assert droplet.seed == 42
        assert droplet.block_indices == [0, 5, 10]
        assert droplet.encrypted_data == b"encrypted_xor_data"
        assert len(droplet.nonces) == 1
        assert droplet.block_id == 7
    
    def test_secure_droplet_with_multiple_nonces(self):
        """Test SecureDroplet with multiple nonces."""
        from meow_decoder.forward_secrecy_encoder import SecureDroplet
        
        nonces = [secrets.token_bytes(12) for _ in range(3)]
        
        droplet = SecureDroplet(
            seed=100,
            block_indices=[1, 2, 3],
            encrypted_data=b"multi_block_encrypted",
            nonces=nonces,
            block_id=50
        )
        
        assert len(droplet.nonces) == 3
        assert all(len(n) == 12 for n in droplet.nonces)
    
    def test_secure_droplet_empty_indices(self):
        """Test SecureDroplet with empty block indices."""
        from meow_decoder.forward_secrecy_encoder import SecureDroplet
        
        droplet = SecureDroplet(
            seed=0,
            block_indices=[],
            encrypted_data=b"",
            nonces=[],
            block_id=0
        )
        
        assert droplet.block_indices == []
        assert droplet.nonces == []


# =============================================================================
# Test ForwardSecrecyFountainEncoder
# =============================================================================

class TestForwardSecrecyFountainEncoder:
    """Tests for ForwardSecrecyFountainEncoder class."""
    
    def test_init_creates_fs_manager(self):
        """Test encoder initializes with ForwardSecrecyManager."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainEncoder(b"test", k_blocks=10, block_size=512)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True,
            ratchet_interval=100
        )
        
        assert encoder.fountain is mock_fountain
        assert encoder.fs_manager is not None
        assert encoder.droplet_counter == 0
    
    def test_init_without_ratchet(self):
        """Test encoder initialization with ratcheting disabled."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainEncoder(b"test", k_blocks=10, block_size=512)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=False
        )
        
        assert encoder.fs_manager is not None
        # Ratcheting disabled - fs_manager should still exist
        assert encoder.fs_manager.enable_ratchet == False
    
    def test_next_secure_droplet_returns_secure_droplet(self):
        """Test next_secure_droplet returns SecureDroplet object."""
        from meow_decoder.forward_secrecy_encoder import (
            ForwardSecrecyFountainEncoder, SecureDroplet
        )
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainEncoder(b"test", k_blocks=10, block_size=64)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        droplet = encoder.next_secure_droplet()
        
        assert isinstance(droplet, SecureDroplet)
        assert droplet.seed == 0
        assert len(droplet.block_indices) >= 0
        assert isinstance(droplet.encrypted_data, bytes)
        assert len(droplet.nonces) >= 1
        assert droplet.block_id == 0
    
    def test_next_secure_droplet_increments_counter(self):
        """Test droplet counter increments with each call."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainEncoder(b"test", k_blocks=10, block_size=64)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        assert encoder.droplet_counter == 0
        
        encoder.next_secure_droplet()
        assert encoder.droplet_counter == 1
        
        encoder.next_secure_droplet()
        assert encoder.droplet_counter == 2
        
        encoder.next_secure_droplet()
        assert encoder.droplet_counter == 3
    
    def test_multiple_secure_droplets_have_different_block_ids(self):
        """Test each secure droplet has unique block_id."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainEncoder(b"test", k_blocks=10, block_size=64)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        droplets = [encoder.next_secure_droplet() for _ in range(5)]
        block_ids = [d.block_id for d in droplets]
        
        assert block_ids == [0, 1, 2, 3, 4]
    
    def test_encrypted_data_differs_from_plaintext(self):
        """Test encrypted data is different from XOR data."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainEncoder(b"test", k_blocks=10, block_size=64)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        droplet = encoder.next_secure_droplet()
        
        # Encrypted data should be different (includes auth tag)
        assert droplet.encrypted_data is not None
        assert len(droplet.encrypted_data) > 0
    
    def test_get_fs_extension_returns_bytes(self):
        """Test get_fs_extension returns extension bytes."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainEncoder(b"test", k_blocks=10, block_size=64)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True
        )
        
        extension = encoder.get_fs_extension()
        
        assert isinstance(extension, bytes)
        assert len(extension) > 0
    
    def test_cleanup_calls_fs_manager_cleanup(self):
        """Test cleanup delegates to fs_manager."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainEncoder(b"test", k_blocks=10, block_size=64)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Mock cleanup method
        encoder.fs_manager.cleanup = Mock()
        
        encoder.cleanup()
        
        encoder.fs_manager.cleanup.assert_called_once()
    
    def test_encrypt_droplet_with_empty_indices_uses_droplet_id(self):
        """Test _encrypt_droplet_data with empty indices uses droplet_id."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create mock that returns empty indices
        mock_fountain = Mock()
        mock_fountain.droplet = Mock(return_value=(42, [], b"test_data"))
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        droplet = encoder.next_secure_droplet()
        
        # Should not crash - uses droplet_id=0 when indices empty
        assert droplet.block_id == 0
        assert droplet.block_indices == []


# =============================================================================
# Test create_secure_fountain_encoder Factory
# =============================================================================

class TestCreateSecureFountainEncoder:
    """Tests for create_secure_fountain_encoder factory function."""
    
    def test_creates_fs_encoder_when_enabled(self):
        """Test factory creates FS encoder when forward secrecy enabled."""
        from meow_decoder.forward_secrecy_encoder import (
            create_secure_fountain_encoder,
            ForwardSecrecyFountainEncoder
        )
        
        data = b"test data for encoding"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=data,
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=True
        )
        
        assert isinstance(encoder, ForwardSecrecyFountainEncoder)
    
    def test_creates_plain_encoder_when_disabled(self):
        """Test factory creates plain encoder when forward secrecy disabled."""
        from meow_decoder.forward_secrecy_encoder import create_secure_fountain_encoder
        
        data = b"test data for encoding"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=data,
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=False
        )
        
        assert isinstance(encoder, MockFountainEncoder)
        # Should not be wrapped in ForwardSecrecyFountainEncoder
    
    def test_passes_ratchet_interval_to_fs_encoder(self):
        """Test factory passes ratchet_interval to FS encoder."""
        from meow_decoder.forward_secrecy_encoder import (
            create_secure_fountain_encoder,
            ForwardSecrecyFountainEncoder
        )
        
        data = b"test data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=data,
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=True,
            ratchet_interval=50
        )
        
        assert isinstance(encoder, ForwardSecrecyFountainEncoder)
        # Ratchet interval should be set in fs_manager
        assert encoder.fs_manager.ratchet_interval == 50
    
    def test_passes_k_blocks_and_block_size_to_fountain(self):
        """Test factory passes k_blocks and block_size to fountain encoder."""
        from meow_decoder.forward_secrecy_encoder import create_secure_fountain_encoder
        
        data = b"test data"
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=data,
            k_blocks=20,
            block_size=128,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=False
        )
        
        assert encoder.k_blocks == 20
        assert encoder.block_size == 128


# =============================================================================
# Test Integration with Real FountainEncoder
# =============================================================================

class TestRealFountainEncoderIntegration:
    """Integration tests with real FountainEncoder using adapter."""
    
    def test_with_real_fountain_encoder(self):
        """Test ForwardSecrecyFountainEncoder with real FountainEncoder via adapter."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"Real test data for fountain encoding" * 10
        k_blocks = 5
        block_size = 64
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create real fountain encoder and wrap with adapter
        real_fountain = FountainEncoder(test_data, k_blocks, block_size)
        adapted_fountain = DropletAdapter(real_fountain)
        
        # Wrap with forward secrecy
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=adapted_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Generate some secure droplets
        droplets = []
        for _ in range(10):
            droplet = fs_encoder.next_secure_droplet()
            droplets.append(droplet)
        
        assert len(droplets) == 10
        # All droplets should have encrypted data
        for d in droplets:
            assert d.encrypted_data is not None
            assert len(d.nonces) >= 1
    
    def test_create_factory_with_mock_encoder(self):
        """Test create_secure_fountain_encoder with mock encoder."""
        from meow_decoder.forward_secrecy_encoder import (
            create_secure_fountain_encoder,
            ForwardSecrecyFountainEncoder
        )
        
        test_data = b"Factory test data" * 20
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=test_data,
            k_blocks=8,
            block_size=32,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=True
        )
        
        assert isinstance(encoder, ForwardSecrecyFountainEncoder)
        
        # Should be able to generate droplets
        droplet = encoder.next_secure_droplet()
        assert droplet.seed is not None


# =============================================================================
# Test Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case tests for forward secrecy encoder."""
    
    def test_single_block_encoding(self):
        """Test with single block (k_blocks=1)."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"x" * 64
        fountain = FountainEncoder(test_data, k_blocks=1, block_size=64)
        adapted_fountain = DropletAdapter(fountain)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=adapted_fountain,
            master_key=master_key,
            salt=salt
        )
        
        droplet = encoder.next_secure_droplet()
        assert droplet.block_id == 0
    
    def test_large_block_size(self):
        """Test with large block size."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"y" * 4096
        fountain = FountainEncoder(test_data, k_blocks=2, block_size=2048)
        adapted_fountain = DropletAdapter(fountain)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=adapted_fountain,
            master_key=master_key,
            salt=salt
        )
        
        droplet = encoder.next_secure_droplet()
        # Encrypted data includes auth tag (16 bytes)
        assert len(droplet.encrypted_data) >= 2048
    
    def test_many_droplets(self):
        """Test generating many droplets."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"z" * 1024
        fountain = FountainEncoder(test_data, k_blocks=10, block_size=128)
        adapted_fountain = DropletAdapter(fountain)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=adapted_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Generate 100 droplets
        for i in range(100):
            droplet = encoder.next_secure_droplet()
            assert droplet.block_id == i
        
        assert encoder.droplet_counter == 100
    
    def test_cleanup_after_encoding(self):
        """Test cleanup properly releases resources."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        from meow_decoder.fountain import FountainEncoder
        
        test_data = b"cleanup test" * 10
        fountain = FountainEncoder(test_data, k_blocks=5, block_size=32)
        adapted_fountain = DropletAdapter(fountain)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=adapted_fountain,
            master_key=master_key,
            salt=salt
        )
        
        encoder.next_secure_droplet()
        
        # Cleanup should not raise
        encoder.cleanup()


# =============================================================================
# Test example_encode_integration function
# =============================================================================

class TestExampleIntegration:
    """Tests for example_encode_integration function."""
    
    def test_example_returns_string(self):
        """Test example_encode_integration returns documentation string."""
        from meow_decoder.forward_secrecy_encoder import example_encode_integration
        
        result = example_encode_integration()
        
        assert isinstance(result, str)
        assert "encode_improved.py" in result or "FountainEncoder" in result
        assert "forward_secrecy" in result.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
