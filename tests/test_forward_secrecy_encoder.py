#!/usr/bin/env python3
"""
🐱 CANONICAL Test Suite for forward_secrecy_encoder.py - Target: 90%+
Tests ForwardSecrecyFountainEncoder wrapper and SecureDroplet dataclass.

Consolidation Status: ✅ CANONICAL
Coverage Target: 90%+
Tests: SecureDroplet, ForwardSecrecyFountainEncoder, create_secure_fountain_encoder
"""

import pytest
import secrets
import sys
from pathlib import Path
from dataclasses import is_dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# Mock Fountain Encoder for Testing
# =============================================================================

class MockFountainEncoder:
    """
    Mock fountain encoder that simulates the interface expected by
    ForwardSecrecyFountainEncoder.
    """
    
    def __init__(self, data: bytes, k_blocks: int, block_size: int):
        self.data = data
        self.k_blocks = k_blocks
        self.block_size = block_size
        self.counter = 0
    
    def droplet(self):
        """Return mock droplet as (seed, block_indices, xor_data) tuple."""
        seed = self.counter
        # Vary the number of block indices for coverage
        if self.counter % 3 == 0:
            indices = [self.counter % self.k_blocks]
        elif self.counter % 3 == 1:
            indices = [self.counter % self.k_blocks, (self.counter + 1) % self.k_blocks]
        else:
            indices = [self.counter % self.k_blocks, (self.counter + 1) % self.k_blocks, (self.counter + 2) % self.k_blocks]
        xor_data = secrets.token_bytes(self.block_size)  # Simulate XOR data
        self.counter += 1
        return seed, indices, xor_data


# =============================================================================
# SecureDroplet Dataclass Tests
# =============================================================================

class TestSecureDroplet:
    """Tests for SecureDroplet dataclass."""
    
    def test_import(self):
        """Test that SecureDroplet can be imported."""
        from meow_decoder.forward_secrecy_encoder import SecureDroplet
        assert SecureDroplet is not None
    
    def test_is_dataclass(self):
        """Test that SecureDroplet is a dataclass."""
        from meow_decoder.forward_secrecy_encoder import SecureDroplet
        assert is_dataclass(SecureDroplet)
    
    def test_creation(self):
        """Test creating a SecureDroplet instance."""
        from meow_decoder.forward_secrecy_encoder import SecureDroplet
        
        droplet = SecureDroplet(
            seed=42,
            block_indices=[0, 1, 2],
            encrypted_data=b"encrypted_data_here",
            nonces=[b"nonce1"],
            block_id=0
        )
        
        assert droplet.seed == 42
        assert droplet.block_indices == [0, 1, 2]
        assert droplet.encrypted_data == b"encrypted_data_here"
        assert droplet.nonces == [b"nonce1"]
        assert droplet.block_id == 0
    
    def test_multiple_nonces(self):
        """Test SecureDroplet with multiple nonces."""
        from meow_decoder.forward_secrecy_encoder import SecureDroplet
        
        nonces = [secrets.token_bytes(12) for _ in range(3)]
        
        droplet = SecureDroplet(
            seed=100,
            block_indices=[0, 1, 2],
            encrypted_data=secrets.token_bytes(512),
            nonces=nonces,
            block_id=5
        )
        
        assert len(droplet.nonces) == 3
        for nonce in droplet.nonces:
            assert len(nonce) == 12
    
    def test_empty_block_indices(self):
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


# =============================================================================
# ForwardSecrecyFountainEncoder Tests
# =============================================================================

class TestForwardSecrecyFountainEncoder:
    """Tests for ForwardSecrecyFountainEncoder class."""
    
    def test_import(self):
        """Test that ForwardSecrecyFountainEncoder can be imported."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        assert ForwardSecrecyFountainEncoder is not None
    
    def test_creation(self):
        """Test creating ForwardSecrecyFountainEncoder."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=512)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True,
            ratchet_interval=100
        )
        
        assert fs_encoder is not None
        assert fs_encoder.fountain is mock_fountain
        assert fs_encoder.droplet_counter == 0
    
    def test_creation_ratchet_disabled(self):
        """Test creating encoder with ratchet disabled."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=512)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=False
        )
        
        assert fs_encoder is not None
    
    def test_next_secure_droplet(self):
        """Test generating a secure droplet."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder, SecureDroplet
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=64)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        droplet = fs_encoder.next_secure_droplet()
        
        assert isinstance(droplet, SecureDroplet)
        assert droplet.block_id == 0
        assert len(droplet.encrypted_data) > 0
        assert len(droplet.nonces) >= 1
    
    def test_droplet_counter_increments(self):
        """Test that droplet counter increments after each call."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=64)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        assert fs_encoder.droplet_counter == 0
        
        fs_encoder.next_secure_droplet()
        assert fs_encoder.droplet_counter == 1
        
        fs_encoder.next_secure_droplet()
        assert fs_encoder.droplet_counter == 2
        
        fs_encoder.next_secure_droplet()
        assert fs_encoder.droplet_counter == 3
    
    def test_multiple_secure_droplets(self):
        """Test generating multiple secure droplets."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=64)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        droplets = []
        for i in range(10):
            droplet = fs_encoder.next_secure_droplet()
            droplets.append(droplet)
            assert droplet.block_id == i
        
        # All droplets should have unique encrypted data
        encrypted_set = set(d.encrypted_data for d in droplets)
        assert len(encrypted_set) == 10  # All unique
    
    def test_get_fs_extension(self):
        """Test getting forward secrecy extension for manifest."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=64)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            enable_ratchet=True
        )
        
        extension = fs_encoder.get_fs_extension()
        
        assert isinstance(extension, bytes)
        assert len(extension) > 0
    
    def test_cleanup(self):
        """Test cleanup method."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=64)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Generate some droplets first
        fs_encoder.next_secure_droplet()
        fs_encoder.next_secure_droplet()
        
        # Cleanup should not raise
        fs_encoder.cleanup()
    
    def test_encrypt_droplet_data(self):
        """Test internal _encrypt_droplet_data method."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=64)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        xor_data = secrets.token_bytes(64)
        block_indices = [3, 5, 7]
        droplet_id = 42
        
        ciphertext, nonces = fs_encoder._encrypt_droplet_data(
            xor_data, block_indices, droplet_id
        )
        
        assert len(ciphertext) > 0
        assert len(nonces) >= 1
    
    def test_encrypt_droplet_data_empty_indices(self):
        """Test encryption with empty block indices uses droplet_id."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test data", k_blocks=10, block_size=64)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            fountain_encoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        xor_data = secrets.token_bytes(64)
        block_indices = []  # Empty indices
        droplet_id = 99
        
        # Should use droplet_id as primary_block
        ciphertext, nonces = fs_encoder._encrypt_droplet_data(
            xor_data, block_indices, droplet_id
        )
        
        assert len(ciphertext) > 0


# =============================================================================
# create_secure_fountain_encoder Tests
# =============================================================================

class TestCreateSecureFountainEncoder:
    """Tests for create_secure_fountain_encoder factory function."""
    
    def test_import(self):
        """Test that function can be imported."""
        from meow_decoder.forward_secrecy_encoder import create_secure_fountain_encoder
        assert create_secure_fountain_encoder is not None
    
    def test_creates_fs_encoder_when_enabled(self):
        """Test that FS encoder is created when forward_secrecy is True."""
        from meow_decoder.forward_secrecy_encoder import (
            create_secure_fountain_encoder,
            ForwardSecrecyFountainEncoder
        )
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=b"test data",
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=True
        )
        
        assert isinstance(encoder, ForwardSecrecyFountainEncoder)
    
    def test_creates_regular_encoder_when_disabled(self):
        """Test that regular encoder is returned when forward_secrecy is False."""
        from meow_decoder.forward_secrecy_encoder import create_secure_fountain_encoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=b"test data",
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=False
        )
        
        assert isinstance(encoder, MockFountainEncoder)
    
    def test_custom_ratchet_interval(self):
        """Test creating encoder with custom ratchet interval."""
        from meow_decoder.forward_secrecy_encoder import (
            create_secure_fountain_encoder,
            ForwardSecrecyFountainEncoder
        )
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=b"test data",
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=True,
            ratchet_interval=50
        )
        
        assert isinstance(encoder, ForwardSecrecyFountainEncoder)
    
    def test_disabled_mode_backward_compatible(self):
        """Test backward compatibility with disabled forward secrecy."""
        from meow_decoder.forward_secrecy_encoder import create_secure_fountain_encoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder = create_secure_fountain_encoder(
            data=b"test data",
            k_blocks=10,
            block_size=64,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=False
        )
        
        # Should still support droplet() method
        seed, indices, xor_data = encoder.droplet()
        assert seed == 0  # First droplet


# =============================================================================
# Integration Tests
# =============================================================================

class TestEncoderIntegration:
    """Integration tests for encoder workflow."""
    
    def test_full_encode_workflow(self):
        """Test full encoding workflow with multiple droplets."""
        from meow_decoder.forward_secrecy_encoder import create_secure_fountain_encoder
        
        # Setup
        test_data = secrets.token_bytes(1024)  # 1KB test data
        k_blocks = 10
        block_size = 128
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create encoder
        encoder = create_secure_fountain_encoder(
            data=test_data,
            k_blocks=k_blocks,
            block_size=block_size,
            master_key=master_key,
            salt=salt,
            fountain_encoder_class=MockFountainEncoder,
            enable_forward_secrecy=True
        )
        
        # Generate droplets (1.5x redundancy)
        num_droplets = int(k_blocks * 1.5)
        droplets = []
        
        for i in range(num_droplets):
            droplet = encoder.next_secure_droplet()
            droplets.append(droplet)
        
        assert len(droplets) == num_droplets
        
        # Get extension
        extension = encoder.get_fs_extension()
        assert len(extension) > 0
        
        # Cleanup
        encoder.cleanup()
    
    def test_encoder_deterministic_with_same_key(self):
        """Test that same key produces consistent encryption keys."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create two encoders with same key
        mock1 = MockFountainEncoder(b"test", k_blocks=5, block_size=32)
        mock2 = MockFountainEncoder(b"test", k_blocks=5, block_size=32)
        
        encoder1 = ForwardSecrecyFountainEncoder(mock1, master_key, salt)
        encoder2 = ForwardSecrecyFountainEncoder(mock2, master_key, salt)
        
        # Both should use same internal keys (verify via fs_manager)
        key1 = encoder1.fs_manager.derive_block_key(0)
        key2 = encoder2.fs_manager.derive_block_key(0)
        
        assert key1 == key2


# =============================================================================
# Edge Cases
# =============================================================================

class TestEncoderEdgeCases:
    """Edge case tests for forward secrecy encoder."""
    
    def test_very_small_block_size(self):
        """Test with very small block size."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test", k_blocks=5, block_size=16)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            mock_fountain, master_key, salt
        )
        
        droplet = fs_encoder.next_secure_droplet()
        assert droplet is not None
    
    def test_large_number_of_droplets(self):
        """Test generating many droplets."""
        from meow_decoder.forward_secrecy_encoder import ForwardSecrecyFountainEncoder
        
        mock_fountain = MockFountainEncoder(b"test", k_blocks=100, block_size=64)
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        fs_encoder = ForwardSecrecyFountainEncoder(
            mock_fountain, master_key, salt,
            enable_ratchet=True,
            ratchet_interval=10  # Ratchet every 10 blocks
        )
        
        # Generate 50 droplets (will trigger multiple ratchets)
        for i in range(50):
            droplet = fs_encoder.next_secure_droplet()
            assert droplet.block_id == i


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
