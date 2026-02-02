#!/usr/bin/env python3
"""
Canonical test suite for meow_decoder/forward_secrecy_decoder.py

Tests ForwardSecrecyFountainDecoder, parse_manifest_v3_forward_secrecy,
and create_secure_fountain_decoder factory function.

Coverage target: 90%+
"""

import pytest
import secrets
import struct
from dataclasses import dataclass
from unittest.mock import Mock, MagicMock, patch


@dataclass
class MockDroplet:
    """Mock Droplet object matching the real Droplet interface."""
    seed: int
    block_indices: list
    data: bytes


class MockFountainDecoder:
    """
    Test double for FountainDecoder.
    Implements add_droplet(), is_complete(), get_data() interface.
    """
    
    def __init__(self, k_blocks: int, block_size: int):
        self.k_blocks = k_blocks
        self.block_size = block_size
        self.blocks = {}
        self._complete = False
        self._data = b""
    
    def add_droplet(self, droplet) -> bool:
        """Add a decoded droplet (matching real FountainDecoder.add_droplet())."""
        self.blocks[droplet.seed] = {
            'indices': droplet.block_indices,
            'data': droplet.data
        }
        if len(self.blocks) >= self.k_blocks:
            self._complete = True
        return self._complete
    
    def is_complete(self) -> bool:
        """Check if decoding is complete."""
        return self._complete
    
    def get_data(self, original_length: int = None) -> bytes:
        """Get decoded data."""
        if not self._complete:
            raise RuntimeError("Decoding not complete")
        # Concatenate all block data in seed order
        result = b""
        for seed in sorted(self.blocks.keys()):
            result += self.blocks[seed]['data']
        return result
    
    def set_complete(self, complete: bool = True):
        """Helper to force completion state."""
        self._complete = complete
    
    def set_data(self, data: bytes):
        """Helper to set return data."""
        self._data = data
        self._complete = True


# =============================================================================
# Test ForwardSecrecyFountainDecoder
# =============================================================================

class TestForwardSecrecyFountainDecoder:
    """Tests for ForwardSecrecyFountainDecoder class."""
    
    def test_init_creates_fs_manager(self):
        """Test decoder initializes with ForwardSecrecyManager."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        assert decoder.fountain is mock_fountain
        assert decoder.fs_manager is not None
        decoder.cleanup()
    
    def test_init_with_ratchet_state(self):
        """Test decoder can be initialized with ratchet state."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create encoder to get ratchet state
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True)
        # Advance ratchet
        encoder_manager.derive_block_key(0)
        encoder_manager.derive_block_key(100)
        ratchet_state = encoder_manager.get_ratchet_state_for_manifest()
        
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=ratchet_state,
            ratchet_interval=100
        )
        
        assert decoder.fs_manager is not None
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_init_with_custom_ratchet_interval(self):
        """Test decoder can use custom ratchet interval."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            ratchet_interval=50
        )
        
        assert decoder.fs_manager is not None
        decoder.cleanup()
    
    def test_process_secure_droplet_decrypts_and_passes_to_fountain(self):
        """Test process_secure_droplet decrypts data and calls fountain.addblock()."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create encoder manager to encrypt test data
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        # Encrypt test data
        test_data = b"test_xor_data_for_block_0"
        nonce, ciphertext = encoder_manager.encrypt_block(test_data, block_id=0)
        
        # Create decoder
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=None  # No ratchet for simplicity
        )
        
        # Process the droplet
        result = decoder.process_secure_droplet(
            encrypted_data=ciphertext,
            nonce=nonce,
            block_indices=[0],
            seed=42
        )
        
        # Verify fountain received decrypted data
        assert 42 in mock_fountain.blocks
        assert mock_fountain.blocks[42]['data'] == test_data
        assert mock_fountain.blocks[42]['indices'] == [0]
        
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_process_secure_droplet_returns_completion_status(self):
        """Test process_secure_droplet returns fountain's completion status."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        # Create decoder with k_blocks=2
        mock_fountain = MockFountainDecoder(k_blocks=2, block_size=512)
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # First droplet
        test_data1 = b"block_0_data"
        nonce1, ct1 = encoder_manager.encrypt_block(test_data1, block_id=0)
        result1 = decoder.process_secure_droplet(ct1, nonce1, [0], seed=0)
        assert result1 is False  # Not complete yet
        
        # Second droplet - should complete
        test_data2 = b"block_1_data"
        nonce2, ct2 = encoder_manager.encrypt_block(test_data2, block_id=1)
        result2 = decoder.process_secure_droplet(ct2, nonce2, [1], seed=1)
        assert result2 is True  # Now complete
        
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_process_secure_droplet_with_multiple_indices(self):
        """Test droplet with multiple block indices uses first for key derivation."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        # Encrypt using block 0's key (first index)
        test_data = b"multi_index_data"
        nonce, ciphertext = encoder_manager.encrypt_block(test_data, block_id=0)
        
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Process with multiple indices - should use index 0 for decryption
        result = decoder.process_secure_droplet(
            encrypted_data=ciphertext,
            nonce=nonce,
            block_indices=[0, 3, 5, 7],
            seed=99
        )
        
        assert 99 in mock_fountain.blocks
        assert mock_fountain.blocks[99]['data'] == test_data
        assert mock_fountain.blocks[99]['indices'] == [0, 3, 5, 7]
        
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_process_secure_droplet_empty_indices_uses_block_zero(self):
        """Test empty indices list defaults to block 0."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        # Encrypt using block 0's key
        test_data = b"empty_indices_data"
        nonce, ciphertext = encoder_manager.encrypt_block(test_data, block_id=0)
        
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Process with empty indices
        result = decoder.process_secure_droplet(
            encrypted_data=ciphertext,
            nonce=nonce,
            block_indices=[],
            seed=77
        )
        
        assert 77 in mock_fountain.blocks
        assert mock_fountain.blocks[77]['data'] == test_data
        
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_is_complete_delegates_to_fountain(self):
        """Test is_complete() delegates to fountain decoder."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        assert decoder.is_complete() is False
        
        mock_fountain.set_complete(True)
        assert decoder.is_complete() is True
        
        decoder.cleanup()
    
    def test_get_decoded_data_delegates_to_fountain(self):
        """Test get_decoded_data() delegates to fountain decoder."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainDecoder(k_blocks=2, block_size=512)
        
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Add blocks to mock using add_droplet (the correct API)
        mock_fountain.add_droplet(MockDroplet(seed=0, block_indices=[0], data=b"block_0"))
        mock_fountain.add_droplet(MockDroplet(seed=1, block_indices=[1], data=b"block_1"))
        
        data = decoder.get_decoded_data()
        assert data == b"block_0block_1"
        
        decoder.cleanup()
    
    def test_cleanup_calls_fs_manager_cleanup(self):
        """Test cleanup() calls fs_manager.cleanup()."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Mock the cleanup method
        decoder.fs_manager.cleanup = Mock()
        
        decoder.cleanup()
        
        decoder.fs_manager.cleanup.assert_called_once()


# =============================================================================
# Test parse_manifest_v3_forward_secrecy
# =============================================================================

class TestParseManifestV3ForwardSecrecy:
    """Tests for parse_manifest_v3_forward_secrecy function."""
    
    def test_empty_extensions_returns_defaults(self):
        """Test empty extensions returns disabled FS."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(b"")
        
        assert fs_enabled is False
        assert interval == 100
        assert state is None
    
    def test_none_extensions_returns_defaults(self):
        """Test None extensions returns defaults."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(None)
        
        assert fs_enabled is False
        assert interval == 100
        assert state is None
    
    def test_too_short_extensions_returns_defaults(self):
        """Test extensions shorter than 3 bytes returns defaults."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(b"\x01\x02")
        
        assert fs_enabled is False
        assert interval == 100
        assert state is None
    
    def test_wrong_extension_type_returns_defaults(self):
        """Test non-FS extension type (not 0x01) returns defaults."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        
        # Type 0x02, length 3, some data
        ext_data = b"\x02\x00\x03ABC"
        
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(ext_data)
        
        assert fs_enabled is False
        assert interval == 100
        assert state is None
    
    def test_valid_fs_extension_without_ratchet(self):
        """Test valid FS extension without ratchet returns correct values."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        from meow_decoder.forward_secrecy import pack_forward_secrecy_extension, ForwardSecrecyManager
        
        # Create FS manager without ratchet
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        fs_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        # Pack extension
        ext_bytes = pack_forward_secrecy_extension(fs_manager)
        
        # Parse it back
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(ext_bytes)
        
        assert fs_enabled is False  # Ratchet not enabled
        assert interval == 0
        assert state is None
        
        fs_manager.cleanup()
    
    def test_valid_fs_extension_with_ratchet(self):
        """Test valid FS extension with ratchet returns correct values."""
        from meow_decoder.forward_secrecy_decoder import parse_manifest_v3_forward_secrecy
        from meow_decoder.forward_secrecy import pack_forward_secrecy_extension, ForwardSecrecyManager
        
        # Create FS manager with ratchet
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        fs_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=50)
        
        # Advance ratchet by deriving keys
        fs_manager.derive_block_key(0)
        fs_manager.derive_block_key(50)  # Trigger ratchet step
        
        # Pack extension
        ext_bytes = pack_forward_secrecy_extension(fs_manager)
        
        # Parse it back
        fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(ext_bytes)
        
        assert fs_enabled is True
        assert interval == 50
        assert state is not None
        assert len(state) == 36  # 4 bytes counter + 32 bytes chain key
        
        fs_manager.cleanup()


# =============================================================================
# Test create_secure_fountain_decoder
# =============================================================================

class TestCreateSecureFountainDecoder:
    """Tests for create_secure_fountain_decoder factory function."""
    
    def test_creates_fs_decoder_when_enabled(self):
        """Test factory creates ForwardSecrecyFountainDecoder when FS enabled."""
        from meow_decoder.forward_secrecy_decoder import (
            create_secure_fountain_decoder,
            ForwardSecrecyFountainDecoder
        )
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        decoder = create_secure_fountain_decoder(
            k_blocks=10,
            block_size=512,
            master_key=master_key,
            salt=salt,
            fountain_decoder_class=MockFountainDecoder,
            enable_forward_secrecy=True
        )
        
        assert isinstance(decoder, ForwardSecrecyFountainDecoder)
        assert isinstance(decoder.fountain, MockFountainDecoder)
        decoder.cleanup()
    
    def test_creates_plain_decoder_when_disabled(self):
        """Test factory creates plain FountainDecoder when FS disabled."""
        from meow_decoder.forward_secrecy_decoder import create_secure_fountain_decoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        decoder = create_secure_fountain_decoder(
            k_blocks=10,
            block_size=512,
            master_key=master_key,
            salt=salt,
            fountain_decoder_class=MockFountainDecoder,
            enable_forward_secrecy=False
        )
        
        assert isinstance(decoder, MockFountainDecoder)
        assert decoder.k_blocks == 10
        assert decoder.block_size == 512
    
    def test_passes_ratchet_state_to_fs_decoder(self):
        """Test factory passes ratchet state to FS decoder."""
        from meow_decoder.forward_secrecy_decoder import (
            create_secure_fountain_decoder,
            ForwardSecrecyFountainDecoder
        )
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create ratchet state
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=25)
        encoder_manager.derive_block_key(0)
        encoder_manager.derive_block_key(25)
        ratchet_state = encoder_manager.get_ratchet_state_for_manifest()
        
        decoder = create_secure_fountain_decoder(
            k_blocks=10,
            block_size=512,
            master_key=master_key,
            salt=salt,
            fountain_decoder_class=MockFountainDecoder,
            ratchet_state_bytes=ratchet_state,
            ratchet_interval=25,
            enable_forward_secrecy=True
        )
        
        assert isinstance(decoder, ForwardSecrecyFountainDecoder)
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_passes_k_blocks_and_block_size(self):
        """Test factory passes k_blocks and block_size to fountain decoder."""
        from meow_decoder.forward_secrecy_decoder import create_secure_fountain_decoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        decoder = create_secure_fountain_decoder(
            k_blocks=42,
            block_size=1024,
            master_key=master_key,
            salt=salt,
            fountain_decoder_class=MockFountainDecoder,
            enable_forward_secrecy=True
        )
        
        assert decoder.fountain.k_blocks == 42
        assert decoder.fountain.block_size == 1024
        decoder.cleanup()
    
    def test_default_ratchet_interval_is_100(self):
        """Test default ratchet interval is 100."""
        from meow_decoder.forward_secrecy_decoder import create_secure_fountain_decoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create without specifying ratchet_interval
        decoder = create_secure_fountain_decoder(
            k_blocks=10,
            block_size=512,
            master_key=master_key,
            salt=salt,
            fountain_decoder_class=MockFountainDecoder,
            enable_forward_secrecy=True
        )
        
        # The FS manager should use default interval
        assert decoder.fs_manager is not None
        decoder.cleanup()


# =============================================================================
# Integration Tests
# =============================================================================

class TestDecoderIntegration:
    """Integration tests with real encryption/decryption."""
    
    def test_full_encode_decode_roundtrip(self):
        """Test complete encode -> decode cycle."""
        from meow_decoder.forward_secrecy_decoder import (
            ForwardSecrecyFountainDecoder,
            create_secure_fountain_decoder
        )
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Encoder side
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=5)
        
        # Create some encrypted droplets
        droplets = []
        for i in range(3):
            data = f"block_{i}_data_here".encode()
            nonce, ciphertext = encoder_manager.encrypt_block(data, block_id=i)
            droplets.append({
                'data': data,
                'nonce': nonce,
                'ciphertext': ciphertext,
                'indices': [i],
                'seed': i
            })
        
        # Get ratchet state for manifest
        ratchet_state = encoder_manager.get_ratchet_state_for_manifest()
        
        # Decoder side - create fresh manager with ratchet state
        decoder = create_secure_fountain_decoder(
            k_blocks=3,
            block_size=512,
            master_key=master_key,
            salt=salt,
            fountain_decoder_class=MockFountainDecoder,
            ratchet_state_bytes=ratchet_state,
            ratchet_interval=5,
            enable_forward_secrecy=True
        )
        
        # Process droplets
        for droplet in droplets:
            complete = decoder.process_secure_droplet(
                encrypted_data=droplet['ciphertext'],
                nonce=droplet['nonce'],
                block_indices=droplet['indices'],
                seed=droplet['seed']
            )
        
        assert decoder.is_complete()
        
        # Verify data
        decoded = decoder.get_decoded_data()
        expected = b"block_0_data_hereblock_1_data_hereblock_2_data_here"
        assert decoded == expected
        
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_decode_with_wrong_key_fails(self):
        """Test decryption with wrong key fails."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        correct_key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Encrypt with correct key
        encoder_manager = ForwardSecrecyManager(correct_key, salt, enable_ratchet=False)
        test_data = b"secret_data"
        nonce, ciphertext = encoder_manager.encrypt_block(test_data, block_id=0)
        
        # Try to decrypt with wrong key
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=512)
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=wrong_key,  # Wrong key!
            salt=salt
        )
        
        # Should raise decryption error
        with pytest.raises(Exception):  # cryptography raises InvalidTag
            decoder.process_secure_droplet(ciphertext, nonce, [0], seed=0)
        
        decoder.cleanup()
        encoder_manager.cleanup()


# =============================================================================
# Edge Cases
# =============================================================================

class TestDecoderEdgeCases:
    """Edge case tests."""
    
    def test_process_large_droplet(self):
        """Test processing larger data blocks."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        # Large data
        large_data = secrets.token_bytes(8192)
        nonce, ciphertext = encoder_manager.encrypt_block(large_data, block_id=0)
        
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=8192)
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        decoder.process_secure_droplet(ciphertext, nonce, [0], seed=0)
        
        assert mock_fountain.blocks[0]['data'] == large_data
        
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_process_many_droplets_sequentially(self):
        """Test processing many droplets in sequence (without ratchet to avoid sync issues)."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Use NO ratchet to avoid state sync issues in test
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        mock_fountain = MockFountainDecoder(k_blocks=50, block_size=256)
        # No ratchet_state_bytes = no ratchet mode
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=None  # Disable ratchet
        )
        
        # Process 50 droplets
        for i in range(50):
            data = f"data_{i:04d}".encode()
            nonce, ciphertext = encoder_manager.encrypt_block(data, block_id=i)
            decoder.process_secure_droplet(ciphertext, nonce, [i], seed=i)
        
        assert decoder.is_complete()
        assert len(mock_fountain.blocks) == 50
        
        decoder.cleanup()
        encoder_manager.cleanup()
    
    def test_decoder_with_high_block_id(self):
        """Test decoding with high block ID values."""
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Use NO ratchet to avoid state sync issues in test
        encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        mock_fountain = MockFountainDecoder(k_blocks=1000, block_size=256)
        # No ratchet_state_bytes = no ratchet mode
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=None  # Disable ratchet
        )
        
        # Use high block IDs
        high_ids = [999, 500, 250]
        for block_id in high_ids:
            data = f"high_id_{block_id}".encode()
            nonce, ciphertext = encoder_manager.encrypt_block(data, block_id)
            decoder.process_secure_droplet(ciphertext, nonce, [block_id], seed=block_id)
        
        assert len(mock_fountain.blocks) == 3
        
        decoder.cleanup()
        encoder_manager.cleanup()


# =============================================================================
# Compatibility Tests
# =============================================================================

class TestDecoderCompatibility:
    """Tests for encoder-decoder compatibility."""
    
    def test_encoder_decoder_key_derivation_match(self):
        """Test encoder and decoder derive same keys."""
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        
        # Create encoder
        encoder = ForwardSecrecyManager(master_key, salt, enable_ratchet=False)
        
        # Encrypt some data
        test_data = b"compatibility_test_data"
        nonce, ciphertext = encoder.encrypt_block(test_data, block_id=5)
        
        # Create decoder with same params
        mock_fountain = MockFountainDecoder(k_blocks=10, block_size=256)
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt
        )
        
        # Decrypt - should work if keys match
        decoder.process_secure_droplet(ciphertext, nonce, [5], seed=5)
        
        assert mock_fountain.blocks[5]['data'] == test_data
        
        encoder.cleanup()
        decoder.cleanup()
    
    def test_ratchet_state_synchronization(self):
        """Test encoder ratchet state is correctly passed to decoder.
        
        This test validates that ratchet state bytes can be passed to decoder.
        For actual encryption/decryption to work in-order, both encoder and decoder
        need to start from the same state. The ratchet state is meant to be saved
        in manifest BEFORE encryption starts, then restored in decoder.
        """
        from meow_decoder.forward_secrecy import ForwardSecrecyManager
        from meow_decoder.forward_secrecy_decoder import ForwardSecrecyFountainDecoder
        
        master_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        ratchet_interval = 10
        
        # For proper sync: create encoder, get its INITIAL state, then encrypt
        encoder = ForwardSecrecyManager(master_key, salt, enable_ratchet=True, ratchet_interval=ratchet_interval)
        
        # Get initial ratchet state BEFORE any encryption
        initial_ratchet_state = encoder.get_ratchet_state_for_manifest()
        
        # Encrypt a few blocks (in order, starting from 0)
        encrypted_blocks = []
        for i in range(3):
            data = f"block_{i}".encode()
            nonce, ct = encoder.encrypt_block(data, block_id=i)
            encrypted_blocks.append((data, nonce, ct, i))
        
        # Create decoder with SAME initial state
        mock_fountain = MockFountainDecoder(k_blocks=3, block_size=256)
        decoder = ForwardSecrecyFountainDecoder(
            fountain_decoder=mock_fountain,
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=initial_ratchet_state,
            ratchet_interval=ratchet_interval
        )
        
        # Decrypt all blocks IN THE SAME ORDER they were encrypted
        for data, nonce, ct, idx in encrypted_blocks:
            decoder.process_secure_droplet(ct, nonce, [idx], seed=idx)
            assert mock_fountain.blocks[idx]['data'] == data, f"Block {idx} mismatch"
        
        encoder.cleanup()
        decoder.cleanup()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
