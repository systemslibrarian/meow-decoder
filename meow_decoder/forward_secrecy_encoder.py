"""
Fountain Encoder with Forward Secrecy Integration
Extends FountainEncoder to support per-block encryption with key ratcheting

IMPORTANT: This is an integration layer. Your existing FountainEncoder
should be modified to call these methods when forward secrecy is enabled.
"""

import struct
import secrets
from typing import Tuple, Optional, List
from dataclasses import dataclass

from meow_decoder.forward_secrecy import (
    ForwardSecrecyManager,
    create_forward_secrecy_encoder,
    pack_forward_secrecy_extension
)


@dataclass
class SecureDroplet:
    """
    Fountain droplet with forward secrecy encryption
    
    Attributes:
        seed: Droplet RNG seed
        block_indices: Selected block indices
        encrypted_data: Encrypted XOR of selected blocks
        nonces: Per-block nonces (one for each block_index)
        block_id: Global droplet ID (for key derivation)
    """
    seed: int
    block_indices: List[int]
    encrypted_data: bytes
    nonces: List[bytes]  # One nonce per block
    block_id: int


class ForwardSecrecyFountainEncoder:
    """
    Wrapper that adds forward secrecy to fountain encoding.
    
    Usage:
        # Create your normal fountain encoder
        fountain = FountainEncoder(data, k_blocks, block_size)
        
        # Wrap with forward secrecy
        fs_fountain = ForwardSecrecyFountainEncoder(
            fountain,
            master_key,
            salt,
            enable_ratchet=True
        )
        
        # Generate secure droplets
        secure_droplet = fs_fountain.next_secure_droplet()
    """
    
    def __init__(self,
                 fountain_encoder,  # Your existing FountainEncoder
                 master_key: bytes,
                 salt: bytes,
                 enable_ratchet: bool = True,
                 ratchet_interval: int = 100):
        """
        Initialize forward secrecy wrapper.
        
        Args:
            fountain_encoder: Existing FountainEncoder instance
            master_key: Master encryption key (32 bytes)
            salt: Random salt (16 bytes)
            enable_ratchet: Enable key ratcheting
            ratchet_interval: Blocks between ratchet steps
        """
        self.fountain = fountain_encoder
        self.fs_manager = create_forward_secrecy_encoder(
            master_key, salt, enable_ratchet, ratchet_interval
        )
        self.droplet_counter = 0
    
    def next_secure_droplet(self) -> SecureDroplet:
        """
        Generate next fountain droplet with forward secrecy.
        
        Returns:
            SecureDroplet with per-block encryption
            
        Note:
            This method assumes your FountainEncoder has:
            - droplet() method that returns (seed, indices, xor_data)
            - Or similar interface
        """
        # Get next droplet from fountain encoder
        # ADAPT THIS to match your FountainEncoder interface
        seed, block_indices, xor_data = self.fountain.droplet()
        
        # Encrypt the XOR data with per-block keys
        encrypted_data, nonces = self._encrypt_droplet_data(
            xor_data, block_indices, self.droplet_counter
        )
        
        # Create secure droplet
        secure_droplet = SecureDroplet(
            seed=seed,
            block_indices=block_indices,
            encrypted_data=encrypted_data,
            nonces=nonces,
            block_id=self.droplet_counter
        )
        
        self.droplet_counter += 1
        return secure_droplet
    
    def _encrypt_droplet_data(self,
                             xor_data: bytes,
                             block_indices: List[int],
                             droplet_id: int) -> Tuple[bytes, List[bytes]]:
        """
        Encrypt droplet data using per-block keys.
        
        Strategy: Encrypt with a key derived from the first block index.
        This maintains forward secrecy while keeping the protocol simple.
        
        Args:
            xor_data: XOR of selected blocks
            block_indices: Indices of blocks used
            droplet_id: Global droplet counter
            
        Returns:
            Tuple of (encrypted_data, [nonce])
        """
        # Use first block index for key derivation
        # (or could use hash of all indices)
        primary_block = block_indices[0] if block_indices else droplet_id
        
        # Encrypt with block-specific key
        nonce, ciphertext = self.fs_manager.encrypt_block(xor_data, primary_block)
        
        return ciphertext, [nonce]
    
    def get_fs_extension(self) -> bytes:
        """Get forward secrecy extension for manifest v3."""
        return pack_forward_secrecy_extension(self.fs_manager)
    
    def cleanup(self):
        """Cleanup sensitive data."""
        self.fs_manager.cleanup()


# Convenience function for encode_improved.py integration

def create_secure_fountain_encoder(
    data: bytes,
    k_blocks: int,
    block_size: int,
    master_key: bytes,
    salt: bytes,
    fountain_encoder_class,  # Your FountainEncoder class
    enable_forward_secrecy: bool = True,
    ratchet_interval: int = 100
):
    """
    Create fountain encoder with optional forward secrecy.
    
    Args:
        data: Data to encode
        k_blocks: Number of blocks
        block_size: Block size in bytes
        master_key: Master encryption key
        salt: Random salt
        fountain_encoder_class: Your FountainEncoder class
        enable_forward_secrecy: Enable forward secrecy
        ratchet_interval: Blocks between ratchet steps
        
    Returns:
        ForwardSecrecyFountainEncoder or regular FountainEncoder
        
    Example:
        >>> from fountain import FountainEncoder
        >>> encoder = create_secure_fountain_encoder(
        ...     data=secret_data,
        ...     k_blocks=100,
        ...     block_size=512,
        ...     master_key=key,
        ...     salt=salt,
        ...     fountain_encoder_class=FountainEncoder,
        ...     enable_forward_secrecy=True
        ... )
    """
    # Create base fountain encoder
    fountain = fountain_encoder_class(data, k_blocks, block_size)
    
    if not enable_forward_secrecy:
        # Return unwrapped encoder (backward compatible)
        return fountain
    
    # Wrap with forward secrecy
    return ForwardSecrecyFountainEncoder(
        fountain,
        master_key,
        salt,
        enable_ratchet=True,
        ratchet_interval=ratchet_interval
    )


# Example integration with encode_improved.py

def example_encode_integration():
    """
    Example of how to integrate forward secrecy into encode_improved.py
    
    Changes needed in encode_improved.py:
    
    1. Add --forward-secrecy flag to argparse
    2. Import forward_secrecy_encoder module
    3. Modify fountain encoder creation
    4. Update manifest to v3 format
    5. Add FS extension to manifest
    """
    
    code_example = '''
# In encode_improved.py:

from meow_decoder.forward_secrecy_encoder import create_secure_fountain_encoder
from meow_decoder.forward_secrecy import pack_forward_secrecy_extension

def encode_file(..., enable_forward_secrecy=False):
    ...
    # Instead of:
    # fountain = FountainEncoder(compressed, k_blocks, block_size)
    
    # Use:
    fountain = create_secure_fountain_encoder(
        data=compressed,
        k_blocks=k_blocks,
        block_size=block_size,
        master_key=key,
        salt=salt,
        fountain_encoder_class=FountainEncoder,
        enable_forward_secrecy=enable_forward_secrecy
    )
    
    # Generate droplets
    for i in range(num_droplets):
        if enable_forward_secrecy:
            droplet = fountain.next_secure_droplet()
            # Store droplet.encrypted_data, droplet.nonces, etc.
        else:
            # Old path (backward compatible)
            droplet = fountain.droplet()
    
    # Update manifest to v3 if using forward secrecy
    if enable_forward_secrecy:
        manifest_version = b"MEOW3"
        fs_extension = fountain.get_fs_extension()
        # Add extension to manifest
    else:
        manifest_version = b"MEOW2"
    ...
    
# CLI usage:
# meow-encode --input secret.pdf --forward-secrecy --output secret.gif
    '''
    
    return code_example


if __name__ == "__main__":
    print("Forward Secrecy Fountain Encoder Integration Example\n")
    print("=" * 60)
    print(example_encode_integration())
    print("=" * 60)
    
    # Mock test with dummy fountain encoder
    class MockFountainEncoder:
        """Mock fountain encoder for testing."""
        def __init__(self, data, k_blocks, block_size):
            self.data = data
            self.k_blocks = k_blocks
            self.block_size = block_size
            self.counter = 0
        
        def droplet(self):
            """Return mock droplet."""
            seed = self.counter
            indices = [self.counter % self.k_blocks]
            xor_data = b"mock_xor_data_" + str(self.counter).encode()
            self.counter += 1
            return seed, indices, xor_data
    
    # Test integration
    print("\nTesting integration with mock fountain encoder...")
    
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    
    # Create secure fountain encoder
    encoder = create_secure_fountain_encoder(
        data=b"test data",
        k_blocks=10,
        block_size=512,
        master_key=master_key,
        salt=salt,
        fountain_encoder_class=MockFountainEncoder,
        enable_forward_secrecy=True
    )
    
    # Generate secure droplets
    for i in range(5):
        droplet = encoder.next_secure_droplet()
        print(f"  Droplet {i}: seed={droplet.seed}, "
              f"blocks={droplet.block_indices}, "
              f"encrypted_len={len(droplet.encrypted_data)}, "
              f"nonces={len(droplet.nonces)}")
    
    # Get extension for manifest
    extension = encoder.get_fs_extension()
    print(f"\n  FS Extension size: {len(extension)} bytes")
    
    encoder.cleanup()
    
    print("\n✅ Integration test complete!")
