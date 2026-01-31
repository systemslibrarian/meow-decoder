"""
Fountain Decoder with Forward Secrecy Integration
Extends FountainDecoder to support per-block decryption with key ratcheting
"""

import struct
from typing import Tuple, Optional, List
from dataclasses import dataclass

from meow_decoder.forward_secrecy import (
    ForwardSecrecyManager,
    create_forward_secrecy_decoder,
    unpack_forward_secrecy_extension
)


class ForwardSecrecyFountainDecoder:
    """
    Wrapper that adds forward secrecy decryption to fountain decoding.
    
    Usage:
        # Parse manifest v3 with FS extension
        fs_enabled, ratchet_interval, ratchet_state = parse_fs_extension(manifest)
        
        # Create your normal fountain decoder
        fountain = FountainDecoder(k_blocks, block_size)
        
        # Wrap with forward secrecy
        fs_fountain = ForwardSecrecyFountainDecoder(
            fountain,
            master_key,
            salt,
            ratchet_state_bytes=ratchet_state,
            ratchet_interval=ratchet_interval
        )
        
        # Process secure droplets
        fs_fountain.process_secure_droplet(encrypted_data, nonce, block_indices, seed)
    """
    
    def __init__(self,
                 fountain_decoder,  # Your existing FountainDecoder
                 master_key: bytes,
                 salt: bytes,
                 ratchet_state_bytes: Optional[bytes] = None,
                 ratchet_interval: int = 100):
        """
        Initialize forward secrecy wrapper for decoder.
        
        Args:
            fountain_decoder: Existing FountainDecoder instance
            master_key: Master encryption key (32 bytes)
            salt: Salt from manifest (16 bytes)
            ratchet_state_bytes: Serialized ratchet state from manifest
            ratchet_interval: Blocks between ratchet steps
        """
        self.fountain = fountain_decoder
        self.fs_manager = create_forward_secrecy_decoder(
            master_key=master_key,
            salt=salt,
            ratchet_state_bytes=ratchet_state_bytes,
            ratchet_interval=ratchet_interval
        )
    
    def process_secure_droplet(self,
                               encrypted_data: bytes,
                               nonce: bytes,
                               block_indices: List[int],
                               seed: int) -> bool:
        """
        Decrypt and process a secure fountain droplet.
        
        Args:
            encrypted_data: Encrypted XOR data
            nonce: Nonce used for encryption
            block_indices: Block indices for this droplet
            seed: Droplet RNG seed
            
        Returns:
            True if decoding complete, False otherwise
        """
        # Decrypt the droplet data
        primary_block = block_indices[0] if block_indices else 0
        xor_data = self.fs_manager.decrypt_block(encrypted_data, nonce, primary_block)
        
        # Create a Droplet object and pass to fountain decoder
        from .fountain import Droplet
        droplet = Droplet(seed=seed, block_indices=block_indices, data=xor_data)
        return self.fountain.add_droplet(droplet)
    
    def is_complete(self) -> bool:
        """Check if decoding is complete."""
        return self.fountain.is_complete()  # Or however your decoder exposes this
    
    def get_decoded_data(self) -> bytes:
        """Get decoded data after completion."""
        return self.fountain.get_data()  # Or however your decoder exposes this
    
    def cleanup(self):
        """Cleanup sensitive data."""
        self.fs_manager.cleanup()


# Convenience functions for decode_improved.py integration

def parse_manifest_v3_forward_secrecy(manifest_extensions: bytes) -> Tuple[bool, int, Optional[bytes]]:
    """
    Parse forward secrecy extension from manifest v3.
    
    Args:
        manifest_extensions: Extension bytes from manifest v3
        
    Returns:
        Tuple of (fs_enabled, ratchet_interval, ratchet_state_bytes)
        
    Extension format:
        - Type: 0x01 (1 byte)
        - Length: variable (2 bytes)
        - Data: see forward_secrecy.py for format
        
    Example:
        >>> ext_data = manifest.extensions
        >>> fs_enabled, interval, state = parse_manifest_v3_forward_secrecy(ext_data)
        >>> if fs_enabled:
        ...     # Create FS decoder
    """
    if not manifest_extensions or len(manifest_extensions) < 3:
        # No extensions or too short
        return False, 100, None
    
    # Parse extension header
    ext_type = manifest_extensions[0]
    ext_length = struct.unpack(">H", manifest_extensions[1:3])[0]
    
    if ext_type != 0x01:
        # Not forward secrecy extension
        return False, 100, None
    
    # Extract extension data
    ext_data = manifest_extensions[3:3+ext_length]
    
    # Unpack using forward_secrecy module
    from meow_decoder.forward_secrecy import unpack_forward_secrecy_extension
    ratchet_enabled, ratchet_interval, ratchet_state = unpack_forward_secrecy_extension(ext_data)
    
    return ratchet_enabled, ratchet_interval, ratchet_state


def create_secure_fountain_decoder(
    k_blocks: int,
    block_size: int,
    master_key: bytes,
    salt: bytes,
    fountain_decoder_class,  # Your FountainDecoder class
    ratchet_state_bytes: Optional[bytes] = None,
    ratchet_interval: int = 100,
    enable_forward_secrecy: bool = True
):
    """
    Create fountain decoder with optional forward secrecy.
    
    Args:
        k_blocks: Number of blocks
        block_size: Block size in bytes
        master_key: Master encryption key
        salt: Salt from manifest
        fountain_decoder_class: Your FountainDecoder class
        ratchet_state_bytes: Ratchet state from manifest (if FS enabled)
        ratchet_interval: Blocks between ratchet steps
        enable_forward_secrecy: Enable forward secrecy
        
    Returns:
        ForwardSecrecyFountainDecoder or regular FountainDecoder
        
    Example:
        >>> from fountain import FountainDecoder
        >>> decoder = create_secure_fountain_decoder(
        ...     k_blocks=100,
        ...     block_size=512,
        ...     master_key=key,
        ...     salt=salt,
        ...     fountain_decoder_class=FountainDecoder,
        ...     ratchet_state_bytes=state,
        ...     enable_forward_secrecy=True
        ... )
    """
    # Create base fountain decoder
    fountain = fountain_decoder_class(k_blocks, block_size)
    
    if not enable_forward_secrecy:
        # Return unwrapped decoder (backward compatible)
        return fountain
    
    # Wrap with forward secrecy
    return ForwardSecrecyFountainDecoder(
        fountain,
        master_key,
        salt,
        ratchet_state_bytes=ratchet_state_bytes,
        ratchet_interval=ratchet_interval
    )


# Example integration with decode_improved.py

def example_decode_integration():
    """
    Example of how to integrate forward secrecy into decode_improved.py
    
    Changes needed in decode_improved.py:
    
    1. Detect manifest version (v2 vs v3)
    2. Parse FS extension from v3 manifests
    3. Import forward_secrecy_decoder module
    4. Modify fountain decoder creation
    5. Update droplet processing
    """
    
    code_example = '''
# In decode_improved.py:

from forward_secrecy_decoder import (
    create_secure_fountain_decoder,
    parse_manifest_v3_forward_secrecy
)

def decode_from_qr_codes(...):
    ...
    # Parse manifest
    manifest = unpack_manifest(manifest_bytes)
    
    # Check if v3 with forward secrecy
    fs_enabled = False
    ratchet_state = None
    ratchet_interval = 100
    
    if manifest.version == b"MEOW3" and hasattr(manifest, 'extensions'):
        fs_enabled, ratchet_interval, ratchet_state = \
            parse_manifest_v3_forward_secrecy(manifest.extensions)
    
    # Create decoder
    decoder = create_secure_fountain_decoder(
        k_blocks=manifest.k_blocks,
        block_size=manifest.block_size,
        master_key=key,
        salt=manifest.salt,
        fountain_decoder_class=FountainDecoder,
        ratchet_state_bytes=ratchet_state,
        ratchet_interval=ratchet_interval,
        enable_forward_secrecy=fs_enabled
    )
    
    # Process droplets
    for qr_data in qr_codes:
        if fs_enabled:
            # Parse secure droplet
            seed, indices, encrypted_data, nonce = parse_secure_droplet(qr_data)
            complete = decoder.process_secure_droplet(
                encrypted_data, nonce, indices, seed
            )
        else:
            # Old path (backward compatible)
            seed, indices, xor_data = parse_droplet(qr_data)
            complete = decoder.addblock(seed, indices, xor_data)
        
        if complete:
            break
    
    # Get decoded data
    if decoder.is_complete():
        data = decoder.get_decoded_data()
        decoder.cleanup()
        return data
    ...
    
# CLI automatically detects v2 vs v3:
# meow-decode-gif --input secret.gif --output secret.pdf
# (works with both v2 and v3 manifests)
    '''
    
    return code_example


if __name__ == "__main__":
    print("Forward Secrecy Fountain Decoder Integration Example\n")
    print("=" * 60)
    print(example_decode_integration())
    print("=" * 60)
    
    # Mock test with dummy fountain decoder
    class MockFountainDecoder:
        """Mock fountain decoder for testing."""
        def __init__(self, k_blocks, block_size):
            self.k_blocks = k_blocks
            self.block_size = block_size
            self.blocks_received = 0
            self.complete = False
        
        def addblock(self, seed, indices, xor_data):
            """Process a block."""
            self.blocks_received += 1
            if self.blocks_received >= self.k_blocks:
                self.complete = True
            return self.complete
        
        def is_complete(self):
            return self.complete
        
        def get_data(self):
            return b"decoded_data"
    
    # Test integration
    print("\nTesting integration with mock fountain decoder...")
    
    import secrets
    
    master_key = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    
    # Create secure fountain decoder (no ratchet state = fresh decode)
    decoder = create_secure_fountain_decoder(
        k_blocks=10,
        block_size=512,
        master_key=master_key,
        salt=salt,
        fountain_decoder_class=MockFountainDecoder,
        ratchet_state_bytes=None,  # Fresh decode
        enable_forward_secrecy=True
    )
    
    # Create matching encoder for test
    # Note: decoder was created with ratchet_state_bytes=None (fresh decode)
    # So we need an encoder with the same initial state
    from meow_decoder.forward_secrecy import ForwardSecrecyManager
    
    # Create encoder with same ratchet setting
    encoder_manager = ForwardSecrecyManager(master_key, salt, enable_ratchet=True)
    
    # Get the initial ratchet state from encoder
    initial_ratchet_state = encoder_manager.get_ratchet_state_for_manifest()
    
    # Recreate decoder with this ratchet state
    decoder.cleanup()
    decoder = create_secure_fountain_decoder(
        k_blocks=10,
        block_size=512,
        master_key=master_key,
        salt=salt,
        fountain_decoder_class=MockFountainDecoder,
        ratchet_state_bytes=initial_ratchet_state,  # Use encoder's state
        enable_forward_secrecy=True
    )
    
    # Now test encryption/decryption
    for i in range(5):
        # Encrypt mock data with encoder
        mock_data = b"mock_xor_data_" + str(i).encode()
        nonce, ciphertext = encoder_manager.encrypt_block(mock_data, block_id=i)
        
        # Decrypt with decoder
        complete = decoder.process_secure_droplet(
            encrypted_data=ciphertext,
            nonce=nonce,
            block_indices=[i],
            seed=i
        )
        
        print(f"  Droplet {i}: processed, complete={complete}")
    
    decoder.cleanup()
    encoder_manager.cleanup()
    
    print("\n✅ Integration test complete!")
