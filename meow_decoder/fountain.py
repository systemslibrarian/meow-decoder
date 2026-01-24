"""
Fountain Code Implementation for Meow Decoder
Uses Luby Transform (LT) codes for rateless encoding

Features:
- Robust Soliton distribution for degree selection
- XOR-based encoding/decoding
- Belief propagation decoding
- Efficient block management
"""

import struct
import random
from typing import List, Tuple, Optional, Set
from dataclasses import dataclass
import numpy as np


@dataclass
class Droplet:
    """
    A fountain code droplet (encoded symbol).
    
    Attributes:
        seed: Random seed for reproducibility
        block_indices: Indices of blocks XORed
        data: XOR of selected blocks
    """
    seed: int
    block_indices: List[int]
    data: bytes


class RobustSolitonDistribution:
    """
    Robust Soliton distribution for selecting droplet degrees.
    
    The Robust Soliton distribution ensures good coverage of blocks
    while maintaining efficient decoding.
    """
    
    def __init__(self, k: int, c: float = 0.1, delta: float = 0.5):
        """
        Initialize Robust Soliton distribution.
        
        Args:
            k: Number of source blocks
            c: Tuning parameter (typically 0.1)
            delta: Failure probability (typically 0.5)
        """
        self.k = k
        self.c = c
        self.delta = delta
        
        # Precompute distribution
        self.distribution = self._compute_distribution()
    
    def _compute_distribution(self) -> List[float]:
        """Compute the distribution probabilities."""
        k = self.k
        
        # Edge case: very small k
        if k <= 1:
            return [0.0, 1.0]  # Only degree 1 makes sense
        
        # Ideal Soliton distribution (ρ)
        rho = [0.0] * (k + 1)
        rho[1] = 1.0 / k
        for i in range(2, k + 1):
            rho[i] = 1.0 / (i * (i - 1))
        
        # Robust part (τ)
        R = self.c * np.log(k / self.delta) * np.sqrt(k)
        tau = [0.0] * (k + 1)
        
        # Clamp spike index to valid range [1, k]
        # This prevents IndexError when R is small relative to k
        m = int(k / R) if R > 0 else k
        m = max(1, min(m, k))
        
        for i in range(1, m):
            tau[i] = R / (i * k)
        tau[m] = R * np.log(R / self.delta) / k
        
        # Combine ρ and τ
        mu = [rho[i] + tau[i] for i in range(k + 1)]
        
        # Normalize
        total = sum(mu)
        if total > 0:
            mu = [m / total for m in mu]
        else:
            # Fallback to ideal soliton if normalization fails
            mu = rho
        
        return mu
    
    def sample_degree(self) -> int:
        """
        Sample a degree from the distribution.
        
        Returns:
            Degree (number of blocks to XOR)
        """
        # Cumulative distribution
        cumulative = 0.0
        r = random.random()
        
        for degree, prob in enumerate(self.distribution):
            cumulative += prob
            if r < cumulative:
                return max(1, degree)
        
        return 1


class FountainEncoder:
    """
    Fountain code encoder using Luby Transform codes.
    
    Generates an endless stream of encoded droplets from source blocks.
    """
    
    def __init__(self, data: bytes, k_blocks: int, block_size: int):
        """
        Initialize fountain encoder.
        
        Args:
            data: Source data to encode
            k_blocks: Number of source blocks
            block_size: Size of each block in bytes
        """
        self.k_blocks = k_blocks
        self.block_size = block_size
        
        # Pad data to fit blocks
        total_size = k_blocks * block_size
        self.data = data + b'\x00' * (total_size - len(data))
        
        # Split into blocks
        self.blocks = [
            self.data[i * block_size:(i + 1) * block_size]
            for i in range(k_blocks)
        ]
        
        # Initialize distribution
        self.distribution = RobustSolitonDistribution(k_blocks)
        
        # Droplet counter
        self.droplet_count = 0
    
    def droplet(self, seed: Optional[int] = None) -> Droplet:
        """
        Generate a fountain code droplet.
        
        Args:
            seed: Optional random seed (auto-generated if None)
            
        Returns:
            Droplet with encoded data
        """
        if seed is None:
            seed = self.droplet_count
        
        self.droplet_count += 1
        
        # Seed RNG for reproducibility
        random.seed(seed)
        
        # Sample degree
        degree = self.distribution.sample_degree()
        
        # Select random blocks
        block_indices = random.sample(range(self.k_blocks), min(degree, self.k_blocks))
        block_indices.sort()
        
        # XOR selected blocks
        xor_data = bytearray(self.block_size)
        for idx in block_indices:
            block_data = self.blocks[idx]
            for i in range(self.block_size):
                xor_data[i] ^= block_data[i]
        
        return Droplet(
            seed=seed,
            block_indices=block_indices,
            data=bytes(xor_data)
        )
    
    def generate_droplets(self, n: int) -> List[Droplet]:
        """
        Generate multiple droplets.
        
        Args:
            n: Number of droplets to generate
            
        Returns:
            List of droplets
        """
        return [self.droplet() for _ in range(n)]


class FountainDecoder:
    """
    Fountain code decoder using belief propagation.
    
    Reconstructs original data from received droplets.
    """
    
    def __init__(self, k_blocks: int, block_size: int, original_length: Optional[int] = None):
        """
        Initialize fountain decoder.
        
        Args:
            k_blocks: Number of source blocks
            block_size: Size of each block in bytes
            original_length: Original data length (before padding). Optional; can be provided later to get_data()
        """
        self.k_blocks = k_blocks
        self.block_size = block_size
        self.original_length = original_length
        
        # Decoded blocks
        self.blocks = [None] * k_blocks
        self.decoded = [False] * k_blocks
        self.decoded_count = 0
        
        # Pending droplets (cannot be decoded yet)
        self.pending_droplets: List[Droplet] = []
    
    def is_complete(self) -> bool:
        """Check if decoding is complete."""
        return self.decoded_count == self.k_blocks
    
    def add_droplet(self, droplet: Droplet) -> bool:
        """
        Add a droplet and attempt to decode.
        
        Args:
            droplet: Received droplet
            
        Returns:
            True if decoding is complete
        """
        # Reduce droplet using already-decoded blocks
        droplet = self._reduce_droplet(droplet)
        
        if len(droplet.block_indices) == 0:
            # Droplet is redundant
            return self.is_complete()
        
        if len(droplet.block_indices) == 1:
            # Degree-1 droplet - can decode immediately
            block_idx = droplet.block_indices[0]
            self._decode_block(block_idx, droplet.data)
            
            # Process pending droplets (belief propagation)
            self._process_pending()
        else:
            # Degree > 1 - add to pending
            self.pending_droplets.append(droplet)
        
        return self.is_complete()
    
    def _reduce_droplet(self, droplet: Droplet) -> Droplet:
        """
        Reduce droplet by XORing out already-decoded blocks.
        
        Args:
            droplet: Original droplet
            
        Returns:
            Reduced droplet
        """
        # Find unknown blocks
        unknown_indices = [
            idx for idx in droplet.block_indices
            if not self.decoded[idx]
        ]
        
        if len(unknown_indices) == len(droplet.block_indices):
            # No decoded blocks - return original
            return droplet
        
        # XOR out decoded blocks
        reduced_data = bytearray(droplet.data)
        for idx in droplet.block_indices:
            if self.decoded[idx]:
                for i in range(self.block_size):
                    reduced_data[i] ^= self.blocks[idx][i]
        
        return Droplet(
            seed=droplet.seed,
            block_indices=unknown_indices,
            data=bytes(reduced_data)
        )
    
    def _decode_block(self, block_idx: int, block_data: bytes):
        """
        Decode a block.
        
        Args:
            block_idx: Block index
            block_data: Block data
        """
        if not self.decoded[block_idx]:
            self.blocks[block_idx] = block_data
            self.decoded[block_idx] = True
            self.decoded_count += 1
    
    def _process_pending(self):
        """
        Process pending droplets using belief propagation.
        
        This is called after decoding a block to check if any
        pending droplets can now be decoded.
        """
        made_progress = True
        
        while made_progress:
            made_progress = False
            new_pending = []
            
            for droplet in self.pending_droplets:
                # Reduce droplet
                reduced = self._reduce_droplet(droplet)
                
                if len(reduced.block_indices) == 0:
                    # Redundant - skip
                    continue
                elif len(reduced.block_indices) == 1:
                    # Can decode now
                    block_idx = reduced.block_indices[0]
                    self._decode_block(block_idx, reduced.data)
                    made_progress = True
                else:
                    # Still pending
                    new_pending.append(reduced)
            
            self.pending_droplets = new_pending
    
    def get_data(self, original_length: Optional[int] = None) -> bytes:
        """
        Get reconstructed data.
        
        Args:
            original_length: Original data length (before padding). 
                           If None, uses length provided to __init__.
            
        Returns:
            Reconstructed data
            
        Raises:
            RuntimeError: If decoding is not complete
            ValueError: If original_length not provided and not set on decoder
        """
        if not self.is_complete():
            raise RuntimeError(
                f"Decoding incomplete: {self.decoded_count}/{self.k_blocks} blocks decoded"
            )
        
        # Use provided length, or fall back to stored length
        if original_length is None:
            original_length = self.original_length
        
        if original_length is None:
            raise ValueError(
                "original_length must be provided either to __init__ or get_data()"
            )
        
        # Concatenate blocks
        full_data = b''.join(self.blocks)
        
        # Remove padding
        return full_data[:original_length]


# Helper functions for encoding/decoding

def pack_droplet(droplet: Droplet) -> bytes:
    """
    Pack droplet into bytes for QR code.
    
    Format:
        seed (4 bytes) +
        num_indices (2 bytes) +
        indices (2 bytes each) +
        data (variable)
    
    Args:
        droplet: Droplet to pack
        
    Returns:
        Packed bytes
    """
    packed = struct.pack(">I", droplet.seed)
    packed += struct.pack(">H", len(droplet.block_indices))
    
    for idx in droplet.block_indices:
        packed += struct.pack(">H", idx)
    
    packed += droplet.data
    
    return packed


def unpack_droplet(data: bytes, block_size: int) -> Droplet:
    """
    Unpack droplet from bytes.
    
    Args:
        data: Packed droplet bytes
        block_size: Expected block size
        
    Returns:
        Unpacked droplet
    """
    offset = 0
    
    # Parse seed
    seed = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    
    # Parse indices
    num_indices = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    
    indices = []
    for _ in range(num_indices):
        idx = struct.unpack(">H", data[offset:offset + 2])[0]
        indices.append(idx)
        offset += 2
    
    # Parse data
    droplet_data = data[offset:offset + block_size]
    
    return Droplet(
        seed=seed,
        block_indices=indices,
        data=droplet_data
    )


# Testing
if __name__ == "__main__":
    print("Testing Fountain Codes...\n")
    
    # Test 1: Basic encoding/decoding
    print("1. Testing basic fountain code...")
    
    test_data = b"Hello, this is a fountain code test! " * 20
    k_blocks = 10
    block_size = 100
    
    # Encode
    encoder = FountainEncoder(test_data, k_blocks, block_size)
    print(f"   Encoder: {k_blocks} blocks, {block_size} bytes each")
    
    # Decode
    decoder = FountainDecoder(k_blocks, block_size)
    
    # Generate and process droplets
    droplets_needed = 0
    while not decoder.is_complete():
        droplet = encoder.droplet()
        decoder.add_droplet(droplet)
        droplets_needed += 1
        
        if droplets_needed > k_blocks * 2:
            print("   ✗ Failed to decode (too many droplets)")
            break
    
    if decoder.is_complete():
        decoded_data = decoder.get_data(len(test_data))
        if decoded_data == test_data:
            print(f"   ✓ Decoded successfully with {droplets_needed} droplets ({droplets_needed/k_blocks:.1f}x overhead)")
        else:
            print("   ✗ Decoded data doesn't match")
    
    # Test 2: Droplet packing/unpacking
    print("\n2. Testing droplet packing...")
    
    droplet = encoder.droplet()
    packed = pack_droplet(droplet)
    unpacked = unpack_droplet(packed, block_size)
    
    if (unpacked.seed == droplet.seed and
        unpacked.block_indices == droplet.block_indices and
        unpacked.data == droplet.data):
        print(f"   ✓ Packing/unpacking works ({len(packed)} bytes)")
    else:
        print("   ✗ Packing/unpacking failed")
    
    # Test 3: Distribution
    print("\n3. Testing Robust Soliton distribution...")
    
    dist = RobustSolitonDistribution(k_blocks)
    degrees = [dist.sample_degree() for _ in range(1000)]
    
    avg_degree = sum(degrees) / len(degrees)
    print(f"   Average degree: {avg_degree:.2f}")
    print(f"   Min degree: {min(degrees)}, Max degree: {max(degrees)}")
    
    if 2 < avg_degree < 5:
        print("   ✓ Distribution looks good")
    else:
        print("   ⚠ Distribution might be suboptimal")
    
    print("\n✅ All fountain code tests complete!")
    print(f"\nPerformance: {droplets_needed}/{k_blocks} droplets needed")
    print(f"Overhead: {(droplets_needed - k_blocks) / k_blocks * 100:.1f}%")
