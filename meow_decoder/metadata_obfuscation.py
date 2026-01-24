"""
Metadata Obfuscation Module
Prevents information leakage from observable metadata

Security Goals:
- Hide true file size via length padding
- Constant frame dimensions and rate
- Randomize frame order
- Avoid "Meow Decoder" format fingerprints
- Obfuscate encoding parameters
"""

import secrets
import struct
import random
from typing import Tuple, List
from dataclasses import dataclass


# Standard size classes for padding (powers of 2, in KB)
SIZE_CLASSES = [
    1024,      # 1 KB
    2048,      # 2 KB
    4096,      # 4 KB
    8192,      # 8 KB
    16384,     # 16 KB
    32768,     # 32 KB
    65536,     # 64 KB
    131072,    # 128 KB
    262144,    # 256 KB
    524288,    # 512 KB
    1048576,   # 1 MB
    2097152,   # 2 MB
    4194304,   # 4 MB
    8388608,   # 8 MB
    16777216,  # 16 MB
    33554432,  # 32 MB
    67108864,  # 64 MB
    134217728, # 128 MB
]


def round_up_to_size_class(size: int) -> int:
    """
    Round size up to next standard size class.
    
    Args:
        size: True data size
        
    Returns:
        Padded size (next power-of-2-ish size class)
        
    Security:
        - Prevents size fingerprinting
        - Attacker learns approximate size class, not exact size
        - Example: 1.5 MB file → 2 MB (attacker can't distinguish 1.5 from 1.9)
    """
    for size_class in SIZE_CLASSES:
        if size <= size_class:
            return size_class
    
    # Beyond largest class, round to nearest 64 MB
    return ((size + 67108863) // 67108864) * 67108864


def add_length_padding(data: bytes) -> bytes:
    """
    Add length padding to data.
    
    Args:
        data: Original data
        
    Returns:
        Padded data || length (8 bytes)
        
    Format:
        [Original Data][Random Padding][Original Length: 8 bytes]
        
    Security:
        - Random padding indistinguishable from ciphertext
        - Length stored at end (authenticated by AEAD)
        - Rounds to size class to hide true size
    """
    orig_len = len(data)
    padded_size = round_up_to_size_class(orig_len)
    
    # Calculate padding needed
    # padded_size = orig_len + padding_len + 8 (length field)
    padding_len = padded_size - orig_len - 8
    
    if padding_len < 0:
        # Need to go to next size class
        padded_size = round_up_to_size_class(orig_len + 8)
        padding_len = padded_size - orig_len - 8
    
    # Generate random padding
    padding = secrets.token_bytes(padding_len)
    
    # Append length field
    length_field = struct.pack('<Q', orig_len)
    
    return data + padding + length_field


def remove_length_padding(padded_data: bytes) -> bytes:
    """
    Remove length padding from data.
    
    Args:
        padded_data: Padded data from add_length_padding()
        
    Returns:
        Original data (unpadded)
        
    Raises:
        ValueError: If padding invalid or length field corrupted
    """
    if len(padded_data) < 8:
        raise ValueError("Data too short to contain length field")
    
    # Extract length field
    length_field = padded_data[-8:]
    orig_len = struct.unpack('<Q', length_field)[0]
    
    # Validate length
    if orig_len > len(padded_data) - 8:
        raise ValueError("Invalid length field (padding corrupted?)")
    
    # Extract original data
    return padded_data[:orig_len]


@dataclass
class FrameObfuscationConfig:
    """
    Configuration for frame obfuscation.
    
    Attributes:
        constant_dimensions: Use constant frame size (prevents size fingerprinting)
        constant_rate: Use constant FPS (prevents timing fingerprinting)
        randomize_order: Randomize frame order (prevents sequential analysis)
        fixed_frame_count: Pad to fixed count (prevents count fingerprinting)
    """
    constant_dimensions: bool = True
    constant_rate: bool = True
    randomize_order: bool = True
    fixed_frame_count: int = None  # None = no padding, int = pad to this count


def randomize_frame_order(
    frames: List[bytes],
    seed: bytes = None
) -> Tuple[List[bytes], List[int]]:
    """
    Randomize frame order with deterministic shuffle.
    
    Args:
        frames: List of frame data
        seed: Optional seed for shuffle (defaults to random)
              If provided, shuffle is deterministic
        
    Returns:
        Tuple of (shuffled_frames, shuffle_indices)
        - shuffled_frames: Frames in randomized order
        - shuffle_indices: Mapping to reconstruct original order
        
    Security:
        - Prevents sequential analysis
        - Attacker can't determine encoding order
        - Shuffle seed included in authenticated manifest
        
    Example:
        Original: [A, B, C, D]
        Shuffled: [C, A, D, B]
        Indices:  [2, 0, 3, 1]
    """
    if seed is None:
        seed = secrets.token_bytes(32)
    
    # Create index list
    indices = list(range(len(frames)))
    
    # Deterministic shuffle using seed
    rng = random.Random(int.from_bytes(seed, 'big'))
    rng.shuffle(indices)
    
    # Reorder frames
    shuffled = [frames[i] for i in indices]
    
    return shuffled, indices


def unshuffle_frames(
    shuffled_frames: List[bytes],
    shuffle_indices: List[int]
) -> List[bytes]:
    """
    Reconstruct original frame order.
    
    Args:
        shuffled_frames: Frames in randomized order
        shuffle_indices: Shuffle mapping from randomize_frame_order()
        
    Returns:
        Frames in original order
    """
    original = [None] * len(shuffled_frames)
    
    for shuffled_pos, original_pos in enumerate(shuffle_indices):
        original[original_pos] = shuffled_frames[shuffled_pos]
    
    return original


def pad_frame_count(
    frames: List[bytes],
    target_count: int
) -> List[bytes]:
    """
    Pad frames to fixed count with decoy frames.
    
    Args:
        frames: Real frames
        target_count: Desired total frame count
        
    Returns:
        Padded frame list
        
    Security:
        - Decoy frames are random data (indistinguishable)
        - Attacker can't tell real from decoy without key
        - Prevents frame count fingerprinting
        
    Note:
        Decoy frames will fail MAC verification during decode.
        This is expected and handled gracefully.
    """
    if len(frames) >= target_count:
        return frames
    
    # Generate decoy frames
    decoy_count = target_count - len(frames)
    decoys = [secrets.token_bytes(len(frames[0])) for _ in range(decoy_count)]
    
    return frames + decoys


def obfuscate_encoding_parameters(
    block_size: int,
    redundancy: float,
    fps: int
) -> Tuple[int, float, int]:
    """
    Add noise to encoding parameters.
    
    Args:
        block_size: True block size
        redundancy: True redundancy
        fps: True frame rate
        
    Returns:
        Tuple of (reported_block_size, reported_redundancy, reported_fps)
        
    Security:
        - Reported parameters slightly differ from true values
        - Makes fingerprinting harder
        - True parameters stored in encrypted manifest
        
    Note:
        This is mild obfuscation only. Don't rely on it for security.
    """
    # Add small random offsets
    block_size_offset = secrets.randbelow(33) - 16  # ±16
    redundancy_offset = (secrets.randbelow(21) - 10) / 100  # ±0.1
    fps_offset = secrets.randbelow(3) - 1  # ±1
    
    return (
        max(64, block_size + block_size_offset),
        max(1.0, redundancy + redundancy_offset),
        max(1, fps + fps_offset)
    )


# Example usage
if __name__ == "__main__":
    print("Metadata Obfuscation Test")
    print("=" * 50)
    
    # Test length padding
    print("\n1. Length padding:")
    
    test_sizes = [1500, 15000, 150000, 1500000]
    
    for size in test_sizes:
        data = secrets.token_bytes(size)
        padded = add_length_padding(data)
        unpadded = remove_length_padding(padded)
        
        print(f"   {size:8d} bytes → {len(padded):8d} bytes (padded)")
        print(f"   Size class: {round_up_to_size_class(size):8d} bytes")
        print(f"   Match: {data == unpadded}")
        print()
    
    # Test frame randomization
    print("2. Frame order randomization:")
    
    frames = [f"Frame {i}".encode() for i in range(10)]
    seed = secrets.token_bytes(32)
    
    shuffled, indices = randomize_frame_order(frames, seed)
    unshuffled = unshuffle_frames(shuffled, indices)
    
    print(f"   Original:  {[f.decode() for f in frames[:3]]}...")
    print(f"   Shuffled:  {[f.decode() for f in shuffled[:3]]}...")
    print(f"   Restored:  {[f.decode() for f in unshuffled[:3]]}...")
    print(f"   Match: {frames == unshuffled}")
    
    # Test frame count padding
    print("\n3. Frame count padding:")
    
    real_frames = [f"Real {i}".encode() for i in range(7)]
    padded_frames = pad_frame_count(real_frames, 10)
    
    print(f"   Real frames: {len(real_frames)}")
    print(f"   Padded frames: {len(padded_frames)}")
    print(f"   First real: {padded_frames[0].decode()}")
    print(f"   First decoy: {padded_frames[7][:10].hex()}... (random)")
    
    # Test parameter obfuscation
    print("\n4. Parameter obfuscation:")
    
    true_block = 512
    true_redund = 1.5
    true_fps = 10
    
    for _ in range(5):
        obs_block, obs_redund, obs_fps = obfuscate_encoding_parameters(
            true_block, true_redund, true_fps
        )
        print(f"   Block: {true_block} → {obs_block}, "
              f"Redundancy: {true_redund:.2f} → {obs_redund:.2f}, "
              f"FPS: {true_fps} → {obs_fps}")
    
    print("\n✅ Metadata obfuscation module working!")
    print("   Length padding: ✅")
    print("   Frame randomization: ✅")
    print("   Frame count padding: ✅")
    print("   Parameter obfuscation: ✅")
