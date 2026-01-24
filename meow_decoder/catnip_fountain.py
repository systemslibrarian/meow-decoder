"""
🐱 Catnip Fountain for Meow Decoder
Dispenses endless kibbles (encoded packets) using Luby Transform

Features:
- Cat Nap distribution for kibble selection
- Infinite kibble stream
- Scratching post-based encoding
- Belief propagation decoding
"""

import random
import struct
import numpy as np
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class Kibble:
    """
    🍖 A kibble of encoded data from the fountain.
    
    Each kibble contains XOR'd data from multiple scratching posts.
    Cats collect kibbles until they can reconstruct all scratching posts!
    
    Attributes:
        seed: Random seed for this kibble
        scratching_post_indices: Which posts were XOR'd together
        data: The yummy XOR'd data
    """
    seed: int
    scratching_post_indices: List[int]
    data: bytes


class CatNapDistribution:
    """
    😴 Cat Nap Distribution - decides how many posts each kibble uses.
    
    Based on Robust Soliton distribution, but with cat naps!
    Some kibbles use few posts (light nap), others use many (deep sleep).
    """
    
    def __init__(self, num_posts: int, c: float = 0.1, delta: float = 0.5):
        """
        Initialize the nap distribution.
        
        Args:
            num_posts: Total number of scratching posts
            c: Nap constant (0.01-0.5)
            delta: Probability of failed nap (0.01-0.5)
        """
        self.num_posts = num_posts
        self.c = c
        self.delta = delta
        
        # Calculate nap probabilities
        self._calculate_nap_schedule()
    
    def _calculate_nap_schedule(self):
        """😴 Calculate the cat nap schedule (probability distribution)."""
        # Ideal cat nap schedule
        light_naps = [0.0] * (self.num_posts + 1)
        light_naps[1] = 1.0 / self.num_posts
        for d in range(2, self.num_posts + 1):
            light_naps[d] = 1.0 / (d * (d - 1))
        
        # Deep sleep component
        deep_sleep = [0.0] * (self.num_posts + 1)
        R = self.c * np.log(self.num_posts / self.delta) * np.sqrt(self.num_posts)
        
        for d in range(1, int(self.num_posts / R) + 1):
            deep_sleep[d] = R / (d * self.num_posts)
        deep_sleep[int(self.num_posts / R)] += R * np.log(R / self.delta) / self.num_posts
        
        # Combine nap schedules
        nap_schedule = [light_naps[d] + deep_sleep[d] for d in range(self.num_posts + 1)]
        
        # Normalize (total should be 1.0)
        total_naps = sum(nap_schedule)
        self.probabilities = [nap_schedule[d] / total_naps for d in range(self.num_posts + 1)]
        
        # Cumulative for sampling
        self.cumulative = [0.0] * (self.num_posts + 1)
        self.cumulative[0] = self.probabilities[0]
        for i in range(1, self.num_posts + 1):
            self.cumulative[i] = self.cumulative[i-1] + self.probabilities[i]
    
    def sample_nap_depth(self, rng: random.Random) -> int:
        """
        😴 Sample how many posts to use (nap depth).
        
        Args:
            rng: Random number generator
            
        Returns:
            Number of scratching posts to XOR together
        """
        p = rng.random()
        for d in range(1, self.num_posts + 1):
            if p <= self.cumulative[d]:
                return d
        return self.num_posts


class CatnipFountain:
    """
    🌊 Catnip Fountain - dispenses infinite kibbles!
    
    Feed it your hissed (encrypted) data and it will generate
    an endless stream of kibbles that cats can collect and
    reassemble into the original scratching posts.
    """
    
    def __init__(self, hissed_data: bytes, num_posts: int, post_size: int):
        """
        Initialize the catnip fountain.
        
        Args:
            hissed_data: Encrypted data to encode
            num_posts: Number of scratching posts
            post_size: Size of each scratching post
        """
        self.num_posts = num_posts
        self.post_size = post_size
        
        # Pad data to exact size
        total_size = num_posts * post_size
        if len(hissed_data) < total_size:
            hissed_data = hissed_data + b'\x00' * (total_size - len(hissed_data))
        elif len(hissed_data) > total_size:
            raise ValueError(f"😿 Too much data: {len(hissed_data)} > {total_size}")
        
        # Split into scratching posts
        self.scratching_posts = []
        for i in range(num_posts):
            start = i * post_size
            end = start + post_size
            self.scratching_posts.append(hissed_data[start:end])
        
        # Initialize cat nap distribution
        self.nap_distribution = CatNapDistribution(num_posts)
        
        # Kibble counter
        self.kibbles_dispensed = 0
    
    def drop_kibble(self, seed: Optional[int] = None) -> Kibble:
        """
        🍖 Drop a kibble from the fountain!
        
        Args:
            seed: Optional seed for reproducibility
            
        Returns:
            A fresh kibble with encoded data
        """
        # Use provided seed or generate new one
        if seed is None:
            seed = self.kibbles_dispensed
        
        self.kibbles_dispensed += 1
        
        # Create RNG with seed
        rng = random.Random(seed)
        
        # Sample nap depth (how many posts to XOR)
        nap_depth = self.nap_distribution.sample_nap_depth(rng)
        
        # Select random scratching posts
        post_indices = sorted(rng.sample(range(self.num_posts), nap_depth))
        
        # XOR selected posts together
        kibble_data = bytearray(self.post_size)
        for idx in post_indices:
            post = self.scratching_posts[idx]
            for i in range(self.post_size):
                kibble_data[i] ^= post[i]
        
        return Kibble(
            seed=seed,
            scratching_post_indices=post_indices,
            data=bytes(kibble_data)
        )
    
    def dispense_kibbles(self, count: int) -> List[Kibble]:
        """
        🍖🍖🍖 Dispense multiple kibbles at once!
        
        Args:
            count: Number of kibbles to dispense
            
        Returns:
            List of fresh kibbles
        """
        return [self.drop_kibble() for _ in range(count)]


class KibbleCollector:
    """
    😺 Kibble Collector - cats collect kibbles and solve for scratching posts!
    
    Uses belief propagation to figure out which posts contain what data.
    """
    
    def __init__(self, num_posts: int, post_size: int):
        """
        Initialize the kibble collector.
        
        Args:
            num_posts: Number of scratching posts to find
            post_size: Size of each scratching post
        """
        self.num_posts = num_posts
        self.post_size = post_size
        
        # Solved scratching posts (None = not yet found)
        self.scratching_posts = [None] * num_posts
        self.posts_found = 0
        
        # Store kibbles for later processing
        self.kibble_stash: List[Tuple[List[int], bytes]] = []
    
    def is_satisfied(self) -> bool:
        """😸 Check if all scratching posts have been found."""
        return self.posts_found == self.num_posts
    
    def collect_kibble(self, seed: int, post_indices: List[int], data: bytes) -> bool:
        """
        😺 Collect a kibble and try to solve posts!
        
        Args:
            seed: Kibble seed
            post_indices: Which posts this kibble contains
            data: XOR'd data
            
        Returns:
            True if all posts found, False otherwise
        """
        if self.is_satisfied():
            return True
        
        # Make mutable copies
        indices = list(post_indices)
        kibble_data = bytearray(data)
        
        # Remove already-known posts
        indices_to_remove = []
        for idx in indices:
            if self.scratching_posts[idx] is not None:
                # XOR out this known post
                known_post = self.scratching_posts[idx]
                for i in range(self.post_size):
                    kibble_data[i] ^= known_post[i]
                indices_to_remove.append(idx)
        
        # Remove known indices
        for idx in indices_to_remove:
            indices.remove(idx)
        
        # Check if we can solve
        if len(indices) == 0:
            # Kibble is all-zero, discard
            pass
        elif len(indices) == 1:
            # Found a post! 🎉
            idx = indices[0]
            self.scratching_posts[idx] = bytes(kibble_data)
            self.posts_found += 1
            
            # Try to solve other kibbles in stash
            self._process_stash()
        else:
            # Store for later
            self.kibble_stash.append((indices, bytes(kibble_data)))
        
        return self.is_satisfied()
    
    def _process_stash(self):
        """🐱 Process stashed kibbles after finding a post."""
        made_progress = True
        while made_progress and not self.is_satisfied():
            made_progress = False
            
            # Try to reduce kibbles
            new_stash = []
            for indices, data in self.kibble_stash:
                # Make mutable
                indices = list(indices)
                kibble_data = bytearray(data)
                
                # Remove known posts
                indices_to_remove = []
                for idx in indices:
                    if self.scratching_posts[idx] is not None:
                        known_post = self.scratching_posts[idx]
                        for i in range(self.post_size):
                            kibble_data[i] ^= known_post[i]
                        indices_to_remove.append(idx)
                
                for idx in indices_to_remove:
                    indices.remove(idx)
                
                # Check status
                if len(indices) == 0:
                    # Fully reduced, discard
                    pass
                elif len(indices) == 1:
                    # Can solve! 🎉
                    idx = indices[0]
                    self.scratching_posts[idx] = bytes(kibble_data)
                    self.posts_found += 1
                    made_progress = True
                else:
                    # Keep for next iteration
                    new_stash.append((indices, bytes(kibble_data)))
            
            self.kibble_stash = new_stash
    
    def get_reconstructed_data(self) -> bytes:
        """
        😸 Get the reconstructed data from all scratching posts!
        
        Returns:
            All posts concatenated together
            
        Raises:
            RuntimeError: If not all posts found yet
        """
        if not self.is_satisfied():
            raise RuntimeError(
                f"😿 Not enough kibbles! Found {self.posts_found}/{self.num_posts} posts"
            )
        
        # Concatenate all scratching posts
        result = b''.join(self.scratching_posts)
        return result


# Helper functions

def pack_kibble(kibble: Kibble) -> bytes:
    """
    📦 Pack a kibble into bytes for QR code.
    
    Format:
        seed (4 bytes) +
        num_posts (2 bytes) +
        post_indices (2 bytes each) +
        data (variable)
    
    Args:
        kibble: Kibble to pack
        
    Returns:
        Packed kibble bytes
    """
    packed = struct.pack(">I", kibble.seed)
    packed += struct.pack(">H", len(kibble.scratching_post_indices))
    
    for idx in kibble.scratching_post_indices:
        packed += struct.pack(">H", idx)
    
    packed += kibble.data
    
    return packed


def unpack_kibble(data: bytes, post_size: int) -> Kibble:
    """
    📦 Unpack a kibble from bytes.
    
    Args:
        data: Packed kibble bytes
        post_size: Expected post size
        
    Returns:
        Unpacked kibble
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
    kibble_data = data[offset:offset + post_size]
    
    return Kibble(
        seed=seed,
        scratching_post_indices=indices,
        data=kibble_data
    )


# Testing
if __name__ == "__main__":
    print("🐱 Testing Catnip Fountain...\n")
    
    # Test 1: Basic kibble dispensing
    print("😸 Test 1: Dispensing kibbles...")
    
    test_data = b"Meow meow meow! " * 100
    num_posts = 20
    post_size = 128
    
    # Pad to exact size
    total_size = num_posts * post_size
    test_data = test_data[:total_size]
    test_data += b'\x00' * (total_size - len(test_data))
    
    # Create fountain
    fountain = CatnipFountain(test_data, num_posts, post_size)
    
    # Create collector
    collector = KibbleCollector(num_posts, post_size)
    
    kibbles_needed = 0
    max_kibbles = num_posts * 2
    
    for i in range(max_kibbles):
        kibble = fountain.drop_kibble()
        satisfied = collector.collect_kibble(
            kibble.seed,
            kibble.scratching_post_indices,
            kibble.data
        )
        kibbles_needed = i + 1
        
        if satisfied:
            break
    
    if collector.is_satisfied():
        reconstructed = collector.get_reconstructed_data()
        if reconstructed == test_data:
            print(f"  ✅ Success! Collected {kibbles_needed}/{num_posts} kibbles")
            print(f"  📊 Overhead: {(kibbles_needed - num_posts) / num_posts * 100:.1f}%")
        else:
            print(f"  ❌ Data mismatch!")
    else:
        print(f"  ❌ Failed after {max_kibbles} kibbles")
    
    # Test 2: Cat Nap Distribution
    print("\n😴 Test 2: Cat nap distribution...")
    
    dist = CatNapDistribution(100)
    rng = random.Random(42)
    
    naps = [dist.sample_nap_depth(rng) for _ in range(1000)]
    avg_nap = sum(naps) / len(naps)
    print(f"  📊 Average nap depth: {avg_nap:.2f} posts")
    print(f"  😴 Lightest nap: {min(naps)} posts")
    print(f"  😴 Deepest nap: {max(naps)} posts")
    
    # Test 3: Larger data
    print("\n😸 Test 3: Large catnip batch...")
    large_data = b"X" * 10000
    num_posts = 50
    post_size = 256
    
    total_size = num_posts * post_size
    large_data = large_data[:total_size]
    large_data += b'\x00' * (total_size - len(large_data))
    
    fountain = CatnipFountain(large_data, num_posts, post_size)
    collector = KibbleCollector(num_posts, post_size)
    
    kibbles_needed = 0
    for i in range(num_posts * 3):
        kibble = fountain.drop_kibble()
        satisfied = collector.collect_kibble(
            kibble.seed,
            kibble.scratching_post_indices,
            kibble.data
        )
        kibbles_needed = i + 1
        
        if satisfied:
            break
    
    if collector.is_satisfied():
        reconstructed = collector.get_reconstructed_data()
        if reconstructed == large_data:
            print(f"  ✅ Large batch success!")
            print(f"  📊 Kibbles: {kibbles_needed}/{num_posts} ({kibbles_needed/num_posts:.2f}x)")
        else:
            print(f"  ❌ Data mismatch")
    else:
        print(f"  ❌ Failed to collect enough kibbles")
    
    print("\n✨ All catnip fountain tests complete! 🐱")
    print(f"\n😸 Typical overhead: 1.1-1.5x (need 10-50% more kibbles than posts)")
    print(f"🎉 Meow meow meow!")
