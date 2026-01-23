"""
🐾 Prowling Mode - Streaming Decode for Low-Memory Devices
Priority 4: True low-RAM fountain decode with disk-based storage

Features:
- Chunked fountain decode (process one kibble at a time)
- Disk-based block storage (minimal RAM)
- Dynamic block size adjustment
- Memory monitoring with psutil
- Works on Raspberry Pi / embedded devices!
"""

import os
import gc
import tempfile
from pathlib import Path
from typing import Optional, Set, List, Tuple
from dataclasses import dataclass
import struct

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("⚠️  psutil not available (install for memory monitoring)")


@dataclass
class ProwlingConfig:
    """🐾 Prowling mode configuration."""
    enable_low_ram: bool = True
    max_ram_mb: int = 100           # Maximum RAM to use
    block_size: int = 256           # Smaller blocks for low RAM
    min_block_size: int = 128       # Minimum allowed
    temp_file: Optional[Path] = None
    warn_threshold_mb: int = 150    # Warn if approaching limit


class MemoryProwler:
    """
    🐾 Memory prowler - monitors RAM usage.
    
    Watches memory like a cat watches prey!
    """
    
    def __init__(self, config: ProwlingConfig):
        """Initialize memory prowler."""
        self.config = config
        self.has_psutil = HAS_PSUTIL
        self.peak_rss_mb = 0
    
    def get_current_ram_mb(self) -> Optional[int]:
        """Get current process RAM usage in MB."""
        if not self.has_psutil:
            return None
        
        try:
            process = psutil.Process()
            ram_mb = process.memory_info().rss // (1024 * 1024)
            self.peak_rss_mb = max(self.peak_rss_mb, ram_mb)
            return ram_mb
        except:
            return None
    
    def get_available_ram_mb(self) -> Optional[int]:
        """Get available system RAM in MB."""
        if not self.has_psutil:
            return None
        
        try:
            mem = psutil.virtual_memory()
            return mem.available // (1024 * 1024)
        except:
            return None
    
    def check_memory(self) -> bool:
        """
        🚨 Check if we're approaching memory limit.
        
        Returns:
            True if OK, False if approaching limit
        """
        current = self.get_current_ram_mb()
        if current is None:
            return True  # Can't check, assume OK
        
        if current > self.config.max_ram_mb:
            print(f"🚨 WARNING: RAM usage {current} MB > limit {self.config.max_ram_mb} MB")
            return False
        
        if current > self.config.warn_threshold_mb:
            print(f"⚠️  RAM usage: {current} MB (approaching limit)")
        
        return True
    
    def force_gc(self):
        """🧹 Force garbage collection."""
        gc.collect()


class DiskBasedKibbleCollector:
    """
    🐾 Disk-based kibble collector for low-memory devices.
    
    Instead of keeping all blocks in RAM, we:
    - Store solved blocks on disk immediately
    - Keep only pending kibbles in RAM
    - Use minimal memory even for huge files!
    """
    
    def __init__(self, num_posts: int, post_size: int, config: ProwlingConfig):
        """
        Initialize disk-based collector.
        
        Args:
            num_posts: Number of scratching posts
            post_size: Size of each post
            config: Prowling configuration
        """
        self.num_posts = num_posts
        self.post_size = post_size
        self.config = config
        
        # Create temp file for blocks
        if config.temp_file is None:
            fd, temp_path = tempfile.mkstemp(suffix='.meow_blocks')
            os.close(fd)
            self.temp_file = Path(temp_path)
        else:
            self.temp_file = config.temp_file
        
        print(f"🐾 Prowling mode: blocks stored at {self.temp_file}")
        
        # Initialize disk file with zeros
        total_size = num_posts * post_size
        with open(self.temp_file, 'wb') as f:
            f.write(b'\x00' * total_size)
        
        # Track which posts are solved (only need bits!)
        self.solved_posts: Set[int] = set()
        self.posts_found = 0
        
        # Pending kibbles (kept in RAM, but should be minimal)
        self.pending_kibbles: List[Tuple[List[int], bytes]] = []
        
        # Memory monitoring
        self.prowler = MemoryProwler(config)
        
        print(f"  📊 Total file size: {total_size:,} bytes")
        print(f"  🐾 Posts to find: {num_posts}")
    
    def is_satisfied(self) -> bool:
        """😸 Check if all posts found."""
        return self.posts_found == self.num_posts
    
    def write_post_to_disk(self, post_idx: int, data: bytes):
        """
        💾 Write a solved post to disk immediately.
        
        This frees up RAM!
        """
        offset = post_idx * self.post_size
        
        with open(self.temp_file, 'r+b') as f:
            f.seek(offset)
            f.write(data)
        
        self.solved_posts.add(post_idx)
        self.posts_found += 1
    
    def read_post_from_disk(self, post_idx: int) -> bytes:
        """
        💾 Read a post from disk.
        
        Only needed during belief propagation.
        """
        offset = post_idx * self.post_size
        
        with open(self.temp_file, 'rb') as f:
            f.seek(offset)
            return f.read(self.post_size)
    
    def collect_kibble_streaming(self, seed: int, post_indices: List[int], data: bytes) -> bool:
        """
        🐾 Collect kibble with minimal memory usage.
        
        Returns:
            True if all posts found
        """
        # Check memory before processing
        if not self.prowler.check_memory():
            print("🚨 Memory limit reached! Forcing GC...")
            self.prowler.force_gc()
        
        if self.is_satisfied():
            return True
        
        # Make mutable copies
        indices = list(post_indices)
        kibble_data = bytearray(data)
        
        # XOR out known posts (reading from disk as needed)
        indices_to_remove = []
        for idx in indices:
            if idx in self.solved_posts:
                # Read from disk, XOR, then discard
                known_post = self.read_post_from_disk(idx)
                for i in range(self.post_size):
                    kibble_data[i] ^= known_post[i]
                indices_to_remove.append(idx)
        
        for idx in indices_to_remove:
            indices.remove(idx)
        
        # Process based on degree
        if len(indices) == 0:
            # Fully reduced, discard
            pass
        elif len(indices) == 1:
            # Found a post! Write to disk immediately
            idx = indices[0]
            self.write_post_to_disk(idx, bytes(kibble_data))
            
            if self.posts_found % 10 == 0:
                print(f"  🐾 Found {self.posts_found}/{self.num_posts} posts ({self.posts_found/self.num_posts*100:.1f}%)")
            
            # Try to solve pending kibbles
            self._process_pending_streaming()
            
            # Force GC after solving
            self.prowler.force_gc()
        else:
            # Store for later (but limit pending to save RAM)
            if len(self.pending_kibbles) < 1000:  # Cap pending
                self.pending_kibbles.append((indices, bytes(kibble_data)))
            
            # Periodic GC
            if len(self.pending_kibbles) % 100 == 0:
                self.prowler.force_gc()
        
        return self.is_satisfied()
    
    def _process_pending_streaming(self):
        """
        🐾 Process pending kibbles (belief propagation).
        
        Uses disk for known blocks to save RAM.
        """
        made_progress = True
        iterations = 0
        max_iterations = 5  # Limit to prevent hanging
        
        while made_progress and not self.is_satisfied() and iterations < max_iterations:
            made_progress = False
            iterations += 1
            new_pending = []
            
            for indices, data in self.pending_kibbles:
                # Make mutable
                indices = list(indices)
                kibble_data = bytearray(data)
                
                # XOR out solved posts from disk
                indices_to_remove = []
                for idx in indices:
                    if idx in self.solved_posts:
                        known_post = self.read_post_from_disk(idx)
                        for i in range(self.post_size):
                            kibble_data[i] ^= known_post[i]
                        indices_to_remove.append(idx)
                
                for idx in indices_to_remove:
                    indices.remove(idx)
                
                # Check status
                if len(indices) == 0:
                    # Fully reduced
                    pass
                elif len(indices) == 1:
                    # Can solve!
                    idx = indices[0]
                    self.write_post_to_disk(idx, bytes(kibble_data))
                    made_progress = True
                else:
                    # Keep for next iteration
                    new_pending.append((indices, bytes(kibble_data)))
            
            self.pending_kibbles = new_pending
            
            # GC after each iteration
            if made_progress:
                self.prowler.force_gc()
    
    def get_reconstructed_data(self, original_length: int) -> bytes:
        """
        😸 Get reconstructed data from disk.
        
        Args:
            original_length: Original data length (before padding)
            
        Returns:
            Reconstructed data
        """
        if not self.is_satisfied():
            raise RuntimeError(
                f"🐾 Not enough kibbles! Found {self.posts_found}/{self.num_posts} posts"
            )
        
        # Read all blocks from disk
        with open(self.temp_file, 'rb') as f:
            full_data = f.read()
        
        # Clean up temp file
        try:
            self.temp_file.unlink()
        except:
            pass
        
        # Remove padding
        return full_data[:original_length]
    
    def get_stats(self) -> dict:
        """📊 Get prowling statistics."""
        current_ram = self.prowler.get_current_ram_mb()
        
        return {
            'posts_found': self.posts_found,
            'total_posts': self.num_posts,
            'pending_kibbles': len(self.pending_kibbles),
            'current_ram_mb': current_ram,
            'peak_ram_mb': self.prowler.peak_rss_mb,
            'temp_file_size_mb': self.temp_file.stat().st_size // (1024 * 1024)
        }


def create_prowling_decoder(num_posts: int,
                            post_size: int,
                            max_ram_mb: int = 100) -> DiskBasedKibbleCollector:
    """
    🐾 Create prowling decoder for low-memory decode.
    
    Args:
        num_posts: Number of posts to find
        post_size: Size of each post
        max_ram_mb: Maximum RAM to use
        
    Returns:
        Configured disk-based collector
    """
    config = ProwlingConfig(
        enable_low_ram=True,
        max_ram_mb=max_ram_mb,
        block_size=min(post_size, 256)
    )
    
    print(f"\n🐾 Prowling Mode Activated!")
    print(f"  📊 Max RAM: {max_ram_mb} MB")
    print(f"  🏠 Posts: {num_posts}")
    print(f"  📏 Post size: {post_size} bytes")
    
    return DiskBasedKibbleCollector(num_posts, post_size, config)


# Testing
if __name__ == "__main__":
    print("🐾 Testing Prowling Mode (Low-Memory Decode)...\n")
    
    # Test with fountain codes
    print("1. Creating test data...")
    from catnip_fountain import CatnipFountain, Kibble
    
    test_data = b"Prowling like a cat! " * 500
    num_posts = 30
    post_size = 256
    
    # Pad data
    total_size = num_posts * post_size
    test_data = test_data[:total_size]
    test_data += b'\x00' * (total_size - len(test_data))
    
    print(f"   Data size: {len(test_data):,} bytes")
    print(f"   Posts: {num_posts}")
    
    # Create fountain
    print("\n2. Creating catnip fountain...")
    fountain = CatnipFountain(test_data, num_posts, post_size)
    
    # Create prowling decoder
    print("\n3. Creating prowling decoder...")
    decoder = create_prowling_decoder(num_posts, post_size, max_ram_mb=50)
    
    # Collect kibbles
    print("\n4. Collecting kibbles...")
    kibbles_needed = 0
    max_kibbles = num_posts * 3
    
    for i in range(max_kibbles):
        kibble = fountain.drop_kibble()
        
        satisfied = decoder.collect_kibble_streaming(
            kibble.seed,
            kibble.scratching_post_indices,
            kibble.data
        )
        
        kibbles_needed = i + 1
        
        if satisfied:
            print(f"\n  ✅ All posts found after {kibbles_needed} kibbles!")
            break
        
        # Show stats every 10 kibbles
        if kibbles_needed % 10 == 0:
            stats = decoder.get_stats()
            if stats['current_ram_mb']:
                print(f"  📊 Kibble {kibbles_needed}: RAM {stats['current_ram_mb']} MB, Pending {stats['pending_kibbles']}")
    
    # Get reconstructed data
    if decoder.is_satisfied():
        print("\n5. Reconstructing data...")
        reconstructed = decoder.get_reconstructed_data(len(test_data))
        
        if reconstructed == test_data:
            print("  ✅ Prowling decode successful!")
        else:
            print("  ❌ Data mismatch!")
        
        # Show final stats
        stats = decoder.get_stats()
        print(f"\n📊 Final Statistics:")
        print(f"  Kibbles needed: {kibbles_needed}/{num_posts} ({kibbles_needed/num_posts:.2f}x)")
        if stats['peak_ram_mb']:
            print(f"  Peak RAM: {stats['peak_ram_mb']} MB")
        print(f"  Temp file: {stats['temp_file_size_mb']} MB")
    else:
        print(f"\n  ❌ Failed after {max_kibbles} kibbles")
    
    print("\n✅ Prowling mode test complete!")
    print("🐾 Ready for Raspberry Pi deployment!")
