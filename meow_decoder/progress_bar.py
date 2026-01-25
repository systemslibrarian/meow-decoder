"""
🐱 Visual Progress Bar for Meow Decoder
Provides rich terminal progress visualization inspired by Bitfountain/TXQR

Features:
- Slice-by-slice visual progress bar
- Real-time throughput statistics
- ETA calculation
- Color-coded status (green=received, red=missing)
- Works in terminal (no GUI required)
"""

import sys
import time
import shutil
from dataclasses import dataclass, field
from typing import Optional, List
from collections import deque


@dataclass
class ProgressStats:
    """Statistics for progress tracking."""
    total_items: int = 0
    received_items: int = 0
    start_time: float = field(default_factory=time.time)
    bytes_transferred: int = 0
    
    # Throughput calculation (sliding window)
    _throughput_samples: deque = field(default_factory=lambda: deque(maxlen=10))
    _throughput_fps_samples: deque = field(default_factory=lambda: deque(maxlen=10))
    _last_sample_time: float = field(default_factory=time.time)
    _last_bytes: int = 0
    _last_items_count: int = 0
    
    @property
    def percentage(self) -> float:
        """Return completion percentage (0-100)."""
        if self.total_items == 0:
            return 0.0
        return (self.received_items / self.total_items) * 100
    
    @property
    def elapsed_seconds(self) -> float:
        """Return elapsed time in seconds."""
        return time.time() - self.start_time
    
    @property
    def elapsed_str(self) -> str:
        """Return elapsed time as HH:MM:SS."""
        elapsed = int(self.elapsed_seconds)
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"
    
    def update_throughput(self, current_bytes: int) -> None:
        """Update throughput calculation."""
        now = time.time()
        time_delta = now - self._last_sample_time
        
        if time_delta >= 0.5:  # Sample every 500ms
            # Byte throughput
            bytes_delta = current_bytes - self._last_bytes
            if time_delta > 0:
                rate = bytes_delta / time_delta
                self._throughput_samples.append(rate)
                
                # FPS throughput
                items_delta = self.received_items - self._last_items_count
                fps = items_delta / time_delta
                self._throughput_fps_samples.append(fps)
            
            self._last_sample_time = now
            self._last_bytes = current_bytes
            self._last_items_count = self.received_items
    
    @property
    def throughput_bps(self) -> float:
        """Return throughput in bytes per second."""
        if not self._throughput_samples:
            return 0.0
        return sum(self._throughput_samples) / len(self._throughput_samples)

    @property
    def throughput_fps(self) -> float:
        """Return throughput in items (frames) per second."""
        if not self._throughput_fps_samples:
            return 0.0
        return sum(self._throughput_fps_samples) / len(self._throughput_fps_samples)
    
    @property
    def throughput_str(self) -> str:
        """Return human-readable throughput (Bytes and FPS)."""
        bps = self.throughput_bps
        fps = self.throughput_fps
        
        # Format bytes
        if bps >= 1024 * 1024:
            s_bytes = f"{bps / (1024 * 1024):.1f} MB/s"
        elif bps >= 1024:
            s_bytes = f"{bps / 1024:.1f} KB/s"
        else:
            s_bytes = f"{bps:.0f} B/s"
            
        return f"{s_bytes} ({fps:.1f} fps)"
    
    @property
    def eta_seconds(self) -> Optional[float]:
        """Return estimated time remaining in seconds."""
        if self.throughput_bps == 0:
            return None
        remaining_items = self.total_items - self.received_items
        if self.received_items == 0:
            return None
        avg_item_size = self.bytes_transferred / self.received_items
        remaining_bytes = remaining_items * avg_item_size
        return remaining_bytes / self.throughput_bps
    
    @property
    def eta_str(self) -> str:
        """Return ETA as HH:MM:SS or 'Calculating...'."""
        eta = self.eta_seconds
        if eta is None:
            return "Calculating..."
        
        eta_int = int(eta)
        hours, remainder = divmod(eta_int, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"


class ProgressBar:
    """
    Visual progress bar for terminal display.
    
    Inspired by Bitfountain's slice-by-slice visualization.
    Shows which blocks have been received (green) vs missing (red).
    """
    
    # ANSI color codes
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    def __init__(self, total: int, width: Optional[int] = None, 
                 use_color: bool = True, title: str = "Progress"):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of items to track
            width: Bar width (auto-detect if None)
            use_color: Use ANSI colors
            title: Title to display
        """
        self.total = total
        self.use_color = use_color and sys.stdout.isatty()
        self.title = title
        
        # Auto-detect terminal width
        if width is None:
            try:
                terminal_width = shutil.get_terminal_size().columns
                self.width = min(50, terminal_width - 40)  # Leave room for stats
            except:
                self.width = 40
        else:
            self.width = width
        
        # Track which items are received
        self.received = [False] * total
        self.stats = ProgressStats(total_items=total)
        
        # For fountain codes: track all received droplet seeds
        self.droplet_seeds: set = set()
    
    def _color(self, text: str, color: str) -> str:
        """Apply color if enabled."""
        if self.use_color:
            return f"{color}{text}{self.RESET}"
        return text
    
    def mark_received(self, index: int, bytes_count: int = 0) -> None:
        """Mark an item as received."""
        if 0 <= index < self.total:
            if not self.received[index]:
                self.received[index] = True
                self.stats.received_items += 1
        
        self.stats.bytes_transferred += bytes_count
        self.stats.update_throughput(self.stats.bytes_transferred)
    
    def mark_droplet(self, seed: int, bytes_count: int = 0) -> None:
        """Mark a fountain droplet as received (by seed)."""
        if seed not in self.droplet_seeds:
            self.droplet_seeds.add(seed)
            self.stats.received_items = len(self.droplet_seeds)
        
        self.stats.bytes_transferred += bytes_count
        self.stats.update_throughput(self.stats.bytes_transferred)
    
    def render_bar(self) -> str:
        """Render the progress bar string."""
        received_count = sum(self.received)
        percentage = (received_count / self.total) * 100 if self.total > 0 else 0
        
        # Calculate filled portion
        filled = int(self.width * received_count / self.total) if self.total > 0 else 0
        
        # Build bar with block characters
        bar = ""
        for i in range(self.width):
            # Calculate which portion of received[] this bar position represents
            start_idx = int(i * self.total / self.width)
            end_idx = int((i + 1) * self.total / self.width)
            
            # Check if any items in this range are received
            if end_idx <= len(self.received):
                segment_received = any(self.received[start_idx:end_idx])
            else:
                segment_received = i < filled
            
            if segment_received:
                bar += self._color("█", self.GREEN)
            else:
                bar += self._color("░", self.RED)
        
        return bar
    
    def render_compact(self) -> str:
        """Render compact single-line progress."""
        bar = self.render_bar()
        pct = self.stats.percentage
        
        return (
            f"\r{self._color('🐱', self.CYAN)} {self.title}: "
            f"[{bar}] "
            f"{self._color(f'{pct:.1f}%', self.BOLD)} "
            f"({self.stats.received_items}/{self.total}) "
            f"{self._color(self.stats.throughput_str, self.BLUE)} "
            f"ETA: {self.stats.eta_str}"
        )
    
    def render_detailed(self) -> str:
        """Render detailed multi-line progress."""
        bar = self.render_bar()
        pct = self.stats.percentage
        
        lines = [
            f"{self._color('╔══ ' + self.title + ' ══╗', self.BOLD)}",
            f"  Progress: [{bar}] {pct:.1f}%",
            f"  Items:    {self.stats.received_items}/{self.total}",
            f"  Bytes:    {self._format_bytes(self.stats.bytes_transferred)}",
            f"  Speed:    {self.stats.throughput_str}",
            f"  Elapsed:  {self.stats.elapsed_str}",
            f"  ETA:      {self.stats.eta_str}",
            f"{self._color('╚' + '═' * (len(self.title) + 8) + '╝', self.BOLD)}"
        ]
        
        return "\n".join(lines)
    
    def _format_bytes(self, size: int) -> str:
        """Format bytes to human-readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def update(self, clear_line: bool = True) -> None:
        """Update the progress display in terminal."""
        if clear_line:
            # Move cursor to beginning and clear line
            sys.stdout.write("\r\033[K")
        
        sys.stdout.write(self.render_compact())
        sys.stdout.flush()
    
    def finish(self, message: str = "Complete!") -> None:
        """Finish progress and show completion message."""
        self.update()
        print()  # New line
        elapsed = self.stats.elapsed_str
        speed = self.stats.throughput_str
        print(f"{self._color('✅', self.GREEN)} {message} "
              f"({elapsed}, avg {speed})")


class FountainProgressBar(ProgressBar):
    """
    Progress bar optimized for fountain code decoding.
    
    Tracks droplets received and blocks decoded separately,
    since fountain codes decode non-linearly.
    """
    
    def __init__(self, k_blocks: int, expected_droplets: int, **kwargs):
        """
        Initialize fountain progress bar.
        
        Args:
            k_blocks: Number of source blocks to reconstruct
            expected_droplets: Expected number of droplets (~1.5x k_blocks)
        """
        super().__init__(total=k_blocks, **kwargs)
        self.k_blocks = k_blocks
        self.expected_droplets = expected_droplets
        self.blocks_decoded = 0
        self.droplets_received = 0
    
    def update_decoding(self, blocks_decoded: int, droplets_received: int,
                       bytes_count: int = 0) -> None:
        """Update decoding progress."""
        self.blocks_decoded = blocks_decoded
        self.droplets_received = droplets_received
        
        # Mark decoded blocks as received
        for i in range(blocks_decoded):
            if i < len(self.received):
                self.received[i] = True
        
        self.stats.received_items = blocks_decoded
        self.stats.bytes_transferred += bytes_count
        self.stats.update_throughput(self.stats.bytes_transferred)
    
    def render_compact(self) -> str:
        """Render compact single-line fountain progress."""
        bar = self.render_bar()
        pct = (self.blocks_decoded / self.k_blocks * 100) if self.k_blocks > 0 else 0
        
        return (
            f"\r{self._color('🌊', self.CYAN)} Fountain: "
            f"[{bar}] "
            f"{self._color(f'{pct:.1f}%', self.BOLD)} "
            f"({self.blocks_decoded}/{self.k_blocks} blocks) "
            f"[{self.droplets_received} droplets] "
            f"{self._color(self.stats.throughput_str, self.BLUE)}"
        )


# Convenience function for quick progress display
def create_progress(total: int, title: str = "Progress", 
                   fountain: bool = False, **kwargs) -> ProgressBar:
    """
    Create appropriate progress bar.
    
    Args:
        total: Total items to track
        title: Progress title
        fountain: Use fountain code progress bar
        **kwargs: Additional arguments
        
    Returns:
        ProgressBar instance
    """
    if fountain:
        expected = int(total * 1.5)
        return FountainProgressBar(total, expected, title=title, **kwargs)
    return ProgressBar(total, title=title, **kwargs)


# Testing
if __name__ == "__main__":
    import random
    
    print("🐱 Visual Progress Bar Demo\n")
    
    # Demo 1: Simple progress
    print("1. Simple Progress Bar:")
    pb = ProgressBar(100, title="Encoding")
    
    for i in range(100):
        pb.mark_received(i, bytes_count=random.randint(100, 500))
        pb.update()
        time.sleep(0.02)
    
    pb.finish("Encoding complete!")
    
    print("\n" + "="*60 + "\n")
    
    # Demo 2: Fountain code progress
    print("2. Fountain Code Progress:")
    fpb = FountainProgressBar(50, 75, title="Decoding")
    
    droplets = 0
    decoded = 0
    
    for i in range(80):
        droplets += 1
        # Simulate belief propagation - blocks decode non-linearly
        if random.random() > 0.3:
            decoded = min(decoded + random.randint(0, 2), 50)
        
        fpb.update_decoding(decoded, droplets, bytes_count=random.randint(200, 400))
        fpb.update()
        time.sleep(0.03)
        
        if decoded >= 50:
            break
    
    fpb.finish("Fountain decoding complete!")
    
    print("\n" + "="*60 + "\n")
    
    # Demo 3: Detailed view
    print("3. Detailed Progress View:")
    pb3 = ProgressBar(20, title="Transfer")
    
    for i in range(20):
        pb3.mark_received(i, bytes_count=1024)
        time.sleep(0.1)
    
    print(pb3.render_detailed())
    
    print("\n✅ Demo complete!")
