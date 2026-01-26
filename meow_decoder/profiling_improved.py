"""
Performance Profiling for Meow Decoder - IMPROVED VERSION
Identify bottlenecks and optimize performance with automated suggestions

IMPROVEMENTS:
- Automated bottleneck analysis with actionable suggestions
- Smart optimization recommendations based on metrics
- Comparison mode for before/after analysis
- Integration with configuration system
"""

import time
import cProfile
import pstats
import io
import os
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from contextlib import contextmanager
from functools import wraps


@dataclass
class TimingData:
    """Store timing information for a named operation."""
    name: str
    total_time: float = 0.0
    call_count: int = 0
    min_time: float = float('inf')
    max_time: float = 0.0
    times: List[float] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)  # For context (block_size, etc.)
    
    @property
    def avg_time(self) -> float:
        """Average time per call."""
        return self.total_time / self.call_count if self.call_count > 0 else 0.0
    
    def add_timing(self, elapsed: float, **metadata):
        """Add a timing measurement with optional metadata."""
        self.total_time += elapsed
        self.call_count += 1
        self.min_time = min(self.min_time, elapsed)
        self.max_time = max(self.max_time, elapsed)
        self.times.append(elapsed)
        
        # Store metadata (like block_size, multiplier, etc.)
        for key, value in metadata.items():
            if key not in self.metadata:
                self.metadata[key] = value


class Profiler:
    """
    Lightweight profiler for tracking operation timing with smart analysis.
    """
    
    def __init__(self):
        self.timings: Dict[str, TimingData] = {}
        self.enabled = True
        self.context: Dict[str, Any] = {}  # Encoding/decoding context
    
    def set_context(self, **kwargs):
        """Set context variables (block_size, multiplier, etc.) for analysis."""
        self.context.update(kwargs)
    
    @contextmanager
    def measure(self, name: str, **metadata):
        """
        Context manager for timing a code block.
        
        Usage:
            with profiler.measure("operation_name", block_size=512):
                # code to time
                pass
        """
        if not self.enabled:
            yield
            return
        
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            
            if name not in self.timings:
                self.timings[name] = TimingData(name)
            
            self.timings[name].add_timing(elapsed, **metadata)
    
    def profile_function(self, name: Optional[str] = None):
        """
        Decorator to profile a function.
        
        Usage:
            @profiler.profile_function("my_func")
            def my_func():
                pass
        """
        def decorator(func: Callable) -> Callable:
            func_name = name or func.__name__
            
            @wraps(func)
            def wrapper(*args, **kwargs):
                with self.measure(func_name):
                    return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def get_summary(self) -> Dict[str, Dict[str, Any]]:
        """
        Get summary of all timings.
        
        Returns:
            Dictionary of timing summaries
        """
        summary = {}
        for name, data in self.timings.items():
            summary[name] = {
                'total_time': data.total_time,
                'avg_time': data.avg_time,
                'min_time': data.min_time,
                'max_time': data.max_time,
                'call_count': data.call_count,
                'percentage': 0.0,  # Will be calculated
                'metadata': data.metadata
            }
        
        # Calculate percentages
        total_time = sum(d['total_time'] for d in summary.values())
        if total_time > 0:
            for data in summary.values():
                data['percentage'] = (data['total_time'] / total_time) * 100
        
        return summary
    
    def analyze_bottlenecks(self) -> List[Tuple[str, str, int]]:
        """
        Analyze profile results and generate actionable suggestions.
        
        Returns:
            List of (category, suggestion, priority) tuples
            Priority: 1=critical, 2=high, 3=medium, 4=low
        """
        suggestions = []
        summary = self.get_summary()
        
        # Sort by time consumption
        sorted_ops = sorted(
            summary.items(),
            key=lambda x: x[1]['total_time'],
            reverse=True
        )
        
        # Analyze top operations
        for name, data in sorted_ops[:5]:
            pct = data['percentage']
            avg_time = data['avg_time']
            metadata = data['metadata']
            
            # QR Generation bottleneck
            if 'qr' in name.lower() and pct > 40:
                current_block_size = metadata.get('block_size', self.context.get('block_size', 512))
                suggested_block_size = current_block_size * 2
                
                suggestions.append((
                    "QR Generation",
                    f"QR generation is {pct:.0f}% of total time.\n"
                    f"   Current: {data['call_count']:,} QR codes generated\n"
                    f"   Avg time: {avg_time*1000:.1f}ms per QR code\n"
                    f"   \n"
                    f"   Recommendations:\n"
                    f"   1. Increase --block-size from {current_block_size} to {suggested_block_size}\n"
                    f"      (reduces QR count by ~50%)\n"
                    f"   2. Consider multiprocessing with --parallel-qr\n"
                    f"   3. Enable QR caching for repeated codes",
                    1  # Critical priority
                ))
            
            elif 'qr' in name.lower() and avg_time > 0.1:
                suggestions.append((
                    "QR Complexity",
                    f"Individual QR codes are slow ({avg_time*1000:.0f}ms each).\n"
                    f"   This suggests very high QR density.\n"
                    f"   \n"
                    f"   Recommendations:\n"
                    f"   1. Increase --block-size to reduce data per QR\n"
                    f"   2. Check if --multiplier is too high\n"
                    f"   3. Consider file splitting for very large files",
                    2  # High priority
                ))
            
            # Encryption bottleneck
            if 'encrypt' in name.lower() and pct > 25:
                suggestions.append((
                    "Encryption",
                    f"Encryption is {pct:.0f}% of total time.\n"
                    f"   This is expected with Argon2id for security.\n"
                    f"   Current: ~{avg_time:.1f}s per file\n"
                    f"   \n"
                    f"   Note: Reducing encryption time reduces security.\n"
                    f"   If acceptable, consider:\n"
                    f"   1. Reduce Argon2 memory_cost (currently 46 MiB)\n"
                    f"   2. Reduce iterations (currently 2)\n"
                    f"   \n"
                    f"   ⚠️  Only do this for non-sensitive data!",
                    4  # Low priority - security trade-off
                ))
            
            # Fountain encoding bottleneck
            if 'droplet' in name.lower() and pct > 20:
                current_mult = self.context.get('multiplier', 1.85)
                suggested_mult = max(1.2, current_mult - 0.3)
                
                suggestions.append((
                    "Fountain Encoding",
                    f"Fountain droplet generation is {pct:.0f}% of time.\n"
                    f"   Droplets: {data['call_count']:,}\n"
                    f"   Avg: {avg_time*1000:.2f}ms per droplet\n"
                    f"   \n"
                    f"   Recommendations:\n"
                    f"   1. Reduce --multiplier from {current_mult:.2f} to {suggested_mult:.2f}\n"
                    f"      (trade-off: slightly higher decode failure risk)\n"
                    f"   2. Use numpy for XOR operations (10x faster)\n"
                    f"   3. Consider pre-computing droplet seeds",
                    2  # High priority
                ))
            
            # GIF saving bottleneck
            if 'gif' in name.lower() and 'save' in name.lower() and pct > 15:
                suggestions.append((
                    "GIF Saving",
                    f"GIF saving is {pct:.0f}% of time ({avg_time:.1f}s).\n"
                    f"   \n"
                    f"   Recommendations:\n"
                    f"   1. Use lower frame rate if acceptable\n"
                    f"   2. Reduce --frame-ms (current: {self.context.get('frame_ms', 280)}ms)\n"
                    f"   3. Consider optimizing GIF compression settings\n"
                    f"   4. Use pillow-simd for faster image operations",
                    3  # Medium priority
                ))
            
            # Webcam frame processing
            if 'process_frame' in name.lower() and avg_time > 0.05:
                suggestions.append((
                    "Webcam Processing",
                    f"Frame processing is slow ({avg_time*1000:.0f}ms per frame).\n"
                    f"   This may cause frame drops.\n"
                    f"   \n"
                    f"   Recommendations:\n"
                    f"   1. Increase --skip-frames (process every Nth frame)\n"
                    f"   2. Disable aggressive mode if not needed\n"
                    f"   3. Reduce camera resolution\n"
                    f"   4. Use faster QR detection algorithm",
                    2  # High priority for real-time
                ))
            
            # Compression bottleneck
            if 'compress' in name.lower() and pct > 15:
                suggestions.append((
                    "Compression",
                    f"Compression is {pct:.0f}% of time.\n"
                    f"   \n"
                    f"   Recommendations:\n"
                    f"   1. Reduce zlib compression level from 9 to 6\n"
                    f"      (trade-off: slightly larger files)\n"
                    f"   2. Pre-compress files with fast algorithms\n"
                    f"   3. Skip compression for already-compressed files (jpg, mp4, etc.)",
                    3  # Medium priority
                ))
        
        # General recommendations if no specific bottlenecks
        if not suggestions:
            total_time = sum(d['total_time'] for d in summary.values())
            suggestions.append((
                "General",
                f"Performance looks good! Total time: {total_time:.1f}s\n"
                f"   No obvious bottlenecks detected.\n"
                f"   \n"
                f"   For even better performance:\n"
                f"   1. Profile with --detailed-profile for line-by-line analysis\n"
                f"   2. Consider batch processing for multiple files\n"
                f"   3. Enable multiprocessing if available",
                4  # Low priority
            ))
        
        # Sort by priority
        suggestions.sort(key=lambda x: x[2])
        return suggestions
    
    def print_summary(self, top_n: int = 20, show_suggestions: bool = True):
        """
        Print formatted timing summary with suggestions.
        
        Args:
            top_n: Show top N slowest operations
            show_suggestions: Show optimization suggestions
        """
        from colorama import Fore, Style, init
        init()
        
        summary = self.get_summary()
        sorted_ops = sorted(
            summary.items(),
            key=lambda x: x[1]['total_time'],
            reverse=True
        )[:top_n]
        
        print(f"\n{Fore.CYAN}{'='*80}")
        print("Performance Profile Summary")
        print(f"{'='*80}{Style.RESET_ALL}\n")
        
        print(f"{'Operation':<30} {'Calls':>8} {'Total':>10} {'Avg':>10} {'Min':>10} {'Max':>10} {'%':>6}")
        print(f"{'-'*30} {'-'*8} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*6}")
        
        for name, data in sorted_ops:
            color = Fore.RED if data['percentage'] > 30 else Fore.YELLOW if data['percentage'] > 10 else Fore.GREEN
            
            print(f"{name:<30} "
                  f"{data['call_count']:>8,} "
                  f"{data['total_time']:>9.3f}s "
                  f"{data['avg_time']:>9.3f}s "
                  f"{data['min_time']:>9.3f}s "
                  f"{data['max_time']:>9.3f}s "
                  f"{color}{data['percentage']:>5.1f}%{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        
        # Show suggestions
        if show_suggestions:
            suggestions = self.analyze_bottlenecks()
            
            if suggestions:
                print(f"{Fore.YELLOW}💡 Optimization Suggestions:{Style.RESET_ALL}\n")
                
                priority_labels = {1: "🔴 CRITICAL", 2: "🟠 HIGH", 3: "🟡 MEDIUM", 4: "🟢 LOW"}
                
                for category, suggestion, priority in suggestions:
                    label = priority_labels.get(priority, "")
                    print(f"{Fore.CYAN}[{category}] {label}{Style.RESET_ALL}")
                    print(suggestion)
                    print()
    
    def compare_with(self, other_profile: 'Profiler', operation: str) -> None:
        """
        Compare this profile with another (before/after optimization).
        
        Args:
            other_profile: Profile to compare against
            operation: Operation name to compare
        """
        from colorama import Fore, Style
        
        if operation not in self.timings or operation not in other_profile.timings:
            print(f"Operation '{operation}' not found in both profiles")
            return
        
        before = other_profile.timings[operation]
        after = self.timings[operation]
        
        time_change = ((after.avg_time - before.avg_time) / before.avg_time) * 100
        speedup = before.avg_time / after.avg_time if after.avg_time > 0 else 0
        
        print(f"\n{Fore.CYAN}Comparison: {operation}{Style.RESET_ALL}\n")
        print(f"  Before: {before.avg_time*1000:.2f}ms avg ({before.call_count:,} calls)")
        print(f"  After:  {after.avg_time*1000:.2f}ms avg ({after.call_count:,} calls)")
        print()
        
        if time_change < 0:
            print(f"  {Fore.GREEN}✓ Improvement: {abs(time_change):.1f}% faster ({speedup:.2f}x speedup){Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}✗ Regression: {time_change:.1f}% slower ({1/speedup:.2f}x slowdown){Style.RESET_ALL}")
    
    def save_profile(self, filename: str):
        """
        Save profile data to JSON file.
        
        Args:
            filename: Output filename
        """
        import json
        
        summary = self.get_summary()
        
        # Add suggestions to output
        suggestions = self.analyze_bottlenecks()
        summary['_suggestions'] = [
            {'category': cat, 'suggestion': sug, 'priority': pri}
            for cat, sug, pri in suggestions
        ]
        summary['_context'] = self.context
        
        with open(filename, 'w') as f:
            json.dump(summary, f, indent=2)
    
    def reset(self):
        """Clear all timing data."""
        self.timings.clear()
        self.context.clear()


class DetailedProfiler:
    """
    Full cProfile-based profiler for detailed analysis.
    """
    
    def __init__(self):
        self.profiler = cProfile.Profile()
        self.enabled = False
    
    def start(self):
        """Start profiling."""
        self.enabled = True
        self.profiler.enable()
    
    def stop(self):
        """Stop profiling."""
        self.profiler.disable()
        self.enabled = False
    
    @contextmanager
    def profile(self):
        """Context manager for profiling a block."""
        self.start()
        try:
            yield
        finally:
            self.stop()
    
    def print_stats(self, top_n: int = 30, sort_by: str = 'cumulative'):
        """
        Print detailed profile statistics.
        
        Args:
            top_n: Number of functions to show
            sort_by: Sort key (time, cumulative, calls, etc.)
        """
        s = io.StringIO()
        ps = pstats.Stats(self.profiler, stream=s).sort_stats(sort_by)
        ps.print_stats(top_n)
        print(s.getvalue())
    
    def save_stats(self, filename: str):
        """Save profile data to file."""
        self.profiler.dump_stats(filename)


# Global profiler instance
_global_profiler = Profiler()


def get_profiler() -> Profiler:
    """Get global profiler instance."""
    return _global_profiler


def measure(name: str, **metadata):
    """Shortcut for global profiler measure."""
    return _global_profiler.measure(name, **metadata)


def profile_function(name: Optional[str] = None):
    """Shortcut for global profiler function decorator."""
    return _global_profiler.profile_function(name)


# Example usage demonstration
if __name__ == "__main__":
    import sys
    import random
    from colorama import Fore, Style, init
    init()
    
    print(f"\n{Fore.CYAN}Profiling Demo - With Smart Analysis{Style.RESET_ALL}\n")
    
    # Create test profiler
    profiler = Profiler()
    profiler.set_context(block_size=512, multiplier=1.85, frame_ms=280)
    
    # Simulate QR generation bottleneck
    print(f"{Fore.YELLOW}Simulating QR generation bottleneck...{Style.RESET_ALL}\n")
    for i in range(500):
        with profiler.measure("create_qr_image", block_size=512):
            time.sleep(random.uniform(0.025, 0.035))
    
    # Simulate other operations
    with profiler.measure("encrypt"):
        time.sleep(0.5)
    
    for i in range(500):
        with profiler.measure("make_droplet"):
            time.sleep(random.uniform(0.003, 0.007))
    
    with profiler.measure("save_gif"):
        time.sleep(0.3)
    
    # Print summary with suggestions
    profiler.print_summary(show_suggestions=True)
    
    # Save profile to temp directory (avoid hardcoded /tmp)
    import tempfile
    from pathlib import Path

    temp_dir = Path(tempfile.gettempdir())
    profile_path = temp_dir / "meow_profile_with_suggestions.json"
    profiler.save_profile(profile_path)
    print(f"{Fore.GREEN}✓ Profile saved to {profile_path}{Style.RESET_ALL}\n")
