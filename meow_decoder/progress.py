"""
Progress Bar Utilities for Meow Decoder CLI

Simple progress display for encoding/decoding operations.
Wraps tqdm with graceful fallback.
"""

import sys
from typing import Optional, Iterator, Iterable, Any

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


class ProgressBar:
    """
    Simple progress bar with graceful fallback.
    
    Uses tqdm if available, otherwise prints dots.
    """
    
    def __init__(
        self,
        total: int,
        desc: str = "",
        unit: str = "it",
        disable: bool = False
    ):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of iterations
            desc: Description to show
            unit: Unit name (e.g., "frames", "blocks")
            disable: If True, don't show progress
        """
        self.total = total
        self.desc = desc
        self.unit = unit
        self.disable = disable
        self.n = 0
        self._tqdm = None
        
        if HAS_TQDM and not disable:
            self._tqdm = tqdm(
                total=total,
                desc=desc,
                unit=unit,
                bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            )
        elif not disable:
            # Print initial description
            if desc:
                print(f"{desc}: ", end="", flush=True)
    
    def update(self, n: int = 1) -> None:
        """Update progress by n steps."""
        self.n += n
        
        if self._tqdm:
            self._tqdm.update(n)
        elif not self.disable:
            # Print dots for progress
            if self.n % max(1, self.total // 20) == 0:
                print(".", end="", flush=True)
    
    def set_description(self, desc: str) -> None:
        """Update description."""
        self.desc = desc
        if self._tqdm:
            self._tqdm.set_description(desc)
    
    def close(self) -> None:
        """Close the progress bar."""
        if self._tqdm:
            self._tqdm.close()
        elif not self.disable:
            print(" done")
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


def progress_iter(
    iterable: Iterable,
    desc: str = "",
    total: Optional[int] = None,
    unit: str = "it",
    disable: bool = False
) -> Iterator:
    """
    Wrap an iterable with a progress bar.
    
    Args:
        iterable: Iterable to wrap
        desc: Description
        total: Total count (auto-detected if possible)
        unit: Unit name
        disable: If True, no progress shown
        
    Yields:
        Items from iterable
    """
    if total is None and hasattr(iterable, '__len__'):
        total = len(iterable)
    
    if HAS_TQDM and not disable:
        yield from tqdm(
            iterable,
            desc=desc,
            total=total,
            unit=unit,
            bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        )
    elif not disable:
        if desc:
            print(f"{desc}: ", end="", flush=True)
        
        count = 0
        for item in iterable:
            yield item
            count += 1
            if total and count % max(1, total // 20) == 0:
                print(".", end="", flush=True)
        
        print(" done")
    else:
        yield from iterable


def spinner(message: str = "Processing") -> 'Spinner':
    """
    Create a simple spinner for indeterminate progress.
    
    Args:
        message: Message to display
        
    Returns:
        Spinner context manager
    """
    return Spinner(message)


class Spinner:
    """Simple spinner for indeterminate progress."""
    
    CHARS = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    
    def __init__(self, message: str = "Processing"):
        self.message = message
        self._idx = 0
        self._running = False
    
    def __enter__(self):
        self._running = True
        sys.stdout.write(f"{self.message}... ")
        sys.stdout.flush()
        return self
    
    def __exit__(self, *args):
        self._running = False
        sys.stdout.write("done\n")
        sys.stdout.flush()
    
    def tick(self) -> None:
        """Update spinner (call in loop if not using as context manager)."""
        if self._running:
            char = self.CHARS[self._idx % len(self.CHARS)]
            sys.stdout.write(f"\r{self.message}... {char}")
            sys.stdout.flush()
            self._idx += 1


# Convenience exports
__all__ = ['ProgressBar', 'progress_iter', 'spinner', 'Spinner', 'HAS_TQDM']
