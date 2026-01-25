"""
🎲 Enhanced Entropy Collection

Grok's suggestion: "Use system entropy pools combined with user-supplied 
randomness (e.g., mouse movements or webcam noise) for salts/nonces."

This module provides:
1. System entropy (/dev/urandom + secrets module)
2. User-supplied entropy (keyboard timing, optional mouse/webcam)
3. Environmental entropy (system metrics, timing jitter)
4. Entropy mixing via HKDF

Security Properties:
- Multiple independent entropy sources
- Failure of one source doesn't compromise security
- HKDF mixing ensures uniform distribution
- Never worse than system entropy alone

Usage:
    from meow_decoder.entropy_boost import collect_enhanced_entropy
    
    # Collect entropy with user interaction
    salt = collect_enhanced_entropy(16, interactive=True)
    
    # Silent collection (system + environment only)
    nonce = collect_enhanced_entropy(12, interactive=False)
"""

import os
import sys
import time
import hashlib
import secrets
import platform
import struct
from typing import Optional, List
from pathlib import Path

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class EntropyPool:
    """
    Collects entropy from multiple sources and mixes them securely.
    
    Sources:
    1. System entropy (secrets.token_bytes)
    2. Timing entropy (high-precision timing jitter)
    3. Environment entropy (system state, PIDs, etc.)
    4. User entropy (keyboard timing if interactive)
    5. Hardware entropy (if available via /dev/hwrng)
    """
    
    def __init__(self):
        """Initialize entropy pool."""
        self.sources: List[bytes] = []
        self._start_time = time.time_ns()
    
    def add_system_entropy(self, length: int = 32):
        """Add entropy from system CSPRNG."""
        # Primary source: Python's secrets module (uses OS entropy)
        self.sources.append(secrets.token_bytes(length))
        
        # Secondary: os.urandom as backup
        self.sources.append(os.urandom(length))
    
    def add_timing_entropy(self, samples: int = 100):
        """
        Add entropy from timing jitter.
        
        Even on deterministic systems, nanosecond timing varies
        due to interrupts, cache misses, and CPU scheduling.
        """
        timings = []
        
        for _ in range(samples):
            # Capture nanosecond timing
            t1 = time.time_ns()
            
            # Do some work that varies in timing
            _ = hashlib.sha256(str(t1).encode()).digest()
            
            t2 = time.time_ns()
            timings.append(t2 - t1)
        
        # Pack timings as entropy
        timing_bytes = b''.join(struct.pack('>Q', t) for t in timings)
        
        # Hash to condense
        self.sources.append(hashlib.sha256(timing_bytes).digest())
    
    def add_environment_entropy(self):
        """
        Add entropy from environment state.
        
        These values are somewhat predictable but add to the mix.
        """
        env_data = []
        
        # Process info
        env_data.append(str(os.getpid()).encode())
        env_data.append(str(os.getppid()).encode())
        
        # Time info (nanoseconds)
        env_data.append(struct.pack('>Q', time.time_ns()))
        env_data.append(struct.pack('>Q', time.perf_counter_ns()))
        env_data.append(struct.pack('>Q', time.monotonic_ns()))
        
        # Platform info
        env_data.append(platform.node().encode())
        env_data.append(platform.machine().encode())
        
        # Python internal state
        env_data.append(str(id(self)).encode())
        env_data.append(str(hash(time.time())).encode())
        
        # Memory info (varies)
        try:
            import gc
            env_data.append(str(gc.get_count()).encode())
        except:
            pass
        
        # /proc info on Linux
        try:
            if Path('/proc/interrupts').exists():
                env_data.append(Path('/proc/interrupts').read_bytes()[:1024])
            if Path('/proc/stat').exists():
                env_data.append(Path('/proc/stat').read_bytes()[:1024])
        except:
            pass
        
        # Hash the environment data
        combined = b''.join(env_data)
        self.sources.append(hashlib.sha256(combined).digest())
    
    def add_user_entropy(self, prompt: str = "Type random characters and press Enter: "):
        """
        Add entropy from user keyboard input.
        
        Captures both the content and timing of keystrokes.
        """
        print(prompt, end='', flush=True)
        
        timings = []
        chars = []
        
        try:
            # Try to get raw keystroke timing
            import tty
            import termios
            
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            
            try:
                tty.setraw(fd)
                
                while True:
                    t1 = time.time_ns()
                    char = sys.stdin.read(1)
                    t2 = time.time_ns()
                    
                    if char in ('\r', '\n'):
                        break
                    
                    chars.append(char)
                    timings.append(t2 - t1)
                    
                    print('*', end='', flush=True)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                print()  # Newline after input
                
        except (ImportError, termios.error, AttributeError):
            # Fallback for Windows or non-TTY
            user_input = input()
            chars = list(user_input)
            timings = [time.time_ns()] * len(chars)
        
        # Combine characters and timings
        char_bytes = ''.join(chars).encode('utf-8')
        timing_bytes = b''.join(struct.pack('>Q', t) for t in timings)
        
        combined = hashlib.sha256(char_bytes + timing_bytes).digest()
        self.sources.append(combined)
    
    def add_hardware_entropy(self, length: int = 32):
        """
        Add entropy from hardware RNG if available.
        
        On Linux, /dev/hwrng provides direct hardware entropy.
        """
        hwrng_path = Path('/dev/hwrng')
        
        if hwrng_path.exists():
            try:
                with open(hwrng_path, 'rb') as f:
                    hw_bytes = f.read(length)
                    if len(hw_bytes) == length:
                        self.sources.append(hw_bytes)
                        return True
            except (PermissionError, IOError):
                pass
        
        return False
    
    def add_webcam_noise(self, frames: int = 5):
        """
        Add entropy from webcam noise (optional, requires opencv).
        
        Camera sensors have inherent thermal noise that provides
        true random data even in darkness.
        """
        try:
            import cv2
            import numpy as np
            
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                return False
            
            frame_data = []
            
            for _ in range(frames):
                ret, frame = cap.read()
                if ret:
                    # Extract noise from low bits
                    noise = (frame & 0x0F).flatten()
                    frame_data.append(noise.tobytes()[:256])
            
            cap.release()
            
            if frame_data:
                combined = b''.join(frame_data)
                self.sources.append(hashlib.sha256(combined).digest())
                return True
                
        except (ImportError, Exception):
            pass
        
        return False
    
    def mix_entropy(self, output_length: int) -> bytes:
        """
        Mix all collected entropy sources using HKDF.
        
        Args:
            output_length: Desired output length in bytes
            
        Returns:
            Cryptographically mixed entropy
            
        Security:
            HKDF ensures uniform distribution.
            Even if some sources are weak, strong sources dominate.
        """
        if not self.sources:
            raise ValueError("No entropy sources collected")
        
        # Concatenate all sources
        combined = b''.join(self.sources)
        
        # Add final timing
        combined += struct.pack('>Q', time.time_ns())
        
        # Use HKDF to extract and expand
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=output_length,
            salt=secrets.token_bytes(32),  # Fresh salt
            info=b"meow_entropy_boost_v1"
        )
        
        return hkdf.derive(combined)
    
    def get_source_count(self) -> int:
        """Return number of entropy sources collected."""
        return len(self.sources)


def collect_enhanced_entropy(
    length: int,
    interactive: bool = False,
    use_webcam: bool = False,
    verbose: bool = False
) -> bytes:
    """
    Collect enhanced entropy from multiple sources.
    
    Args:
        length: Desired output length in bytes
        interactive: If True, prompt user for keyboard entropy
        use_webcam: If True, attempt to collect webcam noise
        verbose: If True, print collection progress
        
    Returns:
        Cryptographically strong random bytes
        
    Security:
        Always includes system entropy (secrets.token_bytes).
        Additional sources add defense-in-depth.
        Output is at least as strong as system entropy alone.
    """
    pool = EntropyPool()
    
    # Always collect system entropy (primary source)
    if verbose:
        print("🎲 Collecting system entropy...")
    pool.add_system_entropy(max(32, length))
    
    # Always collect timing entropy
    if verbose:
        print("⏱️  Collecting timing entropy...")
    pool.add_timing_entropy(100)
    
    # Always collect environment entropy
    if verbose:
        print("🌍 Collecting environment entropy...")
    pool.add_environment_entropy()
    
    # Try hardware entropy
    if verbose:
        print("🔌 Checking hardware entropy...")
    if pool.add_hardware_entropy(32):
        if verbose:
            print("   ✅ Hardware RNG available")
    else:
        if verbose:
            print("   ⚠️  Hardware RNG not available")
    
    # Optional: User keyboard entropy
    if interactive:
        if verbose:
            print("\n👆 User entropy collection:")
        pool.add_user_entropy("   Type some random characters and press Enter: ")
        if verbose:
            print("   ✅ User entropy collected")
    
    # Optional: Webcam noise
    if use_webcam:
        if verbose:
            print("📷 Collecting webcam noise...")
        if pool.add_webcam_noise(5):
            if verbose:
                print("   ✅ Webcam entropy collected")
        else:
            if verbose:
                print("   ⚠️  Webcam not available")
    
    # Mix all sources
    if verbose:
        print(f"\n🔀 Mixing {pool.get_source_count()} entropy sources...")
    
    result = pool.mix_entropy(length)
    
    if verbose:
        print(f"✅ Generated {length} bytes of enhanced entropy")
    
    return result


def generate_enhanced_salt(interactive: bool = False) -> bytes:
    """Generate 16-byte salt with enhanced entropy."""
    return collect_enhanced_entropy(16, interactive=interactive)


def generate_enhanced_nonce(interactive: bool = False) -> bytes:
    """Generate 12-byte nonce with enhanced entropy."""
    return collect_enhanced_entropy(12, interactive=interactive)


# Self-test
if __name__ == "__main__":
    print("🎲 Enhanced Entropy Collection Self-Test")
    print("=" * 60)
    
    # Test 1: Basic collection
    print("\n1. Testing basic entropy collection...")
    entropy1 = collect_enhanced_entropy(32, interactive=False, verbose=True)
    print(f"   Result: {entropy1.hex()[:32]}...")
    
    # Test 2: Verify randomness
    print("\n2. Testing randomness...")
    samples = [collect_enhanced_entropy(32, interactive=False) for _ in range(10)]
    unique = len(set(samples))
    assert unique == 10, "Entropy should be unique each time"
    print(f"   ✅ All {unique} samples are unique")
    
    # Test 3: Length verification
    print("\n3. Testing output lengths...")
    for length in [12, 16, 32, 64]:
        result = collect_enhanced_entropy(length, interactive=False)
        assert len(result) == length
        print(f"   ✅ Length {length}: OK")
    
    # Test 4: Entropy quality (basic check)
    print("\n4. Testing entropy quality...")
    sample = collect_enhanced_entropy(1000, interactive=False)
    
    # Check byte distribution
    from collections import Counter
    counts = Counter(sample)
    
    # Should have good spread (most bytes should appear)
    unique_bytes = len(counts)
    print(f"   Unique bytes in 1000: {unique_bytes}/256")
    
    if unique_bytes > 200:
        print("   ✅ Good byte distribution")
    else:
        print("   ⚠️  Distribution could be better (but still secure)")
    
    print("\n" + "=" * 60)
    print("🎉 Enhanced entropy collection working!")
    print("\n💡 For maximum entropy, use interactive mode:")
    print("   entropy = collect_enhanced_entropy(32, interactive=True)")
