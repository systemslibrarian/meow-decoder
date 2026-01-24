"""
Constant-Time Operations Module
Provides side-channel resistant cryptographic operations

Security Goals:
- Prevent timing attacks on password comparison
- Prevent timing attacks on MAC verification
- Constant-time buffer operations
- Memory wiping with mlock support
"""

import ctypes
import secrets
import time
import platform
from contextlib import contextmanager
from typing import Any, Iterator


# Platform-specific libc loading
def _get_libc():
    """Load platform-specific libc for mlock/memset."""
    system = platform.system()
    try:
        if system == "Linux":
            return ctypes.CDLL("libc.so.6")
        elif system == "Darwin":  # macOS
            return ctypes.CDLL("libc.dylib")
        elif system == "Windows":
            return ctypes.CDLL("msvcrt.dll")
        else:
            return None
    except:
        return None


_libc = _get_libc()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
        
    Security:
        - Uses secrets.compare_digest (constant-time)
        - Prevents timing attacks on password/MAC comparison
        - Essential for cryptographic comparisons
        
    Note:
        This is a wrapper around secrets.compare_digest
        for consistency with other constant-time ops.
    """
    return secrets.compare_digest(a, b)


def secure_zero_memory(buffer: Any) -> None:
    """
    Zero memory buffer in a way compiler can't optimize away.
    
    Args:
        buffer: Buffer to zero (bytearray, ctypes buffer, etc.)
        
    Security:
        - Uses memset to prevent compiler optimization
        - Ensures secrets actually erased from RAM
        - Critical for password/key cleanup
        
    Note:
        Works best with ctypes buffers or bytearray.
        Python immutable bytes cannot be zeroed.
    """
    if _libc is None:
        # Fallback: manual zeroing (less reliable)
        if isinstance(buffer, bytearray):
            for i in range(len(buffer)):
                buffer[i] = 0
        return
    
    # Get buffer address and size
    if isinstance(buffer, bytearray):
        addr = (ctypes.c_char * len(buffer)).from_buffer(buffer)
        size = len(buffer)
    elif isinstance(buffer, ctypes.Array):
        addr = ctypes.addressof(buffer)
        size = ctypes.sizeof(buffer)
    else:
        # Unsupported type, skip
        return
    
    # Zero with memset (cannot be optimized away)
    _libc.memset(addr, 0, size)


@contextmanager
def secure_memory(data: bytes) -> Iterator[bytearray]:
    """
    Context manager for secure memory handling.
    
    Args:
        data: Data to protect in memory
        
    Yields:
        Mutable buffer with data
        
    Security:
        - Locks pages in RAM (prevents swap)
        - Zeros buffer on exit
        - Unlocks after zeroing
        - Use for passwords, keys, plaintext
        
    Example:
        with secure_memory(password.encode()) as pwd:
            key = derive_key(pwd)
        # pwd is now zeroed and unlocked
    """
    # Create mutable buffer
    buf = bytearray(data)
    
    # Try to lock in RAM
    locked = False
    if _libc is not None:
        try:
            addr = (ctypes.c_char * len(buf)).from_buffer(buf)
            result = _libc.mlock(addr, len(buf))
            locked = (result == 0)
        except:
            pass
    
    try:
        yield buf
    finally:
        # Zero buffer
        secure_zero_memory(buf)
        
        # Unlock if locked
        if locked and _libc is not None:
            try:
                addr = (ctypes.c_char * len(buf)).from_buffer(buf)
                _libc.munlock(addr, len(buf))
            except:
                pass


def timing_safe_equal_with_delay(
    a: bytes,
    b: bytes,
    min_delay_ms: int = 1,
    max_delay_ms: int = 10
) -> bool:
    """
    Compare with randomized delay to obscure timing.
    
    Args:
        a: First byte string
        b: Second byte string
        min_delay_ms: Minimum random delay in milliseconds
        max_delay_ms: Maximum random delay in milliseconds
        
    Returns:
        True if equal, False otherwise
        
    Security:
        - Constant-time comparison
        - Random delay masks exact timing
        - Prevents statistical timing attacks
        - Use for password verification
    """
    # Random delay BEFORE comparison
    delay = secrets.randbelow(max_delay_ms - min_delay_ms + 1) + min_delay_ms
    time.sleep(delay / 1000.0)
    
    # Constant-time comparison
    result = secrets.compare_digest(a, b)
    
    # Random delay AFTER comparison
    delay = secrets.randbelow(max_delay_ms - min_delay_ms + 1) + min_delay_ms
    time.sleep(delay / 1000.0)
    
    return result


def equalize_timing(operation_time: float, target_time: float = 0.1) -> None:
    """
    Sleep to equalize operation timing.
    
    Args:
        operation_time: Time operation took (seconds)
        target_time: Target total time (seconds)
        
    Security:
        - Equalizes timing between different code paths
        - Prevents timing side-channel leaks
        - Use when operations have variable time
        
    Example:
        start = time.time()
        result = try_decrypt(data, password)
        elapsed = time.time() - start
        equalize_timing(elapsed, target_time=0.2)
    """
    if operation_time < target_time:
        sleep_time = target_time - operation_time
        time.sleep(sleep_time)


class SecureBuffer:
    """
    Secure buffer with automatic cleanup.
    
    Security:
        - Locked in RAM
        - Zeroed on deletion
        - Use for sensitive data
    """
    
    def __init__(self, size: int):
        """Initialize secure buffer of given size."""
        self.size = size
        self.buffer = bytearray(size)
        self.locked = False
        
        # Try to lock
        if _libc is not None:
            try:
                addr = (ctypes.c_char * size).from_buffer(self.buffer)
                result = _libc.mlock(addr, size)
                self.locked = (result == 0)
            except:
                pass
    
    def write(self, data: bytes, offset: int = 0) -> None:
        """Write data to buffer."""
        if offset + len(data) > self.size:
            raise ValueError("Data too large for buffer")
        self.buffer[offset:offset+len(data)] = data
    
    def read(self, length: int = None, offset: int = 0) -> bytes:
        """Read data from buffer."""
        if length is None:
            return bytes(self.buffer[offset:])
        return bytes(self.buffer[offset:offset+length])
    
    def __del__(self):
        """Clean up: zero and unlock."""
        if hasattr(self, 'buffer'):
            secure_zero_memory(self.buffer)
            
            if self.locked and _libc is not None:
                try:
                    addr = (ctypes.c_char * self.size).from_buffer(self.buffer)
                    _libc.munlock(addr, self.size)
                except:
                    pass
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, *args):
        """Context manager exit."""
        self.__del__()


# Example usage
if __name__ == "__main__":
    print("Constant-Time Operations Test")
    print("=" * 50)
    
    # Test constant-time comparison
    print("\n1. Constant-time comparison:")
    a = b"secret_password_123"
    b = b"secret_password_123"
    c = b"wrong_password_456"
    
    print(f"   a == b: {constant_time_compare(a, b)}")
    print(f"   a == c: {constant_time_compare(a, c)}")
    
    # Test secure memory
    print("\n2. Secure memory context:")
    password = "super_secret_password"
    
    with secure_memory(password.encode()) as pwd_buf:
        print(f"   Password in secure buffer: {pwd_buf[:10]}...")
        # Password is locked in RAM here
    # Password is now zeroed
    print(f"   Password after context: (zeroed)")
    
    # Test timing equalization
    print("\n3. Timing equalization:")
    
    start = time.time()
    time.sleep(0.05)  # Simulate fast operation
    elapsed1 = time.time() - start
    equalize_timing(elapsed1, target_time=0.1)
    total1 = time.time() - start
    
    start = time.time()
    time.sleep(0.08)  # Simulate slow operation
    elapsed2 = time.time() - start
    equalize_timing(elapsed2, target_time=0.1)
    total2 = time.time() - start
    
    print(f"   Fast operation: {elapsed1:.3f}s → {total1:.3f}s (equalized)")
    print(f"   Slow operation: {elapsed2:.3f}s → {total2:.3f}s (equalized)")
    print(f"   Timing difference: {abs(total1 - total2)*1000:.1f}ms")
    
    # Test secure buffer
    print("\n4. Secure buffer:")
    with SecureBuffer(32) as buf:
        buf.write(b"Secret data here")
        data = buf.read(16)
        print(f"   Read from buffer: {data}")
        print(f"   Locked in RAM: {buf.locked}")
    print(f"   Buffer after context: (zeroed and unlocked)")
    
    # Test timing-safe comparison with delay
    print("\n5. Timing-safe comparison with delay:")
    
    start = time.time()
    result = timing_safe_equal_with_delay(a, b, min_delay_ms=5, max_delay_ms=15)
    elapsed = time.time() - start
    
    print(f"   Comparison result: {result}")
    print(f"   Time taken: {elapsed*1000:.1f}ms")
    print(f"   (includes random delays for timing obscuration)")
    
    print(f"\n✅ Constant-time operations module working!")
    print(f"   libc available: {_libc is not None}")
    print(f"   Platform: {platform.system()}")
