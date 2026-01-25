"""
Secure Cleanup Module for Meow Decoder
Handles secure memory zeroing on process exit or signal interruption.

Security Properties:
- Registers atexit and signal handlers to zero sensitive memory
- Tracks all sensitive buffers for cleanup
- Best-effort zeroing even on SIGTERM/SIGINT

Usage:
    from meow_decoder.secure_cleanup import SecureCleanupManager, register_sensitive_buffer
    
    # Register sensitive data for cleanup
    key = derive_key(password, salt)
    register_sensitive_buffer(key)
    
    # Or use context manager
    with SecureCleanupManager() as cleanup:
        key = derive_key(password, salt)
        cleanup.register(key)
        # ... use key ...
    # key is zeroed here
"""

import atexit
import signal
import gc
import weakref
from typing import List, Optional, Set
from contextlib import contextmanager
import threading


# Global registry of sensitive buffers (weak references)
_sensitive_buffers: Set[int] = set()
_buffer_data: dict = {}  # id -> bytearray
_lock = threading.Lock()
_handlers_registered = False


def _zero_buffer(buf_id: int) -> None:
    """Zero a buffer by ID."""
    with _lock:
        if buf_id in _buffer_data:
            data = _buffer_data[buf_id]
            if isinstance(data, bytearray):
                for i in range(len(data)):
                    data[i] = 0
            elif isinstance(data, memoryview):
                try:
                    for i in range(len(data)):
                        data[i] = 0
                except (TypeError, ValueError):
                    pass  # Read-only memoryview
            _sensitive_buffers.discard(buf_id)
            del _buffer_data[buf_id]


def _cleanup_all() -> None:
    """Zero all registered sensitive buffers."""
    with _lock:
        buf_ids = list(_sensitive_buffers)
    
    for buf_id in buf_ids:
        _zero_buffer(buf_id)
    
    # Force garbage collection
    gc.collect()


def _signal_handler(signum: int, frame) -> None:
    """Signal handler for SIGTERM/SIGINT - cleanup then exit."""
    _cleanup_all()
    # Re-raise default handler
    signal.signal(signum, signal.SIG_DFL)
    signal.raise_signal(signum)


def _register_handlers() -> None:
    """Register atexit and signal handlers (once)."""
    global _handlers_registered
    
    if _handlers_registered:
        return
    
    with _lock:
        if _handlers_registered:
            return
        
        # Register atexit handler
        atexit.register(_cleanup_all)
        
        # Register signal handlers (Unix only)
        try:
            signal.signal(signal.SIGTERM, _signal_handler)
            signal.signal(signal.SIGINT, _signal_handler)
        except (ValueError, OSError):
            # Can't set signal handlers (e.g., not main thread)
            pass
        
        _handlers_registered = True


def register_sensitive_buffer(data: bytes) -> bytearray:
    """
    Register a sensitive buffer for secure cleanup.
    
    Args:
        data: Sensitive bytes data
        
    Returns:
        Mutable bytearray copy (original bytes cannot be zeroed)
        
    Note:
        The returned bytearray will be zeroed on process exit,
        SIGTERM, or SIGINT. Always use the returned bytearray
        instead of the original bytes.
    """
    _register_handlers()
    
    # Create mutable copy
    mutable = bytearray(data)
    buf_id = id(mutable)
    
    with _lock:
        _sensitive_buffers.add(buf_id)
        _buffer_data[buf_id] = mutable
    
    return mutable


def unregister_and_zero(data: bytearray) -> None:
    """
    Unregister and zero a sensitive buffer immediately.
    
    Args:
        data: Buffer previously registered with register_sensitive_buffer
    """
    buf_id = id(data)
    _zero_buffer(buf_id)


class SecureCleanupManager:
    """
    Context manager for secure memory cleanup.
    
    Example:
        with SecureCleanupManager() as cleanup:
            key = cleanup.register(derive_key(password, salt))
            # ... use key ...
        # key is zeroed here
    """
    
    def __init__(self):
        self._buffers: List[bytearray] = []
    
    def register(self, data: bytes) -> bytearray:
        """Register data for cleanup, returns mutable bytearray."""
        mutable = register_sensitive_buffer(data)
        self._buffers.append(mutable)
        return mutable
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Zero all registered buffers
        for buf in self._buffers:
            unregister_and_zero(buf)
        self._buffers.clear()
        return False  # Don't suppress exceptions


@contextmanager
def secure_password_context(password: str):
    """
    Context manager for secure password handling.
    
    Encodes password to bytes, registers for cleanup, yields bytearray.
    Zeros on exit.
    
    Example:
        with secure_password_context(password) as pwd_bytes:
            key = derive_from_bytes(pwd_bytes, salt)
    """
    pwd_bytes = register_sensitive_buffer(password.encode('utf-8'))
    try:
        yield pwd_bytes
    finally:
        unregister_and_zero(pwd_bytes)


# Self-test
if __name__ == "__main__":
    print("🧪 Testing Secure Cleanup Module")
    print("=" * 50)
    
    # Test 1: Register and zero
    print("\n1. Testing buffer registration...")
    secret = b"super_secret_password_123"
    mutable = register_sensitive_buffer(secret)
    print(f"   Registered: {len(mutable)} bytes")
    assert mutable == bytearray(secret)
    
    unregister_and_zero(mutable)
    assert all(b == 0 for b in mutable), "Buffer should be zeroed"
    print("   ✅ Buffer zeroed successfully")
    
    # Test 2: Context manager
    print("\n2. Testing SecureCleanupManager...")
    with SecureCleanupManager() as cleanup:
        key = cleanup.register(b"encryption_key_here")
        assert key == bytearray(b"encryption_key_here")
    assert all(b == 0 for b in key), "Key should be zeroed after context"
    print("   ✅ Context manager zeroed on exit")
    
    # Test 3: Password context
    print("\n3. Testing secure_password_context...")
    with secure_password_context("MySecretPassword") as pwd:
        assert pwd == bytearray(b"MySecretPassword")
    assert all(b == 0 for b in pwd), "Password should be zeroed"
    print("   ✅ Password zeroed after context")
    
    # Test 4: Verify handlers registered
    print("\n4. Checking handlers...")
    assert _handlers_registered, "Handlers should be registered"
    print("   ✅ atexit and signal handlers registered")
    
    print("\n" + "=" * 50)
    print("✅ All secure cleanup tests passed!")
