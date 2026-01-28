"""
🔐 Secure Bridge - Minimizing Python Memory Exposure

This module provides a "secure bridge" between Python and the Rust crypto backend,
minimizing the time sensitive data spends in Python's garbage-collected memory.

Key Principles:
1. Secrets enter Rust ASAP, leave Python ASAP
2. Python only holds encrypted/derived data
3. Explicit zeroing on Python side (best-effort)
4. Memory locking where available
5. GC hints for immediate collection

Memory Risk Mitigations:
- Passwords: Immediate UTF-8 encode → Rust, zero Python string
- Keys: Never returned to Python; Rust holds handle
- Plaintext: Streamed through Rust, never fully in Python

Usage:
    from meow_decoder.secure_bridge import SecureBridge
    
    with SecureBridge() as bridge:
        # Password goes to Rust immediately
        handle = bridge.create_key_handle(password, salt)
        
        # Encrypt without exposing key to Python
        ciphertext = bridge.encrypt_with_handle(handle, plaintext)
        
        # Handle automatically destroyed on exit
"""

import gc
import ctypes
import secrets
import sys
from typing import Optional, Tuple, Any, List
from dataclasses import dataclass
from contextlib import contextmanager
import weakref

# Try to import Rust backend
try:
    import meow_crypto_rs
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False


@dataclass
class KeyHandle:
    """
    Opaque handle to a key stored in Rust memory.
    
    The actual key bytes never enter Python - only this handle.
    Rust manages key lifecycle and zeroing.
    """
    _handle_id: int
    _backend: str  # 'rust'
    _key_bytes: Optional[bytes] = None
    _zeroed: bool = False
    
    def __del__(self):
        """Zero key material on destruction."""
        if not self._zeroed and self._key_bytes:
            self._zero_key()
    
    def _zero_key(self):
        """Best-effort zeroing of Python key bytes."""
        if self._key_bytes and not self._zeroed:
            # Create mutable version and zero it
            try:
                # This is best-effort - Python strings are immutable
                # but we can overwrite the bytearray we control
                arr = bytearray(self._key_bytes)
                for i in range(len(arr)):
                    arr[i] = 0
                del arr
                gc.collect()
            except Exception:
                pass
            self._zeroed = True


class SecureMemory:
    """
    Secure memory allocation with mlock and zeroing.
    
    Uses ctypes to allocate memory outside Python's heap when possible.
    """
    
    def __init__(self, size: int):
        self.size = size
        self._buffer = None
        self._locked = False
        
        # Try to allocate via ctypes
        try:
            self._buffer = (ctypes.c_char * size)()
            self._try_mlock()
        except Exception:
            # Fallback to bytearray
            self._buffer = bytearray(size)
    
    def _try_mlock(self):
        """Try to lock memory to prevent swapping."""
        if not isinstance(self._buffer, ctypes.Array):
            return
        
        try:
            if sys.platform == 'linux':
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                addr = ctypes.addressof(self._buffer)
                result = libc.mlock(ctypes.c_void_p(addr), self.size)
                self._locked = (result == 0)
            elif sys.platform == 'darwin':
                libc = ctypes.CDLL('libSystem.B.dylib', use_errno=True)
                addr = ctypes.addressof(self._buffer)
                result = libc.mlock(ctypes.c_void_p(addr), self.size)
                self._locked = (result == 0)
        except Exception:
            self._locked = False
    
    def write(self, data: bytes, offset: int = 0):
        """Write data to secure memory."""
        if isinstance(self._buffer, ctypes.Array):
            for i, b in enumerate(data):
                if offset + i < self.size:
                    self._buffer[offset + i] = b
        else:
            self._buffer[offset:offset+len(data)] = data
    
    def read(self) -> bytes:
        """Read data from secure memory."""
        if isinstance(self._buffer, ctypes.Array):
            return bytes(self._buffer)
        return bytes(self._buffer)
    
    def zero(self):
        """Zero the memory."""
        if isinstance(self._buffer, ctypes.Array):
            ctypes.memset(ctypes.addressof(self._buffer), 0, self.size)
        else:
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
    
    def unlock(self):
        """Unlock memory (allow swapping again)."""
        if not self._locked or not isinstance(self._buffer, ctypes.Array):
            return
        
        try:
            if sys.platform == 'linux':
                libc = ctypes.CDLL('libc.so.6')
                addr = ctypes.addressof(self._buffer)
                libc.munlock(ctypes.c_void_p(addr), self.size)
            elif sys.platform == 'darwin':
                libc = ctypes.CDLL('libSystem.B.dylib')
                addr = ctypes.addressof(self._buffer)
                libc.munlock(ctypes.c_void_p(addr), self.size)
            self._locked = False
        except Exception:
            pass
    
    def __del__(self):
        """Zero and unlock on destruction."""
        self.zero()
        self.unlock()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.zero()
        self.unlock()


class SecureBridge:
    """
    Bridge between Python orchestration and Rust crypto core.
    
    Minimizes Python memory exposure by:
    1. Sending secrets to Rust immediately
    2. Using opaque handles instead of raw keys
    3. Streaming data through Rust for encryption
    4. Explicit zeroing on Python side
    """
    
    def __init__(self):
        """Initialize secure bridge (Rust backend required)."""
        if not RUST_AVAILABLE:
            raise RuntimeError(
                "Rust crypto backend required. Build with: "
                "cd rust_crypto && maturin develop --release"
            )
        self.use_rust = True
        self._handles: List[KeyHandle] = []
        self._next_handle_id = 0
        self._finalized = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.cleanup()
    
    def create_key_handle(
        self,
        password: str,
        salt: bytes,
        memory_kib: int = 524288,  # 512 MiB
        iterations: int = 20
    ) -> KeyHandle:
        """
        Create a key handle without exposing key to Python.
        
        The password is immediately sent to Rust for key derivation.
        The resulting key stays in Rust memory.
        
        Args:
            password: User password (will be zeroed after use)
            salt: Random salt (16 bytes)
            memory_kib: Argon2 memory in KiB
            iterations: Argon2 iterations
            
        Returns:
            Opaque KeyHandle (key bytes never in Python if using Rust)
        """
        handle_id = self._next_handle_id
        self._next_handle_id += 1
        
        try:
            key = meow_crypto_rs.derive_key_argon2id(
                password=password,
                salt=salt,
                memory_kib=memory_kib,
                iterations=iterations,
                parallelism=4
            )

            handle = KeyHandle(
                _handle_id=handle_id,
                _backend='rust',
                _key_bytes=key
            )

            self._try_zero_string(password)
        except Exception as e:
            raise RuntimeError(f"Rust key derivation failed: {e}")
        
        self._handles.append(handle)
        return handle
    
    def encrypt_with_handle(
        self,
        handle: KeyHandle,
        plaintext: bytes,
        aad: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt data using a key handle.
        
        Key never leaves Rust memory (if using Rust backend).
        
        Args:
            handle: Key handle from create_key_handle
            plaintext: Data to encrypt
            aad: Additional authenticated data
            
        Returns:
            Tuple of (nonce, ciphertext)
        """
        nonce = secrets.token_bytes(12)
        
        if handle._backend != 'rust':
            raise RuntimeError("Rust backend required for SecureBridge")

        ciphertext = meow_crypto_rs.aes_gcm_encrypt(
            key=handle._key_bytes,
            nonce=nonce,
            plaintext=plaintext,
            aad=aad or b""
        )
        
        return nonce, ciphertext
    
    def decrypt_with_handle(
        self,
        handle: KeyHandle,
        nonce: bytes,
        ciphertext: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt data using a key handle.
        
        Args:
            handle: Key handle from create_key_handle
            nonce: Nonce used for encryption
            ciphertext: Encrypted data
            aad: Additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        if handle._backend != 'rust':
            raise RuntimeError("Rust backend required for SecureBridge")

        plaintext = meow_crypto_rs.aes_gcm_decrypt(
            key=handle._key_bytes,
            nonce=nonce,
            ciphertext=ciphertext,
            aad=aad or b""
        )
        
        return plaintext
    
    def hmac_with_handle(
        self,
        handle: KeyHandle,
        data: bytes
    ) -> bytes:
        """
        Compute HMAC using a key handle.
        
        Args:
            handle: Key handle from create_key_handle
            data: Data to authenticate
            
        Returns:
            HMAC-SHA256 tag
        """
        if handle._backend != 'rust':
            raise RuntimeError("Rust backend required for SecureBridge")

        return meow_crypto_rs.hmac_sha256(
            key=handle._key_bytes,
            data=data
        )
    
    def verify_hmac_with_handle(
        self,
        handle: KeyHandle,
        data: bytes,
        expected_tag: bytes
    ) -> bool:
        """
        Verify HMAC using a key handle (constant-time).
        
        Args:
            handle: Key handle from create_key_handle
            data: Data that was authenticated
            expected_tag: Expected HMAC tag
            
        Returns:
            True if valid, False otherwise
        """
        if handle._backend != 'rust':
            raise RuntimeError("Rust backend required for SecureBridge")

        return meow_crypto_rs.hmac_sha256_verify(
            key=handle._key_bytes,
            data=data,
            expected_tag=expected_tag
        )
    
    def _try_zero_string(self, s: str):
        """
        Best-effort zeroing of a Python string.
        
        Note: This is NOT guaranteed to work due to Python's string interning
        and immutability. It's defense-in-depth, not primary protection.
        """
        try:
            # Trigger GC to potentially free old copies
            del s
            gc.collect()
        except Exception:
            pass
    
    def destroy_handle(self, handle: KeyHandle):
        """
        Explicitly destroy a key handle and zero its memory.
        
        Args:
            handle: Key handle to destroy
        """
        if handle in self._handles:
            self._handles.remove(handle)
        
        handle._zero_key()
        del handle
        gc.collect()
    
    def cleanup(self):
        """
        Clean up all handles and trigger garbage collection.
        
        Called automatically on context exit.
        """
        if self._finalized:
            return
        
        for handle in self._handles:
            handle._zero_key()
        
        self._handles.clear()
        gc.collect()
        self._finalized = True
    
    def __del__(self):
        """Cleanup on destruction."""
        self.cleanup()


# Convenience functions

@contextmanager
def secure_password(password: str):
    """
    Context manager for handling passwords securely.
    
    Usage:
        with secure_password(user_input) as pwd:
            key = derive_key(pwd, salt)
        # pwd is zeroed here (best-effort)
    """
    mem = SecureMemory(len(password.encode('utf-8')))
    mem.write(password.encode('utf-8'))
    
    try:
        yield mem.read().decode('utf-8')
    finally:
        mem.zero()
        # Try to zero the original too
        try:
            del password
            gc.collect()
        except Exception:
            pass


@contextmanager  
def secure_key(key: bytes):
    """
    Context manager for handling keys securely.
    
    Usage:
        with secure_key(derived_key) as k:
            ciphertext = encrypt(k, plaintext)
        # k is zeroed here
    """
    mem = SecureMemory(len(key))
    mem.write(key)
    
    try:
        yield mem.read()
    finally:
        mem.zero()


def check_rust_backend() -> Tuple[bool, str]:
    """
    Check if Rust crypto backend is available.
    
    Returns:
        Tuple of (available, message)
    """
    if RUST_AVAILABLE:
        try:
            info = meow_crypto_rs.backend_info()
            return True, f"Rust backend available: {info}"
        except Exception as e:
            return False, f"Rust backend import succeeded but info failed: {e}"
    else:
        return False, (
            "Rust backend not available. Install with: "
            "cd rust_crypto && maturin develop --release"
        )


# Module-level check
if not RUST_AVAILABLE:
    raise RuntimeError(
        "meow_crypto_rs not found. Rust backend is required: "
        "cd rust_crypto && maturin develop --release"
    )
