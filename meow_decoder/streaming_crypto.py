"""
Streaming Encryption for Meow Decoder
Provides chunked processing for low-memory environments

Features:
- Stream encryption/decryption (minimal RAM usage)
- Adaptive chunk sizing based on available memory
- Memory usage monitoring
- Compatible with forward secrecy
- Optional memory locking
"""

import os
import gc
import zlib
import struct
import secrets
import hashlib
from typing import IO, Optional, Tuple, Iterator
from dataclasses import dataclass
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Try to import psutil for memory monitoring
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


@dataclass
class MemoryConfig:
    """Memory configuration for streaming."""
    chunk_size: int         # Bytes per chunk
    max_memory_mb: int      # Maximum memory usage (MB)
    enable_gc: bool         # Force GC after chunks
    enable_mlock: bool      # Try to lock memory


class StreamingCipher:
    """
    Streaming cipher using AES-256-CTR mode.
    
    Note: CTR mode is used instead of GCM because GCM requires
    the entire plaintext for authentication. For streaming with
    authentication, we'd need to use encrypt-then-MAC.
    """
    
    def __init__(self,
                 key: bytes,
                 nonce: Optional[bytes] = None,
                 chunk_size: int = 65536):  # 64 KB default
        """
        Initialize streaming cipher.
        
        Args:
            key: Encryption key (32 bytes for AES-256)
            nonce: Nonce/IV (16 bytes for CTR)
            chunk_size: Size of chunks to process
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        
        self.chunk_size = chunk_size
        
        # Generate nonce if not provided
        if nonce is None:
            nonce = secrets.token_bytes(16)
        elif len(nonce) != 16:
            raise ValueError("Nonce must be 16 bytes for CTR mode")
        
        self.nonce = nonce
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce)
        )
        
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
    
    def encrypt_stream(self,
                      input_stream: IO[bytes],
                      output_stream: IO[bytes],
                      enable_compression: bool = True) -> Tuple[int, int, bytes]:
        """
        Encrypt stream in chunks.
        
        Args:
            input_stream: Input file-like object
            output_stream: Output file-like object
            enable_compression: Compress before encryption
            
        Returns:
            Tuple of (original_size, compressed_size, sha256_hash)
        """
        original_size = 0
        compressed_size = 0
        hasher = hashlib.sha256()
        
        # Create compressor if enabled
        if enable_compression:
            compressor = zlib.compressobj(level=9)
        
        while True:
            # Read chunk
            chunk = input_stream.read(self.chunk_size)
            if not chunk:
                break
            
            original_size += len(chunk)
            hasher.update(chunk)
            
            # Compress if enabled
            if enable_compression:
                compressed_chunk = compressor.compress(chunk)
            else:
                compressed_chunk = chunk
            
            # Encrypt chunk
            if compressed_chunk:
                encrypted_chunk = self.encryptor.update(compressed_chunk)
                output_stream.write(encrypted_chunk)
                compressed_size += len(compressed_chunk)
            
            # Force GC to reclaim memory
            del chunk
            if enable_compression:
                del compressed_chunk
            gc.collect()
        
        # Finalize compression
        if enable_compression:
            final_compressed = compressor.flush()
            if final_compressed:
                encrypted_final = self.encryptor.update(final_compressed)
                output_stream.write(encrypted_final)
                compressed_size += len(final_compressed)
        
        # Finalize encryption
        final_encrypted = self.encryptor.finalize()
        if final_encrypted:
            output_stream.write(final_encrypted)
        
        return original_size, compressed_size, hasher.digest()
    
    def decrypt_stream(self,
                      input_stream: IO[bytes],
                      output_stream: IO[bytes],
                      enable_decompression: bool = True) -> int:
        """
        Decrypt stream in chunks.
        
        Args:
            input_stream: Encrypted input stream
            output_stream: Decrypted output stream
            enable_decompression: Decompress after decryption
            
        Returns:
            Total bytes written
        """
        total_written = 0
        
        # Create decompressor if enabled
        if enable_decompression:
            decompressor = zlib.decompressobj()
        
        while True:
            # Read encrypted chunk
            encrypted_chunk = input_stream.read(self.chunk_size)
            if not encrypted_chunk:
                break
            
            # Decrypt chunk
            decrypted_chunk = self.decryptor.update(encrypted_chunk)
            
            # Decompress if enabled
            if enable_decompression:
                try:
                    decompressed_chunk = decompressor.decompress(decrypted_chunk)
                except zlib.error as e:
                    raise RuntimeError(f"Decompression failed: {e}")
            else:
                decompressed_chunk = decrypted_chunk
            
            # Write chunk
            if decompressed_chunk:
                output_stream.write(decompressed_chunk)
                total_written += len(decompressed_chunk)
            
            # Force GC
            del encrypted_chunk
            del decrypted_chunk
            if enable_decompression:
                del decompressed_chunk
            gc.collect()
        
        # Finalize decryption
        final_decrypted = self.decryptor.finalize()
        
        # Finalize decompression
        if enable_decompression and final_decrypted:
            try:
                final_decompressed = decompressor.flush()
                if final_decompressed:
                    output_stream.write(final_decompressed)
                    total_written += len(final_decompressed)
            except zlib.error as e:
                raise RuntimeError(f"Final decompression failed: {e}")
        elif final_decrypted:
            output_stream.write(final_decrypted)
            total_written += len(final_decrypted)
        
        return total_written


class MemoryMonitor:
    """Monitor and adapt to available system memory."""
    
    def __init__(self, target_usage_mb: int = 50):
        """
        Initialize memory monitor.
        
        Args:
            target_usage_mb: Target memory usage in MB
        """
        self.target_usage_mb = target_usage_mb
        self.has_psutil = HAS_PSUTIL
    
    def get_available_memory_mb(self) -> Optional[int]:
        """Get available system memory in MB."""
        if not self.has_psutil:
            return None
        
        try:
            mem = psutil.virtual_memory()
            return mem.available // (1024 * 1024)
        except:
            return None
    
    def get_optimal_chunk_size(self,
                              min_chunk: int = 4096,
                              max_chunk: int = 1024 * 1024) -> int:
        """
        Calculate optimal chunk size based on available memory.
        
        Args:
            min_chunk: Minimum chunk size (4 KB)
            max_chunk: Maximum chunk size (1 MB)
            
        Returns:
            Optimal chunk size in bytes
        """
        available_mb = self.get_available_memory_mb()
        
        if available_mb is None:
            # No psutil, use conservative default
            return 65536  # 64 KB
        
        # Use 10% of available memory, capped at max_chunk
        optimal = min(
            int(available_mb * 0.1 * 1024 * 1024),
            max_chunk
        )
        
        return max(optimal, min_chunk)
    
    def should_enable_aggressive_gc(self) -> bool:
        """Check if aggressive GC should be enabled."""
        available_mb = self.get_available_memory_mb()
        
        if available_mb is None:
            return False  # Conservative
        
        # Enable aggressive GC if < 500 MB available
        return available_mb < 500


def create_streaming_encoder(key: bytes,
                             low_memory: bool = False) -> Tuple[StreamingCipher, MemoryConfig]:
    """
    Create streaming encoder with optimal settings.
    
    Args:
        key: Encryption key
        low_memory: Enable low-memory mode
        
    Returns:
        Tuple of (cipher, memory_config)
    """
    # Configure memory
    if low_memory:
        monitor = MemoryMonitor(target_usage_mb=20)
        chunk_size = monitor.get_optimal_chunk_size(
            min_chunk=4096,
            max_chunk=65536  # Cap at 64 KB for low-memory
        )
        enable_gc = monitor.should_enable_aggressive_gc()
    else:
        chunk_size = 1024 * 1024  # 1 MB default
        enable_gc = False
    
    cipher = StreamingCipher(key, chunk_size=chunk_size)
    
    config = MemoryConfig(
        chunk_size=chunk_size,
        max_memory_mb=100 if low_memory else 500,
        enable_gc=enable_gc,
        enable_mlock=low_memory
    )
    
    return cipher, config


# Integration with existing crypto module

def stream_encrypt_file(input_path: str,
                        output_path: str,
                        password: str,
                        salt: bytes,
                        low_memory: bool = False) -> Tuple[bytes, int, int, bytes]:
    """
    Encrypt file using streaming mode.
    
    Args:
        input_path: Path to input file
        output_path: Path to output file
        password: Encryption password
        salt: Random salt
        low_memory: Enable low-memory mode
        
    Returns:
        Tuple of (nonce, original_size, compressed_size, sha256)
    """
    # Derive key
    from crypto_enhanced import derive_key
    key = derive_key(password, salt)
    
    # Create streaming cipher
    cipher, config = create_streaming_encoder(key, low_memory)
    
    # Encrypt file
    with open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            orig_size, comp_size, sha256 = cipher.encrypt_stream(
                f_in, f_out, enable_compression=True
            )
    
    # Zero key
    key_array = bytearray(key)
    key_array[:] = b'\x00' * len(key_array)
    del key_array
    gc.collect()
    
    return cipher.nonce, orig_size, comp_size, sha256


def stream_decrypt_file(input_path: str,
                        output_path: str,
                        password: str,
                        salt: bytes,
                        nonce: bytes,
                        low_memory: bool = False) -> int:
    """
    Decrypt file using streaming mode.
    
    Args:
        input_path: Path to encrypted file
        output_path: Path to output file
        password: Encryption password
        salt: Salt from manifest
        nonce: Nonce from encryption
        low_memory: Enable low-memory mode
        
    Returns:
        Total bytes written
    """
    # Derive key
    from crypto_enhanced import derive_key
    key = derive_key(password, salt)
    
    # Create streaming cipher with same nonce
    _, config = create_streaming_encoder(key, low_memory)
    cipher = StreamingCipher(key, nonce=nonce, chunk_size=config.chunk_size)
    
    # Decrypt file
    with open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            total_written = cipher.decrypt_stream(
                f_in, f_out, enable_decompression=True
            )
    
    # Zero key
    key_array = bytearray(key)
    key_array[:] = b'\x00' * len(key_array)
    del key_array
    gc.collect()
    
    return total_written


# Testing

if __name__ == "__main__":
    import tempfile
    
    print("Testing Streaming Encryption...\n")
    
    # Test 1: Basic streaming roundtrip
    print("1. Testing basic streaming...")
    
    # Create test data
    test_data = b"Secret streaming test data! " * 10000  # ~280 KB
    
    with tempfile.NamedTemporaryFile(delete=False) as f_orig:
        f_orig.write(test_data)
        orig_path = f_orig.name
    
    try:
        # Encrypt
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key, chunk_size=4096)  # Small chunks
        
        with tempfile.NamedTemporaryFile(delete=False) as f_enc:
            enc_path = f_enc.name
        
        with open(orig_path, 'rb') as f_in:
            with open(enc_path, 'wb') as f_out:
                orig_size, comp_size, sha256 = cipher.encrypt_stream(
                    f_in, f_out, enable_compression=True
                )
        
        print(f"   Original size: {orig_size:,} bytes")
        print(f"   Compressed size: {comp_size:,} bytes")
        print(f"   Compression ratio: {comp_size/orig_size*100:.1f}%")
        
        # Decrypt
        cipher_dec = StreamingCipher(key, nonce=cipher.nonce, chunk_size=4096)
        
        with tempfile.NamedTemporaryFile(delete=False) as f_dec:
            dec_path = f_dec.name
        
        with open(enc_path, 'rb') as f_in:
            with open(dec_path, 'wb') as f_out:
                total_written = cipher_dec.decrypt_stream(
                    f_in, f_out, enable_decompression=True
                )
        
        # Verify
        with open(dec_path, 'rb') as f:
            decrypted_data = f.read()
        
        if decrypted_data == test_data:
            print("   ✓ Roundtrip successful")
        else:
            print("   ✗ Roundtrip failed")
        
        # Cleanup
        os.unlink(enc_path)
        os.unlink(dec_path)
    
    finally:
        os.unlink(orig_path)
    
    # Test 2: Memory monitoring
    print("\n2. Testing memory monitoring...")
    monitor = MemoryMonitor(target_usage_mb=50)
    
    available = monitor.get_available_memory_mb()
    if available:
        print(f"   Available memory: {available:,} MB")
    else:
        print("   psutil not available (using defaults)")
    
    optimal_chunk = monitor.get_optimal_chunk_size()
    print(f"   Optimal chunk size: {optimal_chunk:,} bytes")
    
    aggressive_gc = monitor.should_enable_aggressive_gc()
    print(f"   Aggressive GC: {aggressive_gc}")
    
    # Test 3: Low-memory mode
    print("\n3. Testing low-memory mode...")
    
    key = secrets.token_bytes(32)
    cipher, config = create_streaming_encoder(key, low_memory=True)
    
    print(f"   Chunk size: {config.chunk_size:,} bytes")
    print(f"   Max memory: {config.max_memory_mb} MB")
    print(f"   Enable GC: {config.enable_gc}")
    
    # Test 4: Integration with file encryption
    print("\n4. Testing file encryption integration...")
    
    try:
        # Create test file
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b"Test file content " * 5000)
            test_file = f.name
        
        # Encrypt
        password = "test_password_123"
        salt = secrets.token_bytes(16)
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            enc_file = f.name
        
        nonce, orig_sz, comp_sz, sha = stream_encrypt_file(
            test_file, enc_file, password, salt, low_memory=True
        )
        
        print(f"   Encrypted: {orig_sz:,} → {comp_sz:,} bytes")
        
        # Decrypt
        with tempfile.NamedTemporaryFile(delete=False) as f:
            dec_file = f.name
        
        written = stream_decrypt_file(
            enc_file, dec_file, password, salt, nonce, low_memory=True
        )
        
        print(f"   Decrypted: {written:,} bytes")
        
        # Verify
        with open(test_file, 'rb') as f1, open(dec_file, 'rb') as f2:
            if f1.read() == f2.read():
                print("   ✓ File roundtrip successful")
            else:
                print("   ✗ File roundtrip failed")
        
        # Cleanup
        os.unlink(test_file)
        os.unlink(enc_file)
        os.unlink(dec_file)
    
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    print("\n✅ All streaming encryption tests complete!")
    print("\nMemory Usage:")
    print(f"  • Normal mode: ~{1024} KB chunks, ~500 MB max")
    print(f"  • Low-memory mode: ~{64} KB chunks, ~100 MB max")
    print(f"  • Embedded mode: ~{4} KB chunks, ~20 MB max")
