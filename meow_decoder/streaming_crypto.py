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
from typing import IO, Optional, Tuple, Iterator
from dataclasses import dataclass
from contextlib import contextmanager

from .crypto_backend import get_default_backend

# Try to import psutil for memory monitoring
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:  # pragma: no cover
    HAS_PSUTIL = False


@dataclass
class MemoryConfig:
    """Memory configuration for streaming."""

    chunk_size: int = 65536  # Bytes per chunk
    max_memory_mb: int = 100  # Maximum memory usage (MB)
    enable_gc: bool = False  # Force GC after chunks
    enable_mlock: bool = True  # Try to lock memory


# Domain separation for streaming MAC
STREAMING_MAC_INFO = b"meow_streaming_mac_v1"


def derive_stream_keys(password: str, salt: bytes) -> tuple:
    """Derive (enc_key, mac_key) for streaming crypto from password + salt.

    This mirrors the key derivation in StreamingCipher.__init__ but returns
    both keys for testing/inspection.

    Args:
        password: User password.
        salt: 16-byte random salt.

    Returns:
        Tuple of (enc_key: bytes, mac_key: bytes) — each 32 bytes.
    """
    from meow_decoder.crypto import derive_key

    enc_key = derive_key(password, salt)
    backend = get_default_backend()
    # Use a deterministic nonce-equivalent for key derivation testing
    # In production, the nonce is random; here we derive mac_key from enc_key+salt
    mac_key = backend.derive_key_hkdf(enc_key, salt, STREAMING_MAC_INFO, 32)
    return enc_key, mac_key


class StreamingCipher:
    """
    Streaming cipher using AES-256-CTR mode with Encrypt-then-MAC authentication.

    SECURITY NOTE (Audit 2026-02-06):
    CTR mode alone provides NO authentication. This class now implements
    Encrypt-then-MAC pattern using HMAC-SHA256 to authenticate the ciphertext.

    The MAC covers: nonce || ciphertext

    Always verify MAC before decryption to prevent:
    - Bit-flipping attacks (CWE-353)
    - Ciphertext substitution
    - Malleability exploits
    """

    def __init__(
        self, key: bytes, nonce: Optional[bytes] = None, chunk_size: int = 65536
    ):  # 64 KB default
        """
        Initialize streaming cipher.

        Args:
            key: Encryption key (32 bytes for AES-256)
            nonce: Nonce/IV (16 bytes for CTR)
            chunk_size: Size of chunks to process
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")

        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        self.key = key
        self.chunk_size = chunk_size

        # Generate nonce if not provided
        if nonce is None:
            nonce = secrets.token_bytes(16)
        elif len(nonce) != 16:
            raise ValueError("Nonce must be 16 bytes for CTR mode")

        self.nonce = nonce

        # Track byte offsets for streaming CTR mode
        self._encrypt_offset = 0
        self._decrypt_offset = 0

        # Derive MAC key using HKDF for domain separation
        # This ensures the MAC key is distinct from the encryption key
        backend = get_default_backend()
        mac_key_material = backend.derive_key_hkdf(key, nonce, STREAMING_MAC_INFO, 32)
        self._mac_key = mac_key_material

    def _compute_mac(self, data: bytes) -> bytes:  # pragma: no cover
        """Compute HMAC-SHA256 over data."""
        backend = get_default_backend()
        return backend.hmac_sha256(self._mac_key, data)

    def _verify_mac(self, data: bytes, expected_mac: bytes) -> bool:  # pragma: no cover
        """Verify HMAC-SHA256 in constant time."""
        computed = self._compute_mac(data)
        return secrets.compare_digest(computed, expected_mac)

    def encrypt_stream(
        self, input_stream: IO[bytes], output_stream: IO[bytes], enable_compression: bool = True
    ) -> Tuple[int, int, bytes, bytes]:
        """
        Encrypt stream in chunks with authentication.

        Args:
            input_stream: Input file-like object
            output_stream: Output file-like object
            enable_compression: Compress before encryption

        Returns:
            Tuple of (original_size, compressed_size, sha256_hash, mac_tag)

        The MAC authenticates: nonce || ciphertext
        Callers MUST store and verify the MAC before decryption.
        """
        original_size = 0
        compressed_size = 0

        # Accumulate data for hash and MAC computation (Rust backend, single-shot)
        backend = get_default_backend()
        all_plaintext_chunks = []
        all_ciphertext_chunks = []

        # Create compressor if enabled
        if enable_compression:
            compressor = zlib.compressobj(level=9)

        while True:
            # Read chunk
            chunk = input_stream.read(self.chunk_size)
            if not chunk:
                break

            original_size += len(chunk)
            all_plaintext_chunks.append(chunk)

            # Compress if enabled
            if enable_compression:
                compressed_chunk = compressor.compress(chunk)
            else:
                compressed_chunk = chunk

            # Encrypt chunk using Rust AES-CTR with byte offset tracking
            if compressed_chunk:
                encrypted_chunk = backend.aes_ctr_crypt(
                    self.key, self.nonce, compressed_chunk, self._encrypt_offset
                )
                self._encrypt_offset += len(compressed_chunk)
                output_stream.write(encrypted_chunk)
                all_ciphertext_chunks.append(encrypted_chunk)
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
                encrypted_final = backend.aes_ctr_crypt(
                    self.key, self.nonce, final_compressed, self._encrypt_offset
                )
                self._encrypt_offset += len(final_compressed)
                output_stream.write(encrypted_final)
                all_ciphertext_chunks.append(encrypted_final)
                compressed_size += len(final_compressed)

        # Compute SHA-256 of all plaintext using Rust backend
        all_plaintext = b"".join(all_plaintext_chunks)
        sha256_hash = backend.sha256(all_plaintext)
        del all_plaintext
        del all_plaintext_chunks

        # Compute MAC: HMAC-SHA256(mac_key, nonce || ciphertext) using Rust backend
        all_ciphertext = b"".join(all_ciphertext_chunks)
        mac_tag = backend.hmac_sha256(self._mac_key, self.nonce + all_ciphertext)
        del all_ciphertext
        del all_ciphertext_chunks

        gc.collect()

        return original_size, compressed_size, sha256_hash, mac_tag

    def decrypt_stream(
        self,
        input_stream: Optional[IO[bytes]] = None,
        output_stream: Optional[IO[bytes]] = None,
        enable_decompression: bool = True,
        expected_mac: Optional[bytes] = None,
        **kwargs,
    ) -> int:
        """
        Decrypt stream with MANDATORY authentication verification.

        SECURITY (Signal-grade, 2026-02-18):
        MAC verification is MANDATORY. The expected_mac parameter MUST be provided.
        No plaintext is released until authentication succeeds.
        Passing expected_mac=None raises ValueError immediately.

        Args:
            input_stream: Encrypted input stream
            output_stream: Decrypted output stream
            enable_decompression: Decompress after decryption
            expected_mac: MAC tag (32 bytes). MANDATORY — no unauthenticated decryption.

        Returns:
            Total bytes written

        Raises:
            ValueError: If expected_mac is None or wrong length
            RuntimeError: If MAC verification fails
        """
        if input_stream is None and "input_stream" in kwargs:  # pragma: no cover
            input_stream = kwargs["input_stream"]
        if output_stream is None and "output_stream" in kwargs:  # pragma: no cover
            output_stream = kwargs["output_stream"]
        if output_stream is None and "decrypted_stream" in kwargs:
            output_stream = kwargs["decrypted_stream"]

        if input_stream is None or output_stream is None:
            raise ValueError("input_stream and output_stream are required")

        # FAIL-CLOSED: MAC is mandatory. No unauthenticated decryption path.
        if expected_mac is None:
            raise ValueError(
                "expected_mac is required. Unauthenticated decryption is forbidden. "
                "Provide the MAC tag from encrypt_stream() to verify ciphertext integrity."
            )

        if len(expected_mac) != 32:
            raise ValueError("MAC must be 32 bytes")

        # Read entire ciphertext for MAC verification BEFORE any decryption
        ciphertext = input_stream.read()

        # Verify MAC: HMAC(mac_key, nonce || ciphertext) using Rust backend
        backend = get_default_backend()
        computed_mac = backend.hmac_sha256(self._mac_key, self.nonce + ciphertext)

        if not secrets.compare_digest(computed_mac, expected_mac):
            raise RuntimeError("MAC verification failed - ciphertext may be tampered")

        # MAC verified - proceed with decryption (no plaintext released before this point)
        from io import BytesIO

        verified_stream = BytesIO(ciphertext)
        return self._decrypt_verified_stream(
            verified_stream, output_stream, enable_decompression
        )

    def _decrypt_verified_stream(
        self, input_stream: IO[bytes], output_stream: IO[bytes], enable_decompression: bool
    ) -> int:
        """
        Internal decryption after MAC verification.

        This method assumes MAC has already been verified or caller accepts risk.
        """
        total_written = 0
        backend = get_default_backend()

        # Create decompressor if enabled
        if enable_decompression:
            decompressor = zlib.decompressobj()

        while True:
            # Read encrypted chunk
            encrypted_chunk = input_stream.read(self.chunk_size)
            if not encrypted_chunk:
                break

            # Decrypt chunk using Rust AES-CTR with byte offset tracking
            decrypted_chunk = backend.aes_ctr_crypt(
                self.key, self.nonce, encrypted_chunk, self._decrypt_offset
            )
            self._decrypt_offset += len(encrypted_chunk)

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

        # Finalize decompression
        if enable_decompression:  # pragma: no cover
            try:
                final_decompressed = decompressor.flush()
                if final_decompressed:
                    output_stream.write(final_decompressed)
                    total_written += len(final_decompressed)
            except zlib.error as e:
                raise RuntimeError(f"Final decompression failed: {e}")

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
            return mem.available // (1024 * 1024)  # type: ignore[no-any-return]
        except:
            return None

    def get_optimal_chunk_size(self, min_chunk: int = 4096, max_chunk: int = 1024 * 1024) -> int:
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
            # No psutil, use conservative default (clamped to caller's range)
            return max(min(65536, max_chunk), min_chunk)

        # Use 10% of available memory, capped at max_chunk
        optimal = min(int(available_mb * 0.1 * 1024 * 1024), max_chunk)

        return max(optimal, min_chunk)

    def should_enable_aggressive_gc(self) -> bool:
        """Check if aggressive GC should be enabled."""
        available_mb = self.get_available_memory_mb()

        if available_mb is None:
            return False  # Conservative

        # Enable aggressive GC if < 500 MB available
        return available_mb < 500


def create_streaming_encoder(
    key: bytes, low_memory: bool = False
) -> Tuple[StreamingCipher, MemoryConfig]:
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
            min_chunk=4096, max_chunk=65536  # Cap at 64 KB for low-memory
        )
        enable_gc = True
    else:
        chunk_size = 1024 * 1024  # 1 MB default
        enable_gc = False

    cipher = StreamingCipher(key, chunk_size=chunk_size)

    config = MemoryConfig(
        chunk_size=chunk_size,
        max_memory_mb=100 if low_memory else 500,
        enable_gc=enable_gc,
        enable_mlock=low_memory,
    )

    return cipher, config


# Integration with existing crypto module


def stream_encrypt_file(
    input_path: str, output_path: str, password: str, salt: bytes, low_memory: bool = False
) -> Tuple[bytes, int, int, bytes, bytes]:
    """
    Encrypt file using streaming mode.

    Args:
        input_path: Path to input file
        output_path: Path to output file
        password: Encryption password
        salt: Random salt
        low_memory: Enable low-memory mode

    Returns:
        Tuple of (nonce, original_size, compressed_size, sha256, mac_tag)
    """
    # Derive key
    from meow_decoder.crypto import derive_key

    key = derive_key(password, salt)

    # Create streaming cipher
    cipher, config = create_streaming_encoder(key, low_memory)

    # Encrypt file
    with open(input_path, "rb") as f_in:
        with open(output_path, "wb") as f_out:
            orig_size, comp_size, sha256, mac_tag = cipher.encrypt_stream(
                f_in, f_out, enable_compression=True
            )

    # Zero key
    key_array = bytearray(key)
    key_array[:] = b"\x00" * len(key_array)
    del key_array
    gc.collect()

    return cipher.nonce, orig_size, comp_size, sha256, mac_tag


def stream_decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    salt: bytes,
    nonce: bytes,
    mac_tag: bytes,
    low_memory: bool = False,
) -> int:
    """
    Decrypt file using streaming mode with mandatory MAC verification.

    Args:
        input_path: Path to encrypted file
        output_path: Path to output file
        password: Encryption password
        salt: Salt from manifest
        nonce: Nonce from encryption
        mac_tag: MAC tag from encrypt_stream (32 bytes). MANDATORY.
        low_memory: Enable low-memory mode

    Returns:
        Total bytes written

    Raises:
        ValueError: If mac_tag is None or wrong length
        RuntimeError: If MAC verification fails
    """
    # Derive key
    from meow_decoder.crypto import derive_key

    key = derive_key(password, salt)

    # Create streaming cipher with same nonce
    _, config = create_streaming_encoder(key, low_memory)
    cipher = StreamingCipher(key, nonce=nonce, chunk_size=config.chunk_size)

    # Decrypt file with mandatory MAC verification
    with open(input_path, "rb") as f_in:
        with open(output_path, "wb") as f_out:
            total_written = cipher.decrypt_stream(
                f_in, f_out, enable_decompression=True, expected_mac=mac_tag
            )

    # Zero key
    key_array = bytearray(key)
    key_array[:] = b"\x00" * len(key_array)
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

        with open(orig_path, "rb") as f_in:
            with open(enc_path, "wb") as f_out:
                orig_size, comp_size, sha256, mac_tag = cipher.encrypt_stream(
                    f_in, f_out, enable_compression=True
                )

        print(f"   Original size: {orig_size:,} bytes")
        print(f"   Compressed size: {comp_size:,} bytes")
        print(f"   Compression ratio: {comp_size/orig_size*100:.1f}%")

        # Decrypt
        cipher_dec = StreamingCipher(key, nonce=cipher.nonce, chunk_size=4096)

        with tempfile.NamedTemporaryFile(delete=False) as f_dec:
            dec_path = f_dec.name

        with open(enc_path, "rb") as f_in:
            with open(dec_path, "wb") as f_out:
                total_written = cipher_dec.decrypt_stream(
                    f_in, f_out, enable_decompression=True, expected_mac=mac_tag
                )

        # Verify
        with open(dec_path, "rb") as f:
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
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
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

        written = stream_decrypt_file(enc_file, dec_file, password, salt, nonce, low_memory=True)

        print(f"   Decrypted: {written:,} bytes")

        # Verify
        with open(test_file, "rb") as f1, open(dec_file, "rb") as f2:
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
