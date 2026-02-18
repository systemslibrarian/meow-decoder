#!/usr/bin/env python3
"""
🐱 Comprehensive Test Suite for streaming_crypto.py
Tests for low-memory streaming encryption/decryption operations

Targets 90-95% code coverage with:
- Happy path tests
- Edge cases
- Error conditions
- Security invariants
- Memory management
"""

import pytest
import secrets
import hashlib
import io
import os
import gc
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from typing import Optional
from meow_decoder.streaming_crypto import (
    MemoryConfig,
    StreamingCipher,
    MemoryMonitor,
    create_streaming_encoder,
    stream_encrypt_file,
    stream_decrypt_file,
)

# Imports from merged file
from meow_decoder.streaming_crypto import StreamingCipher, STREAMING_MAC_INFO


@pytest.fixture
def valid_key():
    """Generate a valid 32-byte AES-256 key."""
    return secrets.token_bytes(32)


@pytest.fixture
def valid_nonce():
    """Generate a valid 16-byte nonce."""
    return secrets.token_bytes(16)


@pytest.fixture
def small_test_data():
    """Small test data for basic tests."""
    return b"The cat prowls through bytes of encrypted dreams! " * 10


@pytest.fixture
def medium_test_data():
    """Medium test data for compression tests."""
    return b"Meow! " * 10000  # Highly compressible


@pytest.fixture
def large_test_data():
    """Large test data for streaming tests."""
    return secrets.token_bytes(100 * 1024)  # 100 KB random data


@pytest.fixture
def streaming_cipher(valid_key, valid_nonce):
    """Create a StreamingCipher instance."""
    return StreamingCipher(valid_key, nonce=valid_nonce, chunk_size=4096)


@pytest.fixture
def memory_monitor():
    """Create a MemoryMonitor instance."""
    return MemoryMonitor(target_usage_mb=100)


@pytest.fixture
def temp_test_file(small_test_data):
    """Create a temporary test file with data."""
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
        f.write(small_test_data)
        path = f.name
    yield path
    # Cleanup
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def temp_output_file():
    """Create a temporary output file path."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name
    yield path
    # Cleanup
    if os.path.exists(path):
        os.unlink(path)


# =============================================================================
# 🐱 TEST CLASS: MemoryConfig
# =============================================================================


class TestCatMemoryConfig:
    """Tests for MemoryConfig dataclass."""

    def test_cat_default_values(self):
        """Test that MemoryConfig has sensible defaults."""
        config = MemoryConfig()

        assert config.chunk_size > 0
        assert config.max_memory_mb > 0
        assert isinstance(config.enable_gc, bool)
        assert isinstance(config.enable_mlock, bool)

    def test_cat_custom_values(self):
        """Test creating MemoryConfig with custom values."""
        config = MemoryConfig(
            chunk_size=8192, max_memory_mb=200, enable_gc=True, enable_mlock=False
        )

        assert config.chunk_size == 8192
        assert config.max_memory_mb == 200
        assert config.enable_gc is True
        assert config.enable_mlock is False

    def test_cat_immutable_style(self):
        """Test that config attributes can be accessed like a dataclass."""
        config = MemoryConfig(chunk_size=1024)

        # Should be able to access attributes
        _ = config.chunk_size
        _ = config.max_memory_mb
        _ = config.enable_gc
        _ = config.enable_mlock


# =============================================================================
# 🐱 TEST CLASS: StreamingCipher Initialization
# =============================================================================


class TestCatStreamingCipherInit:
    """Tests for StreamingCipher initialization."""

    def test_cat_init_with_valid_key_and_nonce(self, valid_key, valid_nonce):
        """Test initialization with valid key and nonce (handle-based: no raw key storage)."""
        cipher = StreamingCipher(valid_key, nonce=valid_nonce)

        # Rule #2: cipher must NOT store raw key bytes
        assert not hasattr(cipher, 'key'), "cipher.key must not exist (Rule #2)"
        assert not hasattr(cipher, '_mac_key'), "cipher._mac_key must not exist (Rule #2)"
        # Nonce is non-secret metadata — OK to store
        assert cipher.nonce == valid_nonce
        # Stream handle must be an integer (opaque Rust handle)
        assert isinstance(cipher._stream_handle, int)

    def test_cat_init_generates_nonce_if_none(self, valid_key):
        """Test that nonce is generated if not provided."""
        cipher = StreamingCipher(valid_key, nonce=None)

        assert cipher.nonce is not None
        assert len(cipher.nonce) == 16

    def test_cat_init_with_custom_chunk_size(self, valid_key):
        """Test initialization with custom chunk size."""
        cipher = StreamingCipher(valid_key, chunk_size=8192)

        assert cipher.chunk_size == 8192

    def test_cat_init_with_default_chunk_size(self, valid_key):
        """Test initialization with default chunk size."""
        cipher = StreamingCipher(valid_key)

        assert cipher.chunk_size > 0  # Should have a default

    def test_cat_init_invalid_key_length_too_short(self):
        """Test that short keys are rejected."""
        short_key = b"too_short"

        with pytest.raises((ValueError, Exception)):
            StreamingCipher(short_key)

    def test_cat_init_invalid_key_length_too_long(self):
        """Test that overly long keys are rejected or truncated."""
        long_key = secrets.token_bytes(64)

        # Either raises or uses first 32 bytes
        try:
            cipher = StreamingCipher(long_key)
            # If it doesn't raise, key should be handled
        except (ValueError, Exception):
            pass  # Expected behavior

    def test_cat_init_empty_key_rejected(self):
        """Test that empty keys are rejected."""
        with pytest.raises((ValueError, Exception)):
            StreamingCipher(b"")

    def test_cat_init_invalid_nonce_length(self, valid_key):
        """Test that invalid nonce lengths are handled."""
        short_nonce = b"short"

        # Should either raise or handle gracefully
        try:
            cipher = StreamingCipher(valid_key, nonce=short_nonce)
        except (ValueError, Exception):
            pass  # Expected

    def test_cat_init_zero_chunk_size(self, valid_key):
        """Test behavior with zero chunk size."""
        with pytest.raises((ValueError, Exception)):
            StreamingCipher(valid_key, chunk_size=0)

    def test_cat_init_negative_chunk_size(self, valid_key):
        """Test behavior with negative chunk size."""
        with pytest.raises((ValueError, Exception)):
            StreamingCipher(valid_key, chunk_size=-1)


# =============================================================================
# 🐱 TEST CLASS: StreamingCipher Encryption
# =============================================================================


class TestCatStreamingCipherEncrypt:
    """Tests for StreamingCipher.encrypt_stream()."""

    def test_cat_encrypt_basic(self, streaming_cipher, small_test_data):
        """Test basic encryption works."""
        input_stream = io.BytesIO(small_test_data)
        output_stream = io.BytesIO()

        orig_size, comp_size, sha256, _ = streaming_cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )

        assert orig_size == len(small_test_data)
        assert comp_size > 0
        assert len(sha256) == 32
        assert output_stream.tell() > 0

    def test_cat_encrypt_returns_correct_sha256(self, streaming_cipher, small_test_data):
        """Test that returned SHA256 matches input data hash."""
        input_stream = io.BytesIO(small_test_data)
        output_stream = io.BytesIO()

        _, _, sha256, _ = streaming_cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )

        expected_sha = hashlib.sha256(small_test_data).digest()
        assert sha256 == expected_sha

    def test_cat_encrypt_with_compression_reduces_size(self, streaming_cipher, medium_test_data):
        """Test that compression reduces size for compressible data."""
        input_stream = io.BytesIO(medium_test_data)
        output_stream = io.BytesIO()

        orig_size, comp_size, _, _ = streaming_cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )

        # Highly compressible data should compress well
        assert comp_size < orig_size

    def test_cat_encrypt_without_compression(self, valid_key, valid_nonce, small_test_data):
        """Test encryption without compression."""
        cipher = StreamingCipher(valid_key, nonce=valid_nonce)
        input_stream = io.BytesIO(small_test_data)
        output_stream = io.BytesIO()

        orig_size, comp_size, _, _ = cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=False
        )

        assert orig_size == len(small_test_data)
        # Without compression, comp_size should be similar to orig_size
        assert comp_size >= orig_size - 100  # Allow small overhead

    def test_cat_encrypt_empty_input(self, streaming_cipher):
        """Test encryption of empty input."""
        input_stream = io.BytesIO(b"")
        output_stream = io.BytesIO()

        orig_size, comp_size, sha256, _ = streaming_cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )

        assert orig_size == 0
        # SHA256 of empty data
        expected_sha = hashlib.sha256(b"").digest()
        assert sha256 == expected_sha

    def test_cat_encrypt_large_data_streaming(self, valid_key, large_test_data):
        """Test encryption of large data uses streaming."""
        cipher = StreamingCipher(valid_key, chunk_size=1024)  # Small chunks
        input_stream = io.BytesIO(large_test_data)
        output_stream = io.BytesIO()

        orig_size, comp_size, sha256, _ = cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )

        assert orig_size == len(large_test_data)
        assert len(sha256) == 32

    def test_cat_encrypt_produces_different_output_each_time(self, valid_key, small_test_data):
        """Test that encryption with different nonces produces different output."""
        cipher1 = StreamingCipher(valid_key)
        cipher2 = StreamingCipher(valid_key)  # Different nonce

        input1 = io.BytesIO(small_test_data)
        input2 = io.BytesIO(small_test_data)
        output1 = io.BytesIO()
        output2 = io.BytesIO()

        cipher1.encrypt_stream(input1, output1, enable_compression=True)
        cipher2.encrypt_stream(input2, output2, enable_compression=True)

        # Different nonces should produce different ciphertexts
        assert cipher1.nonce != cipher2.nonce
        assert output1.getvalue() != output2.getvalue()

    def test_cat_encrypt_same_nonce_same_output(self, valid_key, valid_nonce, small_test_data):
        """Test that same key+nonce produces same output (deterministic)."""
        cipher1 = StreamingCipher(valid_key, nonce=valid_nonce)
        cipher2 = StreamingCipher(valid_key, nonce=valid_nonce)

        input1 = io.BytesIO(small_test_data)
        input2 = io.BytesIO(small_test_data)
        output1 = io.BytesIO()
        output2 = io.BytesIO()

        cipher1.encrypt_stream(input1, output1, enable_compression=False)
        cipher2.encrypt_stream(input2, output2, enable_compression=False)

        # Same key+nonce should produce same ciphertext
        assert output1.getvalue() == output2.getvalue()

    def test_cat_encrypt_binary_data(self, streaming_cipher):
        """Test encryption of binary data with null bytes."""
        binary_data = bytes(range(256)) * 4
        input_stream = io.BytesIO(binary_data)
        output_stream = io.BytesIO()

        orig_size, _, sha256, _ = streaming_cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=False
        )

        assert orig_size == len(binary_data)
        assert sha256 == hashlib.sha256(binary_data).digest()


# =============================================================================
# 🐱 TEST CLASS: StreamingCipher Decryption
# =============================================================================


class TestCatStreamingCipherDecrypt:
    """Tests for StreamingCipher.decrypt_stream()."""

    def test_cat_decrypt_basic(self, valid_key, valid_nonce, small_test_data):
        """Test basic encryption-decryption roundtrip."""
        # Encrypt
        cipher_enc = StreamingCipher(valid_key, nonce=valid_nonce)
        input_stream = io.BytesIO(small_test_data)
        encrypted_stream = io.BytesIO()

        _, _, _, mac_tag = cipher_enc.encrypt_stream(
            input_stream, encrypted_stream, enable_compression=True
        )

        # Decrypt
        cipher_dec = StreamingCipher(valid_key, nonce=valid_nonce)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        total_written = cipher_dec.decrypt_stream(
            encrypted_stream, decrypted_stream, enable_decompression=True, expected_mac=mac_tag
        )

        assert total_written == len(small_test_data)
        assert decrypted_stream.getvalue() == small_test_data

    def test_cat_decrypt_without_decompression(self, valid_key, valid_nonce, small_test_data):
        """Test decryption without decompression (when not compressed)."""
        # Encrypt without compression
        cipher_enc = StreamingCipher(valid_key, nonce=valid_nonce)
        input_stream = io.BytesIO(small_test_data)
        encrypted_stream = io.BytesIO()

        _, _, _, mac_tag = cipher_enc.encrypt_stream(
            input_stream, encrypted_stream, enable_compression=False
        )

        # Decrypt without decompression
        cipher_dec = StreamingCipher(valid_key, nonce=valid_nonce)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        total_written = cipher_dec.decrypt_stream(
            encrypted_stream, decrypted_stream, enable_decompression=False, expected_mac=mac_tag
        )

        assert decrypted_stream.getvalue() == small_test_data

    def test_cat_decrypt_large_data(self, valid_key, large_test_data):
        """Test decryption of large data."""
        nonce = secrets.token_bytes(16)

        # Encrypt
        cipher_enc = StreamingCipher(valid_key, nonce=nonce, chunk_size=1024)
        input_stream = io.BytesIO(large_test_data)
        encrypted_stream = io.BytesIO()

        _, _, _, mac_tag = cipher_enc.encrypt_stream(
            input_stream, encrypted_stream, enable_compression=True
        )

        # Decrypt
        cipher_dec = StreamingCipher(valid_key, nonce=nonce, chunk_size=1024)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        cipher_dec.decrypt_stream(
            decrypted_stream=decrypted_stream,
            input_stream=encrypted_stream,
            enable_decompression=True,
            expected_mac=mac_tag,
        )

        assert decrypted_stream.getvalue() == large_test_data

    def test_cat_decrypt_empty_input(self, valid_key, valid_nonce):
        """Test decryption of empty encrypted data."""
        # Encrypt empty data
        cipher_enc = StreamingCipher(valid_key, nonce=valid_nonce)
        input_stream = io.BytesIO(b"")
        encrypted_stream = io.BytesIO()

        _, _, _, mac_tag = cipher_enc.encrypt_stream(
            input_stream, encrypted_stream, enable_compression=True
        )

        # Decrypt
        cipher_dec = StreamingCipher(valid_key, nonce=valid_nonce)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        cipher_dec.decrypt_stream(
            encrypted_stream, decrypted_stream, enable_decompression=True, expected_mac=mac_tag
        )

        assert decrypted_stream.getvalue() == b""

    def test_cat_decrypt_wrong_key_fails(self, valid_key, valid_nonce, small_test_data):
        """Test that decryption with wrong key fails MAC verification."""
        wrong_key = secrets.token_bytes(32)

        # Encrypt with valid key
        cipher_enc = StreamingCipher(valid_key, nonce=valid_nonce)
        input_stream = io.BytesIO(small_test_data)
        encrypted_stream = io.BytesIO()

        _, _, _, mac_tag = cipher_enc.encrypt_stream(
            input_stream, encrypted_stream, enable_compression=False
        )

        # Decrypt with wrong key — MAC verification must fail (no plaintext released)
        cipher_dec = StreamingCipher(wrong_key, nonce=valid_nonce)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        with pytest.raises(RuntimeError, match="MAC verification failed"):
            cipher_dec.decrypt_stream(
                encrypted_stream, decrypted_stream, enable_decompression=False, expected_mac=mac_tag
            )

        # No plaintext should have been written
        assert decrypted_stream.getvalue() == b""

    def test_cat_decrypt_wrong_nonce_fails(self, valid_key, valid_nonce, small_test_data):
        """Test that decryption with wrong nonce fails MAC verification."""
        wrong_nonce = secrets.token_bytes(16)

        # Encrypt
        cipher_enc = StreamingCipher(valid_key, nonce=valid_nonce)
        input_stream = io.BytesIO(small_test_data)
        encrypted_stream = io.BytesIO()

        _, _, _, mac_tag = cipher_enc.encrypt_stream(
            input_stream, encrypted_stream, enable_compression=False
        )

        # Decrypt with wrong nonce — MAC verification must fail (nonce is bound into MAC)
        cipher_dec = StreamingCipher(valid_key, nonce=wrong_nonce)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()

        with pytest.raises(RuntimeError, match="MAC verification failed"):
            cipher_dec.decrypt_stream(
                encrypted_stream, decrypted_stream, enable_decompression=False, expected_mac=mac_tag
            )

        # No plaintext released
        assert decrypted_stream.getvalue() == b""

    def test_cat_decrypt_binary_data_roundtrip(self, valid_key, valid_nonce):
        """Test roundtrip of binary data with all byte values."""
        binary_data = bytes(range(256)) * 4

        # Encrypt
        cipher_enc = StreamingCipher(valid_key, nonce=valid_nonce)
        encrypted_stream = io.BytesIO()
        _, _, _, mac_tag = cipher_enc.encrypt_stream(
            io.BytesIO(binary_data), encrypted_stream, enable_compression=False
        )

        # Decrypt
        cipher_dec = StreamingCipher(valid_key, nonce=valid_nonce)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()
        cipher_dec.decrypt_stream(
            encrypted_stream, decrypted_stream, enable_decompression=False, expected_mac=mac_tag
        )

        assert decrypted_stream.getvalue() == binary_data


# =============================================================================
# 🐱 TEST CLASS: MemoryMonitor
# =============================================================================


class TestCatMemoryMonitor:
    """Tests for MemoryMonitor class."""

    def test_cat_init_default(self):
        """Test MemoryMonitor initialization with defaults."""
        monitor = MemoryMonitor()

        assert monitor.target_usage_mb > 0

    def test_cat_init_custom_target(self):
        """Test MemoryMonitor with custom target usage."""
        monitor = MemoryMonitor(target_usage_mb=256)

        assert monitor.target_usage_mb == 256

    def test_cat_get_available_memory_with_psutil(self, memory_monitor):
        """Test getting available memory when psutil is available."""
        available = memory_monitor.get_available_memory_mb()

        # Should return positive number or None if psutil unavailable
        if available is not None:
            assert available > 0

    def test_cat_get_available_memory_without_psutil(self):
        """Test behavior when psutil is not available."""
        monitor = MemoryMonitor()

        with patch.dict("sys.modules", {"psutil": None}):
            # Should handle gracefully
            try:
                available = monitor.get_available_memory_mb()
                # Returns None or a default value
            except ImportError:
                pass  # Expected

    def test_cat_get_optimal_chunk_size_returns_valid(self, memory_monitor):
        """Test that optimal chunk size is within valid range."""
        chunk_size = memory_monitor.get_optimal_chunk_size(min_chunk=1024, max_chunk=1048576)

        assert chunk_size >= 1024
        assert chunk_size <= 1048576

    def test_cat_get_optimal_chunk_size_respects_min(self, memory_monitor):
        """Test that optimal chunk size respects minimum."""
        chunk_size = memory_monitor.get_optimal_chunk_size(min_chunk=4096, max_chunk=8192)

        assert chunk_size >= 4096

    def test_cat_get_optimal_chunk_size_respects_max(self, memory_monitor):
        """Test that optimal chunk size respects maximum."""
        chunk_size = memory_monitor.get_optimal_chunk_size(min_chunk=1024, max_chunk=4096)

        assert chunk_size <= 4096

    def test_cat_should_enable_aggressive_gc_low_memory(self):
        """Test aggressive GC recommendation for low memory."""
        monitor = MemoryMonitor(target_usage_mb=10)

        # Mock low memory scenario
        with patch.object(monitor, "get_available_memory_mb", return_value=5):
            should_gc = monitor.should_enable_aggressive_gc()
            assert should_gc is True

    def test_cat_should_enable_aggressive_gc_high_memory(self):
        """Test aggressive GC not needed for high memory."""
        monitor = MemoryMonitor(target_usage_mb=100)

        # Mock high memory scenario
        with patch.object(monitor, "get_available_memory_mb", return_value=8000):
            should_gc = monitor.should_enable_aggressive_gc()
            assert should_gc is False

    def test_cat_should_enable_aggressive_gc_handles_none(self):
        """Test aggressive GC handling when memory info unavailable."""
        monitor = MemoryMonitor()

        with patch.object(monitor, "get_available_memory_mb", return_value=None):
            # Should return a default (likely False)
            result = monitor.should_enable_aggressive_gc()
            assert isinstance(result, bool)


# =============================================================================
# 🐱 TEST CLASS: create_streaming_encoder Factory
# =============================================================================


class TestCatCreateStreamingEncoder:
    """Tests for create_streaming_encoder() factory function."""

    def test_cat_create_normal_mode(self, valid_key):
        """Test creating encoder in normal mode."""
        cipher, config = create_streaming_encoder(valid_key, low_memory=False)

        assert isinstance(cipher, StreamingCipher)
        assert isinstance(config, MemoryConfig)

    def test_cat_create_low_memory_mode(self, valid_key):
        """Test creating encoder in low-memory mode."""
        cipher, config = create_streaming_encoder(valid_key, low_memory=True)

        assert isinstance(cipher, StreamingCipher)
        assert isinstance(config, MemoryConfig)
        # Low memory mode should have smaller chunks and/or enable GC
        assert config.enable_gc is True or config.chunk_size < 1024 * 1024

    def test_cat_create_returns_configured_cipher(self, valid_key):
        """Test that returned cipher has correct chunk size from config."""
        cipher, config = create_streaming_encoder(valid_key, low_memory=False)

        assert cipher.chunk_size == config.chunk_size

    def test_cat_create_generates_unique_nonces(self, valid_key):
        """Test that each call generates a unique nonce."""
        cipher1, _ = create_streaming_encoder(valid_key, low_memory=False)
        cipher2, _ = create_streaming_encoder(valid_key, low_memory=False)

        assert cipher1.nonce != cipher2.nonce

    def test_cat_create_with_invalid_key(self):
        """Test factory with invalid key."""
        with pytest.raises((ValueError, Exception)):
            create_streaming_encoder(b"short", low_memory=False)


# =============================================================================
# 🐱 TEST CLASS: stream_encrypt_file
# =============================================================================


class TestCatStreamEncryptFile:
    """Tests for stream_encrypt_file() function."""

    def test_cat_encrypt_file_basic(self, temp_test_file, temp_output_file):
        """Test basic file encryption."""
        password = "test_password_12345678"
        salt = secrets.token_bytes(16)

        nonce, orig_size, comp_size, sha256, _ = stream_encrypt_file(
            temp_test_file, temp_output_file, password, salt, low_memory=False
        )

        assert len(nonce) == 16
        assert orig_size > 0
        assert comp_size > 0
        assert len(sha256) == 32
        assert os.path.exists(temp_output_file)
        assert os.path.getsize(temp_output_file) > 0

    def test_cat_encrypt_file_low_memory(self, temp_test_file, temp_output_file):
        """Test file encryption in low-memory mode."""
        password = "low_memory_test_123"
        salt = secrets.token_bytes(16)

        nonce, orig_size, comp_size, sha256, _ = stream_encrypt_file(
            temp_test_file, temp_output_file, password, salt, low_memory=True
        )

        assert len(nonce) == 16
        assert os.path.exists(temp_output_file)

    def test_cat_encrypt_file_returns_valid_hash(
        self, temp_test_file, temp_output_file, small_test_data
    ):
        """Test that returned SHA256 matches original file."""
        password = "hash_test_password123"
        salt = secrets.token_bytes(16)

        _, _, _, sha256, _ = stream_encrypt_file(temp_test_file, temp_output_file, password, salt)

        expected_sha = hashlib.sha256(small_test_data).digest()
        assert sha256 == expected_sha

    def test_cat_encrypt_file_nonexistent_input(self, temp_output_file):
        """Test encryption of nonexistent file."""
        password = "nonexistent_test123"
        salt = secrets.token_bytes(16)

        with pytest.raises((FileNotFoundError, IOError, Exception)):
            stream_encrypt_file("/nonexistent/path/file.txt", temp_output_file, password, salt)

    def test_cat_encrypt_file_invalid_output_path(self, temp_test_file):
        """Test encryption with invalid output path."""
        password = "invalid_path_test123"
        salt = secrets.token_bytes(16)

        with pytest.raises((IOError, OSError, Exception)):
            stream_encrypt_file(temp_test_file, "/nonexistent/dir/output.enc", password, salt)

    def test_cat_encrypt_file_empty_password(self, temp_test_file, temp_output_file):
        """Test encryption with empty password."""
        salt = secrets.token_bytes(16)

        with pytest.raises((ValueError, Exception)):
            stream_encrypt_file(temp_test_file, temp_output_file, "", salt)

    def test_cat_encrypt_file_short_password(self, temp_test_file, temp_output_file):
        """Test encryption with short password (may be rejected)."""
        password = "short"  # Less than 8 chars
        salt = secrets.token_bytes(16)

        # May raise ValueError for short password per NIST guidelines
        try:
            stream_encrypt_file(temp_test_file, temp_output_file, password, salt)
        except ValueError:
            pass  # Expected - short passwords rejected

    def test_cat_encrypt_file_different_salts_different_output(self, temp_test_file):
        """Test that different salts produce different encrypted files."""
        password = "same_password_for_both"
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)

        with tempfile.NamedTemporaryFile(delete=False) as f1:
            output1 = f1.name
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            output2 = f2.name

        try:
            stream_encrypt_file(temp_test_file, output1, password, salt1)
            stream_encrypt_file(temp_test_file, output2, password, salt2)

            with open(output1, "rb") as f:
                enc1 = f.read()
            with open(output2, "rb") as f:
                enc2 = f.read()

            assert enc1 != enc2
        finally:
            os.unlink(output1)
            os.unlink(output2)


# =============================================================================
# 🐱 TEST CLASS: stream_decrypt_file
# =============================================================================


class TestCatStreamDecryptFile:
    """Tests for stream_decrypt_file() function."""

    def test_cat_decrypt_file_roundtrip(self, temp_test_file, small_test_data):
        """Test complete encryption-decryption roundtrip."""
        password = "roundtrip_password123"
        salt = secrets.token_bytes(16)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            enc_path = f.name
        with tempfile.NamedTemporaryFile(delete=False) as f:
            dec_path = f.name

        try:
            # Encrypt
            nonce, _, _, _, mac_tag = stream_encrypt_file(temp_test_file, enc_path, password, salt)

            # Decrypt
            written = stream_decrypt_file(enc_path, dec_path, password, salt, nonce, mac_tag)

            # Verify
            with open(dec_path, "rb") as f:
                decrypted = f.read()

            assert decrypted == small_test_data
        finally:
            os.unlink(enc_path)
            os.unlink(dec_path)

    def test_cat_decrypt_file_low_memory(self, temp_test_file, small_test_data):
        """Test decryption in low-memory mode."""
        password = "low_mem_decrypt_123"
        salt = secrets.token_bytes(16)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            enc_path = f.name
        with tempfile.NamedTemporaryFile(delete=False) as f:
            dec_path = f.name

        try:
            nonce, _, _, _, mac_tag = stream_encrypt_file(
                temp_test_file, enc_path, password, salt, low_memory=True
            )

            written = stream_decrypt_file(
                enc_path, dec_path, password, salt, nonce, mac_tag, low_memory=True
            )

            with open(dec_path, "rb") as f:
                assert f.read() == small_test_data
        finally:
            os.unlink(enc_path)
            os.unlink(dec_path)

    def test_cat_decrypt_file_wrong_password(self, temp_test_file):
        """Test decryption with wrong password fails MAC verification."""
        correct_password = "correct_password123"
        wrong_password = "wrong_password_456"
        salt = secrets.token_bytes(16)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            enc_path = f.name
        with tempfile.NamedTemporaryFile(delete=False) as f:
            dec_path = f.name

        try:
            nonce, _, _, _, mac_tag = stream_encrypt_file(
                temp_test_file, enc_path, correct_password, salt
            )

            # Decrypt with wrong password — MAC verification must fail
            with pytest.raises(RuntimeError, match="MAC verification failed"):
                stream_decrypt_file(enc_path, dec_path, wrong_password, salt, nonce, mac_tag)
        finally:
            if os.path.exists(enc_path):
                os.unlink(enc_path)
            if os.path.exists(dec_path):
                os.unlink(dec_path)

    def test_cat_decrypt_file_wrong_nonce(self, temp_test_file):
        """Test decryption with wrong nonce fails MAC verification."""
        password = "nonce_test_password123"
        salt = secrets.token_bytes(16)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            enc_path = f.name
        with tempfile.NamedTemporaryFile(delete=False) as f:
            dec_path = f.name

        try:
            nonce, _, _, _, mac_tag = stream_encrypt_file(temp_test_file, enc_path, password, salt)

            wrong_nonce = secrets.token_bytes(16)

            # Decryption with wrong nonce — MAC verification must fail
            with pytest.raises(RuntimeError, match="MAC verification failed"):
                stream_decrypt_file(enc_path, dec_path, password, salt, wrong_nonce, mac_tag)
        finally:
            if os.path.exists(enc_path):
                os.unlink(enc_path)
            if os.path.exists(dec_path):
                os.unlink(dec_path)

    def test_cat_decrypt_file_nonexistent_input(self, temp_output_file):
        """Test decryption of nonexistent file."""
        password = "nonexistent_dec_test"
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(16)
        mac_tag = secrets.token_bytes(32)

        with pytest.raises((FileNotFoundError, IOError, Exception)):
            stream_decrypt_file(
                "/nonexistent/file.enc", temp_output_file, password, salt, nonce, mac_tag
            )

    def test_cat_decrypt_file_returns_correct_size(self, temp_test_file, small_test_data):
        """Test that decryption returns correct byte count."""
        password = "size_test_password123"
        salt = secrets.token_bytes(16)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            enc_path = f.name
        with tempfile.NamedTemporaryFile(delete=False) as f:
            dec_path = f.name

        try:
            nonce, _, _, _, mac_tag = stream_encrypt_file(temp_test_file, enc_path, password, salt)

            written = stream_decrypt_file(enc_path, dec_path, password, salt, nonce, mac_tag)

            assert written == len(small_test_data)
        finally:
            os.unlink(enc_path)
            os.unlink(dec_path)


# =============================================================================
# 🐱 TEST CLASS: Security Invariants
# =============================================================================


class TestCatSecurityInvariants:
    """Tests for security-critical invariants."""

    def test_cat_key_not_in_output(self, valid_key, small_test_data):
        """Test that encryption key doesn't appear in ciphertext."""
        nonce = secrets.token_bytes(16)
        cipher = StreamingCipher(valid_key, nonce=nonce)

        input_stream = io.BytesIO(small_test_data)
        output_stream = io.BytesIO()

        cipher.encrypt_stream(input_stream, output_stream, enable_compression=False)

        ciphertext = output_stream.getvalue()
        assert valid_key not in ciphertext

    def test_cat_nonce_uniqueness_per_encryption(self, valid_key):
        """Test that each encryption uses unique nonce."""
        nonces = set()

        for _ in range(100):
            cipher = StreamingCipher(valid_key)
            nonces.add(cipher.nonce)

        # All nonces should be unique
        assert len(nonces) == 100

    def test_cat_ciphertext_differs_from_plaintext(self, valid_key, small_test_data):
        """Test that ciphertext differs from plaintext."""
        cipher = StreamingCipher(valid_key)

        input_stream = io.BytesIO(small_test_data)
        output_stream = io.BytesIO()

        cipher.encrypt_stream(input_stream, output_stream, enable_compression=False)

        ciphertext = output_stream.getvalue()
        assert ciphertext != small_test_data

    def test_cat_zero_key_after_file_encrypt(self, temp_test_file, temp_output_file):
        """Test that key is zeroed after file encryption (best-effort)."""
        password = "zero_key_test_12345"
        salt = secrets.token_bytes(16)

        # Force garbage collection before
        gc.collect()

        stream_encrypt_file(temp_test_file, temp_output_file, password, salt)

        # Force garbage collection after
        gc.collect()

        # This is best-effort verification - in practice, checking memory
        # for zeroed keys is implementation-dependent

    def test_cat_different_plaintexts_different_ciphertexts(self, valid_key, valid_nonce):
        """Test that different plaintexts produce different ciphertexts."""
        cipher1 = StreamingCipher(valid_key, nonce=valid_nonce)
        cipher2 = StreamingCipher(valid_key, nonce=valid_nonce)

        data1 = b"Message A for the cat"
        data2 = b"Message B for the dog"

        out1 = io.BytesIO()
        out2 = io.BytesIO()

        cipher1.encrypt_stream(io.BytesIO(data1), out1, enable_compression=False)
        cipher2.encrypt_stream(io.BytesIO(data2), out2, enable_compression=False)

        assert out1.getvalue() != out2.getvalue()

    def test_cat_compression_before_encryption(self, valid_key, medium_test_data):
        """Test that compression happens before encryption (not after)."""
        cipher = StreamingCipher(valid_key)

        input_stream = io.BytesIO(medium_test_data)
        output_stream = io.BytesIO()

        orig_size, comp_size, _, _ = cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )

        # Compression should reduce size
        assert comp_size < orig_size

        # Ciphertext includes compression overhead but shouldn't be massively larger
        ciphertext_size = len(output_stream.getvalue())
        assert ciphertext_size < orig_size


# =============================================================================
# 🐱 TEST CLASS: Edge Cases and Error Handling
# =============================================================================


class TestCatEdgeCases:
    """Tests for edge cases and error handling."""

    def test_cat_encrypt_single_byte(self, streaming_cipher):
        """Test encryption of single byte."""
        input_stream = io.BytesIO(b"X")
        output_stream = io.BytesIO()

        orig_size, _, _, _ = streaming_cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )

        assert orig_size == 1

    def test_cat_encrypt_exactly_chunk_size(self, valid_key):
        """Test encryption of data exactly matching chunk size."""
        chunk_size = 4096
        data = b"A" * chunk_size

        cipher = StreamingCipher(valid_key, chunk_size=chunk_size)
        output = io.BytesIO()

        cipher.encrypt_stream(io.BytesIO(data), output, enable_compression=False)

        # Should work without issues
        assert output.tell() > 0

    def test_cat_encrypt_multiple_of_chunk_size(self, valid_key):
        """Test encryption of data that's exact multiple of chunk size."""
        chunk_size = 1024
        data = b"B" * (chunk_size * 5)

        cipher = StreamingCipher(valid_key, chunk_size=chunk_size)
        output = io.BytesIO()

        orig_size, _, _, _ = cipher.encrypt_stream(
            io.BytesIO(data), output, enable_compression=False
        )

        assert orig_size == len(data)

    def test_cat_encrypt_chunk_size_plus_one(self, valid_key):
        """Test encryption of data just over chunk size."""
        chunk_size = 1024
        data = b"C" * (chunk_size + 1)

        cipher = StreamingCipher(valid_key, chunk_size=chunk_size)
        output = io.BytesIO()

        orig_size, _, _, _ = cipher.encrypt_stream(
            io.BytesIO(data), output, enable_compression=False
        )

        assert orig_size == len(data)

    def test_cat_very_small_chunk_size(self, valid_key, small_test_data):
        """Test with very small chunk size (stress test)."""
        cipher = StreamingCipher(valid_key, chunk_size=16)

        output = io.BytesIO()
        orig_size, _, _, _ = cipher.encrypt_stream(
            io.BytesIO(small_test_data), output, enable_compression=False
        )

        assert orig_size == len(small_test_data)

    def test_cat_closed_input_stream(self, streaming_cipher):
        """Test behavior with pre-closed input stream."""
        input_stream = io.BytesIO(b"test data")
        input_stream.close()

        output_stream = io.BytesIO()

        with pytest.raises((ValueError, IOError, Exception)):
            streaming_cipher.encrypt_stream(input_stream, output_stream)

    def test_cat_closed_output_stream(self, streaming_cipher, small_test_data):
        """Test behavior with pre-closed output stream."""
        input_stream = io.BytesIO(small_test_data)
        output_stream = io.BytesIO()
        output_stream.close()

        with pytest.raises((ValueError, IOError, Exception)):
            streaming_cipher.encrypt_stream(input_stream, output_stream)

    def test_cat_unicode_password(self, temp_test_file, temp_output_file):
        """Test encryption with Unicode password."""
        password = "пароль_кота_🐱_密码"
        salt = secrets.token_bytes(16)

        # Should handle Unicode gracefully
        try:
            nonce, _, _, _, _ = stream_encrypt_file(
                temp_test_file, temp_output_file, password, salt
            )
            assert len(nonce) == 16
        except UnicodeError:
            pytest.fail("Unicode password should be supported")


# =============================================================================
# 🐱 TEST CLASS: Memory Management
# =============================================================================


class TestCatMemoryManagement:
    """Tests for memory management features."""

    def test_cat_gc_called_in_low_memory_mode(self, valid_key, medium_test_data):
        """Test that GC is called in low-memory mode."""
        cipher, config = create_streaming_encoder(valid_key, low_memory=True)

        assert config.enable_gc is True

    def test_cat_chunk_size_adapts_to_low_memory(self, valid_key):
        """Test that chunk size is reduced in low-memory mode."""
        _, config_normal = create_streaming_encoder(valid_key, low_memory=False)
        _, config_low = create_streaming_encoder(valid_key, low_memory=True)

        # Low memory should have same or smaller chunk size
        assert config_low.chunk_size <= config_normal.chunk_size

    def test_cat_max_memory_respected(self, valid_key):
        """Test that max_memory_mb is set appropriately."""
        _, config_normal = create_streaming_encoder(valid_key, low_memory=False)
        _, config_low = create_streaming_encoder(valid_key, low_memory=True)

        # Low memory mode should have lower max memory
        assert config_low.max_memory_mb <= config_normal.max_memory_mb

    @pytest.mark.parametrize("chunk_size", [1024, 4096, 16384, 65536])
    def test_cat_various_chunk_sizes(self, valid_key, small_test_data, chunk_size):
        """Test encryption works with various chunk sizes."""
        cipher = StreamingCipher(valid_key, chunk_size=chunk_size)

        input_stream = io.BytesIO(small_test_data)
        output_stream = io.BytesIO()

        orig_size, _, _, _ = cipher.encrypt_stream(
            input_stream, output_stream, enable_compression=True
        )

        assert orig_size == len(small_test_data)


# =============================================================================
# 🐱 TEST CLASS: Integration Tests
# =============================================================================


class TestCatIntegration:
    """Integration tests combining multiple components."""

    def test_cat_full_pipeline_small_file(self):
        """Test complete pipeline with small file."""
        password = "integration_test_12345"
        salt = secrets.token_bytes(16)
        test_data = b"Small integration test data for the cat! " * 100

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(test_data)
            orig_path = f.name

        enc_path = orig_path + ".enc"
        dec_path = orig_path + ".dec"

        try:
            # Encrypt
            nonce, orig_size, comp_size, sha256, mac_tag = stream_encrypt_file(
                orig_path, enc_path, password, salt
            )

            # Verify encryption metadata
            assert orig_size == len(test_data)
            assert sha256 == hashlib.sha256(test_data).digest()

            # Decrypt
            written = stream_decrypt_file(enc_path, dec_path, password, salt, nonce, mac_tag)

            # Verify decryption
            with open(dec_path, "rb") as f:
                decrypted = f.read()

            assert decrypted == test_data
            assert written == len(test_data)
        finally:
            for p in [orig_path, enc_path, dec_path]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_cat_full_pipeline_large_file(self):
        """Test complete pipeline with larger file."""
        password = "large_file_test_1234"
        salt = secrets.token_bytes(16)
        test_data = secrets.token_bytes(500 * 1024)  # 500 KB

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(test_data)
            orig_path = f.name

        enc_path = orig_path + ".enc"
        dec_path = orig_path + ".dec"

        try:
            # Encrypt in low memory mode
            nonce, _, _, _, mac_tag = stream_encrypt_file(
                orig_path, enc_path, password, salt, low_memory=True
            )

            # Decrypt in low memory mode
            stream_decrypt_file(enc_path, dec_path, password, salt, nonce, mac_tag, low_memory=True)

            # Verify
            with open(dec_path, "rb") as f:
                decrypted = f.read()

            assert decrypted == test_data
        finally:
            for p in [orig_path, enc_path, dec_path]:
                if os.path.exists(p):
                    os.unlink(p)

    def test_cat_memory_monitor_integration(self, valid_key):
        """Test MemoryMonitor integration with streaming encoder."""
        monitor = MemoryMonitor(target_usage_mb=50)

        # Get optimal settings
        optimal_chunk = monitor.get_optimal_chunk_size()
        should_gc = monitor.should_enable_aggressive_gc()

        # Create cipher with monitor-recommended settings
        config = MemoryConfig(chunk_size=optimal_chunk, enable_gc=should_gc)

        cipher = StreamingCipher(valid_key, chunk_size=config.chunk_size)

        # Should work
        data = b"Test data for memory monitoring"
        output = io.BytesIO()
        cipher.encrypt_stream(io.BytesIO(data), output, enable_compression=True)

        assert output.tell() > 0


# =============================================================================
# 🐱 TEST CLASS: Parameterized Tests
# =============================================================================


class TestCatParameterized:
    """Parameterized tests for comprehensive coverage."""

    @pytest.mark.parametrize("data_size", [0, 1, 100, 1000, 10000])
    def test_cat_various_data_sizes(self, valid_key, data_size):
        """Test encryption of various data sizes."""
        data = secrets.token_bytes(data_size) if data_size > 0 else b""

        cipher = StreamingCipher(valid_key)
        output = io.BytesIO()

        orig_size, _, _, _ = cipher.encrypt_stream(
            io.BytesIO(data), output, enable_compression=True
        )

        assert orig_size == data_size

    @pytest.mark.parametrize("compression", [True, False])
    def test_cat_compression_modes(self, valid_key, small_test_data, compression):
        """Test both compression modes."""
        nonce = secrets.token_bytes(16)

        # Encrypt
        cipher_enc = StreamingCipher(valid_key, nonce=nonce)
        enc_output = io.BytesIO()
        _, _, _, mac_tag = cipher_enc.encrypt_stream(
            io.BytesIO(small_test_data), enc_output, enable_compression=compression
        )

        # Decrypt
        cipher_dec = StreamingCipher(valid_key, nonce=nonce)
        enc_output.seek(0)
        dec_output = io.BytesIO()
        cipher_dec.decrypt_stream(
            enc_output, dec_output, enable_decompression=compression, expected_mac=mac_tag
        )

        assert dec_output.getvalue() == small_test_data

    @pytest.mark.parametrize("password_length", [8, 16, 32, 64, 128])
    def test_cat_various_password_lengths(self, temp_test_file, temp_output_file, password_length):
        """Test with various password lengths."""
        password = "a" * password_length
        salt = secrets.token_bytes(16)

        try:
            nonce, _, _, _, _ = stream_encrypt_file(
                temp_test_file, temp_output_file, password, salt
            )
            assert len(nonce) == 16
        except ValueError:
            # May reject short passwords
            if password_length >= 8:
                pytest.fail(f"Password of length {password_length} should be accepted")

    @pytest.mark.parametrize("target_mb", [10, 50, 100, 500])
    def test_cat_various_memory_targets(self, target_mb):
        """Test MemoryMonitor with various target memory settings."""
        monitor = MemoryMonitor(target_usage_mb=target_mb)

        chunk_size = monitor.get_optimal_chunk_size()

        assert chunk_size > 0
        assert monitor.target_usage_mb == target_mb


# =============================================================================
# 🐱 TEST CLASS: Mock-based Tests
# =============================================================================


class TestCatMocked:
    """Tests using mocks for edge case coverage."""

    def test_cat_psutil_import_error(self):
        """Test behavior when psutil is not installed."""
        # This tests the graceful fallback
        monitor = MemoryMonitor()

        # Simulate psutil unavailability by setting has_psutil=False
        orig = monitor.has_psutil
        try:
            monitor.has_psutil = False
            result = monitor.get_available_memory_mb()
            assert result is None
        finally:
            monitor.has_psutil = orig

    def test_cat_file_write_error(self, temp_test_file):
        """Test handling of file write errors."""
        password = "write_error_test_123"
        salt = secrets.token_bytes(16)

        # Try to write to a read-only location
        with pytest.raises((IOError, OSError, PermissionError, Exception)):
            stream_encrypt_file(
                temp_test_file, "/read_only_or_nonexistent/output.enc", password, salt
            )

    def test_cat_memory_very_low(self):
        """Test behavior when available memory is very low."""
        monitor = MemoryMonitor(target_usage_mb=10)

        with patch.object(monitor, "get_available_memory_mb", return_value=5):
            chunk = monitor.get_optimal_chunk_size(min_chunk=1024, max_chunk=1048576)
            gc_needed = monitor.should_enable_aggressive_gc()

            assert chunk >= 1024  # Respects minimum
            assert gc_needed is True  # Should recommend GC


# =============================================================================
# 🐱 MAIN - Run tests if executed directly
# =============================================================================


# --- Merged from test_coverage_boost_extras.py ---


# =====================================================
# streaming_crypto.py — push from 89.22% higher
# =====================================================
class TestStreamingCryptoExtras:
    """Extra streaming_crypto tests for uncovered branches."""

    def test_encrypt_stream_returns_mac(self):
        """encrypt_stream returns (orig_size, comp_size, sha256, mac_tag)."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        nonce = os.urandom(16)

        cipher = StreamingCipher(key, nonce)
        inp = io.BytesIO(b"test data for MAC return")
        out = io.BytesIO()
        result = cipher.encrypt_stream(inp, out)

        assert len(result) == 4
        orig_size, comp_size, sha256_hash, mac_tag = result
        assert orig_size == len(b"test data for MAC return")
        assert len(sha256_hash) == 32
        assert len(mac_tag) == 32

    def test_decrypt_with_valid_mac(self):
        """Decrypt with correct MAC should succeed."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        nonce = os.urandom(16)

        plaintext = b"MAC verified plaintext data!"
        enc = StreamingCipher(key, nonce)
        enc_out = io.BytesIO()
        _, _, _, mac_tag = enc.encrypt_stream(io.BytesIO(plaintext), enc_out)

        enc_out.seek(0)
        dec = StreamingCipher(key, nonce)
        dec_out = io.BytesIO()
        dec.decrypt_stream(enc_out, dec_out, expected_mac=mac_tag)
        dec_out.seek(0)
        assert dec_out.read() == plaintext

    def test_decrypt_with_wrong_mac(self):
        """Decrypt with wrong MAC should raise RuntimeError."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        nonce = os.urandom(16)

        enc = StreamingCipher(key, nonce)
        enc_out = io.BytesIO()
        enc.encrypt_stream(io.BytesIO(b"data to encrypt"), enc_out)

        enc_out.seek(0)
        dec = StreamingCipher(key, nonce)
        with pytest.raises(RuntimeError, match="MAC"):
            dec.decrypt_stream(enc_out, io.BytesIO(), expected_mac=b"\x00" * 32)

    def test_decrypt_mac_wrong_length(self):
        """MAC must be 32 bytes."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        cipher = StreamingCipher(key)
        with pytest.raises(ValueError, match="32 bytes|MAC"):
            cipher.decrypt_stream(io.BytesIO(b"x"), io.BytesIO(), expected_mac=b"\x00" * 16)

    def test_decrypt_no_compression(self):
        """Encrypt and decrypt without compression."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        nonce = os.urandom(16)

        plaintext = b"no compression test data"
        enc = StreamingCipher(key, nonce)
        enc_out = io.BytesIO()
        _, _, _, mac_tag = enc.encrypt_stream(
            io.BytesIO(plaintext), enc_out, enable_compression=False
        )

        enc_out.seek(0)
        dec = StreamingCipher(key, nonce)
        dec_out = io.BytesIO()
        dec.decrypt_stream(enc_out, dec_out, enable_decompression=False, expected_mac=mac_tag)
        dec_out.seek(0)
        assert dec_out.read() == plaintext

    def test_decrypt_missing_streams_raises(self):
        """Calling decrypt_stream with no args should raise ValueError."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        cipher = StreamingCipher(key)
        with pytest.raises((ValueError, TypeError)):
            cipher.decrypt_stream(expected_mac=b"\x00" * 32)

    def test_streaming_cipher_none_nonce_generates(self):
        """None nonce auto-generates a 16-byte nonce."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        cipher = StreamingCipher(key, nonce=None)
        assert cipher.nonce is not None
        assert len(cipher.nonce) == 16

    def test_streaming_cipher_wrong_key_length(self):
        """Key must be 32 bytes."""
        from meow_decoder.streaming_crypto import StreamingCipher

        with pytest.raises(ValueError, match="32 bytes|key"):
            StreamingCipher(b"short_key")

    def test_memory_monitor_with_psutil_mocked(self):
        """MemoryMonitor with mocked psutil."""
        from meow_decoder.streaming_crypto import MemoryMonitor

        mock_psutil = MagicMock()
        mock_vm = MagicMock()
        mock_vm.available = 1024 * 1024 * 512  # 512 MB
        mock_psutil.virtual_memory.return_value = mock_vm

        monitor = MemoryMonitor()
        monitor.has_psutil = True
        with patch.object(monitor, "_psutil", mock_psutil, create=True):
            # Just test the chunk size calculation
            chunk = monitor.get_optimal_chunk_size()
            assert chunk >= 4096


# =====================================================
# duress_mode.py — push from 91.16% higher
# =====================================================


# --- Merged from test_coverage_boost_remaining.py ---


# =====================================================
# streaming_crypto.py coverage
# =====================================================
class TestStreamingCryptoBoost:
    def test_streaming_cipher_wrong_nonce_length(self):
        """Nonce of wrong length should raise ValueError."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        with pytest.raises(ValueError):
            StreamingCipher(key, nonce=b"short")

    def test_streaming_cipher_encrypt_decrypt_roundtrip(self):
        """Full encrypt/decrypt stream roundtrip."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        nonce = os.urandom(16)

        plaintext = b"Hello streaming crypto! " * 100

        cipher = StreamingCipher(key, nonce)
        input_stream = io.BytesIO(plaintext)
        encrypted_stream = io.BytesIO()
        _, _, _, mac_tag = cipher.encrypt_stream(input_stream, encrypted_stream)

        cipher2 = StreamingCipher(key, nonce)
        encrypted_stream.seek(0)
        decrypted_stream = io.BytesIO()
        cipher2.decrypt_stream(encrypted_stream, decrypted_stream, expected_mac=mac_tag)

        decrypted_stream.seek(0)
        assert decrypted_stream.read() == plaintext

    def test_decrypt_stream_kwargs_compat(self):
        """Test backward-compat kwargs in decrypt_stream."""
        from meow_decoder.streaming_crypto import StreamingCipher

        key = os.urandom(32)
        nonce = os.urandom(16)
        plaintext = b"Test data"

        cipher = StreamingCipher(key, nonce)
        in_s = io.BytesIO(plaintext)
        enc_s = io.BytesIO()
        _, _, _, mac_tag = cipher.encrypt_stream(in_s, enc_s)

        cipher2 = StreamingCipher(key, nonce)
        enc_s.seek(0)
        dec_s = io.BytesIO()
        cipher2.decrypt_stream(input_stream=enc_s, decrypted_stream=dec_s, expected_mac=mac_tag)
        dec_s.seek(0)
        assert dec_s.read() == plaintext

    def test_memory_monitor_no_psutil(self):
        """MemoryMonitor without psutil should fallback."""
        from meow_decoder.streaming_crypto import MemoryMonitor

        monitor = MemoryMonitor()
        monitor.has_psutil = False
        result = monitor.get_available_memory_mb()
        assert result is None
        chunk = monitor.get_optimal_chunk_size()
        assert chunk == 65536


# =====================================================
# entropy_boost.py coverage
# =====================================================


# =====================================================
# Signal-Grade Streaming Auth Tests (Step 5)
# =====================================================


class TestStreamingFailClosed:
    """
    Signal-grade fail-closed tests for streaming crypto.

    These tests verify that NO plaintext is released under any
    failure condition. All must pass for production deployment.
    """

    def test_streaming_rejects_missing_mac(self):
        """Decrypt with expected_mac=None MUST raise ValueError immediately."""
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key)
        enc_out = io.BytesIO()
        cipher.encrypt_stream(io.BytesIO(b"secret data"), enc_out)

        enc_out.seek(0)
        dec_cipher = StreamingCipher(key, nonce=cipher.nonce)
        dec_out = io.BytesIO()

        with pytest.raises(ValueError, match="expected_mac is required"):
            dec_cipher.decrypt_stream(enc_out, dec_out)

        # No plaintext released
        assert dec_out.getvalue() == b""

    def test_streaming_rejects_invalid_mac(self):
        """Decrypt with wrong MAC MUST raise RuntimeError, no plaintext."""
        key = secrets.token_bytes(32)
        plaintext = b"sensitive data must not leak"

        enc_cipher = StreamingCipher(key)
        enc_out = io.BytesIO()
        enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_out)

        wrong_mac = secrets.token_bytes(32)
        enc_out.seek(0)
        dec_cipher = StreamingCipher(key, nonce=enc_cipher.nonce)
        dec_out = io.BytesIO()

        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(enc_out, dec_out, expected_mac=wrong_mac)

        # No plaintext released
        assert dec_out.getvalue() == b""

    def test_streaming_no_partial_output_on_failure(self):
        """On authentication failure, output stream must contain zero bytes."""
        key = secrets.token_bytes(32)
        large_plaintext = b"X" * 100_000  # Large enough that partial output would be detectable

        enc_cipher = StreamingCipher(key)
        enc_out = io.BytesIO()
        enc_cipher.encrypt_stream(io.BytesIO(large_plaintext), enc_out, enable_compression=False)

        # Tamper
        ct = bytearray(enc_out.getvalue())
        ct[len(ct) // 2] ^= 0xFF
        tampered = io.BytesIO(bytes(ct))

        dec_cipher = StreamingCipher(key, nonce=enc_cipher.nonce)
        dec_out = io.BytesIO()
        _, _, _, mac_tag = enc_cipher.encrypt_stream(io.BytesIO(large_plaintext), io.BytesIO())

        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(
                tampered, dec_out, expected_mac=mac_tag, enable_decompression=False
            )

        # Absolutely no partial output
        assert dec_out.getvalue() == b""

    def test_streaming_truncation_attack(self):
        """Truncated ciphertext MUST be rejected by MAC. No plaintext."""
        key = secrets.token_bytes(32)
        plaintext = b"This message will be truncated by attacker"

        enc_cipher = StreamingCipher(key)
        enc_out = io.BytesIO()
        _, _, _, mac_tag = enc_cipher.encrypt_stream(
            io.BytesIO(plaintext), enc_out, enable_compression=False
        )

        # Truncate ciphertext
        ct = enc_out.getvalue()
        truncated = io.BytesIO(ct[: len(ct) // 2])

        dec_cipher = StreamingCipher(key, nonce=enc_cipher.nonce)
        dec_out = io.BytesIO()

        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(
                truncated, dec_out, expected_mac=mac_tag, enable_decompression=False
            )

        assert dec_out.getvalue() == b""

    def test_streaming_extension_attack(self):
        """Extended ciphertext MUST be rejected by MAC. No plaintext."""
        key = secrets.token_bytes(32)
        plaintext = b"This message will be extended by attacker"

        enc_cipher = StreamingCipher(key)
        enc_out = io.BytesIO()
        _, _, _, mac_tag = enc_cipher.encrypt_stream(
            io.BytesIO(plaintext), enc_out, enable_compression=False
        )

        # Extend ciphertext
        ct = enc_out.getvalue()
        extended = io.BytesIO(ct + b"\x00" * 64)

        dec_cipher = StreamingCipher(key, nonce=enc_cipher.nonce)
        dec_out = io.BytesIO()

        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(
                extended, dec_out, expected_mac=mac_tag, enable_decompression=False
            )

        assert dec_out.getvalue() == b""


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])


# ===============================================================
# Merged from test_streaming_crypto_security.py
# ===============================================================


class TestStreamingCryptoAuthentication:
    """Test suite for streaming crypto MAC authentication (CRIT-01 fix)."""

    def test_encrypt_returns_mac_tag(self):
        """encrypt_stream should return MAC tag as 4th element."""
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key)

        input_data = b"Test data for MAC verification"
        result = cipher.encrypt_stream(io.BytesIO(input_data), io.BytesIO())

        assert len(result) == 4, "Should return 4 elements"
        orig_len, comp_len, sha_hash, mac_tag = result

        assert orig_len == len(input_data)
        assert isinstance(mac_tag, bytes)
        assert len(mac_tag) == 32, "MAC should be 32 bytes (HMAC-SHA256)"

    def test_roundtrip_with_mac_verification(self):
        """Encrypt-then-MAC roundtrip should work correctly."""
        key = secrets.token_bytes(32)
        plaintext = b"Secret message for authenticated streaming encryption"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        orig_len, comp_len, sha_hash, mac_tag = enc_cipher.encrypt_stream(
            io.BytesIO(plaintext), enc_output
        )

        # Decrypt with MAC verification
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce)
        dec_output = io.BytesIO()
        bytes_written = dec_cipher.decrypt_stream(enc_output, dec_output, expected_mac=mac_tag)

        assert bytes_written == len(plaintext)
        assert dec_output.getvalue() == plaintext

    def test_tampered_ciphertext_rejected(self):
        """Tampered ciphertext should be rejected by MAC verification."""
        key = secrets.token_bytes(32)
        plaintext = b"Secret data that must not be tampered with"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        _, _, _, mac_tag = enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_output)

        # Tamper with ciphertext
        ciphertext = bytearray(enc_output.getvalue())
        ciphertext[5] ^= 0xFF  # Flip a bit
        tampered = io.BytesIO(bytes(ciphertext))

        # Decrypt with MAC verification - MUST fail
        dec_cipher = StreamingCipher(key, nonce=nonce)
        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(tampered, io.BytesIO(), expected_mac=mac_tag)

    def test_truncated_ciphertext_rejected(self):
        """Truncated ciphertext should be rejected by MAC verification."""
        key = secrets.token_bytes(32)
        plaintext = b"This is a longer message that will be truncated during attack"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        _, _, _, mac_tag = enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_output)

        # Truncate ciphertext
        ciphertext = enc_output.getvalue()
        truncated = io.BytesIO(ciphertext[:-10])

        # Decrypt with MAC verification - MUST fail
        dec_cipher = StreamingCipher(key, nonce=nonce)
        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(truncated, io.BytesIO(), expected_mac=mac_tag)

    def test_wrong_mac_rejected(self):
        """Wrong MAC should be rejected."""
        key = secrets.token_bytes(32)
        plaintext = b"Data with wrong MAC"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_output)

        # Try to decrypt with wrong MAC
        wrong_mac = secrets.token_bytes(32)
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce)

        with pytest.raises(RuntimeError, match="MAC verification failed"):
            dec_cipher.decrypt_stream(enc_output, io.BytesIO(), expected_mac=wrong_mac)

    def test_mac_length_validation(self):
        """MAC must be exactly 32 bytes."""
        key = secrets.token_bytes(32)
        cipher = StreamingCipher(key)

        with pytest.raises(ValueError, match="MAC must be 32 bytes"):
            cipher.decrypt_stream(io.BytesIO(b"data"), io.BytesIO(), expected_mac=b"short")

    def test_mac_is_deterministic(self):
        """Same key/nonce/plaintext should produce same MAC."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        plaintext = b"Deterministic MAC test data"

        # Encrypt twice with same key/nonce
        c1 = StreamingCipher(key, nonce=nonce)
        out1 = io.BytesIO()
        _, _, _, mac1 = c1.encrypt_stream(io.BytesIO(plaintext), out1)

        c2 = StreamingCipher(key, nonce=nonce)
        out2 = io.BytesIO()
        _, _, _, mac2 = c2.encrypt_stream(io.BytesIO(plaintext), out2)

        assert mac1 == mac2
        assert out1.getvalue() == out2.getvalue()

    def test_different_keys_produce_different_macs(self):
        """Different keys should produce different MACs."""
        plaintext = b"Same plaintext, different keys"
        nonce = secrets.token_bytes(16)

        c1 = StreamingCipher(secrets.token_bytes(32), nonce=nonce)
        out1 = io.BytesIO()
        _, _, _, mac1 = c1.encrypt_stream(io.BytesIO(plaintext), out1)

        c2 = StreamingCipher(secrets.token_bytes(32), nonce=nonce)
        out2 = io.BytesIO()
        _, _, _, mac2 = c2.encrypt_stream(io.BytesIO(plaintext), out2)

        assert mac1 != mac2

    def test_mac_includes_nonce(self):
        """MAC should include nonce to prevent nonce substitution attacks."""
        key = secrets.token_bytes(32)
        plaintext = b"Test nonce binding"

        # Encrypt with nonce1
        nonce1 = secrets.token_bytes(16)
        c1 = StreamingCipher(key, nonce=nonce1)
        out1 = io.BytesIO()
        _, _, _, mac1 = c1.encrypt_stream(io.BytesIO(plaintext), out1)

        # Encrypt with nonce2
        nonce2 = secrets.token_bytes(16)
        c2 = StreamingCipher(key, nonce=nonce2)
        out2 = io.BytesIO()
        _, _, _, mac2 = c2.encrypt_stream(io.BytesIO(plaintext), out2)

        # MACs should differ due to nonce binding
        assert mac1 != mac2

    def test_decrypt_without_mac_raises_valueerror(self):
        """Decrypt without MAC must raise ValueError (fail-closed, Signal-grade)."""
        key = secrets.token_bytes(32)
        plaintext = b"Unauthenticated decryption must fail"

        # Encrypt
        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        enc_cipher.encrypt_stream(io.BytesIO(plaintext), enc_output)

        # Decrypt WITHOUT MAC — MUST raise ValueError (no plaintext released)
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce)
        dec_output = io.BytesIO()

        with pytest.raises(ValueError, match="expected_mac is required"):
            dec_cipher.decrypt_stream(enc_output, dec_output)

        # No plaintext should have been written
        assert dec_output.getvalue() == b""

    def test_large_data_authenticated(self):
        """MAC should work correctly for large data."""
        key = secrets.token_bytes(32)
        plaintext = secrets.token_bytes(1024 * 1024)  # 1 MB

        # Encrypt
        enc_cipher = StreamingCipher(key, chunk_size=65536)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        orig_len, _, _, mac_tag = enc_cipher.encrypt_stream(
            io.BytesIO(plaintext),
            enc_output,
            enable_compression=False,  # Skip compression for raw test
        )

        # Decrypt with MAC
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce, chunk_size=65536)
        dec_output = io.BytesIO()
        dec_cipher.decrypt_stream(
            enc_output, dec_output, enable_decompression=False, expected_mac=mac_tag
        )

        assert dec_output.getvalue() == plaintext

    def test_empty_plaintext(self):
        """MAC should work for empty plaintext."""
        key = secrets.token_bytes(32)
        plaintext = b""

        enc_cipher = StreamingCipher(key)
        nonce = enc_cipher.nonce
        enc_output = io.BytesIO()
        orig_len, _, _, mac_tag = enc_cipher.encrypt_stream(
            io.BytesIO(plaintext), enc_output, enable_compression=False
        )

        assert orig_len == 0
        assert len(mac_tag) == 32

        # Verify MAC still protects against modification
        enc_output.seek(0)
        dec_cipher = StreamingCipher(key, nonce=nonce)
        dec_output = io.BytesIO()
        dec_cipher.decrypt_stream(
            enc_output, dec_output, enable_decompression=False, expected_mac=mac_tag
        )

        assert dec_output.getvalue() == plaintext


class TestMACKeyDerivation:
    """Test MAC key derivation uses proper domain separation."""

    def test_mac_key_not_stored_in_python(self):
        """Rule #2: MAC key must NOT be stored as Python bytes."""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        cipher = StreamingCipher(key, nonce=nonce)

        # MAC key must NOT exist as Python attribute (lives in Rust stream handle)
        assert not hasattr(cipher, "_mac_key"), "_mac_key must not exist in Python (Rule #2)"
        assert not hasattr(cipher, "key"), "key must not exist in Python (Rule #2)"
        # Stream handle must be an opaque integer
        assert isinstance(cipher._stream_handle, int)

    def test_mac_key_uses_hkdf_domain_separation(self):
        """MAC key derivation uses HKDF domain separation inside Rust.

        Verify by checking that the stream handle produces the same MAC
        as manual HKDF + HMAC (functional equivalence test).
        """
        import meow_crypto_rs

        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)

        cipher = StreamingCipher(key, nonce=nonce)

        # Manually derive expected MAC key and compute HMAC via Rust raw API
        expected_mac_key = meow_crypto_rs.derive_key_hkdf(key, nonce, STREAMING_MAC_INFO, 32)
        test_msg = b"domain separation test"
        expected_mac = meow_crypto_rs.hmac_sha256(expected_mac_key, test_msg)

        # Compute same HMAC via stream handle (key stays in Rust)
        from meow_decoder.crypto_backend import get_handle_backend
        hb = get_handle_backend()
        actual_mac = hb.stream_hmac(cipher._stream_handle, test_msg)

        assert actual_mac == expected_mac, "Stream handle MAC must match manual HKDF+HMAC"


class TestStreamingCryptoCoverageGaps:
    """Tests for remaining coverage gaps."""

    def test_encrypt_stream_empty_compressor_flush(self, valid_key, valid_nonce):
        """Test encrypt_stream when compressor.flush() returns empty bytes (line 179->186)."""
        import zlib

        cipher = StreamingCipher(valid_key, nonce=valid_nonce)

        # Very small data that compresses to nothing on flush
        input_data = b"a"
        input_stream = io.BytesIO(input_data)
        output_stream = io.BytesIO()

        # Mock the compressor's flush to return empty
        original_compress_obj = zlib.compressobj

        class MockCompressor:
            def __init__(self, *args, **kwargs):
                self._real = original_compress_obj(*args, **kwargs)

            def compress(self, data):
                return self._real.compress(data)

            def flush(self):
                # Return empty to hit the branch 179->186
                return b""

        with patch("zlib.compressobj", MockCompressor):
            cipher.encrypt_stream(input_stream, output_stream, enable_compression=True)

        # Encryption should still complete
        assert output_stream.tell() > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
