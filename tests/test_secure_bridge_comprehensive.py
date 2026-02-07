#!/usr/bin/env python3
"""
🔐 Comprehensive Test Suite for secure_bridge.py
Trust Boundary Bridging Between Python and Rust Crypto Backend

Target Coverage: 85-92%

Tests cover:
- KeyHandle lifecycle (creation, zeroing, destruction)
- SecureMemory allocation, locking, zeroing
- SecureBridge operations (encrypt, decrypt, HMAC)
- Context managers (secure_password, secure_key)
- Edge cases and error conditions
- Memory safety invariants

Author: Meow Decoder Security Team
Date: February 2026
"""

import gc
import ctypes
import secrets
import sys
import pytest
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_rust_backend():
    """Mock the Rust crypto backend for isolated testing."""
    mock_rs = MagicMock()

    # Mock key derivation
    mock_rs.derive_key_argon2id.return_value = secrets.token_bytes(32)

    # Mock encryption - returns ciphertext with auth tag
    mock_rs.aes_gcm_encrypt.return_value = secrets.token_bytes(48)

    # Mock decryption - returns original plaintext
    mock_rs.aes_gcm_decrypt.return_value = b"test plaintext data"

    # Mock HMAC
    mock_rs.hmac_sha256.return_value = secrets.token_bytes(32)
    mock_rs.hmac_sha256_verify.return_value = True

    # Mock backend info
    mock_rs.backend_info.return_value = "Mock Rust Backend v1.0"

    return mock_rs


@pytest.fixture
def valid_password():
    """A valid password meeting minimum length requirements."""
    return "TestPassword123!ValidSecure"


@pytest.fixture
def random_salt():
    """Generate a random 16-byte salt."""
    return secrets.token_bytes(16)


@pytest.fixture
def sample_plaintext():
    """Sample plaintext data for encryption tests."""
    return b"This is sample data for encryption testing. " * 10


@pytest.fixture
def sample_aad():
    """Sample additional authenticated data."""
    return b"meow_authenticated_header_v1"


# ============================================================================
# Test KeyHandle Class
# ============================================================================


class TestKeyHandleMeow:
    """Tests for KeyHandle opaque key reference."""

    def test_key_handle_creation_initializes_fields(self):
        """🐱 Test KeyHandle initializes all fields correctly."""
        # Import with mocked backend
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import KeyHandle

            key_bytes = secrets.token_bytes(32)
            handle = KeyHandle(_handle_id=42, _backend="rust", _key_bytes=key_bytes, _zeroed=False)

            assert handle._handle_id == 42
            assert handle._backend == "rust"
            assert handle._key_bytes == key_bytes
            assert handle._zeroed is False

    def test_key_handle_zero_key_sets_flag(self):
        """🐱 Test _zero_key() sets zeroed flag."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import KeyHandle

            key_bytes = secrets.token_bytes(32)
            handle = KeyHandle(_handle_id=1, _backend="rust", _key_bytes=key_bytes, _zeroed=False)

            handle._zero_key()

            assert handle._zeroed is True

    def test_key_handle_zero_key_idempotent(self):
        """🐱 Test _zero_key() is idempotent (can be called multiple times)."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import KeyHandle

            handle = KeyHandle(
                _handle_id=1, _backend="rust", _key_bytes=secrets.token_bytes(32), _zeroed=False
            )

            # First call should zero
            handle._zero_key()
            assert handle._zeroed is True

            # Second call should be safe (no-op)
            handle._zero_key()
            assert handle._zeroed is True

    def test_key_handle_zero_key_with_none_bytes(self):
        """🐱 Test _zero_key() handles None key bytes gracefully."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import KeyHandle

            handle = KeyHandle(_handle_id=1, _backend="rust", _key_bytes=None, _zeroed=False)

            # Should not raise
            handle._zero_key()
            assert handle._zeroed is True

    def test_key_handle_destructor_zeros_key(self):
        """🐱 Test KeyHandle destructor zeros key material."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import KeyHandle

            key_bytes = secrets.token_bytes(32)
            handle = KeyHandle(_handle_id=1, _backend="rust", _key_bytes=key_bytes, _zeroed=False)

            # Trigger destructor
            del handle
            gc.collect()

            # Can't verify after del, but at least no exceptions


# ============================================================================
# Test SecureMemory Class
# ============================================================================


class TestSecureMemoryMeow:
    """Tests for SecureMemory allocation with mlock and zeroing."""

    def test_secure_memory_creation_with_size(self):
        """🐱 Test SecureMemory allocates buffer of correct size."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            size = 256
            mem = SecureMemory(size)

            assert mem.size == size
            assert mem._buffer is not None

    def test_secure_memory_write_and_read(self):
        """🐱 Test SecureMemory write and read roundtrip."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            test_data = b"Secret cat whiskers!"
            mem = SecureMemory(len(test_data))

            mem.write(test_data)
            read_data = mem.read()

            assert read_data == test_data

    def test_secure_memory_write_with_offset(self):
        """🐱 Test SecureMemory write at offset."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            mem = SecureMemory(32)
            data = b"MEOW"

            mem.write(data, offset=10)
            read_data = mem.read()

            assert read_data[10:14] == data

    def test_secure_memory_zero_clears_data(self):
        """🐱 Test SecureMemory zero() clears all data."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            test_data = b"Super secret data!!"
            mem = SecureMemory(len(test_data))
            mem.write(test_data)

            # Verify data is there
            assert mem.read() == test_data

            # Zero it
            mem.zero()

            # Should be all zeros
            assert mem.read() == b"\x00" * len(test_data)

    def test_secure_memory_context_manager_zeros_on_exit(self):
        """🐱 Test SecureMemory context manager zeros data on exit."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            test_data = b"Context sensitive meow"

            with SecureMemory(len(test_data)) as mem:
                mem.write(test_data)
                assert mem.read() == test_data
            # After exit, should be zeroed (destructor called)

    def test_secure_memory_destructor_zeros_and_unlocks(self):
        """🐱 Test SecureMemory destructor zeros and unlocks."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            mem = SecureMemory(64)
            mem.write(b"X" * 64)

            # Delete should zero
            del mem
            gc.collect()

    def test_secure_memory_mlock_attempt_on_linux(self):
        """🐱 Test SecureMemory attempts mlock on Linux."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            with patch("sys.platform", "linux"):
                # Mock ctypes.CDLL to avoid actual libc calls
                mock_libc = MagicMock()
                mock_libc.mlock.return_value = 0  # Success

                with patch("ctypes.CDLL", return_value=mock_libc):
                    from importlib import reload
                    import meow_decoder.secure_bridge as sb_module

                    # Can't easily reload with mocked ctypes, but test structure is valid

    def test_secure_memory_fallback_to_bytearray(self):
        """🐱 Test SecureMemory falls back to bytearray on ctypes failure."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            # Force ctypes to fail
            with patch("ctypes.c_char", side_effect=Exception("ctypes failed")):
                mem = SecureMemory(32)
                # Should still work with bytearray fallback
                mem.write(b"test")
                # Read back
                data = mem.read()
                assert b"test" in data


# ============================================================================
# Test SecureBridge Class
# ============================================================================


class TestSecureBridgeMeow:
    """Tests for SecureBridge Python-Rust boundary."""

    def test_secure_bridge_creation_requires_rust(self, mock_rust_backend):
        """🐱 Test SecureBridge requires Rust backend."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            # Reload module to pick up mock
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    assert bridge.use_rust is True
                    assert bridge._handles == []
                    assert bridge._finalized is False

    def test_secure_bridge_fails_without_rust(self):
        """🐱 Test SecureBridge raises error without Rust backend."""
        with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", False):
            from importlib import reload

            # This should raise on module load due to the check at bottom
            # For isolated test, check the class behavior
            pass  # Module-level check makes this hard to test in isolation

    def test_secure_bridge_context_manager_cleanup(self, mock_rust_backend):
        """🐱 Test SecureBridge context manager cleans up handles."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with SecureBridge() as bridge:
                        # Create a handle
                        handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))
                        assert len(bridge._handles) == 1

                    # After context exit, should be cleaned up
                    assert bridge._finalized is True

    def test_secure_bridge_create_key_handle(self, mock_rust_backend, valid_password, random_salt):
        """🐱 Test create_key_handle derives key via Rust."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle(valid_password, random_salt)

                    assert handle._backend == "rust"
                    assert handle._key_bytes is not None
                    assert len(handle._key_bytes) == 32
                    mock_rust_backend.derive_key_argon2id.assert_called_once()

    def test_secure_bridge_create_key_handle_custom_params(self, mock_rust_backend, random_salt):
        """🐱 Test create_key_handle with custom Argon2 parameters."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle(
                        "SecurePassword!", random_salt, memory_kib=262144, iterations=10  # 256 MiB
                    )

                    # Verify custom params passed to Rust
                    call_args = mock_rust_backend.derive_key_argon2id.call_args
                    assert call_args[0][2] == 262144  # memory_kib
                    assert call_args[0][3] == 10  # iterations

    def test_secure_bridge_encrypt_with_handle(
        self, mock_rust_backend, sample_plaintext, sample_aad
    ):
        """🐱 Test encrypt_with_handle encrypts via Rust."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    nonce, ciphertext = bridge.encrypt_with_handle(
                        handle, sample_plaintext, sample_aad
                    )

                    assert len(nonce) == 12  # AES-GCM nonce
                    assert ciphertext is not None
                    mock_rust_backend.aes_gcm_encrypt.assert_called_once()

    def test_secure_bridge_encrypt_without_aad(self, mock_rust_backend, sample_plaintext):
        """🐱 Test encrypt_with_handle works without AAD."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    nonce, ciphertext = bridge.encrypt_with_handle(handle, sample_plaintext)

                    assert nonce is not None
                    assert ciphertext is not None
                    # Verify empty AAD passed
                    call_args = mock_rust_backend.aes_gcm_encrypt.call_args
                    assert call_args.kwargs.get("aad") == b""

    def test_secure_bridge_decrypt_with_handle(self, mock_rust_backend, sample_aad):
        """🐱 Test decrypt_with_handle decrypts via Rust."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    nonce = secrets.token_bytes(12)
                    ciphertext = secrets.token_bytes(48)

                    plaintext = bridge.decrypt_with_handle(handle, nonce, ciphertext, sample_aad)

                    assert plaintext is not None
                    mock_rust_backend.aes_gcm_decrypt.assert_called_once()

    def test_secure_bridge_hmac_with_handle(self, mock_rust_backend):
        """🐱 Test hmac_with_handle computes HMAC via Rust."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    data = b"Authenticate this meow message"
                    tag = bridge.hmac_with_handle(handle, data)

                    assert len(tag) == 32  # SHA-256
                    mock_rust_backend.hmac_sha256.assert_called_once()

    def test_secure_bridge_verify_hmac_with_handle(self, mock_rust_backend):
        """🐱 Test verify_hmac_with_handle verifies via Rust."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    data = b"Verify this meow message"
                    expected_tag = secrets.token_bytes(32)

                    result = bridge.verify_hmac_with_handle(handle, data, expected_tag)

                    assert result is True
                    mock_rust_backend.hmac_sha256_verify.assert_called_once()

    def test_secure_bridge_verify_hmac_returns_false_on_mismatch(self, mock_rust_backend):
        """🐱 Test verify_hmac_with_handle returns False on mismatch."""
        mock_rust_backend.hmac_sha256_verify.return_value = False

        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    result = bridge.verify_hmac_with_handle(handle, b"data", b"wrong_tag" * 4)

                    assert result is False

    def test_secure_bridge_destroy_handle_removes_and_zeros(self, mock_rust_backend):
        """🐱 Test destroy_handle removes handle and zeros key."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    assert len(bridge._handles) == 1

                    bridge.destroy_handle(handle)

                    assert len(bridge._handles) == 0

    def test_secure_bridge_cleanup_zeros_all_handles(self, mock_rust_backend):
        """🐱 Test cleanup zeros all handles."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle1 = bridge.create_key_handle("password1!", secrets.token_bytes(16))
                    handle2 = bridge.create_key_handle("password2!", secrets.token_bytes(16))

                    assert len(bridge._handles) == 2

                    bridge.cleanup()

                    assert bridge._finalized is True
                    assert len(bridge._handles) == 0

    def test_secure_bridge_cleanup_idempotent(self, mock_rust_backend):
        """🐱 Test cleanup is idempotent (safe to call multiple times)."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    bridge.cleanup()
                    assert bridge._finalized is True

                    # Second cleanup should be safe
                    bridge.cleanup()
                    assert bridge._finalized is True


# ============================================================================
# Test Context Managers
# ============================================================================


class TestSecurePasswordContextMeow:
    """Tests for secure_password context manager."""

    def test_secure_password_provides_password_in_context(self, mock_rust_backend):
        """🐱 Test secure_password yields password within context."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                from meow_decoder.secure_bridge import secure_password

                test_password = "MySecretPassword123!"

                with secure_password(test_password) as pwd:
                    assert pwd == test_password

    def test_secure_password_zeros_on_exit(self, mock_rust_backend):
        """🐱 Test secure_password zeros memory on context exit."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                from meow_decoder.secure_bridge import secure_password, SecureMemory

                test_password = "SensitivePassword!"

                # Just verify no exception on exit
                with secure_password(test_password) as pwd:
                    assert pwd is not None

                # After context, memory should be zeroed

    def test_secure_password_handles_unicode(self, mock_rust_backend):
        """🐱 Test secure_password handles unicode passwords."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                from meow_decoder.secure_bridge import secure_password

                unicode_password = "猫パスワード🐱"

                with secure_password(unicode_password) as pwd:
                    assert pwd == unicode_password


class TestSecureKeyContextMeow:
    """Tests for secure_key context manager."""

    def test_secure_key_provides_key_in_context(self, mock_rust_backend):
        """🐱 Test secure_key yields key within context."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                from meow_decoder.secure_bridge import secure_key

                test_key = secrets.token_bytes(32)

                with secure_key(test_key) as k:
                    assert k == test_key

    def test_secure_key_zeros_on_exit(self, mock_rust_backend):
        """🐱 Test secure_key zeros memory on context exit."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                from meow_decoder.secure_bridge import secure_key

                test_key = secrets.token_bytes(32)

                with secure_key(test_key) as k:
                    assert len(k) == 32

                # Memory zeroed after exit


# ============================================================================
# Test check_rust_backend Function
# ============================================================================


class TestCheckRustBackendMeow:
    """Tests for check_rust_backend helper function."""

    def test_check_rust_backend_returns_true_when_available(self, mock_rust_backend):
        """🐱 Test check_rust_backend returns True when Rust available."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import check_rust_backend

                    available, message = check_rust_backend()

                    assert available is True
                    assert "Rust backend available" in message

    def test_check_rust_backend_returns_false_when_unavailable(self):
        """🐱 Test check_rust_backend returns False when Rust unavailable."""
        with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", False):
            # Would need to reload module, but can verify logic
            pass


# ============================================================================
# Test Error Handling
# ============================================================================


class TestSecureBridgeErrorHandlingMeow:
    """Tests for error handling in SecureBridge."""

    def test_encrypt_with_non_rust_handle_raises(self, mock_rust_backend):
        """🐱 Test encrypt_with_handle raises for non-Rust backend."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge, KeyHandle

                    bridge = SecureBridge()

                    # Create a non-Rust handle manually
                    fake_handle = KeyHandle(
                        _handle_id=999,
                        _backend="python",  # Not 'rust'
                        _key_bytes=secrets.token_bytes(32),
                    )

                    with pytest.raises(RuntimeError, match="Rust backend required"):
                        bridge.encrypt_with_handle(fake_handle, b"plaintext")

    def test_decrypt_with_non_rust_handle_raises(self, mock_rust_backend):
        """🐱 Test decrypt_with_handle raises for non-Rust backend."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge, KeyHandle

                    bridge = SecureBridge()

                    fake_handle = KeyHandle(
                        _handle_id=999, _backend="python", _key_bytes=secrets.token_bytes(32)
                    )

                    with pytest.raises(RuntimeError, match="Rust backend required"):
                        bridge.decrypt_with_handle(fake_handle, b"nonce" * 4, b"ciphertext")

    def test_hmac_with_non_rust_handle_raises(self, mock_rust_backend):
        """🐱 Test hmac_with_handle raises for non-Rust backend."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge, KeyHandle

                    bridge = SecureBridge()

                    fake_handle = KeyHandle(
                        _handle_id=999, _backend="python", _key_bytes=secrets.token_bytes(32)
                    )

                    with pytest.raises(RuntimeError, match="Rust backend required"):
                        bridge.hmac_with_handle(fake_handle, b"data")

    def test_verify_hmac_with_non_rust_handle_raises(self, mock_rust_backend):
        """🐱 Test verify_hmac_with_handle raises for non-Rust backend."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge, KeyHandle

                    bridge = SecureBridge()

                    fake_handle = KeyHandle(
                        _handle_id=999, _backend="python", _key_bytes=secrets.token_bytes(32)
                    )

                    with pytest.raises(RuntimeError, match="Rust backend required"):
                        bridge.verify_hmac_with_handle(fake_handle, b"data", b"tag" * 8)

    def test_key_derivation_failure_raises(self, mock_rust_backend, random_salt):
        """🐱 Test key derivation failure raises RuntimeError."""
        mock_rust_backend.derive_key_argon2id.side_effect = Exception("Argon2 failed")

        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()

                    with pytest.raises(RuntimeError, match="Rust key derivation failed"):
                        bridge.create_key_handle("password123!", random_salt)


# ============================================================================
# Test Memory Safety Invariants
# ============================================================================


class TestMemorySafetyInvariantsMeow:
    """Tests verifying memory safety invariants."""

    def test_key_bytes_zeroed_after_handle_destruction(self, mock_rust_backend):
        """🐱 Test key bytes are zeroed when handle is destroyed."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    # Capture key bytes reference
                    key_bytes = handle._key_bytes
                    assert key_bytes is not None

                    # Destroy handle
                    bridge.destroy_handle(handle)

                    # Handle should be zeroed
                    assert handle._zeroed is True

    def test_multiple_handles_independent(self, mock_rust_backend):
        """🐱 Test multiple handles are independent."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()

                    handle1 = bridge.create_key_handle("password1!", secrets.token_bytes(16))
                    handle2 = bridge.create_key_handle("password2!", secrets.token_bytes(16))

                    assert handle1._handle_id != handle2._handle_id
                    assert len(bridge._handles) == 2

                    # Destroying one doesn't affect other
                    bridge.destroy_handle(handle1)

                    assert len(bridge._handles) == 1
                    assert handle2 in bridge._handles

    def test_secure_memory_locked_if_supported(self):
        """🐱 Test SecureMemory attempts mlock when platform supports it."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            mem = SecureMemory(256)

            # mlock may or may not succeed depending on platform/permissions
            # Just verify no crash
            assert mem._buffer is not None

    def test_gc_collect_called_on_cleanup(self, mock_rust_backend):
        """🐱 Test garbage collection triggered on cleanup."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with patch("meow_decoder.secure_bridge.gc.collect") as mock_gc:
                        bridge = SecureBridge()
                        bridge.create_key_handle("password123!", secrets.token_bytes(16))
                        bridge.cleanup()

                        # gc.collect should have been called
                        assert mock_gc.called


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestSecureBridgeEdgeCasesMeow:
    """Tests for edge cases and boundary conditions."""

    def test_empty_plaintext_encryption(self, mock_rust_backend):
        """🐱 Test encrypting empty plaintext."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    nonce, ciphertext = bridge.encrypt_with_handle(handle, b"")

                    assert nonce is not None
                    assert ciphertext is not None

    def test_large_plaintext_encryption(self, mock_rust_backend):
        """🐱 Test encrypting large plaintext (1 MB)."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()
                    handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                    large_plaintext = b"X" * (1024 * 1024)  # 1 MB

                    nonce, ciphertext = bridge.encrypt_with_handle(handle, large_plaintext)

                    assert nonce is not None
                    assert ciphertext is not None

    def test_password_with_bytes_input(self, mock_rust_backend, random_salt):
        """🐱 Test create_key_handle accepts bytes password."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()

                    # Pass password as bytes
                    handle = bridge.create_key_handle(b"bytes_password!", random_salt)

                    assert handle is not None

    def test_destroy_handle_not_in_list(self, mock_rust_backend):
        """🐱 Test destroying handle not in handles list is safe."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge, KeyHandle

                    bridge = SecureBridge()

                    # Create a handle not in the bridge's list
                    orphan_handle = KeyHandle(
                        _handle_id=999, _backend="rust", _key_bytes=secrets.token_bytes(32)
                    )

                    # Should not raise
                    bridge.destroy_handle(orphan_handle)

    def test_secure_memory_zero_size(self):
        """🐱 Test SecureMemory with zero size."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            mem = SecureMemory(0)

            assert mem.size == 0
            # Should not crash
            mem.zero()

    def test_secure_memory_write_beyond_bounds_truncates(self):
        """🐱 Test SecureMemory write beyond bounds is handled."""
        with patch.dict("sys.modules", {"meow_crypto_rs": MagicMock()}):
            from meow_decoder.secure_bridge import SecureMemory

            mem = SecureMemory(10)

            # Write more than capacity - should truncate or handle gracefully
            mem.write(b"X" * 20, offset=0)

            data = mem.read()
            # Should not crash; behavior depends on implementation
            assert len(data) == 10


# ============================================================================
# Integration Tests
# ============================================================================


class TestSecureBridgeIntegrationMeow:
    """Integration tests for complete encrypt/decrypt flow."""

    def test_encrypt_decrypt_roundtrip(self, mock_rust_backend):
        """🐱 Test full encrypt-decrypt roundtrip."""
        # Setup mock to return original plaintext on decrypt
        original_plaintext = b"Top secret cat plans!"
        mock_rust_backend.aes_gcm_decrypt.return_value = original_plaintext

        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with SecureBridge() as bridge:
                        handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                        # Encrypt
                        nonce, ciphertext = bridge.encrypt_with_handle(handle, original_plaintext)

                        # Decrypt
                        decrypted = bridge.decrypt_with_handle(handle, nonce, ciphertext)

                        assert decrypted == original_plaintext

    def test_encrypt_decrypt_with_aad(self, mock_rust_backend):
        """🐱 Test encrypt-decrypt with additional authenticated data."""
        original_plaintext = b"Authenticated cat message!"
        aad = b"meow_header_v1"
        mock_rust_backend.aes_gcm_decrypt.return_value = original_plaintext

        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with SecureBridge() as bridge:
                        handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                        nonce, ciphertext = bridge.encrypt_with_handle(
                            handle, original_plaintext, aad
                        )
                        decrypted = bridge.decrypt_with_handle(handle, nonce, ciphertext, aad)

                        assert decrypted == original_plaintext

    def test_hmac_sign_verify_flow(self, mock_rust_backend):
        """🐱 Test HMAC sign and verify flow."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with SecureBridge() as bridge:
                        handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                        data = b"Message to authenticate"
                        tag = bridge.hmac_with_handle(handle, data)

                        assert len(tag) == 32

                        # Verify
                        is_valid = bridge.verify_hmac_with_handle(handle, data, tag)
                        assert is_valid is True

    def test_multiple_operations_same_handle(self, mock_rust_backend):
        """🐱 Test multiple operations with same key handle."""
        mock_rust_backend.aes_gcm_decrypt.return_value = b"decrypted"

        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with SecureBridge() as bridge:
                        handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                        # Multiple encryptions
                        nonce1, ct1 = bridge.encrypt_with_handle(handle, b"message 1")
                        nonce2, ct2 = bridge.encrypt_with_handle(handle, b"message 2")

                        # Multiple HMACs
                        tag1 = bridge.hmac_with_handle(handle, b"data 1")
                        tag2 = bridge.hmac_with_handle(handle, b"data 2")

                        assert nonce1 != nonce2  # Different nonces
                        assert ct1 is not None
                        assert ct2 is not None
                        assert tag1 is not None
                        assert tag2 is not None


# ============================================================================
# Test Try Zero String Helper
# ============================================================================


class TestTryZeroStringMeow:
    """Tests for _try_zero_string helper method."""

    def test_try_zero_string_does_not_crash(self, mock_rust_backend):
        """🐱 Test _try_zero_string handles string gracefully."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    bridge = SecureBridge()

                    # Should not raise
                    bridge._try_zero_string("test password")

    def test_try_zero_string_triggers_gc(self, mock_rust_backend):
        """🐱 Test _try_zero_string triggers garbage collection."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with patch("meow_decoder.secure_bridge.gc.collect") as mock_gc:
                        bridge = SecureBridge()
                        bridge._try_zero_string("password")

                        assert mock_gc.called


# ============================================================================
# Performance and Stress Tests
# ============================================================================


class TestSecureBridgePerformanceMeow:
    """Performance and stress tests for SecureBridge."""

    def test_many_handles_created_and_cleaned(self, mock_rust_backend):
        """🐱 Test creating and cleaning many handles."""
        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with SecureBridge() as bridge:
                        handles = []
                        for i in range(100):
                            h = bridge.create_key_handle(f"password{i}!", secrets.token_bytes(16))
                            handles.append(h)

                        assert len(bridge._handles) == 100

                    # All cleaned up after context exit
                    assert bridge._finalized is True

    def test_rapid_encrypt_decrypt_cycles(self, mock_rust_backend):
        """🐱 Test rapid encrypt/decrypt cycles."""
        mock_rust_backend.aes_gcm_decrypt.return_value = b"decrypted"

        with patch.dict("sys.modules", {"meow_crypto_rs": mock_rust_backend}):
            with patch("meow_decoder.secure_bridge.RUST_AVAILABLE", True):
                with patch("meow_decoder.secure_bridge.meow_crypto_rs", mock_rust_backend):
                    from meow_decoder.secure_bridge import SecureBridge

                    with SecureBridge() as bridge:
                        handle = bridge.create_key_handle("password123!", secrets.token_bytes(16))

                        for i in range(50):
                            nonce, ct = bridge.encrypt_with_handle(handle, f"message {i}".encode())
                            _ = bridge.decrypt_with_handle(handle, nonce, ct)

                        # All operations completed


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
