"""
Pytest configuration for Meow Decoder tests.

Rust backend is required for all tests.
Test mode uses fast Argon2 parameters for CI speed.
"""

import os
import secrets
import tempfile
from pathlib import Path

import pytest

# Enable test mode for fast Argon2 parameters BEFORE importing meow_decoder modules
os.environ["MEOW_TEST_MODE"] = "1"


def pytest_configure(config):
    """Ensure Rust backend is available for tests."""
    try:
        import meow_crypto_rs
        print("\n🦀 Rust crypto backend detected - using constant-time operations")
    except ImportError:
        pytest.exit(
            "Rust crypto backend required for tests. Build with: "
            "cd rust_crypto && maturin develop --release",
            returncode=1,
        )


@pytest.fixture
def rust_backend_available():
    """Fixture to check if Rust backend is available."""
    try:
        import meow_crypto_rs
        return True
    except ImportError:
        return False


@pytest.fixture
def force_rust_backend(monkeypatch, rust_backend_available):
    """Force Rust backend for a specific test (skip if unavailable)."""
    if not rust_backend_available:
        pytest.skip("Rust backend not available")
    
    monkeypatch.setenv('MEOW_CRYPTO_BACKEND', 'rust')
    
    # Reset the cached backend
    from meow_decoder import crypto_backend
    crypto_backend._default_backend = None
    
    yield
    
    # Cleanup
    crypto_backend._default_backend = None


# ===== Security Test Fixtures =====

@pytest.fixture
def random_salt():
    """Generate a random 16-byte salt."""
    return secrets.token_bytes(16)


@pytest.fixture
def random_nonce():
    """Generate a random 12-byte nonce for AES-GCM."""
    return secrets.token_bytes(12)


@pytest.fixture
def valid_password():
    """A valid password meeting minimum length requirements."""
    return "TestPassword123!ValidSecure"


@pytest.fixture
def short_password():
    """A password that is too short (for negative testing)."""
    return "short"


@pytest.fixture
def random_key():
    """Generate a random 32-byte encryption key."""
    return secrets.token_bytes(32)


@pytest.fixture
def sample_plaintext():
    """Sample plaintext data for encryption tests."""
    return b"This is sample data for encryption testing. " * 10


@pytest.fixture
def sample_file(tmp_path):
    """Create a sample file for encode/decode tests."""
    file_path = tmp_path / "sample.txt"
    content = b"Sample file content for testing." * 100
    file_path.write_bytes(content)
    return file_path


@pytest.fixture
def temp_directory():
    """Create a temporary directory that is cleaned up after test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def keyfile(tmp_path):
    """Create a valid keyfile for testing."""
    keyfile_path = tmp_path / "test.keyfile"
    keyfile_path.write_bytes(secrets.token_bytes(64))
    return keyfile_path


@pytest.fixture
def invalid_keyfile(tmp_path):
    """Create an invalid (too small) keyfile for negative testing."""
    keyfile_path = tmp_path / "invalid.keyfile"
    keyfile_path.write_bytes(b"too short")  # Less than 32 bytes
    return keyfile_path
