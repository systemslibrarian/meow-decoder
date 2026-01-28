"""
Pytest configuration for Meow Decoder tests.

Rust backend is required for all tests.
Test mode uses fast Argon2 parameters for CI speed.
"""

import os
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
