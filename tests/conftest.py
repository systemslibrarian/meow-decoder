"""
Pytest configuration for Meow Decoder tests.

Auto-enables Python fallback when Rust backend is not available.
This ensures tests can run in CI environments without Rust toolchain.
"""

import os
import pytest


def pytest_configure(config):
    """
    Configure test environment before collection.
    
    If Rust backend is unavailable, automatically enable Python fallback.
    This allows tests to run in environments without Rust toolchain.
    """
    try:
        import meow_crypto_rs
        # Rust is available - no fallback needed
        print("\n🦀 Rust crypto backend detected - using constant-time operations")
    except ImportError:
        # Rust not available - enable Python fallback for testing
        os.environ['MEOW_ALLOW_PYTHON_FALLBACK'] = '1'
        print("\n⚠️  Rust backend unavailable - using Python fallback for tests")
        print("   Build Rust: cd rust_crypto && maturin develop --release\n")


@pytest.fixture
def rust_backend_available():
    """Fixture to check if Rust backend is available."""
    try:
        import meow_crypto_rs
        return True
    except ImportError:
        return False


@pytest.fixture
def force_python_backend(monkeypatch):
    """Force Python backend for a specific test."""
    monkeypatch.setenv('MEOW_CRYPTO_BACKEND', 'python')
    monkeypatch.setenv('MEOW_ALLOW_PYTHON_FALLBACK', '1')
    
    # Reset the cached backend
    from meow_decoder import crypto_backend
    crypto_backend._default_backend = None
    
    yield
    
    # Cleanup
    crypto_backend._default_backend = None


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
