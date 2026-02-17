"""Tests for post-quantum cryptography modules."""

import pytest


class TestPQCryptoReal:
    def test_pq_crypto_real_quarantined(self):
        """pq_crypto_real is quarantined in legacy_py/ — importing from
        meow_decoder should fail (module removed from production)."""
        with pytest.raises((ImportError, ModuleNotFoundError, RuntimeError)):
            from meow_decoder import pq_crypto_real  # noqa: F401

    def test_pq_crypto_real_legacy_raises(self):
        """legacy_py/pq_crypto_real.py raises RuntimeError on import (FIX-D1)."""
        with pytest.raises(RuntimeError, match="DISABLED"):
            from legacy_py import pq_crypto_real  # noqa: F401


class TestPQHybrid:
    def test_pq_hybrid_import(self):
        try:
            from meow_decoder import pq_hybrid

            assert pq_hybrid is not None
        except ImportError:
            pytest.skip("pq_hybrid module not available")


class TestPQSignatures:
    def test_pq_signatures_experimental(self):
        """pq_signatures lives in experimental/ — not importable from top-level."""
        with pytest.raises((ImportError, ModuleNotFoundError)):
            from meow_decoder import pq_signatures  # noqa: F401

    def test_pq_signatures_experimental_import(self):
        """pq_signatures is importable from experimental/ path."""
        try:
            from meow_decoder.experimental import pq_signatures

            assert pq_signatures is not None
        except ImportError:
            pytest.skip("pq_signatures dependencies not available")
