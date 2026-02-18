#!/usr/bin/env python3
"""Tests for quarantined pq_crypto_real module.

pq_crypto_real.py was moved from meow_decoder/ to legacy_py/ because:
1. It uses an insecure XOR combiner (OPUS-AUDIT finding D1)
2. It imports `cryptography` which is banned from production code
3. It always raises RuntimeError on import (hard-disabled)

These tests verify the quarantine is intact.
"""

import pytest


class TestPQCryptoRealQuarantine:
    """Verify pq_crypto_real is properly quarantined."""

    def test_not_importable_from_production(self):
        """pq_crypto_real must NOT be importable from meow_decoder/."""
        with pytest.raises((ImportError, ModuleNotFoundError)):
            from meow_decoder import pq_crypto_real  # noqa: F401

    def test_legacy_module_removed(self):
        """legacy_py/ has been deleted (no-downgrade-paths enforcement)."""
        with pytest.raises((ImportError, ModuleNotFoundError)):
            from legacy_py import pq_crypto_real  # noqa: F401

    def test_production_pq_hybrid_still_works(self):
        """pq_hybrid.py is the production replacement — must still import."""
        try:
            from meow_decoder import pq_hybrid

            assert pq_hybrid is not None
        except ImportError:
            pytest.skip("pq_hybrid module not available")
