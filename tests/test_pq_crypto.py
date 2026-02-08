"""Tests for post-quantum cryptography modules."""

import pytest


class TestPQCryptoReal:
    def test_pq_crypto_real_import(self):
        try:
            from meow_decoder import pq_crypto_real

            assert pq_crypto_real is not None
        except ImportError:
            pytest.skip("pq_crypto_real module not available")


class TestPQHybrid:
    def test_pq_hybrid_import(self):
        try:
            from meow_decoder import pq_hybrid

            assert pq_hybrid is not None
        except ImportError:
            pytest.skip("pq_hybrid module not available")


class TestPQSignatures:
    def test_pq_signatures_import(self):
        try:
            from meow_decoder import pq_signatures

            assert pq_signatures is not None
        except ImportError:
            pytest.skip("pq_signatures module not available")
