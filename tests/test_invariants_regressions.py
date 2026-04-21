"""
No-Regressions Tests — Part 3 of 3

TestNoRegressions: verify nonce randomness and compression haven't regressed.
Runs in CI batch 3 in parallel with test_invariants_critical.py (batch 1)
and test_invariants_fail_closed.py (batch 2).
"""

from meow_decoder.crypto import encrypt_file_bytes
import pytest

pytestmark = [pytest.mark.security, pytest.mark.slow]


class TestNoRegressions:
    """Tests that verify no regressions in core functionality."""

    def test_no_regression_nonce_randomness(self):
        """Verify nonce randomness hasn't regressed."""
        data = b"Test"
        password = "password"

        nonces = []
        for _ in range(5):
            _, _, _, nonce, _, _, _ = encrypt_file_bytes(data, password, None, None)
            nonces.append(nonce)

        unique_nonces = set(nonces)
        assert len(unique_nonces) == len(nonces), "Nonce collision detected!"

        nonce_bytes = b"".join(nonces)
        byte_counts = [nonce_bytes.count(bytes([i])) for i in range(256)]
        assert len(set(byte_counts)) > 2, "Nonce distribution suspicious"

    def test_no_regression_compression(self):
        """Verify compression still works."""
        compressible = b"A" * 10000

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            compressible, "password", None, None
        )

        compression_ratio = len(comp) / len(compressible)
        assert compression_ratio < 0.11, f"Compression regressed: {compression_ratio:.2%}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
