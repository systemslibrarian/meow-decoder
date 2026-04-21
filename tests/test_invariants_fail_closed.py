"""
Fail-Closed Behavior Tests — Part 2 of 3

TestFailClosedBehavior: verify the system fails closed under attack or corruption.
Runs in CI batch 2 in parallel with test_invariants_critical.py (batch 1)
and test_invariants_regressions.py (batch 3).
"""

from meow_decoder.decode_gif import decode_gif
from meow_decoder.encode import encode_file
import secrets
import pytest

pytestmark = [pytest.mark.security, pytest.mark.slow]


class TestFailClosedBehavior:
    """Tests that verify fail-closed behavior under attack."""

    def test_fail_closed_corrupted_manifest(self, tmp_path):
        """System MUST fail closed on manifest corruption (via wrong password)."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Test")

        gif_file = tmp_path / "test.gif"
        encode_file(input_file, gif_file, "password")

        output_file = tmp_path / "output.txt"
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, "wrong_password")

    def test_fail_closed_truncated_data(self, tmp_path):
        """System MUST fail closed on truncated data."""
        input_file = tmp_path / "test.txt"
        input_file.write_text("Test data")

        gif_file = tmp_path / "test.gif"
        encode_file(input_file, gif_file, "password")

        gif_data = gif_file.read_bytes()
        truncated = gif_data[: len(gif_data) // 2]
        gif_file.write_bytes(truncated)

        output_file = tmp_path / "output.txt"
        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, "password")

    def test_fail_closed_empty_password(self):
        """Empty password MUST be rejected."""
        from meow_decoder.crypto import derive_key

        with pytest.raises(ValueError, match="Password cannot be empty"):
            derive_key("", secrets.token_bytes(16), None)
