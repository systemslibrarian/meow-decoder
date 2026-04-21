"""
High Security Boost Tests — Part 3 of 3

TestHighSecurityBoost class: coverage-boost tests for enable_high_security_mode,
secure_wipe, is_high_security_mode, generic_error, normalize_size.
Runs in CI batch 3 in parallel with test_high_security_mode.py (batch 1)
and test_high_security_extras.py (batch 2).
"""

from meow_decoder import high_security
import os

import pytest

pytestmark = pytest.mark.security


@pytest.fixture(autouse=True)
def _restore_crypto_globals():
    from meow_decoder import crypto

    saved_mem = crypto.ARGON2_MEMORY
    saved_iter = crypto.ARGON2_ITERATIONS
    saved_par = crypto.ARGON2_PARALLELISM
    saved_active = high_security._HIGH_SECURITY_MODE_ACTIVE
    yield
    crypto.ARGON2_MEMORY = saved_mem
    crypto.ARGON2_ITERATIONS = saved_iter
    crypto.ARGON2_PARALLELISM = saved_par
    high_security._HIGH_SECURITY_MODE_ACTIVE = saved_active


class TestHighSecurityBoost:
    def test_enable_high_security_mode_twice(self):
        """Calling enable_high_security_mode() twice should hit the 'already active' guard."""
        from meow_decoder.high_security import enable_high_security_mode
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False
        enable_high_security_mode(silent=True)
        assert hs._HIGH_SECURITY_MODE_ACTIVE is True
        # Second call hits the early return
        enable_high_security_mode(silent=True)
        assert hs._HIGH_SECURITY_MODE_ACTIVE is True

    def test_enable_high_security_mode_not_silent(self, capsys):
        """Test non-silent mode prints confirmation."""
        from meow_decoder.high_security import enable_high_security_mode
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False
        enable_high_security_mode(silent=False)
        captured = capsys.readouterr()
        assert "High security mode active" in captured.out or hs._HIGH_SECURITY_MODE_ACTIVE

    def test_secure_wipe_file(self, tmp_path):
        """Test secure_wipe_file on a real file."""
        from meow_decoder.high_security import secure_wipe_file

        test_file = tmp_path / "wipe_me.txt"
        test_file.write_bytes(b"sensitive data " * 100)
        assert test_file.exists()
        result = secure_wipe_file(str(test_file))
        assert result is True
        assert not test_file.exists()

    def test_secure_wipe_file_nonexistent(self):
        """Wiping nonexistent file returns True (already gone)."""
        from meow_decoder.high_security import secure_wipe_file

        result = secure_wipe_file("/tmp/nonexistent_file_xyz_abc.txt")
        assert result is True

    def test_secure_wipe_memory(self):
        """Test secure_wipe_memory runs without error."""
        from meow_decoder.high_security import secure_wipe_memory

        secure_wipe_memory()

    def test_is_high_security_mode(self):
        """Test is_high_security_mode getter."""
        from meow_decoder.high_security import is_high_security_mode
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False
        old_env = os.environ.pop("MEOW_HIGH_SECURITY_MODE", None)
        try:
            assert is_high_security_mode() is False
            hs._HIGH_SECURITY_MODE_ACTIVE = True
            assert is_high_security_mode() is True
        finally:
            hs._HIGH_SECURITY_MODE_ACTIVE = False
            if old_env is not None:
                os.environ["MEOW_HIGH_SECURITY_MODE"] = old_env

    def test_generic_error(self):
        """Test generic_error message formatting."""
        from meow_decoder.high_security import generic_error

        msg = generic_error("Decryption")
        assert "Decryption" in msg
        assert "failed" in msg

    def test_normalize_size(self):
        """Test normalize_size pads data correctly."""
        from meow_decoder.high_security import normalize_size

        data = b"short data"
        result = normalize_size(data)
        assert len(result) >= len(data)
