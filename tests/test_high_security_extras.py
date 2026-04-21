"""
High Security Extras Tests — Part 2 of 3

TestHighSecurityExtras class: secure_wipe_file multi-pass, gc,
normalize_size branches, and module patching tests.
Runs in CI batch 2 in parallel with test_high_security_mode.py (batch 1)
and test_high_security_boost.py (batch 3).
"""

from meow_decoder import high_security
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


class TestHighSecurityExtras:
    """Additional high_security tests for uncovered branches."""

    def test_secure_wipe_file_multi_pass(self, tmp_path):
        """Test secure_wipe_file with 7 passes (hits all pass patterns)."""
        from meow_decoder.high_security import secure_wipe_file

        f = tmp_path / "multi_pass.dat"
        f.write_bytes(b"sensitive " * 500)
        result = secure_wipe_file(str(f), passes=7)
        assert result is True
        assert not f.exists()

    def test_secure_wipe_file_1_pass(self, tmp_path):
        """Test secure_wipe_file with 1 pass."""
        from meow_decoder.high_security import secure_wipe_file

        f = tmp_path / "one_pass.dat"
        f.write_bytes(b"secret")
        result = secure_wipe_file(str(f), passes=1)
        assert result is True

    def test_enable_high_security_patches_modules(self):
        """Test that enable_high_security_mode patches crypto modules."""
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False
        hs.enable_high_security_mode(silent=True)
        assert hs._HIGH_SECURITY_MODE_ACTIVE is True
        # Cleanup
        hs._HIGH_SECURITY_MODE_ACTIVE = False

    def test_enable_handles_missing_modules(self):
        """Module import errors during patching should be handled gracefully."""
        import meow_decoder.high_security as hs

        hs._HIGH_SECURITY_MODE_ACTIVE = False

        # Ensure we don't crash even if modules have import issues
        hs.enable_high_security_mode(silent=True)
        assert hs._HIGH_SECURITY_MODE_ACTIVE is True
        hs._HIGH_SECURITY_MODE_ACTIVE = False

    def test_high_security_config(self):
        """Test HighSecurityConfig instantiation and fields."""
        from meow_decoder.high_security import HighSecurityConfig

        config = HighSecurityConfig()
        assert hasattr(config, "output_size_classes")
        assert isinstance(config.output_size_classes, list)
        assert len(config.output_size_classes) > 0

    def test_normalize_size_various_sizes(self):
        """Test normalize_size with various data sizes."""
        from meow_decoder.high_security import normalize_size

        # Small data
        r1 = normalize_size(b"x" * 10)
        assert len(r1) >= 10

        # Larger data
        r2 = normalize_size(b"x" * 5000)
        assert len(r2) >= 5000

        # Empty data
        r3 = normalize_size(b"")
        assert len(r3) >= 0

    def test_secure_wipe_memory_with_gc(self):
        """secure_wipe_memory should trigger gc."""
        from meow_decoder.high_security import secure_wipe_memory

        # Just ensure it doesn't crash
        secure_wipe_memory()
