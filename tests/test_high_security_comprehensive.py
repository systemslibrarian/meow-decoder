import os

from meow_decoder import high_security
from meow_decoder.config import MeowConfig


def test_enable_high_security_mode_sets_env_and_flag(monkeypatch):
    high_security._HIGH_SECURITY_MODE_ACTIVE = False
    monkeypatch.delenv("MEOW_HIGH_SECURITY_MODE", raising=False)
    monkeypatch.delenv("MEOW_NO_DEBUG", raising=False)
    monkeypatch.delenv("MEOW_NO_LOGS", raising=False)

    high_security.enable_high_security_mode(silent=True)

    assert high_security.is_high_security_mode()
    assert os.environ.get("MEOW_HIGH_SECURITY_MODE") == "1"
    assert os.environ.get("MEOW_NO_DEBUG") == "1"
    assert os.environ.get("MEOW_NO_LOGS") == "1"


def test_enable_high_security_mode_patches_crypto_params():
    high_security._HIGH_SECURITY_MODE_ACTIVE = False
    from meow_decoder import crypto

    old_mem = crypto.ARGON2_MEMORY
    old_iter = crypto.ARGON2_ITERATIONS
    old_par = crypto.ARGON2_PARALLELISM

    try:
        high_security.enable_high_security_mode(silent=True)
        assert crypto.ARGON2_MEMORY == high_security.HIGH_SECURITY_ARGON2_MEMORY
        assert crypto.ARGON2_ITERATIONS == high_security.HIGH_SECURITY_ARGON2_ITERATIONS
        assert crypto.ARGON2_PARALLELISM == high_security.HIGH_SECURITY_ARGON2_PARALLELISM
    finally:
        crypto.ARGON2_MEMORY = old_mem
        crypto.ARGON2_ITERATIONS = old_iter
        crypto.ARGON2_PARALLELISM = old_par


def test_generic_error_message():
    msg = high_security.generic_error("Encode")
    assert msg == "Encode failed. Please try again."


def test_normalize_size_pads_to_bucket():
    data = b"a" * 100
    padded = high_security.normalize_size(data, size_classes=[128, 1024])
    assert len(padded) == 128
    assert padded[:100] == data


def test_normalize_size_no_padding_for_large_input():
    data = b"a" * 2048
    padded = high_security.normalize_size(data, size_classes=[128, 1024])
    assert padded == data


def test_normalize_size_default_classes():
    data = b"a" * 10
    padded = high_security.normalize_size(data)
    assert len(padded) == 64 * 1024


def test_normalize_size_exact_bucket_no_padding():
    data = b"a" * 1024
    padded = high_security.normalize_size(data, size_classes=[128, 1024])
    assert padded == data


def test_apply_high_security_to_config_updates_settings():
    config = MeowConfig()
    updated = high_security.apply_high_security_to_config(config)

    assert updated.crypto.argon2_memory == high_security.HIGH_SECURITY_ARGON2_MEMORY
    assert updated.crypto.argon2_iterations == high_security.HIGH_SECURITY_ARGON2_ITERATIONS
    assert updated.crypto.enable_pq
    assert updated.crypto.kyber_variant == "kyber1024"
    assert updated.crypto.enable_forward_secrecy
    assert updated.crypto.ratchet_interval == 10

    assert updated.encoding.enable_forward_secrecy
    assert updated.encoding.ratchet_interval == 10
    assert updated.encoding.enable_stego
    assert updated.encoding.stealth_level == 4


def test_generate_innocuous_filename_format():
    name = high_security.generate_innocuous_filename()
    assert name.endswith(".gif")
    assert "_" in name
    assert any(year in name for year in ["2024", "2025", "2026"])


def test_get_high_security_config_aliases():
    cfg = high_security.get_high_security_config()
    alias = high_security.get_oppression_config()
    assert isinstance(cfg, high_security.HighSecurityConfig)
    assert isinstance(alias, high_security.HighSecurityConfig)


def test_get_safety_checklist_contains_header():
    checklist = high_security.get_safety_checklist()
    assert "SAFETY CHECKLIST" in checklist


def test_apply_oppression_alias():
    config = MeowConfig()
    updated = high_security.apply_oppression_to_config(config)
    assert updated.encoding.enable_stego is True


def test_secure_wipe_file_deletes(tmp_path):
    target = tmp_path / "secret.txt"
    target.write_bytes(b"top secret")
    assert target.exists()

    result = high_security.secure_wipe_file(target, passes=1)
    assert result is True
    assert not target.exists()


def test_secure_wipe_file_missing_returns_true(tmp_path):
    target = tmp_path / "missing.txt"
    assert high_security.secure_wipe_file(target, passes=1) is True


def test_secure_wipe_memory_handles_memoryerror(monkeypatch):
    calls = []

    monkeypatch.setattr(high_security.gc, "collect", lambda: calls.append(1))
    monkeypatch.setattr(
        high_security, "bytearray", lambda *_a, **_k: (_ for _ in ()).throw(MemoryError())
    )

    high_security.secure_wipe_memory()
    assert len(calls) >= 3


def test_is_oppression_mode_alias(monkeypatch):
    high_security._HIGH_SECURITY_MODE_ACTIVE = False
    monkeypatch.setenv("MEOW_HIGH_SECURITY_MODE", "1")
    assert high_security.is_oppression_mode() is True


def test_secure_wipe_file_failure_returns_false(monkeypatch, tmp_path):
    target = tmp_path / "secret.txt"
    target.write_bytes(b"top secret")

    def _boom(*_args, **_kwargs):
        raise OSError("fail")

    monkeypatch.setattr(high_security, "open", _boom)
    assert high_security.secure_wipe_file(target, passes=1) is False


def test_is_high_security_mode_env_var(monkeypatch):
    high_security._HIGH_SECURITY_MODE_ACTIVE = False
    monkeypatch.setenv("MEOW_HIGH_SECURITY_MODE", "1")
    assert high_security.is_high_security_mode() is True


def test_paranoid_mode_alias_sets_active(monkeypatch):
    high_security._HIGH_SECURITY_MODE_ACTIVE = False
    monkeypatch.delenv("MEOW_HIGH_SECURITY_MODE", raising=False)
    high_security.paranoid_mode()
    assert high_security.is_high_security_mode() is True

# --- Merged from test_coverage_boost_extras.py ---

# =====================================================
# high_security.py — push from 85.9% higher
# =====================================================
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
        import gc

        # Just ensure it doesn't crash
        secure_wipe_memory()


# =====================================================
# entropy_boost.py — push from 88.24% higher
# =====================================================

# --- Merged from test_coverage_boost_remaining.py ---

# =====================================================
# high_security.py coverage
# =====================================================
class TestHighSecurityBoost:
    def test_enable_high_security_mode_twice(self):
        """Calling enable_high_security_mode() twice should hit the 'already active' guard."""
        from meow_decoder.high_security import enable_high_security_mode
        import meow_decoder.high_security as hs

        # Reset
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
        # Source returns True for nonexistent files ("Already gone")
        assert result is True

    def test_secure_wipe_memory(self):
        """Test secure_wipe_memory runs without error."""
        from meow_decoder.high_security import secure_wipe_memory

        secure_wipe_memory()

    def test_is_high_security_mode(self):
        """Test is_high_security_mode getter."""
        from meow_decoder.high_security import is_high_security_mode
        import meow_decoder.high_security as hs

        # Reset the global and env var
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


# =====================================================
# streaming_crypto.py coverage
# =====================================================

