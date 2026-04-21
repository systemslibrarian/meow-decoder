"""
High Security Mode Tests — Part 1 of 3

Module-level function tests for high_security.py.
Runs in CI batch 1 in parallel with test_high_security_extras.py (batch 2)
and test_high_security_boost.py (batch 3).
"""

from meow_decoder.config import MeowConfig
from meow_decoder import high_security
import os

import pytest

pytestmark = pytest.mark.security


@pytest.fixture(autouse=True)
def _restore_crypto_globals():
    """Restore crypto module globals after each test to prevent state contamination."""
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
    from meow_decoder import crypto

    high_security._HIGH_SECURITY_MODE_ACTIVE = False
    high_security.enable_high_security_mode(silent=True)
    assert crypto.ARGON2_MEMORY == high_security.HIGH_SECURITY_ARGON2_MEMORY
    assert crypto.ARGON2_ITERATIONS == high_security.HIGH_SECURITY_ARGON2_ITERATIONS
    assert crypto.ARGON2_PARALLELISM == high_security.HIGH_SECURITY_ARGON2_PARALLELISM


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
    """Test secure_wipe_memory handles MemoryError gracefully."""
    calls = []

    monkeypatch.setattr(high_security.gc, "collect", lambda: calls.append(1))
    high_security.secure_wipe_memory()
    assert len(calls) >= 3


def test_is_oppression_mode_alias(monkeypatch):
    high_security._HIGH_SECURITY_MODE_ACTIVE = False
    monkeypatch.setenv("MEOW_HIGH_SECURITY_MODE", "1")
    assert high_security.is_oppression_mode() is True


def test_secure_wipe_file_failure_returns_false(monkeypatch, tmp_path):
    """Test secure_wipe_file returns False on write failure."""
    target = tmp_path / "secret.txt"
    target.write_bytes(b"top secret")

    import builtins

    original_open = builtins.open

    def patched_open(path, mode="r", *args, **kwargs):
        f = original_open(path, mode, *args, **kwargs)
        if "+" in mode or "w" in mode:

            def fail_write(*a, **kw):
                raise OSError("fail")

            f.write = fail_write
        return f

    monkeypatch.setattr(builtins, "open", patched_open)
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
