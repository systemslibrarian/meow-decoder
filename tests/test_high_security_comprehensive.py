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


def test_get_safety_checklist_contains_header():
    checklist = high_security.get_safety_checklist()
    assert "SAFETY CHECKLIST" in checklist


def test_secure_wipe_file_deletes(tmp_path):
    target = tmp_path / "secret.txt"
    target.write_bytes(b"top secret")
    assert target.exists()

    result = high_security.secure_wipe_file(target, passes=1)
    assert result is True
    assert not target.exists()
