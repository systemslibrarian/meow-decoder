"""
Tests for Phase 5 security hardening modules.

Tests the following newly implemented modules:
- shamir_split.py: Shamir's Secret Sharing
- tamper_detection.py: Tamper detection + poisoning
- env_safety.py: Environment safety checks
- master_ratchet.py: Master key ratchet
- secure_keyboard.py: Secure password entry
- adversarial_carrier.py: Adversarial carrier noise

Run with: MEOW_TEST_MODE=1 pytest tests/test_phase5_modules.py -v
"""

import hashlib
import os
import platform
import secrets
import struct
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest


# ============================================================================
# Shamir Secret Sharing Tests
# ============================================================================


class TestShamirSplit:
    """Tests for shamir_split.py module."""

    def test_import(self):
        """Module should import without errors."""
        from meow_decoder import shamir_split
        assert hasattr(shamir_split, 'shamir_split')
        assert hasattr(shamir_split, 'shamir_combine')

    def test_basic_split_combine(self):
        """Basic (3,5) split and combine."""
        from meow_decoder.shamir_split import shamir_split, shamir_combine

        secret = b"test secret data for splitting"
        threshold = 3
        num_shares = 5

        shares = shamir_split(secret, threshold, num_shares)

        # Should have correct number of shares
        assert len(shares) == num_shares

        # Combine with exactly threshold shares
        recovered = shamir_combine(shares[:threshold], threshold)
        assert recovered == secret

    def test_any_threshold_shares_work(self):
        """Any threshold shares should recover the secret."""
        from meow_decoder.shamir_split import shamir_split, shamir_combine

        secret = b"another test secret"
        threshold = 3
        num_shares = 5

        shares = shamir_split(secret, threshold, num_shares)

        # Try different combinations
        import itertools
        for combo in itertools.combinations(range(num_shares), threshold):
            selected = [shares[i] for i in combo]
            recovered = shamir_combine(selected, threshold)
            assert recovered == secret, f"Failed for combo {combo}"

    def test_insufficient_shares_fail(self):
        """Fewer than threshold shares should not recover secret."""
        from meow_decoder.shamir_split import shamir_split, shamir_combine

        secret = b"secret123"
        threshold = 3

        shares = shamir_split(secret, threshold, 5)

        # Try with 2 shares (less than threshold)
        with pytest.raises(ValueError):
            shamir_combine(shares[:2], threshold)

    def test_empty_secret(self):
        """Empty secret should raise ValueError."""
        from meow_decoder.shamir_split import shamir_split

        with pytest.raises(ValueError):
            shamir_split(b"", 2, 3)

    def test_large_secret(self):
        """Large secrets should work (1 MB)."""
        from meow_decoder.shamir_split import shamir_split, shamir_combine

        secret = os.urandom(1024 * 1024)  # 1 MB
        shares = shamir_split(secret, 2, 3)
        recovered = shamir_combine(shares[:2], 2)
        assert recovered == secret

    def test_share_serialization(self):
        """Shares should serialize/deserialize correctly."""
        from meow_decoder.shamir_split import ShamirShare, shamir_split

        shares = shamir_split(b"test", 2, 3)

        for share in shares:
            serialized = share.to_bytes()
            restored = ShamirShare.from_bytes(serialized)
            assert restored.share_id == share.share_id
            assert restored.data == share.data
            assert restored.threshold == share.threshold

    def test_gf256_arithmetic(self):
        """GF(2^8) arithmetic should be correct."""
        from meow_decoder.shamir_split import _gf_mul, _gf_div, _gf_pow

        # Test multiplication identity
        for i in range(256):
            assert _gf_mul(i, 1) == i
            assert _gf_mul(1, i) == i

        # Test division inverse
        for i in range(1, 256):
            result = _gf_div(_gf_mul(42, i), i)
            assert result == 42

        # Test power
        assert _gf_pow(2, 0) == 1


# ============================================================================
# Tamper Detection Tests
# ============================================================================


class TestTamperDetection:
    """Tests for tamper_detection.py module."""

    def test_import(self):
        """Module should import without errors."""
        from meow_decoder import tamper_detection
        assert hasattr(tamper_detection, 'TamperDetector')
        assert hasattr(tamper_detection, 'TamperState')

    def test_baseline_initialization(self):
        """Baseline should initialize correctly."""
        from meow_decoder.tamper_detection import TamperDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            checkpoint = Path(tmpdir) / "state"
            detector = TamperDetector(
                checkpoint_file=checkpoint,
                auto_initialize=True,
            )

            assert detector.state is not None
            assert len(detector.state.baseline_hashes) > 0
            assert checkpoint.exists()

    def test_integrity_check_passes(self):
        """Integrity check should pass when nothing modified."""
        from meow_decoder.tamper_detection import TamperDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            detector = TamperDetector(
                checkpoint_file=Path(tmpdir) / "state",
            )

            ok, tampered = detector.check_integrity()
            assert ok or len(tampered) == 0  # May be ok or empty

    def test_poison_output_length(self):
        """Poison output should match requested length."""
        from meow_decoder.tamper_detection import silent_poison_bytes

        for length in [0, 1, 100, 1000, 65536]:
            result = silent_poison_bytes(length)
            assert len(result) == length

    def test_poison_deterministic(self):
        """Poison output should be deterministic with seed."""
        from meow_decoder.tamper_detection import silent_poison_bytes

        seed = b"test_seed"
        result1 = silent_poison_bytes(100, seed)
        result2 = silent_poison_bytes(100, seed)
        assert result1 == result2

    def test_poison_different_without_seed(self):
        """Poison output should be random without seed."""
        from meow_decoder.tamper_detection import silent_poison_bytes

        result1 = silent_poison_bytes(100)
        result2 = silent_poison_bytes(100)
        assert result1 != result2  # Overwhelmingly likely

    def test_state_serialization(self):
        """TamperState should serialize/deserialize correctly."""
        from meow_decoder.tamper_detection import TamperState

        state = TamperState(
            baseline_hashes={"test.py": "abc123"},
            baseline_timestamp=time.time(),
            tamper_count=0,
        )

        # to_bytes uses internal state_key
        serialized = state.to_bytes()
        restored = TamperState.from_bytes(serialized)

        assert restored is not None
        assert restored.baseline_hashes == state.baseline_hashes
        assert restored.tamper_count == state.tamper_count

    def test_state_tampered_fails(self):
        """Tampering with serialized state should fail."""
        from meow_decoder.tamper_detection import TamperState

        state = TamperState()

        serialized = state.to_bytes()
        # Tamper with the data
        tampered = bytearray(serialized)
        if len(tampered) > 50:
            tampered[50] ^= 0xFF  # Flip bits
        restored = TamperState.from_bytes(bytes(tampered))

        # Should fail due to HMAC mismatch
        assert restored is None


# ============================================================================
# Environment Safety Tests
# ============================================================================


class TestEnvSafety:
    """Tests for env_safety.py module."""

    def test_import(self):
        """Module should import without errors."""
        from meow_decoder import env_safety
        assert hasattr(env_safety, 'EnvironmentSafety')
        assert hasattr(env_safety, 'SafetyReport')

    def test_basic_check(self):
        """Basic safety check should return report."""
        from meow_decoder.env_safety import EnvironmentSafety

        safety = EnvironmentSafety()
        report = safety.check_all()

        assert report is not None
        assert hasattr(report, 'is_safe')
        assert hasattr(report, 'risks')
        assert report.checks_performed > 0

    def test_risk_category_enum(self):
        """Risk categories should be defined."""
        from meow_decoder.env_safety import RiskCategory

        assert RiskCategory.VIRTUAL_MACHINE
        assert RiskCategory.DEBUGGER
        assert RiskCategory.SCREEN_RECORDER

    def test_report_add_risk(self):
        """Adding risks should update report."""
        from meow_decoder.env_safety import SafetyReport, Risk, RiskCategory

        report = SafetyReport(is_safe=True)
        assert report.is_safe

        report.add_risk(Risk(
            category=RiskCategory.DEBUGGER,
            description="Test risk",
            severity="high",
        ))

        assert not report.is_safe
        assert len(report.risks) == 1

    def test_cache_invalidation(self):
        """Cache should be invalidatable."""
        from meow_decoder.env_safety import EnvironmentSafety

        safety = EnvironmentSafety()
        report1 = safety.check_all()
        report2 = safety.check_all(use_cache=True)

        assert report1 is report2  # Same cached object

        safety.invalidate_cache()
        report3 = safety.check_all()

        assert report1 is not report3  # New object

    @pytest.mark.skipif(
        platform.system() != "Linux",
        reason="Linux-specific test"
    )
    def test_linux_ptrace_check(self):
        """Linux ptrace check should not raise."""
        from meow_decoder.env_safety import EnvironmentSafety

        safety = EnvironmentSafety()
        report = safety.check_all()
        # Should complete without error
        assert report.checks_performed > 0


# ============================================================================
# Master Ratchet Tests
# ============================================================================


class TestMasterRatchet:
    """Tests for master_ratchet.py module."""

    def test_import(self):
        """Module should import without errors."""
        from meow_decoder import master_ratchet
        assert hasattr(master_ratchet, 'MasterRatchet')
        assert hasattr(master_ratchet, 'ChainState')

    def test_create_from_password(self):
        """Ratchet should create from password."""
        from meow_decoder.master_ratchet import MasterRatchet

        ratchet = MasterRatchet.from_password(
            "test_password",
            auto_persist=False,
        )

        assert ratchet.generation == 0
        assert ratchet._state.chain_key != bytes(32)

    def test_ratchet_forward(self):
        """Ratcheting should advance generation."""
        from meow_decoder.master_ratchet import MasterRatchet

        ratchet = MasterRatchet.from_password("test", auto_persist=False)

        old_key = ratchet._state.chain_key
        old_gen = ratchet.generation

        ratchet.ratchet()

        assert ratchet.generation == old_gen + 1
        assert ratchet._state.chain_key != old_key

    def test_file_key_derivation(self):
        """File keys should be derivable."""
        from meow_decoder.master_ratchet import MasterRatchet

        ratchet = MasterRatchet.from_password("test", auto_persist=False)

        key1 = ratchet.derive_file_key("file1.pdf")
        key2 = ratchet.derive_file_key("file2.pdf")

        assert len(key1) == 32
        assert len(key2) == 32
        assert key1 != key2

    def test_same_file_same_key(self):
        """Same file ID at same generation should give same key."""
        from meow_decoder.master_ratchet import MasterRatchet

        ratchet = MasterRatchet.from_password("test", auto_persist=False)

        key1 = ratchet.derive_file_key("same_file")
        key2 = ratchet.derive_file_key("same_file")

        assert key1 == key2

    def test_ratchet_changes_file_keys(self):
        """Ratcheting should change derived file keys."""
        from meow_decoder.master_ratchet import MasterRatchet

        ratchet = MasterRatchet.from_password("test", auto_persist=False)

        key_before = ratchet.derive_file_key("file.pdf")
        ratchet.ratchet()
        key_after = ratchet.derive_file_key("file.pdf")

        assert key_before != key_after

    def test_key_commitment(self):
        """Key commitment should be derivable."""
        from meow_decoder.master_ratchet import MasterRatchet

        ratchet = MasterRatchet.from_password("test", auto_persist=False)

        key, commitment = ratchet.derive_file_key_with_commitment("file.pdf")

        assert len(key) == 32
        assert len(commitment) == 16

    def test_emergency_wipe(self):
        """Emergency wipe should zero state."""
        from meow_decoder.master_ratchet import MasterRatchet

        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state"
            ratchet = MasterRatchet.from_password(
                "test",
                state_file=state_file,
                auto_persist=True,
            )

            # Save to file
            ratchet._save_state()
            assert state_file.exists()

            # Wipe
            result = ratchet.emergency_wipe()

            assert result
            assert not state_file.exists()
            assert ratchet._state.chain_key == bytes(32)

    def test_save_load_roundtrip(self):
        """State should save and load correctly."""
        from meow_decoder.master_ratchet import MasterRatchet

        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state"
            password = "test_password_123"

            # Create and ratchet
            ratchet1 = MasterRatchet.from_password(
                password,
                state_file=state_file,
                auto_persist=True,
            )
            ratchet1.ratchet()
            ratchet1.ratchet()

            file_key_1 = ratchet1.derive_file_key("test")
            gen_1 = ratchet1.generation

            # Load
            ratchet2 = MasterRatchet.load(password, state_file)

            assert ratchet2 is not None
            assert ratchet2.generation == gen_1
            assert ratchet2.derive_file_key("test") == file_key_1


# ============================================================================
# Secure Keyboard Tests
# ============================================================================


class TestSecureKeyboard:
    """Tests for secure_keyboard.py module."""

    def test_import(self):
        """Module should import without errors."""
        from meow_decoder import secure_keyboard
        assert hasattr(secure_keyboard, 'SecureKeyboard')
        assert hasattr(secure_keyboard, 'SecureString')

    def test_secure_string_operations(self):
        """SecureString basic operations."""
        from meow_decoder.secure_keyboard import SecureString

        s = SecureString()
        s.append_char('a')
        s.append_char('b')
        s.append_char('c')

        assert s.get_value() == 'abc'
        assert len(s) == 3

    def test_secure_string_backspace(self):
        """SecureString backspace."""
        from meow_decoder.secure_keyboard import SecureString

        s = SecureString()
        s.append_char('a')
        s.append_char('b')
        s.backspace()

        assert s.get_value() == 'a'

    def test_secure_string_clear(self):
        """SecureString clear."""
        from meow_decoder.secure_keyboard import SecureString

        s = SecureString()
        s.append_char('s')
        s.append_char('e')
        s.append_char('c')
        s.append_char('r')
        s.append_char('e')
        s.append_char('t')

        s.clear()
        assert s.get_value() == ''
        assert len(s) == 0

    def test_timing_normalized_input_exists(self):
        """timing_normalized_input function should exist."""
        from meow_decoder.secure_keyboard import timing_normalized_input
        assert callable(timing_normalized_input)

    def test_keyboard_layout_generation(self):
        """Keyboard layout should generate."""
        from meow_decoder.secure_keyboard import SecureKeyboard

        kb = SecureKeyboard(randomize_layout=True)
        layout = kb._generate_layout()

        assert len(layout) == 4  # 4 rows
        for row in layout:
            assert len(row) > 0

    def test_decoy_mask_generation(self):
        """Decoy mask should generate."""
        from meow_decoder.secure_keyboard import SecureKeyboard

        kb = SecureKeyboard(decoy_chars=True, mask_char="●")

        mask = kb._generate_decoy_mask(5)
        assert len(mask) >= 5  # May have extra decoys


# ============================================================================
# Adversarial Carrier Tests
# ============================================================================


class TestAdversarialCarrier:
    """Tests for adversarial_carrier.py module."""

    def test_import(self):
        """Module should import without errors."""
        from meow_decoder import adversarial_carrier
        assert hasattr(adversarial_carrier, 'AdversarialNoiseGenerator')
        assert hasattr(adversarial_carrier, 'generate_carrier_noise')

    def test_seeded_rng_determinism(self):
        """Seeded RNG should be deterministic."""
        from meow_decoder.adversarial_carrier import SeededRNG

        rng1 = SeededRNG(b"test_seed")
        rng2 = SeededRNG(b"test_seed")

        assert rng1.random_bytes(100) == rng2.random_bytes(100)

    def test_seeded_rng_different_seeds(self):
        """Different seeds should give different output."""
        from meow_decoder.adversarial_carrier import SeededRNG

        rng1 = SeededRNG(b"seed1")
        rng2 = SeededRNG(b"seed2")

        assert rng1.random_bytes(100) != rng2.random_bytes(100)

    def test_gaussian_distribution(self):
        """Gaussian random should have correct distribution."""
        from meow_decoder.adversarial_carrier import SeededRNG

        rng = SeededRNG(b"test")
        samples = [rng.random_gaussian(0, 1) for _ in range(1000)]

        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)

        # Should be close to N(0, 1)
        assert abs(mean) < 0.2
        assert abs(variance - 1.0) < 0.3

    def test_sensor_noise_dimensions(self):
        """Sensor noise should have correct dimensions."""
        from meow_decoder.adversarial_carrier import generate_sensor_noise

        width, height = 100, 50
        noise = generate_sensor_noise(width, height)

        assert len(noise) == height
        assert all(len(row) == width for row in noise)

    def test_texture_noise_dimensions(self):
        """Texture noise should have correct dimensions."""
        from meow_decoder.adversarial_carrier import generate_texture_noise

        width, height = 100, 50
        noise = generate_texture_noise(width, height)

        assert len(noise) == height
        assert all(len(row) == width for row in noise)

    def test_carrier_noise_integer_output(self):
        """Carrier noise should produce integer values."""
        from meow_decoder.adversarial_carrier import generate_carrier_noise

        noise = generate_carrier_noise(50, 50)

        for row in noise:
            for value in row:
                assert isinstance(value, int)
                assert -128 <= value <= 127

    def test_chi_square_test_function(self):
        """Chi-square test should compute statistic."""
        from meow_decoder.adversarial_carrier import chi_square_test

        # Uniform data should have low chi-square
        uniform_data = list(range(256)) * 10
        chi2_uniform = chi_square_test(uniform_data)

        # Biased data should have higher chi-square
        biased_data = [0] * 1000 + [1] * 100
        chi2_biased = chi_square_test(biased_data)

        assert chi2_biased > chi2_uniform

    def test_histogram_equalization(self):
        """Histogram equalization should work."""
        from meow_decoder.adversarial_carrier import AdversarialNoiseGenerator

        gen = AdversarialNoiseGenerator()
        noise = gen.generate_sensor_noise(50, 50)
        equalized = gen.histogram_equalize(noise)

        assert len(equalized) == len(noise)
        assert len(equalized[0]) == len(noise[0])


# ============================================================================
# Integration Tests
# ============================================================================


class TestPhase5Integration:
    """Integration tests for Phase 5 modules working together."""

    def test_shamir_with_encryption_key(self):
        """Shamir should work with encryption-derived keys."""
        from meow_decoder.shamir_split import shamir_split, shamir_combine
        from meow_decoder.master_ratchet import MasterRatchet

        # Derive key from ratchet
        ratchet = MasterRatchet.from_password("test", auto_persist=False)
        file_key = ratchet.derive_file_key("secret.gif")

        # Split the key
        shares = shamir_split(file_key, 3, 5)

        # Recover
        recovered = shamir_combine(shares[:3], 3)
        assert recovered == file_key

    def test_tamper_with_env_safety(self):
        """Tamper detection and env safety should work together."""
        from meow_decoder.tamper_detection import get_tamper_detector
        from meow_decoder.env_safety import get_environment_safety

        # Both should be usable
        detector = get_tamper_detector()
        safety = get_environment_safety()

        # Check both
        tampered = detector.is_tampered()
        report = safety.check_all()

        # Should complete without error
        assert isinstance(tampered, bool)
        assert hasattr(report, 'is_safe')

    def test_ratchet_emergency_wipe_sequence(self):
        """Emergency wipe should work in sequence."""
        from meow_decoder.master_ratchet import (
            MasterRatchet,
            set_master_ratchet,
            emergency_wipe_chain,
        )

        ratchet = MasterRatchet.from_password("test", auto_persist=False)
        set_master_ratchet(ratchet)

        # Derive some keys
        key1 = ratchet.derive_file_key("file1")
        ratchet.ratchet()
        key2 = ratchet.derive_file_key("file2")

        # Emergency wipe
        result = emergency_wipe_chain()
        assert result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
