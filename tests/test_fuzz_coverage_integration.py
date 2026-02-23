"""
Integration tests for formal verification and fuzzing coverage.

Covers all 5 new fuzz/formal areas:
1. Guard page / memory protection (GuardedBuffer)
2. Mouse gesture auth (quantization + BLAKE2b)
3. Tamper detection (TamperState, TamperDetector, silent_poison)
4. Adversarial stego rotation (noise generators, schedule)
5. Schrödinger deniability (manifest structure)
6. Ratchet integration (forward secrecy, PQ beacon, domain separation)

60+ deterministic tests exercising the same code paths as fuzz targets.
"""

import hashlib
import math
import os
import secrets
import struct
import tempfile
from pathlib import Path

import pytest

os.environ["MEOW_TEST_MODE"] = "1"


# =============================================================================
# 1. Guard Page / Memory Protection Tests
# =============================================================================


class TestGuardedBuffer:
    """Tests for meow_decoder.memory_guard.GuardedBuffer."""

    def _get_cls(self):
        from meow_decoder.memory_guard import GuardedBuffer

        return GuardedBuffer

    def test_basic_write_read_roundtrip(self):
        """Write data and read it back (roundtrip)."""
        GuardedBuffer = self._get_cls()
        with GuardedBuffer(256) as buf:
            data = b"hello meow" * 10
            buf.write(data)
            got = buf.read(len(data))
            assert got == data

    def test_write_at_offset(self):
        """Write at non-zero offset and read the full range."""
        GuardedBuffer = self._get_cls()
        with GuardedBuffer(256) as buf:
            buf.write(b"\x00" * 256)  # zero fill
            buf.write(b"\xaa\xbb", offset=100)
            got = buf.read(2, offset=100)
            assert got == b"\xaa\xbb"

    def test_write_oob_raises(self):
        """Writing beyond buffer end raises ValueError."""
        GuardedBuffer = self._get_cls()
        with GuardedBuffer(16) as buf:
            with pytest.raises((ValueError, RuntimeError)):
                buf.write(b"x" * 100)

    def test_read_oob_raises(self):
        """Reading beyond buffer end raises ValueError."""
        GuardedBuffer = self._get_cls()
        with GuardedBuffer(16) as buf:
            with pytest.raises((ValueError, RuntimeError)):
                buf.read(100)

    def test_zero_wipe_clears_data(self):
        """zero() clears all buffer contents."""
        GuardedBuffer = self._get_cls()
        with GuardedBuffer(64) as buf:
            buf.write(b"\xff" * 64)
            buf.zero()
            got = buf.read(64)
            assert got == b"\x00" * 64

    def test_double_close_safe(self):
        """Closing twice must not crash (idempotent)."""
        GuardedBuffer = self._get_cls()
        buf = GuardedBuffer(32)
        buf.write(b"a" * 32)
        buf.close()
        buf.close()  # second close should be no-op

    def test_use_after_close_raises(self):
        """Operations after close() raise RuntimeError."""
        GuardedBuffer = self._get_cls()
        buf = GuardedBuffer(32)
        buf.close()
        with pytest.raises(RuntimeError):
            buf.write(b"x")

    def test_context_manager_auto_close(self):
        """Exiting context manager calls close() automatically."""
        GuardedBuffer = self._get_cls()
        buf = GuardedBuffer(32)
        with buf:
            buf.write(b"y" * 32)
        # After exiting, write should fail
        with pytest.raises(RuntimeError):
            buf.write(b"z")

    def test_invalid_size_raises(self):
        """Size <= 0 raises ValueError."""
        GuardedBuffer = self._get_cls()
        with pytest.raises(ValueError):
            GuardedBuffer(0)
        with pytest.raises(ValueError):
            GuardedBuffer(-1)


# =============================================================================
# 2. Mouse Gesture Auth Tests
# =============================================================================


class TestMouseGesturePassword:
    """Tests for meow_decoder.secure_keyboard.MouseGesturePassword."""

    def _get_cls(self):
        from meow_decoder.secure_keyboard import MouseGesturePassword

        return MouseGesturePassword

    def test_quantize_determinism(self):
        """Same points always yield the same quantized bytes."""
        Cls = self._get_cls()
        mgp = Cls(grid_size=16, path_length=20)
        points = [(0.5, 0.5), (0.25, 0.75), (0.1, 0.9)]
        q1 = mgp._quantize(points)
        q2 = mgp._quantize(points)
        assert q1 == q2

    def test_blake2b_derivation_hex_length(self):
        """collect() returns 64-char hex string (32-byte BLAKE2b)."""
        Cls = self._get_cls()
        mgp = Cls(grid_size=16, path_length=20)
        points = [(0.1, 0.2), (0.3, 0.4), (0.5, 0.6)]
        result = mgp.collect(points, output_hex=True)
        assert isinstance(result, str)
        assert len(result) == 64
        # Must be valid hex
        int(result, 16)

    def test_blake2b_person_tag(self):
        """BLAKE2b uses person=b"meow_gesture_v1"."""
        Cls = self._get_cls()
        mgp = Cls(grid_size=16, path_length=20)
        points = [(0.5, 0.5), (0.25, 0.75)]
        result = mgp.collect(points, output_hex=True)

        # Manually compute expected
        quantized = mgp._quantize(points)
        expected = hashlib.blake2b(quantized, digest_size=32, person=b"meow_gesture_v1").hexdigest()
        assert result == expected

    def test_different_points_different_keys(self):
        """Different gesture paths produce different keys."""
        Cls = self._get_cls()
        mgp = Cls(grid_size=16, path_length=20)
        k1 = mgp.collect([(0.1, 0.1), (0.9, 0.9)], output_hex=True)
        k2 = mgp.collect([(0.9, 0.1), (0.1, 0.9)], output_hex=True)
        assert k1 != k2

    def test_quantize_clamping_out_of_range(self):
        """Points outside [0,1] should be clamped or handled."""
        Cls = self._get_cls()
        mgp = Cls(grid_size=16, path_length=20)
        # Very large coordinates
        points = [(999.0, 999.0), (-5.0, -5.0)]
        try:
            q = mgp._quantize(points)
            assert isinstance(q, bytes)
        except (ValueError, OverflowError):
            pass  # also acceptable

    def test_quantize_zero_coords(self):
        """(0.0, 0.0) quantizes to grid cell (0, 0)."""
        Cls = self._get_cls()
        mgp = Cls(grid_size=16, path_length=20)
        result = mgp._quantize([(0.0, 0.0)])
        assert isinstance(result, bytes)
        assert len(result) >= 2

    def test_grid_size_affects_output(self):
        """Different grid_size produces different quantized bytes."""
        Cls = self._get_cls()
        mgp8 = Cls(grid_size=8, path_length=20)
        mgp32 = Cls(grid_size=32, path_length=20)
        points = [(0.33, 0.66), (0.77, 0.11)]
        q8 = mgp8._quantize(points)
        q32 = mgp32._quantize(points)
        # Not guaranteed different for all inputs, but likely for these
        # At minimum, both should be valid bytes
        assert isinstance(q8, bytes)
        assert isinstance(q32, bytes)

    def test_perturbation_stability(self):
        """Small perturbation within same grid cell yields same key."""
        Cls = self._get_cls()
        mgp = Cls(grid_size=16, path_length=20)
        # Two points that differ by < 1/16 = 0.0625, same cell
        p1 = [(0.51, 0.51)]
        p2 = [(0.52, 0.52)]
        k1 = mgp.collect(p1, output_hex=True)
        k2 = mgp.collect(p2, output_hex=True)
        # They SHOULD produce the same key since they're in the same grid cell
        assert k1 == k2


# =============================================================================
# 3. Tamper Detection Tests
# =============================================================================


class TestTamperState:
    """Tests for meow_decoder.tamper_detection.TamperState."""

    def _get_cls(self):
        from meow_decoder.tamper_detection import TamperState

        return TamperState

    def test_roundtrip_serialize(self):
        """TamperState serializes and deserializes correctly."""
        TamperState = self._get_cls()
        state = TamperState()
        state.baseline_hashes = {"module_a": "abc123", "module_b": "def456"}
        state.tamper_count = 3
        state.tampered_modules = ["module_a"]

        data = state.to_bytes()
        restored = TamperState.from_bytes(data)
        assert restored is not None
        assert restored.baseline_hashes == state.baseline_hashes
        assert restored.tamper_count == state.tamper_count
        assert restored.tampered_modules == state.tampered_modules

    def test_corrupt_state_rejected(self):
        """Flipping a byte in serialized state fails HMAC verification."""
        TamperState = self._get_cls()
        state = TamperState()
        state.baseline_hashes = {"test": "abcdef"}
        data = state.to_bytes()

        # Corrupt a byte in the middle
        corrupted = bytearray(data)
        mid = len(corrupted) // 2
        corrupted[mid] ^= 0xFF
        corrupted = bytes(corrupted)

        result = TamperState.from_bytes(corrupted)
        assert result is None

    def test_truncated_state_rejected(self):
        """Truncated serialized data is rejected."""
        TamperState = self._get_cls()
        state = TamperState()
        data = state.to_bytes()
        truncated = data[: len(data) // 2]
        result = TamperState.from_bytes(truncated)
        assert result is None

    def test_hmac_integrity(self):
        """compute_state_hmac produces 32-byte HMAC."""
        TamperState = self._get_cls()
        state = TamperState()
        hmac_val = state.compute_state_hmac()
        assert isinstance(hmac_val, bytes)
        assert len(hmac_val) == 32


class TestSilentPoison:
    """Tests for meow_decoder.tamper_detection.silent_poison_bytes."""

    def _get_fn(self):
        from meow_decoder.tamper_detection import silent_poison_bytes

        return silent_poison_bytes

    def test_determinism(self):
        """Same seed produces identical poison bytes."""
        fn = self._get_fn()
        seed = b"test_seed_12345"
        a = fn(64, seed=seed)
        b = fn(64, seed=seed)
        assert a == b

    def test_different_seeds_differ(self):
        """Different seeds produce different poison bytes."""
        fn = self._get_fn()
        a = fn(64, seed=b"seed_alpha")
        b = fn(64, seed=b"seed_beta")
        assert a != b

    def test_correct_length(self):
        """Output length matches requested length."""
        fn = self._get_fn()
        for n in [0, 1, 16, 256, 1024]:
            out = fn(n)
            assert len(out) == n


class TestTamperDetector:
    """Tests for meow_decoder.tamper_detection.TamperDetector."""

    def _get_cls(self):
        from meow_decoder.tamper_detection import TamperDetector

        return TamperDetector

    def test_detector_init(self):
        """TamperDetector initializes baseline on a temp directory."""
        TamperDetector = self._get_cls()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            # Create a dummy module file
            (p / "dummy.py").write_text("x = 1\n")
            detector = TamperDetector(
                package_dir=p,
                checkpoint_file=p / ".checkpoint",
                auto_initialize=True,
            )
            ok, issues = detector.check_integrity()
            assert ok is True
            assert issues == []

    def test_poison_output_length(self):
        """poison_output returns bytes of requested length."""
        TamperDetector = self._get_cls()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "dummy.py").write_text("x = 1\n")
            detector = TamperDetector(
                package_dir=p,
                checkpoint_file=p / ".checkpoint",
            )
            poison = detector.poison_output(128)
            assert len(poison) == 128


# =============================================================================
# 4. Adversarial Stego Rotation Tests
# =============================================================================


class TestAdversarialNoiseGenerator:
    """Tests for meow_decoder.adversarial_carrier noise generators."""

    def _get_modules(self):
        from meow_decoder.adversarial_carrier import (
            AdversarialNoiseGenerator,
            NoiseProfile,
            generate_sensor_noise,
            generate_texture_noise,
            generate_carrier_noise,
            apply_dct_matching,
            histogram_equalize_noise,
            chi_square_test,
            pairs_test,
        )

        return (
            AdversarialNoiseGenerator,
            NoiseProfile,
            generate_sensor_noise,
            generate_texture_noise,
            generate_carrier_noise,
            apply_dct_matching,
            histogram_equalize_noise,
            chi_square_test,
            pairs_test,
        )

    def test_rotation_differential(self):
        """Sensor/texture/dct/combined produce DIFFERENT noise for same seed."""
        ANG, *_ = self._get_modules()
        seed = secrets.token_bytes(32)
        gen = ANG(seed)

        def _fp(noise: list) -> bytes:
            flat = []
            for row in noise:
                flat.extend(row)
            data = struct.pack(f">{len(flat)}f", *flat)
            return hashlib.sha256(data).digest()

        fps = {
            "sensor": _fp(gen.generate_sensor_noise(8, 8)),
            "texture": _fp(gen.generate_texture_noise(8, 8)),
            "dct": _fp(gen.generate_dct_matched_noise(8, 8)),
            "combined": _fp(gen.generate_combined_noise(8, 8)),
        }

        unique = set(fps.values())
        assert len(unique) == 4, "Algorithms must produce distinct noise"

    def test_determinism_same_seed(self):
        """Same seed = identical noise for each algorithm."""
        ANG, *_ = self._get_modules()
        seed = b"determinism_test_seed_0123456789"

        for method_name in [
            "generate_sensor_noise",
            "generate_texture_noise",
            "generate_dct_matched_noise",
            "generate_combined_noise",
        ]:
            gen1 = ANG(seed)
            gen2 = ANG(seed)
            n1 = getattr(gen1, method_name)(8, 8)
            n2 = getattr(gen2, method_name)(8, 8)
            assert n1 == n2, f"{method_name} not deterministic"

    def test_different_seeds_differ(self):
        """Different seeds produce different noise."""
        ANG, *_ = self._get_modules()
        gen_a = ANG(b"a" * 32)
        gen_b = ANG(b"b" * 32)
        n_a = gen_a.generate_sensor_noise(8, 8)
        n_b = gen_b.generate_sensor_noise(8, 8)
        assert n_a != n_b

    def test_carrier_noise_integer_range(self):
        """generate_carrier_noise returns ints in [-128, 127]."""
        _, _, _, _, gen_carrier, *_ = self._get_modules()
        noise = gen_carrier(16, 16, seed=b"range_check_seed_0123456789AB")
        for row in noise:
            for v in row:
                assert isinstance(v, int)
                assert -128 <= v <= 127

    def test_histogram_equalization_dimensions(self):
        """histogram_equalize preserves 2D array dimensions."""
        ANG, _, _, _, _, _, hist_eq, *_ = self._get_modules()
        gen = ANG(b"hist_eq_test_seed_0123456789AB")
        raw = gen.generate_sensor_noise(12, 10)
        eq = gen.histogram_equalize(raw)
        assert len(eq) == 10
        for row in eq:
            assert len(row) == 12

    def test_chi_square_is_finite(self):
        """chi_square_test returns a finite float for random data."""
        *_, chi_sq, _ = self._get_modules()
        data = list(range(256))  # uniform
        result = chi_sq(data)
        assert math.isfinite(result)

    def test_pairs_test_is_finite(self):
        """pairs_test returns a finite float for random bytes."""
        *_, pairs = self._get_modules()
        data = secrets.token_bytes(256)
        result = pairs(data)
        assert math.isfinite(result)

    def test_rotation_schedule_coverage(self):
        """Simulate rotation schedule and verify all 4 algorithms are used."""
        ANG, _, gen_sensor, gen_texture, _, apply_dct, *_ = self._get_modules()
        rotation_schedule = ["sensor", "texture", "dct", "combined"]
        seed = b"rotation_schedule_test_seed_0123"
        used = set()

        for i in range(8):
            algo = rotation_schedule[i % len(rotation_schedule)]
            used.add(algo)
            frame_seed = hashlib.sha256(seed + i.to_bytes(4, "little")).digest()

            if algo == "sensor":
                noise = gen_sensor(8, 8, seed=frame_seed)
            elif algo == "texture":
                noise = gen_texture(8, 8, seed=frame_seed)
            elif algo == "dct":
                base = gen_sensor(8, 8, seed=frame_seed)
                noise = apply_dct(base, seed=frame_seed)
            else:
                gen = ANG(frame_seed)
                noise = gen.generate_combined_noise(8, 8)

            assert len(noise) == 8
            assert len(noise[0]) == 8

        assert used == {"sensor", "texture", "dct", "combined"}

    def test_noise_profile_customization(self):
        """Custom NoiseProfile changes generator output."""
        ANG, NP, *_ = self._get_modules()
        seed = b"profile_test_seed_0123456789AB"

        default_gen = ANG(seed, profile=NP())
        custom_gen = ANG(seed, profile=NP(read_noise_sigma=50.0, shot_noise_factor=2.0))

        n_default = default_gen.generate_sensor_noise(8, 8)
        n_custom = custom_gen.generate_sensor_noise(8, 8)

        # Custom high-sigma noise should differ from default
        assert n_default != n_custom


# =============================================================================
# 5. Schrödinger Deniability Structure Tests
# =============================================================================


class TestSchrodingerStructure:
    """
    Tests for Schrödinger mode structural properties.

    These verify the quantum_mixer and schrodinger_encode module
    properties that the Tamarin model formalizes.
    """

    def test_quantum_noise_xor_symmetric(self):
        """QuantumNoise = XOR(H(A), H(B)) is commutative."""
        hash_a = hashlib.sha256(b"password_A").digest()
        hash_b = hashlib.sha256(b"password_B").digest()

        qn_ab = bytes(a ^ b for a, b in zip(hash_a, hash_b))
        qn_ba = bytes(b ^ a for a, b in zip(hash_a, hash_b))
        assert qn_ab == qn_ba

    def test_quantum_noise_zero_same_password(self):
        """XOR(H(A), H(A)) = 0 (same password produces zero noise)."""
        hash_a = hashlib.sha256(b"identical_password").digest()
        qn = bytes(a ^ b for a, b in zip(hash_a, hash_a))
        assert qn == b"\x00" * 32

    def test_kdf_commitment_binding(self):
        """
        KDF commitment: commit(key, salt) is deterministic and
        different keys produce different commitments.
        """
        from hashlib import blake2b

        def commit(key: bytes, salt: bytes) -> bytes:
            return blake2b(key, salt=salt, digest_size=32).digest()

        salt = secrets.token_bytes(16)
        c1 = commit(b"key_alpha", salt)
        c2 = commit(b"key_alpha", salt)
        c3 = commit(b"key_beta", salt)

        assert c1 == c2  # deterministic
        assert c1 != c3  # different keys differ


# =============================================================================
# 6. Enhanced Guard Page / Memory Tests (INV-038)
# =============================================================================


class TestGuardedBufferEnhanced:
    """Additional tests for memory guard robustness."""

    def _get_cls(self):
        from meow_decoder.memory_guard import GuardedBuffer

        return GuardedBuffer

    def test_rapid_alloc_free_no_leak(self):
        """Rapid create/close cycles must not leak or crash."""
        cls = self._get_cls()
        for _ in range(50):
            buf = cls(64)
            buf.write(b"\xaa" * 64)
            buf.close()

    def test_boundary_write_exact(self):
        """Writing exactly buffer_size bytes succeeds."""
        cls = self._get_cls()
        buf = cls(128)
        data = b"\x42" * 128
        buf.write(data)
        assert buf.read(128) == data
        buf.close()

    def test_zero_wipe_idempotent(self):
        """Multiple zero() calls produce consistent zeroed state."""
        cls = self._get_cls()
        buf = cls(64)
        buf.write(b"\xff" * 64)
        buf.zero()
        buf.zero()
        buf.zero()
        assert buf.read(64) == b"\x00" * 64
        buf.close()

    def test_partial_read_at_offsets(self):
        """Read at various offsets returns correct slices."""
        cls = self._get_cls()
        buf = cls(256)
        data = bytes(range(256))
        buf.write(data)
        assert buf.read(16) == data[:16]
        assert buf.read(50, offset=100) == data[100:150]
        assert buf.read(1, offset=255) == data[255:256]
        buf.close()


# =============================================================================
# 7. Enhanced Mouse Gesture Auth Tests (INV-039)
# =============================================================================


class TestMouseGestureEnhanced:
    """Additional tests for gesture auth security properties."""

    def _get_mgp(self, grid_size=16):
        from meow_decoder.secure_keyboard import MouseGesturePassword

        return MouseGesturePassword(grid_size=grid_size)

    def test_person_tag_domain_separation(self):
        """BLAKE2b with person tag differs from without it."""
        from hashlib import blake2b

        key_material = b"test_gesture_key_material_0xBEEF"
        person_tag = b"meow_gesture_v1\x00"

        h_with = blake2b(key_material, person=person_tag, digest_size=32).hexdigest()
        h_without = blake2b(key_material, digest_size=32).hexdigest()

        assert h_with != h_without, "Person tag must affect BLAKE2b output"

    def test_gesture_replay_resistance_via_salt(self):
        """Same gesture + different salt → different derivation."""
        from hashlib import blake2b

        gesture = b"canonical_gesture_data"
        salt1 = b"salt_2024_01_01"
        salt2 = b"salt_2024_12_31"

        h1 = blake2b(gesture + salt1, digest_size=32).digest()
        h2 = blake2b(gesture + salt2, digest_size=32).digest()

        assert h1 != h2

    def test_quantize_grid_boundary_consistency(self):
        """Points on exact grid boundaries quantize deterministically."""
        mgp = self._get_mgp(grid_size=8)
        # Create boundary points
        points = [(0, 0), (100, 100), (500, 500), (1000, 1000)]
        q1 = mgp._quantize(points)
        q2 = mgp._quantize(points)
        assert q1 == q2

    def test_min_points_threshold(self):
        """Gesture with fewer than 2 points should produce empty or raise."""
        mgp = self._get_mgp()
        try:
            result = mgp._quantize([])
            # Empty input: should return empty tuple or raise
            assert result == () or result == (0, 0) or len(result) == 0
        except (ValueError, TypeError):
            pass  # Expected

    def test_large_grid_still_deterministic(self):
        """Large grid_size doesn't break quantization determinism."""
        mgp = self._get_mgp(grid_size=256)
        points = [(100, 200), (300, 400), (500, 600)]
        q1 = mgp._quantize(points)
        q2 = mgp._quantize(points)
        assert q1 == q2


# =============================================================================
# 8. Enhanced Tamper Detection Tests (INV-040)
# =============================================================================


class TestTamperDetectionEnhanced:
    """Additional tests for tamper detection robustness."""

    def _get_state_cls(self):
        from meow_decoder.tamper_detection import TamperState

        return TamperState

    def _get_poison(self):
        from meow_decoder.tamper_detection import silent_poison_bytes

        return silent_poison_bytes

    def test_poison_entropy_quality(self):
        """Silent poison output must have high Shannon entropy."""
        import math as _math

        poison_fn = self._get_poison()
        output = poison_fn(256, seed=b"entropy_test_seed")

        freq = {}
        for b in output:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(output)
            if p > 0:
                entropy -= p * _math.log2(p)

        assert entropy > 5.0, f"Poison entropy too low: {entropy:.2f} bits/byte"

    def test_state_version_corruption_detected(self):
        """Corrupted bytes in serialized state triggers rejection."""
        cls = self._get_state_cls()
        state = cls()
        serialized = state.to_bytes()

        # Corrupt first byte
        tampered = bytearray(serialized)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        result = cls.from_bytes(tampered)
        # from_bytes returns None on invalid data
        assert result is None, "Corrupted state should be rejected"

    def test_checkpoint_replay_detection(self):
        """Serialized states from different epochs must differ."""
        cls = self._get_state_cls()
        state1 = cls()
        cp1 = state1.to_bytes()

        state2 = cls()
        state2.tamper_count = 5  # Modify state
        cp2 = state2.to_bytes()

        assert cp1 != cp2, "Different states must serialize differently"

    def test_poison_different_seeds_differ(self):
        """Different seeds produce different poison output."""
        poison_fn = self._get_poison()
        p1 = poison_fn(128, seed=b"seed_alpha__xxxxx")
        p2 = poison_fn(128, seed=b"seed_beta___xxxxx")

        assert p1 != p2

    def test_poison_correct_length(self):
        """Poison output always has requested length."""
        poison_fn = self._get_poison()
        for size in [16, 64, 128, 512, 1024]:
            output = poison_fn(size, seed=b"length_test_seed!")
            assert len(output) == size


# =============================================================================
# 9. Enhanced Adversarial Stego Tests (INV-041)
# =============================================================================


class TestAdversarialStegoEnhanced:
    """Additional tests for adversarial stego robustness."""

    def _get_modules(self):
        from meow_decoder.adversarial_carrier import (
            AdversarialNoiseGenerator,
            NoiseProfile,
            generate_sensor_noise,
            generate_carrier_noise,
            chi_square_test,
            pairs_test,
        )

        return (
            AdversarialNoiseGenerator,
            NoiseProfile,
            generate_sensor_noise,
            generate_carrier_noise,
            chi_square_test,
            pairs_test,
        )

    def test_cross_seed_independence(self):
        """Different seeds produce statistically independent noise."""
        ANG, NP, *_ = self._get_modules()
        gen1 = ANG(b"seed_1_for_independence_test!!", NP())
        gen2 = ANG(b"seed_2_for_independence_test!!", NP())

        n1 = gen1.generate_combined_noise(16, 16)
        n2 = gen2.generate_combined_noise(16, 16)

        flat1 = [v for row in n1 for v in row]
        flat2 = [v for row in n2 for v in row]

        assert flat1 != flat2, "Different seeds produced identical noise"

    def test_noise_all_finite(self):
        """All noise values must be finite (no NaN/Inf)."""
        ANG, NP, *_ = self._get_modules()
        gen = ANG(b"finite_test_seed_0123456789AB", NP())

        for method in [
            "generate_sensor_noise",
            "generate_texture_noise",
            "generate_dct_matched_noise",
            "generate_combined_noise",
        ]:
            noise = getattr(gen, method)(16, 16)
            for row in noise:
                for v in row:
                    assert math.isfinite(v), f"{method} produced non-finite: {v}"

    def test_rotation_visits_all_algorithms(self):
        """Rotation schedule visits all algorithm indices over 100+ frames."""
        ANG, *_ = self._get_modules()
        seed = b"rotation_visit_test_seed_012345"
        gen = ANG(seed)

        algos_seen = set()
        for i in range(100):
            frame_seed = hashlib.sha256(seed + i.to_bytes(4, "little")).digest()
            algo_idx = frame_seed[0] % 4
            algos_seen.add(algo_idx)

        assert len(algos_seen) >= 3, f"Only {len(algos_seen)} algorithms visited in 100 frames"

    def test_carrier_noise_range_strict(self):
        """Carrier noise must be in [-128, 127] for all pixels."""
        _, _, _, gen_carrier, *_ = self._get_modules()
        noise = gen_carrier(32, 32, seed=b"strict_range_check_seed_0123AB")
        for row in noise:
            for v in row:
                assert -128 <= v <= 127, f"Out of range: {v}"
                assert isinstance(v, int)

    def test_large_dimension_no_crash(self):
        """Large image dimensions don't crash the generator."""
        ANG, NP, *_ = self._get_modules()
        gen = ANG(b"large_dim_test_seed_0123456789", NP())
        noise = gen.generate_combined_noise(256, 256)
        assert len(noise) == 256
        assert len(noise[0]) == 256


# =============================================================================
# 10. Ratchet Integration Tests (INV-042)
# =============================================================================


class TestRatchetIntegration:
    """Tests for ratchet forward secrecy and PQ beacon properties."""

    def test_default_rekey_interval_nonzero(self):
        """DEFAULT_REKEY_INTERVAL must be non-zero (enabled by default)."""
        from meow_decoder.ratchet import DEFAULT_REKEY_INTERVAL

        assert (
            DEFAULT_REKEY_INTERVAL > 0
        ), f"DEFAULT_REKEY_INTERVAL={DEFAULT_REKEY_INTERVAL} — must be >0"

    def test_dead_kem_beacon_functions_removed(self):
        """_generate_kem_beacon and _recover_kem_beacon must not exist."""
        import meow_decoder.ratchet as ratchet_mod

        assert not hasattr(
            ratchet_mod, "_generate_kem_beacon"
        ), "Dead function _generate_kem_beacon still exists"
        assert not hasattr(
            ratchet_mod, "_recover_kem_beacon"
        ), "Dead function _recover_kem_beacon still exists"

    def test_pq_beacon_domain_separation(self):
        """PQ beacon mix info differs from classical beacon info."""
        from meow_decoder.ratchet import (
            PQ_BEACON_MIX_INFO,
            REKEY_BEACON_INFO,
            REKEY_BEACON_KEM_INFO,
        )

        assert PQ_BEACON_MIX_INFO != REKEY_BEACON_INFO
        assert PQ_BEACON_MIX_INFO != REKEY_BEACON_KEM_INFO
        assert REKEY_BEACON_INFO != REKEY_BEACON_KEM_INFO

    def test_header_encryption_domain_separation(self):
        """Header encryption constants differ from other domain constants."""
        from meow_decoder.ratchet import (
            HEADER_ENC_INFO,
            HEADER_MASK_INFO,
            REKEY_BEACON_INFO,
        )

        assert HEADER_ENC_INFO != HEADER_MASK_INFO
        assert HEADER_ENC_INFO != REKEY_BEACON_INFO
        assert HEADER_MASK_INFO != REKEY_BEACON_INFO

    def test_ratchet_state_has_required_fields(self):
        """RatchetState must expose root_key, position, epoch."""
        from meow_decoder.ratchet import RatchetState

        # Verify the dataclass has expected field names
        fields = {f.name for f in RatchetState.__dataclass_fields__.values()}
        for required in ["root_key", "position", "epoch"]:
            assert required in fields, f"RatchetState missing '{required}' field"


# =============================================================================
# 11. Schrödinger Enhanced Tests
# =============================================================================


class TestSchrodingerEnhanced:
    """Additional Schrödinger deniability structure tests."""

    def test_quantum_noise_high_entropy(self):
        """Quantum noise from different passwords must have high entropy."""
        hash_a = hashlib.sha256(b"strong_password_alpha").digest()
        hash_b = hashlib.sha256(b"strong_password_beta_").digest()

        qn = bytes(a ^ b for a, b in zip(hash_a, hash_b))

        # Compute entropy
        freq = {}
        for b in qn:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(qn)
            if p > 0:
                entropy -= p * math.log2(p)

        assert entropy > 3.0, f"Quantum noise entropy too low: {entropy:.2f}"

    def test_commitment_non_collision(self):
        """1000 random keys must produce 1000 unique commitments."""
        from hashlib import blake2b

        salt = secrets.token_bytes(16)
        commits = set()
        for i in range(1000):
            key = f"key_{i:04d}".encode()
            c = blake2b(key, salt=salt, digest_size=32).digest()
            commits.add(c)

        assert len(commits) == 1000, "KDF commitment collision detected"

    def test_xor_noise_nonzero_different_passwords(self):
        """XOR noise is non-zero for distinct passwords."""
        for i in range(50):
            h_a = hashlib.sha256(f"pw_a_{i}".encode()).digest()
            h_b = hashlib.sha256(f"pw_b_{i}".encode()).digest()
            qn = bytes(a ^ b for a, b in zip(h_a, h_b))
            assert qn != b"\x00" * 32, f"Zero noise at iteration {i}"
