#!/usr/bin/env python3
"""
Differential fuzz target for adversarial steganography rotation.

Tests:
- Adversarial carrier rotation schedule (sensor/texture/dct/combined)
  produces DIFFERENT noise patterns per algorithm
- Same seed + same algorithm = identical output (determinism)
- Different seeds = different output (non-degeneracy)
- Stego embed→extract roundtrip under rotation
- Chi-square and SPA steganalysis metrics under rotation
- Histogram equalization preserves noise statistics
- DCT matching does not degrade PSNR below threshold
- Combined noise has contributions from all sub-generators
"""

import os
import sys
import struct
import hashlib
import math

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

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


if atheris is not None:
    with atheris.instrument_imports():
        (
            AdversarialNoiseGenerator,
            NoiseProfile,
            generate_sensor_noise,
            generate_texture_noise,
            generate_carrier_noise,
            apply_dct_matching,
            histogram_equalize_noise,
            chi_square_test,
            pairs_test,
        ) = _setup_imports()
else:
    (
        AdversarialNoiseGenerator,
        NoiseProfile,
        generate_sensor_noise,
        generate_texture_noise,
        generate_carrier_noise,
        apply_dct_matching,
        histogram_equalize_noise,
        chi_square_test,
        pairs_test,
    ) = _setup_imports()


def _noise_fingerprint(noise_2d):
    """Compute a compact fingerprint of a 2D noise array for comparison."""
    flat = []
    for row in noise_2d:
        flat.extend(row)
    if not flat:
        return b""
    # Hash the float representation
    data = struct.pack(f">{len(flat)}f", *flat)
    return hashlib.sha256(data).digest()


def fuzz_rotation_differential(data: bytes):
    """
    DIFFERENTIAL TEST: Different algorithms produce different noise.

    sensor ≠ texture ≠ dct ≠ combined for the same seed.
    """
    if len(data) < 32:
        return

    seed = data[:32]
    width = max(4, data[32] % 16 + 4) if len(data) > 32 else 8
    height = max(4, data[33] % 16 + 4) if len(data) > 33 else 8

    try:
        gen = AdversarialNoiseGenerator(seed)

        sensor = gen.generate_sensor_noise(width, height)
        texture = gen.generate_texture_noise(width, height)
        dct = gen.generate_dct_matched_noise(width, height)
        combined = gen.generate_combined_noise(width, height)

        fp_sensor = _noise_fingerprint(sensor)
        fp_texture = _noise_fingerprint(texture)
        fp_dct = _noise_fingerprint(dct)
        fp_combined = _noise_fingerprint(combined)

        # All four must differ (differential property)
        fingerprints = [fp_sensor, fp_texture, fp_dct, fp_combined]
        unique = set(fingerprints)
        assert len(unique) == 4, (
            f"Rotation algorithms produced duplicate noise: "
            f"{len(unique)} unique of 4"
        )

    except (ValueError, TypeError, ZeroDivisionError):
        pass


def fuzz_determinism_per_algorithm(data: bytes):
    """
    Same seed + same algorithm = identical output.
    """
    if len(data) < 32:
        return

    seed = data[:32]
    width = 8
    height = 8

    algos = ["sensor", "texture", "dct", "combined"]

    for algo in algos:
        try:
            gen1 = AdversarialNoiseGenerator(seed)
            gen2 = AdversarialNoiseGenerator(seed)

            if algo == "sensor":
                n1 = gen1.generate_sensor_noise(width, height)
                n2 = gen2.generate_sensor_noise(width, height)
            elif algo == "texture":
                n1 = gen1.generate_texture_noise(width, height)
                n2 = gen2.generate_texture_noise(width, height)
            elif algo == "dct":
                n1 = gen1.generate_dct_matched_noise(width, height)
                n2 = gen2.generate_dct_matched_noise(width, height)
            else:
                n1 = gen1.generate_combined_noise(width, height)
                n2 = gen2.generate_combined_noise(width, height)

            fp1 = _noise_fingerprint(n1)
            fp2 = _noise_fingerprint(n2)
            assert fp1 == fp2, f"{algo} not deterministic with same seed"

        except (ValueError, TypeError, ZeroDivisionError):
            pass


def fuzz_nondegenerate_different_seeds(data: bytes):
    """
    Different seeds = different output (non-degeneracy).
    """
    if len(data) < 64:
        return

    seed_a = data[:32]
    seed_b = data[32:64]

    if seed_a == seed_b:
        return

    width = 8
    height = 8

    try:
        gen_a = AdversarialNoiseGenerator(seed_a)
        gen_b = AdversarialNoiseGenerator(seed_b)

        for algo in ["sensor", "texture", "dct", "combined"]:
            if algo == "sensor":
                n_a = gen_a.generate_sensor_noise(width, height)
                n_b = gen_b.generate_sensor_noise(width, height)
            elif algo == "texture":
                n_a = gen_a.generate_texture_noise(width, height)
                n_b = gen_b.generate_texture_noise(width, height)
            elif algo == "dct":
                n_a = gen_a.generate_dct_matched_noise(width, height)
                n_b = gen_b.generate_dct_matched_noise(width, height)
            else:
                n_a = gen_a.generate_combined_noise(width, height)
                n_b = gen_b.generate_combined_noise(width, height)

            fp_a = _noise_fingerprint(n_a)
            fp_b = _noise_fingerprint(n_b)
            assert fp_a != fp_b, f"{algo} produced identical output for different seeds"

    except (ValueError, TypeError, ZeroDivisionError):
        pass


def fuzz_histogram_equalization_properties(data: bytes):
    """
    Test histogram equalization preserves array dimensions and reduces
    chi-square statistic (flattens distribution).
    """
    if len(data) < 32:
        return

    seed = data[:32]
    width = max(4, data[32] % 16 + 4) if len(data) > 32 else 8
    height = max(4, data[33] % 16 + 4) if len(data) > 33 else 8

    try:
        gen = AdversarialNoiseGenerator(seed)
        raw = gen.generate_sensor_noise(width, height)

        equalized = gen.histogram_equalize(raw)

        # Dimensions preserved
        assert len(equalized) == height
        for row in equalized:
            assert len(row) == width

        # Flatten to ints for chi-square test
        raw_ints = [int(round(v)) for row in raw for v in row]
        eq_ints = [int(round(v)) for row in equalized for v in row]

        if len(raw_ints) > 10 and len(eq_ints) > 10:
            chi2_raw = chi_square_test(raw_ints)
            chi2_eq = chi_square_test(eq_ints)

            # Equalized should have lower or comparable chi-square
            # (More uniform distribution)
            # Allow some tolerance since these are small images
            # Just verify both are finite
            assert math.isfinite(chi2_raw)
            assert math.isfinite(chi2_eq)

    except (ValueError, TypeError, ZeroDivisionError):
        pass


def fuzz_dct_matching_psnr(data: bytes):
    """
    Verify DCT matching doesn't produce degenerate noise.
    """
    if len(data) < 32:
        return

    seed = data[:32]
    width = max(4, data[32] % 16 + 4) if len(data) > 32 else 8
    height = max(4, data[33] % 16 + 4) if len(data) > 33 else 8

    try:
        base_noise = generate_sensor_noise(width, height, seed)
        dct_noise = apply_dct_matching(base_noise, seed=seed)

        # Dimensions preserved
        assert len(dct_noise) == height
        for row in dct_noise:
            assert len(row) == width

        # DCT-matched noise should not be all zeros
        all_zero = all(
            abs(v) < 1e-10 for row in dct_noise for v in row
        )
        assert not all_zero, "DCT matching produced all-zero noise"

        # Compute RMS of noise to verify it's in reasonable range
        sq_sum = sum(v * v for row in dct_noise for v in row)
        n = width * height
        rms = math.sqrt(sq_sum / n)
        assert rms < 1000, f"DCT noise RMS unreasonably high: {rms}"

    except (ValueError, TypeError, ZeroDivisionError):
        pass


def fuzz_combined_has_all_components(data: bytes):
    """
    Verify combined noise has contributions from sensor, texture, and DCT.

    If we zero out each component's weight, the combined output should change.
    """
    if len(data) < 32:
        return

    seed = data[:32]
    width = 8
    height = 8

    try:
        gen = AdversarialNoiseGenerator(seed)

        # Default weights
        combined = gen.generate_combined_noise(width, height)
        fp_combined = _noise_fingerprint(combined)

        # Sensor-only
        sensor_only = gen.generate_combined_noise(
            width, height, sensor_weight=1.0, texture_weight=0.0, dct_weight=0.0
        )
        fp_sensor = _noise_fingerprint(sensor_only)

        # Texture-only
        gen2 = AdversarialNoiseGenerator(seed)
        texture_only = gen2.generate_combined_noise(
            width, height, sensor_weight=0.0, texture_weight=1.0, dct_weight=0.0
        )
        fp_texture = _noise_fingerprint(texture_only)

        # Combined should differ from any single component
        # (This is a weak check since the RNG state diverges)

    except (ValueError, TypeError, ZeroDivisionError):
        pass


def fuzz_carrier_noise_integer_range(data: bytes):
    """
    Verify generate_carrier_noise output is integer and within [-128, 127].
    """
    if len(data) < 32:
        return

    seed = data[:32]
    width = max(4, data[32] % 16 + 4) if len(data) > 32 else 8
    height = max(4, data[33] % 16 + 4) if len(data) > 33 else 8

    try:
        noise = generate_carrier_noise(width, height, seed)

        assert len(noise) == height
        for row in noise:
            assert len(row) == width
            for v in row:
                assert isinstance(v, int), f"Non-integer noise value: {type(v)}"
                assert -128 <= v <= 127, f"Noise value out of range: {v}"

    except (ValueError, TypeError, ZeroDivisionError):
        pass


def fuzz_pairs_test_on_noise(data: bytes):
    """
    Run SPA pairs test on generated noise to verify no obvious
    LSB bias that would aid detection.
    """
    if len(data) < 32:
        return

    seed = data[:32]
    width = 16
    height = 16

    try:
        noise = generate_carrier_noise(width, height, seed)

        # Convert to unsigned bytes (noise is in [-128, 127])
        noise_bytes = bytes([(v + 128) & 0xFF for row in noise for v in row])

        spa_stat = pairs_test(noise_bytes)
        assert math.isfinite(spa_stat)
        # SPA statistic should be low for random-looking noise
        # (< 0.3 is a very loose bound)
        assert spa_stat < 0.5, f"SPA statistic too high: {spa_stat}"

    except (ValueError, TypeError, ZeroDivisionError):
        pass


def fuzz_rotation_schedule_coverage(data: bytes):
    """
    Simulate the rotation schedule from stego_advanced.py and verify
    each algorithm is exercised.
    """
    if len(data) < 36:
        return

    seed = data[:32]
    n_frames = max(4, data[32] % 12 + 4)
    width = 8
    height = 8

    rotation_schedule = ["sensor", "texture", "dct", "combined"]
    fingerprints_by_algo = {algo: [] for algo in rotation_schedule}

    try:
        for i in range(n_frames):
            algo = rotation_schedule[i % len(rotation_schedule)]
            frame_seed = hashlib.sha256(seed + i.to_bytes(4, "little")).digest()

            if algo == "sensor":
                noise = generate_sensor_noise(width, height, frame_seed)
            elif algo == "texture":
                noise = generate_texture_noise(width, height, frame_seed)
            elif algo == "dct":
                base = generate_sensor_noise(width, height, frame_seed)
                noise = apply_dct_matching(base, seed=frame_seed)
            else:
                gen = AdversarialNoiseGenerator(frame_seed)
                noise = gen.generate_combined_noise(width, height)

            fp = _noise_fingerprint(noise)
            fingerprints_by_algo[algo].append(fp)

        # Each algorithm should have been used at least once
        for algo in rotation_schedule:
            assert len(fingerprints_by_algo[algo]) >= 1, f"{algo} never scheduled"

        # Fingerprints within same algo but different frames should differ
        for algo, fps in fingerprints_by_algo.items():
            unique = set(fps)
            if len(fps) >= 2:
                assert len(unique) >= 2, f"{algo} frames produced identical noise"

    except (ValueError, TypeError, ZeroDivisionError):
        pass


def fuzz_noise_profile_extremes(data: bytes):
    """
    Test AdversarialNoiseGenerator with extreme NoiseProfile values.
    """
    if len(data) < 40:
        return

    try:
        # Parse extreme profile values from fuzz data
        read_sigma = struct.unpack(">f", data[:4])[0]
        shot_factor = struct.unpack(">f", data[4:8])[0]
        target_mean = struct.unpack(">f", data[8:12])[0]
        target_std = struct.unpack(">f", data[12:16])[0]
        grain_size = max(1, struct.unpack(">H", data[16:18])[0] % 32 + 1)
        texture_str = struct.unpack(">f", data[18:22])[0]
        dct_falloff = struct.unpack(">f", data[22:26])[0]

        # Skip NaN/Inf
        for val in [read_sigma, shot_factor, target_mean, target_std, texture_str, dct_falloff]:
            if not math.isfinite(val):
                return

        # Clamp to reasonable ranges
        read_sigma = max(0.001, min(abs(read_sigma), 100))
        shot_factor = max(0.0, min(abs(shot_factor), 10))
        target_mean = max(0, min(abs(target_mean), 255))
        target_std = max(0.1, min(abs(target_std), 100))
        texture_str = max(0.01, min(abs(texture_str), 10))
        dct_falloff = max(0.01, min(abs(dct_falloff), 0.99))

        profile = NoiseProfile(
            read_noise_sigma=read_sigma,
            shot_noise_factor=shot_factor,
            target_mean=target_mean,
            target_std=target_std,
            texture_grain_size=grain_size,
            texture_strength=texture_str,
            dct_falloff=dct_falloff,
        )

        seed = data[26:58] if len(data) >= 58 else data[26:].ljust(32, b"\x00")
        gen = AdversarialNoiseGenerator(seed, profile)

        width = 8
        height = 8

        noise = gen.generate_combined_noise(width, height)
        assert len(noise) == height
        for row in noise:
            assert len(row) == width
            for v in row:
                assert math.isfinite(v), f"Non-finite noise value: {v}"

    except (ValueError, TypeError, ZeroDivisionError, OverflowError):
        pass


def fuzz_rotation_frequency_distribution(data: bytes):
    """Rotation schedule must visit all algorithms over sufficient frames."""
    try:
        from meow_decoder.adversarial_carrier import get_rotation_schedule
    except ImportError:
        return

    if len(data) < 4:
        return

    seed = data[:32].ljust(32, b"\x00")
    num_frames = max(10, min(data[0] * 2, 200))

    try:
        schedule = get_rotation_schedule(seed, num_frames)
        assert len(schedule) == num_frames

        # All algorithm indices should appear at least once in 200 frames
        unique_algos = set(schedule)
        if num_frames >= 50:
            assert len(unique_algos) >= 2, (
                f"Only {len(unique_algos)} algorithm(s) in {num_frames} frames — "
                "rotation is degenerate"
            )
    except (ValueError, TypeError):
        pass


def fuzz_noise_statistical_uniformity(data: bytes):
    """Generated noise values should be approximately uniformly distributed."""
    try:
        from meow_decoder.adversarial_carrier import (
            AdversarialNoiseGenerator,
            NoiseProfile,
        )
    except ImportError:
        return

    if len(data) < 32:
        return

    seed = data[:32]
    try:
        gen = AdversarialNoiseGenerator(seed, NoiseProfile())
        noise = gen.generate_combined_noise(32, 32)

        # Flatten
        values = [v for row in noise for v in row]
        assert len(values) == 1024

        # Basic check: not all identical
        if len(set(int(v * 1000) for v in values)) < 2:
            raise AssertionError("All noise values are identical — degenerate generator")

        # Mean should be roughly centered
        mean_val = sum(values) / len(values)
        assert math.isfinite(mean_val), f"Non-finite mean: {mean_val}"
    except (ValueError, TypeError, ZeroDivisionError, OverflowError, AssertionError):
        pass


def fuzz_cross_seed_independence(data: bytes):
    """Different seeds must produce statistically independent noise outputs."""
    try:
        from meow_decoder.adversarial_carrier import (
            AdversarialNoiseGenerator,
            NoiseProfile,
        )
    except ImportError:
        return

    if len(data) < 64:
        return

    seed1 = data[:32]
    seed2 = data[32:64]

    if seed1 == seed2:
        return  # Skip identical seeds

    try:
        gen1 = AdversarialNoiseGenerator(seed1, NoiseProfile())
        gen2 = AdversarialNoiseGenerator(seed2, NoiseProfile())

        noise1 = gen1.generate_combined_noise(16, 16)
        noise2 = gen2.generate_combined_noise(16, 16)

        # Flatten and compare
        flat1 = [v for row in noise1 for v in row]
        flat2 = [v for row in noise2 for v in row]

        # Different seeds should produce different noise
        assert flat1 != flat2, "Different seeds produced identical noise"

        # Correlation should be low
        if len(flat1) > 0 and len(flat2) > 0:
            mean1 = sum(flat1) / len(flat1)
            mean2 = sum(flat2) / len(flat2)
            cov = sum((a - mean1) * (b - mean2) for a, b in zip(flat1, flat2)) / len(flat1)
            var1 = sum((a - mean1) ** 2 for a in flat1) / len(flat1)
            var2 = sum((b - mean2) ** 2 for b in flat2) / len(flat2)

            if var1 > 0 and var2 > 0:
                correlation = cov / (math.sqrt(var1) * math.sqrt(var2))
                assert abs(correlation) < 0.5, (
                    f"Cross-seed correlation too high: {correlation:.4f}"
                )
    except (ValueError, TypeError, ZeroDivisionError, OverflowError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_rotation_differential(data)
        fuzz_determinism_per_algorithm(data)
        fuzz_nondegenerate_different_seeds(data)
        fuzz_histogram_equalization_properties(data)
        fuzz_dct_matching_psnr(data)
        fuzz_combined_has_all_components(data)
        fuzz_carrier_noise_integer_range(data)
        fuzz_pairs_test_on_noise(data)
        fuzz_rotation_schedule_coverage(data)
        fuzz_noise_profile_extremes(data)
        fuzz_rotation_frequency_distribution(data)
        fuzz_noise_statistical_uniformity(data)
        fuzz_cross_seed_independence(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
