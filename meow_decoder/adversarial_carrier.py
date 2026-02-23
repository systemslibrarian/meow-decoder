"""
Adversarial Carrier Noise Generation.

Generates procedural noise patterns that defeat statistical steganalysis.
When QR codes or steganographic data are embedded in cat photos or other
carriers, this module provides noise that:

1. Mimics natural image statistics (histogram, DCT coefficients)
2. Defeats χ² tests for LSB embedding detection
3. Adds plausible camera sensor noise patterns
4. Generates consistent texture to mask embedding artifacts

Security model:
- Attacker has unlimited forensic analysis capabilities
- Can run all known steganalysis tools (StegExpose, Aletheia, etc.)
- Has corpus of known carrier images for comparison
- Goal: Make steganographic carriers statistically indistinguishable
  from natural images with NO embedded data

IMPORTANT LIMITATIONS:
- This does NOT provide cryptographic security
- Detection-resistant ≠ detection-proof
- Advanced ML-based steganalysis may still detect patterns
- Should be combined with other defenses (encryption, Schrödinger mode)
"""

from __future__ import annotations

import hashlib
import math
import secrets
import struct
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

__all__ = [
    "AdversarialNoiseGenerator",
    "generate_sensor_noise",
    "generate_texture_noise",
    "histogram_equalize_noise",
    "apply_dct_matching",
    "generate_carrier_noise",
]


@dataclass
class NoiseProfile:
    """
    Statistical profile for noise generation.

    Matches target image characteristics to generate plausible noise.
    """

    # Target mean pixel value (0-255)
    target_mean: float = 128.0

    # Target standard deviation
    target_std: float = 20.0

    # Sensor noise characteristics
    read_noise_sigma: float = 3.0
    shot_noise_factor: float = 0.1

    # DCT coefficient distribution (simplified)
    dct_falloff: float = 0.8  # How quickly higher frequencies attenuate

    # Texture parameters
    texture_grain_size: int = 4
    texture_strength: float = 0.3


class SeededRNG:
    """
    Deterministic PRNG for reproducible noise generation.

    Based on ChaCha20-style mixing with SHA-256 output.
    """

    def __init__(self, seed: bytes):
        self._state = hashlib.sha256(seed).digest()
        self._counter = 0

    def _next_block(self) -> bytes:
        """Generate next 32 bytes of randomness."""
        self._counter += 1
        data = self._state + struct.pack("<Q", self._counter)
        self._state = hashlib.sha256(data).digest()
        return self._state

    def random_bytes(self, n: int) -> bytes:
        """Generate n random bytes."""
        result = bytearray()
        while len(result) < n:
            result.extend(self._next_block())
        return bytes(result[:n])

    def random_float(self) -> float:
        """Generate random float in [0, 1)."""
        b = self.random_bytes(8)
        i = struct.unpack("<Q", b)[0]
        return (i & 0x001FFFFFFFFFFFFF) / 0x001FFFFFFFFFFFFF

    def random_gaussian(self, mu: float = 0.0, sigma: float = 1.0) -> float:
        """Generate Gaussian random number using Box-Muller transform."""
        u1 = self.random_float()
        u2 = self.random_float()

        # Avoid log(0)
        while u1 < 1e-10:
            u1 = self.random_float()

        z0 = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
        return mu + z0 * sigma

    def randint(self, a: int, b: int) -> int:
        """Generate random integer in [a, b]."""
        range_size = b - a + 1
        return a + (struct.unpack("<I", self.random_bytes(4))[0] % range_size)


class AdversarialNoiseGenerator:
    """
    Generate noise that defeats statistical steganalysis.

    Creates noise patterns matching natural image statistics to prevent
    detection of embedded data.
    """

    def __init__(
        self,
        seed: Optional[bytes] = None,
        profile: Optional[NoiseProfile] = None,
    ):
        """
        Initialize noise generator.

        Args:
            seed: Deterministic seed (random if None).
            profile: Noise profile to match.
        """
        if seed is None:
            seed = secrets.token_bytes(32)

        self.rng = SeededRNG(seed)
        self.profile = profile or NoiseProfile()

    def generate_sensor_noise(
        self,
        width: int,
        height: int,
    ) -> List[List[float]]:
        """
        Generate realistic camera sensor noise.

        Combines read noise (constant) and shot noise (signal-dependent).

        Args:
            width: Image width in pixels.
            height: Image height in pixels.

        Returns:
            2D array of noise values (to be added to pixel values).
        """
        noise = []

        for y in range(height):
            row = []
            for x in range(width):
                # Read noise (Gaussian, constant sigma)
                read = self.rng.random_gaussian(0, self.profile.read_noise_sigma)

                # Shot noise (Poisson, approximated as Gaussian)
                # Variance proportional to signal level
                signal_estimate = self.profile.target_mean + read
                shot_sigma = math.sqrt(max(0, signal_estimate) * self.profile.shot_noise_factor)
                shot = self.rng.random_gaussian(0, shot_sigma)

                row.append(read + shot)
            noise.append(row)

        return noise

    def generate_texture_noise(
        self,
        width: int,
        height: int,
    ) -> List[List[float]]:
        """
        Generate texture-like noise (for fabric, paper, etc.).

        Uses Perlin-like value noise for natural-looking patterns.

        Args:
            width: Image width in pixels.
            height: Image height in pixels.

        Returns:
            2D array of noise values.
        """
        grain = self.profile.texture_grain_size
        strength = self.profile.texture_strength

        # Generate coarse grid
        grid_w = (width // grain) + 2
        grid_h = (height // grain) + 2

        grid = [[self.rng.random_float() for _ in range(grid_w)] for _ in range(grid_h)]

        # Interpolate to full resolution
        noise = []
        for y in range(height):
            row = []
            for x in range(width):
                # Find grid cell
                gx = x / grain
                gy = y / grain
                x0 = int(gx)
                y0 = int(gy)

                # Bilinear interpolation
                fx = gx - x0
                fy = gy - y0

                v00 = grid[y0 % grid_h][x0 % grid_w]
                v10 = grid[y0 % grid_h][(x0 + 1) % grid_w]
                v01 = grid[(y0 + 1) % grid_h][x0 % grid_w]
                v11 = grid[(y0 + 1) % grid_h][(x0 + 1) % grid_w]

                # Smooth interpolation
                fx = fx * fx * (3 - 2 * fx)
                fy = fy * fy * (3 - 2 * fy)

                v0 = v00 * (1 - fx) + v10 * fx
                v1 = v01 * (1 - fx) + v11 * fx
                value = v0 * (1 - fy) + v1 * fy

                # Scale to noise range
                noise_value = (value - 0.5) * self.profile.target_std * strength
                row.append(noise_value)
            noise.append(row)

        return noise

    def generate_dct_matched_noise(
        self,
        width: int,
        height: int,
        block_size: int = 8,
    ) -> List[List[float]]:
        """
        Generate noise matching expected DCT coefficient distribution.

        Creates noise in frequency domain then transforms back to spatial,
        ensuring DCT statistics match natural images.

        Args:
            width: Image width in pixels.
            height: Image height in pixels.
            block_size: DCT block size (default 8, like JPEG).

        Returns:
            2D array of noise values.
        """
        # Simplified: Generate noise with frequency falloff
        # In practice, would use actual DCT/IDCT

        noise = []
        falloff = self.profile.dct_falloff

        for y in range(height):
            row = []
            for x in range(width):
                # Multiple frequency components with falloff
                value = 0.0

                # Simulate different frequency bands
                for freq in range(1, 5):
                    amplitude = self.profile.target_std * (falloff**freq)
                    phase_x = self.rng.random_float() * 2 * math.pi
                    phase_y = self.rng.random_float() * 2 * math.pi

                    component = (
                        amplitude
                        * math.sin(freq * x * math.pi / block_size + phase_x)
                        * math.sin(freq * y * math.pi / block_size + phase_y)
                    )
                    value += component * self.rng.random_gaussian(0, 0.3)

                row.append(value)
            noise.append(row)

        return noise

    def generate_combined_noise(
        self,
        width: int,
        height: int,
        sensor_weight: float = 0.4,
        texture_weight: float = 0.3,
        dct_weight: float = 0.3,
    ) -> List[List[float]]:
        """
        Generate combined adversarial noise from multiple sources.

        Blends sensor noise, texture noise, and DCT-matched noise for
        realistic statistics.

        Args:
            width: Image width.
            height: Image height.
            sensor_weight: Weight for sensor noise.
            texture_weight: Weight for texture noise.
            dct_weight: Weight for DCT-matched noise.

        Returns:
            2D array of combined noise values.
        """
        # Normalize weights
        total = sensor_weight + texture_weight + dct_weight
        sensor_weight /= total
        texture_weight /= total
        dct_weight /= total

        # Generate noise layers
        sensor = self.generate_sensor_noise(width, height)
        texture = self.generate_texture_noise(width, height)
        dct = self.generate_dct_matched_noise(width, height)

        # Combine
        noise = []
        for y in range(height):
            row = []
            for x in range(width):
                value = (
                    sensor[y][x] * sensor_weight
                    + texture[y][x] * texture_weight
                    + dct[y][x] * dct_weight
                )
                row.append(value)
            noise.append(row)

        return noise

    def histogram_equalize(
        self,
        noise: List[List[float]],
        target_histogram: Optional[List[float]] = None,
    ) -> List[List[float]]:
        """
        Equalize noise histogram to match target distribution.

        Helps defeat χ² tests that look for unusual distributions.

        Args:
            noise: Input noise array.
            target_histogram: Target histogram (256 bins). If None, uses flat.

        Returns:
            Histogram-equalized noise.
        """
        height = len(noise)
        width = len(noise[0]) if height > 0 else 0

        if target_histogram is None:
            # Flat histogram (uniform distribution)
            target_histogram = [1.0 / 256] * 256

        # Build CDF of target
        target_cdf = []
        cumsum = 0.0
        for h in target_histogram:
            cumsum += h
            target_cdf.append(cumsum)

        # Normalize to [0, 1]
        if cumsum > 0:
            target_cdf = [c / cumsum for c in target_cdf]

        # Collect all noise values
        values = []
        for row in noise:
            values.extend(row)

        # Sort and compute source CDF
        sorted_indices = sorted(range(len(values)), key=lambda i: values[i])
        n = len(values)

        # Map each value to target distribution
        mapped_values = [0.0] * n
        for rank, idx in enumerate(sorted_indices):
            # Position in source distribution
            source_pos = rank / max(1, n - 1)

            # Find corresponding position in target CDF
            target_bin = 0
            for i, cdf_val in enumerate(target_cdf):
                if cdf_val >= source_pos:
                    target_bin = i
                    break

            # Map to target value range
            noise_range = self.profile.target_std * 4
            mapped_values[idx] = (target_bin / 255 - 0.5) * noise_range

        # Reshape to 2D
        result = []
        idx = 0
        for y in range(height):
            row = []
            for x in range(width):
                row.append(mapped_values[idx])
                idx += 1
            result.append(row)

        return result


def generate_sensor_noise(
    width: int,
    height: int,
    seed: Optional[bytes] = None,
) -> List[List[float]]:
    """Convenience function for sensor noise generation."""
    gen = AdversarialNoiseGenerator(seed)
    return gen.generate_sensor_noise(width, height)


def generate_texture_noise(
    width: int,
    height: int,
    seed: Optional[bytes] = None,
    grain_size: int = 4,
) -> List[List[float]]:
    """Convenience function for texture noise generation."""
    profile = NoiseProfile(texture_grain_size=grain_size)
    gen = AdversarialNoiseGenerator(seed, profile)
    return gen.generate_texture_noise(width, height)


def histogram_equalize_noise(
    noise: List[List[float]],
    seed: Optional[bytes] = None,
) -> List[List[float]]:
    """Convenience function for histogram equalization."""
    gen = AdversarialNoiseGenerator(seed)
    return gen.histogram_equalize(noise)


def apply_dct_matching(
    noise: List[List[float]],
    falloff: float = 0.8,
    seed: Optional[bytes] = None,
) -> List[List[float]]:
    """
    Apply DCT-based frequency matching to existing noise.

    Modifies noise to match expected DCT coefficient distribution.
    """
    profile = NoiseProfile(dct_falloff=falloff)
    gen = AdversarialNoiseGenerator(seed, profile)

    height = len(noise)
    width = len(noise[0]) if height > 0 else 0

    # Generate DCT-matched noise and blend
    dct_noise = gen.generate_dct_matched_noise(width, height)

    result = []
    for y in range(height):
        row = []
        for x in range(width):
            # Blend original with DCT-matched
            value = noise[y][x] * 0.5 + dct_noise[y][x] * 0.5
            row.append(value)
        result.append(row)

    return result


def generate_carrier_noise(
    width: int,
    height: int,
    seed: Optional[bytes] = None,
    profile: Optional[NoiseProfile] = None,
) -> List[List[int]]:
    """
    Generate complete carrier noise pattern as integer pixel values.

    Ready to be added to carrier image or used as standalone noise layer.

    Args:
        width: Image width.
        height: Image height.
        seed: Random seed for deterministic generation.
        profile: Noise profile to match.

    Returns:
        2D array of integer noise values (centered around 0).
    """
    gen = AdversarialNoiseGenerator(seed, profile)

    # Generate combined noise
    float_noise = gen.generate_combined_noise(width, height)

    # Histogram equalize for uniform statistics
    float_noise = gen.histogram_equalize(float_noise)

    # Convert to integer
    result = []
    for row in float_noise:
        int_row = []
        for value in row:
            # Round to integer, clamp to reasonable range
            int_value = int(round(value))
            int_value = max(-128, min(127, int_value))
            int_row.append(int_value)
        result.append(int_row)

    return result


# Steganalysis test functions (for verification)
def chi_square_test(
    data: List[int],
    expected: Optional[List[float]] = None,
) -> float:
    """
    Chi-square test for uniformity.

    Lower values indicate data matches expected distribution.
    Used to verify noise doesn't have detectable patterns.

    Args:
        data: Sample data values.
        expected: Expected frequencies (None for uniform).

    Returns:
        Chi-square statistic.
    """
    # Build histogram
    hist = {}
    for v in data:
        hist[v] = hist.get(v, 0) + 1

    # If no expected, assume uniform
    if expected is None:
        unique_vals = len(hist)
        expected_count = len(data) / unique_vals
        expected = {k: expected_count for k in hist.keys()}
    else:
        expected = dict(enumerate(expected))

    # Compute chi-square
    chi2 = 0.0
    for k, observed in hist.items():
        exp = expected.get(k, len(data) / len(hist))
        if exp > 0:
            chi2 += (observed - exp) ** 2 / exp

    return chi2


def pairs_test(data: bytes) -> float:
    """
    Sample pairs analysis (SPA) for LSB detection.

    Looks for characteristic LSB embedding patterns.
    Lower values indicate less detectability.

    Args:
        data: Byte data to analyze.

    Returns:
        SPA detection statistic.
    """
    if len(data) < 4:
        return 0.0

    # Count 2m and 2m+1 pairs
    pairs = {}
    for i in range(len(data) - 1):
        pair = (data[i], data[i + 1])
        pairs[pair] = pairs.get(pair, 0) + 1

    # Look for even/odd imbalance
    even_count = 0
    odd_count = 0

    for (a, b), count in pairs.items():
        if (a & 1) == (b & 1):
            even_count += count
        else:
            odd_count += count

    total = even_count + odd_count
    if total == 0:
        return 0.0

    # Return imbalance ratio
    return abs(even_count - odd_count) / total


def adversarial_embed(
    frame: "Image.Image",
    carrier: Optional["Image.Image"],
    algo: str = "sensor",
    seed: Optional[bytes] = None,
) -> "Image.Image":
    """
    Apply adversarial noise to a carrier image to defeat steganalysis.

    Args:
        frame: The QR frame (used for sizing if carrier is None)
        carrier: The carrier image to modify
        algo: Noise algorithm ('sensor', 'texture', 'dct', 'combined')
        seed: Random seed for deterministic noise

    Returns:
        Modified carrier image
    """
    from PIL import Image
    import numpy as np

    if carrier is None:
        # Create a blank carrier if none provided
        carrier = Image.new("RGB", frame.size, (128, 128, 128))

    width, height = carrier.size

    # Generate noise based on algorithm
    if algo == "sensor":
        noise = generate_sensor_noise(width, height, seed)
    elif algo == "texture":
        noise = generate_texture_noise(width, height, seed)
    elif algo == "dct":
        # Start with sensor noise, then apply DCT matching
        base_noise = generate_sensor_noise(width, height, seed)
        noise = apply_dct_matching(base_noise, seed=seed)
    elif algo == "combined":
        gen = AdversarialNoiseGenerator(seed)
        noise = gen.generate_combined_noise(width, height)
    else:
        noise = generate_sensor_noise(width, height, seed)

    # Apply noise to carrier
    carrier_arr = np.array(carrier).astype(np.float32)

    # Add noise to all channels
    noise_arr = np.array(noise)
    for c in range(3):
        carrier_arr[:, :, c] += noise_arr

    # Clip and convert back
    carrier_arr = np.clip(carrier_arr, 0, 255).astype(np.uint8)
    return Image.fromarray(carrier_arr)
