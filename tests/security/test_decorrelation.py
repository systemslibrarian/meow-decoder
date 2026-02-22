"""
Tests for inter-file decorrelation module.

Tests cover:
- CSPRNG integer generation (uniform, bounds, bias rejection)
- CSPRNG float generation (uniform, bounds)
- Config decorrelation (all parameters randomized within valid ranges)
- Security invariant: crypto parameters NOT modified
"""

import os
import struct
from dataclasses import dataclass

import pytest

from meow_decoder.decorrelation import (
    DecorrelationParams,
    _csprng_float,
    _csprng_int,
    decorrelate_config,
)


class TestCsprngInt:
    """Tests for cryptographic random integer generation."""

    def test_within_bounds(self):
        """Generated integers should be in [low, high]."""
        for _ in range(200):
            val = _csprng_int(10, 50)
            assert 10 <= val <= 50

    def test_equal_bounds(self):
        """Equal low and high should return that value."""
        assert _csprng_int(42, 42) == 42

    def test_invalid_bounds(self):
        """low > high should raise ValueError."""
        with pytest.raises(ValueError):
            _csprng_int(50, 10)

    def test_full_range_coverage(self):
        """Should cover the entire range given enough samples."""
        values = {_csprng_int(0, 4) for _ in range(500)}
        assert values == {0, 1, 2, 3, 4}

    def test_uniformity(self):
        """Distribution should be roughly uniform (chi-squared)."""
        low, high = 0, 9
        counts = [0] * (high - low + 1)
        n = 5000
        for _ in range(n):
            val = _csprng_int(low, high)
            counts[val - low] += 1

        expected = n / (high - low + 1)
        chi_sq = sum((c - expected) ** 2 / expected for c in counts)
        # 9 degrees of freedom, p=0.01 critical value ≈ 21.67
        assert chi_sq < 25, f"Chi-squared {chi_sq} too high (non-uniform)"


class TestCsprngFloat:
    """Tests for cryptographic random float generation."""

    def test_within_bounds(self):
        """Generated floats should be in [low, high]."""
        for _ in range(200):
            val = _csprng_float(1.0, 5.0)
            assert 1.0 <= val <= 5.0

    def test_invalid_bounds(self):
        """low > high should raise ValueError."""
        with pytest.raises(ValueError):
            _csprng_float(5.0, 1.0)

    def test_generates_variety(self):
        """Multiple calls should return different values."""
        values = {_csprng_float(0.0, 1.0) for _ in range(50)}
        assert len(values) > 20  # Should get many unique floats


@dataclass
class MockConfig:
    """Mock config for testing decorrelation."""

    block_size: int = 512
    redundancy: float = 1.5
    fps: int = 2
    qr_border: int = 4
    qr_box_size: int = 14
    # Crypto params (should NOT be modified)
    qr_error_correction: str = "H"
    qr_version: int = 25
    enable_forward_secrecy: bool = True
    enable_pq: bool = True


class TestDecorrelateConfig:
    """Tests for config decorrelation."""

    def test_modifies_block_size(self):
        """block_size should be randomized."""
        configs = [MockConfig() for _ in range(20)]
        for c in configs:
            decorrelate_config(c)

        block_sizes = {c.block_size for c in configs}
        # Should have variation
        assert len(block_sizes) > 3

    def test_block_size_in_range(self):
        """block_size should be within default range [400, 700]."""
        for _ in range(50):
            c = MockConfig()
            decorrelate_config(c)
            assert 400 <= c.block_size <= 700

    def test_redundancy_in_range(self):
        """redundancy should be within [1.3, 2.0]."""
        for _ in range(50):
            c = MockConfig()
            decorrelate_config(c)
            assert 1.3 <= c.redundancy <= 2.0

    def test_fps_in_range(self):
        """fps should be within [1, 4]."""
        for _ in range(50):
            c = MockConfig()
            decorrelate_config(c)
            assert 1 <= c.fps <= 4

    def test_qr_border_in_range(self):
        """qr_border should be within [3, 6]."""
        for _ in range(50):
            c = MockConfig()
            decorrelate_config(c)
            assert 3 <= c.qr_border <= 6

    def test_qr_box_size_in_range(self):
        """qr_box_size should be within [10, 18]."""
        for _ in range(50):
            c = MockConfig()
            decorrelate_config(c)
            assert 10 <= c.qr_box_size <= 18

    def test_crypto_params_not_modified(self):
        """Security-critical parameters must NOT be changed."""
        c = MockConfig()
        decorrelate_config(c)
        assert c.qr_error_correction == "H"
        assert c.qr_version == 25
        assert c.enable_forward_secrecy is True
        assert c.enable_pq is True

    def test_custom_params(self):
        """Custom DecorrelationParams should be respected."""
        params = DecorrelationParams(
            block_size_min=100,
            block_size_max=200,
            fps_min=5,
            fps_max=10,
        )
        for _ in range(50):
            c = MockConfig()
            decorrelate_config(c, params=params)
            assert 100 <= c.block_size <= 200
            assert 5 <= c.fps <= 10

    def test_inter_file_decorrelation(self):
        """Two consecutive configs should differ (with high probability)."""
        c1 = MockConfig()
        c2 = MockConfig()
        decorrelate_config(c1)
        decorrelate_config(c2)

        # At least one parameter should differ (extremely high probability)
        differs = (
            c1.block_size != c2.block_size
            or c1.redundancy != c2.redundancy
            or c1.fps != c2.fps
            or c1.qr_border != c2.qr_border
            or c1.qr_box_size != c2.qr_box_size
        )
        # Could theoretically be the same, but probability is ~1/(301*7*4*4*9) ≈ 1/300K
        # Run the test — if it fails, it's a legitimate CSPRNG concern
        assert differs, "Two decorrelated configs should differ"
