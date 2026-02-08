"""Tests for quantum mixer module."""

import pytest
import secrets
from meow_decoder.quantum_mixer import (
    derive_quantum_noise,
    entangle_realities,
    collapse_to_reality,
    expand_noise,
    compute_entanglement_root,
    verify_indistinguishability,
    YARN_REALITY_A,
    YARN_REALITY_B,
)


class TestQuantumNoiseDerivation:
    """Tests for quantum noise derivation."""

    def test_derive_quantum_noise_basic(self):
        """Test basic quantum noise derivation."""
        salt = secrets.token_bytes(16)
        noise = derive_quantum_noise("password1", "password2", salt)

        assert len(noise) == 32
        assert isinstance(noise, bytes)

    def test_derive_quantum_noise_deterministic(self):
        """Test that same inputs produce same noise."""
        salt = secrets.token_bytes(16)
        noise1 = derive_quantum_noise("pass_a", "pass_b", salt)
        noise2 = derive_quantum_noise("pass_a", "pass_b", salt)

        assert noise1 == noise2

    def test_derive_quantum_noise_different_passwords(self):
        """Test that different passwords produce different noise."""
        salt = secrets.token_bytes(16)
        noise1 = derive_quantum_noise("pass_a", "pass_b", salt)
        noise2 = derive_quantum_noise("pass_c", "pass_d", salt)

        assert noise1 != noise2

    def test_derive_quantum_noise_custom_length(self):
        """Test custom output length."""
        salt = secrets.token_bytes(16)
        noise = derive_quantum_noise("pass_a", "pass_b", salt, length=64)

        assert len(noise) == 64


class TestEntangleRealities:
    """Tests for reality entanglement."""

    def test_entangle_same_length(self):
        """Test entangling equal-length realities."""
        reality_a = b"AAAAAAAAAA"
        reality_b = b"BBBBBBBBBB"

        superposition = entangle_realities(reality_a, reality_b)

        assert len(superposition) == 20

    def test_entangle_different_lengths(self):
        """Test entangling different-length realities."""
        reality_a = b"AAAAA"
        reality_b = b"BBBBBBBBBB"

        superposition = entangle_realities(reality_a, reality_b)

        assert len(superposition) == 20

    def test_entangle_preserves_data(self):
        """Test that entanglement preserves original data."""
        reality_a = b"Secret A data here"
        reality_b = b"Secret B data here"

        superposition = entangle_realities(reality_a, reality_b)

        collapsed_a = collapse_to_reality(superposition, YARN_REALITY_A)
        collapsed_b = collapse_to_reality(superposition, YARN_REALITY_B)

        assert collapsed_a[: len(reality_a)] == reality_a
        assert collapsed_b[: len(reality_b)] == reality_b


class TestCollapseToReality:
    """Tests for reality collapse."""

    def test_collapse_to_reality_a(self):
        """Test collapsing to reality A."""
        reality_a = b"AAAAAAAAAA"
        reality_b = b"BBBBBBBBBB"

        superposition = entangle_realities(reality_a, reality_b)
        collapsed = collapse_to_reality(superposition, YARN_REALITY_A)

        assert collapsed == reality_a

    def test_collapse_to_reality_b(self):
        """Test collapsing to reality B."""
        reality_a = b"AAAAAAAAAA"
        reality_b = b"BBBBBBBBBB"

        superposition = entangle_realities(reality_a, reality_b)
        collapsed = collapse_to_reality(superposition, YARN_REALITY_B)

        assert collapsed == reality_b

    def test_collapse_roundtrip(self):
        """Test full entangle/collapse roundtrip."""
        reality_a = secrets.token_bytes(100)
        reality_b = secrets.token_bytes(100)

        superposition = entangle_realities(reality_a, reality_b)
        recovered_a = collapse_to_reality(superposition, YARN_REALITY_A)
        recovered_b = collapse_to_reality(superposition, YARN_REALITY_B)

        assert recovered_a == reality_a
        assert recovered_b == reality_b


class TestExpandNoise:
    """Tests for noise expansion."""

    def test_expand_noise_shorter(self):
        """Test expanding to shorter length."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 16)

        assert len(expanded) == 16
        assert expanded == seed[:16]

    def test_expand_noise_equal(self):
        """Test expanding to equal length."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 32)

        assert len(expanded) == 32
        assert expanded == seed

    def test_expand_noise_longer(self):
        """Test expanding to longer length."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 64)

        assert len(expanded) == 64


class TestComputeEntanglementRoot:
    """Tests for Merkle root computation."""

    def test_compute_root_empty(self):
        """Test computing root of empty list."""
        root = compute_entanglement_root([])

        assert len(root) == 32

    def test_compute_root_single_block(self):
        """Test computing root of single block."""
        blocks = [b"single block data"]
        root = compute_entanglement_root(blocks)

        assert len(root) == 32

    def test_compute_root_multiple_blocks(self):
        """Test computing root of multiple blocks."""
        blocks = [b"block1", b"block2", b"block3", b"block4"]
        root = compute_entanglement_root(blocks)

        assert len(root) == 32

    def test_compute_root_deterministic(self):
        """Test that same blocks produce same root."""
        blocks = [b"block1", b"block2"]
        root1 = compute_entanglement_root(blocks)
        root2 = compute_entanglement_root(blocks)

        assert root1 == root2

    def test_compute_root_different_blocks(self):
        """Test that different blocks produce different roots."""
        blocks1 = [b"block1", b"block2"]
        blocks2 = [b"block1", b"block3"]

        root1 = compute_entanglement_root(blocks1)
        root2 = compute_entanglement_root(blocks2)

        assert root1 != root2


class TestVerifyIndistinguishability:
    """Tests for statistical indistinguishability verification."""

    def test_verify_random_data(self):
        """Test verification with random data."""
        data_a = secrets.token_bytes(1000)
        data_b = secrets.token_bytes(1000)

        is_indist, results = verify_indistinguishability(data_a, data_b)

        assert isinstance(is_indist, bool)
        assert "entropy_a" in results
        assert "entropy_b" in results
        assert "entropy_diff" in results
        assert "max_freq_diff" in results

    def test_verify_identical_data(self):
        """Test verification with identical data."""
        data = secrets.token_bytes(1000)

        is_indist, results = verify_indistinguishability(data, data)

        assert is_indist is True
        assert results["entropy_diff"] == 0.0
        assert results["max_freq_diff"] == 0.0

    def test_verify_very_different_data(self):
        """Test verification with very different data."""
        data_a = b"\x00" * 1000
        data_b = b"\xff" * 1000

        is_indist, results = verify_indistinguishability(data_a, data_b)

        assert "entropy_diff" in results
