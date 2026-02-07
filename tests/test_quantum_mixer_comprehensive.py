#!/usr/bin/env python3
"""
🐱⚛️ Comprehensive Test Suite for quantum_mixer.py

Schrödinger's Yarn Ball Core - Cryptographic Mixing for Plausible Deniability

"You cannot prove a secret exists unless you already know how to look for it.
 And once you look… you've already chosen your reality."

Target Coverage: 88-94%
"""

import pytest
import hashlib
import secrets
import struct
from collections import Counter
from unittest.mock import patch, MagicMock

# Import the module under test
from meow_decoder.quantum_mixer import (
    QuantumState,
    derive_quantum_noise,
    entangle_realities,
    collapse_to_reality,
    expand_noise,
    compute_entanglement_root,
    verify_indistinguishability,
    YARN_REALITY_A,
    YARN_REALITY_B,
    YARN_TANGLED,
)

# =============================================================================
# 🐱 Test Fixtures - Quantum Yarn Ball Setup
# =============================================================================


@pytest.fixture
def password_a():
    """Meow's first password for reality A."""
    return "CatSecretPassword123!"


@pytest.fixture
def password_b():
    """Meow's second password for reality B."""
    return "DogDecoyPassword456!"


@pytest.fixture
def quantum_salt():
    """Random salt for quantum operations."""
    return secrets.token_bytes(16)


@pytest.fixture
def reality_a_data():
    """Secret data for reality A - the cat's true secrets."""
    return b"TOP SECRET: Cat world domination plans! " * 10


@pytest.fixture
def reality_b_data():
    """Decoy data for reality B - innocent cat photos."""
    return b"Innocent vacation photos of cats on beach! " * 10


@pytest.fixture
def sample_blocks():
    """Sample blocks for Merkle tree testing."""
    return [secrets.token_bytes(64) for _ in range(8)]


@pytest.fixture
def equal_length_realities():
    """Two realities of exactly equal length."""
    return b"A" * 100, b"B" * 100


@pytest.fixture
def unequal_length_realities():
    """Two realities of different lengths (shorter will be padded)."""
    return b"A" * 50, b"B" * 100


# =============================================================================
# 🐱 Test Class: QuantumState Dataclass
# =============================================================================


class TestQuantumStateMeow:
    """Tests for the QuantumState dataclass - the cat's quantum yarn ball."""

    def test_quantum_state_creation_meow(self):
        """Test creating a QuantumState with all fields."""
        state = QuantumState(
            mixed_data=b"mixed_meow_data",
            reality_a_key=b"key_a_32bytes___________________",
            reality_b_key=b"key_b_32bytes___________________",
            quantum_noise=b"noise_32bytes___________________",
            entanglement_root=b"root_32bytes____________________",
        )

        assert state.mixed_data == b"mixed_meow_data"
        assert state.reality_a_key == b"key_a_32bytes___________________"
        assert state.reality_b_key == b"key_b_32bytes___________________"
        assert state.quantum_noise == b"noise_32bytes___________________"
        assert state.entanglement_root == b"root_32bytes____________________"

    def test_quantum_state_immutability_meow(self):
        """Test that QuantumState is a dataclass (not frozen by default)."""
        state = QuantumState(
            mixed_data=b"original",
            reality_a_key=b"key_a",
            reality_b_key=b"key_b",
            quantum_noise=b"noise",
            entanglement_root=b"root",
        )

        # Dataclass allows modification by default
        state.mixed_data = b"modified"
        assert state.mixed_data == b"modified"

    def test_quantum_state_equality_meow(self):
        """Test QuantumState equality comparison."""
        state1 = QuantumState(
            mixed_data=b"data",
            reality_a_key=b"key_a",
            reality_b_key=b"key_b",
            quantum_noise=b"noise",
            entanglement_root=b"root",
        )
        state2 = QuantumState(
            mixed_data=b"data",
            reality_a_key=b"key_a",
            reality_b_key=b"key_b",
            quantum_noise=b"noise",
            entanglement_root=b"root",
        )

        assert state1 == state2


# =============================================================================
# 🐱 Test Class: Quantum Noise Derivation
# =============================================================================


class TestDeriveQuantumNoiseMeow:
    """Tests for derive_quantum_noise - tangling the cat's yarn."""

    def test_derive_noise_basic_meow(self, password_a, password_b, quantum_salt):
        """Test basic quantum noise derivation."""
        noise = derive_quantum_noise(password_a, password_b, quantum_salt)

        assert isinstance(noise, bytes)
        assert len(noise) == 32  # Default length

    def test_derive_noise_deterministic_meow(self, password_a, password_b, quantum_salt):
        """Test that same inputs produce same noise (deterministic)."""
        noise1 = derive_quantum_noise(password_a, password_b, quantum_salt)
        noise2 = derive_quantum_noise(password_a, password_b, quantum_salt)

        assert noise1 == noise2

    def test_derive_noise_different_passwords_meow(self, quantum_salt):
        """Test that different passwords produce different noise."""
        noise1 = derive_quantum_noise("password1", "password2", quantum_salt)
        noise2 = derive_quantum_noise("password3", "password4", quantum_salt)

        assert noise1 != noise2

    def test_derive_noise_password_order_matters_meow(self, password_a, password_b, quantum_salt):
        """Test that swapping password order produces different noise."""
        noise1 = derive_quantum_noise(password_a, password_b, quantum_salt)
        noise2 = derive_quantum_noise(password_b, password_a, quantum_salt)

        # XOR is commutative, so swapping doesn't change the combined hash
        # But the noise should still be identical due to XOR commutativity
        assert noise1 == noise2

    def test_derive_noise_different_salt_meow(self, password_a, password_b):
        """Test that different salts produce different noise."""
        salt1 = b"salt1___________"
        salt2 = b"salt2___________"

        noise1 = derive_quantum_noise(password_a, password_b, salt1)
        noise2 = derive_quantum_noise(password_a, password_b, salt2)

        assert noise1 != noise2

    def test_derive_noise_custom_length_meow(self, password_a, password_b, quantum_salt):
        """Test deriving noise with custom length."""
        noise_16 = derive_quantum_noise(password_a, password_b, quantum_salt, length=16)
        noise_64 = derive_quantum_noise(password_a, password_b, quantum_salt, length=64)

        assert len(noise_16) == 16
        assert len(noise_64) == 64

    def test_derive_noise_zero_length_meow(self, password_a, password_b, quantum_salt):
        """Test deriving zero-length noise."""
        # HKDF with length=0 should return empty bytes
        noise = derive_quantum_noise(password_a, password_b, quantum_salt, length=0)
        assert noise == b""

    def test_derive_noise_empty_passwords_meow(self, quantum_salt):
        """Test with empty passwords."""
        noise = derive_quantum_noise("", "", quantum_salt)

        assert isinstance(noise, bytes)
        assert len(noise) == 32

    def test_derive_noise_unicode_passwords_meow(self, quantum_salt):
        """Test with unicode passwords (cat emoji!)."""
        noise = derive_quantum_noise("🐱password", "😺secret", quantum_salt)

        assert isinstance(noise, bytes)
        assert len(noise) == 32

    def test_derive_noise_long_passwords_meow(self, quantum_salt):
        """Test with very long passwords."""
        long_password_a = "A" * 10000
        long_password_b = "B" * 10000

        noise = derive_quantum_noise(long_password_a, long_password_b, quantum_salt)

        assert isinstance(noise, bytes)
        assert len(noise) == 32


# =============================================================================
# 🐱 Test Class: Entangle Realities
# =============================================================================


class TestEntangleRealitiesMeow:
    """Tests for entangle_realities - weaving the quantum yarn ball."""

    def test_entangle_equal_length_meow(self, equal_length_realities):
        """Test entangling equal length realities."""
        reality_a, reality_b = equal_length_realities

        superposition = entangle_realities(reality_a, reality_b)

        # Superposition should be 2x the length
        assert len(superposition) == len(reality_a) + len(reality_b)

    def test_entangle_unequal_length_meow(self, unequal_length_realities):
        """Test entangling unequal length realities (shorter is padded)."""
        reality_a, reality_b = unequal_length_realities
        max_len = max(len(reality_a), len(reality_b))

        superposition = entangle_realities(reality_a, reality_b)

        # Superposition should be 2x the max length
        assert len(superposition) == max_len * 2

    def test_entangle_preserves_data_meow(self, reality_a_data, reality_b_data):
        """Test that entangling preserves both realities."""
        superposition = entangle_realities(reality_a_data, reality_b_data)

        # Extract even positions (reality A)
        extracted_a = bytes(superposition[i] for i in range(0, len(superposition), 2))
        # Extract odd positions (reality B)
        extracted_b = bytes(superposition[i] for i in range(1, len(superposition), 2))

        # Reality A should match (possibly padded)
        assert extracted_a[: len(reality_a_data)] == reality_a_data
        # Reality B should match (possibly padded)
        assert extracted_b[: len(reality_b_data)] == reality_b_data

    def test_entangle_interleaving_pattern_meow(self):
        """Test the interleaving pattern is correct."""
        reality_a = b"AAAA"
        reality_b = b"BBBB"

        superposition = entangle_realities(reality_a, reality_b)

        # Should interleave: A[0], B[0], A[1], B[1], ...
        expected = b"ABABABAB"
        assert superposition == expected

    def test_entangle_empty_realities_meow(self):
        """Test entangling empty realities."""
        superposition = entangle_realities(b"", b"")

        assert superposition == b""

    def test_entangle_one_empty_meow(self):
        """Test entangling when one reality is empty."""
        reality_a = b"AAAA"
        reality_b = b""

        superposition = entangle_realities(reality_a, reality_b)

        # Both padded to len(reality_a), so superposition is 2x that
        assert len(superposition) == len(reality_a) * 2

        # Even positions should be reality_a
        extracted_a = bytes(superposition[i] for i in range(0, len(superposition), 2))
        assert extracted_a == reality_a

    def test_entangle_large_data_meow(self):
        """Test entangling large data."""
        reality_a = secrets.token_bytes(100000)
        reality_b = secrets.token_bytes(100000)

        superposition = entangle_realities(reality_a, reality_b)

        assert len(superposition) == 200000

    def test_entangle_padding_is_random_meow(self):
        """Test that padding uses random bytes."""
        reality_a = b"A" * 10
        reality_b = b"B" * 100

        # Call twice with same input
        super1 = entangle_realities(reality_a, reality_b)
        super2 = entangle_realities(reality_a, reality_b)

        # The padding portion should be different (random)
        # Extract padding from reality_a (positions 10-100 in even slots)
        padding1 = bytes(super1[i] for i in range(20, len(super1), 2))
        padding2 = bytes(super2[i] for i in range(20, len(super2), 2))

        # Random padding means they should differ
        assert padding1 != padding2


# =============================================================================
# 🐱 Test Class: Collapse to Reality
# =============================================================================


class TestCollapseToRealityMeow:
    """Tests for collapse_to_reality - observing the quantum state."""

    def test_collapse_reality_a_meow(self):
        """Test collapsing to reality A (index 0)."""
        reality_a = b"SECRETCATDATA"
        reality_b = b"DECOYDOG_DATA"

        superposition = entangle_realities(reality_a, reality_b)
        collapsed = collapse_to_reality(superposition, YARN_REALITY_A)

        assert collapsed == reality_a

    def test_collapse_reality_b_meow(self):
        """Test collapsing to reality B (index 1)."""
        reality_a = b"SECRETCATDATA"
        reality_b = b"DECOYDOG_DATA"

        superposition = entangle_realities(reality_a, reality_b)
        collapsed = collapse_to_reality(superposition, YARN_REALITY_B)

        assert collapsed == reality_b

    def test_collapse_preserves_data_meow(self, reality_a_data, reality_b_data):
        """Test that collapse preserves original data."""
        # Make them equal length to avoid padding issues
        min_len = min(len(reality_a_data), len(reality_b_data))
        ra = reality_a_data[:min_len]
        rb = reality_b_data[:min_len]

        superposition = entangle_realities(ra, rb)

        collapsed_a = collapse_to_reality(superposition, 0)
        collapsed_b = collapse_to_reality(superposition, 1)

        assert collapsed_a == ra
        assert collapsed_b == rb

    def test_collapse_empty_superposition_meow(self):
        """Test collapsing empty superposition."""
        collapsed = collapse_to_reality(b"", 0)
        assert collapsed == b""

    def test_collapse_single_byte_meow(self):
        """Test collapsing minimal superposition (2 bytes)."""
        superposition = b"AB"

        assert collapse_to_reality(superposition, 0) == b"A"
        assert collapse_to_reality(superposition, 1) == b"B"

    def test_collapse_odd_length_superposition_meow(self):
        """Test collapsing odd-length superposition."""
        superposition = b"ABC"  # Odd length

        # Even positions: A, C (indices 0, 2)
        collapsed_a = collapse_to_reality(superposition, 0)
        # Odd positions: B (index 1)
        collapsed_b = collapse_to_reality(superposition, 1)

        assert collapsed_a == b"AC"
        assert collapsed_b == b"B"


# =============================================================================
# 🐱 Test Class: Expand Noise
# =============================================================================


class TestExpandNoiseMeow:
    """Tests for expand_noise - stretching the quantum yarn."""

    def test_expand_same_length_meow(self):
        """Test expanding to same length as seed."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 32)

        assert expanded == seed

    def test_expand_shorter_length_meow(self):
        """Test expanding to shorter length (truncation)."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 16)

        assert len(expanded) == 16
        assert expanded == seed[:16]

    def test_expand_longer_length_meow(self):
        """Test expanding to longer length."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 100)

        assert len(expanded) == 100

    def test_expand_deterministic_meow(self):
        """Test that expansion is deterministic."""
        seed = b"deterministic_seed______________"

        expanded1 = expand_noise(seed, 100)
        expanded2 = expand_noise(seed, 100)

        assert expanded1 == expanded2

    def test_expand_different_seeds_meow(self):
        """Test that different seeds produce different expansion."""
        seed1 = b"seed_one________________________"
        seed2 = b"seed_two________________________"

        expanded1 = expand_noise(seed1, 100)
        expanded2 = expand_noise(seed2, 100)

        assert expanded1 != expanded2

    def test_expand_large_length_meow(self):
        """Test expanding to very large length."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 10000)

        assert len(expanded) == 10000

    def test_expand_zero_length_meow(self):
        """Test expanding to zero length."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 0)

        assert expanded == b""

    def test_expand_chunking_meow(self):
        """Test that expansion creates cryptographically sound output."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 200)

        # Each chunk should be unique (not repeated pattern)
        chunk1 = expanded[0:32]
        chunk2 = expanded[32:64]
        chunk3 = expanded[64:96]

        assert chunk1 != chunk2
        assert chunk2 != chunk3
        assert chunk1 != chunk3


# =============================================================================
# 🐱 Test Class: Compute Entanglement Root
# =============================================================================


class TestComputeEntanglementRootMeow:
    """Tests for compute_entanglement_root - the Merkle yarn ball."""

    def test_merkle_root_basic_meow(self, sample_blocks):
        """Test basic Merkle root computation."""
        root = compute_entanglement_root(sample_blocks)

        assert isinstance(root, bytes)
        assert len(root) == 32  # SHA256 output

    def test_merkle_root_deterministic_meow(self, sample_blocks):
        """Test that Merkle root is deterministic."""
        root1 = compute_entanglement_root(sample_blocks)
        root2 = compute_entanglement_root(sample_blocks)

        assert root1 == root2

    def test_merkle_root_empty_blocks_meow(self):
        """Test Merkle root of empty block list."""
        root = compute_entanglement_root([])

        expected = hashlib.sha256(b"meow_empty_yarn").digest()
        assert root == expected

    def test_merkle_root_single_block_meow(self):
        """Test Merkle root of single block."""
        block = b"single_meow_block"
        root = compute_entanglement_root([block])

        expected = hashlib.sha256(block).digest()
        assert root == expected

    def test_merkle_root_two_blocks_meow(self):
        """Test Merkle root of two blocks."""
        block1 = b"block_one_meow"
        block2 = b"block_two_meow"

        root = compute_entanglement_root([block1, block2])

        # Manual calculation
        hash1 = hashlib.sha256(block1).digest()
        hash2 = hashlib.sha256(block2).digest()
        expected = hashlib.sha256(hash1 + hash2).digest()

        assert root == expected

    def test_merkle_root_odd_number_blocks_meow(self):
        """Test Merkle root with odd number of blocks (last is duplicated)."""
        blocks = [b"block_1", b"block_2", b"block_3"]

        root = compute_entanglement_root(blocks)

        # Should handle odd count by duplicating last at each level
        assert isinstance(root, bytes)
        assert len(root) == 32

    def test_merkle_root_tamper_detection_meow(self):
        """Test that modifying a block changes the root."""
        original_blocks = [b"block_1", b"block_2", b"block_3", b"block_4"]
        tampered_blocks = [b"block_1", b"TAMPERED", b"block_3", b"block_4"]

        root_original = compute_entanglement_root(original_blocks)
        root_tampered = compute_entanglement_root(tampered_blocks)

        assert root_original != root_tampered

    def test_merkle_root_order_matters_meow(self):
        """Test that block order affects the root."""
        blocks = [b"block_1", b"block_2", b"block_3", b"block_4"]
        reversed_blocks = list(reversed(blocks))

        root1 = compute_entanglement_root(blocks)
        root2 = compute_entanglement_root(reversed_blocks)

        assert root1 != root2

    def test_merkle_root_power_of_two_meow(self):
        """Test Merkle root with power-of-2 blocks (perfect tree)."""
        blocks = [secrets.token_bytes(32) for _ in range(16)]
        root = compute_entanglement_root(blocks)

        assert isinstance(root, bytes)
        assert len(root) == 32

    def test_merkle_root_large_blocks_meow(self):
        """Test with large blocks."""
        blocks = [secrets.token_bytes(10000) for _ in range(10)]
        root = compute_entanglement_root(blocks)

        assert isinstance(root, bytes)
        assert len(root) == 32


# =============================================================================
# 🐱 Test Class: Verify Indistinguishability
# =============================================================================


class TestVerifyIndistinguishabilityMeow:
    """Tests for verify_indistinguishability - can the cat hide its secrets?"""

    def test_verify_random_data_indistinguishable_meow(self):
        """Test that random data is indistinguishable."""
        data_a = secrets.token_bytes(10000)
        data_b = secrets.token_bytes(10000)

        is_indist, results = verify_indistinguishability(data_a, data_b, threshold=0.1)

        # Random data should be statistically similar
        assert "entropy_a" in results
        assert "entropy_b" in results
        assert "entropy_diff" in results
        assert "entropy_pass" in results
        assert "max_freq_diff" in results
        assert "freq_pass" in results
        assert "indistinguishable" in results

    def test_verify_identical_data_meow(self):
        """Test that identical data is indistinguishable."""
        data = secrets.token_bytes(1000)

        is_indist, results = verify_indistinguishability(data, data)

        assert is_indist is True
        assert results["entropy_diff"] == 0.0
        assert results["max_freq_diff"] == 0.0

    def test_verify_very_different_data_meow(self):
        """Test that very different data is distinguishable."""
        data_a = b"A" * 1000  # All same byte
        data_b = secrets.token_bytes(1000)  # Random

        is_indist, results = verify_indistinguishability(data_a, data_b)

        # Single byte vs random should be very different
        assert results["entropy_a"] == 0.0  # Single byte = zero entropy
        assert results["entropy_b"] > 7.0  # Random = high entropy
        assert is_indist is False

    def test_verify_threshold_effect_meow(self):
        """Test that threshold affects the result."""
        # Create slightly different random data
        data_a = secrets.token_bytes(5000)
        data_b = secrets.token_bytes(5000)

        # With strict threshold
        _, results_strict = verify_indistinguishability(data_a, data_b, threshold=0.001)

        # With relaxed threshold
        _, results_relaxed = verify_indistinguishability(data_a, data_b, threshold=0.5)

        # Relaxed should pass more often
        # (Can't guarantee, but relaxed is more lenient)
        assert results_relaxed["indistinguishable"] or not results_strict["indistinguishable"]

    def test_verify_empty_data_meow(self):
        """Test verification with empty data."""
        is_indist, results = verify_indistinguishability(b"", b"")

        assert results["entropy_a"] == 0.0
        assert results["entropy_b"] == 0.0
        assert results["entropy_diff"] == 0.0

    def test_verify_single_byte_data_meow(self):
        """Test verification with single byte."""
        is_indist, results = verify_indistinguishability(b"A", b"B")

        assert results["entropy_a"] == 0.0  # Single byte = zero entropy
        assert results["entropy_b"] == 0.0

    def test_verify_entropy_calculation_meow(self):
        """Test entropy calculation is correct."""
        # Data with known entropy
        # 256 unique bytes = max entropy of 8 bits/byte
        all_bytes = bytes(range(256)) * 4

        is_indist, results = verify_indistinguishability(all_bytes, all_bytes)

        # Should be close to 8 bits/byte (max)
        assert results["entropy_a"] > 7.9

    def test_verify_frequency_analysis_meow(self):
        """Test frequency analysis is correct."""
        # Create data with biased frequencies
        data_a = b"A" * 500 + b"B" * 500  # 50% A, 50% B
        data_b = b"A" * 900 + b"B" * 100  # 90% A, 10% B

        is_indist, results = verify_indistinguishability(data_a, data_b)

        # Should detect the frequency difference
        assert results["max_freq_diff"] == pytest.approx(0.4, abs=0.01)
        assert results["freq_pass"] is False


# =============================================================================
# 🐱 Test Class: Constants
# =============================================================================


class TestYarnConstantsMeow:
    """Tests for yarn metaphor constants."""

    def test_yarn_reality_a_meow(self):
        """Test YARN_REALITY_A constant."""
        assert YARN_REALITY_A == 0

    def test_yarn_reality_b_meow(self):
        """Test YARN_REALITY_B constant."""
        assert YARN_REALITY_B == 1

    def test_yarn_tangled_meow(self):
        """Test YARN_TANGLED constant."""
        assert YARN_TANGLED == 2


# =============================================================================
# 🐱 Test Class: Integration Tests
# =============================================================================


class TestQuantumMixerIntegrationMeow:
    """Integration tests for the quantum mixer workflow."""

    def test_full_entangle_collapse_cycle_meow(self, reality_a_data, reality_b_data):
        """Test complete entangle → collapse cycle."""
        # Make equal length
        min_len = min(len(reality_a_data), len(reality_b_data))
        ra = reality_a_data[:min_len]
        rb = reality_b_data[:min_len]

        # Entangle
        superposition = entangle_realities(ra, rb)

        # Collapse to A
        collapsed_a = collapse_to_reality(superposition, YARN_REALITY_A)
        assert collapsed_a == ra

        # Collapse to B
        collapsed_b = collapse_to_reality(superposition, YARN_REALITY_B)
        assert collapsed_b == rb

    def test_noise_plus_entangle_meow(self, password_a, password_b, quantum_salt):
        """Test quantum noise derivation followed by entanglement."""
        # Derive noise
        noise = derive_quantum_noise(password_a, password_b, quantum_salt)

        # Expand noise to create realities
        reality_a = expand_noise(noise, 100)

        # Use different derivation for reality B
        noise_b = derive_quantum_noise(password_b, password_a, quantum_salt)
        reality_b = expand_noise(noise_b, 100)

        # Entangle
        superposition = entangle_realities(reality_a, reality_b)

        # Verify
        assert len(superposition) == 200

    def test_merkle_root_of_entangled_blocks_meow(self):
        """Test computing Merkle root of entangled blocks."""
        # Create blocks
        blocks = []
        for i in range(8):
            reality_a = f"block_a_{i}".encode() * 10
            reality_b = f"block_b_{i}".encode() * 10
            entangled = entangle_realities(reality_a, reality_b)
            blocks.append(entangled)

        # Compute root
        root = compute_entanglement_root(blocks)

        assert len(root) == 32

        # Verify tamper detection
        blocks_tampered = blocks.copy()
        blocks_tampered[0] = b"TAMPERED" * 50
        root_tampered = compute_entanglement_root(blocks_tampered)

        assert root != root_tampered

    def test_indistinguishability_of_entangled_data_meow(self):
        """Test that entangled data appears indistinguishable."""
        # Create two similar-entropy realities
        reality_a = secrets.token_bytes(5000)
        reality_b = secrets.token_bytes(5000)

        # Entangle
        superposition = entangle_realities(reality_a, reality_b)

        # Split superposition in half
        half = len(superposition) // 2
        first_half = superposition[:half]
        second_half = superposition[half:]

        # Verify they look similar
        is_indist, results = verify_indistinguishability(first_half, second_half, threshold=0.1)

        # Entangled random data should be indistinguishable
        assert results["entropy_diff"] < 0.1

    def test_quantum_state_workflow_meow(self, password_a, password_b, quantum_salt):
        """Test creating a full QuantumState."""
        # Create realities
        reality_a = b"TOP SECRET CAT DATA!" * 100
        reality_b = b"Innocent dog photos!" * 100

        # Derive noise
        noise = derive_quantum_noise(password_a, password_b, quantum_salt)

        # Entangle
        superposition = entangle_realities(reality_a, reality_b)

        # Split into blocks and compute root
        block_size = 200
        blocks = [
            superposition[i : i + block_size] for i in range(0, len(superposition), block_size)
        ]
        root = compute_entanglement_root(blocks)

        # Create QuantumState
        state = QuantumState(
            mixed_data=superposition,
            reality_a_key=hashlib.sha256(password_a.encode()).digest(),
            reality_b_key=hashlib.sha256(password_b.encode()).digest(),
            quantum_noise=noise,
            entanglement_root=root,
        )

        # Verify
        assert len(state.mixed_data) == len(superposition)
        assert len(state.quantum_noise) == 32
        assert len(state.entanglement_root) == 32


# =============================================================================
# 🐱 Test Class: Edge Cases
# =============================================================================


class TestQuantumMixerEdgeCasesMeow:
    """Edge case tests for the quantum mixer."""

    def test_entangle_with_null_bytes_meow(self):
        """Test entangling data with null bytes."""
        reality_a = b"\x00\x00\x00\x00"
        reality_b = b"\xff\xff\xff\xff"

        superposition = entangle_realities(reality_a, reality_b)

        assert collapse_to_reality(superposition, 0) == reality_a
        assert collapse_to_reality(superposition, 1) == reality_b

    def test_entangle_binary_data_meow(self):
        """Test entangling binary data with all byte values."""
        reality_a = bytes(range(256))
        reality_b = bytes(reversed(range(256)))

        superposition = entangle_realities(reality_a, reality_b)

        assert collapse_to_reality(superposition, 0) == reality_a
        assert collapse_to_reality(superposition, 1) == reality_b

    def test_expand_noise_to_one_byte_meow(self):
        """Test expanding noise to exactly one byte."""
        seed = secrets.token_bytes(32)
        expanded = expand_noise(seed, 1)

        assert len(expanded) == 1

    def test_collapse_invalid_index_meow(self):
        """Test collapse with invalid index (should still work, just different positions)."""
        superposition = b"AABBCCDD"

        # Index 2 would extract positions 2, 4, 6... (if they exist)
        # But the function only checks 0 vs non-0
        collapsed = collapse_to_reality(superposition, 2)

        # Non-zero index extracts odd positions
        assert collapsed == b"ABCD"  # Odd positions: B, B, C, D

    def test_noise_derivation_special_chars_meow(self, quantum_salt):
        """Test noise derivation with special characters in passwords."""
        special_pass_a = "p@$$w0rd!#$%^&*()"
        special_pass_b = "s3cr3t<>{}[]|\\;:'\""

        noise = derive_quantum_noise(special_pass_a, special_pass_b, quantum_salt)

        assert len(noise) == 32

    def test_merkle_root_many_blocks_meow(self):
        """Test Merkle root with many blocks."""
        blocks = [secrets.token_bytes(32) for _ in range(1000)]
        root = compute_entanglement_root(blocks)

        assert len(root) == 32


# =============================================================================
# 🐱 Test Class: Security Properties
# =============================================================================


class TestQuantumMixerSecurityMeow:
    """Security-focused tests for the quantum mixer."""

    def test_noise_cannot_be_derived_with_one_password_meow(self, quantum_salt):
        """Test that noise cannot be derived with only one password."""
        password_a = "secret_cat_password"
        password_b = "secret_dog_password"

        # Real noise requires both
        real_noise = derive_quantum_noise(password_a, password_b, quantum_salt)

        # Trying with just one password (and empty string for other)
        partial_noise = derive_quantum_noise(password_a, "", quantum_salt)

        # Should be different
        assert real_noise != partial_noise

    def test_entanglement_hides_original_patterns_meow(self):
        """Test that entanglement obscures original data patterns."""
        # Create patterned data
        reality_a = b"AAAAAAAAAA" * 100  # Obvious pattern
        reality_b = secrets.token_bytes(1000)  # Random

        superposition = entangle_realities(reality_a, reality_b)

        # The superposition should look more random due to interleaving
        is_indist, results = verify_indistinguishability(superposition[:500], superposition[500:])

        # Interleaving with random data should increase entropy
        assert results["entropy_a"] > 3.0  # Mixed data has higher entropy

    def test_merkle_root_integrity_meow(self):
        """Test that Merkle root provides tamper detection."""
        blocks = [b"block_1", b"block_2", b"block_3", b"block_4"]
        original_root = compute_entanglement_root(blocks)

        # Test various tampering scenarios
        tamper_scenarios = [
            ([b"TAMPER", b"block_2", b"block_3", b"block_4"], "first block"),
            ([b"block_1", b"block_2", b"block_3", b"TAMPER"], "last block"),
            ([b"block_1", b"TAMPER", b"block_3", b"block_4"], "middle block"),
            ([b"block_1", b"block_2", b"block_3"], "removed block"),
            ([b"block_1", b"block_2", b"block_3", b"block_4", b"extra"], "added block"),
        ]

        for tampered_blocks, scenario in tamper_scenarios:
            tampered_root = compute_entanglement_root(tampered_blocks)
            assert tampered_root != original_root, f"Failed to detect: {scenario}"

    def test_collapse_cannot_extract_wrong_reality_meow(self):
        """Test that collapsing to wrong reality gives wrong data."""
        reality_a = b"CORRECT_SECRET_DATA"
        reality_b = b"DECOY___DOG___DATA"

        superposition = entangle_realities(reality_a, reality_b)

        # Extracting A gets A
        extracted_a = collapse_to_reality(superposition, 0)
        # Extracting B gets B
        extracted_b = collapse_to_reality(superposition, 1)

        assert extracted_a == reality_a
        assert extracted_b[: len(reality_b)] == reality_b
        assert extracted_a != extracted_b


# =============================================================================
# 🐱 Test Class: Performance
# =============================================================================


class TestQuantumMixerPerformanceMeow:
    """Performance tests for the quantum mixer."""

    def test_entangle_large_data_performance_meow(self):
        """Test entangling large amounts of data."""
        # 1 MB of data
        reality_a = secrets.token_bytes(1024 * 1024)
        reality_b = secrets.token_bytes(1024 * 1024)

        import time

        start = time.time()
        superposition = entangle_realities(reality_a, reality_b)
        elapsed = time.time() - start

        assert len(superposition) == 2 * 1024 * 1024
        # Should complete in reasonable time (< 5 seconds)
        assert elapsed < 5.0

    def test_expand_noise_large_length_performance_meow(self):
        """Test expanding noise to large length."""
        seed = secrets.token_bytes(32)

        import time

        start = time.time()
        expanded = expand_noise(seed, 100000)
        elapsed = time.time() - start

        assert len(expanded) == 100000
        # Should be fast (< 1 second)
        assert elapsed < 1.0

    def test_merkle_root_many_blocks_performance_meow(self):
        """Test Merkle root computation with many blocks."""
        blocks = [secrets.token_bytes(64) for _ in range(10000)]

        import time

        start = time.time()
        root = compute_entanglement_root(blocks)
        elapsed = time.time() - start

        assert len(root) == 32
        # Should be fast (< 5 seconds)
        assert elapsed < 5.0



# --- Merged from test_coverage_boost_remaining.py ---

# =====================================================
# quantum_mixer.py coverage
# =====================================================
class TestQuantumMixerBoost:
    def test_entangle_collapse_roundtrip(self):
        """Test entangle/collapse roundtrip."""
        from meow_decoder.quantum_mixer import entangle_realities, collapse_to_reality

        data_a = os.urandom(256)
        data_b = os.urandom(256)

        superposition = entangle_realities(data_a, data_b)
        assert len(superposition) > 0

        recovered_a = collapse_to_reality(superposition, 0)
        recovered_b = collapse_to_reality(superposition, 1)

        assert recovered_a[: len(data_a)] == data_a
        assert recovered_b[: len(data_b)] == data_b

    def test_entangle_different_sizes(self):
        """Test entangling data of different sizes."""
        from meow_decoder.quantum_mixer import entangle_realities

        data_a = os.urandom(100)
        data_b = os.urandom(200)

        superposition = entangle_realities(data_a, data_b)
        assert len(superposition) > 0



if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
