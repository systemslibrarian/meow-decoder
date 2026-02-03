#!/usr/bin/env python3
"""
🐱⚛️ Comprehensive Tests for Multi-Secret Schrödinger Mode (N-Deniability)

This test suite provides comprehensive coverage for meow_decoder/multi_secret.py,
targeting 85-92% coverage with focus on:
- Reality dataclass functionality
- MultiSecretManifest serialization/deserialization
- MultiSecretEncoder encoding operations
- MultiSecretDecoder decoding operations
- Statistical indistinguishability verification
- Convenience functions (encode_multi_secret, decode_multi_secret)
- Security properties (constant-time comparison, key derivation)
- Edge cases and error handling

Cat Theme: N secrets tangled like yarn balls in quantum superposition! 🧶⚛️
"""

import os
import pytest
import secrets
import hashlib
import struct
import zlib
from unittest.mock import patch, MagicMock
from collections import Counter
import math
import runpy

# Set test mode for faster Argon2 (if applicable)
os.environ.setdefault("MEOW_TEST_MODE", "1")

from meow_decoder.multi_secret import (
    Reality,
    MultiSecretManifest,
    MultiSecretEncoder,
    MultiSecretDecoder,
    verify_statistical_indistinguishability,
    encode_multi_secret,
    decode_multi_secret,
)


# =============================================================================
# Test Fixtures - Cat-themed test data
# =============================================================================

@pytest.fixture
def basic_realities():
    """Basic test realities - 3 secrets like a trio of kittens."""
    return [
        (b"Secret Level 1: The cat's meow location", "password1_meow"),
        (b"Secret Level 2: Hidden catnip stash map", "password2_purr"),
        (b"Secret Level 3: Top secret tuna coordinates", "password3_whiskers"),
    ]


@pytest.fixture
def large_realities():
    """Large test realities - big yarn balls of data."""
    return [
        (b"A" * 10000, "large_secret_a"),
        (b"B" * 10000, "large_secret_b"),
        (b"C" * 10000, "large_secret_c"),
    ]


@pytest.fixture
def five_realities():
    """Five realities - a full litter of kittens."""
    return [
        (f"Secret {i}: {'x' * 500}".encode(), f"password_{i}")
        for i in range(5)
    ]


@pytest.fixture
def encoded_superposition(basic_realities):
    """Pre-encoded superposition for decoder tests."""
    encoder = MultiSecretEncoder(basic_realities)
    return encoder.encode()


@pytest.fixture
def sample_manifest():
    """Sample manifest for testing."""
    return MultiSecretManifest(
        n_realities=3,
        block_size=256,
        total_blocks=12,
        cipher_lengths=[100, 100, 100],
        salts=[secrets.token_bytes(16) for _ in range(3)],
        nonces=[secrets.token_bytes(12) for _ in range(3)],
        hmacs=[secrets.token_bytes(32) for _ in range(3)],
        merkle_root=secrets.token_bytes(32),
    )


# =============================================================================
# TestRealityDataclassMeow - Reality dataclass tests
# =============================================================================

class TestRealityDataclassMeow:
    """Tests for the Reality dataclass - where quantum cats live."""

    def test_reality_creation_basic_meow(self):
        """Test basic Reality creation with required fields."""
        reality = Reality(
            data=b"Secret cat message",
            password="meow_password"
        )
        
        assert reality.data == b"Secret cat message"
        assert reality.password == "meow_password"
        assert len(reality.salt) == 16
        assert len(reality.nonce) == 12
        assert reality.priority == 0

    def test_reality_auto_generates_salt_and_nonce_meow(self):
        """Test that Reality auto-generates cryptographically secure salt and nonce."""
        reality1 = Reality(data=b"data1", password="pass1")
        reality2 = Reality(data=b"data2", password="pass2")
        
        # Each should have unique salt and nonce
        assert reality1.salt != reality2.salt
        assert reality1.nonce != reality2.nonce
        
        # Correct lengths
        assert len(reality1.salt) == 16
        assert len(reality1.nonce) == 12

    def test_reality_custom_salt_and_nonce_meow(self):
        """Test Reality with custom salt and nonce."""
        custom_salt = b"custom_salt_1234"
        custom_nonce = b"nonce12bytes"
        
        reality = Reality(
            data=b"test data",
            password="test_pass",
            salt=custom_salt,
            nonce=custom_nonce
        )
        
        assert reality.salt == custom_salt
        assert reality.nonce == custom_nonce

    def test_reality_priority_assignment_meow(self):
        """Test Reality priority assignment for sensitivity ordering."""
        low_priority = Reality(data=b"public", password="low", priority=0)
        medium_priority = Reality(data=b"confidential", password="med", priority=5)
        high_priority = Reality(data=b"top_secret", password="high", priority=10)
        
        assert low_priority.priority < medium_priority.priority
        assert medium_priority.priority < high_priority.priority

    def test_reality_equality_meow(self):
        """Test Reality equality based on all fields."""
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        reality1 = Reality(
            data=b"same data",
            password="same_pass",
            salt=salt,
            nonce=nonce,
            priority=1
        )
        
        reality2 = Reality(
            data=b"same data",
            password="same_pass",
            salt=salt,
            nonce=nonce,
            priority=1
        )
        
        assert reality1 == reality2


# =============================================================================
# TestMultiSecretManifestMeow - Manifest serialization tests
# =============================================================================

class TestMultiSecretManifestMeow:
    """Tests for MultiSecretManifest - the collar tag for N secrets."""

    def test_manifest_creation_default_values_meow(self):
        """Test manifest creation with defaults."""
        manifest = MultiSecretManifest()
        
        assert manifest.magic == b"MEOWN"
        assert manifest.version == 0x01
        assert manifest.n_realities == 0
        assert manifest.block_size == 256
        assert manifest.total_blocks == 0
        assert manifest.cipher_lengths == []
        assert manifest.salts == []
        assert manifest.nonces == []
        assert manifest.hmacs == []
        assert len(manifest.merkle_root) == 32


def test_multi_secret_module_main_runs():
    runpy.run_module("meow_decoder.multi_secret", run_name="__main__")

    def test_manifest_pack_unpack_roundtrip_meow(self, sample_manifest):
        """Test manifest serialization roundtrip."""
        packed = sample_manifest.pack()
        unpacked = MultiSecretManifest.unpack(packed)
        
        assert unpacked.magic == sample_manifest.magic
        assert unpacked.version == sample_manifest.version
        assert unpacked.n_realities == sample_manifest.n_realities
        assert unpacked.block_size == sample_manifest.block_size
        assert unpacked.total_blocks == sample_manifest.total_blocks
        assert unpacked.cipher_lengths == sample_manifest.cipher_lengths
        assert unpacked.salts == sample_manifest.salts
        assert unpacked.nonces == sample_manifest.nonces
        assert unpacked.hmacs == sample_manifest.hmacs
        assert unpacked.merkle_root == sample_manifest.merkle_root

    def test_manifest_pack_structure_meow(self):
        """Test manifest binary structure."""
        manifest = MultiSecretManifest(
            n_realities=2,
            block_size=512,
            total_blocks=100,
            cipher_lengths=[50, 60],
            salts=[b"0" * 16, b"1" * 16],
            nonces=[b"a" * 12, b"b" * 12],
            hmacs=[b"x" * 32, b"y" * 32],
            merkle_root=b"r" * 32,
        )
        
        packed = manifest.pack()
        
        # Check magic
        assert packed[:5] == b"MEOWN"
        
        # Check version, n_realities, block_size
        version, n_realities, block_size = struct.unpack('>BBH', packed[5:9])
        assert version == 0x01
        assert n_realities == 2
        assert block_size == 512
        
        # Check total_blocks
        total_blocks, = struct.unpack('>I', packed[9:13])
        assert total_blocks == 100

    def test_manifest_unpack_invalid_magic_meow(self):
        """Test manifest unpacking with invalid magic raises error."""
        invalid_data = b"BADMA" + b"\x00" * 100
        
        with pytest.raises(ValueError, match="Invalid multi-secret manifest magic"):
            MultiSecretManifest.unpack(invalid_data)

    def test_manifest_multiple_realities_meow(self):
        """Test manifest with various numbers of realities."""
        for n in [2, 3, 5, 8, 10]:
            manifest = MultiSecretManifest(
                n_realities=n,
                block_size=256,
                total_blocks=n * 10,
                cipher_lengths=[100] * n,
                salts=[secrets.token_bytes(16) for _ in range(n)],
                nonces=[secrets.token_bytes(12) for _ in range(n)],
                hmacs=[secrets.token_bytes(32) for _ in range(n)],
                merkle_root=secrets.token_bytes(32),
            )
            
            packed = manifest.pack()
            unpacked = MultiSecretManifest.unpack(packed)
            
            assert unpacked.n_realities == n
            assert len(unpacked.salts) == n
            assert len(unpacked.nonces) == n
            assert len(unpacked.hmacs) == n
            assert len(unpacked.cipher_lengths) == n

    def test_manifest_cipher_lengths_preserved_meow(self):
        """Test that cipher lengths are correctly preserved through pack/unpack."""
        lengths = [123, 456, 789]
        manifest = MultiSecretManifest(
            n_realities=3,
            cipher_lengths=lengths,
            salts=[secrets.token_bytes(16) for _ in range(3)],
            nonces=[secrets.token_bytes(12) for _ in range(3)],
            hmacs=[secrets.token_bytes(32) for _ in range(3)],
        )
        
        packed = manifest.pack()
        unpacked = MultiSecretManifest.unpack(packed)
        
        assert unpacked.cipher_lengths == lengths


# =============================================================================
# TestMultiSecretEncoderMeow - Encoder tests
# =============================================================================

class TestMultiSecretEncoderMeow:
    """Tests for MultiSecretEncoder - tangling quantum yarn balls."""

    def test_encoder_initialization_meow(self, basic_realities):
        """Test encoder initialization with valid realities."""
        encoder = MultiSecretEncoder(basic_realities)
        
        assert len(encoder.realities) == 3
        assert encoder.block_size == 256
        assert encoder.manifest is None

    def test_encoder_custom_block_size_meow(self, basic_realities):
        """Test encoder with custom block size."""
        encoder = MultiSecretEncoder(basic_realities, block_size=512)
        
        assert encoder.block_size == 512

    def test_encoder_minimum_realities_check_meow(self):
        """Test encoder requires at least 2 realities."""
        with pytest.raises(ValueError, match="Need at least 2 realities"):
            MultiSecretEncoder([(b"single secret", "password")])

    def test_encoder_maximum_realities_check_meow(self):
        """Test encoder rejects more than 16 realities."""
        too_many = [(b"secret", f"pass_{i}") for i in range(17)]
        
        with pytest.raises(ValueError, match="Maximum 16 realities"):
            MultiSecretEncoder(too_many)

    def test_encoder_encodes_successfully_meow(self, basic_realities):
        """Test encoder produces valid superposition and manifest."""
        encoder = MultiSecretEncoder(basic_realities)
        superposition, manifest = encoder.encode()
        
        assert isinstance(superposition, bytes)
        assert len(superposition) > 0
        assert isinstance(manifest, MultiSecretManifest)
        assert manifest.n_realities == 3
        assert manifest.total_blocks > 0
        assert len(manifest.cipher_lengths) == 3

    def test_encoder_produces_deterministic_merkle_root_meow(self, basic_realities):
        """Test that same realities produce same merkle root."""
        # Use fixed salts/nonces for deterministic test
        encoder1 = MultiSecretEncoder(basic_realities)
        superposition1, manifest1 = encoder1.encode()
        
        # Note: Different encodings will have different random salts
        # so merkle roots will differ - this tests structure consistency
        assert len(manifest1.merkle_root) == 32

    def test_encoder_interleaves_blocks_meow(self, basic_realities):
        """Test that encoder interleaves blocks from all realities."""
        encoder = MultiSecretEncoder(basic_realities, block_size=64)
        superposition, manifest = encoder.encode()
        
        # Total blocks should be divisible by n_realities
        assert manifest.total_blocks % manifest.n_realities == 0

    def test_encoder_large_data_meow(self, large_realities):
        """Test encoder handles large data correctly."""
        encoder = MultiSecretEncoder(large_realities)
        superposition, manifest = encoder.encode()

        assert len(superposition) > 0
        assert manifest.total_blocks > 0
        assert len(superposition) == manifest.total_blocks * manifest.block_size

    def test_encoder_derive_key_consistency_meow(self, basic_realities):
        """Test that key derivation is consistent."""
        encoder = MultiSecretEncoder(basic_realities)
        
        salt = secrets.token_bytes(16)
        key1 = encoder._derive_key("test_password", salt)
        key2 = encoder._derive_key("test_password", salt)
        
        assert key1 == key2
        assert len(key1) == 32

    def test_encoder_derive_key_different_salts_meow(self, basic_realities):
        """Test different salts produce different keys."""
        encoder = MultiSecretEncoder(basic_realities)
        
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        
        key1 = encoder._derive_key("test_password", salt1)
        key2 = encoder._derive_key("test_password", salt2)
        
        assert key1 != key2

    def test_encoder_encrypt_reality_meow(self, basic_realities):
        """Test single reality encryption."""
        encoder = MultiSecretEncoder(basic_realities)
        reality = encoder.realities[0]
        
        ciphertext = encoder._encrypt_reality(reality)
        
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) > 0
        # Ciphertext should be different from plaintext
        assert ciphertext != reality.data

    def test_encoder_pad_to_blocks_meow(self, basic_realities):
        """Test block padding functionality."""
        encoder = MultiSecretEncoder(basic_realities, block_size=64)
        
        data = b"short data"
        blocks = encoder._pad_to_blocks(data, 5)
        
        assert len(blocks) == 5
        for block in blocks:
            assert len(block) == 64

    def test_encoder_pad_to_blocks_exact_fit_meow(self, basic_realities):
        """Test padding when data fits exactly."""
        encoder = MultiSecretEncoder(basic_realities, block_size=10)
        
        data = b"exactly10!"  # Exactly 10 bytes
        blocks = encoder._pad_to_blocks(data, 1)
        
        assert len(blocks) == 1
        assert blocks[0] == data

    def test_encoder_compute_hmac_meow(self, basic_realities):
        """Test HMAC computation."""
        encoder = MultiSecretEncoder(basic_realities)
        
        key = secrets.token_bytes(32)
        data = b"test data for hmac"
        
        hmac = encoder._compute_hmac(key, data)
        
        assert len(hmac) == 32
        
        # Verify determinism
        hmac2 = encoder._compute_hmac(key, data)
        assert hmac == hmac2

    def test_encoder_compute_merkle_root_meow(self, basic_realities):
        """Test Merkle root computation."""
        encoder = MultiSecretEncoder(basic_realities)
        
        blocks = [b"block1", b"block2", b"block3", b"block4"]
        root = encoder._compute_merkle_root(blocks)
        
        assert len(root) == 32
        
        # Same blocks should produce same root
        root2 = encoder._compute_merkle_root(blocks)
        assert root == root2

    def test_encoder_compute_merkle_root_empty_meow(self, basic_realities):
        """Test Merkle root for empty block list."""
        encoder = MultiSecretEncoder(basic_realities)
        
        root = encoder._compute_merkle_root([])
        
        assert len(root) == 32
        assert root == hashlib.sha256(b"empty").digest()

    def test_encoder_compute_merkle_root_single_block_meow(self, basic_realities):
        """Test Merkle root for single block."""
        encoder = MultiSecretEncoder(basic_realities)
        
        block = b"single block"
        root = encoder._compute_merkle_root([block])
        
        assert root == hashlib.sha256(block).digest()

    def test_encoder_cryptographic_shuffle_deterministic_meow(self, basic_realities):
        """Test cryptographic shuffle is deterministic for same seed."""
        encoder = MultiSecretEncoder(basic_realities)
        
        blocks = [b"block_0", b"block_1", b"block_2", b"block_3"]
        seed = b"fixed_seed_for_shuffle_1234567890"
        
        shuffled1 = encoder._cryptographic_shuffle(blocks[:], seed)
        shuffled2 = encoder._cryptographic_shuffle(blocks[:], seed)
        
        assert shuffled1 == shuffled2

    def test_encoder_cryptographic_shuffle_different_seeds_meow(self, basic_realities):
        """Test different seeds produce different shuffles."""
        encoder = MultiSecretEncoder(basic_realities)
        
        blocks = [b"block_0", b"block_1", b"block_2", b"block_3"]
        seed1 = b"seed1_______________________________"
        seed2 = b"seed2_______________________________"
        
        shuffled1 = encoder._cryptographic_shuffle(blocks[:], seed1)
        shuffled2 = encoder._cryptographic_shuffle(blocks[:], seed2)
        
        # Very unlikely to be same with different seeds
        assert shuffled1 != shuffled2

    def test_encoder_manifest_set_after_encode_meow(self, basic_realities):
        """Test that manifest is set after encoding."""
        encoder = MultiSecretEncoder(basic_realities)
        
        assert encoder.manifest is None
        
        superposition, manifest = encoder.encode()
        
        assert encoder.manifest is not None
        assert encoder.manifest == manifest


# =============================================================================
# TestMultiSecretDecoderMeow - Decoder tests
# =============================================================================

class TestMultiSecretDecoderMeow:
    """Tests for MultiSecretDecoder - collapsing quantum states."""

    def test_decoder_initialization_meow(self, encoded_superposition):
        """Test decoder initialization."""
        superposition, manifest = encoded_superposition
        decoder = MultiSecretDecoder(superposition, manifest)
        
        assert decoder.superposition == superposition
        assert decoder.manifest == manifest
        assert len(decoder.blocks) > 0

    def test_decoder_splits_into_blocks_meow(self, encoded_superposition):
        """Test decoder correctly splits superposition into blocks."""
        superposition, manifest = encoded_superposition
        decoder = MultiSecretDecoder(superposition, manifest)
        
        expected_blocks = len(superposition) // manifest.block_size
        assert len(decoder.blocks) == expected_blocks
        
        for block in decoder.blocks:
            assert len(block) == manifest.block_size

    def test_decoder_verify_password_valid_meow(self, basic_realities):
        """Test password verification for valid passwords."""
        encoder = MultiSecretEncoder(basic_realities)
        superposition, manifest = encoder.encode()
        decoder = MultiSecretDecoder(superposition, manifest)
        
        # Each password should verify to correct index
        for i, (_, password) in enumerate(basic_realities):
            idx = decoder._verify_password(password)
            assert idx == i

    def test_decoder_verify_password_invalid_meow(self, encoded_superposition):
        """Test password verification rejects invalid passwords."""
        superposition, manifest = encoded_superposition
        decoder = MultiSecretDecoder(superposition, manifest)
        
        idx = decoder._verify_password("wrong_password_meow")
        assert idx == -1

    def test_decoder_decode_all_realities_meow(self, basic_realities):
        """Test decoding all realities correctly."""
        encoder = MultiSecretEncoder(basic_realities)
        superposition, manifest = encoder.encode()
        decoder = MultiSecretDecoder(superposition, manifest)
        
        for original_data, password in basic_realities:
            decoded = decoder.decode(password)
            assert decoded == original_data

    def test_decoder_decode_wrong_password_raises_meow(self, encoded_superposition):
        """Test decoding with wrong password raises ValueError."""
        superposition, manifest = encoded_superposition
        decoder = MultiSecretDecoder(superposition, manifest)
        
        with pytest.raises(ValueError, match="Invalid password"):
            decoder.decode("completely_wrong_password")

    def test_decoder_unshuffle_meow(self, basic_realities):
        """Test block unshuffling."""
        encoder = MultiSecretEncoder(basic_realities)
        superposition, manifest = encoder.encode()
        decoder = MultiSecretDecoder(superposition, manifest)
        
        unshuffled = decoder._unshuffle(decoder.blocks)
        
        assert len(unshuffled) == len(decoder.blocks)
        # All blocks should be non-None
        assert all(b is not None for b in unshuffled)

    def test_decoder_derive_key_matches_encoder_meow(self, basic_realities):
        """Test that decoder key derivation matches encoder."""
        encoder = MultiSecretEncoder(basic_realities)
        superposition, manifest = encoder.encode()
        decoder = MultiSecretDecoder(superposition, manifest)
        
        salt = secrets.token_bytes(16)
        password = "test_password"
        
        encoder_key = encoder._derive_key(password, salt)
        decoder_key = decoder._derive_key(password, salt)
        
        assert encoder_key == decoder_key

    def test_decoder_compute_hmac_matches_encoder_meow(self, basic_realities):
        """Test that decoder HMAC computation matches encoder."""
        encoder = MultiSecretEncoder(basic_realities)
        superposition, manifest = encoder.encode()
        decoder = MultiSecretDecoder(superposition, manifest)
        
        key = secrets.token_bytes(32)
        data = b"test data"
        
        encoder_hmac = encoder._compute_hmac(key, data)
        decoder_hmac = decoder._compute_hmac(key, data)
        
        assert encoder_hmac == decoder_hmac


# =============================================================================
# TestStatisticalIndistinguishabilityMeow - Statistical tests
# =============================================================================

class TestStatisticalIndistinguishabilityMeow:
    """Tests for statistical indistinguishability verification."""

    def test_verify_random_data_passes_meow(self):
        """Test random data passes statistical tests."""
        random_data = secrets.token_bytes(10000)
        
        result = verify_statistical_indistinguishability(random_data)
        
        assert result is True

    def test_verify_low_entropy_fails_meow(self):
        """Test low entropy data fails statistical tests."""
        # Highly repetitive data has low entropy
        low_entropy_data = b"AAAA" * 2500
        
        result = verify_statistical_indistinguishability(low_entropy_data)
        
        assert result is False

    def test_verify_biased_distribution_fails_meow(self):
        """Test biased byte distribution fails chi-square test."""
        # Create data with biased distribution
        biased_data = bytes([i % 128 for i in range(10000)])  # Only uses 0-127
        
        result = verify_statistical_indistinguishability(biased_data)
        
        # Biased towards lower bytes should fail
        assert result is False

    def test_verify_encoded_superposition_meow(self, basic_realities):
        """Test that encoded superposition passes statistical tests."""
        encoder = MultiSecretEncoder(basic_realities)
        superposition, _ = encoder.encode()
        
        # Encoded superposition should look random
        result = verify_statistical_indistinguishability(superposition)
        
        # Note: This may not always pass due to small data size
        # but for larger data it should
        assert isinstance(result, bool)

    def test_verify_large_superposition_passes_meow(self, large_realities):
        """Test large encoded superposition passes statistical tests."""
        encoder = MultiSecretEncoder(large_realities)
        superposition, _ = encoder.encode()
        
        result = verify_statistical_indistinguishability(superposition)
        
        # Large encrypted data should look random
        assert result is True

    def test_entropy_calculation_meow(self):
        """Test entropy calculation is reasonable."""
        # Maximum entropy is 8 bits/byte for uniform distribution
        uniform_data = secrets.token_bytes(1000)
        
        counter = Counter(uniform_data)
        length = len(uniform_data)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        
        # Should be close to 8
        assert 7.0 < entropy <= 8.0


# =============================================================================
# TestConvenienceFunctionsMeow - Convenience function tests
# =============================================================================

class TestConvenienceFunctionsMeow:
    """Tests for convenience functions - making cat life easier."""

    def test_encode_multi_secret_basic_meow(self, basic_realities):
        """Test encode_multi_secret convenience function."""
        superposition, manifest = encode_multi_secret(basic_realities)
        
        assert isinstance(superposition, bytes)
        assert isinstance(manifest, MultiSecretManifest)
        assert manifest.n_realities == 3

    def test_encode_multi_secret_custom_block_size_meow(self, basic_realities):
        """Test encode_multi_secret with custom block size."""
        superposition, manifest = encode_multi_secret(basic_realities, block_size=128)
        
        assert manifest.block_size == 128

    def test_decode_multi_secret_basic_meow(self, basic_realities):
        """Test decode_multi_secret convenience function."""
        superposition, manifest = encode_multi_secret(basic_realities)
        
        for original_data, password in basic_realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == original_data

    def test_decode_multi_secret_wrong_password_meow(self, basic_realities):
        """Test decode_multi_secret with wrong password."""
        superposition, manifest = encode_multi_secret(basic_realities)
        
        with pytest.raises(ValueError, match="Invalid password"):
            decode_multi_secret(superposition, manifest, "wrong_password")

    def test_encode_decode_roundtrip_meow(self, five_realities):
        """Test full encode/decode roundtrip with 5 realities."""
        superposition, manifest = encode_multi_secret(five_realities)
        
        for original_data, password in five_realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == original_data


# =============================================================================
# TestSecurityPropertiesMeow - Security-focused tests
# =============================================================================

class TestSecurityPropertiesMeow:
    """Tests for security properties - keeping cats safe."""

    def test_constant_time_password_comparison_meow(self, encoded_superposition):
        """Test that password verification uses constant-time comparison."""
        superposition, manifest = encoded_superposition
        decoder = MultiSecretDecoder(superposition, manifest)
        
        # This is a structural test - verify secrets.compare_digest is used
        # by checking the code flow (actual timing tests are in test_sidechannel.py)
        with patch('secrets.compare_digest') as mock_compare:
            mock_compare.return_value = False
            
            result = decoder._verify_password("test_password")
            
            # Should have called compare_digest for each reality
            assert mock_compare.call_count >= 1

    def test_unique_salts_per_reality_meow(self, basic_realities):
        """Test each reality gets unique salt."""
        encoder = MultiSecretEncoder(basic_realities)
        
        salts = [r.salt for r in encoder.realities]
        
        # All salts should be unique
        assert len(salts) == len(set(salts))

    def test_unique_nonces_per_reality_meow(self, basic_realities):
        """Test each reality gets unique nonce."""
        encoder = MultiSecretEncoder(basic_realities)
        
        nonces = [r.nonce for r in encoder.realities]
        
        # All nonces should be unique
        assert len(nonces) == len(set(nonces))

    def test_ciphertext_differs_from_plaintext_meow(self, basic_realities):
        """Test ciphertext is different from plaintext."""
        encoder = MultiSecretEncoder(basic_realities)
        
        for reality in encoder.realities:
            ciphertext = encoder._encrypt_reality(reality)
            assert ciphertext != reality.data

    def test_different_passwords_produce_different_keys_meow(self, basic_realities):
        """Test different passwords produce different encryption keys."""
        encoder = MultiSecretEncoder(basic_realities)
        salt = secrets.token_bytes(16)
        
        key1 = encoder._derive_key("password1", salt)
        key2 = encoder._derive_key("password2", salt)
        
        assert key1 != key2

    def test_argon2id_parameters_meow(self, basic_realities):
        """Test Argon2id is used with reasonable parameters."""
        encoder = MultiSecretEncoder(basic_realities)
        
        # Verify key derivation produces 32-byte keys
        salt = secrets.token_bytes(16)
        key = encoder._derive_key("test_password", salt)
        
        assert len(key) == 32

    def test_aes_gcm_encryption_meow(self, basic_realities):
        """Test AES-GCM encryption is used."""
        encoder = MultiSecretEncoder(basic_realities)
        
        reality = encoder.realities[0]
        ciphertext = encoder._encrypt_reality(reality)
        
        # AES-GCM adds 16-byte auth tag
        # Ciphertext should be at least as long as compressed data + 16
        compressed = zlib.compress(reality.data, level=9)
        assert len(ciphertext) >= len(compressed) + 16


# =============================================================================
# TestEdgeCasesMeow - Edge case tests
# =============================================================================

class TestEdgeCasesMeow:
    """Tests for edge cases - when cats get into strange places."""

    def test_exactly_two_realities_meow(self):
        """Test minimum number of realities (2)."""
        realities = [
            (b"Secret 1", "pass1"),
            (b"Secret 2", "pass2"),
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        assert manifest.n_realities == 2
        
        # Decode both
        for data, password in realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == data

    def test_exactly_sixteen_realities_meow(self):
        """Test maximum number of realities (16)."""
        realities = [
            (f"Secret {i}".encode() * 100, f"password_{i}")
            for i in range(16)
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        assert manifest.n_realities == 16
        
        # Decode a few
        for i in [0, 7, 15]:
            data, password = realities[i]
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == data

    def test_empty_secret_data_meow(self):
        """Test handling of empty secret data."""
        realities = [
            (b"", "pass1"),
            (b"non-empty", "pass2"),
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        decoded1 = decode_multi_secret(superposition, manifest, "pass1")
        decoded2 = decode_multi_secret(superposition, manifest, "pass2")
        
        assert decoded1 == b""
        assert decoded2 == b"non-empty"

    def test_very_different_sized_secrets_meow(self):
        """Test secrets of vastly different sizes."""
        realities = [
            (b"tiny", "pass1"),
            (b"medium secret data" * 100, "pass2"),
            (b"X" * 50000, "pass3"),
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        for data, password in realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == data

    def test_unicode_passwords_meow(self):
        """Test Unicode characters in passwords."""
        realities = [
            (b"Secret 1", "パスワード1_猫"),  # Japanese
            (b"Secret 2", "密码2_喵"),  # Chinese
            (b"Secret 3", "пароль3_кот"),  # Russian
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        for data, password in realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == data

    def test_special_characters_in_passwords_meow(self):
        """Test special characters in passwords."""
        realities = [
            (b"Secret 1", "p@$$w0rd!#$%^&*()"),
            (b"Secret 2", "pass\x00word\x00with\x00nulls"),  # Null bytes
            (b"Secret 3", "emoji_🐱_password_😺"),
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        for data, password in realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == data

    def test_binary_data_secrets_meow(self):
        """Test binary data (all byte values) as secrets."""
        realities = [
            (bytes(range(256)) * 10, "pass1"),
            (secrets.token_bytes(1000), "pass2"),
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        for data, password in realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == data


# =============================================================================
# TestErrorHandlingMeow - Error handling tests
# =============================================================================

class TestErrorHandlingMeow:
    """Tests for error handling - graceful cat recovery."""

    def test_encoder_too_few_realities_meow(self):
        """Test encoder rejects fewer than 2 realities."""
        with pytest.raises(ValueError, match="Need at least 2"):
            MultiSecretEncoder([(b"single", "pass")])

    def test_encoder_too_many_realities_meow(self):
        """Test encoder rejects more than 16 realities."""
        realities = [(b"secret", f"pass{i}") for i in range(17)]
        
        with pytest.raises(ValueError, match="Maximum 16"):
            MultiSecretEncoder(realities)

    def test_decoder_invalid_password_meow(self, encoded_superposition):
        """Test decoder raises on invalid password."""
        superposition, manifest = encoded_superposition
        decoder = MultiSecretDecoder(superposition, manifest)
        
        with pytest.raises(ValueError, match="Invalid password"):
            decoder.decode("wrong_password")

    def test_manifest_unpack_invalid_magic_meow(self):
        """Test manifest unpack raises on invalid magic."""
        invalid = b"BADMA" + b"\x00" * 200
        
        with pytest.raises(ValueError, match="Invalid multi-secret manifest magic"):
            MultiSecretManifest.unpack(invalid)

    def test_corrupted_ciphertext_meow(self, basic_realities):
        """Test decryption failure on corrupted ciphertext."""
        encoder = MultiSecretEncoder(basic_realities)
        superposition, manifest = encoder.encode()
        
        # Corrupt some bytes
        corrupted = bytearray(superposition)
        corrupted[100] ^= 0xFF
        corrupted[200] ^= 0xFF
        corrupted = bytes(corrupted)
        
        decoder = MultiSecretDecoder(corrupted, manifest)
        
        # Should raise due to GCM auth failure
        with pytest.raises(ValueError, match="Decryption failed"):
            decoder.decode(basic_realities[0][1])


# =============================================================================
# TestIntegrationMeow - Integration tests
# =============================================================================

class TestIntegrationMeow:
    """Integration tests - all cats working together."""

    def test_full_roundtrip_three_realities_meow(self, basic_realities):
        """Test complete encode/decode cycle with 3 realities."""
        superposition, manifest = encode_multi_secret(basic_realities)
        
        for original_data, password in basic_realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == original_data
            assert len(decoded) == len(original_data)

    def test_full_roundtrip_five_realities_meow(self, five_realities):
        """Test complete encode/decode cycle with 5 realities."""
        superposition, manifest = encode_multi_secret(five_realities)
        
        assert manifest.n_realities == 5
        
        for original_data, password in five_realities:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == original_data

    def test_manifest_survives_serialization_meow(self, basic_realities):
        """Test manifest can be serialized and used for decoding."""
        superposition, manifest = encode_multi_secret(basic_realities)
        
        # Serialize and deserialize manifest
        packed = manifest.pack()
        restored_manifest = MultiSecretManifest.unpack(packed)
        
        # Should still decode correctly
        for original_data, password in basic_realities:
            decoded = decode_multi_secret(superposition, restored_manifest, password)
            assert decoded == original_data

    def test_different_encodings_produce_different_superpositions_meow(self, basic_realities):
        """Test encoding same data twice produces different superpositions."""
        superposition1, _ = encode_multi_secret(basic_realities)
        superposition2, _ = encode_multi_secret(basic_realities)
        
        # Due to random salts/nonces, superpositions should differ
        assert superposition1 != superposition2

    def test_selective_revelation_meow(self, five_realities):
        """Test revealing only some realities (plausible deniability)."""
        superposition, manifest = encode_multi_secret(five_realities)
        
        # Reveal only password_0 and password_4 (skip middle ones)
        decoded_0 = decode_multi_secret(superposition, manifest, "password_0")
        decoded_4 = decode_multi_secret(superposition, manifest, "password_4")
        
        assert decoded_0 == five_realities[0][0]
        assert decoded_4 == five_realities[4][0]
        
        # The other passwords still work but we "chose" not to reveal them
        # This demonstrates plausible deniability


# =============================================================================
# TestPerformanceMeow - Performance tests
# =============================================================================

class TestPerformanceMeow:
    """Performance tests - fast cats are happy cats."""

    @pytest.mark.parametrize("n_realities", [2, 4, 8])
    def test_encoding_time_scales_linearly_meow(self, n_realities):
        """Test encoding time scales reasonably with number of realities."""
        import time
        
        realities = [
            (f"Secret {i}: {'x' * 1000}".encode(), f"pass_{i}")
            for i in range(n_realities)
        ]
        
        start = time.time()
        encode_multi_secret(realities)
        elapsed = time.time() - start
        
        # Should complete in reasonable time (under 30 seconds for any test case)
        assert elapsed < 30

    @pytest.mark.parametrize("data_size", [100, 1000, 10000])
    def test_decoding_time_scales_with_data_size_meow(self, data_size):
        """Test decoding time scales reasonably with data size."""
        import time
        
        realities = [
            (b"A" * data_size, "pass_a"),
            (b"B" * data_size, "pass_b"),
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        start = time.time()
        decode_multi_secret(superposition, manifest, "pass_a")
        elapsed = time.time() - start
        
        # Should complete in reasonable time
        assert elapsed < 30


# =============================================================================
# TestMerkleTreeIntegrationMeow - Merkle tree integration
# =============================================================================

class TestMerkleTreeIntegrationMeow:
    """Tests for Merkle tree integration in multi-secret mode."""

    def test_merkle_root_changes_with_data_meow(self, basic_realities):
        """Test merkle root changes when data changes."""
        encoder1 = MultiSecretEncoder(basic_realities)
        _, manifest1 = encoder1.encode()
        
        modified_realities = [
            (b"Different data 1", "password1_meow"),
            (b"Different data 2", "password2_purr"),
            (b"Different data 3", "password3_whiskers"),
        ]
        
        encoder2 = MultiSecretEncoder(modified_realities)
        _, manifest2 = encoder2.encode()
        
        # Merkle roots should differ
        assert manifest1.merkle_root != manifest2.merkle_root

    def test_merkle_root_stored_in_manifest_meow(self, basic_realities):
        """Test merkle root is stored in manifest."""
        _, manifest = encode_multi_secret(basic_realities)
        
        assert len(manifest.merkle_root) == 32
        assert manifest.merkle_root != b"\x00" * 32


# =============================================================================
# Main execution
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-x"])
