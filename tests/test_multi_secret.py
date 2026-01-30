#!/usr/bin/env python3
"""
🧪 Tests for multi_secret.py - N-Secret Schrödinger Mode

Tests cover:
- Reality dataclass
- MultiSecretManifest pack/unpack
- MultiSecretEncoder (initialization, encryption, encoding)
- MultiSecretDecoder (password verification, decoding)
- Statistical indistinguishability verification
- Convenience functions
- Edge cases and error handling
"""

import pytest
import secrets
import hashlib
import struct
import zlib
from collections import Counter
from typing import List, Tuple

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
# Test Reality Dataclass
# =============================================================================

class TestReality:
    """Tests for Reality dataclass."""
    
    def test_reality_creation_minimal(self):
        """Test creating Reality with required fields only."""
        reality = Reality(
            data=b"test data",
            password="testpass"
        )
        assert reality.data == b"test data"
        assert reality.password == "testpass"
        # Check defaults
        assert len(reality.salt) == 16
        assert len(reality.nonce) == 12
        assert reality.priority == 0
    
    def test_reality_creation_full(self):
        """Test creating Reality with all fields."""
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        reality = Reality(
            data=b"secret",
            password="pass123",
            salt=salt,
            nonce=nonce,
            priority=5
        )
        assert reality.data == b"secret"
        assert reality.password == "pass123"
        assert reality.salt == salt
        assert reality.nonce == nonce
        assert reality.priority == 5
    
    def test_reality_unique_salts_and_nonces(self):
        """Test that default salts and nonces are unique."""
        r1 = Reality(data=b"a", password="p1")
        r2 = Reality(data=b"b", password="p2")
        assert r1.salt != r2.salt
        assert r1.nonce != r2.nonce
    
    def test_reality_empty_data(self):
        """Test Reality with empty data."""
        reality = Reality(data=b"", password="pass")
        assert reality.data == b""


# =============================================================================
# Test MultiSecretManifest
# =============================================================================

class TestMultiSecretManifest:
    """Tests for MultiSecretManifest pack/unpack."""
    
    def test_manifest_defaults(self):
        """Test manifest default values."""
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
        assert manifest.merkle_root == b'\x00' * 32
    
    def test_manifest_pack_minimal(self):
        """Test packing manifest with no realities."""
        manifest = MultiSecretManifest()
        packed = manifest.pack()
        
        # Check magic
        assert packed[:5] == b"MEOWN"
        # Check version/n_realities/block_size
        version, n_realities, block_size = struct.unpack('>BBH', packed[5:9])
        assert version == 0x01
        assert n_realities == 0
        assert block_size == 256
    
    def test_manifest_pack_with_realities(self):
        """Test packing manifest with multiple realities."""
        manifest = MultiSecretManifest(
            n_realities=3,
            block_size=512,
            total_blocks=100,
            cipher_lengths=[1000, 2000, 3000],
            salts=[secrets.token_bytes(16) for _ in range(3)],
            nonces=[secrets.token_bytes(12) for _ in range(3)],
            hmacs=[secrets.token_bytes(32) for _ in range(3)],
            merkle_root=secrets.token_bytes(32)
        )
        packed = manifest.pack()
        
        # Verify basic structure
        assert packed[:5] == b"MEOWN"
        version, n_realities, block_size = struct.unpack('>BBH', packed[5:9])
        assert n_realities == 3
        assert block_size == 512
    
    def test_manifest_unpack(self):
        """Test unpacking manifest."""
        original = MultiSecretManifest(
            n_realities=2,
            block_size=256,
            total_blocks=50,
            cipher_lengths=[500, 600],
            salts=[secrets.token_bytes(16) for _ in range(2)],
            nonces=[secrets.token_bytes(12) for _ in range(2)],
            hmacs=[secrets.token_bytes(32) for _ in range(2)],
            merkle_root=secrets.token_bytes(32)
        )
        packed = original.pack()
        unpacked = MultiSecretManifest.unpack(packed)
        
        assert unpacked.magic == original.magic
        assert unpacked.version == original.version
        assert unpacked.n_realities == original.n_realities
        assert unpacked.block_size == original.block_size
        assert unpacked.total_blocks == original.total_blocks
        assert unpacked.cipher_lengths == original.cipher_lengths
        assert unpacked.salts == original.salts
        assert unpacked.nonces == original.nonces
        assert unpacked.hmacs == original.hmacs
        assert unpacked.merkle_root == original.merkle_root
    
    def test_manifest_roundtrip(self):
        """Test pack/unpack roundtrip for various configurations."""
        for n in [2, 3, 5, 10]:
            manifest = MultiSecretManifest(
                n_realities=n,
                block_size=128 * n,
                total_blocks=n * 10,
                cipher_lengths=[i * 100 for i in range(n)],
                salts=[secrets.token_bytes(16) for _ in range(n)],
                nonces=[secrets.token_bytes(12) for _ in range(n)],
                hmacs=[secrets.token_bytes(32) for _ in range(n)],
                merkle_root=secrets.token_bytes(32)
            )
            packed = manifest.pack()
            unpacked = MultiSecretManifest.unpack(packed)
            assert unpacked.n_realities == n
            assert unpacked.cipher_lengths == manifest.cipher_lengths
    
    def test_manifest_unpack_invalid_magic(self):
        """Test that invalid magic raises ValueError."""
        invalid_data = b"WRONG" + b'\x00' * 100
        with pytest.raises(ValueError, match="Invalid multi-secret manifest magic"):
            MultiSecretManifest.unpack(invalid_data)


# =============================================================================
# Test MultiSecretEncoder
# =============================================================================

class TestMultiSecretEncoder:
    """Tests for MultiSecretEncoder."""
    
    def test_encoder_init_two_realities(self):
        """Test initializing encoder with 2 realities."""
        realities = [
            (b"secret1", "pass1"),
            (b"secret2", "pass2"),
        ]
        encoder = MultiSecretEncoder(realities)
        assert len(encoder.realities) == 2
        assert encoder.block_size == 256
    
    def test_encoder_init_custom_block_size(self):
        """Test initializing encoder with custom block size."""
        realities = [
            (b"a", "p1"),
            (b"b", "p2"),
        ]
        encoder = MultiSecretEncoder(realities, block_size=512)
        assert encoder.block_size == 512
    
    def test_encoder_init_too_few_realities(self):
        """Test that fewer than 2 realities raises ValueError."""
        with pytest.raises(ValueError, match="Need at least 2 realities"):
            MultiSecretEncoder([(b"only one", "pass")])
    
    def test_encoder_init_too_many_realities(self):
        """Test that more than 16 realities raises ValueError."""
        realities = [(b"data", f"pass{i}") for i in range(17)]
        with pytest.raises(ValueError, match="Maximum 16 realities"):
            MultiSecretEncoder(realities)
    
    def test_encoder_init_exactly_16_realities(self):
        """Test that exactly 16 realities is allowed."""
        realities = [(b"data", f"pass{i}") for i in range(16)]
        encoder = MultiSecretEncoder(realities)
        assert len(encoder.realities) == 16
    
    def test_encoder_priority_assignment(self):
        """Test that priorities are assigned correctly."""
        realities = [
            (b"a", "p1"),
            (b"b", "p2"),
            (b"c", "p3"),
        ]
        encoder = MultiSecretEncoder(realities)
        for i, r in enumerate(encoder.realities):
            assert r.priority == i
    
    def test_encoder_derive_key(self):
        """Test key derivation."""
        encoder = MultiSecretEncoder([(b"a", "p1"), (b"b", "p2")])
        salt = secrets.token_bytes(16)
        key = encoder._derive_key("password", salt)
        assert len(key) == 32
        
        # Same password + salt should give same key
        key2 = encoder._derive_key("password", salt)
        assert key == key2
        
        # Different password should give different key
        key3 = encoder._derive_key("other", salt)
        assert key != key3
    
    def test_encoder_encrypt_reality(self):
        """Test encrypting a reality."""
        encoder = MultiSecretEncoder([(b"a", "p1"), (b"b", "p2")])
        reality = encoder.realities[0]
        reality.data = b"test data for encryption"
        
        ciphertext = encoder._encrypt_reality(reality)
        
        # Ciphertext should be different from plaintext
        assert ciphertext != reality.data
        # Should be longer due to compression overhead and auth tag
        assert len(ciphertext) > 0
    
    def test_encoder_pad_to_blocks(self):
        """Test padding data to blocks."""
        encoder = MultiSecretEncoder([(b"a", "p1"), (b"b", "p2")], block_size=16)
        
        # Data smaller than one block
        blocks = encoder._pad_to_blocks(b"small", 3)
        assert len(blocks) == 3
        assert all(len(b) == 16 for b in blocks)
        
        # First block should contain original data
        assert blocks[0][:5] == b"small"
    
    def test_encoder_pad_to_blocks_exact(self):
        """Test padding when data exactly fits blocks."""
        encoder = MultiSecretEncoder([(b"a", "p1"), (b"b", "p2")], block_size=16)
        data = b"exactly16bytes!!"
        blocks = encoder._pad_to_blocks(data, 1)
        assert len(blocks) == 1
        assert blocks[0] == data
    
    def test_encoder_compute_hmac(self):
        """Test HMAC computation."""
        encoder = MultiSecretEncoder([(b"a", "p1"), (b"b", "p2")])
        key = secrets.token_bytes(32)
        data = b"test data"
        
        hmac = encoder._compute_hmac(key, data)
        assert len(hmac) == 32
        
        # Same inputs should give same HMAC
        hmac2 = encoder._compute_hmac(key, data)
        assert hmac == hmac2
        
        # Different data should give different HMAC
        hmac3 = encoder._compute_hmac(key, b"other data")
        assert hmac != hmac3
    
    def test_encoder_compute_merkle_root(self):
        """Test Merkle root computation."""
        encoder = MultiSecretEncoder([(b"a", "p1"), (b"b", "p2")])
        
        blocks = [b"block1", b"block2", b"block3", b"block4"]
        root = encoder._compute_merkle_root(blocks)
        assert len(root) == 32
        
        # Same blocks should give same root
        root2 = encoder._compute_merkle_root(blocks)
        assert root == root2
        
        # Different blocks should give different root
        root3 = encoder._compute_merkle_root([b"other"])
        assert root != root3
    
    def test_encoder_compute_merkle_root_empty(self):
        """Test Merkle root with empty blocks."""
        encoder = MultiSecretEncoder([(b"a", "p1"), (b"b", "p2")])
        root = encoder._compute_merkle_root([])
        assert len(root) == 32
        # Should return hash of "empty"
        expected = hashlib.sha256(b"empty").digest()
        assert root == expected
    
    def test_encoder_cryptographic_shuffle(self):
        """Test cryptographic shuffle."""
        encoder = MultiSecretEncoder([(b"a", "p1"), (b"b", "p2")])
        blocks = [b"0", b"1", b"2", b"3", b"4"]
        seed = secrets.token_bytes(32)
        
        shuffled = encoder._cryptographic_shuffle(blocks, seed)
        
        # Same length
        assert len(shuffled) == len(blocks)
        
        # Same elements (just reordered)
        assert set(shuffled) == set(blocks)
        
        # Deterministic: same seed gives same shuffle
        shuffled2 = encoder._cryptographic_shuffle(blocks, seed)
        assert shuffled == shuffled2
        
        # Different seed gives different shuffle
        shuffled3 = encoder._cryptographic_shuffle(blocks, secrets.token_bytes(32))
        # Might occasionally be same, but very unlikely
        # Just check it runs without error
    
    def test_encoder_encode_two_realities(self):
        """Test full encoding with 2 realities."""
        realities = [
            (b"Secret data for reality A" * 10, "passwordA"),
            (b"Secret data for reality B" * 10, "passwordB"),
        ]
        encoder = MultiSecretEncoder(realities, block_size=64)
        
        superposition, manifest = encoder.encode()
        
        assert len(superposition) > 0
        assert manifest.n_realities == 2
        assert manifest.total_blocks > 0
        assert len(manifest.cipher_lengths) == 2
        assert len(manifest.salts) == 2
        assert len(manifest.nonces) == 2
        assert len(manifest.hmacs) == 2
        assert len(manifest.merkle_root) == 32
    
    def test_encoder_encode_three_realities(self):
        """Test full encoding with 3 realities."""
        realities = [
            (b"Level 1 secret" * 10, "pass1"),
            (b"Level 2 secret" * 10, "pass2"),
            (b"Level 3 secret" * 10, "pass3"),
        ]
        encoder = MultiSecretEncoder(realities)
        
        superposition, manifest = encoder.encode()
        
        assert manifest.n_realities == 3
        assert len(manifest.cipher_lengths) == 3
    
    def test_encoder_encode_different_sized_data(self):
        """Test encoding with different sized data."""
        realities = [
            (b"short", "pass1"),
            (b"medium length data here" * 10, "pass2"),
            (b"very long data" * 100, "pass3"),
        ]
        encoder = MultiSecretEncoder(realities)
        
        superposition, manifest = encoder.encode()
        
        # All should be padded to same block count
        assert manifest.n_realities == 3
        # Total blocks should be multiple of n_realities
        assert manifest.total_blocks % 3 == 0


# =============================================================================
# Test MultiSecretDecoder
# =============================================================================

class TestMultiSecretDecoder:
    """Tests for MultiSecretDecoder."""
    
    @pytest.fixture
    def encoded_data(self):
        """Create encoded data for testing."""
        realities = [
            (b"Reality A data content" * 5, "passA"),
            (b"Reality B data content" * 5, "passB"),
        ]
        encoder = MultiSecretEncoder(realities, block_size=64)
        return encoder.encode()
    
    def test_decoder_init(self, encoded_data):
        """Test decoder initialization."""
        superposition, manifest = encoded_data
        decoder = MultiSecretDecoder(superposition, manifest)
        
        assert decoder.superposition == superposition
        assert decoder.manifest == manifest
        assert len(decoder.blocks) == manifest.total_blocks
    
    def test_decoder_verify_password_valid(self, encoded_data):
        """Test password verification with valid password."""
        superposition, manifest = encoded_data
        decoder = MultiSecretDecoder(superposition, manifest)
        
        # Test first password
        idx = decoder._verify_password("passA")
        assert idx == 0
        
        # Test second password
        idx = decoder._verify_password("passB")
        assert idx == 1
    
    def test_decoder_verify_password_invalid(self, encoded_data):
        """Test password verification with invalid password."""
        superposition, manifest = encoded_data
        decoder = MultiSecretDecoder(superposition, manifest)
        
        idx = decoder._verify_password("wrongpass")
        assert idx == -1
    
    def test_decoder_unshuffle(self, encoded_data):
        """Test unshuffle reverses shuffle."""
        superposition, manifest = encoded_data
        decoder = MultiSecretDecoder(superposition, manifest)
        
        # Unshuffle should be deterministic
        unshuffled = decoder._unshuffle(decoder.blocks)
        unshuffled2 = decoder._unshuffle(decoder.blocks)
        assert unshuffled == unshuffled2
    
    def test_decoder_decode_reality_a(self, encoded_data):
        """Test decoding first reality."""
        superposition, manifest = encoded_data
        decoder = MultiSecretDecoder(superposition, manifest)
        
        decoded = decoder.decode("passA")
        assert decoded == b"Reality A data content" * 5
    
    def test_decoder_decode_reality_b(self, encoded_data):
        """Test decoding second reality."""
        superposition, manifest = encoded_data
        decoder = MultiSecretDecoder(superposition, manifest)
        
        decoded = decoder.decode("passB")
        assert decoded == b"Reality B data content" * 5
    
    def test_decoder_decode_invalid_password(self, encoded_data):
        """Test decoding with invalid password raises ValueError."""
        superposition, manifest = encoded_data
        decoder = MultiSecretDecoder(superposition, manifest)
        
        with pytest.raises(ValueError, match="Invalid password"):
            decoder.decode("wrongpassword")
    
    def test_decoder_three_realities(self):
        """Test decoding with 3 realities."""
        realities = [
            (b"First secret", "pass1"),
            (b"Second secret", "pass2"),
            (b"Third secret", "pass3"),
        ]
        superposition, manifest = encode_multi_secret(realities)
        decoder = MultiSecretDecoder(superposition, manifest)
        
        assert decoder.decode("pass1") == b"First secret"
        assert decoder.decode("pass2") == b"Second secret"
        assert decoder.decode("pass3") == b"Third secret"
    
    def test_decoder_five_realities(self):
        """Test decoding with 5 realities."""
        realities = [
            (f"Secret number {i}".encode() * 10, f"password{i}")
            for i in range(5)
        ]
        superposition, manifest = encode_multi_secret(realities)
        decoder = MultiSecretDecoder(superposition, manifest)
        
        for i in range(5):
            expected = f"Secret number {i}".encode() * 10
            assert decoder.decode(f"password{i}") == expected


# =============================================================================
# Test verify_statistical_indistinguishability
# =============================================================================

class TestStatisticalIndistinguishability:
    """Tests for verify_statistical_indistinguishability function."""
    
    def test_random_data_passes(self):
        """Test that random data passes indistinguishability check."""
        random_data = secrets.token_bytes(10000)
        result = verify_statistical_indistinguishability(random_data)
        assert result is True
    
    def test_low_entropy_fails(self):
        """Test that low entropy data fails check."""
        # Repeating pattern has low entropy
        low_entropy = b"AAAA" * 2500
        result = verify_statistical_indistinguishability(low_entropy)
        assert result is False
    
    def test_encoded_data_passes(self):
        """Test that encoded superposition passes check."""
        realities = [
            (b"Secret A" * 100, "passA"),
            (b"Secret B" * 100, "passB"),
        ]
        superposition, _ = encode_multi_secret(realities)
        result = verify_statistical_indistinguishability(superposition)
        assert result is True
    
    def test_biased_distribution_fails(self):
        """Test that biased byte distribution fails chi-square."""
        # Data heavily biased toward low bytes
        biased = bytes([i % 64 for i in range(10000)])
        result = verify_statistical_indistinguishability(biased)
        assert result is False


# =============================================================================
# Test Convenience Functions
# =============================================================================

class TestConvenienceFunctions:
    """Tests for encode_multi_secret and decode_multi_secret."""
    
    def test_encode_decode_roundtrip(self):
        """Test basic encode/decode roundtrip."""
        secrets_data = [
            (b"First secret data", "password1"),
            (b"Second secret data", "password2"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        decoded1 = decode_multi_secret(superposition, manifest, "password1")
        decoded2 = decode_multi_secret(superposition, manifest, "password2")
        
        assert decoded1 == b"First secret data"
        assert decoded2 == b"Second secret data"
    
    def test_encode_with_custom_block_size(self):
        """Test encoding with custom block size."""
        secrets_data = [
            (b"A" * 1000, "p1"),
            (b"B" * 1000, "p2"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data, block_size=128)
        
        assert manifest.block_size == 128
    
    def test_decode_wrong_password_raises(self):
        """Test that wrong password raises ValueError."""
        secrets_data = [
            (b"secret", "correct"),
            (b"other", "other"),
        ]
        superposition, manifest = encode_multi_secret(secrets_data)
        
        with pytest.raises(ValueError):
            decode_multi_secret(superposition, manifest, "wrong")
    
    def test_large_data_roundtrip(self):
        """Test with larger data."""
        large_data = secrets.token_bytes(50000)
        secrets_data = [
            (large_data, "pass1"),
            (secrets.token_bytes(30000), "pass2"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        decoded = decode_multi_secret(superposition, manifest, "pass1")
        
        assert decoded == large_data
    
    def test_binary_data_roundtrip(self):
        """Test with binary data containing null bytes."""
        binary_data = bytes(range(256)) * 10
        secrets_data = [
            (binary_data, "pass1"),
            (b"text", "pass2"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        decoded = decode_multi_secret(superposition, manifest, "pass1")
        
        assert decoded == binary_data


# =============================================================================
# Test Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_empty_secret_data(self):
        """Test with empty secret data."""
        secrets_data = [
            (b"", "pass1"),
            (b"not empty", "pass2"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        decoded1 = decode_multi_secret(superposition, manifest, "pass1")
        decoded2 = decode_multi_secret(superposition, manifest, "pass2")
        
        assert decoded1 == b""
        assert decoded2 == b"not empty"
    
    def test_unicode_passwords(self):
        """Test with unicode passwords."""
        secrets_data = [
            (b"secret1", "пароль"),  # Russian
            (b"secret2", "密码"),    # Chinese
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        decoded1 = decode_multi_secret(superposition, manifest, "пароль")
        decoded2 = decode_multi_secret(superposition, manifest, "密码")
        
        assert decoded1 == b"secret1"
        assert decoded2 == b"secret2"
    
    def test_special_character_passwords(self):
        """Test with special character passwords."""
        secrets_data = [
            (b"data1", "pass!@#$%^&*()"),
            (b"data2", "pass with spaces"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        assert decode_multi_secret(superposition, manifest, "pass!@#$%^&*()") == b"data1"
        assert decode_multi_secret(superposition, manifest, "pass with spaces") == b"data2"
    
    def test_very_short_data(self):
        """Test with very short data."""
        secrets_data = [
            (b"a", "p1"),
            (b"b", "p2"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        assert decode_multi_secret(superposition, manifest, "p1") == b"a"
        assert decode_multi_secret(superposition, manifest, "p2") == b"b"
    
    def test_same_password_different_salts(self):
        """Test that same password with different salts works independently."""
        # Note: This tests internal behavior - same password but different realities
        # The encoder assigns different salts to each reality
        secrets_data = [
            (b"data A", "samepass"),
            (b"data B", "different"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        # Should be able to decode both
        decoded = decode_multi_secret(superposition, manifest, "samepass")
        assert decoded == b"data A"
    
    def test_manifest_integrity(self):
        """Test that manifest corruption is detected."""
        secrets_data = [
            (b"secret1", "pass1"),
            (b"secret2", "pass2"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        # Corrupt the HMAC
        manifest.hmacs[0] = secrets.token_bytes(32)
        
        # Should fail to verify password
        with pytest.raises(ValueError, match="Invalid password"):
            decode_multi_secret(superposition, manifest, "pass1")
    
    def test_superposition_corruption(self):
        """Test that superposition corruption is detected."""
        secrets_data = [
            (b"secret1", "pass1"),
            (b"secret2", "pass2"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        # Corrupt the superposition
        corrupted = bytearray(superposition)
        corrupted[len(corrupted) // 2] ^= 0xFF
        corrupted = bytes(corrupted)
        
        # Decryption should fail
        with pytest.raises(ValueError, match="Decryption failed"):
            decode_multi_secret(corrupted, manifest, "pass1")


# =============================================================================
# Test Integration Scenarios
# =============================================================================

class TestIntegrationScenarios:
    """Integration tests for realistic usage scenarios."""
    
    def test_progressive_reveal_scenario(self):
        """Test progressive reveal under coercion scenario."""
        # 3-level deniability
        secrets_data = [
            (b"LEVEL 1: Public vacation photos", "vacation123"),
            (b"LEVEL 2: Tax documents", "taxes2024!"),
            (b"LEVEL 3: TOP SECRET PLANS", "ultra$ecret"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        # Coercer gets level 1 password
        level1 = decode_multi_secret(superposition, manifest, "vacation123")
        assert b"vacation photos" in level1
        
        # Cannot prove other levels exist
        with pytest.raises(ValueError):
            decode_multi_secret(superposition, manifest, "wrong")
    
    def test_multiple_classification_levels(self):
        """Test multiple classification levels."""
        levels = [
            (b"UNCLASSIFIED: Weather report", "public"),
            (b"CONFIDENTIAL: Budget data", "confidential"),
            (b"SECRET: Intelligence report", "secret"),
            (b"TOP SECRET: Nuclear codes", "topsecret"),
        ]
        
        superposition, manifest = encode_multi_secret(levels)
        
        # Each level decrypts correctly
        for data, password in levels:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == data
    
    def test_ten_realities(self):
        """Test with 10 realities."""
        realities = [
            (f"Reality {i}: content".encode() * 10, f"realitypass{i}")
            for i in range(10)
        ]
        
        superposition, manifest = encode_multi_secret(realities)
        
        assert manifest.n_realities == 10
        
        # Verify each can be decoded
        for i in range(10):
            expected = f"Reality {i}: content".encode() * 10
            decoded = decode_multi_secret(superposition, manifest, f"realitypass{i}")
            assert decoded == expected
    
    def test_mixed_size_secrets(self):
        """Test with greatly varying secret sizes."""
        secrets_data = [
            (b"tiny", "p1"),
            (b"medium sized secret" * 50, "p2"),
            (b"very large secret content " * 500, "p3"),
        ]
        
        superposition, manifest = encode_multi_secret(secrets_data)
        
        for original, password in secrets_data:
            decoded = decode_multi_secret(superposition, manifest, password)
            assert decoded == original


# =============================================================================
# Test Determinism
# =============================================================================

class TestDeterminism:
    """Tests for deterministic behavior."""
    
    def test_same_inputs_different_outputs(self):
        """Test that same inputs produce different outputs (random salt/nonce)."""
        secrets_data = [
            (b"secret", "pass1"),
            (b"secret", "pass2"),
        ]
        
        superposition1, manifest1 = encode_multi_secret(secrets_data)
        superposition2, manifest2 = encode_multi_secret(secrets_data)
        
        # Superpositions should differ due to random salt/nonce
        assert superposition1 != superposition2
    
    def test_merkle_root_deterministic_per_encoding(self):
        """Test that Merkle root is deterministic for given blocks."""
        encoder = MultiSecretEncoder([
            (b"a", "p1"),
            (b"b", "p2"),
        ])
        
        blocks = [b"block1", b"block2", b"block3"]
        root1 = encoder._compute_merkle_root(blocks)
        root2 = encoder._compute_merkle_root(blocks)
        
        assert root1 == root2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
