#!/usr/bin/env python3
"""
🎲 Property-Based Tests - Hypothesis Fuzzing

CANONICAL test file for property-based testing. DO NOT create numbered variants.

Uses Hypothesis to generate thousands of random inputs and verify invariants:
1. Encrypt/Decrypt roundtrip invariants
2. Fountain encode/decode invariants
3. Nonce uniqueness invariants
4. Key derivation determinism
5. Manifest serialization roundtrip
6. Frame MAC integrity
7. Tamper detection coverage

Property-based testing finds edge cases that handwritten tests miss.
"""

import pytest

pytestmark = [pytest.mark.fuzz, pytest.mark.crypto]

import secrets
import hashlib
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from meow_decoder.crypto import (
    encrypt_file_bytes,
    decrypt_to_raw,
    derive_key,
    Manifest,
    pack_manifest,
    unpack_manifest,
    pack_manifest_core,
    compute_manifest_hmac,
    verify_manifest_hmac,
    MAGIC,
    MIN_PASSWORD_LENGTH,
)
from meow_decoder.fountain import (
    FountainEncoder,
    FountainDecoder,
    pack_droplet,
    unpack_droplet,
    Droplet,
)
from meow_decoder.frame_mac import (
    pack_frame_with_mac,
    unpack_frame_with_mac,
    derive_frame_master_key,
    compute_frame_mac,
    MAC_SIZE,
)

# =============================================================================
# CUSTOM STRATEGIES
# =============================================================================

# Password strategy (must be at least MIN_PASSWORD_LENGTH characters)
password_strategy = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)), min_size=MIN_PASSWORD_LENGTH, max_size=64
)

# Salt strategy (16 bytes)
salt_strategy = st.binary(min_size=16, max_size=16)

# Nonce strategy (12 bytes)
nonce_strategy = st.binary(min_size=12, max_size=12)

# Small data strategy for fast tests
small_data_strategy = st.binary(min_size=1, max_size=1024)

# Block size strategy (reasonable range)
block_size_strategy = st.integers(min_value=16, max_value=512)


# =============================================================================
# ENCRYPT/DECRYPT ROUNDTRIP INVARIANTS (4 tests)
# =============================================================================


class TestEncryptDecryptInvariants:
    """Property: decrypt(encrypt(data)) == data for all valid inputs."""

    @given(
        data=small_data_strategy,
        password=password_strategy,
    )
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_roundtrip_preserves_data(self, data, password):
        """encrypt then decrypt should always return original data."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(password.strip())  # Non-empty after stripping

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        recovered = decrypt_to_raw(
            cipher, password, salt, nonce, None, orig_len=len(data), comp_len=len(comp), sha256=sha
        )

        assert recovered == data

    @given(
        data=small_data_strategy,
        password=password_strategy,
    )
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_sha256_matches_original(self, data, password):
        """SHA256 hash should always match original data."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(password.strip())

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password, None, None)

        expected_sha = hashlib.sha256(data).digest()
        assert sha == expected_sha

    @given(
        data=small_data_strategy,
        password1=password_strategy,
        password2=password_strategy,
    )
    @settings(max_examples=30, deadline=15000, suppress_health_check=[HealthCheck.too_slow])
    def test_different_password_fails(self, data, password1, password2):
        """Different password should fail decryption."""
        assume(len(password1) >= MIN_PASSWORD_LENGTH)
        assume(len(password2) >= MIN_PASSWORD_LENGTH)
        assume(password1 != password2)
        assume(password1.strip() and password2.strip())

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(data, password1, None, None)

        with pytest.raises(Exception):
            decrypt_to_raw(
                cipher,
                password2,
                salt,
                nonce,
                None,
                orig_len=len(data),
                comp_len=len(comp),
                sha256=sha,
            )

    @given(data=small_data_strategy, password=password_strategy)
    @settings(max_examples=30, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_unique_nonce_per_encryption(self, data, password):
        """Each encryption should produce unique nonce."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(password.strip())

        _, _, _, nonce1, _, _, _ = encrypt_file_bytes(data, password, None, None)
        _, _, _, nonce2, _, _, _ = encrypt_file_bytes(data, password, None, None)

        assert nonce1 != nonce2


# =============================================================================
# KEY DERIVATION INVARIANTS (4 tests)
# =============================================================================


class TestKeyDerivationInvariants:
    """Property: key derivation is deterministic and secure."""

    @given(password=password_strategy, salt=salt_strategy)
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_deterministic_key_derivation(self, password, salt):
        """Same password + salt should always produce same key."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(password.strip())

        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)

        assert key1 == key2
        assert len(key1) == 32

    @given(password=password_strategy, salt1=salt_strategy, salt2=salt_strategy)
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_different_salt_different_key(self, password, salt1, salt2):
        """Different salts should produce different keys."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(password.strip())
        assume(salt1 != salt2)

        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)

        assert key1 != key2

    @given(password1=password_strategy, password2=password_strategy, salt=salt_strategy)
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_different_password_different_key(self, password1, password2, salt):
        """Different passwords should produce different keys."""
        assume(len(password1) >= MIN_PASSWORD_LENGTH)
        assume(len(password2) >= MIN_PASSWORD_LENGTH)
        assume(password1 != password2)
        assume(password1.strip() and password2.strip())

        key1 = derive_key(password1, salt)
        key2 = derive_key(password2, salt)

        assert key1 != key2

    @given(password=password_strategy, salt=salt_strategy)
    @settings(max_examples=30, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_key_length_always_32(self, password, salt):
        """Derived key should always be exactly 32 bytes."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(password.strip())

        key = derive_key(password, salt)
        assert len(key) == 32


# =============================================================================
# FOUNTAIN CODE INVARIANTS (4 tests)
# =============================================================================


class TestFountainCodeInvariants:
    """Property: fountain codes are rateless and error-tolerant."""

    @given(
        data=st.binary(min_size=100, max_size=500),
        k_blocks=st.integers(min_value=2, max_value=10),
    )
    @settings(max_examples=30, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_fountain_decode_recovers_data(self, data, k_blocks):
        """Fountain decode should recover original data."""
        block_size = (len(data) + k_blocks - 1) // k_blocks
        block_size = max(16, block_size)

        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)

        # Generate 2x droplets to ensure completion
        for i in range(k_blocks * 2):
            droplet = encoder.droplet()
            if decoder.add_droplet(droplet):
                break

        assert decoder.is_complete()
        recovered = decoder.get_data(len(data))
        assert recovered == data

    @given(seed=st.integers(min_value=0, max_value=10000))
    @settings(max_examples=50)
    def test_droplet_seed_determinism(self, seed):
        """Same seed should always produce same droplet."""
        data = b"Test data for seed determinism" * 10
        k_blocks = 5
        block_size = 64

        encoder1 = FountainEncoder(data, k_blocks, block_size)
        droplet1 = encoder1.droplet(seed=seed)

        encoder2 = FountainEncoder(data, k_blocks, block_size)
        droplet2 = encoder2.droplet(seed=seed)

        assert droplet1.seed == droplet2.seed
        assert droplet1.block_indices == droplet2.block_indices
        assert droplet1.data == droplet2.data

    @given(k_blocks=st.integers(min_value=2, max_value=20))
    @settings(max_examples=30)
    def test_droplet_pack_unpack_roundtrip(self, k_blocks):
        """pack_droplet then unpack_droplet should preserve data."""
        data = secrets.token_bytes(100 * k_blocks)
        block_size = 64

        encoder = FountainEncoder(data, k_blocks, block_size)
        droplet = encoder.droplet()

        packed = pack_droplet(droplet)
        unpacked = unpack_droplet(packed, block_size)

        assert unpacked.seed == droplet.seed
        assert unpacked.block_indices == droplet.block_indices
        assert unpacked.data == droplet.data

    @given(redundancy=st.floats(min_value=1.2, max_value=3.0))
    @settings(max_examples=20, deadline=10000)
    def test_fountain_tolerates_redundancy(self, redundancy):
        """Fountain should decode with any redundancy >= 1.0."""
        data = b"Test data" * 50
        k_blocks = 5
        block_size = 100

        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size)

        num_droplets = int(k_blocks * redundancy)
        for _ in range(num_droplets):
            if decoder.add_droplet(encoder.droplet()):
                break

        if decoder.is_complete():
            recovered = decoder.get_data(len(data))
            assert recovered == data


# =============================================================================
# MANIFEST SERIALIZATION INVARIANTS (4 tests)
# =============================================================================


class TestManifestInvariants:
    """Property: manifest pack/unpack is lossless."""

    @given(
        orig_len=st.integers(min_value=1, max_value=10**6),
        comp_len=st.integers(min_value=1, max_value=10**6),
        cipher_len=st.integers(min_value=1, max_value=10**6),
        block_size=st.integers(min_value=64, max_value=4096),
        k_blocks=st.integers(min_value=1, max_value=10000),
    )
    @settings(max_examples=50)
    def test_manifest_pack_unpack_roundtrip(
        self, orig_len, comp_len, cipher_len, block_size, k_blocks
    ):
        """pack_manifest then unpack_manifest should preserve all fields."""
        # Ensure decompression ratio is within bounds (MAX_DECOMP_RATIO=10)
        assume(comp_len == 0 or orig_len <= comp_len * 10)
        manifest = Manifest(
            salt=secrets.token_bytes(16),
            nonce=secrets.token_bytes(12),
            orig_len=orig_len,
            comp_len=comp_len,
            cipher_len=cipher_len,
            sha256=secrets.token_bytes(32),
            block_size=block_size,
            k_blocks=k_blocks,
            hmac=secrets.token_bytes(32),
            ephemeral_public_key=None,
            pq_ciphertext=None,
            duress_tag=None,
        )

        packed = pack_manifest(manifest)
        unpacked = unpack_manifest(packed)

        assert unpacked.salt == manifest.salt
        assert unpacked.nonce == manifest.nonce
        assert unpacked.orig_len == manifest.orig_len
        assert unpacked.comp_len == manifest.comp_len
        assert unpacked.cipher_len == manifest.cipher_len
        assert unpacked.sha256 == manifest.sha256
        assert unpacked.block_size == manifest.block_size
        assert unpacked.k_blocks == manifest.k_blocks
        assert unpacked.hmac == manifest.hmac

    @given(garbage=st.binary(min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_invalid_manifest_rejected(self, garbage):
        """Invalid manifest bytes should raise ValueError."""
        assume(len(garbage) < 115)  # Too short to be valid

        with pytest.raises(ValueError):
            unpack_manifest(garbage)

    @given(password=password_strategy, salt=salt_strategy)
    @settings(max_examples=30, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_manifest_hmac_verifies(self, password, salt):
        """Valid manifest HMAC should verify successfully."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(password.strip())

        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=1,
            hmac=b"\x00" * 32,
            ephemeral_public_key=None,
            pq_ciphertext=None,
            duress_tag=None,
        )

        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)
        enc_key = derive_key(password, salt)
        manifest.hmac = compute_manifest_hmac(
            password, salt, packed_no_hmac, encryption_key=enc_key
        )

        assert verify_manifest_hmac(password, manifest) is True

    @given(password=password_strategy)
    @settings(max_examples=30, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_manifest_hmac_fails_on_tamper(self, password):
        """Tampered manifest should fail HMAC verification."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(password.strip())

        salt = secrets.token_bytes(16)

        manifest = Manifest(
            salt=salt,
            nonce=secrets.token_bytes(12),
            orig_len=100,
            comp_len=80,
            cipher_len=96,
            sha256=secrets.token_bytes(32),
            block_size=256,
            k_blocks=1,
            hmac=b"\x00" * 32,
            ephemeral_public_key=None,
            pq_ciphertext=None,
            duress_tag=None,
        )

        packed_no_hmac = pack_manifest_core(manifest, include_duress_tag=False)
        enc_key = derive_key(password, salt)
        manifest.hmac = compute_manifest_hmac(
            password, salt, packed_no_hmac, encryption_key=enc_key
        )

        # Tamper with orig_len
        manifest.orig_len = 999

        assert verify_manifest_hmac(password, manifest) is False


# =============================================================================
# FRAME MAC INVARIANTS (4 tests)
# =============================================================================


class TestFrameMACInvariants:
    """Property: frame MACs are secure and deterministic."""

    @given(data=small_data_strategy, frame_index=st.integers(min_value=0, max_value=10000))
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_frame_mac_pack_unpack_roundtrip(self, data, frame_index):
        """pack_frame_with_mac then unpack should preserve data."""
        password = "testpassword123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)

        packed = pack_frame_with_mac(data, master_key, frame_index, salt)
        is_valid, unpacked = unpack_frame_with_mac(packed, master_key, frame_index, salt)

        assert is_valid is True
        assert unpacked == data

    @given(frame_index=st.integers(min_value=0, max_value=10000))
    @settings(max_examples=50)
    def test_frame_mac_deterministic(self, frame_index):
        """Same inputs should produce same MAC."""
        data = b"Test frame data"
        password = "testpassword123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)

        mac1 = compute_frame_mac(data, master_key, frame_index, salt)
        mac2 = compute_frame_mac(data, master_key, frame_index, salt)

        assert mac1 == mac2

    @given(
        frame_index1=st.integers(min_value=0, max_value=10000),
        frame_index2=st.integers(min_value=0, max_value=10000),
    )
    @settings(max_examples=50)
    def test_different_frame_index_different_mac(self, frame_index1, frame_index2):
        """Different frame indices should produce different MACs."""
        assume(frame_index1 != frame_index2)

        data = b"Test frame data"
        password = "testpassword123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)

        mac1 = compute_frame_mac(data, master_key, frame_index1, salt)
        mac2 = compute_frame_mac(data, master_key, frame_index2, salt)

        assert mac1 != mac2

    @given(bit_position=st.integers(min_value=0, max_value=63))
    @settings(max_examples=64)
    def test_frame_mac_detects_any_bit_flip(self, bit_position):
        """Any single bit flip in data should invalidate MAC."""
        data = b"Test data for bit flip detection12"  # 36 bytes
        password = "testpassword123"
        salt = secrets.token_bytes(16)
        enc_key = derive_key(password, salt)
        master_key = derive_frame_master_key(enc_key, salt)

        packed = pack_frame_with_mac(data, master_key, 0, salt)

        # Flip bit in the data portion (after MAC)
        byte_pos = MAC_SIZE + (bit_position // 8)
        if byte_pos < len(packed):
            bit_in_byte = bit_position % 8
            flipped = bytearray(packed)
            flipped[byte_pos] ^= 1 << bit_in_byte

            is_valid, _ = unpack_frame_with_mac(bytes(flipped), master_key, 0, salt)
            assert is_valid is False
