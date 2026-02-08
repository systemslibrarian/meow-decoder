"""Tests for Schrödinger's Yarn Ball encoder/decoder."""

import pytest
import secrets

from meow_decoder.schrodinger_encode import (
    SchrodingerManifest,
    schrodinger_encode_data,
)
from meow_decoder.decoy_generator import generate_convincing_decoy


class TestSchrodingerManifest:
    def test_manifest_creation(self):
        manifest = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=secrets.token_bytes(32),
            reality_b_hmac=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            block_count=10,
            block_size=256,
            superposition_len=5000,
        )
        assert manifest.version == 0x07
        assert manifest.magic == b"MEOW"
        assert manifest.block_count == 10

    def test_manifest_pack_unpack(self):
        manifest = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=secrets.token_bytes(32),
            reality_b_hmac=secrets.token_bytes(32),
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            block_count=10,
            block_size=256,
            superposition_len=5000,
        )
        packed = manifest.pack()
        assert len(packed) == 382
        unpacked = SchrodingerManifest.unpack(packed)
        assert unpacked.block_count == manifest.block_count
        assert unpacked.superposition_len == manifest.superposition_len

    def test_manifest_pack_core_for_auth(self):
        manifest = SchrodingerManifest(
            salt_a=secrets.token_bytes(16),
            salt_b=secrets.token_bytes(16),
            nonce_a=secrets.token_bytes(12),
            nonce_b=secrets.token_bytes(12),
            reality_a_hmac=b"\x00" * 32,
            reality_b_hmac=b"\x00" * 32,
            metadata_a=secrets.token_bytes(104),
            metadata_b=secrets.token_bytes(104),
            block_count=10,
            block_size=256,
            superposition_len=5000,
        )
        core = manifest.pack_core_for_auth()
        assert len(core) == 382 - 64


class TestSchrodingerEncodeData:
    def test_encode_data_basic(self):
        real_data = b"TOP SECRET DATA" * 100
        decoy_data = b"Innocent shopping list" * 100
        mixed, manifest = schrodinger_encode_data(
            real_data,
            decoy_data,
            "RealPassword123",
            "DecoyPassword456",
            block_size=256,
        )
        assert len(mixed) > 0
        assert manifest.block_count > 0
        assert manifest.superposition_len > 0

    def test_encode_data_different_sizes(self):
        real_data = b"Short secret"
        decoy_data = b"Much longer decoy data that takes up more space" * 10
        mixed, manifest = schrodinger_encode_data(
            real_data,
            decoy_data,
            "RealPass12345678",
            "DecoyPass1234567",
        )
        assert len(mixed) > 0

    def test_encode_data_produces_valid_manifest(self):
        real_data = secrets.token_bytes(1000)
        decoy_data = secrets.token_bytes(1000)
        mixed, manifest = schrodinger_encode_data(
            real_data,
            decoy_data,
            "Password1234",
            "Password5678",
        )
        packed = manifest.pack()
        unpacked = SchrodingerManifest.unpack(packed)
        assert unpacked.block_count == manifest.block_count


class TestDecoyGenerator:
    def test_generate_convincing_decoy(self):
        """Test that generate_convincing_decoy returns valid ZIP data."""
        decoy = generate_convincing_decoy(10000)
        # Decoy should be bytes and contain ZIP magic
        assert isinstance(decoy, bytes)
        assert len(decoy) > 0
        # Should be a valid ZIP file (starts with PK magic)
        assert decoy[:2] == b"PK"

    def test_generate_decoy_various_sizes(self):
        """Test decoy generation for various sizes produces valid data."""
        for size in [1000, 5000, 20000]:
            decoy = generate_convincing_decoy(size)
            assert len(decoy) > 0
            assert decoy[:2] == b"PK"  # ZIP magic

    def test_generate_decoy_randomness(self):
        decoy1 = generate_convincing_decoy(1000)
        decoy2 = generate_convincing_decoy(1000)
        assert decoy1 != decoy2
