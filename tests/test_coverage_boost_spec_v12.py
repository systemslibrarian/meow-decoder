"""
Tests to boost coverage for spec_v12/multi_tier.py, key_management.py, steganography.py
"""

import os
import struct
import pytest
from unittest.mock import patch, MagicMock


class TestSteganography:
    """Tests for spec_v12/steganography.py — targeting uncovered lines."""

    def test_find_gif_insertion_point_too_short(self):
        """GIF too short should raise ValueError."""
        from meow_decoder.spec_v12.steganography import find_gif_insertion_point

        with pytest.raises(ValueError, match="too short"):
            find_gif_insertion_point(b"GIF89a")  # only 6 bytes

    def test_find_gif_insertion_point_no_extensions(self):
        """GIF with no extensions returns fallback insertion point."""
        from meow_decoder.spec_v12.steganography import find_gif_insertion_point

        # Minimal GIF: Header(6) + LSD(7) + no GCT + Image descriptor(0x2C)
        # LSD packed byte: no GCT (bit 7 = 0)
        gif = b"GIF89a"  # header
        gif += b"\x01\x00\x01\x00"  # width=1, height=1
        gif += b"\x00"  # packed: no GCT
        gif += b"\x00\x00"  # bg color, aspect ratio
        gif += b"\x2c"  # image descriptor marker
        gif += b"\x00" * 20  # padding
        pos = find_gif_insertion_point(gif)
        assert pos == 13  # After LSD, no GCT

    def test_find_gif_insertion_point_with_gct(self):
        """GIF with Global Color Table."""
        from meow_decoder.spec_v12.steganography import find_gif_insertion_point

        # LSD packed byte: GCT present (bit 7=1), size=0 (2 colors = 6 bytes)
        gif = b"GIF89a"
        gif += b"\x01\x00\x01\x00"
        gif += b"\x80"  # packed: GCT present, size=0 → 2 colors × 3 = 6 bytes
        gif += b"\x00\x00"
        gif += b"\xff" * 6  # GCT (2 colors × 3 bytes)
        gif += b"\x2c"  # Image descriptor
        gif += b"\x00" * 20
        pos = find_gif_insertion_point(gif)
        assert pos == 13 + 6  # After LSD + GCT

    def test_find_gif_insertion_point_with_app_extension(self):
        """GIF with Application Extension (0x21 0xFF)."""
        from meow_decoder.spec_v12.steganography import find_gif_insertion_point

        gif = b"GIF89a"
        gif += b"\x01\x00\x01\x00"
        gif += b"\x00"  # no GCT
        gif += b"\x00\x00"
        # Application extension
        gif += b"\x21\xff"  # Extension introducer + app label
        gif += b"\x0b"  # block size = 11
        gif += b"NETSCAPE2.0"  # app identifier
        gif += b"\x03"  # sub-block size
        gif += b"\x01\x00\x00"  # sub-block data
        gif += b"\x00"  # block terminator
        gif += b"\x2c"  # Image descriptor
        gif += b"\x00" * 20
        pos = find_gif_insertion_point(gif)
        # Should be after the app extension
        assert pos > 13

    def test_find_gif_insertion_point_with_comment_extension(self):
        """GIF with Comment Extension (0x21 0xFE)."""
        from meow_decoder.spec_v12.steganography import find_gif_insertion_point

        gif = b"GIF89a"
        gif += b"\x01\x00\x01\x00"
        gif += b"\x00"
        gif += b"\x00\x00"
        # Comment extension
        gif += b"\x21\xfe"
        gif += b"\x05"  # sub-block size
        gif += b"hello"
        gif += b"\x00"  # block terminator
        gif += b"\x2c"
        gif += b"\x00" * 20
        pos = find_gif_insertion_point(gif)
        assert pos > 13

    def test_find_gif_insertion_point_with_other_extension(self):
        """GIF with other extension type (not 0xFF or 0xFE)."""
        from meow_decoder.spec_v12.steganography import find_gif_insertion_point

        gif = b"GIF89a"
        gif += b"\x01\x00\x01\x00"
        gif += b"\x00"
        gif += b"\x00\x00"
        # Graphic Control Extension (0x21 0xF9)
        gif += b"\x21\xf9"
        gif += b"\x04"  # block size
        gif += b"\x00\x00\x00\x00"
        gif += b"\x00"  # terminator
        gif += b"\x2c"
        gif += b"\x00" * 20
        pos = find_gif_insertion_point(gif)
        assert pos >= 13

    def test_find_gif_insertion_point_trailer(self):
        """GIF ending with trailer marker."""
        from meow_decoder.spec_v12.steganography import find_gif_insertion_point

        gif = b"GIF89a"
        gif += b"\x01\x00\x01\x00"
        gif += b"\x00"
        gif += b"\x00\x00"
        gif += b"\x3b"  # Trailer
        pos = find_gif_insertion_point(gif)
        assert pos == 13

    def test_embed_extract_roundtrip(self):
        """embed_in_gif + extract_from_gif roundtrip."""
        from meow_decoder.spec_v12.steganography import embed_in_gif, extract_from_gif

        # Create minimal GIF
        gif = b"GIF89a"
        gif += b"\x01\x00\x01\x00"
        gif += b"\x00\x00\x00"
        gif += b"\x2c"
        gif += b"\x00" * 20

        payload = b"Hello, Meow Decoder! " * 20
        embedded = embed_in_gif(gif, payload)
        extracted = extract_from_gif(embedded)
        assert extracted == payload

    def test_extract_no_payload(self):
        """extract_from_gif with no payload should raise."""
        from meow_decoder.spec_v12.steganography import extract_from_gif

        gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00" + b"\x3b"
        with pytest.raises(ValueError, match="No embedded payload"):
            extract_from_gif(gif)

    def test_extract_truncated_payload(self):
        """extract_from_gif with truncated sub-block."""
        from meow_decoder.spec_v12.steganography import (
            embed_in_gif,
            extract_from_gif,
            MEOW_PAYLOAD_MARKER,
        )

        # Manually create a truncated payload
        gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00"
        # Embed marker + a sub-block that claims 255 bytes but has less
        gif += MEOW_PAYLOAD_MARKER
        gif += b"\xff"  # claims 255 bytes
        gif += b"short"  # only 5 bytes
        with pytest.raises(ValueError, match="truncated"):
            extract_from_gif(gif)


class TestKeyManagement:
    """Tests for spec_v12/key_management.py — targeting uncovered lines."""

    def test_software_backend_full_lifecycle(self):
        """Test SoftwareBackend: generate, sign, get public key."""
        from meow_decoder.spec_v12.key_management import SoftwareBackend

        backend = SoftwareBackend()
        assert backend.get_backend_name() == "Software"

        sk_bytes, pk_bytes = backend.generate_ed25519_keypair()
        assert len(sk_bytes) == 64  # SK (32) + PK (32)
        assert len(pk_bytes) == 32

        # Sign
        message = b"test message for signing"
        sig = backend.ed25519_sign(message)
        assert len(sig) == 64

        # Get public key
        pk = backend.get_ed25519_public_key()
        assert pk == pk_bytes

    def test_software_backend_sign_without_key(self):
        """Sign without loaded key should raise."""
        from meow_decoder.spec_v12.key_management import SoftwareBackend

        backend = SoftwareBackend()
        with pytest.raises(ValueError, match="No key loaded"):
            backend.ed25519_sign(b"message")

    def test_software_backend_get_pk_without_key(self):
        """Get public key without loaded key should raise."""
        from meow_decoder.spec_v12.key_management import SoftwareBackend

        backend = SoftwareBackend()
        with pytest.raises(ValueError, match="No key loaded"):
            backend.get_ed25519_public_key()

    def test_get_best_backend(self):
        """get_best_backend should return SoftwareBackend on Linux."""
        from meow_decoder.spec_v12.key_management import get_best_backend, SoftwareBackend

        backend = get_best_backend()
        assert isinstance(backend, SoftwareBackend)

    def test_ed25519_pk_to_x25519_pk(self):
        """Test Ed25519 public key to X25519 conversion."""
        from meow_decoder.spec_v12.key_management import SoftwareBackend, ed25519_pk_to_x25519_pk

        backend = SoftwareBackend()
        _, pk = backend.generate_ed25519_keypair()
        x25519_pk = ed25519_pk_to_x25519_pk(pk)
        assert len(x25519_pk) == 32

    def test_ed25519_sk_to_x25519_sk(self):
        """Test Ed25519 secret key to X25519 conversion."""
        from meow_decoder.spec_v12.key_management import SoftwareBackend, ed25519_sk_to_x25519_sk

        backend = SoftwareBackend()
        sk, _ = backend.generate_ed25519_keypair()
        x25519_sk = ed25519_sk_to_x25519_sk(sk)
        assert len(x25519_sk) == 32

    def test_secure_enclave_not_implemented(self):
        """Secure Enclave stub methods raise NotImplementedError."""
        from meow_decoder.spec_v12.key_management import SecureEnclaveBackend

        backend = SecureEnclaveBackend()
        assert backend.get_backend_name() == "Secure Enclave"
        with pytest.raises(NotImplementedError):
            backend.generate_ed25519_keypair()
        with pytest.raises(NotImplementedError):
            backend.ed25519_sign(b"msg")
        with pytest.raises(NotImplementedError):
            backend.get_ed25519_public_key()

    def test_tpm_not_implemented(self):
        """TPM stub methods raise NotImplementedError."""
        from meow_decoder.spec_v12.key_management import TPMBackend

        backend = TPMBackend()
        assert backend.get_backend_name() == "TPM"
        with pytest.raises(NotImplementedError):
            backend.generate_ed25519_keypair()
        with pytest.raises(NotImplementedError):
            backend.ed25519_sign(b"msg")
        with pytest.raises(NotImplementedError):
            backend.get_ed25519_public_key()

    def test_strongbox_not_implemented(self):
        """StrongBox stub methods raise NotImplementedError."""
        from meow_decoder.spec_v12.key_management import StrongBoxBackend

        backend = StrongBoxBackend()
        assert backend.get_backend_name() == "StrongBox"
        with pytest.raises(NotImplementedError):
            backend.generate_ed25519_keypair()
        with pytest.raises(NotImplementedError):
            backend.ed25519_sign(b"msg")
        with pytest.raises(NotImplementedError):
            backend.get_ed25519_public_key()


class TestMultiTier:
    """Tests for spec_v12/multi_tier.py — targeting uncovered lines."""

    def _generate_ed25519_keypair_raw(self):
        """Helper to generate raw Ed25519 keypair bytes."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sk_bytes = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk_bytes = pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return sk_bytes + pk_bytes, pk_bytes

    def test_ed25519_private_from_bytes_short(self):
        """Short key should raise ValueError."""
        from meow_decoder.spec_v12.multi_tier import _ed25519_private_from_bytes

        with pytest.raises(ValueError, match="at least 32"):
            _ed25519_private_from_bytes(b"\x00" * 16)

    def test_ed25519_public_from_bytes_wrong_length(self):
        """Wrong length public key should raise ValueError."""
        from meow_decoder.spec_v12.multi_tier import _ed25519_public_from_bytes

        with pytest.raises(ValueError, match="32 bytes"):
            _ed25519_public_from_bytes(b"\x00" * 16)

    def test_encode_decode_single_tier_roundtrip(self):
        """Full encode → decode roundtrip with 1 tier."""
        from meow_decoder.spec_v12.multi_tier import encode_multi_tier, decode_multi_tier

        sender_sk, sender_pk = self._generate_ed25519_keypair_raw()
        recipient_sk, recipient_pk = self._generate_ed25519_keypair_raw()

        plaintext = b"Hello from tier 0! Secret message."

        # Create minimal GIF carrier
        gif = b"GIF89a"
        gif += b"\x01\x00\x01\x00"
        gif += b"\x00\x00\x00"
        gif += b"\x2c"
        gif += b"\x00" * 20

        encoded = encode_multi_tier([plaintext], recipient_pk, sender_sk, gif)
        assert len(encoded) > len(gif)

        decoded = decode_multi_tier(encoded, sender_pk, recipient_sk, tier_index=0)
        assert decoded[: len(plaintext)] == plaintext

    def test_encode_decode_multi_tier_roundtrip(self):
        """Full roundtrip with 3 tiers."""
        from meow_decoder.spec_v12.multi_tier import encode_multi_tier, decode_multi_tier

        sender_sk, sender_pk = self._generate_ed25519_keypair_raw()
        recipient_sk, recipient_pk = self._generate_ed25519_keypair_raw()

        tier0 = b"Secret tier 0 data"
        tier1 = b"Decoy tier 1 data for testing"
        tier2 = b"Another decoy tier"

        gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00" + b"\x2c" + b"\x00" * 20

        encoded = encode_multi_tier([tier0, tier1, tier2], recipient_pk, sender_sk, gif)

        for i, expected in enumerate([tier0, tier1, tier2]):
            decoded = decode_multi_tier(encoded, sender_pk, recipient_sk, tier_index=i)
            assert decoded[: len(expected)] == expected

    def test_encode_invalid_tier_count(self):
        """Must have 1-3 tiers."""
        from meow_decoder.spec_v12.multi_tier import encode_multi_tier

        sender_sk, _ = self._generate_ed25519_keypair_raw()
        _, recipient_pk = self._generate_ed25519_keypair_raw()
        gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00" + b"\x2c" + b"\x00" * 20

        with pytest.raises(ValueError, match="1-3 tiers"):
            encode_multi_tier([], recipient_pk, sender_sk, gif)

        with pytest.raises(ValueError, match="1-3 tiers"):
            encode_multi_tier([b"a"] * 4, recipient_pk, sender_sk, gif)

    def test_encode_invalid_recipient_pk(self):
        """recipient_ed25519_pk must be 32 bytes."""
        from meow_decoder.spec_v12.multi_tier import encode_multi_tier

        sender_sk, _ = self._generate_ed25519_keypair_raw()
        gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00" + b"\x2c" + b"\x00" * 20
        with pytest.raises(ValueError, match="32 bytes"):
            encode_multi_tier([b"data"], b"\x00" * 16, sender_sk, gif)

    def test_decode_wrong_recipient(self):
        """Decoding with wrong recipient key should fail."""
        from meow_decoder.spec_v12.multi_tier import encode_multi_tier, decode_multi_tier

        sender_sk, sender_pk = self._generate_ed25519_keypair_raw()
        recipient_sk, recipient_pk = self._generate_ed25519_keypair_raw()
        wrong_sk, _ = self._generate_ed25519_keypair_raw()

        gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00" + b"\x2c" + b"\x00" * 20
        encoded = encode_multi_tier([b"secret"], recipient_pk, sender_sk, gif)

        with pytest.raises(ValueError, match="Decryption failed"):
            decode_multi_tier(encoded, sender_pk, wrong_sk, tier_index=0)

    def test_decode_tier_out_of_range(self):
        """Accessing invalid tier index should fail."""
        from meow_decoder.spec_v12.multi_tier import encode_multi_tier, decode_multi_tier

        sender_sk, sender_pk = self._generate_ed25519_keypair_raw()
        recipient_sk, recipient_pk = self._generate_ed25519_keypair_raw()

        gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00" + b"\x2c" + b"\x00" * 20
        encoded = encode_multi_tier([b"secret"], recipient_pk, sender_sk, gif)

        with pytest.raises(ValueError, match="Decryption failed"):
            decode_multi_tier(encoded, sender_pk, recipient_sk, tier_index=5)

    def test_decode_truncated_payload(self):
        """Decoding a truncated payload should fail."""
        from meow_decoder.spec_v12.multi_tier import decode_multi_tier

        sender_sk, sender_pk = self._generate_ed25519_keypair_raw()
        # Minimal GIF with short payload
        from meow_decoder.spec_v12.steganography import embed_in_gif

        gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00" + b"\x2c" + b"\x00" * 20
        embedded = embed_in_gif(gif, b"\x00" * 10)  # too short payload
        with pytest.raises(ValueError, match="Decryption failed"):
            decode_multi_tier(embedded, sender_pk, sender_sk, tier_index=0)
