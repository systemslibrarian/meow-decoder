#!/usr/bin/env python3
"""
End-to-end GIF pipeline integration tests with ratcheting + rekey beacons.

Tests the FULL on-disk pipeline:
    file → encode_file (encrypt → fountain → ratchet → QR → GIF) →
    decode_gif (GIF → QR scan → MAC verify → ratchet decrypt → fountain → decrypt) →
    verify

This goes through actual GIF creation and pyzbar QR scanning, unlike
test_e2e_ratchet_pipeline.py which tests the crypto+fountain layer in memory.
"""

from meow_decoder.decode_gif import decode_gif
from meow_decoder.encode import encode_file
from meow_decoder.config import EncodingConfig, DecodingConfig
import os
import secrets

import pytest

os.environ.setdefault("MEOW_TEST_MODE", "1")


cv2 = pytest.importorskip("cv2", reason="cv2 required for GIF decode pipeline")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _roundtrip(
    tmp_path,
    data: bytes,
    password: str,
    *,
    enable_ratchet: bool = True,
    rekey_beacon_interval: int = 0,
    receiver_public_key: bytes | None = None,
    receiver_private_key: bytes | None = None,
    redundancy: float = 10.0,
    block_size: int = 512,
) -> bytes:
    """Encode data to GIF, decode back, return recovered bytes."""
    input_file = tmp_path / "input.dat"
    input_file.write_bytes(data)

    gif_file = tmp_path / "output.gif"
    output_file = tmp_path / "recovered.dat"

    enc_config = EncodingConfig(
        block_size=block_size,
        redundancy=redundancy,
        enable_ratchet=enable_ratchet,
        rekey_beacon_interval=rekey_beacon_interval,
    )
    dec_config = DecodingConfig(
        rekey_beacon_interval=rekey_beacon_interval,
    )

    encode_file(
        input_file,
        gif_file,
        password,
        config=enc_config,
        receiver_public_key=receiver_public_key,
    )
    decode_gif(
        gif_file,
        output_file,
        password,
        config=dec_config,
        receiver_private_key=receiver_private_key,
    )

    return output_file.read_bytes()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestGIFRatchetRoundtrip:
    """Full GIF encode→decode with per-frame symmetric ratchet."""

    def test_basic_ratchet_roundtrip(self, tmp_path):
        """Ratchet-encrypted GIF roundtrip preserves data exactly."""
        data = secrets.token_bytes(200)
        recovered = _roundtrip(tmp_path, data, "ratchet-gif-basic")
        assert recovered == data

    def test_ratchet_with_text_data(self, tmp_path):
        """Ratchet roundtrip with ASCII text payload."""
        data = b"The quick brown fox jumps over the lazy cat. " * 5
        recovered = _roundtrip(tmp_path, data, "ratchet-gif-text")
        assert recovered == data

    def test_ratchet_with_binary_patterns(self, tmp_path):
        """Ratchet roundtrip with adversarial binary patterns."""
        patterns = [
            b"\x00" * 100,
            b"\xff" * 100,
            bytes(range(256)),
        ]
        for i, data in enumerate(patterns):
            sub = tmp_path / f"pattern_{i}"
            sub.mkdir()
            recovered = _roundtrip(sub, data, f"ratchet-gif-pattern-{i}")
            assert recovered == data, f"Pattern {i} failed roundtrip"


@pytest.mark.slow
class TestGIFRatchetWithRekeyBeacons:
    """Full GIF encode→decode with ratchet + periodic rekey beacons."""

    def test_plaintext_beacon_roundtrip(self, tmp_path):
        """Ratchet + plaintext rekey beacons survive full GIF pipeline."""
        data = secrets.token_bytes(300)
        recovered = _roundtrip(
            tmp_path, data, "beacon-gif-plain", rekey_beacon_interval=3
        )
        assert recovered == data

    def test_kem_beacon_roundtrip(self, tmp_path):
        """Ratchet + X25519 KEM rekey beacons survive full GIF pipeline."""
        import meow_crypto_rs

        priv, pub = meow_crypto_rs.x25519_generate_keypair()

        data = secrets.token_bytes(300)
        recovered = _roundtrip(
            tmp_path,
            data,
            "beacon-gif-kem",
            rekey_beacon_interval=4,
            receiver_public_key=pub,
            receiver_private_key=priv,
        )
        assert recovered == data


@pytest.mark.slow
class TestGIFRatchetWrongPassword:
    """Verify ratcheted GIF rejects wrong password (fail-closed)."""

    def test_wrong_password_fails(self, tmp_path):
        """Decoding a ratcheted GIF with wrong password must fail."""
        data = secrets.token_bytes(100)
        input_file = tmp_path / "input.dat"
        input_file.write_bytes(data)

        gif_file = tmp_path / "output.gif"
        output_file = tmp_path / "recovered.dat"

        enc_config = EncodingConfig(
            block_size=512,
            redundancy=10.0,
            enable_ratchet=True,
        )

        encode_file(input_file, gif_file, "correct-password", config=enc_config)

        with pytest.raises(Exception):
            decode_gif(gif_file, output_file, "wrong-password")
