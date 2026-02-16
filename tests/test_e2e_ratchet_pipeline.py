#!/usr/bin/env python3
"""
End-to-end integration tests for the MEOW Symmetric Ratchet (MSR v1.1)
with fountain codes.

Tests the full pipeline:
    encrypt → fountain encode → ratchet encrypt → [shuffle/drop] →
    ratchet decrypt → fountain decode → decrypt → verify

This bridges the gap between:
    - tests/test_ratchet.py (unit tests, ratchet in isolation)
    - tests/test_e2e_crypto_fountain.py (E2E without ratchet)
"""

import hashlib
import os
import random
import secrets
import struct

import pytest

os.environ.setdefault("MEOW_TEST_MODE", "1")

from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw
from meow_decoder.fountain import (
    FountainEncoder,
    FountainDecoder,
    pack_droplet,
    unpack_droplet,
)
from meow_decoder.ratchet import (
    EncoderRatchet,
    DecoderRatchet,
    FRAME_INDEX_SIZE,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _full_ratchet_pipeline(
    raw: bytes,
    password: str,
    block_size: int = 600,
    redundancy: float = 2.0,
    rekey_interval: int = 0,
    receiver_public_key: bytes = None,
    receiver_private_key: bytes = None,
):
    """Full encrypt → fountain → ratchet pipeline. Returns dict with everything."""
    comp, sha256, salt, nonce, cipher, eph_pk, enc_key = encrypt_file_bytes(
        raw=raw,
        password=password,
    )

    k_blocks = max(1, (len(cipher) + block_size - 1) // block_size)
    num_droplets = max(10, int(k_blocks * redundancy))

    encoder = FountainEncoder(cipher, k_blocks, block_size)
    droplets_obj = encoder.generate_droplets(num_droplets)
    droplet_bytes_list = [pack_droplet(d) for d in droplets_obj]

    # Ratchet-encrypt each droplet
    enc_ratchet = EncoderRatchet(
        root_key=enc_key,
        salt=salt,
        k_blocks=k_blocks,
        block_size=block_size,
        total_frames=num_droplets,
        rekey_interval=rekey_interval,
        receiver_public_key=receiver_public_key,
    )

    ratcheted_droplets = []
    for db in droplet_bytes_list:
        ratcheted_droplets.append(enc_ratchet.encrypt_next(db))
    enc_ratchet.finalize()

    return {
        "ratcheted_droplets": ratcheted_droplets,
        "plain_droplets": droplet_bytes_list,
        "salt": salt,
        "nonce": nonce,
        "sha256": sha256,
        "cipher_len": len(cipher),
        "k_blocks": k_blocks,
        "block_size": block_size,
        "orig_len": len(raw),
        "comp_len": len(comp),
        "ephemeral_public_key": eph_pk,
        "enc_key": enc_key,
        "num_droplets": num_droplets,
        "rekey_interval": rekey_interval,
    }


def _ratchet_decode_pipeline(
    meta: dict,
    received_frames: list,
    password: str,
    rekey_interval: int = 0,
    receiver_private_key: bytes = None,
):
    """Ratchet-decrypt → fountain-decode → crypto-decrypt pipeline."""
    dec_ratchet = DecoderRatchet(
        root_key=meta["enc_key"],
        salt=meta["salt"],
        k_blocks=meta["k_blocks"],
        block_size=meta["block_size"],
        total_frames=meta["num_droplets"],
        rekey_interval=rekey_interval,
        receiver_private_key=receiver_private_key,
    )

    fountain_dec = FountainDecoder(
        meta["k_blocks"],
        meta["block_size"],
        original_length=meta["cipher_len"],
    )

    for frame in received_frames:
        try:
            droplet_bytes = dec_ratchet.decrypt(frame)
        except ValueError:
            continue  # Skip frames that fail ratchet auth

        droplet = unpack_droplet(droplet_bytes, meta["block_size"])
        fountain_dec.add_droplet(droplet)
        if fountain_dec.is_complete():
            break

    dec_ratchet.finalize()

    if not fountain_dec.is_complete():
        raise RuntimeError(
            f"Fountain decode incomplete: {fountain_dec.decoded_count}/{meta['k_blocks']}"
        )

    cipher = fountain_dec.get_data(meta["cipher_len"])

    raw = decrypt_to_raw(
        cipher,
        password,
        meta["salt"],
        meta["nonce"],
        None,  # keyfile
        meta["orig_len"],
        meta["comp_len"],
        meta["sha256"],
        meta["ephemeral_public_key"],
        None,  # receiver_private_key for X25519 (separate from beacon key)
    )
    return raw


# ---------------------------------------------------------------------------
# E2E Tests: Ratchet + Fountain Pipeline
# ---------------------------------------------------------------------------


class TestE2ERatchetFountain:
    """Full ratchet + fountain pipeline tests."""

    @pytest.fixture(
        params=[
            b"Small payload",
            secrets.token_bytes(3000),
            secrets.token_bytes(30_000),
        ],
        ids=["small", "medium", "large"],
    )
    def test_data(self, request):
        return request.param

    def test_roundtrip_in_order(self, test_data):
        """Perfect channel: all ratcheted frames in order."""
        password = "ratchet-e2e-test-1234"
        meta = _full_ratchet_pipeline(test_data, password)
        recovered = _ratchet_decode_pipeline(meta, meta["ratcheted_droplets"], password)
        assert recovered == test_data

    def test_roundtrip_shuffled(self, test_data):
        """Shuffled delivery: ratchet handles out-of-order fountain frames."""
        password = "ratchet-shuffle-5678"
        meta = _full_ratchet_pipeline(test_data, password, redundancy=2.0)

        rng = random.Random(42)
        shuffled = list(meta["ratcheted_droplets"])
        rng.shuffle(shuffled)

        recovered = _ratchet_decode_pipeline(meta, shuffled, password)
        assert recovered == test_data

    def test_roundtrip_with_20pct_loss(self, test_data):
        """Lossy channel: 20% frame loss with ratchet."""
        password = "ratchet-loss-9012"
        meta = _full_ratchet_pipeline(test_data, password, redundancy=3.0)

        rng = random.Random(77)
        surviving = [d for d in meta["ratcheted_droplets"] if rng.random() > 0.20]

        recovered = _ratchet_decode_pipeline(meta, surviving, password)
        assert recovered == test_data

    def test_roundtrip_loss_and_shuffle(self, test_data):
        """Hostile channel: 15% loss + random shuffle with ratchet."""
        password = "ratchet-hostile-3456"
        meta = _full_ratchet_pipeline(test_data, password, redundancy=3.0)

        rng = random.Random(123)
        surviving = [d for d in meta["ratcheted_droplets"] if rng.random() > 0.15]
        rng.shuffle(surviving)

        recovered = _ratchet_decode_pipeline(meta, surviving, password)
        assert recovered == test_data

    def test_tampered_frame_rejected(self):
        """Bit-flipped ratcheted frame is rejected (GCM auth)."""
        password = "ratchet-tamper-7890"
        data = b"tamper test payload 1234567890" * 10
        meta = _full_ratchet_pipeline(data, password, redundancy=2.0)

        # Tamper with first frame
        tampered = list(meta["ratcheted_droplets"])
        frame = bytearray(tampered[0])
        frame[10] ^= 0xFF  # Flip bits in ciphertext
        tampered[0] = bytes(frame)

        # Should still succeed (tampered frame skipped, fountain tolerates loss)
        recovered = _ratchet_decode_pipeline(meta, tampered, password)
        assert recovered == data

    def test_wrong_key_fails_all_frames(self):
        """Wrong encryption key fails all ratchet decryptions."""
        password = "ratchet-wrong-key"
        data = b"secret payload"
        meta = _full_ratchet_pipeline(data, password, redundancy=2.0)

        # Corrupt the key
        meta_copy = dict(meta)
        meta_copy["enc_key"] = secrets.token_bytes(32)

        with pytest.raises(RuntimeError, match="incomplete"):
            _ratchet_decode_pipeline(meta_copy, meta["ratcheted_droplets"], password)

    def test_cross_session_isolation(self):
        """Same password, different sessions → different ratchet chains."""
        password = "cross-session-test"
        data = b"session isolation test"

        meta1 = _full_ratchet_pipeline(data, password)
        meta2 = _full_ratchet_pipeline(data, password)

        # Different salts → different encryption → different ratchet chains
        assert meta1["salt"] != meta2["salt"]

        # Session 1 frames cannot be decrypted by session 2's ratchet
        meta2_with_frames1 = dict(meta2)
        with pytest.raises(RuntimeError, match="incomplete"):
            _ratchet_decode_pipeline(meta2_with_frames1, meta1["ratcheted_droplets"], password)


class TestE2ERatchetBeacons:
    """E2E tests with sender rekey beacons."""

    def test_plaintext_beacon_roundtrip(self):
        """Full pipeline with plaintext rekey beacons."""
        password = "beacon-plaintext-e2e"
        data = secrets.token_bytes(5000)
        rekey = 4

        meta = _full_ratchet_pipeline(data, password, redundancy=2.0, rekey_interval=rekey)
        recovered = _ratchet_decode_pipeline(
            meta, meta["ratcheted_droplets"], password, rekey_interval=rekey
        )
        assert recovered == data

    def test_plaintext_beacon_shuffled(self):
        """Beacon frames survive shuffle (fountain + ratchet + beacons)."""
        password = "beacon-shuffle-e2e"
        data = secrets.token_bytes(8000)
        rekey = 3

        meta = _full_ratchet_pipeline(data, password, redundancy=2.5, rekey_interval=rekey)

        rng = random.Random(55)
        shuffled = list(meta["ratcheted_droplets"])
        rng.shuffle(shuffled)

        recovered = _ratchet_decode_pipeline(meta, shuffled, password, rekey_interval=rekey)
        assert recovered == data

    def test_plaintext_beacon_with_loss(self):
        """Beacon frames survive 20% loss + shuffle."""
        password = "beacon-loss-e2e"
        data = secrets.token_bytes(10_000)
        rekey = 5

        meta = _full_ratchet_pipeline(data, password, redundancy=3.0, rekey_interval=rekey)

        rng = random.Random(88)
        surviving = [d for d in meta["ratcheted_droplets"] if rng.random() > 0.20]
        rng.shuffle(surviving)

        recovered = _ratchet_decode_pipeline(meta, surviving, password, rekey_interval=rekey)
        assert recovered == data

    def test_kem_beacon_roundtrip(self):
        """Full pipeline with X25519 KEM rekey beacons."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            NoEncryption,
            PrivateFormat,
        )

        receiver_private = X25519PrivateKey.generate()
        receiver_public_bytes = receiver_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        receiver_private_bytes = receiver_private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

        password = "kem-beacon-e2e"
        data = secrets.token_bytes(5000)
        rekey = 4

        meta = _full_ratchet_pipeline(
            data,
            password,
            redundancy=2.0,
            rekey_interval=rekey,
            receiver_public_key=receiver_public_bytes,
        )
        recovered = _ratchet_decode_pipeline(
            meta,
            meta["ratcheted_droplets"],
            password,
            rekey_interval=rekey,
            receiver_private_key=receiver_private_bytes,
        )
        assert recovered == data

    def test_kem_beacon_wrong_receiver_key_fails(self):
        """KEM beacon with wrong receiver key → all beacon frames fail."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            NoEncryption,
            PrivateFormat,
        )

        receiver_private = X25519PrivateKey.generate()
        receiver_public_bytes = receiver_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        wrong_private = X25519PrivateKey.generate()
        wrong_private_bytes = wrong_private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

        password = "kem-wrong-key-e2e"
        data = secrets.token_bytes(3000)
        rekey = 1  # Every frame is a beacon — wrong key breaks all frames

        meta = _full_ratchet_pipeline(
            data,
            password,
            redundancy=2.0,
            rekey_interval=rekey,
            receiver_public_key=receiver_public_bytes,
        )

        # With wrong key, ALL frames are beacon frames → ALL fail GCM auth.
        with pytest.raises(RuntimeError, match="incomplete"):
            _ratchet_decode_pipeline(
                meta,
                meta["ratcheted_droplets"],
                password,
                rekey_interval=rekey,
                receiver_private_key=wrong_private_bytes,
            )

    def test_beacon_interval_mismatch_fails(self):
        """Encoder beacon interval != decoder → beacon frames fail."""
        password = "beacon-mismatch-e2e"
        data = secrets.token_bytes(3000)

        meta = _full_ratchet_pipeline(data, password, redundancy=2.0, rekey_interval=3)

        # Decoder thinks beacons are every 5 frames (wrong)
        with pytest.raises((RuntimeError, ValueError)):
            _ratchet_decode_pipeline(
                meta,
                meta["ratcheted_droplets"],
                password,
                rekey_interval=5,
            )


class TestE2ERatchetHashVerification:
    """Verify cryptographic integrity through the full pipeline."""

    def test_sha256_matches_after_full_pipeline(self):
        """SHA-256 of recovered data must match original."""
        password = "hash-verify-e2e"
        data = secrets.token_bytes(20_000)
        original_hash = hashlib.sha256(data).hexdigest()

        meta = _full_ratchet_pipeline(data, password, redundancy=2.0)

        rng = random.Random(42)
        shuffled = list(meta["ratcheted_droplets"])
        rng.shuffle(shuffled)

        recovered = _ratchet_decode_pipeline(meta, shuffled, password)
        recovered_hash = hashlib.sha256(recovered).hexdigest()

        assert recovered_hash == original_hash

    def test_binary_exact_match(self):
        """Recovered bytes must be bit-for-bit identical to original."""
        password = "binary-exact-e2e"
        data = secrets.token_bytes(15_000)

        meta = _full_ratchet_pipeline(data, password, redundancy=2.5)

        rng = random.Random(99)
        surviving = [d for d in meta["ratcheted_droplets"] if rng.random() > 0.10]
        rng.shuffle(surviving)

        recovered = _ratchet_decode_pipeline(meta, surviving, password)
        assert recovered == data
        assert len(recovered) == len(data)
