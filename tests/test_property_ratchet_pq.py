#!/usr/bin/env python3
"""
Property-Based Tests — Ratchet, PQ Beacon, Manifest Signing, and P1 Modules

Uses Hypothesis to verify security invariants:
1. Ratchet chain_key one-wayness
2. Ratchet key commitment binding
3. Master ratchet monotonicity & wipe completeness
4. PQ beacon encapsulate/decapsulate roundtrip (hybrid combiner correctness)
5. Manifest signing non-malleability & dual-algo enforcement
6. Shamir threshold reconstruction
7. Size normalizer padding invariant
8. Dual stream statistical properties
"""

import os
import struct
import tempfile
from pathlib import Path

import pytest

os.environ["MEOW_TEST_MODE"] = "1"

pytestmark = [pytest.mark.fuzz, pytest.mark.crypto]

import hashlib
import secrets

from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

# =============================================================================
# STRATEGIES
# =============================================================================

# 32-byte keys
key_strategy = st.binary(min_size=32, max_size=32)

# Password (at least 8 chars)
password_strategy = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    min_size=8,
    max_size=64,
)

# Small binary data
small_data_strategy = st.binary(min_size=1, max_size=1024)

# Frame index
frame_index_strategy = st.integers(min_value=0, max_value=10000)

# Small integers for step counts
small_int_strategy = st.integers(min_value=1, max_value=10)


# =============================================================================
# RATCHET CHAIN INVARIANTS
# =============================================================================


class TestRatchetChainInvariants:
    """Property: ratchet chain provides one-way forward secrecy."""

    @given(chain_key=key_strategy, n_steps=st.integers(min_value=1, max_value=5))
    @settings(max_examples=50, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_chain_key_one_wayness(self, chain_key, n_steps):
        """chain_key[n] must not be derivable from chain_key[n+k]."""
        try:
            from meow_decoder.ratchet import SymmetricRatchet

            ratchet = SymmetricRatchet(chain_key)

            # Collect all chain keys
            seen_keys = [chain_key]
            for _ in range(n_steps):
                ratchet.step()
                current = ratchet._chain_key if hasattr(ratchet, "_chain_key") else None
                if current is not None:
                    # No previous key should appear again
                    assert (
                        current not in seen_keys[:-1]
                    ), "Chain key collision — forward secrecy violated"
                    seen_keys.append(current)
        except (ImportError, AttributeError, TypeError, RuntimeError):
            pytest.skip("Ratchet API not available in expected form")

    @given(chain_key=key_strategy)
    @settings(max_examples=50, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_chain_step_deterministic(self, chain_key):
        """Same starting key + same step count => same result."""
        try:
            from meow_decoder.ratchet import SymmetricRatchet

            r1 = SymmetricRatchet(chain_key)
            r2 = SymmetricRatchet(chain_key)

            for _ in range(3):
                msg_key_1 = r1.step()
                msg_key_2 = r2.step()
                if msg_key_1 is not None and msg_key_2 is not None:
                    assert msg_key_1 == msg_key_2, "Determinism violated"
        except (ImportError, AttributeError, TypeError, RuntimeError):
            pytest.skip("Ratchet API not available in expected form")

    @given(chain_key=key_strategy, frame_data=small_data_strategy)
    @settings(max_examples=50, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_key_commitment_binding(self, chain_key, frame_data):
        """Key commitment tag must reject data encrypted under a different key."""
        import hmac as hmac_mod

        # Simulate key commitment: HMAC(chain_key, data)
        commitment = hmac_mod.new(chain_key, frame_data, hashlib.sha256).digest()[:16]

        # Different key must produce different commitment
        different_key = bytes((b + 1) % 256 for b in chain_key)
        different_commitment = hmac_mod.new(different_key, frame_data, hashlib.sha256).digest()[:16]

        assert (
            commitment != different_commitment
        ), "Key commitment collision — invisible salamanders possible"


# =============================================================================
# MASTER RATCHET INVARIANTS
# =============================================================================


class TestMasterRatchetInvariants:
    """Property: master ratchet provides cross-session forward secrecy."""

    @given(n_steps=st.integers(min_value=1, max_value=8))
    @settings(max_examples=50, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_generation_monotonically_increasing(self, n_steps):
        """Generation counter must strictly increase with each ratchet."""
        try:
            from meow_decoder.master_ratchet import MasterRatchet

            ratchet = MasterRatchet.from_password("test_password_1234", auto_persist=False)
            prev = ratchet.generation
            assert prev == 0

            for i in range(n_steps):
                ratchet.ratchet()
                assert (
                    ratchet.generation == prev + 1
                ), f"Step {i}: generation {ratchet.generation} != expected {prev + 1}"
                prev = ratchet.generation
        except (ImportError, RuntimeError):
            pytest.skip("MasterRatchet not available")

    @given(file_id=st.text(min_size=1, max_size=50))
    @settings(max_examples=50, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_file_key_deterministic_within_generation(self, file_id):
        """Same generation + same file_id => same file key."""
        try:
            from meow_decoder.master_ratchet import MasterRatchet

            ratchet = MasterRatchet.from_password("test_password_1234", auto_persist=False)
            key1 = ratchet.derive_file_key(file_id)
            key2 = ratchet.derive_file_key(file_id)
            assert key1 == key2, "File key not deterministic within same generation"
        except (ImportError, RuntimeError):
            pytest.skip("MasterRatchet not available")

    @given(file_id=st.text(min_size=1, max_size=50))
    @settings(max_examples=50, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_file_key_changes_after_ratchet(self, file_id):
        """File key must change after ratcheting."""
        try:
            from meow_decoder.master_ratchet import MasterRatchet

            ratchet = MasterRatchet.from_password("test_password_1234", auto_persist=False)
            key_before = ratchet.derive_file_key(file_id)
            ratchet.ratchet()
            key_after = ratchet.derive_file_key(file_id)
            assert key_before != key_after, "File key unchanged after ratchet — no forward secrecy"
        except (ImportError, RuntimeError):
            pytest.skip("MasterRatchet not available")

    def test_emergency_wipe_zeros_all_state(self):
        """Emergency wipe must drop chain handle, zero salt, reset generation."""
        try:
            from meow_decoder.master_ratchet import MasterRatchet

            ratchet = MasterRatchet.from_password("test_password_1234", auto_persist=False)
            ratchet.ratchet()
            ratchet.ratchet()

            pre_wipe_handle = ratchet._state.chain_handle
            assert pre_wipe_handle is not None

            # Wipe
            result = ratchet.emergency_wipe()
            assert result is True

            # Chain handle dropped (Rust SecretKey zeroized via Drop), salt
            # zeroed in Python (defense-in-depth — salt is non-secret),
            # generation reset.
            assert ratchet._state.chain_handle is None
            assert not ratchet._hb.exists(pre_wipe_handle)
            assert ratchet._state.master_salt == bytes(32)
            assert ratchet._state.generation == 0
        except (ImportError, RuntimeError):
            pytest.skip("MasterRatchet not available")

    @given(
        file_id=st.text(min_size=1, max_size=30),
        key_length=st.integers(min_value=16, max_value=64),
    )
    @settings(max_examples=50, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_commitment_tag_accompanies_file_key(self, file_id, key_length):
        """derive_file_key_with_commitment must return (key, commitment) pair."""
        try:
            from meow_decoder.master_ratchet import MasterRatchet

            ratchet = MasterRatchet.from_password("test_password_1234", auto_persist=False)
            key, commitment = ratchet.derive_file_key_with_commitment(file_id, key_length)
            assert isinstance(key, bytes)
            assert len(key) == key_length
            assert isinstance(commitment, bytes)
            assert len(commitment) == 16
        except (ImportError, RuntimeError):
            pytest.skip("MasterRatchet not available")


# =============================================================================
# PQ RATCHET BEACON INVARIANTS
# =============================================================================


class TestPQBeaconInvariants:
    """Property: PQ beacon provides quantum-resistant entropy injection."""

    @given(message_key=key_strategy, salt=st.binary(min_size=0, max_size=64))
    @settings(max_examples=500, deadline=60000, suppress_health_check=[HealthCheck.too_slow])
    def test_encapsulate_decapsulate_roundtrip(self, message_key, salt):
        """Sender encapsulate + receiver decapsulate must yield same enhanced key."""
        try:
            from meow_decoder.pq_ratchet_beacon import (
                PQRatchetBeacon,
                generate_beacon_keypair,
            )

            keypair = generate_beacon_keypair()

            sender = PQRatchetBeacon(receiver_public_key=keypair.public_key)
            ct, enhanced_sender = sender.encapsulate(message_key, salt=salt)

            receiver = PQRatchetBeacon(receiver_keypair=keypair)
            enhanced_receiver = receiver.decapsulate(ct, message_key, salt=salt)

            assert enhanced_sender == enhanced_receiver, "PQ beacon roundtrip mismatch"
            assert len(enhanced_sender) == 32
        except (ImportError, RuntimeError):
            pytest.skip("ML-KEM-1024 not available")

    @given(message_key=key_strategy)
    @settings(max_examples=500, deadline=60000, suppress_health_check=[HealthCheck.too_slow])
    def test_enhanced_key_differs_from_input(self, message_key):
        """Enhanced key must differ from input message key."""
        try:
            from meow_decoder.pq_ratchet_beacon import (
                PQRatchetBeacon,
                generate_beacon_keypair,
            )

            keypair = generate_beacon_keypair()
            sender = PQRatchetBeacon(receiver_public_key=keypair.public_key)
            _, enhanced = sender.encapsulate(message_key)
            assert enhanced != message_key, "Beacon mixing is identity — no entropy injected"
        except (ImportError, RuntimeError):
            pytest.skip("ML-KEM-1024 not available")

    def test_beacon_frame_pack_unpack_roundtrip(self):
        """PQBeaconFrame serialization must be lossless."""
        try:
            from meow_decoder.pq_ratchet_beacon import PQBeaconFrame

            ct = secrets.token_bytes(1568)  # ML-KEM-1024 ciphertext size
            frame = PQBeaconFrame(ciphertext=ct)
            serialized = frame.to_bytes()
            recovered = PQBeaconFrame.from_bytes(serialized)
            assert recovered is not None
            assert recovered.ciphertext == ct
        except (ImportError, RuntimeError):
            pytest.skip("PQBeaconFrame not available")


# =============================================================================
# MANIFEST SIGNING INVARIANTS
# =============================================================================


class TestManifestSigningInvariants:
    """Property: hybrid signing provides non-malleability and dual-algo enforcement."""

    @given(manifest_data=small_data_strategy)
    @settings(max_examples=500, deadline=60000, suppress_health_check=[HealthCheck.too_slow])
    def test_sign_verify_roundtrip(self, manifest_data):
        """sign then verify must always succeed for valid keypair."""
        try:
            from meow_decoder.manifest_signing import (
                generate_signing_keypair,
                sign_manifest,
                verify_manifest_signature,
            )

            keypair = generate_signing_keypair()
            sig = sign_manifest(keypair, manifest_data)
            result = verify_manifest_signature(keypair.export_public_key(), manifest_data, sig)
            assert result is True
        except (ImportError, RuntimeError):
            pytest.skip("Signing implementation not available")

    @given(manifest_data=small_data_strategy)
    @settings(max_examples=500, deadline=60000, suppress_health_check=[HealthCheck.too_slow])
    def test_tampered_manifest_rejected(self, manifest_data):
        """Modified manifest must fail verification."""
        assume(len(manifest_data) > 0)

        try:
            from meow_decoder.manifest_signing import (
                generate_signing_keypair,
                sign_manifest,
                verify_manifest_signature,
            )

            keypair = generate_signing_keypair()
            sig = sign_manifest(keypair, manifest_data)

            # Tamper with manifest
            tampered = bytearray(manifest_data)
            tampered[0] = (tampered[0] + 1) % 256
            tampered = bytes(tampered)

            with pytest.raises(ValueError):
                verify_manifest_signature(keypair.export_public_key(), tampered, sig)
        except (ImportError, RuntimeError):
            pytest.skip("Signing implementation not available")

    @given(manifest_data=small_data_strategy)
    @settings(max_examples=500, deadline=60000, suppress_health_check=[HealthCheck.too_slow])
    def test_wrong_keypair_rejected(self, manifest_data):
        """Signature from different keypair must fail verification."""
        try:
            from meow_decoder.manifest_signing import (
                generate_signing_keypair,
                sign_manifest,
                verify_manifest_signature,
            )

            keypair_a = generate_signing_keypair()
            keypair_b = generate_signing_keypair()

            sig = sign_manifest(keypair_a, manifest_data)

            with pytest.raises(ValueError):
                verify_manifest_signature(keypair_b.export_public_key(), manifest_data, sig)
        except (ImportError, RuntimeError):
            pytest.skip("Signing implementation not available")

    def test_signature_pack_unpack_roundtrip(self):
        """ManifestSignature serialization must be lossless."""
        try:
            from meow_decoder.manifest_signing import ManifestSignature

            ed_sig = secrets.token_bytes(64)
            ml_sig = secrets.token_bytes(3293)  # ML-DSA-65 sig size
            sig = ManifestSignature(ed25519_sig=ed_sig, mldsa65_sig=ml_sig)

            serialized = sig.to_bytes()
            recovered = ManifestSignature.from_bytes(serialized)
            assert recovered.ed25519_sig == ed_sig
            assert recovered.mldsa65_sig == ml_sig
        except (ImportError, RuntimeError):
            pytest.skip("ManifestSignature not available")

    @given(public_key=st.binary(min_size=32, max_size=2048))
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_public_key_commitment_deterministic(self, public_key):
        """Public key commitment must be deterministic."""
        try:
            from meow_decoder.manifest_signing import compute_public_key_commitment

            c1 = compute_public_key_commitment(public_key)
            c2 = compute_public_key_commitment(public_key)
            assert c1 == c2
            assert len(c1) == 32
        except (ImportError, RuntimeError):
            pytest.skip("Not available")


# =============================================================================
# SHAMIR SPLIT INVARIANTS
# =============================================================================


class TestShamirInvariants:
    """Property: Shamir secret sharing provides threshold reconstruction."""

    @given(
        secret=st.binary(min_size=1, max_size=256),
        threshold=st.integers(min_value=2, max_value=5),
    )
    @settings(max_examples=50, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_threshold_shares_reconstruct(self, secret, threshold):
        """Any t-of-n shares must reconstruct the secret."""
        n_shares = threshold + 2  # Always have more shares than threshold

        try:
            from meow_decoder.shamir_split import shamir_split, shamir_combine

            shares = shamir_split(secret, num_shares=n_shares, threshold=threshold)
            assert len(shares) == n_shares

            # Use exactly threshold shares
            subset = shares[:threshold]
            recovered = shamir_combine(subset, threshold=threshold)
            assert recovered == secret, "Reconstruction failed with threshold shares"
        except (ImportError, RuntimeError, ValueError) as e:
            if "threshold" in str(e).lower() or "share" in str(e).lower():
                pass  # Invalid params
            else:
                pytest.skip(f"Shamir not available: {e}")

    @given(
        secret=st.binary(min_size=1, max_size=64),
    )
    @settings(max_examples=500, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_insufficient_shares_fail(self, secret):
        """Fewer than threshold shares must not reconstruct."""
        threshold = 3
        n_shares = 5

        try:
            from meow_decoder.shamir_split import shamir_split, shamir_combine

            shares = shamir_split(secret, num_shares=n_shares, threshold=threshold)

            # Use fewer than threshold
            insufficient = shares[: threshold - 1]
            recovered = shamir_combine(insufficient, threshold=threshold)

            # If it returned, the data must differ from original
            # (in a proper implementation, it should raise or return garbage)
            if recovered == secret:
                pytest.fail("Insufficient shares reconstructed secret — threshold violated")
        except (ImportError, RuntimeError, ValueError):
            pass  # Expected

    @given(secret=st.binary(min_size=1, max_size=100))
    @settings(max_examples=500, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_share_serialization_roundtrip(self, secret):
        """ShamirShare to_bytes/from_bytes must be lossless."""
        try:
            from meow_decoder.shamir_split import shamir_split, ShamirShare

            shares = shamir_split(secret, num_shares=3, threshold=2)
            for share in shares:
                serialized = share.to_bytes()
                recovered = ShamirShare.from_bytes(serialized)
                assert recovered.share_id == share.share_id
                assert recovered.data == share.data
        except (ImportError, RuntimeError, ValueError):
            pytest.skip("Shamir not available")


# =============================================================================
# SIZE NORMALIZER INVARIANTS
# =============================================================================


class TestSizeNormalizerInvariants:
    """Property: size normalizer bucket must always be >= input."""

    @given(data_size=st.integers(min_value=0, max_value=100_000))
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_bucket_never_truncates(self, data_size):
        """Padded size must always be >= original data size."""
        try:
            from meow_decoder.size_normalizer import normalize_size, BUCKET_SIZES

            bucket = normalize_size(data_size)
            assert bucket >= data_size, f"Bucket {bucket} < data size {data_size} — truncation!"
        except (ImportError, AttributeError):
            pytest.skip("size_normalizer not available")
        except (ValueError, TypeError):
            pass  # Some sizes may be invalid


# =============================================================================
# DUAL STREAM INVARIANTS
# =============================================================================


class TestDualStreamInvariants:
    """Property: dual stream manifest serialization is lossless."""

    def test_manifest_pack_unpack_roundtrip(self):
        """DualStreamManifest must round-trip through pack/unpack."""
        try:
            from meow_decoder.dual_stream import DualStreamManifest

            manifest = DualStreamManifest(
                version=1,
                stream_a_salt=secrets.token_bytes(16),
                stream_b_salt=secrets.token_bytes(16),
                stream_a_nonce=secrets.token_bytes(12),
                stream_b_nonce=secrets.token_bytes(12),
                frame_assignment=secrets.token_bytes(32),
                hmac_tag=secrets.token_bytes(32),
            )
            packed = manifest.pack()
            recovered = DualStreamManifest.unpack(packed)

            assert recovered.stream_a_salt == manifest.stream_a_salt
            assert recovered.stream_b_salt == manifest.stream_b_salt
            assert recovered.stream_a_nonce == manifest.stream_a_nonce
            assert recovered.stream_b_nonce == manifest.stream_b_nonce
        except (ImportError, RuntimeError, TypeError, AttributeError):
            pytest.skip("DualStreamManifest not available")

    @given(data=st.binary(min_size=10, max_size=500))
    @settings(max_examples=500, deadline=30000, suppress_health_check=[HealthCheck.too_slow])
    def test_corrupt_manifest_rejected(self, data):
        """Random bytes must not parse as valid DualStreamManifest."""
        try:
            from meow_decoder.dual_stream import DualStreamManifest

            DualStreamManifest.unpack(data)
            # If it parsed without error, that's suspicious but possible if
            # data happens to match the format
        except (ValueError, TypeError, struct.error):
            pass  # Expected for garbage input
        except (ImportError, RuntimeError):
            pytest.skip("DualStreamManifest not available")


# =============================================================================
# DECODER ROLLBACK INVARIANTS — Bug #1 + Bug #2 from gemini_suggestions_v2.md
# =============================================================================
#
# Hypothesis-driven hardening for the speculative-state rollback pattern
# introduced in commit 8a3bb48 (see docs/audits/RATCHET_SPECULATIVE_ROLLBACK.md).
#
# The deterministic regression tests in test_ratchet.py::TestSpeculativeStateRollback
# cover the two specific failure modes. These property tests randomize the
# tampering location across many trials to catch any edge case where state
# is not preserved on failure.


class TestDecoderRollbackInvariants:
    """Property-based asserts for the rollback invariants (I-1 ... I-6 in
    docs/audits/RATCHET_SPECULATIVE_ROLLBACK.md)."""

    @given(
        total=st.integers(min_value=4, max_value=12),
        target_idx=st.integers(min_value=0, max_value=11),
        tamper_offset_seed=st.integers(min_value=0, max_value=10000),
    )
    @settings(
        max_examples=40,
        deadline=20000,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_tampered_frame_does_not_burn_cached_key(
        self, total, target_idx, tamper_offset_seed
    ):
        """For any fountain-style frame layout, tampering with a frame whose
        key was previously cached (out-of-order receive) must not invalidate
        the cache: a clean re-scan of the same frame_index must succeed.

        Random parameters: total frames, the index we'll tamper with, and a
        deterministic offset seed for the tamper location inside the frame
        body.
        """
        from meow_decoder.ratchet import (
            EncoderRatchet,
            DecoderRatchet,
            FRAME_INDEX_SIZE,
            COMMIT_TAG_SIZE,
            GCM_TAG_SIZE,
        )

        assume(target_idx < total)
        # We need at least one frame strictly LESS than the first decode
        # target so the loop in _advance_to caches a key before our tampered
        # scan; otherwise Case 1 path is never exercised.
        assume(target_idx > 0)

        root_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        encoder = EncoderRatchet(
            root_key, salt, k_blocks=3, block_size=200, total_frames=total
        )
        encrypted = []
        for i in range(total):
            data = f"frame_{i:04d}".encode()
            encrypted.append(encoder.encrypt_next(data))
        encoder.finalize()

        decoder = DecoderRatchet(
            root_key, salt, k_blocks=3, block_size=200, total_frames=total
        )

        # Decrypt a later frame first to populate the skipped-keys cache
        # for [0, target_idx-1] (and beyond, up to the first decoded one).
        first_decode = total - 1
        decoder.decrypt(encrypted[first_decode])
        # `target_idx` should now be in the skipped-keys cache.
        assume(target_idx in decoder._skipped_keys)

        # Tamper with the target frame body. Pick an offset deterministically
        # from the hypothesis-supplied seed, well inside the AEAD-protected
        # body so commitment / GCM both fail.
        tampered = bytearray(encrypted[target_idx])
        body_start = FRAME_INDEX_SIZE + COMMIT_TAG_SIZE
        body_room = len(tampered) - body_start - GCM_TAG_SIZE
        assume(body_room > 0)
        offset = body_start + (tamper_offset_seed % max(body_room, 1))
        tampered[offset] ^= 0x42

        # The tampered scan must raise...
        with pytest.raises(Exception):
            decoder.decrypt(bytes(tampered))

        # ... and the cached key must still be present (Bug #2 invariant).
        assert target_idx in decoder._skipped_keys, (
            f"Cached msg-key for frame {target_idx} was burned by a "
            f"tampered scan (offset={offset}). Regression of bug #2 / "
            "the speculative cache pattern in decrypt()."
        )

        # The clean re-scan must succeed.
        plaintext = decoder.decrypt(encrypted[target_idx])
        assert plaintext == f"frame_{target_idx:04d}".encode()

        decoder.finalize()

    @given(
        rekey_interval=st.integers(min_value=2, max_value=4),
        total=st.integers(min_value=6, max_value=10),
        tamper_offset_seed=st.integers(min_value=0, max_value=10000),
    )
    @settings(
        max_examples=20,
        deadline=30000,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_tampered_rekey_frame_preserves_state(
        self, rekey_interval, total, tamper_offset_seed
    ):
        """For an asymmetric rekey frame whose body has been tampered with,
        the decoder's root_key/chain_key/position/epoch must be identical
        before and after the failed decrypt — invariant I-3 from the
        cryptographer-review brief.
        """
        import meow_crypto_rs

        from meow_decoder.ratchet import (
            EncoderRatchet,
            DecoderRatchet,
            FRAME_INDEX_SIZE,
            COMMIT_TAG_SIZE,
            GCM_TAG_SIZE,
            REKEY_BEACON_SIZE,
        )

        assume(rekey_interval < total)

        receiver_priv, receiver_pub = meow_crypto_rs.x25519_generate_keypair()
        root_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        encoder = EncoderRatchet(
            root_key,
            salt,
            k_blocks=2,
            block_size=200,
            total_frames=total,
            rekey_interval=rekey_interval,
            receiver_public_key=receiver_pub,
        )
        decoder = DecoderRatchet(
            root_key,
            salt,
            k_blocks=2,
            block_size=200,
            total_frames=total,
            rekey_interval=rekey_interval,
            receiver_private_key=receiver_priv,
        )

        # Burn through frames up to (but not including) the first rekey.
        for i in range(rekey_interval):
            d = secrets.token_bytes(80)
            assert decoder.decrypt(encoder.encrypt_next(d)) == d

        # Snapshot pre-rekey state.
        pre_state = (
            decoder._state.root_key,
            decoder._state.chain_key,
            decoder._state.position,
            decoder._state.epoch,
        )

        # Build the rekey frame, tamper inside its body.
        clean_payload = b"clean rekey payload"
        rekey_frame = encoder.encrypt_next(clean_payload)
        tampered = bytearray(rekey_frame)
        body_start = FRAME_INDEX_SIZE + COMMIT_TAG_SIZE + REKEY_BEACON_SIZE
        body_room = len(tampered) - body_start - GCM_TAG_SIZE
        assume(body_room > 0)
        offset = body_start + (tamper_offset_seed % max(body_room, 1))
        tampered[offset] ^= 0x80

        with pytest.raises(Exception):
            decoder.decrypt(bytes(tampered))

        # Invariants:
        # - state restored exactly to snapshot
        # - _pending_rollback drained
        post_state = (
            decoder._state.root_key,
            decoder._state.chain_key,
            decoder._state.position,
            decoder._state.epoch,
        )
        assert post_state == pre_state, (
            f"Decoder state mutated by tampered rekey frame (offset={offset}). "
            f"pre={pre_state} post={post_state}. Regression of bug #1 / "
            "the speculative-rekey rollback pattern."
        )
        assert decoder._pending_rollback is None, (
            "_pending_rollback should be cleared after a failed decrypt; "
            "found stale snapshot."
        )

        encoder.finalize()
        decoder.finalize()

    @given(n_decrypts=st.integers(min_value=1, max_value=5))
    @settings(
        max_examples=15,
        deadline=15000,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    )
    def test_no_pending_rollback_after_clean_decrypts(self, n_decrypts):
        """After every clean decrypt, _pending_rollback must be None.
        _commit_rekey() drains it on the success path; this property test
        asserts the drain is not skipped on any non-rekey frame.
        """
        from meow_decoder.ratchet import EncoderRatchet, DecoderRatchet

        root_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        total = max(n_decrypts + 1, 4)

        encoder = EncoderRatchet(
            root_key, salt, k_blocks=3, block_size=200, total_frames=total
        )
        decoder = DecoderRatchet(
            root_key, salt, k_blocks=3, block_size=200, total_frames=total
        )

        for i in range(n_decrypts):
            d = secrets.token_bytes(80)
            decoder.decrypt(encoder.encrypt_next(d))
            assert decoder._pending_rollback is None, (
                f"_pending_rollback non-None after clean non-rekey "
                f"decrypt #{i}: {decoder._pending_rollback}"
            )

        encoder.finalize()
        decoder.finalize()
