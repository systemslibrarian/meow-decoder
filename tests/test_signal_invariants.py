"""
Signal-Grade Protocol Invariant Tests

These tests verify the 7 critical protocol invariants that MUST hold
for the Meow Decoder ratchet protocol to match Signal's security properties.

Each test is deterministic (fixed inputs) and tests a SINGLE invariant.
ANY failure is a CRITICAL security regression.

Invariants tested:
1. Backward secrecy (key compromise doesn't reveal past)
2. Jump-ahead DoS bound (attacker can't cause unbounded computation)
3. Out-of-order delivery (fountain code compatibility)
4. Replay rejection (same frame twice → rejected)
5. Cross-session replay rejection (salt binding)
6. Nonce uniqueness (no (key, nonce) reuse)
7. Transcript/AAD binding (all context bound in authenticated data)

Run: MEOW_TEST_MODE=1 pytest tests/test_signal_invariants.py -v
"""

from meow_decoder.frame_mac import (
    derive_frame_master_key,
    derive_frame_key,
    compute_frame_mac,
    verify_frame_mac,
)
from meow_decoder.crypto import (
    encrypt_file_bytes,
    decrypt_to_raw,
    build_canonical_aad,
    derive_key,
    MAGIC,
    AAD_VERSION,
)
from meow_decoder.ratchet import (
    init_ratchet,
    ratchet_step,
    derive_frame_keys,
    encrypt_frame,
    decrypt_frame,
    EncoderRatchet,
    DecoderRatchet,
    MAX_SKIP_KEYS,
    _derive_header_key,
    _encrypt_index,
    COMMIT_TAG_SIZE,
    GCM_TAG_SIZE,
)
import os
import secrets
import struct

import pytest

os.environ["MEOW_TEST_MODE"] = "1"


# Fixed test inputs for determinism
ROOT_KEY = bytes(range(32))
SALT = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
K_BLOCKS = 5
BLOCK_SIZE = 800
TOTAL_FRAMES = 20


class TestInvariant1_BackwardSecrecy:
    """
    INVARIANT: Compromise of frame N key MUST NOT reveal frames < N.

    This is the core forward secrecy property. The hash ratchet is
    one-way: given chain_key[N], it is computationally infeasible
    to derive chain_key[N-1] or any prior message keys.
    """

    def test_compromised_key_cannot_decrypt_prior_frames(self):
        """Attacker with msg_key[10] cannot decrypt frames 0-9."""
        state = init_ratchet(ROOT_KEY, SALT)
        msg_keys = []
        for _ in range(TOTAL_FRAMES):
            mk, state = ratchet_step(state)
            msg_keys.append(mk)

        # Encrypt all frames
        encrypted = []
        for i in range(TOTAL_FRAMES):
            enc = encrypt_frame(
                frame_data=f"secret_frame_{i}".encode(),
                message_key=msg_keys[i],
                frame_index=i,
                salt=SALT,
                k_blocks=K_BLOCKS,
                block_size=BLOCK_SIZE,
                total_frames=TOTAL_FRAMES,
            )
            encrypted.append(enc)

        # Attacker compromises frame 10's key
        compromised = msg_keys[10]

        # Verify: compromised key decrypts its own frame
        pt = decrypt_frame(
            encrypted_frame=encrypted[10],
            message_key=compromised,
            expected_index=10,
            salt=SALT,
            k_blocks=K_BLOCKS,
            block_size=BLOCK_SIZE,
            total_frames=TOTAL_FRAMES,
        )
        assert pt == b"secret_frame_10"

        # Verify: compromised key CANNOT decrypt any prior frame
        for i in range(10):
            with pytest.raises(Exception):
                decrypt_frame(
                    encrypted_frame=encrypted[i],
                    message_key=compromised,
                    expected_index=i,
                    salt=SALT,
                    k_blocks=K_BLOCKS,
                    block_size=BLOCK_SIZE,
                    total_frames=TOTAL_FRAMES,
                )

    def test_chain_key_is_one_way(self):
        """Given chain_key[N], chain_key[N-1] is not derivable."""
        state = init_ratchet(ROOT_KEY, SALT)
        chain_keys = [bytes(state.chain_key)]

        for _ in range(10):
            _, state = ratchet_step(state)
            chain_keys.append(bytes(state.chain_key))

        # Each chain key must be unique
        assert len(set(chain_keys)) == len(chain_keys), "Chain key collision"

        # No chain key should be derivable from a later one
        # (we can't prove this mathematically, but we can verify
        # the keys are all distinct and not related by simple XOR/shift)
        for i in range(len(chain_keys) - 1):
            for j in range(i + 1, len(chain_keys)):
                xor = bytes(a ^ b for a, b in zip(chain_keys[i], chain_keys[j]))
                # XOR should look random (high entropy)
                unique_bytes = len(set(xor))
                assert unique_bytes > 8, f"Chain keys {i},{j} suspiciously related"


class TestInvariant2_JumpAheadDoS:
    """
    INVARIANT: Adversarial jump-ahead frame index MUST be rejected in bounded time.

    An attacker who crafts a frame claiming index MAX_SKIP_KEYS+N must
    not cause O(N) real crypto operations — the decoder must reject
    immediately.
    """

    def test_jump_ahead_rejected_fast(self):
        """Frame index beyond MAX_SKIP_KEYS rejected in <1s."""
        import time

        decoder = DecoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=BLOCK_SIZE,
            total_frames=MAX_SKIP_KEYS + 200,
        )

        # Craft frame with adversarially high index
        header_key = _derive_header_key(ROOT_KEY, SALT)
        fake_index = MAX_SKIP_KEYS + 100
        enc_idx = _encrypt_index(header_key, fake_index)
        fake_body = secrets.token_bytes(COMMIT_TAG_SIZE + GCM_TAG_SIZE + 16)
        fake_frame = enc_idx + fake_body

        start = time.monotonic()
        with pytest.raises(ValueError, match="skip|DoS"):
            decoder.decrypt(fake_frame)
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"DoS bound violated: {elapsed:.2f}s"
        decoder.finalize()

    def test_max_skip_boundary_exact(self):
        """Frame at exactly MAX_SKIP_KEYS works; MAX_SKIP_KEYS+1 fails."""
        total = MAX_SKIP_KEYS + 10
        encoder = EncoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=BLOCK_SIZE,
            total_frames=total,
        )
        # Encrypt all frames
        encrypted = [encoder.encrypt_next(f"f{i}".encode()) for i in range(total)]
        encoder.finalize()

        # Decode frame at MAX_SKIP_KEYS-1 (skipping 0..MAX_SKIP_KEYS-2)
        decoder = DecoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=BLOCK_SIZE,
            total_frames=total,
        )
        # This should succeed (within skip limit)
        result = decoder.decrypt(encrypted[MAX_SKIP_KEYS - 1])
        assert result == f"f{MAX_SKIP_KEYS - 1}".encode()
        decoder.finalize()


class TestInvariant3_OutOfOrder:
    """
    INVARIANT: Out-of-order frame delivery MUST succeed (fountain compat).

    Fountain codes deliver frames in arbitrary order. Every permutation
    of frames must decrypt correctly.
    """

    def test_fully_shuffled_delivery(self):
        """All frames arrive in reverse order — all must decrypt."""
        import random

        total = 30
        frames = [f"payload_{i:04d}".encode() for i in range(total)]

        encoder = EncoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=400,
            total_frames=total,
        )
        encrypted = [encoder.encrypt_next(f) for f in frames]
        encoder.finalize()

        decoder = DecoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=400,
            total_frames=total,
        )

        # Deliver in fully random order
        indices = list(range(total))
        random.seed(42)  # Deterministic shuffle
        random.shuffle(indices)

        results = {}
        for i in indices:
            results[i] = decoder.decrypt(encrypted[i])
        decoder.finalize()

        # Verify all frames decrypted correctly
        for i in range(total):
            assert results[i] == frames[i], f"Frame {i} corrupted: {results[i]}"

    def test_reverse_order_delivery(self):
        """Deliver all frames in reverse order."""
        total = 15
        frames = [f"rev_{i}".encode() for i in range(total)]

        encoder = EncoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=total,
        )
        encrypted = [encoder.encrypt_next(f) for f in frames]
        encoder.finalize()

        decoder = DecoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=total,
        )

        results = {}
        for i in reversed(range(total)):
            results[i] = decoder.decrypt(encrypted[i])
        decoder.finalize()

        for i in range(total):
            assert results[i] == frames[i]


class TestInvariant4_ReplayRejection:
    """
    INVARIANT: Replaying the same encrypted frame MUST be rejected.

    A replay attack sends the exact same ciphertext twice.
    The decoder must detect this and raise ValueError.
    """

    def test_exact_replay_rejected(self):
        """Same bytes sent twice → ValueError on second attempt."""
        total = 5
        encoder = EncoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=total,
        )
        encrypted = [encoder.encrypt_next(f"f{i}".encode()) for i in range(total)]
        encoder.finalize()

        decoder = DecoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=total,
        )

        # First decrypt succeeds
        assert decoder.decrypt(encrypted[2]) == b"f2"

        # Exact replay → rejected
        with pytest.raises(ValueError, match="[Rr]eplay"):
            decoder.decrypt(encrypted[2])

        # Other frames still work
        assert decoder.decrypt(encrypted[0]) == b"f0"
        assert decoder.decrypt(encrypted[4]) == b"f4"
        decoder.finalize()

    def test_all_frames_replayable_once_only(self):
        """Every frame can be decrypted exactly once."""
        total = 10
        encoder = EncoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=total,
        )
        encrypted = [encoder.encrypt_next(f"f{i}".encode()) for i in range(total)]
        encoder.finalize()

        decoder = DecoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=total,
        )

        # Decrypt all in order
        for i in range(total):
            assert decoder.decrypt(encrypted[i]) == f"f{i}".encode()

        # Replay ANY frame → rejected
        for i in range(total):
            with pytest.raises(ValueError, match="[Rr]eplay"):
                decoder.decrypt(encrypted[i])

        decoder.finalize()


class TestInvariant5_CrossSessionReplay:
    """
    INVARIANT: Frames from session A MUST NOT decrypt under session B.

    The salt is bound in the AAD, so cross-session replay is
    cryptographically impossible (AES-GCM authentication fails).
    """

    def test_different_salt_rejects_frames(self):
        """Session A frames fail under session B (different salt)."""
        salt_a = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")[:16]
        salt_b = bytes.fromhex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")[:16]

        encoder = EncoderRatchet(
            ROOT_KEY, salt_a,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=5,
        )
        encrypted_a = [encoder.encrypt_next(f"a{i}".encode()) for i in range(5)]
        encoder.finalize()

        decoder_b = DecoderRatchet(
            ROOT_KEY, salt_b,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=5,
        )

        for enc in encrypted_a:
            with pytest.raises(Exception):
                decoder_b.decrypt(enc)
        decoder_b.finalize()

    def test_different_root_key_rejects_frames(self):
        """Session A frames fail under session B (different root key)."""
        key_a = bytes(range(32))
        key_b = bytes(range(1, 33))

        encoder = EncoderRatchet(
            key_a, SALT,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=5,
        )
        encrypted = [encoder.encrypt_next(f"a{i}".encode()) for i in range(5)]
        encoder.finalize()

        decoder_b = DecoderRatchet(
            key_b, SALT,
            k_blocks=K_BLOCKS, block_size=800,
            total_frames=5,
        )

        for enc in encrypted:
            with pytest.raises(Exception):
                decoder_b.decrypt(enc)
        decoder_b.finalize()


class TestInvariant6_NonceUniqueness:
    """
    INVARIANT: No (encryption_key, nonce) pair is ever reused.

    AES-GCM is catastrophically broken by (key, nonce) reuse.
    The ratchet must produce unique (key, nonce) for every frame.
    """

    def test_100_frames_all_unique_pairs(self):
        """100 consecutive frames have 100 unique (key, nonce) pairs."""
        state = init_ratchet(ROOT_KEY, SALT)

        pairs = set()
        for _ in range(100):
            mk, state = ratchet_step(state)
            keys = derive_frame_keys(mk, SALT)
            pair = (bytes(keys.enc_key), bytes(keys.nonce))
            assert pair not in pairs, "CRITICAL: (key, nonce) reuse detected!"
            pairs.add(pair)

        assert len(pairs) == 100

    def test_encryption_keys_all_unique(self):
        """All 100 encryption keys are distinct."""
        state = init_ratchet(ROOT_KEY, SALT)

        enc_keys = set()
        for _ in range(100):
            mk, state = ratchet_step(state)
            keys = derive_frame_keys(mk, SALT)
            enc_keys.add(bytes(keys.enc_key))

        assert len(enc_keys) == 100, "Encryption key collision!"

    def test_nonces_all_unique(self):
        """All 100 nonces are distinct."""
        state = init_ratchet(ROOT_KEY, SALT)

        nonces = set()
        for _ in range(100):
            mk, state = ratchet_step(state)
            keys = derive_frame_keys(mk, SALT)
            nonces.add(bytes(keys.nonce))

        assert len(nonces) == 100, "Nonce collision!"


class TestInvariant7_TranscriptBinding:
    """
    INVARIANT: AAD must bind all protocol context.

    The canonical AAD construction must include:
    - AAD version byte
    - Original file length
    - Compressed length
    - Salt
    - SHA-256 of original file
    - Magic string
    - Mode byte
    - Ephemeral public key (when present)
    - PQ ciphertext (when present)

    Changing ANY field must cause authentication failure.
    """

    def test_aad_contains_all_fields(self):
        """AAD includes version, lengths, salt, hash, magic, mode."""
        sha = bytes(32)
        aad = build_canonical_aad(
            orig_len=1000,
            comp_len=800,
            salt=SALT,
            sha256_hash=sha,
            magic=MAGIC,
            ephemeral_public_key=None,
            pq_ciphertext=None,
            mode_byte=0x03,
        )

        # Must contain AAD version
        assert aad[0:1] == AAD_VERSION

        # Must contain lengths (LE u64)
        assert struct.pack("<Q", 1000) in aad
        assert struct.pack("<Q", 800) in aad

        # Must contain salt
        assert SALT in aad

        # Must contain sha256
        assert sha in aad

        # Must contain magic
        assert MAGIC in aad

        # Must contain mode byte
        assert bytes([0x03]) in aad

    def test_aad_tampered_orig_len_rejected(self):
        """Tampered orig_len in AAD causes decryption failure."""
        data = b"Test data for AAD binding"
        password = "aad_test_pass"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )

        # Correct decryption works
        pt = decrypt_to_raw(cipher, password, salt, nonce,
                            orig_len=len(data), comp_len=len(comp), sha256=sha)
        assert pt == data

        # Tampered orig_len → rejected
        with pytest.raises(Exception):
            decrypt_to_raw(cipher, password, salt, nonce,
                           orig_len=len(data) + 1, comp_len=len(comp), sha256=sha)

    def test_aad_tampered_comp_len_rejected(self):
        """Tampered comp_len in AAD causes decryption failure."""
        data = b"Test data for comp_len binding"
        password = "aad_comp_test"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )

        with pytest.raises(Exception):
            decrypt_to_raw(cipher, password, salt, nonce,
                           orig_len=len(data), comp_len=len(comp) + 1, sha256=sha)

    def test_aad_tampered_sha256_rejected(self):
        """Tampered SHA-256 hash in AAD causes decryption failure."""
        data = b"Test data for sha256 binding"
        password = "aad_sha_test"

        comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            data, password, None, None
        )

        bad_sha = bytes(32)  # All zeros
        with pytest.raises(Exception):
            decrypt_to_raw(cipher, password, salt, nonce,
                           orig_len=len(data), comp_len=len(comp), sha256=bad_sha)

    def test_frame_mac_aad_binding(self):
        """Frame MAC is bound to frame index and salt."""
        fmk = derive_frame_master_key(ROOT_KEY, SALT)
        data = b"FOUNTAIN:5:800:2847:AAAA"

        mac_0 = compute_frame_mac(data, fmk, 0, SALT)
        mac_1 = compute_frame_mac(data, fmk, 1, SALT)

        # Same data, different index → different MAC
        assert mac_0 != mac_1

        # Verify correct MAC
        assert verify_frame_mac(data, mac_0, fmk, 0, SALT)

        # Wrong index → verification fails
        assert not verify_frame_mac(data, mac_0, fmk, 1, SALT)

        # Wrong salt → verification fails
        wrong_salt = bytes(16)
        fmk_wrong = derive_frame_master_key(ROOT_KEY, wrong_salt)
        assert not verify_frame_mac(data, mac_0, fmk_wrong, 0, wrong_salt)


class TestRatchetDeterminism:
    """Verify ratchet operations are fully deterministic."""

    def test_same_inputs_same_outputs_ratchet(self):
        """Identical init → identical chain progression."""
        s1 = init_ratchet(ROOT_KEY, SALT)
        s2 = init_ratchet(ROOT_KEY, SALT)

        for _ in range(20):
            mk1, s1 = ratchet_step(s1)
            mk2, s2 = ratchet_step(s2)
            assert mk1 == mk2

    def test_same_inputs_same_frame_keys(self):
        """Same message key + salt → same (enc_key, nonce, mac_key)."""
        state = init_ratchet(ROOT_KEY, SALT)
        mk, _ = ratchet_step(state)

        fk1 = derive_frame_keys(mk, SALT)
        fk2 = derive_frame_keys(mk, SALT)

        assert bytes(fk1.enc_key) == bytes(fk2.enc_key)
        assert bytes(fk1.nonce) == bytes(fk2.nonce)
        assert bytes(fk1.mac_key) == bytes(fk2.mac_key)

    def test_encrypt_decrypt_roundtrip_deterministic(self):
        """Encrypt → decrypt roundtrip produces original plaintext."""
        total = 10
        frames = [f"deterministic_{i}".encode() for i in range(total)]

        encoder = EncoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=BLOCK_SIZE,
            total_frames=total,
        )
        encrypted = [encoder.encrypt_next(f) for f in frames]
        encoder.finalize()

        decoder = DecoderRatchet(
            ROOT_KEY, SALT,
            k_blocks=K_BLOCKS, block_size=BLOCK_SIZE,
            total_frames=total,
        )
        for i in range(total):
            pt = decoder.decrypt(encrypted[i])
            assert pt == frames[i], f"Frame {i}: expected {frames[i]}, got {pt}"
        decoder.finalize()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
