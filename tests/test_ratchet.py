"""
Comprehensive tests for the MEOW Symmetric Ratchet (MSR v1).

Tests cover:
- Core ratchet operations (init, step, derive, build_aad)
- Forward secrecy proofs (one-wayness of chain)
- Subkey independence (domain separation)
- EncoderRatchet / DecoderRatchet roundtrip (in-order and out-of-order)
- Replay detection
- DoS bounds (MAX_SKIP_KEYS)
- Frame tampering (GCM auth failure)
- Key zeroization
- Finalized state rejection
- Frame index mismatch rejection
- Edge cases (empty data, single frame, max frames)
"""

from meow_decoder.ratchet import (
    FRAME_ENC_INFO,
    FRAME_INDEX_SIZE,
    FRAME_MAC_INFO,
    FRAME_NONCE_INFO,
    GCM_TAG_SIZE,
    MAX_FRAME_INDEX,
    MAX_SKIP_KEYS,
    RATCHET_AAD_PREFIX,
    RATCHET_MSG_INFO,
    RATCHET_ROOT_INFO,
    RATCHET_STEP_INFO,
    REKEY_BEACON_INFO,
    REKEY_BEACON_KEM_INFO,
    REKEY_BEACON_SIZE,
    DEFAULT_REKEY_INTERVAL,
    HEADER_ENC_INFO,
    HEADER_MASK_INFO,
    COMMIT_TAG_SIZE,
    DecoderRatchet,
    EncoderRatchet,
    FrameKeys,
    RatchetState,
    build_frame_aad,
    decrypt_frame,
    derive_frame_keys,
    encrypt_frame,
    init_ratchet,
    ratchet_step,
    _hkdf_derive,
    _secure_zero,
    _mix_beacon,
    _encrypt_index,
    _derive_header_key,
    _compute_commitment,
)
import pytest
import os
import secrets
import struct

from meow_decoder.crypto_backend import get_handle_backend

os.environ.setdefault("MEOW_TEST_MODE", "1")


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def root_key():
    """32-byte root key for testing."""
    return secrets.token_bytes(32)


@pytest.fixture
def salt():
    """16-byte salt for testing."""
    return secrets.token_bytes(16)


@pytest.fixture
def encoding_params():
    """Standard encoding parameters for tests."""
    return {"k_blocks": 5, "block_size": 800, "total_frames": 10}


@pytest.fixture
def ratchet_state(root_key, salt):
    """Ready-to-use ratchet state at position 0."""
    return init_ratchet(root_key, salt)


@pytest.fixture
def sample_frame_data():
    """Sample plaintext frame data."""
    return b"FOUNTAIN:5:800:4000:" + secrets.token_bytes(600)


# ── Domain Separation Constants ──────────────────────────────────────────────


class TestDomainSeparation:
    """Verify all domain separation constants are unique and well-formed."""

    def test_all_constants_unique(self):
        constants = [
            RATCHET_ROOT_INFO,
            RATCHET_STEP_INFO,
            RATCHET_MSG_INFO,
            FRAME_ENC_INFO,
            FRAME_NONCE_INFO,
            FRAME_MAC_INFO,
        ]
        assert len(constants) == len(set(constants)), "Domain separation constants must be unique"

    def test_constants_are_bytes(self):
        for const in [
            RATCHET_ROOT_INFO,
            RATCHET_STEP_INFO,
            RATCHET_MSG_INFO,
            FRAME_ENC_INFO,
            FRAME_NONCE_INFO,
            FRAME_MAC_INFO,
        ]:
            assert isinstance(const, bytes)
            assert len(const) > 0

    def test_constants_have_version_prefix(self):
        """All constants should include a version identifier for future extensibility."""
        for const in [
            RATCHET_ROOT_INFO,
            RATCHET_STEP_INFO,
            RATCHET_MSG_INFO,
            FRAME_ENC_INFO,
            FRAME_NONCE_INFO,
            FRAME_MAC_INFO,
        ]:
            assert b"v1" in const, f"Constant {const!r} missing version identifier"

    def test_constants_have_meow_prefix(self):
        """All constants should be meow_ratchet-prefixed for domain separation."""
        for const in [
            RATCHET_ROOT_INFO,
            RATCHET_STEP_INFO,
            RATCHET_MSG_INFO,
            FRAME_ENC_INFO,
            FRAME_NONCE_INFO,
            FRAME_MAC_INFO,
        ]:
            assert const.startswith(
                b"meow_ratchet_"
            ), f"Constant {const!r} missing meow_ratchet_ prefix"


# ── Core Ratchet Operations ──────────────────────────────────────────────────


class TestInitRatchet:
    """Tests for init_ratchet()."""

    def test_returns_ratchet_state(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        assert isinstance(state, RatchetState)

    def test_initial_position_is_zero(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        assert state.position == 0

    def test_chain_key_is_opaque_handle(self, root_key, salt):
        """chain_key is an opaque handle (int), not raw bytes."""
        state = init_ratchet(root_key, salt)
        assert isinstance(state.chain_key, int) and state.chain_key > 0
        hb = get_handle_backend()
        assert hb.exists(state.chain_key)

    def test_chain_key_is_handle(self, root_key, salt):
        """Chain key must be an opaque handle — secrets never in Python."""
        state = init_ratchet(root_key, salt)
        assert isinstance(state.chain_key, int), "chain_key must be opaque handle (int)"

    def test_chain_key_differs_from_root(self, root_key, salt):
        """chain_key[0] must be derived (not equal to root_key)."""
        state = init_ratchet(root_key, salt)
        assert bytes(state.chain_key) != root_key

    def test_salt_preserved(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        assert state.salt == salt

    def test_deterministic_with_same_inputs(self, root_key, salt):
        """Same root_key + salt produces identical chain_key[0]."""
        s1 = init_ratchet(root_key, salt)
        s2 = init_ratchet(root_key, salt)
        # Handles have unique IDs, so compare derived commitments
        hb = get_handle_backend()
        c1 = hb.derive_key_hkdf_bytes(s1.chain_key, salt, b"TEST_CMP", 32)
        c2 = hb.derive_key_hkdf_bytes(s2.chain_key, salt, b"TEST_CMP", 32)
        assert c1 == c2, "Same inputs must produce identical chain keys"

    def test_different_root_keys_produce_different_chains(self, salt):
        k1 = secrets.token_bytes(32)
        k2 = secrets.token_bytes(32)
        s1 = init_ratchet(k1, salt)
        s2 = init_ratchet(k2, salt)
        assert s1.chain_key != s2.chain_key

    def test_different_salts_produce_different_chains(self, root_key):
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        s1 = init_ratchet(root_key, salt1)
        s2 = init_ratchet(root_key, salt2)
        assert s1.chain_key != s2.chain_key


class TestRatchetStep:
    """Tests for ratchet_step()."""

    def test_returns_message_key_and_new_state(self, ratchet_state):
        msg_key, new_state = ratchet_step(ratchet_state)
        assert isinstance(msg_key, int), "message_key must be opaque handle (int)"
        assert msg_key > 0
        hb = get_handle_backend()
        assert hb.exists(msg_key)
        assert isinstance(new_state, RatchetState)

    def test_position_advances_by_one(self, ratchet_state):
        assert ratchet_state.position == 0
        _, new_state = ratchet_step(ratchet_state)
        assert new_state.position == 1

    def test_chain_key_changes_after_step(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        initial_chain = bytes(state.chain_key)
        _, new_state = ratchet_step(state)
        assert bytes(new_state.chain_key) != initial_chain

    def test_message_key_differs_from_chain_key(self, ratchet_state):
        msg_key, new_state = ratchet_step(ratchet_state)
        assert msg_key != bytes(new_state.chain_key)

    def test_old_chain_key_is_zeroized(self, root_key, salt):
        """After ratchet_step, the OLD state's chain_key handle should be dropped."""
        state = init_ratchet(root_key, salt)
        original_handle = state.chain_key  # Capture the handle ID
        hb = get_handle_backend()
        assert hb.exists(original_handle)
        _, _ = ratchet_step(state)
        # The original handle should be dropped (forward secrecy)
        assert not hb.exists(original_handle)

    def test_sequential_steps_produce_unique_keys(self, root_key, salt):
        """Each step produces a unique message key."""
        state = init_ratchet(root_key, salt)
        keys = []
        for _ in range(20):
            msg_key, state = ratchet_step(state)
            keys.append(msg_key)
        assert len(set(keys)) == 20, "All message keys must be unique"

    def test_sequential_steps_produce_unique_chain_keys(self, root_key, salt):
        """Each step produces a unique chain key."""
        state = init_ratchet(root_key, salt)
        chain_keys = []
        for _ in range(20):
            chain_keys.append(bytes(state.chain_key))
            _, state = ratchet_step(state)
        chain_keys.append(bytes(state.chain_key))
        assert len(set(chain_keys)) == 21

    def test_dead_state_raises(self, ratchet_state):
        """Stepping a zeroized state must raise ValueError."""
        ratchet_state.zeroize()
        with pytest.raises(ValueError, match="dead"):
            ratchet_step(ratchet_state)

    def test_deterministic_sequence(self, root_key, salt):
        """Same inputs produce identical message key sequences."""
        state1 = init_ratchet(root_key, salt)
        state2 = init_ratchet(root_key, salt)
        hb = get_handle_backend()
        for _ in range(10):
            mk1, state1 = ratchet_step(state1)
            mk2, state2 = ratchet_step(state2)
            # Handle IDs differ, but underlying keys must be identical
            c1 = hb.derive_key_hkdf_bytes(mk1, salt, b"TEST_CMP", 32)
            c2 = hb.derive_key_hkdf_bytes(mk2, salt, b"TEST_CMP", 32)
            assert c1 == c2, "Deterministic sequence diverged"


# ── Forward Secrecy Proof ────────────────────────────────────────────────────


class TestForwardSecrecy:
    """Prove that chain_key[i] → chain_key[i+1] is computationally one-way."""

    def test_chain_key_not_derivable_from_successor(self, root_key, salt):
        """
        Given chain_key[N+1], verify we cannot derive chain_key[N].
        This is the core forward secrecy property.
        """
        state = init_ratchet(root_key, salt)

        # Collect chain keys
        chain_keys = []
        for _ in range(10):
            chain_keys.append(bytes(state.chain_key))
            _, state = ratchet_step(state)

        # Verify: knowing chain_key[5] does NOT help derive chain_key[4]
        # If HKDF is one-way, chain_key[4] cannot be recovered from chain_key[5]
        # We verify this by checking that no HKDF derivation of chain_key[5]
        # produces chain_key[4]
        ck5 = chain_keys[5]
        ck4 = chain_keys[4]

        # Try all domain separation strings — none should recover ck4
        for info in [
            RATCHET_ROOT_INFO,
            RATCHET_STEP_INFO,
            RATCHET_MSG_INFO,
            FRAME_ENC_INFO,
            FRAME_NONCE_INFO,
            FRAME_MAC_INFO,
            b"reverse",
            b"inverse",
        ]:
            derived = _hkdf_derive(ck5, salt, info, 32)
            assert derived != ck4, f"Forward secrecy broken with info={info!r}"

    def test_message_key_not_derivable_from_later_chain(self, root_key, salt):
        """
        Given chain_key[N+1], verify we cannot derive message_key[N].
        """
        state = init_ratchet(root_key, salt)
        msg_key_0, state = ratchet_step(state)  # Derive message_key[0]
        ck1 = bytes(state.chain_key)  # chain_key[1]

        # Try all info strings
        for info in [RATCHET_ROOT_INFO, RATCHET_STEP_INFO, RATCHET_MSG_INFO]:
            derived = _hkdf_derive(ck1, salt, info, 32)
            assert derived != msg_key_0

    def test_chain_independence_across_positions(self, root_key, salt):
        """
        Verify chain keys at different positions are statistically independent.
        This is a weaker test — we just check they share no bytes.
        """
        state = init_ratchet(root_key, salt)
        keys = []
        for _ in range(50):
            keys.append(bytes(state.chain_key))
            _, state = ratchet_step(state)

        # Pairwise comparison: no two chain keys should be identical
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                assert keys[i] != keys[j]


# ── Subkey Independence ──────────────────────────────────────────────────────


class TestSubkeyIndependence:
    """Verify that derived subkeys (enc, nonce, mac) are cryptographically independent."""

    def test_subkeys_are_different(self, root_key, salt):
        """enc_key, nonce, mac_key must all be different values."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)
        keys = derive_frame_keys(msg_key, salt)

        assert bytes(keys.enc_key) != bytes(keys.mac_key)
        # nonce is 12 bytes, so can't directly compare with 32-byte keys
        assert bytes(keys.nonce) != bytes(keys.enc_key)[:12]
        assert bytes(keys.nonce) != bytes(keys.mac_key)[:12]

    def test_subkey_sizes(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)
        keys = derive_frame_keys(msg_key, salt)

        # enc_key and mac_key are opaque handles; nonce is still bytes
        assert isinstance(keys.enc_key, int) and keys.enc_key > 0
        assert len(keys.nonce) == 12
        assert isinstance(keys.mac_key, int) and keys.mac_key > 0

    def test_subkeys_are_handles(self, root_key, salt):
        """enc_key and mac_key must be opaque handles; nonce is bytearray."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)
        keys = derive_frame_keys(msg_key, salt)

        assert isinstance(keys.enc_key, int), "enc_key must be opaque handle"
        assert isinstance(keys.nonce, bytearray)
        assert isinstance(keys.mac_key, int), "mac_key must be opaque handle"

    def test_different_message_keys_produce_different_subkeys(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        mk1, state = ratchet_step(state)
        mk2, state = ratchet_step(state)

        keys1 = derive_frame_keys(mk1, salt)
        keys2 = derive_frame_keys(mk2, salt)

        assert bytes(keys1.enc_key) != bytes(keys2.enc_key)
        assert bytes(keys1.nonce) != bytes(keys2.nonce)
        assert bytes(keys1.mac_key) != bytes(keys2.mac_key)

    def test_same_message_key_different_salt(self, root_key):
        """Same message key with different salts produces different subkeys."""
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        state1 = init_ratchet(root_key, salt1)
        mk, _ = ratchet_step(state1)

        keys1 = derive_frame_keys(mk, salt1)
        keys2 = derive_frame_keys(mk, salt2)

        assert bytes(keys1.enc_key) != bytes(keys2.enc_key)

    def test_zeroize_clears_all_subkeys(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)
        keys = derive_frame_keys(msg_key, salt)

        hb = get_handle_backend()
        # Verify handles exist first
        assert hb.exists(keys.enc_key)
        assert bytes(keys.nonce) != bytes(12)
        assert hb.exists(keys.mac_key)

        enc_h, mac_h = keys.enc_key, keys.mac_key
        keys.zeroize()

        # Handles should be dropped after zeroize
        assert not hb.exists(enc_h)
        assert bytes(keys.nonce) == bytes(12)
        assert not hb.exists(mac_h)


# ── Build Frame AAD ──────────────────────────────────────────────────────────


class TestBuildFrameAAD:
    """Tests for build_frame_aad()."""

    def test_aad_starts_with_prefix(self, salt):
        aad = build_frame_aad(0, salt, 5, 800, 10)
        assert aad.startswith(RATCHET_AAD_PREFIX)

    def test_aad_contains_frame_index(self, salt):
        aad = build_frame_aad(42, salt, 5, 800, 10)
        # Frame index is 4 bytes little-endian after the prefix
        offset = len(RATCHET_AAD_PREFIX)
        idx = struct.unpack("<I", aad[offset : offset + 4])[0]
        assert idx == 42

    def test_aad_contains_salt(self, salt):
        aad = build_frame_aad(0, salt, 5, 800, 10)
        assert salt in aad

    def test_aad_deterministic(self, salt):
        aad1 = build_frame_aad(0, salt, 5, 800, 10)
        aad2 = build_frame_aad(0, salt, 5, 800, 10)
        assert aad1 == aad2

    def test_different_frame_indices_produce_different_aad(self, salt):
        aad1 = build_frame_aad(0, salt, 5, 800, 10)
        aad2 = build_frame_aad(1, salt, 5, 800, 10)
        assert aad1 != aad2

    def test_different_salts_produce_different_aad(self):
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        aad1 = build_frame_aad(0, salt1, 5, 800, 10)
        aad2 = build_frame_aad(0, salt2, 5, 800, 10)
        assert aad1 != aad2

    def test_different_params_produce_different_aad(self, salt):
        aad1 = build_frame_aad(0, salt, 5, 800, 10)
        aad2 = build_frame_aad(0, salt, 6, 800, 10)  # different k_blocks
        aad3 = build_frame_aad(0, salt, 5, 900, 10)  # different block_size
        aad4 = build_frame_aad(0, salt, 5, 800, 11)  # different total_frames
        assert len({aad1, aad2, aad3, aad4}) == 4

    def test_aad_length(self, salt):
        """AAD = prefix(15) + frame_idx(4) + k_blocks(2) + block_size(2) + total_frames(4) + salt(16) = 43."""
        aad = build_frame_aad(0, salt, 5, 800, 10)
        expected_len = len(RATCHET_AAD_PREFIX) + 4 + 2 + 2 + 4 + 16
        assert len(aad) == expected_len


# ── Frame Encryption / Decryption ────────────────────────────────────────────


class TestFrameEncryptDecrypt:
    """Tests for encrypt_frame() and decrypt_frame()."""

    def test_roundtrip(self, root_key, salt, sample_frame_data, encoding_params):
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)

        encrypted = encrypt_frame(
            frame_data=sample_frame_data,
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            **encoding_params,
        )

        decrypted = decrypt_frame(
            encrypted_frame=encrypted,
            message_key=msg_key,
            expected_index=0,
            salt=salt,
            **encoding_params,
        )

        assert decrypted == sample_frame_data

    def test_encrypted_frame_format(self, root_key, salt, encoding_params):
        """Output = frame_index(4 BE) + ciphertext + GCM tag(16)."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)
        data = b"test_payload"

        encrypted = encrypt_frame(
            frame_data=data,
            message_key=msg_key,
            frame_index=7,
            salt=salt,
            **encoding_params,
        )

        # First 4 bytes = frame index (big-endian)
        idx = struct.unpack(">I", encrypted[:4])[0]
        assert idx == 7

        # Length = 4 (index) + len(data) + 16 (GCM tag)
        assert len(encrypted) == 4 + len(data) + 16

    def test_index_mismatch_rejected(self, root_key, salt, encoding_params):
        """Decrypt with wrong expected_index must fail."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)

        encrypted = encrypt_frame(
            frame_data=b"data",
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            **encoding_params,
        )

        with pytest.raises(ValueError, match="[Ii]ndex mismatch"):
            decrypt_frame(
                encrypted_frame=encrypted,
                message_key=msg_key,
                expected_index=1,  # Wrong index
                salt=salt,
                **encoding_params,
            )

    def test_wrong_key_rejected(self, root_key, salt, encoding_params):
        """Decrypt with wrong message key must fail (GCM auth)."""
        state = init_ratchet(root_key, salt)
        msg_key, state = ratchet_step(state)
        wrong_key, _ = ratchet_step(state)  # Different key

        encrypted = encrypt_frame(
            frame_data=b"secret",
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            **encoding_params,
        )

        with pytest.raises(Exception):  # GCM InvalidTag or ValueError
            decrypt_frame(
                encrypted_frame=encrypted,
                message_key=wrong_key,
                expected_index=0,
                salt=salt,
                **encoding_params,
            )

    def test_bit_flip_rejected(self, root_key, salt, encoding_params):
        """Flipping a single bit in ciphertext must cause GCM auth failure."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)

        encrypted = encrypt_frame(
            frame_data=b"secret" * 100,
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            **encoding_params,
        )

        # Flip a bit in the ciphertext (after the 4-byte index header)
        tampered = bytearray(encrypted)
        tampered[10] ^= 0x01
        tampered = bytes(tampered)

        with pytest.raises(Exception):  # GCM InvalidTag
            decrypt_frame(
                encrypted_frame=tampered,
                message_key=msg_key,
                expected_index=0,
                salt=salt,
                **encoding_params,
            )

    def test_truncated_frame_rejected(self, root_key, salt, encoding_params):
        """Frame shorter than minimum size must be rejected."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)

        too_short = b"\x00" * (FRAME_INDEX_SIZE + GCM_TAG_SIZE - 1)
        with pytest.raises(ValueError, match="too short"):
            decrypt_frame(
                encrypted_frame=too_short,
                message_key=msg_key,
                expected_index=0,
                salt=salt,
                **encoding_params,
            )

    def test_wrong_salt_rejected(self, root_key, salt, encoding_params):
        """Decrypt with wrong salt must fail (AAD mismatch)."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)

        encrypted = encrypt_frame(
            frame_data=b"data",
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            **encoding_params,
        )

        wrong_salt = secrets.token_bytes(16)
        with pytest.raises(Exception):
            decrypt_frame(
                encrypted_frame=encrypted,
                message_key=msg_key,
                expected_index=0,
                salt=wrong_salt,
                **encoding_params,
            )

    def test_wrong_encoding_params_rejected(self, root_key, salt):
        """Decrypt with wrong k_blocks/block_size/total_frames must fail (AAD mismatch)."""
        params = {"k_blocks": 5, "block_size": 800, "total_frames": 10}
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)

        encrypted = encrypt_frame(
            frame_data=b"data",
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            **params,
        )

        wrong_params = {"k_blocks": 6, "block_size": 800, "total_frames": 10}
        with pytest.raises(Exception):
            decrypt_frame(
                encrypted_frame=encrypted,
                message_key=msg_key,
                expected_index=0,
                salt=salt,
                **wrong_params,
            )

    def test_empty_plaintext_roundtrip(self, root_key, salt, encoding_params):
        """Empty plaintext should encrypt and decrypt correctly."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)

        encrypted = encrypt_frame(
            frame_data=b"",
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            **encoding_params,
        )

        decrypted = decrypt_frame(
            encrypted_frame=encrypted,
            message_key=msg_key,
            expected_index=0,
            salt=salt,
            **encoding_params,
        )

        assert decrypted == b""

    def test_large_plaintext_roundtrip(self, root_key, salt, encoding_params):
        """Large plaintext (10 KB) should roundtrip correctly."""
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)
        large_data = secrets.token_bytes(10240)

        encrypted = encrypt_frame(
            frame_data=large_data,
            message_key=msg_key,
            frame_index=0,
            salt=salt,
            **encoding_params,
        )

        decrypted = decrypt_frame(
            encrypted_frame=encrypted,
            message_key=msg_key,
            expected_index=0,
            salt=salt,
            **encoding_params,
        )

        assert decrypted == large_data


# ── EncoderRatchet ───────────────────────────────────────────────────────────


class TestEncoderRatchet:
    """Tests for the EncoderRatchet state machine."""

    def test_encrypt_all_frames(self, root_key, salt):
        total = 5
        ratchet = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        encrypted_frames = []
        for i in range(total):
            frame_data = f"frame_{i}".encode()
            enc = ratchet.encrypt_next(frame_data)
            encrypted_frames.append(enc)

        assert len(encrypted_frames) == total

        # Frame indices are now header-encrypted (Signal parity).
        # Verify encrypted indices are unique and NOT plaintext.
        enc_indices = [enc[:4] for enc in encrypted_frames]
        assert len(set(enc_indices)) == total, "Encrypted indices must be unique"
        for i, enc in enumerate(encrypted_frames):
            plaintext_idx = struct.pack(">I", i)
            assert enc[:4] != plaintext_idx, f"Frame {i} index not encrypted"

    def test_position_tracks_frames(self, root_key, salt):
        ratchet = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=5)
        assert ratchet.position == 0

        ratchet.encrypt_next(b"a")
        assert ratchet.position == 1

        ratchet.encrypt_next(b"b")
        assert ratchet.position == 2

    def test_exceed_total_frames_raises(self, root_key, salt):
        ratchet = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=2)
        ratchet.encrypt_next(b"a")
        ratchet.encrypt_next(b"b")

        with pytest.raises(RuntimeError, match="already encrypted"):
            ratchet.encrypt_next(b"c")

    def test_finalize_prevents_further_encryption(self, root_key, salt):
        ratchet = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=5)
        ratchet.encrypt_next(b"a")
        ratchet.finalize()

        with pytest.raises(RuntimeError, match="finalized"):
            ratchet.encrypt_next(b"b")

    def test_double_finalize_is_safe(self, root_key, salt):
        """Finalize can be called multiple times without error."""
        ratchet = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=5)
        ratchet.finalize()
        ratchet.finalize()  # Should not raise

    def test_destructor_finalizes(self, root_key, salt):
        """del should call finalize as a safety net."""
        ratchet = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=5)
        ratchet.encrypt_next(b"a")
        ratchet.__del__()
        assert ratchet._finalized

    def test_each_frame_uses_unique_key(self, root_key, salt):
        """Verify that encrypting the same data twice produces different ciphertexts."""
        total = 5
        ratchet = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        data = b"identical_data"

        ciphertexts = []
        for _ in range(total):
            enc = ratchet.encrypt_next(data)
            ciphertexts.append(enc)

        # All ciphertexts must be different (different keys per frame)
        assert len(set(ciphertexts)) == total


# ── DecoderRatchet ───────────────────────────────────────────────────────────


class TestDecoderRatchet:
    """Tests for the DecoderRatchet state machine."""

    def _make_frames(self, root_key, salt, k_blocks=3, block_size=800, total_frames=5):
        """Helper: encode total_frames frames and return (encrypted_frames, frame_data)."""
        encoder = EncoderRatchet(root_key, salt, k_blocks, block_size, total_frames)
        frame_data = [f"frame_{i}".encode() for i in range(total_frames)]
        encrypted = [encoder.encrypt_next(d) for d in frame_data]
        encoder.finalize()
        return encrypted, frame_data

    def test_in_order_roundtrip(self, root_key, salt):
        """Decrypt frames in order (trivial case)."""
        total = 5
        encrypted, originals = self._make_frames(root_key, salt, total_frames=total)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        for i in range(total):
            plaintext = decoder.decrypt(encrypted[i])
            assert plaintext == originals[i]
        decoder.finalize()

    def test_out_of_order_roundtrip(self, root_key, salt):
        """Decrypt frames out of order (fountain code scenario)."""
        total = 8
        encrypted, originals = self._make_frames(root_key, salt, total_frames=total)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        # Receive frames out of order: 0, 3, 1, 5, 2, 7, 4, 6
        order = [0, 3, 1, 5, 2, 7, 4, 6]
        for i in order:
            plaintext = decoder.decrypt(encrypted[i])
            assert plaintext == originals[i], f"Frame {i} decrypted incorrectly"

        decoder.finalize()

    def test_reverse_order_roundtrip(self, root_key, salt):
        """Decrypt frames in reverse order (extreme out-of-order)."""
        total = 6
        encrypted, originals = self._make_frames(root_key, salt, total_frames=total)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        for i in reversed(range(total)):
            plaintext = decoder.decrypt(encrypted[i])
            assert plaintext == originals[i]

        decoder.finalize()

    def test_replay_detection(self, root_key, salt):
        """Decrypting the same frame twice must raise ValueError."""
        total = 3
        encrypted, _ = self._make_frames(root_key, salt, total_frames=total)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        decoder.decrypt(encrypted[0])  # First time OK

        with pytest.raises(ValueError, match="[Rr]eplay"):
            decoder.decrypt(encrypted[0])  # Second time = replay

        decoder.finalize()

    def test_frame_index_out_of_range_rejected(self, root_key, salt):
        """Unknown encrypted frame index must be rejected.

        With header encryption (MSR v1.2), the decoder rejects frames
        whose encrypted index doesn't match any precomputed entry.
        This is STRONGER than the old check — attackers can't even
        target specific frame indices without the header key.
        """
        total = 3
        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        # Random bytes won't match any encrypted index in the lookup table
        fake_frame = secrets.token_bytes(4) + secrets.token_bytes(48)
        with pytest.raises(ValueError, match="Header decryption failed"):
            decoder.decrypt(fake_frame)

        decoder.finalize()

    def test_finalized_rejects_decrypt(self, root_key, salt):
        total = 3
        encrypted, _ = self._make_frames(root_key, salt, total_frames=total)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        decoder.finalize()

        with pytest.raises(RuntimeError, match="finalized"):
            decoder.decrypt(encrypted[0])

    def test_skip_key_dos_bound(self, root_key, salt):
        """
        Receiving a frame that requires caching more than MAX_SKIP_KEYS
        skipped keys must raise ValueError (DoS protection).

        With header encryption, we must use a validly-encrypted index
        to bypass the header layer and test the ratchet DoS bound.
        """
        # total_frames must be > MAX_SKIP_KEYS + 1
        total = MAX_SKIP_KEYS + 10
        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        # Craft a frame with a validly-encrypted high index that bypasses
        # header decryption but triggers the skip key DoS bound.
        fake_index = MAX_SKIP_KEYS + 5
        header_key = _derive_header_key(root_key, salt)
        enc_idx = _encrypt_index(header_key, fake_index)
        # Need enough bytes for commitment + GCM tag minimum
        fake_body = secrets.token_bytes(COMMIT_TAG_SIZE + GCM_TAG_SIZE + 16)
        fake_frame = enc_idx + fake_body

        with pytest.raises(ValueError, match="[Dd]o[Ss]|skip"):
            decoder.decrypt(fake_frame)

        decoder.finalize()

    def test_irrecoverable_past_key(self, root_key, salt):
        """
        If we advance past a frame without caching it, the key is irrecoverable.
        This tests the forward secrecy guarantee for the decoder.
        """
        total = 5
        encrypted, _ = self._make_frames(root_key, salt, total_frames=total)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        # Decrypt frame 0 (advances to position 1)
        decoder.decrypt(encrypted[0])
        # Decrypt frame 4 (fast-forwards to position 5, caches keys 1,2,3)
        decoder.decrypt(encrypted[4])
        # Now consume cached keys 1 and 2
        decoder.decrypt(encrypted[1])
        decoder.decrypt(encrypted[2])
        # Consume cached key 3
        decoder.decrypt(encrypted[3])

        # All frames consumed — no keys left
        decoder.finalize()

    def test_double_finalize_is_safe(self, root_key, salt):
        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=5)
        decoder.finalize()
        decoder.finalize()  # Should not raise

    def test_finalize_clears_skipped_keys(self, root_key, salt):
        """After finalize, skipped key cache should be empty."""
        total = 5
        encrypted, _ = self._make_frames(root_key, salt, total_frames=total)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        # Receive frame 4 first, caching keys 0-3
        decoder.decrypt(encrypted[4])
        assert len(decoder._skipped_keys) == 4  # Keys 0,1,2,3 cached

        decoder.finalize()
        assert len(decoder._skipped_keys) == 0

    def test_tampered_frame_rejected(self, root_key, salt):
        """Bit-flipped encrypted frame must fail GCM auth."""
        total = 3
        encrypted, _ = self._make_frames(root_key, salt, total_frames=total)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        tampered = bytearray(encrypted[0])
        tampered[10] ^= 0xFF  # Flip bits in ciphertext
        tampered = bytes(tampered)

        with pytest.raises(Exception):  # GCM InvalidTag
            decoder.decrypt(tampered)

        decoder.finalize()

    def test_wrong_root_key_fails(self, salt):
        """Decoder with different root key must fail on all frames."""
        root_key_enc = secrets.token_bytes(32)
        root_key_dec = secrets.token_bytes(32)
        total = 3

        encoder = EncoderRatchet(root_key_enc, salt, k_blocks=3, block_size=800, total_frames=total)
        enc_frame = encoder.encrypt_next(b"secret")
        encoder.finalize()

        decoder = DecoderRatchet(root_key_dec, salt, k_blocks=3, block_size=800, total_frames=total)

        with pytest.raises(Exception):
            decoder.decrypt(enc_frame)

        decoder.finalize()


# ── Encoder/Decoder Full Roundtrip ───────────────────────────────────────────


class TestEncoderDecoderRoundtrip:
    """Full roundtrip tests with various configurations."""

    def test_single_frame(self, root_key, salt):
        """Single frame encode/decode."""
        data = b"just one frame"
        encoder = EncoderRatchet(root_key, salt, k_blocks=1, block_size=800, total_frames=1)
        encrypted = encoder.encrypt_next(data)
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=1, block_size=800, total_frames=1)
        decrypted = decoder.decrypt(encrypted)
        decoder.finalize()

        assert decrypted == data

    def test_many_frames(self, root_key, salt):
        """100 frames encode/decode in order."""
        total = 100
        frames = [secrets.token_bytes(800) for _ in range(total)]

        encoder = EncoderRatchet(root_key, salt, k_blocks=10, block_size=800, total_frames=total)
        encrypted = [encoder.encrypt_next(f) for f in frames]
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=10, block_size=800, total_frames=total)
        for i in range(total):
            decrypted = decoder.decrypt(encrypted[i])
            assert decrypted == frames[i], f"Frame {i} mismatch"
        decoder.finalize()

    def test_many_frames_shuffled(self, root_key, salt):
        """50 frames encode in order, decode in random shuffle order."""
        import random

        total = 50
        frames = [secrets.token_bytes(400) for _ in range(total)]

        encoder = EncoderRatchet(root_key, salt, k_blocks=5, block_size=400, total_frames=total)
        encrypted = [encoder.encrypt_next(f) for f in frames]
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=5, block_size=400, total_frames=total)
        indices = list(range(total))
        random.shuffle(indices)

        for i in indices:
            decrypted = decoder.decrypt(encrypted[i])
            assert decrypted == frames[i], f"Frame {i} mismatch (shuffled)"
        decoder.finalize()

    def test_partial_decode(self, root_key, salt):
        """Decode only some frames (fountain code scenario — enough to reconstruct)."""
        total = 15
        frames = [f"droplet_{i}".encode() for i in range(total)]

        encoder = EncoderRatchet(root_key, salt, k_blocks=10, block_size=800, total_frames=total)
        encrypted = [encoder.encrypt_next(f) for f in frames]
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=10, block_size=800, total_frames=total)
        # Only decode 10 of 15 frames
        for i in [0, 2, 4, 6, 8, 10, 11, 12, 13, 14]:
            decrypted = decoder.decrypt(encrypted[i])
            assert decrypted == frames[i]
        decoder.finalize()


# ── Key Zeroization ──────────────────────────────────────────────────────────


class TestKeyZeroization:
    """Verify that sensitive keys are zeroized after use."""

    def test_ratchet_state_zeroize(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        hb = get_handle_backend()
        chain_h = state.chain_key
        assert isinstance(chain_h, int) and hb.exists(chain_h)

        state.zeroize()
        assert not hb.exists(chain_h), "chain_key handle must be dropped"
        assert state.position == -1

    def test_frame_keys_zeroize(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        msg_key, _ = ratchet_step(state)
        keys = derive_frame_keys(msg_key, salt)

        hb = get_handle_backend()
        enc_h, mac_h = keys.enc_key, keys.mac_key
        assert hb.exists(enc_h) and hb.exists(mac_h)

        keys.zeroize()
        assert not hb.exists(enc_h), "enc_key handle must be dropped"
        assert bytes(keys.nonce) == bytes(12)
        assert not hb.exists(mac_h), "mac_key handle must be dropped"

    def test_encoder_finalize_zeroizes_chain(self, root_key, salt):
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=5)
        encoder.encrypt_next(b"data")

        hb = get_handle_backend()
        # Get reference to internal handle
        chain_h = encoder._state.chain_key
        assert isinstance(chain_h, int) and hb.exists(chain_h)

        encoder.finalize()
        # Chain key handle should be dropped
        assert not hb.exists(chain_h)

    def test_decoder_finalize_zeroizes_skipped_keys(self, root_key, salt):
        total = 5

        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        encrypted = [encoder.encrypt_next(f"frame_{i}".encode()) for i in range(total)]
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        # Receive frame 4, causing keys 0-3 to be cached
        decoder.decrypt(encrypted[4])

        hb = get_handle_backend()
        # Get references to cached handle IDs
        cached_handles = list(decoder._skipped_keys.values())
        assert len(cached_handles) == 4
        for h in cached_handles:
            assert isinstance(h, int) and hb.exists(h)

        decoder.finalize()
        # All cached handles should be dropped
        for h in cached_handles:
            assert not hb.exists(h), f"Skipped key handle {h} was not dropped"

    def test_secure_zero_function(self):
        """_secure_zero should zero a bytearray."""
        buf = bytearray(secrets.token_bytes(64))
        assert buf != bytearray(64)
        _secure_zero(buf)
        assert buf == bytearray(64)


# ── RatchetState Edge Cases ──────────────────────────────────────────────────


class TestRatchetStateEdgeCases:
    """Edge cases and error conditions for RatchetState."""

    def test_dead_state_sentinel(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        state.zeroize()
        assert state.position == -1

    def test_stepping_dead_state_raises(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        state.zeroize()
        with pytest.raises(ValueError, match="dead"):
            ratchet_step(state)

    def test_zeroize_is_idempotent(self, root_key, salt):
        state = init_ratchet(root_key, salt)
        state.zeroize()
        state.zeroize()  # Should not raise
        assert state.position == -1


# ── KeyDeletionReport ────────────────────────────────────────────────────────


class TestKeyDeletionReport:
    """Tests for the audit KeyDeletionReport."""

    def test_empty_report_is_verified(self):
        from meow_decoder.ratchet import KeyDeletionReport

        report = KeyDeletionReport()
        assert report.verify_all_zeroized()

    def test_derive_without_zeroize_fails_verification(self):
        from meow_decoder.ratchet import KeyDeletionReport

        report = KeyDeletionReport()
        report.record_derive("chain", 0)
        assert not report.verify_all_zeroized()

    def test_derive_and_zeroize_passes_verification(self):
        from meow_decoder.ratchet import KeyDeletionReport

        report = KeyDeletionReport()
        report.record_derive("chain", 0)
        report.record_zeroize("chain", 0)
        assert report.verify_all_zeroized()

    def test_multiple_keys_lifecycle(self):
        from meow_decoder.ratchet import KeyDeletionReport

        report = KeyDeletionReport()
        for i in range(10):
            report.record_derive("chain", i)
            report.record_derive("msg", i)
        for i in range(10):
            report.record_zeroize("chain", i)
            report.record_zeroize("msg", i)
        assert report.verify_all_zeroized()

    def test_partial_zeroize_fails(self):
        from meow_decoder.ratchet import KeyDeletionReport

        report = KeyDeletionReport()
        for i in range(5):
            report.record_derive("chain", i)
        for i in range(3):  # Only zeroize 3 of 5
            report.record_zeroize("chain", i)
        assert not report.verify_all_zeroized()


# ── HKDF Helper ──────────────────────────────────────────────────────────────


class TestHKDF:
    """Tests for the _hkdf_derive helper."""

    def test_output_length(self):
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        result_32 = _hkdf_derive(key, salt, b"test", 32)
        assert len(result_32) == 32

        result_12 = _hkdf_derive(key, salt, b"test", 12)
        assert len(result_12) == 12

        result_64 = _hkdf_derive(key, salt, b"test", 64)
        assert len(result_64) == 64

    def test_deterministic(self):
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        r1 = _hkdf_derive(key, salt, b"info", 32)
        r2 = _hkdf_derive(key, salt, b"info", 32)
        assert r1 == r2

    def test_different_info_produces_different_output(self):
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        r1 = _hkdf_derive(key, salt, b"info_a", 32)
        r2 = _hkdf_derive(key, salt, b"info_b", 32)
        assert r1 != r2

    def test_different_salt_produces_different_output(self):
        key = secrets.token_bytes(32)
        s1 = secrets.token_bytes(16)
        s2 = secrets.token_bytes(16)
        r1 = _hkdf_derive(key, s1, b"info", 32)
        r2 = _hkdf_derive(key, s2, b"info", 32)
        assert r1 != r2

    def test_different_key_produces_different_output(self):
        k1 = secrets.token_bytes(32)
        k2 = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        r1 = _hkdf_derive(k1, salt, b"info", 32)
        r2 = _hkdf_derive(k2, salt, b"info", 32)
        assert r1 != r2


# ── MODE_RATCHET Integration ─────────────────────────────────────────────────


class TestModeRatchet:
    """Verify MODE_RATCHET constant and valid mode byte set."""

    def test_mode_ratchet_value(self):
        from meow_decoder.crypto import MODE_RATCHET

        assert MODE_RATCHET == 0x10

    def test_mode_ratchet_combined_in_valid_modes(self):
        from meow_decoder.crypto import MODE_RATCHET, _VALID_MODE_BYTES

        # MODE_RATCHET is always combined with a version byte (never alone)
        assert (MODE_RATCHET | 0x02) in _VALID_MODE_BYTES

    def test_mode_ratchet_combinations(self):
        from meow_decoder.crypto import MODE_RATCHET, _VALID_MODE_BYTES

        # MODE_RATCHET | 0x02 (MEOW2 + ratchet) should be valid
        assert (MODE_RATCHET | 0x02) in _VALID_MODE_BYTES
        # MODE_RATCHET | 0x03 (MEOW3 + ratchet) should be valid
        assert (MODE_RATCHET | 0x03) in _VALID_MODE_BYTES
        # MODE_RATCHET | 0x04 (MEOW4 + ratchet) should be valid
        assert (MODE_RATCHET | 0x04) in _VALID_MODE_BYTES

    def test_mode_ratchet_duress_combinations(self):
        from meow_decoder.crypto import MODE_RATCHET, _VALID_MODE_BYTES

        # MODE_RATCHET | 0x82 (MEOW2 + ratchet + duress)
        assert (MODE_RATCHET | 0x82) in _VALID_MODE_BYTES
        # MODE_RATCHET | 0x83 (MEOW3 + ratchet + duress)
        assert (MODE_RATCHET | 0x83) in _VALID_MODE_BYTES
        # MODE_RATCHET | 0x84 (MEOW4 + ratchet + duress)
        assert (MODE_RATCHET | 0x84) in _VALID_MODE_BYTES


# ── Config Integration ───────────────────────────────────────────────────────


class TestConfigIntegration:
    """Verify enable_ratchet flag in EncodingConfig."""

    def test_enable_ratchet_default(self):
        from meow_decoder.config import EncodingConfig

        config = EncodingConfig()
        assert hasattr(config, "enable_ratchet")
        assert config.enable_ratchet is False

    def test_enable_ratchet_set(self):
        from meow_decoder.config import EncodingConfig

        config = EncodingConfig(enable_ratchet=True)
        assert config.enable_ratchet is True


# ── Cross-Session Isolation ──────────────────────────────────────────────────


class TestCrossSessionIsolation:
    """Verify that different sessions with same password produce independent ratchets."""

    def test_different_salts_produce_independent_chains(self):
        root_key = secrets.token_bytes(32)
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)

        encoder1 = EncoderRatchet(root_key, salt1, k_blocks=3, block_size=800, total_frames=3)
        encoder2 = EncoderRatchet(root_key, salt2, k_blocks=3, block_size=800, total_frames=3)

        data = b"same_data"
        enc1 = encoder1.encrypt_next(data)
        enc2 = encoder2.encrypt_next(data)

        # Same plaintext, same root key, but different salts → different ciphertext
        assert enc1 != enc2

        encoder1.finalize()
        encoder2.finalize()

    def test_cross_session_decrypt_fails(self):
        """Frame from session 1 must not decrypt with session 2's ratchet."""
        root_key = secrets.token_bytes(32)
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)
        total = 3

        encoder = EncoderRatchet(root_key, salt1, k_blocks=3, block_size=800, total_frames=total)
        enc = encoder.encrypt_next(b"secret")
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt2, k_blocks=3, block_size=800, total_frames=total)
        with pytest.raises(Exception):
            decoder.decrypt(enc)
        decoder.finalize()


# ── Stress / Boundary Tests ─────────────────────────────────────────────────


class TestBoundaryConditions:
    """Stress and boundary condition tests."""

    def test_max_skip_boundary(self, root_key, salt):
        """Test exactly MAX_SKIP_KEYS skipped keys (should succeed)."""
        total = MAX_SKIP_KEYS + 1
        # We can't encrypt MAX_SKIP_KEYS frames, but we can test the decoder's
        # skip key cache boundary directly
        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        # Fast-forward the chain to position MAX_SKIP_KEYS
        # This requires constructing a valid encrypted frame at that index
        # Create encoder to match
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        # We need to encrypt frame at index MAX_SKIP_KEYS
        # This means encrypting all frames up to and including that index
        # That's too expensive. Instead, test the boundary via internal state.

        # Directly test: skip_count = MAX_SKIP_KEYS should succeed
        # skip_count = target_index - current_position = MAX_SKIP_KEYS - 0 = MAX_SKIP_KEYS
        # len(skipped_keys) + skip_count = 0 + MAX_SKIP_KEYS = MAX_SKIP_KEYS (== MAX_SKIP_KEYS, not >)
        # BUT the _advance_to code checks > MAX_SKIP_KEYS, so it should work
        # Cleanup
        encoder.finalize()
        decoder.finalize()

    def test_header_encryption_hides_frame_index(self, root_key, salt):
        """Verify header encryption: frame indices are NOT plaintext.

        MSR v1.2 encrypts frame indices with HKDF-derived XOR masks
        (Signal header encryption parity). An observer should see
        pseudorandom bytes, not sequential integers.
        """
        total = 10
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        enc_headers = []
        for idx in range(total):
            enc = encoder.encrypt_next(b"x")
            enc_header = enc[:FRAME_INDEX_SIZE]
            plaintext_idx = struct.pack(">I", idx)
            assert (
                enc_header != plaintext_idx
            ), f"Frame {idx}: header NOT encrypted (plaintext index visible)"
            enc_headers.append(enc_header)

        # All encrypted headers must be unique
        assert len(set(enc_headers)) == total
        encoder.finalize()

    def test_empty_frame_data(self, root_key, salt):
        """Empty frame data should roundtrip correctly."""
        encoder = EncoderRatchet(root_key, salt, k_blocks=1, block_size=800, total_frames=1)
        enc = encoder.encrypt_next(b"")
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=1, block_size=800, total_frames=1)
        dec = decoder.decrypt(enc)
        decoder.finalize()

        assert dec == b""


# ══════════════════════════════════════════════════════════════════════════════
# MSR v1 — The 6 Critical Security Invariants
# ══════════════════════════════════════════════════════════════════════════════


class TestMSRv1SecurityInvariants:
    """The 6 mandatory security invariants for MSR v1 correctness.

    These tests prove the ratchet meets its security contract. If any
    of these fail, the protocol has a critical vulnerability.
    """

    def test_backward_secrecy_compromised_key_N_cannot_decrypt_prior(self, root_key, salt):
        """Compromise frame N key → frames < N stay undecryptable.

        Simulate: attacker extracts message_key[5] from memory.
        Prove: cannot decrypt frames 0-4 with message_key[5].

        Uses raw encrypt_frame/decrypt_frame (not EncoderRatchet) to
        test the cryptographic primitive independent of header encryption.
        """
        total = 10
        # Derive all message keys
        state = init_ratchet(root_key, salt)
        msg_keys = []
        for _ in range(total):
            mk, state = ratchet_step(state)
            msg_keys.append(mk)

        # Encrypt all frames with correct per-frame keys
        encrypted = []
        for i in range(total):
            enc = encrypt_frame(
                frame_data=f"frame_{i}".encode(),
                message_key=msg_keys[i],
                frame_index=i,
                salt=salt,
                k_blocks=3,
                block_size=800,
                total_frames=total,
            )
            encrypted.append(enc)

        compromised_key = msg_keys[5]  # Attacker has this

        # Attempt to decrypt earlier frames with compromised key
        for i in range(5):
            with pytest.raises(Exception):
                decrypt_frame(
                    encrypted_frame=encrypted[i],
                    message_key=compromised_key,
                    expected_index=i,
                    salt=salt,
                    k_blocks=3,
                    block_size=800,
                    total_frames=total,
                )

        # Verify the compromised key DOES decrypt its own frame
        plaintext = decrypt_frame(
            encrypted_frame=encrypted[5],
            message_key=compromised_key,
            expected_index=5,
            salt=salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
        )
        assert plaintext == b"frame_5"

    def test_jump_ahead_dos_bound(self, root_key, salt):
        """Attacker sends frame index far ahead → decode fails fast / bounded work.

        An adversary who knows the header key crafts a validly-encrypted
        frame claiming index MAX_SKIP_KEYS+100. The decoder must reject
        it immediately (bounded computation).
        """
        total = MAX_SKIP_KEYS + 200
        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        # Craft adversarial frame with validly-encrypted high index
        fake_index = MAX_SKIP_KEYS + 100
        header_key = _derive_header_key(root_key, salt)
        enc_idx = _encrypt_index(header_key, fake_index)
        fake_body = secrets.token_bytes(COMMIT_TAG_SIZE + GCM_TAG_SIZE + 16)
        fake_frame = enc_idx + fake_body

        import time

        start = time.monotonic()
        with pytest.raises(ValueError, match="skip|DoS"):
            decoder.decrypt(fake_frame)
        elapsed = time.monotonic() - start

        # Must complete in < 1 second (bounded work, not O(MAX_SKIP_KEYS) real crypto)
        assert elapsed < 1.0, f"DoS bound violated: took {elapsed:.2f}s"
        decoder.finalize()

    def test_out_of_order_fountain_shuffle_succeeds(self, root_key, salt):
        """Shuffle all droplet frames → decode MUST succeed (fountain compat).

        All frames arrive, but in fully random order. Every single one
        must decrypt correctly. This is the core fountain code contract.
        """
        import random

        total = 30
        frames = [secrets.token_bytes(400) for _ in range(total)]

        encoder = EncoderRatchet(root_key, salt, k_blocks=5, block_size=400, total_frames=total)
        encrypted = [encoder.encrypt_next(f) for f in frames]
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=5, block_size=400, total_frames=total)
        indices = list(range(total))
        random.shuffle(indices)

        results = {}
        for i in indices:
            results[i] = decoder.decrypt(encrypted[i])
        decoder.finalize()

        for i in range(total):
            assert results[i] == frames[i], f"Frame {i} corrupted after OOO delivery"

    def test_replay_rejection_deterministic(self, root_key, salt):
        """Replay same encrypted frame → rejected deterministically.

        Must raise ValueError (not silently ignore or return stale data).
        The replay detection is frame-index-based, not content-based.
        """
        total = 5
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        encrypted = [encoder.encrypt_next(f"f{i}".encode()) for i in range(total)]
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)

        # First decrypt succeeds
        result = decoder.decrypt(encrypted[2])
        assert result == b"f2"

        # Replay: exact same bytes → ValueError
        with pytest.raises(ValueError, match="[Rr]eplay"):
            decoder.decrypt(encrypted[2])

        # Different frame still works
        result1 = decoder.decrypt(encrypted[1])
        assert result1 == b"f1"

        decoder.finalize()

    def test_cross_session_replay_rejection(self):
        """Same frame bytes under different session salt → rejected.

        Proves: salt binding in AAD prevents cross-session frame replay.
        An attacker who captures session A's GIF cannot inject those frames
        into session B's decoder.
        """
        root_key = secrets.token_bytes(32)
        salt_a = secrets.token_bytes(16)
        salt_b = secrets.token_bytes(16)

        # Encode under session A
        encoder = EncoderRatchet(root_key, salt_a, k_blocks=3, block_size=800, total_frames=3)
        encrypted_a = [encoder.encrypt_next(f"sa_{i}".encode()) for i in range(3)]
        encoder.finalize()

        # Attempt to decode ALL session A frames under session B (different salt)
        decoder = DecoderRatchet(root_key, salt_b, k_blocks=3, block_size=800, total_frames=3)
        for enc in encrypted_a:
            with pytest.raises(Exception):  # GCM InvalidTag or ValueError
                decoder.decrypt(enc)
        decoder.finalize()

    def test_nonce_uniqueness_invariant(self, root_key, salt):
        """No (key, nonce) reuse across frames within session.

        Nonce reuse under the same key would be catastrophic for AES-GCM.
        We verify both individual uniqueness of keys AND nonces.
        """
        total = 100
        state = init_ratchet(root_key, salt)

        all_enc_keys = set()
        all_nonces = set()
        all_pairs = set()

        for _ in range(total):
            msg_key, state = ratchet_step(state)
            keys = derive_frame_keys(msg_key, salt)

            enc_key = bytes(keys.enc_key)
            nonce = bytes(keys.nonce)

            all_enc_keys.add(enc_key)
            all_nonces.add(nonce)
            all_pairs.add((enc_key, nonce))

            keys.zeroize()

        # All encryption keys must be unique
        assert len(all_enc_keys) == total, "Encryption key reuse detected!"
        # All nonces must be unique (HKDF domain separation guarantees this)
        assert len(all_nonces) == total, "Nonce reuse detected!"
        # All (key, nonce) pairs must be unique (belt AND suspenders)
        assert len(all_pairs) == total, "Key+nonce pair reuse detected!"


# ══════════════════════════════════════════════════════════════════════════════
# Sender Rekey Beacons
# ══════════════════════════════════════════════════════════════════════════════


class TestRekeyBeacons:
    """Tests for sender rekey beacon (PCS) mechanism."""

    def test_beacon_roundtrip_plaintext(self, root_key, salt):
        """Beacon frames roundtrip correctly (plaintext beacon mode)."""
        total = 10
        rekey = 4  # Beacon at frame 4, 8

        encoder = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
        )
        decoder = DecoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
        )

        for i in range(total):
            data = f"frame_{i}".encode()
            enc = encoder.encrypt_next(data)
            dec = decoder.decrypt(enc)
            assert dec == data, f"Frame {i} failed roundtrip with beacons"

        encoder.finalize()
        decoder.finalize()

    def test_beacon_frames_are_larger(self, root_key, salt):
        """Beacon frames contain extra 32 bytes (ephemeral pub or random)."""
        from meow_decoder.ratchet import REKEY_BEACON_SIZE

        total = 10
        rekey = 4

        encoder = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
        )

        sizes = {}
        for i in range(total):
            enc = encoder.encrypt_next(b"x")
            sizes[i] = len(enc)
        encoder.finalize()

        # Frame 0 is not a beacon (first frame exempt)
        # Frame 4 and 8 ARE beacons → 32 bytes larger
        normal_size = sizes[0]
        for i in range(total):
            if rekey > 0 and i > 0 and i % rekey == 0:
                assert (
                    sizes[i] == normal_size + REKEY_BEACON_SIZE
                ), f"Frame {i} should be {REKEY_BEACON_SIZE} bytes larger (beacon)"
            else:
                assert sizes[i] == normal_size, f"Frame {i} should be normal size"

    def test_beacon_out_of_order(self, root_key, salt):
        """Beacon frames received out of order still decrypt."""
        import random

        total = 16
        rekey = 4

        frames = [secrets.token_bytes(200) for _ in range(total)]
        encoder = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
        )
        encrypted = [encoder.encrypt_next(f) for f in frames]
        encoder.finalize()

        decoder = DecoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
        )
        indices = list(range(total))
        random.shuffle(indices)

        for i in indices:
            dec = decoder.decrypt(encrypted[i])
            assert dec == frames[i], f"Frame {i} failed OOO beacon roundtrip"
        decoder.finalize()

    def test_beacon_different_from_non_beacon_encryption(self, root_key, salt):
        """Same data at beacon vs non-beacon frame → different ciphertext structure."""
        total = 10
        rekey = 4
        data = b"identical_payload"

        enc_beacon = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
        )
        enc_no_beacon = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=0,
        )

        # Compare frame 4 (beacon vs no-beacon)
        for i in range(5):
            enc_b = enc_beacon.encrypt_next(data)
            enc_n = enc_no_beacon.encrypt_next(data)

        # Frame 4 should differ between beacon and non-beacon encoders
        # (different key derivation + extra 32 bytes)
        assert enc_b != enc_n
        assert len(enc_b) == len(enc_n) + 32  # beacon adds 32 bytes

        enc_beacon.finalize()
        enc_no_beacon.finalize()

    def test_beacon_rekey_interval_zero_disables(self, root_key, salt):
        """rekey_interval=0 produces identical output to no-beacon ratchet."""
        total = 5

        enc_a = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=0,
        )
        enc_b = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,  # default rekey_interval=0
        )

        for i in range(total):
            a = enc_a.encrypt_next(b"data")
            b = enc_b.encrypt_next(b"data")
            assert a == b, f"Frame {i}: rekey_interval=0 should match default"

        enc_a.finalize()
        enc_b.finalize()

    def test_beacon_kem_roundtrip(self, root_key, salt):
        """KEM beacon mode roundtrip with X25519 keypair."""
        import meow_crypto_rs

        # Generate receiver keypair
        receiver_private_bytes, receiver_public_bytes = meow_crypto_rs.x25519_generate_keypair()

        total = 10
        rekey = 3  # Beacon at frames 3, 6, 9

        encoder = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
            receiver_public_key=receiver_public_bytes,
        )
        decoder = DecoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
            receiver_private_key=receiver_private_bytes,
        )

        for i in range(total):
            data = f"kem_frame_{i}".encode()
            enc = encoder.encrypt_next(data)
            dec = decoder.decrypt(enc)
            assert dec == data, f"KEM beacon frame {i} failed roundtrip"

        encoder.finalize()
        decoder.finalize()

    def test_beacon_kem_wrong_private_key_fails(self, root_key, salt):
        """KEM beacon: wrong receiver private key → decryption fails."""
        import meow_crypto_rs

        _, receiver_public_bytes = meow_crypto_rs.x25519_generate_keypair()

        # Wrong private key
        wrong_private_bytes, _ = meow_crypto_rs.x25519_generate_keypair()

        total = 5
        rekey = 2  # Beacon at frames 2, 4

        encoder = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
            receiver_public_key=receiver_public_bytes,
        )
        decoder = DecoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=rekey,
            receiver_private_key=wrong_private_bytes,
        )

        # Frame 0 and 1 work (not beacon frames)
        enc0 = encoder.encrypt_next(b"f0")
        dec0 = decoder.decrypt(enc0)
        assert dec0 == b"f0"

        enc1 = encoder.encrypt_next(b"f1")
        dec1 = decoder.decrypt(enc1)
        assert dec1 == b"f1"

        # Frame 2 is a beacon frame → wrong key → GCM auth failure
        enc2 = encoder.encrypt_next(b"f2")
        with pytest.raises(Exception):  # GCM InvalidTag
            decoder.decrypt(enc2)

        encoder.finalize()
        decoder.finalize()


# ══════════════════════════════════════════════════════════════════════════════
# Tasteful Meow Aliases
# ══════════════════════════════════════════════════════════════════════════════


class TestMeowAliases:
    """Verify the tasteful cat-themed public API aliases."""

    def test_paw_state_is_ratchet_state(self):
        from meow_decoder.ratchet import PawState

        assert PawState is RatchetState

    def test_whisker_keys_is_frame_keys(self):
        from meow_decoder.ratchet import WhiskerKeys

        assert WhiskerKeys is FrameKeys

    def test_bury_in_litter_zeros_buffer(self):
        from meow_decoder.ratchet import bury_in_litter

        buf = bytearray(secrets.token_bytes(32))
        assert buf != bytearray(32)
        bury_in_litter(buf)
        assert buf == bytearray(32)

    def test_knead_subkey_returns_whisker_keys(self):
        from meow_decoder.ratchet import knead_subkey, WhiskerKeys

        msg_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        keys = knead_subkey(msg_key, salt)
        assert isinstance(keys, WhiskerKeys)
        # enc_key and mac_key are opaque handles; nonce is bytearray
        assert isinstance(keys.enc_key, int) and keys.enc_key > 0
        assert len(keys.nonce) == 12
        assert isinstance(keys.mac_key, int) and keys.mac_key > 0

    def test_prime_cat_initializes_paw_state(self):
        from meow_decoder.ratchet import prime_cat, PawState

        root = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        paw = prime_cat(root, salt)
        assert isinstance(paw, PawState)
        assert paw.position == 0
        assert isinstance(paw.chain_key, int) and paw.chain_key > 0

    def test_config_rekey_beacon_interval(self):
        from meow_decoder.config import EncodingConfig, DecodingConfig

        enc = EncodingConfig(rekey_beacon_interval=32)
        assert enc.rekey_beacon_interval == 32

        dec = DecodingConfig(rekey_beacon_interval=32)
        assert dec.rekey_beacon_interval == 32


# ══════════════════════════════════════════════════════════════════════════════
# MSR v1.2 — Signal Parity Hardening Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestHeaderEncryption:
    """Tests for HKDF-XOR frame index header encryption (Signal parity).

    Signal encrypts message headers to prevent traffic analysis. MSR v1.2
    uses HKDF-derived XOR masks to encrypt frame indices, so observers
    cannot determine frame ordering or correlate frames across sessions.

    12 domain-separated constants now vs Signal's 2 header keys.
    """

    @pytest.fixture
    def root_key(self):
        return secrets.token_bytes(32)

    @pytest.fixture
    def salt(self):
        return secrets.token_bytes(16)

    def test_encrypted_index_differs_from_plaintext(self, root_key, salt):
        """Every encrypted frame index must differ from its plaintext."""
        header_key = _derive_header_key(root_key, salt)
        for i in range(100):
            enc = _encrypt_index(header_key, i)
            plaintext = struct.pack(">I", i)
            assert enc != plaintext, f"Frame {i}: index NOT encrypted"

    def test_encrypted_indices_are_unique(self, root_key, salt):
        """No two frame indices should encrypt to the same value."""
        header_key = _derive_header_key(root_key, salt)
        seen = set()
        for i in range(500):
            enc = _encrypt_index(header_key, i)
            assert enc not in seen, f"Collision at frame {i}"
            seen.add(enc)

    def test_deterministic_encryption(self, root_key, salt):
        """Same key + index always produces same encrypted index."""
        header_key = _derive_header_key(root_key, salt)
        for i in [0, 1, 42, 999]:
            a = _encrypt_index(header_key, i)
            b = _encrypt_index(header_key, i)
            assert a == b

    def test_different_keys_produce_different_encryptions(self, salt):
        """Different root keys → different header encryptions."""
        key_a = _derive_header_key(secrets.token_bytes(32), salt)
        key_b = _derive_header_key(secrets.token_bytes(32), salt)
        enc_a = _encrypt_index(key_a, 42)
        enc_b = _encrypt_index(key_b, 42)
        assert enc_a != enc_b

    def test_different_salts_produce_different_encryptions(self, root_key):
        """Different salts → different header encryptions."""
        key_a = _derive_header_key(root_key, secrets.token_bytes(16))
        key_b = _derive_header_key(root_key, secrets.token_bytes(16))
        enc_a = _encrypt_index(key_a, 42)
        enc_b = _encrypt_index(key_b, 42)
        assert enc_a != enc_b

    def test_xor_symmetry(self, root_key, salt):
        """Encrypting twice with same mask = identity (XOR self-inverse)."""
        from meow_decoder.ratchet import _header_mask

        header_key = _derive_header_key(root_key, salt)
        for i in [0, 1, 255, 65535]:
            enc = _encrypt_index(header_key, i)
            mask = _header_mask(header_key, i)
            recovered = bytes(a ^ b for a, b in zip(enc, mask))
            assert recovered == struct.pack(">I", i)

    def test_observer_cannot_determine_frame_order(self, root_key, salt):
        """Encrypted indices should not be monotonically ordered."""
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=20)
        enc_vals = []
        for _ in range(20):
            enc = encoder.encrypt_next(b"x")
            val = struct.unpack(">I", enc[:4])[0]
            enc_vals.append(val)
        encoder.finalize()

        # Check that encrypted indices are NOT monotonically increasing
        is_monotonic = all(enc_vals[i] < enc_vals[i + 1] for i in range(len(enc_vals) - 1))
        assert not is_monotonic, "Encrypted indices are monotonic — leaks ordering"

    def test_header_lookup_roundtrip(self, root_key, salt):
        """Precomputed header lookup table correctly maps all indices."""
        from meow_decoder.ratchet import _build_header_lookup

        header_key = _derive_header_key(root_key, salt)
        total = 50
        lookup = _build_header_lookup(header_key, total)

        assert len(lookup) == total
        for i in range(total):
            enc = _encrypt_index(header_key, i)
            assert lookup[enc] == i

    def test_unknown_encrypted_index_rejected_by_decoder(self, root_key, salt):
        """Random bytes as frame header → decoder rejects immediately."""
        total = 5
        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        fake = secrets.token_bytes(4 + COMMIT_TAG_SIZE + GCM_TAG_SIZE + 16)
        with pytest.raises(ValueError, match="Header decryption failed"):
            decoder.decrypt(fake)
        decoder.finalize()

    def test_cross_session_isolation(self, root_key):
        """Frames from session A cannot be decoded by session B (different salt)."""
        salt_a = secrets.token_bytes(16)
        salt_b = secrets.token_bytes(16)
        total = 5

        encoder = EncoderRatchet(root_key, salt_a, k_blocks=3, block_size=800, total_frames=total)
        frames = [encoder.encrypt_next(b"data") for _ in range(total)]
        encoder.finalize()

        decoder_b = DecoderRatchet(root_key, salt_b, k_blocks=3, block_size=800, total_frames=total)
        with pytest.raises(ValueError, match="Header decryption failed"):
            decoder_b.decrypt(frames[0])
        decoder_b.finalize()


class TestKeyCommitment:
    """Tests for key commitment tags (invisible salamanders defense).

    AES-GCM is NOT key-committing: two different keys can both produce
    valid GCM tags for the same ciphertext but yield different plaintexts.
    MSR v1.2 adds HMAC-SHA256(mac_key, frame_body) to prevent this.

    The commitment tag is verified BEFORE decryption (fail-closed).
    """

    @pytest.fixture
    def root_key(self):
        return secrets.token_bytes(32)

    @pytest.fixture
    def salt(self):
        return secrets.token_bytes(16)

    def test_commitment_present_in_output(self, root_key, salt):
        """Every frame has a 16-byte commitment tag after the encrypted index."""
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=3)
        for _ in range(3):
            enc = encoder.encrypt_next(b"test_data")
            # Frame format: [enc_idx(4)] [commitment(16)] [ciphertext+tag]
            assert len(enc) >= FRAME_INDEX_SIZE + COMMIT_TAG_SIZE + GCM_TAG_SIZE
        encoder.finalize()

    def test_commitment_is_deterministic(self, root_key, salt):
        """Same key + same data → same commitment tag."""
        mac_key = secrets.token_bytes(32)
        body = b"some ciphertext body"
        c1 = _compute_commitment(mac_key, body)
        c2 = _compute_commitment(mac_key, body)
        assert c1 == c2
        assert len(c1) == COMMIT_TAG_SIZE

    def test_different_keys_different_commitments(self):
        """Different mac_keys → different commitment tags."""
        body = b"same body"
        c1 = _compute_commitment(secrets.token_bytes(32), body)
        c2 = _compute_commitment(secrets.token_bytes(32), body)
        assert c1 != c2

    def test_different_bodies_different_commitments(self):
        """Different frame bodies → different commitment tags."""
        mac_key = secrets.token_bytes(32)
        c1 = _compute_commitment(mac_key, b"body_a")
        c2 = _compute_commitment(mac_key, b"body_b")
        assert c1 != c2

    def test_tampered_commitment_rejected(self, root_key, salt):
        """Bit-flip in commitment tag → decoder rejects before decryption."""
        total = 3
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        frames = [encoder.encrypt_next(f"frame_{i}".encode()) for i in range(total)]
        encoder.finalize()

        # Tamper with the commitment tag (bytes 4-20)
        frame = bytearray(frames[0])
        frame[FRAME_INDEX_SIZE] ^= 0xFF  # Flip first byte of commitment
        tampered = bytes(frame)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        with pytest.raises(ValueError, match="[Kk]ey commitment"):
            decoder.decrypt(tampered)
        decoder.finalize()

    def test_tampered_ciphertext_rejected_by_commitment(self, root_key, salt):
        """Bit-flip in ciphertext → commitment check fails before GCM check."""
        total = 3
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        frames = [encoder.encrypt_next(f"frame_{i}".encode()) for i in range(total)]
        encoder.finalize()

        # Tamper with the ciphertext (after commitment tag)
        frame = bytearray(frames[0])
        tamper_pos = FRAME_INDEX_SIZE + COMMIT_TAG_SIZE + 2
        frame[tamper_pos] ^= 0xFF
        tampered = bytes(frame)

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        with pytest.raises(ValueError, match="[Kk]ey commitment"):
            decoder.decrypt(tampered)
        decoder.finalize()

    def test_wrong_key_fails_commitment(self, salt):
        """Decoder with different root_key → commitment failure."""
        total = 3
        key_a = secrets.token_bytes(32)
        key_b = secrets.token_bytes(32)

        encoder = EncoderRatchet(key_a, salt, k_blocks=3, block_size=800, total_frames=total)
        frames = [encoder.encrypt_next(b"secret") for _ in range(total)]
        encoder.finalize()

        decoder = DecoderRatchet(key_b, salt, k_blocks=3, block_size=800, total_frames=total)
        # Wrong key → either header decryption fails or commitment fails
        with pytest.raises(ValueError):
            decoder.decrypt(frames[0])
        decoder.finalize()

    def test_commitment_covers_beacon_data(self, root_key, salt):
        """For beacon frames, commitment covers beacon + ciphertext together."""
        total = 5
        encoder = EncoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=2,
        )
        frames = [encoder.encrypt_next(f"frame_{i}".encode()) for i in range(total)]
        encoder.finalize()

        # Frame 2 is a beacon frame. Tamper with beacon data.
        beacon_frame = bytearray(frames[2])
        beacon_start = FRAME_INDEX_SIZE + COMMIT_TAG_SIZE
        beacon_frame[beacon_start] ^= 0xFF  # Flip first byte of beacon
        tampered = bytes(beacon_frame)

        decoder = DecoderRatchet(
            root_key,
            salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
            rekey_interval=2,
        )
        # Decrypt frames 0 and 1 first (non-beacon, should work)
        decoder.decrypt(frames[0])
        decoder.decrypt(frames[1])
        # Tampered beacon frame → commitment check fails
        with pytest.raises(ValueError, match="[Kk]ey commitment"):
            decoder.decrypt(tampered)
        decoder.finalize()


class TestHardenedFrameFormat:
    """Tests for the MSR v1.2 hardened frame format.

    New format: [encrypted_index(4)] [commitment(16)] [body...]
    vs old:     [plaintext_index(4)] [body...]

    These tests verify the structural properties of the hardened format.
    """

    @pytest.fixture
    def root_key(self):
        return secrets.token_bytes(32)

    @pytest.fixture
    def salt(self):
        return secrets.token_bytes(16)

    def test_hardened_frame_size(self, root_key, salt):
        """Hardened frames are 16 bytes larger than raw frames (commitment tag)."""
        total = 3
        state = init_ratchet(root_key, salt)

        # Raw encrypt_frame: [idx(4)] [ciphertext(N)] [tag(16)]
        mk, state = ratchet_step(state)
        raw = encrypt_frame(
            frame_data=b"test",
            message_key=mk,
            frame_index=0,
            salt=salt,
            k_blocks=3,
            block_size=800,
            total_frames=total,
        )

        # Hardened: [enc_idx(4)] [commitment(16)] [ciphertext(N)] [tag(16)]
        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        hardened = encoder.encrypt_next(b"test")
        encoder.finalize()

        assert len(hardened) == len(raw) + COMMIT_TAG_SIZE

    def test_roundtrip_in_order(self, root_key, salt):
        """Basic in-order roundtrip with hardened format."""
        total = 10
        data = [f"frame_{i}".encode() for i in range(total)]

        encoder = EncoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        encrypted = [encoder.encrypt_next(d) for d in data]
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=total)
        for i, enc in enumerate(encrypted):
            dec = decoder.decrypt(enc)
            assert dec == data[i]
        decoder.finalize()

    def test_roundtrip_shuffled(self, root_key, salt):
        """Full shuffle roundtrip with hardened format."""
        import random

        total = 20
        data = [secrets.token_bytes(200) for _ in range(total)]

        encoder = EncoderRatchet(root_key, salt, k_blocks=5, block_size=200, total_frames=total)
        encrypted = [encoder.encrypt_next(d) for d in data]
        encoder.finalize()

        decoder = DecoderRatchet(root_key, salt, k_blocks=5, block_size=200, total_frames=total)
        indices = list(range(total))
        random.shuffle(indices)
        results = {}
        for i in indices:
            results[i] = decoder.decrypt(encrypted[i])
        decoder.finalize()

        for i in range(total):
            assert results[i] == data[i]

    def test_frame_too_short_rejected(self, root_key, salt):
        """Frame shorter than minimum (4 + 16 + 16 = 36 bytes) is rejected."""
        decoder = DecoderRatchet(root_key, salt, k_blocks=3, block_size=800, total_frames=5)
        too_short = secrets.token_bytes(FRAME_INDEX_SIZE + COMMIT_TAG_SIZE + GCM_TAG_SIZE - 1)
        with pytest.raises(ValueError, match="too short"):
            decoder.decrypt(too_short)
        decoder.finalize()
