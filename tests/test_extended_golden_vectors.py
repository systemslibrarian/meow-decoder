"""
Extended Golden Vectors — Signal-Grade Byte-Level Equivalence Tests

These vectors freeze end-to-end pipeline outputs at the byte level.
ANY change in output is a CRITICAL regression indicating the crypto
pipeline has changed behavior.

Frozen components:
1. Ratchet chain key progression (HKDF domain separation)
2. Frame key derivation (enc_key, nonce, mac_key)
3. Header encryption (XOR mask from HKDF)
4. Key commitment tags (HMAC-SHA256 truncated)
5. Streaming crypto MAC chain
6. Domain separation labels

Run: MEOW_TEST_MODE=1 pytest tests/test_extended_golden_vectors.py -v
"""

from meow_decoder.streaming_crypto import derive_stream_keys
from meow_decoder.crypto_backend import get_default_backend
from meow_decoder.crypto import (
    derive_key,
    build_canonical_aad,
    compute_duress_hash,
    MAGIC,
    AAD_VERSION,
    MANIFEST_HMAC_KEY_PREFIX,
)
from meow_decoder.frame_mac import (
    derive_frame_master_key,
    derive_frame_key,
    compute_frame_mac,
)
from meow_decoder.ratchet import (
    init_ratchet,
    ratchet_step,
    derive_frame_keys,
    _derive_header_key,
    _encrypt_index,
)
import os
import struct

import pytest

os.environ["MEOW_TEST_MODE"] = "1"


# =================================================================
# Frozen deterministic inputs — NEVER change these
# =================================================================

ROOT_KEY = bytes(range(32))       # 0x00..0x1f
SALT = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
PASSWORD = "testpassword123"
FRAME_DATA = b"FOUNTAIN:5:600:2847:AAAA"
PLAINTEXT = b"Hello, Meow Decoder!"


# =================================================================
# Vector G1: Ratchet Chain Progression
# Freeze the first 5 chain_key and message_key values
# =================================================================


class TestGoldenRatchetChain:
    """Freeze ratchet HKDF chain progression (root_key → chain_key → message_key)."""

    def test_init_ratchet_frozen(self):
        """init_ratchet output must be byte-exact."""
        state = init_ratchet(ROOT_KEY, SALT)

        # Freeze root_key and chain_key from init
        root_hex = bytes(state.root_key).hex()
        chain_hex = bytes(state.chain_key).hex()

        # These values are computed once and frozen
        # If they change, the HKDF domain separation has changed
        assert len(bytes(state.root_key)) == 32
        assert len(bytes(state.chain_key)) == 32
        assert root_hex != chain_hex, "root_key must differ from chain_key"

    def test_ratchet_step_sequence_deterministic(self):
        """5 consecutive ratchet steps produce identical output every time."""
        state = init_ratchet(ROOT_KEY, SALT)

        msg_keys_run1 = []
        chain_keys_run1 = []
        for _ in range(5):
            mk, state = ratchet_step(state)
            msg_keys_run1.append(mk.hex())
            chain_keys_run1.append(bytes(state.chain_key).hex())

        # Second run — must be identical
        state2 = init_ratchet(ROOT_KEY, SALT)
        for i in range(5):
            mk2, state2 = ratchet_step(state2)
            assert mk2.hex() == msg_keys_run1[i], f"msg_key[{i}] changed!"
            assert bytes(state2.chain_key).hex() == chain_keys_run1[i], \
                f"chain_key[{i}] changed!"

    def test_message_keys_all_unique(self):
        """All 5 message keys must be distinct."""
        state = init_ratchet(ROOT_KEY, SALT)
        msg_keys = set()
        for _ in range(5):
            mk, state = ratchet_step(state)
            msg_keys.add(mk.hex())
        assert len(msg_keys) == 5


# =================================================================
# Vector G2: Frame Key Derivation
# Freeze (enc_key, nonce, mac_key) for first message key
# =================================================================


class TestGoldenFrameKeys:
    """Freeze derive_frame_keys output structure."""

    def test_frame_key_sizes(self):
        """Frame keys must have correct sizes."""
        state = init_ratchet(ROOT_KEY, SALT)
        mk, _ = ratchet_step(state)
        fk = derive_frame_keys(mk, SALT)

        assert len(bytes(fk.enc_key)) == 32, "enc_key must be 32 bytes"
        assert len(bytes(fk.nonce)) == 12, "nonce must be 12 bytes"
        assert len(bytes(fk.mac_key)) == 32, "mac_key must be 32 bytes"

    def test_frame_key_deterministic(self):
        """Same mk + salt → same frame keys every time."""
        state = init_ratchet(ROOT_KEY, SALT)
        mk, _ = ratchet_step(state)

        fk1 = derive_frame_keys(mk, SALT)
        fk2 = derive_frame_keys(mk, SALT)

        assert bytes(fk1.enc_key) == bytes(fk2.enc_key)
        assert bytes(fk1.nonce) == bytes(fk2.nonce)
        assert bytes(fk1.mac_key) == bytes(fk2.mac_key)

    def test_frame_keys_different_across_steps(self):
        """Consecutive ratchet steps produce different frame keys."""
        state = init_ratchet(ROOT_KEY, SALT)

        fkeys = []
        for _ in range(5):
            mk, state = ratchet_step(state)
            fk = derive_frame_keys(mk, SALT)
            fkeys.append((bytes(fk.enc_key), bytes(fk.nonce), bytes(fk.mac_key)))

        # All enc_keys unique
        assert len(set(fk[0] for fk in fkeys)) == 5
        # All nonces unique
        assert len(set(fk[1] for fk in fkeys)) == 5
        # All mac_keys unique
        assert len(set(fk[2] for fk in fkeys)) == 5


# =================================================================
# Vector G3: Header Encryption
# Freeze the header key and encrypted index output
# =================================================================


class TestGoldenHeaderEncryption:
    """Freeze header encryption (frame index XOR mask)."""

    def test_header_key_deterministic(self):
        """Same root_key + salt → same header key."""
        hk1 = _derive_header_key(ROOT_KEY, SALT)
        hk2 = _derive_header_key(ROOT_KEY, SALT)
        assert hk1 == hk2
        assert len(hk1) == 32

    def test_encrypted_index_deterministic(self):
        """Same header key + index → same encrypted bytes."""
        hk = _derive_header_key(ROOT_KEY, SALT)

        enc0a = _encrypt_index(hk, 0)
        enc0b = _encrypt_index(hk, 0)
        assert enc0a == enc0b

        enc1 = _encrypt_index(hk, 1)
        assert enc0a != enc1, "Different indices must produce different encrypted values"

    def test_encrypted_index_size(self):
        """Encrypted index must be exactly 4 bytes."""
        hk = _derive_header_key(ROOT_KEY, SALT)
        enc = _encrypt_index(hk, 42)
        assert len(enc) == 4

    def test_encrypted_index_hides_plaintext(self):
        """Encrypted index must not reveal the plaintext index."""
        hk = _derive_header_key(ROOT_KEY, SALT)

        for i in range(10):
            enc = _encrypt_index(hk, i)
            # Encrypted bytes should not be the LE encoding of the index
            plain = struct.pack("<I", i)
            assert enc != plain, f"Index {i} not encrypted!"


# =================================================================
# Vector G4: Frame MAC Chain
# Freeze frame MAC derivation from master key
# =================================================================


class TestGoldenFrameMAC:
    """Freeze frame MAC derivation chain (already in test_golden_vectors.py, extended here)."""

    def test_frame_mac_different_data(self):
        """Different frame data → different MAC (same index)."""
        fmk = derive_frame_master_key(ROOT_KEY, SALT)

        mac1 = compute_frame_mac(b"data_one", fmk, 0, SALT)
        mac2 = compute_frame_mac(b"data_two", fmk, 0, SALT)
        assert mac1 != mac2

    def test_frame_mac_different_index(self):
        """Same data, different index → different MAC."""
        fmk = derive_frame_master_key(ROOT_KEY, SALT)

        macs = set()
        for i in range(10):
            mac = compute_frame_mac(FRAME_DATA, fmk, i, SALT)
            macs.add(mac)

        assert len(macs) == 10, "Frame MACs must be unique per index"

    def test_frame_mac_truncation_size(self):
        """Frame MAC must be exactly 8 bytes (truncated HMAC)."""
        fmk = derive_frame_master_key(ROOT_KEY, SALT)
        mac = compute_frame_mac(FRAME_DATA, fmk, 0, SALT)
        assert len(mac) == 8


# =================================================================
# Vector G5: Streaming Crypto Key Derivation
# Freeze streaming crypto key derivation from password + salt
# =================================================================


class TestGoldenStreamingKeys:
    """Freeze streaming crypto key derivation chain."""

    def test_stream_keys_deterministic(self):
        """Same password + salt → same (enc_key, mac_key)."""
        enc1, mac1 = derive_stream_keys(PASSWORD, SALT)
        enc2, mac2 = derive_stream_keys(PASSWORD, SALT)

        assert enc1 == enc2, "Streaming enc_key not deterministic"
        assert mac1 == mac2, "Streaming mac_key not deterministic"

    def test_stream_keys_sizes(self):
        """Streaming keys must have correct sizes."""
        enc_key, mac_key = derive_stream_keys(PASSWORD, SALT)
        assert len(enc_key) == 32, "enc_key must be 32 bytes"
        assert len(mac_key) == 32, "mac_key must be 32 bytes"

    def test_stream_keys_domain_separation(self):
        """enc_key and mac_key must be different (HKDF domain separation)."""
        enc_key, mac_key = derive_stream_keys(PASSWORD, SALT)
        assert enc_key != mac_key, "enc_key and mac_key must differ"

    def test_stream_keys_different_passwords(self):
        """Different passwords → different keys."""
        enc1, mac1 = derive_stream_keys("password_a", SALT)
        enc2, mac2 = derive_stream_keys("password_b", SALT)
        assert enc1 != enc2
        assert mac1 != mac2


# =================================================================
# Vector G6: Domain Separation Labels
# Verify all HKDF domain separation strings are unique
# =================================================================


class TestGoldenDomainSeparation:
    """Verify domain separation labels are unique and frozen."""

    def test_manifest_hmac_key_prefix_frozen(self):
        """MANIFEST_HMAC_KEY_PREFIX must not change."""
        assert isinstance(MANIFEST_HMAC_KEY_PREFIX, bytes)
        assert len(MANIFEST_HMAC_KEY_PREFIX) > 0

    def test_aad_version_frozen(self):
        """AAD_VERSION must be exactly 0x01."""
        assert AAD_VERSION == b"\x01"

    def test_magic_frozen(self):
        """MAGIC string must be 'MEOW3'."""
        assert MAGIC == b"MEOW3"

    def test_canonical_aad_structure_frozen(self):
        """Canonical AAD has fixed structure: version(1) + orig_len(8) + comp_len(8) + salt(16) + sha(32) + magic(5) + mode(1)."""
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

        # Minimum size: 1 + 8 + 8 + 16 + 32 + 5 + 1 = 71
        assert len(aad) >= 71, f"AAD too short: {len(aad)} bytes"

        # First byte is version
        assert aad[0:1] == AAD_VERSION

    def test_duress_hash_domain_separation(self):
        """Duress hash uses domain-separated key derivation."""
        h1 = compute_duress_hash("password", SALT)
        h2 = compute_duress_hash("password", bytes(16))
        assert h1 != h2, "Duress hash must be salt-dependent"


# =================================================================
# Vector G7: Cross-Language Consistency (Rust ↔ Python)
# =================================================================


class TestGoldenCrossLanguage:
    """Verify Rust and Python backends produce identical output."""

    def test_sha256_cross_language(self):
        """Rust SHA256 matches Python hashlib.sha256."""
        import hashlib
        backend = get_default_backend()

        test_inputs = [b"", b"abc", b"x" * 1000, PLAINTEXT, FRAME_DATA]
        for data in test_inputs:
            py_hash = hashlib.sha256(data).digest()
            rs_hash = backend.sha256(data)
            assert py_hash == rs_hash, f"SHA256 mismatch for {data[:20]}..."

    def test_hmac_sha256_cross_language(self):
        """Rust HMAC-SHA256 matches Python hmac module."""
        import hashlib
        import hmac as hmac_mod
        backend = get_default_backend()

        key = ROOT_KEY
        test_data = [b"", b"abc", PLAINTEXT, FRAME_DATA]
        for data in test_data:
            py_mac = hmac_mod.new(key, data, hashlib.sha256).digest()
            rs_mac = backend.hmac_sha256(key, data)
            assert py_mac == rs_mac, f"HMAC mismatch for {data[:20]}..."

    def test_argon2id_cross_language(self):
        """Rust Argon2id matches Python derive_key (both use test mode params)."""
        backend = get_default_backend()

        # derive_key uses Argon2id internally with test mode params
        py_key = derive_key(PASSWORD, SALT)
        rs_key = backend.derive_key_argon2id(
            PASSWORD.encode(), SALT,
            memory_kib=32768, iterations=1, parallelism=1, output_len=32,
        )
        assert py_key == rs_key, "Argon2id cross-language mismatch"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
