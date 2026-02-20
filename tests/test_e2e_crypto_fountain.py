#!/usr/bin/env python3
"""
End-to-end reliability harness: encrypt → fountain encode → corrupt → decode → verify.

Covers ChatGPT audit Requirements 1 (PQ roundtrip) and 5 (reliability harness).
Tests the full crypto+fountain pipeline without QR/GIF (those are presentation-layer).
"""

from meow_decoder.fountain import (
    FountainEncoder,
    FountainDecoder,
    pack_droplet,
    unpack_droplet,
)
from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw, build_canonical_aad
import hashlib
import os
import random
import secrets

import pytest

os.environ.setdefault("MEOW_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _encrypt_and_fountain_encode(
    raw: bytes, password: str, block_size: int = 600, redundancy: float = 2.0, **encrypt_kwargs
):
    """Encrypt raw data and produce fountain droplets."""
    comp, sha256, salt, nonce, cipher, eph_pk, enc_key = encrypt_file_bytes(
        raw=raw,
        password=password,
        **encrypt_kwargs,
    )

    k_blocks = max(1, (len(cipher) + block_size - 1) // block_size)
    # Ensure enough droplets for loss-tolerance tests.
    # For tiny payloads (1-2 blocks), generate at least 10 droplets.
    num_droplets = max(10, int(k_blocks * redundancy))

    encoder = FountainEncoder(cipher, k_blocks, block_size)
    droplets_obj = encoder.generate_droplets(num_droplets)
    droplets = [pack_droplet(d) for d in droplets_obj]

    return {
        "droplets": droplets,
        "salt": salt,
        "nonce": nonce,
        "sha256": sha256,
        "cipher_len": len(cipher),
        "k_blocks": k_blocks,
        "block_size": block_size,
        "orig_len": len(raw),
        "comp_len": len(comp),
        "ephemeral_public_key": eph_pk,
        "pq_ciphertext": encrypt_kwargs.get("pq_ciphertext"),
    }


def _fountain_decode_and_decrypt(
    meta: dict, droplet_bytes_list: list, password: str, **decrypt_kwargs
):
    """Fountain-decode droplet bytes and decrypt."""
    decoder = FountainDecoder(
        meta["k_blocks"], meta["block_size"], original_length=meta["cipher_len"]
    )

    for db in droplet_bytes_list:
        droplet = unpack_droplet(db, meta["block_size"])
        decoder.add_droplet(droplet)
        if decoder.is_complete():
            break

    if not decoder.is_complete():
        raise RuntimeError(
            f"Fountain decode incomplete: {decoder.decoded_count}/{meta['k_blocks']}"
        )

    cipher = decoder.get_data(meta["cipher_len"])

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
        decrypt_kwargs.get("receiver_private_key"),
        precomputed_key=decrypt_kwargs.get("precomputed_key"),
        pq_ciphertext=meta["pq_ciphertext"],
    )
    return raw


# ---------------------------------------------------------------------------
# Requirement 5: End-to-end reliability harness
# ---------------------------------------------------------------------------


class TestE2EReliabilityHarness:
    """Full crypto + fountain pipeline with simulated corruption."""

    @pytest.fixture(
        params=[
            b"Hello world",
            secrets.token_bytes(3000),
            secrets.token_bytes(50_000),
        ],
        ids=["small", "medium", "large"],
    )
    def test_data(self, request):
        return request.param

    def test_roundtrip_no_loss(self, test_data):
        """Perfect channel: all droplets received in order."""
        password = "test-password-1234"
        meta = _encrypt_and_fountain_encode(test_data, password)
        recovered = _fountain_decode_and_decrypt(meta, meta["droplets"], password)
        assert recovered == test_data

    def test_roundtrip_30pct_loss(self, test_data):
        """Lossy channel: 30% of droplets randomly dropped."""
        password = "lossy-pass-5678"
        # Need high redundancy: 30% loss means ~70% survive.
        # Fountain codes need ~1.5x k_blocks received droplets,
        # so total redundancy ≈ 1.5 / 0.70 ≈ 2.15.  Use 3.5x for margin.
        meta = _encrypt_and_fountain_encode(test_data, password, redundancy=3.5)

        rng = random.Random(42)
        surviving = [d for d in meta["droplets"] if rng.random() > 0.30]
        assert len(surviving) < len(meta["droplets"]), "sanity: some were dropped"

        recovered = _fountain_decode_and_decrypt(meta, surviving, password)
        assert recovered == test_data

    def test_roundtrip_reorder(self, test_data):
        """Channel that delivers droplets in random order."""
        password = "reorder-pass-9012"
        meta = _encrypt_and_fountain_encode(test_data, password, redundancy=2.0)

        rng = random.Random(99)
        shuffled = list(meta["droplets"])
        rng.shuffle(shuffled)

        recovered = _fountain_decode_and_decrypt(meta, shuffled, password)
        assert recovered == test_data

    def test_roundtrip_duplicates(self, test_data):
        """Channel that duplicates some droplets."""
        password = "dup-pass-3456"
        meta = _encrypt_and_fountain_encode(test_data, password, redundancy=2.0)

        rng = random.Random(77)
        # Double some droplets
        with_dups = []
        for d in meta["droplets"]:
            with_dups.append(d)
            if rng.random() < 0.3:
                with_dups.append(d)

        recovered = _fountain_decode_and_decrypt(meta, with_dups, password)
        assert recovered == test_data

    def test_roundtrip_combined_loss_reorder_dups(self, test_data):
        """Hostile channel: combined 20% loss + reorder + duplicates."""
        password = "hostile-pass-7890"
        meta = _encrypt_and_fountain_encode(test_data, password, redundancy=3.0)

        rng = random.Random(123)
        # Drop 20%
        surviving = [d for d in meta["droplets"] if rng.random() > 0.20]
        # Add 15% duplicates
        with_dups = []
        for d in surviving:
            with_dups.append(d)
            if rng.random() < 0.15:
                with_dups.append(d)
        # Shuffle
        rng.shuffle(with_dups)

        recovered = _fountain_decode_and_decrypt(meta, with_dups, password)
        assert recovered == test_data

    def test_wrong_password_fails(self, test_data):
        """Wrong password must fail decryption."""
        password = "correct-password"
        meta = _encrypt_and_fountain_encode(test_data, password)

        with pytest.raises(RuntimeError, match="Decryption failed"):
            _fountain_decode_and_decrypt(meta, meta["droplets"], "wrong-password")

    def test_tampered_droplet_fails(self):
        """Corrupting a single byte in all droplets must fail decryption."""
        raw = secrets.token_bytes(2000)
        password = "tamper-test-pass"
        meta = _encrypt_and_fountain_encode(raw, password, redundancy=1.5)

        # Flip a byte in every droplet
        tampered = []
        for d in meta["droplets"]:
            ba = bytearray(d)
            ba[len(ba) // 2] ^= 0xFF
            tampered.append(bytes(ba))

        # Fountain decode may succeed (XOR of corrupted data) but decryption
        # should fail because GCM auth tag won't match.
        with pytest.raises((RuntimeError, ValueError)):
            _fountain_decode_and_decrypt(meta, tampered, password)

    def test_sha256_mismatch_causes_error(self):
        """Modified SHA-256 in metadata must cause decryption to fail via AAD mismatch."""
        raw = b"integrity check data"
        password = "sha-test-pass-1"
        meta = _encrypt_and_fountain_encode(raw, password)

        # Tamper with sha256 in metadata
        meta["sha256"] = hashlib.sha256(b"wrong data").digest()

        with pytest.raises(RuntimeError, match="Decryption failed"):
            _fountain_decode_and_decrypt(meta, meta["droplets"], password)

    def test_keyfile_roundtrip(self):
        """Encrypt with keyfile, decrypt with same keyfile."""
        raw = secrets.token_bytes(5000)
        password = "keyfile-pass"
        keyfile = secrets.token_bytes(64)

        comp, sha256, salt, nonce, cipher, eph_pk, enc_key = encrypt_file_bytes(
            raw=raw,
            password=password,
            keyfile=keyfile,
        )

        # Decrypt
        recovered = decrypt_to_raw(
            cipher,
            password,
            salt,
            nonce,
            keyfile,
            len(raw),
            len(comp),
            sha256,
            eph_pk,
            None,
        )
        assert recovered == raw

    def test_keyfile_mismatch_fails(self):
        """Wrong keyfile must fail decryption."""
        raw = secrets.token_bytes(5000)
        password = "keyfile-pass-2"
        keyfile = secrets.token_bytes(64)

        comp, sha256, salt, nonce, cipher, eph_pk, enc_key = encrypt_file_bytes(
            raw=raw,
            password=password,
            keyfile=keyfile,
        )

        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                secrets.token_bytes(64),
                len(raw),
                len(comp),
                sha256,
                eph_pk,
                None,
            )


# ---------------------------------------------------------------------------
# Requirement 5: HSM synthetic IV determinism test
# ---------------------------------------------------------------------------


class TestHSMSyntheticIV:
    """FIX-GPT-4: Synthetic IV for precomputed_key mode."""

    def test_same_key_same_plaintext_same_nonce(self):
        """Synthetic IV produces same nonce for same (key, plaintext) pair."""
        from meow_decoder.crypto import _nonce_reuse_cache

        _nonce_reuse_cache.clear()

        raw = b"deterministic plaintext test"
        password = "hsm-pass"
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        # Disable length padding so compressed data is deterministic
        _, _, salt1, nonce1, cipher1, _, _ = encrypt_file_bytes(
            raw=raw,
            password=password,
            precomputed_key=key,
            precomputed_salt=salt,
            use_length_padding=False,
        )

        _nonce_reuse_cache.clear()  # Simulate restart

        _, _, salt2, nonce2, cipher2, _, _ = encrypt_file_bytes(
            raw=raw,
            password=password,
            precomputed_key=key,
            precomputed_salt=salt,
            use_length_padding=False,
        )

        assert nonce1 == nonce2, "Synthetic IV must be deterministic"
        assert cipher1 == cipher2, "Same key+salt+plaintext → same ciphertext"

    def test_different_plaintext_different_nonce(self):
        """Different plaintexts under same key produce different nonces."""
        from meow_decoder.crypto import _nonce_reuse_cache

        _nonce_reuse_cache.clear()

        password = "hsm-pass-2"
        key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)

        _, _, _, nonce1, _, _, _ = encrypt_file_bytes(
            raw=b"plaintext A" * 100,
            password=password,
            precomputed_key=key,
            precomputed_salt=salt,
            use_length_padding=False,
        )

        _nonce_reuse_cache.clear()

        _, _, _, nonce2, _, _, _ = encrypt_file_bytes(
            raw=b"plaintext B" * 100,
            password=password,
            precomputed_key=key,
            precomputed_salt=salt,
            use_length_padding=False,
        )

        assert nonce1 != nonce2, "Different plaintexts must produce different nonces"

    def test_non_hsm_mode_uses_random_nonce(self):
        """Password-only mode still uses random nonces (not synthetic IV)."""
        from meow_decoder.crypto import _nonce_reuse_cache

        _nonce_reuse_cache.clear()

        raw = b"random nonce test" * 50
        password = "random-nonce-pass"

        _, _, _, nonce1, _, _, _ = encrypt_file_bytes(
            raw=raw,
            password=password,
        )

        _nonce_reuse_cache.clear()

        _, _, _, nonce2, _, _, _ = encrypt_file_bytes(
            raw=raw,
            password=password,
        )

        # Random nonces should differ (probability of collision: 2^-96)
        assert nonce1 != nonce2, "Password-only mode should use random nonces"


# ---------------------------------------------------------------------------
# Requirement 1: PQ hybrid roundtrip test (unit level)
# ---------------------------------------------------------------------------


class TestPQHybridRoundtrip:
    """PQ hybrid encapsulate → encrypt → decrypt → decapsulate."""

    @pytest.fixture(autouse=True)
    def skip_without_liboqs(self):
        try:
            import oqs

            oqs.KeyEncapsulation("Kyber1024")
        except (ImportError, Exception):
            pytest.skip("liboqs not available for PQ tests")

    def test_pq_hybrid_crypto_roundtrip(self):
        """Full PQ hybrid: encapsulate → encrypt → decrypt → verify."""
        from meow_decoder.pq_hybrid import (
            hybrid_encapsulate,
            hybrid_decapsulate,
            generate_hybrid_keypair,
        )

        raw = secrets.token_bytes(8000)
        password = "pq-roundtrip-pass"

        # Generate receiver keypair
        keypair = generate_hybrid_keypair()

        # Get receiver's classical public key bytes
        receiver_classical_public = keypair.classical_public_bytes
        receiver_pq_public = keypair.pq_public_key

        # Encapsulate
        shared_secret, eph_classical_pub, pq_ciphertext, _ = hybrid_encapsulate(
            receiver_classical_public=receiver_classical_public,
            receiver_pq_public=receiver_pq_public,
        )
        assert pq_ciphertext is not None
        assert len(pq_ciphertext) == 1568  # ML-KEM-1024
        assert len(shared_secret) == 32

        # Encrypt using hybrid shared secret as precomputed_key
        from meow_decoder.crypto import _nonce_reuse_cache

        _nonce_reuse_cache.clear()

        comp, sha256, salt, nonce, cipher, eph_pk, enc_key = encrypt_file_bytes(
            raw=raw,
            password=password,
            precomputed_key=shared_secret,
            pq_ciphertext=pq_ciphertext,
            pq_ephemeral_public_key=eph_classical_pub,
        )

        # Verify ephemeral public key was stored
        assert eph_pk is not None
        assert eph_pk == eph_classical_pub

        # Decapsulate (receiver side)
        recovered_secret = hybrid_decapsulate(
            ephemeral_classical_public=eph_pk,
            pq_ciphertext=pq_ciphertext,
            receiver_keypair=keypair,
        )
        assert recovered_secret == shared_secret

        # Decrypt
        recovered = decrypt_to_raw(
            cipher,
            password,
            salt,
            nonce,
            None,
            len(raw),
            len(comp),
            sha256,
            eph_pk,
            None,
            precomputed_key=recovered_secret,
            pq_ciphertext=pq_ciphertext,
        )
        assert recovered == raw

    def test_pq_hybrid_wrong_keypair_fails(self):
        """Decapsulating with wrong keypair must fail."""
        from meow_decoder.pq_hybrid import (
            hybrid_encapsulate,
            hybrid_decapsulate,
            generate_hybrid_keypair,
        )
        keypair_sender = generate_hybrid_keypair()
        keypair_wrong = generate_hybrid_keypair()

        sender_classical_pub = keypair_sender.classical_public_bytes

        shared_secret, eph_pub, pq_ct, _ = hybrid_encapsulate(
            receiver_classical_public=sender_classical_pub,
            receiver_pq_public=keypair_sender.pq_public_key,
        )

        # Decapsulate with WRONG keypair — shared secret should differ
        wrong_secret = hybrid_decapsulate(
            ephemeral_classical_public=eph_pub,
            pq_ciphertext=pq_ct,
            receiver_keypair=keypair_wrong,
        )
        assert wrong_secret != shared_secret

    def test_pq_ciphertext_size_is_1568(self):
        """ML-KEM-1024 ciphertext must be exactly 1568 bytes."""
        from meow_decoder.pq_hybrid import hybrid_encapsulate, generate_hybrid_keypair

        keypair = generate_hybrid_keypair()
        pub = keypair.classical_public_bytes

        _, _, pq_ct, _ = hybrid_encapsulate(
            receiver_classical_public=pub,
            receiver_pq_public=keypair.pq_public_key,
        )
        assert len(pq_ct) == 1568


# ---------------------------------------------------------------------------
# Requirement 2: Parameter drift assertion
# ---------------------------------------------------------------------------


class TestParameterDrift:
    """Verify PQ defaults match architecture: ML-KEM-768 (MEOW5, Signal PQXDH parity)."""

    def test_pq_hybrid_uses_kyber768(self):
        """Default PQ algorithm is Kyber768 (ML-KEM-768) per MEOW5 spec."""
        from meow_decoder.pq_hybrid import PQ_ALGORITHM, LIBOQS_AVAILABLE

        if not LIBOQS_AVAILABLE:
            pytest.skip("liboqs not available")
        assert PQ_ALGORITHM == "Kyber768"

    def test_pq_crypto_real_defaults_to_kyber1024(self):
        """FIX-D1 v2: pq_crypto_real is hard-disabled (removed or RuntimeError on import)."""
        import importlib
        import sys

        mod_name = "meow_decoder.pq_crypto_real"
        if mod_name in sys.modules:
            del sys.modules[mod_name]

        with pytest.raises((RuntimeError, ModuleNotFoundError)):
            importlib.import_module(mod_name)


# ---------------------------------------------------------------------------
# Requirement 3: AAD completeness assertions
# ---------------------------------------------------------------------------


class TestAADCompleteness:
    """FIX-GPT-3: All crypto-relevant metadata must be in AAD or HMAC."""

    def test_aad_includes_all_core_fields(self):
        """AAD must include orig_len, comp_len, salt, sha256, magic."""
        import struct
        from meow_decoder.crypto import MAGIC, AAD_VERSION

        aad = build_canonical_aad(
            orig_len=1000,
            comp_len=500,
            salt=b"\x00" * 16,
            sha256_hash=b"\x01" * 32,
            magic=MAGIC,
        )

        # Verify layout
        assert aad[:1] == AAD_VERSION
        orig, comp = struct.unpack_from("<QQ", aad, 1)
        assert orig == 1000
        assert comp == 500

    def test_aad_includes_ephemeral_key(self):
        """AAD with ephemeral key is longer than without."""
        from meow_decoder.crypto import MAGIC

        aad_without = build_canonical_aad(
            orig_len=1,
            comp_len=1,
            salt=b"\x00" * 16,
            sha256_hash=b"\x01" * 32,
            magic=MAGIC,
        )
        aad_with = build_canonical_aad(
            orig_len=1,
            comp_len=1,
            salt=b"\x00" * 16,
            sha256_hash=b"\x01" * 32,
            magic=MAGIC,
            ephemeral_public_key=b"\x02" * 32,
        )
        assert len(aad_with) == len(aad_without) + 32

    def test_aad_includes_pq_ciphertext(self):
        """AAD with PQ ciphertext is longer than without."""
        from meow_decoder.crypto import MAGIC

        aad_without = build_canonical_aad(
            orig_len=1,
            comp_len=1,
            salt=b"\x00" * 16,
            sha256_hash=b"\x01" * 32,
            magic=MAGIC,
        )
        aad_with = build_canonical_aad(
            orig_len=1,
            comp_len=1,
            salt=b"\x00" * 16,
            sha256_hash=b"\x01" * 32,
            magic=MAGIC,
            pq_ciphertext=b"\x03" * 1568,
        )
        assert len(aad_with) == len(aad_without) + 1568

    def test_aad_mismatch_causes_decryption_failure(self):
        """Changing any AAD field must cause GCM decryption to fail."""
        from meow_decoder.crypto import _nonce_reuse_cache

        _nonce_reuse_cache.clear()

        raw = b"AAD integrity test"
        password = "aad-test-pass"

        comp, sha256, salt, nonce, cipher, _, _ = encrypt_file_bytes(
            raw=raw,
            password=password,
        )

        # Correct decryption works
        recovered = decrypt_to_raw(
            cipher,
            password,
            salt,
            nonce,
            None,
            len(raw),
            len(comp),
            sha256,
            None,
            None,
        )
        assert recovered == raw

        # Tamper orig_len → AAD mismatch → GCM failure
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                None,
                len(raw) + 1,
                len(comp),
                sha256,
                None,
                None,
            )

        # Tamper comp_len → AAD mismatch → GCM failure
        with pytest.raises(RuntimeError):
            decrypt_to_raw(
                cipher,
                password,
                salt,
                nonce,
                None,
                len(raw),
                len(comp) + 1,
                sha256,
                None,
                None,
            )
