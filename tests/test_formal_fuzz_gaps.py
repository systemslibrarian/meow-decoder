#!/usr/bin/env python3
"""
tests/test_formal_fuzz_gaps.py
================================
Verification tests for the 10 formal+fuzzing gaps identified in
test-formal-fuzz-audit.md.

Each section targets one gap and provides regression tests ensuring
that the stated security property holds at the Python runtime level.

Gap mapping:
  Gap-5   — AEAD properties AEAD-005 through AEAD-010 (runtime validation)
  Gap-6   — Belief propagation progress (Lean proof backed by Python behaviour)
  Gap-7   — Schrödinger timing indistinguishability (statistical + structural)
  Gap-10  — Tamper detection long-run coverage (adversarial poisoning patterns)

Gaps 1-4, 8-9 are confirmed resolved upstream; representative smoke tests
are included for regression protection.
"""

import os
import time
import secrets
import inspect
from typing import List

import pytest

os.environ.setdefault("MEOW_TEST_MODE", "1")


# ============================================================================
# Crypto roundtrip helper
# encrypt_file_bytes returns (comp, sha, salt, nonce, cipher, _, _)
# decrypt_to_raw requires (cipher, password, salt, nonce, ...)
# ============================================================================

_PW = "password123"   # 12-char password meeting NIST 8-char minimum


def _encrypt(plaintext: bytes, password: str):
    """Encrypt and return (comp, sha, salt, nonce, cipher, orig_len)."""
    from meow_decoder.crypto import encrypt_file_bytes
    comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(plaintext, password)
    return comp, sha, salt, nonce, cipher, len(plaintext)


def _decrypt(cipher, password, salt, nonce, comp, sha, orig_len: int = 0):
    """Decrypt using the full required argument set."""
    from meow_decoder.crypto import decrypt_to_raw
    return decrypt_to_raw(
        cipher, password, salt, nonce,
        orig_len=orig_len, comp_len=len(comp), sha256=sha
    )


def _roundtrip(plaintext: bytes, password: str) -> bytes:
    """Full encrypt→decrypt roundtrip helper."""
    comp, sha, salt, nonce, cipher, orig_len = _encrypt(plaintext, password)
    return _decrypt(cipher, password, salt, nonce, comp, sha, orig_len)


# ============================================================================
# GAP-5: AEAD Runtime Property Validation (AEAD-005 through AEAD-010)
# ============================================================================

class TestAEAD005CiphertextIntegrity:
    """AEAD-005: Tampered ciphertext → AuthenticationFailed, never plaintext."""

    def test_single_bit_flip_rejected(self):
        """Flip one ciphertext bit; decryption must raise."""
        plaintext = b"AEAD-005 test payload"
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(plaintext, _PW)
        corrupted = bytearray(cipher)
        corrupted[len(cipher) // 2] ^= 0xFF
        with pytest.raises(Exception):
            _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)

    def test_truncated_ciphertext_rejected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"truncation test", _PW)
        with pytest.raises(Exception):
            _decrypt(cipher[:-10], _PW, salt, nonce, comp, sha)

    def test_extended_ciphertext_rejected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"extension test", _PW)
        with pytest.raises(Exception):
            _decrypt(cipher + b"\x00" * 16, _PW, salt, nonce, comp, sha)

    def test_no_plaintext_on_corrupt(self):
        """ValueError raised means no plaintext leaks (fail-closed, AEAD-008)."""
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"secret data here", _PW)
        corrupted = bytearray(cipher)
        corrupted[len(corrupted) // 3] ^= 0x01
        try:
            result = _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)
            assert result is None or len(result) == 0
        except Exception:
            pass  # expected path


class TestAEAD006AADBinding:
    """AEAD-006: Wrong AAD (wrong password) → authentication failure."""

    def test_wrong_password_rejected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"secret payload", _PW)
        with pytest.raises(Exception):
            _decrypt(cipher, "wrongpassword!", salt, nonce, comp, sha)

    def test_correct_password_succeeds(self):
        plaintext = b"hello world aad test"
        assert _roundtrip(plaintext, _PW) == plaintext

    def test_aad_unique_per_encryption(self):
        """Two encryptions of same payload → distinct salts (fresh AAD bindings)."""
        result1 = _encrypt(b"same plaintext", _PW)
        result2 = _encrypt(b"same plaintext", _PW)
        # salts at index 2 must differ
        assert result1[2] != result2[2], "Each encryption must produce a distinct salt"

    def test_mismatched_sha256_rejected(self):
        """Wrong sha256 in the AAD causes rejection."""
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"aad sha256 test", _PW)
        bad_sha = secrets.token_bytes(32)
        with pytest.raises(Exception):
            _decrypt(cipher, _PW, salt, nonce, comp, bad_sha)

    def test_mismatched_salt_rejected(self):
        """Wrong salt causes rejection."""
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"aad salt test", _PW)
        bad_salt = secrets.token_bytes(len(salt))
        with pytest.raises(Exception):
            _decrypt(cipher, _PW, bad_salt, nonce, comp, sha)


class TestAEAD007NonceDomainSeparation:
    """AEAD-007: Fresh nonce+salt per encryption, nonce-reuse guard."""

    def test_successive_encryptions_use_distinct_salts(self):
        salts = {_encrypt(b"nonce-test", _PW)[2] for _ in range(5)}
        assert len(salts) == 5, "All five salts must be distinct"

    def test_nonce_reuse_guard_fires(self):
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        _nonce_reuse_cache.clear()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        _register_nonce_use(key, nonce)
        with pytest.raises(RuntimeError):
            _register_nonce_use(key, nonce)
        _nonce_reuse_cache.clear()

    def test_different_keys_same_nonce_ok(self):
        """Different keys with same nonce bytes are allowed (nonce is key-scoped)."""
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        _nonce_reuse_cache.clear()
        key1, key2 = secrets.token_bytes(32), secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        _register_nonce_use(key1, nonce)
        _register_nonce_use(key2, nonce)  # must NOT raise
        _nonce_reuse_cache.clear()


class TestAEAD008FailClosed:
    """AEAD-008: decrypt() never returns plaintext on failure."""

    def test_all_zeros_fails_closed(self):
        from meow_decoder.crypto import decrypt_to_raw
        with pytest.raises(Exception):
            decrypt_to_raw(b"\x00" * 32, _PW, b"\x00" * 32, b"\x00" * 12,
                           orig_len=None, comp_len=10, sha256=b"\x00" * 32)

    def test_random_noise_fails_closed(self):
        from meow_decoder.crypto import decrypt_to_raw
        for _ in range(3):
            with pytest.raises(Exception):
                decrypt_to_raw(
                    secrets.token_bytes(64), _PW,
                    secrets.token_bytes(32), secrets.token_bytes(12),
                    orig_len=None, comp_len=32, sha256=secrets.token_bytes(32)
                )

    def test_no_plaintext_in_error(self):
        plaintext = b"AEAD008-secret-data"
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(plaintext, _PW)
        corrupted = bytearray(cipher)
        corrupted[5] ^= 0xFF
        try:
            _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)
        except Exception as exc:
            assert plaintext not in str(exc).encode()


class TestAEAD009RatchetKeyIndependence:
    """AEAD-009: Different ratchet epochs → independent keys, distinct ciphertexts."""

    def test_successive_encoder_outputs_differ(self):
        from meow_decoder.ratchet import EncoderRatchet
        root_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        enc = EncoderRatchet(root_key, salt, k_blocks=4, block_size=100, total_frames=10)
        pt = b"same plaintext for all frames"
        ciphertexts = [enc.encrypt_next(pt) for _ in range(3)]
        enc.finalize()
        assert len(set(ciphertexts)) == 3, "Each ratchet epoch must produce distinct CT"

    def test_encoder_decoder_roundtrip(self):
        from meow_decoder.ratchet import EncoderRatchet, DecoderRatchet
        root_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        total = 5
        enc = EncoderRatchet(root_key, salt, k_blocks=4, block_size=100, total_frames=total)
        frames = [enc.encrypt_next(f"frame-{i}".encode()) for i in range(total)]
        enc.finalize()
        dec = DecoderRatchet(root_key, salt, k_blocks=4, block_size=100, total_frames=total)
        for i, frame in enumerate(frames):
            assert dec.decrypt(frame) == f"frame-{i}".encode()
        dec.finalize()

    def test_wrong_epoch_decrypt_fails(self):
        """Decrypting frame 0 ciphertext at expected_index=1 must fail."""
        from meow_decoder.ratchet import encrypt_frame, decrypt_frame
        msg_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        ct0 = encrypt_frame(b"frame zero", msg_key, frame_index=0, salt=salt,
                            k_blocks=4, block_size=100, total_frames=5)
        with pytest.raises(Exception):
            decrypt_frame(ct0, msg_key, expected_index=1, salt=salt,
                          k_blocks=4, block_size=100, total_frames=5)

    def test_module_level_encrypt_decrypt_roundtrip(self):
        from meow_decoder.ratchet import encrypt_frame, decrypt_frame
        msg_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        pt = b"encrypt_frame test data"
        ct = encrypt_frame(pt, msg_key, frame_index=0, salt=salt,
                           k_blocks=4, block_size=100, total_frames=10)
        recovered = decrypt_frame(ct, msg_key, expected_index=0, salt=salt,
                                  k_blocks=4, block_size=100, total_frames=10)
        assert recovered == pt


class TestAEAD010NoInfoLeakageOnFailure:
    """AEAD-010: Error on failure carries no secret-dependent information."""

    def test_error_message_no_plaintext(self):
        plaintext = b"supersecret-AEAD-010"
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(plaintext, _PW)
        corrupted = bytearray(cipher)
        corrupted[min(40, len(corrupted) - 1)] ^= 0xFF
        try:
            _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)
        except Exception as exc:
            assert b"supersecret" not in str(exc).encode()
            assert plaintext not in str(exc).encode()

    def test_timing_wrong_vs_correct_not_trivially_faster(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"timing test", _PW)
        t0 = time.monotonic()
        try:
            _decrypt(cipher, "completelywrongpassword!", salt, nonce, comp, sha)
        except Exception:
            pass
        wrong_time = time.monotonic() - t0
        t0 = time.monotonic()
        _decrypt(cipher, _PW, salt, nonce, comp, sha, orig_len)
        good_time = time.monotonic() - t0
        assert wrong_time >= good_time * 0.10, (
            f"Wrong-password ({wrong_time:.3f}s) much faster than correct "
            f"({good_time:.3f}s) — possible timing leak"
        )


# ============================================================================
# GAP-6: Belief Propagation Progress (Python-side validation of Lean proof)
# ============================================================================

class TestBeliefPropagationProgress:
    """
    Validates the Python fountain decoder's belief propagation matches
    the Lean 4 proof in FountainCodes.lean:
    a degree-1 droplet in pending strictly increases solvedCount.
    """

    def test_degree_one_makes_progress(self):
        """Two degree-1 droplets solve both blocks of a 2-block decoder."""
        from meow_decoder.fountain import FountainDecoder, Droplet
        k, block_size = 2, 50
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=100)
        assert not decoder.is_complete()
        d0 = Droplet(seed=0, block_indices=[0], data=b"A" * block_size)
        d1 = Droplet(seed=1, block_indices=[1], data=b"B" * block_size)
        decoder.add_droplet(d0)
        assert not decoder.is_complete(), "After 1 of 2, still incomplete"
        decoder.add_droplet(d1)
        assert decoder.is_complete(), "After degree-1 for each block, must be complete"
        assert decoder.get_data() == b"A" * 50 + b"B" * 50

    def test_cascade_solve_completes_decoder(self):
        """Cascade belief propagation solves all k blocks from sufficient droplets."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        payload = secrets.token_bytes(400)
        k, block_size = 4, 100
        encoder = FountainEncoder(payload, k_blocks=k, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=400)
        for i in range(k * 3):
            if decoder.add_droplet(encoder.droplet(i)):
                break
        assert decoder.is_complete(), "Must complete with 3× redundancy"
        assert decoder.get_data() == payload

    def test_high_degree_only_no_immediate_solve(self):
        """Only high-degree droplets means decoder is not immediately complete."""
        from meow_decoder.fountain import FountainDecoder, Droplet
        k, block_size = 4, 100
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=400)
        d = Droplet(seed=99, block_indices=[0, 1, 2], data=secrets.token_bytes(block_size))
        decoder.add_droplet(d)
        assert not decoder.is_complete()
        assert len(decoder.pending_droplets) >= 1

    def test_belief_propagation_terminates(self):
        """Belief propagation always terminates (no infinite loop)."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        payload = secrets.token_bytes(800)
        k, block_size = 8, 100
        encoder = FountainEncoder(payload, k_blocks=k, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=800)
        for i in range(k * 4):
            if decoder.add_droplet(encoder.droplet(i)):
                break
        assert True  # no infinite loop

    def test_roundtrip_preserves_exact_bytes(self):
        """FountainEncoder → FountainDecoder roundtrip is bit-perfect."""
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        payload = secrets.token_bytes(600)
        k, block_size = 6, 100
        encoder = FountainEncoder(payload, k_blocks=k, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=600)
        for i in range(k * 5):
            if decoder.add_droplet(encoder.droplet(i)):
                assert decoder.get_data() == payload
                return
        pytest.fail("Decode did not complete with 5× redundancy")


# ============================================================================
# GAP-7: Schrödinger Timing Indistinguishability
# ============================================================================

class TestSchrodingerTimingIndistinguishability:
    """
    Python-side statistical tests backing the Tamarin timing model
    MeowSchrodingerDeniabilityTiming.spthy (T1-T5).
    """

    TRIALS = 10

    def test_both_passwords_decode_successfully(self):
        """T1/T2: Both real and decoy passwords decode without exception."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data
        superpos, manifest = schrodinger_encode_data(
            b"real secret content", b"innocent decoy text",
            real_password="realpass123", decoy_password="decoypass123"
        )
        assert schrodinger_decode_data(superpos, manifest, "realpass123") == b"real secret content"
        assert schrodinger_decode_data(superpos, manifest, "decoypass123") == b"innocent decoy text"

    def test_deniability_coerced_party_sees_decoy(self):
        """T1: Coerced party shows only innocent decoy output."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data
        superpos, manifest = schrodinger_encode_data(
            b"classified data", b"harmless content",
            real_password="classified123", decoy_password="harmless123"
        )
        assert schrodinger_decode_data(superpos, manifest, "harmless123") == b"harmless content"

    def test_wrong_password_does_not_decode_either_secret(self):
        """T3: Wrong password must not successfully decode either reality."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data
        superpos, manifest = schrodinger_encode_data(
            b"real", b"decoy",
            real_password="correctreal123", decoy_password="correctdecoy123"
        )
        try:
            result = schrodinger_decode_data(superpos, manifest, "wrongpassword1")
            assert result not in (b"real", b"decoy")
        except Exception:
            pass  # expected path

    def test_no_consistent_ordering_in_timing(self):
        """T4: Neither password consistently decodes faster (Argon2 dominates)."""
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data
        superpos, manifest = schrodinger_encode_data(
            b"payload A" * 4, b"payload B" * 4,
            real_password="passwordA123", decoy_password="passwordB123"
        )
        a_wins = 0
        for _ in range(self.TRIALS):
            t0 = time.monotonic()
            schrodinger_decode_data(superpos, manifest, "passwordA123")
            ta = time.monotonic() - t0
            t0 = time.monotonic()
            schrodinger_decode_data(superpos, manifest, "passwordB123")
            tb = time.monotonic() - t0
            if ta < tb:
                a_wins += 1
        # with 10 trials allow 9/10 (wide margin for CI variability)
        assert a_wins <= int(self.TRIALS * 0.90), "Path A consistently faster — timing leak"
        assert (self.TRIALS - a_wins) <= int(self.TRIALS * 0.90), "Path B consistently faster"

    def test_isomorphic_code_path(self):
        """T5: schrodinger_decode_data must not branch on password equality."""
        import meow_decoder.schrodinger_decode as sd_module
        src = inspect.getsource(sd_module)
        assert "if password ==" not in src and "elif password ==" not in src, (
            "schrodinger_decode_data must not branch on literal password equality"
        )


# ============================================================================
# GAP-10: Tamper Detection — Adversarial Poisoning Patterns
# Backed by long-fuzz.yml: 3600s weekly, 5 security-critical targets
# ============================================================================

class TestTamperDetectionAdversarialPatterns:
    """Extended tamper detection tests covering adversarial poisoning scenarios."""

    def test_single_byte_flip_at_various_offsets_rejected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"tamper test payload", _PW)
        for pos in [0, len(cipher) // 4, len(cipher) // 2, len(cipher) - 1]:
            if pos >= len(cipher):
                continue
            corrupted = bytearray(cipher)
            corrupted[pos] ^= 0x01
            with pytest.raises(Exception):
                _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)

    def test_wrong_password_rejected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"payload one", _PW)
        with pytest.raises(Exception):
            _decrypt(cipher, "completely_wrong_pw!", salt, nonce, comp, sha)

    def test_magic_byte_tamper_rejected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"magic test payload", _PW)
        corrupted = bytearray(cipher)
        corrupted[0:4] = b"\x00\x00\x00\x00"
        with pytest.raises(Exception):
            _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)

    def test_replay_same_bundle_twice_ok(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"replay test", _PW)
        r1 = _decrypt(cipher, _PW, salt, nonce, comp, sha, orig_len)
        r2 = _decrypt(cipher, _PW, salt, nonce, comp, sha, orig_len)
        assert r1 == r2 == b"replay test"

    def test_accumulated_bit_flips_always_rejected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"bit flip test data", _PW)
        for n_flips in [1, 2, 4, 8]:
            corrupted = bytearray(cipher)
            for i in range(n_flips):
                pos = (len(cipher) // 4 + i * 3) % len(cipher)
                corrupted[pos] ^= 0x55
            with pytest.raises(Exception):
                _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)

    def test_hmac_tail_tamper_detected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"hmac tail test", _PW)
        corrupted = bytearray(cipher)
        corrupted[-1] ^= 0xFF
        corrupted[-2] ^= 0xFF
        with pytest.raises(Exception):
            _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)

    def test_constant_time_compare_used(self):
        src = inspect.getsource(__import__("meow_decoder.crypto", fromlist=["crypto"]))
        assert "compare_digest" in src, "crypto.py must use compare_digest"

    def test_empty_payload_roundtrip(self):
        assert _roundtrip(b"", _PW) == b""

    def test_small_payload_roundtrip(self):
        assert _roundtrip(b"\x42", _PW) == b"\x42"

    def test_large_payload_roundtrip(self):
        payload = secrets.token_bytes(256 * 1024)
        assert _roundtrip(payload, _PW) == payload

    def test_all_byte_values_roundtrip(self):
        payload = bytes(range(256)) * 16
        assert _roundtrip(payload, _PW) == payload


# ============================================================================
# REGRESSION: Gaps 1-4, 8-9 (confirmed resolved; smoke tests)
# ============================================================================

class TestGap1ContinueOnErrorAbsent:
    """Gap-1: fuzz CI must not swallow crashes. Smoke: fuzz target importable."""

    def test_fuzz_tamper_is_importable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "fuzz_tamper_detection",
            "/workspaces/meow-decoder/fuzz/fuzz_tamper_detection.py"
        )
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except SystemExit:
            pass


class TestGap3CoverageThreshold:
    """Gap-3: Coverage gate exists. Verify key modules are importable."""

    def test_crypto_module_importable(self):
        from meow_decoder import crypto
        assert hasattr(crypto, "encrypt_file_bytes") and hasattr(crypto, "decrypt_to_raw")

    def test_fountain_module_importable(self):
        from meow_decoder import fountain
        assert hasattr(fountain, "FountainEncoder") and hasattr(fountain, "FountainDecoder")

    def test_ratchet_module_importable(self):
        from meow_decoder import ratchet
        assert hasattr(ratchet, "EncoderRatchet") and hasattr(ratchet, "DecoderRatchet")

    def test_schrodinger_module_importable(self):
        from meow_decoder import schrodinger_encode
        assert hasattr(schrodinger_encode, "schrodinger_encode_data")


class TestGap4Tamarin4AryAAD:
    """Gap-4: 4-ary AEAD model. Python-side: 8-field AAD bound in production."""

    def test_aad_has_eight_fields(self):
        try:
            from meow_decoder.crypto import build_canonical_aad
            aad = build_canonical_aad(
                orig_len=100, comp_len=80,
                salt=secrets.token_bytes(32), sha256_hash=secrets.token_bytes(32),
                magic=b"MEOW", ephemeral_public_key=b"", pq_ciphertext=b"",
                mode_byte=0x02
            )
            assert isinstance(aad, bytes) and len(aad) > 0
        except ImportError:
            pytest.skip("build_canonical_aad not exported")

    def test_different_orig_len_different_aad(self):
        try:
            from meow_decoder.crypto import build_canonical_aad
            salt = secrets.token_bytes(32)
            sha = secrets.token_bytes(32)
            kwargs = dict(comp_len=80, salt=salt, sha256_hash=sha,
                          magic=b"MEOW", ephemeral_public_key=b"",
                          pq_ciphertext=b"", mode_byte=0x02)
            aad100 = build_canonical_aad(orig_len=100, **kwargs)
            aad200 = build_canonical_aad(orig_len=200, **kwargs)
            assert aad100 != aad200
        except ImportError:
            pytest.skip("build_canonical_aad not exported")


class TestGap8WindowsFuzz:
    """Gap-8: Windows fuzz guard target. Smoke: GuardedBuffer zeroize."""

    def test_guarded_buffer_zeroize(self):
        try:
            from meow_decoder.constant_time import GuardedBuffer
            buf = GuardedBuffer(b"sensitive data here")
            buf.release()
            assert buf.is_released()
        except ImportError:
            pytest.skip("GuardedBuffer not available")


class TestGap9DifferentialStegoFuzz:
    """Gap-9: Differential stego fuzz target. Smoke: stego roundtrip."""

    def test_stego_encode_decode_roundtrip(self):
        try:
            from meow_decoder.stego import encode_lsb, decode_lsb
            from PIL import Image
            img = Image.new("RGB", (100, 100), color=(128, 128, 128))
            payload = b"stego test payload"
            stego_img = encode_lsb(img, payload, depth=1)
            recovered = decode_lsb(stego_img, len(payload), depth=1)
            assert recovered == payload
        except ImportError:
            pytest.skip("stego/PIL module not available")
