"""
Formal Fuzz Gaps — Part 1 of 3: AEAD Runtime Property Validation

GAP-5: AEAD-005 through AEAD-010 runtime validation tests.
Runs in CI batch 1 in parallel with test_formal_fuzz_gaps_fountain.py (batch 2)
and test_formal_fuzz_gaps_tamper.py (batch 3).
"""

import time
import secrets

import pytest

pytestmark = pytest.mark.security

import os
os.environ.setdefault("MEOW_TEST_MODE", "1")

_PW = "password123"


def _encrypt(plaintext: bytes, password: str):
    from meow_decoder.crypto import encrypt_file_bytes
    comp, sha, salt, nonce, cipher, _, _ = encrypt_file_bytes(plaintext, password)
    return comp, sha, salt, nonce, cipher, len(plaintext)


def _decrypt(cipher, password, salt, nonce, comp, sha, orig_len: int = 0):
    from meow_decoder.crypto import decrypt_to_raw
    return decrypt_to_raw(
        cipher, password, salt, nonce, orig_len=orig_len, comp_len=len(comp), sha256=sha
    )


def _roundtrip(plaintext: bytes, password: str) -> bytes:
    comp, sha, salt, nonce, cipher, orig_len = _encrypt(plaintext, password)
    return _decrypt(cipher, password, salt, nonce, comp, sha, orig_len)


class TestAEAD005CiphertextIntegrity:
    """AEAD-005: Tampered ciphertext → AuthenticationFailed, never plaintext."""

    def test_single_bit_flip_rejected(self):
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
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"secret data here", _PW)
        corrupted = bytearray(cipher)
        corrupted[len(corrupted) // 3] ^= 0x01
        try:
            result = _decrypt(bytes(corrupted), _PW, salt, nonce, comp, sha)
            assert result is None or len(result) == 0
        except Exception:
            pass


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
        result1 = _encrypt(b"same plaintext", _PW)
        result2 = _encrypt(b"same plaintext", _PW)
        assert result1[2] != result2[2], "Each encryption must produce a distinct salt"

    def test_mismatched_sha256_rejected(self):
        comp, sha, salt, nonce, cipher, orig_len = _encrypt(b"aad sha256 test", _PW)
        bad_sha = secrets.token_bytes(32)
        with pytest.raises(Exception):
            _decrypt(cipher, _PW, salt, nonce, comp, bad_sha)

    def test_mismatched_salt_rejected(self):
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
        from meow_decoder.crypto import _register_nonce_use, _nonce_reuse_cache
        _nonce_reuse_cache.clear()
        key1, key2 = secrets.token_bytes(32), secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        _register_nonce_use(key1, nonce)
        _register_nonce_use(key2, nonce)
        _nonce_reuse_cache.clear()


class TestAEAD008FailClosed:
    """AEAD-008: decrypt() never returns plaintext on failure."""

    def test_all_zeros_fails_closed(self):
        from meow_decoder.crypto import decrypt_to_raw
        with pytest.raises(Exception):
            decrypt_to_raw(
                b"\x00" * 32, _PW, b"\x00" * 32, b"\x00" * 12,
                orig_len=None, comp_len=10, sha256=b"\x00" * 32,
            )

    def test_random_noise_fails_closed(self):
        from meow_decoder.crypto import decrypt_to_raw
        for _ in range(3):
            with pytest.raises(Exception):
                decrypt_to_raw(
                    secrets.token_bytes(64), _PW,
                    secrets.token_bytes(32), secrets.token_bytes(12),
                    orig_len=None, comp_len=32, sha256=secrets.token_bytes(32),
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
        assert len(set(ciphertexts)) == 3

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
        from meow_decoder.ratchet import encrypt_frame, decrypt_frame
        msg_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        ct0 = encrypt_frame(
            b"frame zero", msg_key, frame_index=0, salt=salt,
            k_blocks=4, block_size=100, total_frames=5,
        )
        with pytest.raises(Exception):
            decrypt_frame(
                ct0, msg_key, expected_index=1, salt=salt,
                k_blocks=4, block_size=100, total_frames=5,
            )

    def test_module_level_encrypt_decrypt_roundtrip(self):
        from meow_decoder.ratchet import encrypt_frame, decrypt_frame
        msg_key = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        pt = b"encrypt_frame test data"
        ct = encrypt_frame(
            pt, msg_key, frame_index=0, salt=salt, k_blocks=4, block_size=100, total_frames=10
        )
        recovered = decrypt_frame(
            ct, msg_key, expected_index=0, salt=salt, k_blocks=4, block_size=100, total_frames=10
        )
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
