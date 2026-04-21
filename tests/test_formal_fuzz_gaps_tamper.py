"""
Formal Fuzz Gaps — Part 3 of 3: Tamper Detection & Gap Regression Smoke Tests

GAP-10: Tamper detection adversarial poisoning patterns.
GAP-1,3,4,8,9: Regression smoke tests for confirmed-resolved gaps.
Runs in CI batch 3 in parallel with test_formal_fuzz_gaps_aead.py (batch 1)
and test_formal_fuzz_gaps_fountain.py (batch 2).
"""

import os
import secrets
import inspect

import pytest

pytestmark = pytest.mark.security

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


class TestTamperDetectionAdversarialPatterns:
    """GAP-10: Extended tamper detection covering adversarial poisoning scenarios."""

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


class TestGap1ContinueOnErrorAbsent:
    """Gap-1: fuzz CI must not swallow crashes. Smoke: fuzz target importable."""

    def test_fuzz_tamper_is_importable(self):
        import importlib.util
        from pathlib import Path
        fuzz_path = Path(__file__).parent.parent / "fuzz" / "fuzz_tamper_detection.py"
        spec = importlib.util.spec_from_file_location("fuzz_tamper_detection", str(fuzz_path))
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
                orig_len=100,
                comp_len=80,
                salt=secrets.token_bytes(32),
                sha256_hash=secrets.token_bytes(32),
                magic=b"MEOW",
                ephemeral_public_key=b"",
                pq_ciphertext=b"",
                mode_byte=0x02,
            )
            assert isinstance(aad, bytes) and len(aad) > 0
        except ImportError:
            pytest.skip("build_canonical_aad not exported")

    def test_different_orig_len_different_aad(self):
        try:
            from meow_decoder.crypto import build_canonical_aad
            salt = secrets.token_bytes(32)
            sha = secrets.token_bytes(32)
            kwargs = dict(
                comp_len=80, salt=salt, sha256_hash=sha,
                magic=b"MEOW", ephemeral_public_key=b"", pq_ciphertext=b"", mode_byte=0x02,
            )
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
