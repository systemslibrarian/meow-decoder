"""
Decompression-bomb branch coverage for ``meow_decoder.crypto.decrypt_to_raw``.

The decompressor is fed a ciphertext whose plaintext is `comp` — a zlib
stream that, when decompressed, produces more output than
``MAX_DECOMP_RATIO * orig_len``. The decryptor's bomb-protection branch
fires AFTER AES-GCM auth passes (since the AAD includes the *declared*
``orig_len``), so the test must construct a genuine ciphertext + AAD
pair that passes GCM but lies about ``orig_len`` relative to the actual
compressed payload size.

Closes deferred FOLLOWUP "Finding 13" item — coverage gap on
``# pragma: no cover`` decompression-bomb branches in
``meow_decoder/crypto.py``.

Two scenarios:

1. ``test_decompression_bomb_detected`` — actual decompressed output
   exceeds ``decomp_limit``; the initial-chunk overflow branch fires.

2. ``test_corrupted_zlib_payload_rejected`` — plaintext is *not* a
   valid zlib stream; ``zlib.error`` is raised and the
   ``except zlib.error`` branch wraps it as ``RuntimeError``.

A third branch (post-flush overflow at line 1453) is dead-code in
practice — under every observed zlib behaviour the initial-chunk
branch catches the overflow first. It retains its ``# pragma: no
cover`` annotation with a documented rationale rather than a forced
synthetic test that does not reflect any real zlib output pattern.
"""

import secrets
import zlib

import pytest

from meow_decoder.crypto import (
    MAGIC,
    MAX_DECOMP_RATIO,
    build_canonical_aad,
    decrypt_to_raw,
    derive_key,
)
from meow_decoder.crypto_backend import get_default_backend


def _fabricate_ciphertext(
    *,
    password: str,
    salt: bytes,
    nonce: bytes,
    plaintext: bytes,
    declared_orig_len: int,
    declared_comp_len: int,
    declared_sha256: bytes,
) -> bytes:
    """Encrypt ``plaintext`` with the same AAD that ``decrypt_to_raw`` will
    rebuild from the declared fields. Returns the AES-GCM ciphertext.

    The trick: ``declared_orig_len`` and ``declared_sha256`` are the
    values the *decryptor* will use to rebuild AAD. Both encryptor and
    decryptor must use the same values for GCM auth to pass. As long as
    both sides agree on these "declared" values, the ciphertext decrypts
    cleanly — and the decryptor uses ``declared_orig_len`` to compute
    its bomb threshold (``decomp_limit = max(orig_len * 10, 1MB)``). By
    making the *actual* decompressed size exceed that threshold, we
    isolate the bomb branch.
    """
    key = derive_key(password, salt)
    aad = build_canonical_aad(
        orig_len=declared_orig_len,
        comp_len=declared_comp_len,
        salt=salt,
        sha256_hash=declared_sha256,
        magic=MAGIC,
    )
    backend = get_default_backend()
    return backend.aes_gcm_encrypt(key, nonce, plaintext, aad)


def test_decompression_bomb_detected():
    """Bomb scenario: declared orig_len=100 → decomp_limit=1 MiB. Actual
    decompressed plaintext = 4 MiB. Initial-chunk overflow branch fires.
    Outer ``decrypt_to_raw`` wraps the ValueError into the generic
    "Decryption failed" RuntimeError (audit-followup 6.1 sanitization).
    """
    password = "TestPassword123!ValidSecure"
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    # 4 MiB of highly compressible 'A's → tiny ciphertext, huge expansion.
    raw_data = b"A" * (4 * 1024 * 1024)
    comp = zlib.compress(raw_data, level=9)

    # Lie: declare orig_len=100 → decomp_limit = max(100*10, 1MB) = 1 MiB.
    # Actual decompressed output = 4 MiB → branch fires.
    fake_orig_len = 100
    declared_comp_len = len(comp)
    declared_sha256 = get_default_backend().sha256(raw_data)

    cipher = _fabricate_ciphertext(
        password=password,
        salt=salt,
        nonce=nonce,
        plaintext=comp,
        declared_orig_len=fake_orig_len,
        declared_comp_len=declared_comp_len,
        declared_sha256=declared_sha256,
    )

    with pytest.raises(RuntimeError, match="Decryption failed"):
        decrypt_to_raw(
            cipher=cipher,
            password=password,
            salt=salt,
            nonce=nonce,
            orig_len=fake_orig_len,
            comp_len=declared_comp_len,
            sha256=declared_sha256,
        )


def test_decompression_bomb_threshold_at_minimum_floor():
    """Even when orig_len is tiny, the floor of 1 MiB applies. Covers the
    `max(orig_len * MAX_DECOMP_RATIO, 1 MiB)` lower bound: a 1.5 MiB
    decompressed payload with declared orig_len=1 still trips the bomb
    branch (limit = max(10, 1 MiB) = 1 MiB, actual = 1.5 MiB).
    """
    password = "TestPassword123!ValidSecure"
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    raw_data = b"B" * (1_500_000)  # ~1.43 MiB
    comp = zlib.compress(raw_data, level=9)

    fake_orig_len = 1
    declared_comp_len = len(comp)
    declared_sha256 = get_default_backend().sha256(raw_data)

    cipher = _fabricate_ciphertext(
        password=password,
        salt=salt,
        nonce=nonce,
        plaintext=comp,
        declared_orig_len=fake_orig_len,
        declared_comp_len=declared_comp_len,
        declared_sha256=declared_sha256,
    )

    with pytest.raises(RuntimeError, match="Decryption failed"):
        decrypt_to_raw(
            cipher=cipher,
            password=password,
            salt=salt,
            nonce=nonce,
            orig_len=fake_orig_len,
            comp_len=declared_comp_len,
            sha256=declared_sha256,
        )


def test_corrupted_zlib_payload_rejected():
    """``zlib.error`` branch: plaintext is random bytes, not a valid zlib
    stream. The decompressor raises ``zlib.error`` which the wrapper
    converts to ``RuntimeError("Decompression failed: ...")``. The outer
    ``decrypt_to_raw`` then re-wraps as the generic "Decryption failed"
    error.
    """
    password = "TestPassword123!ValidSecure"
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    # Random bytes (not a valid zlib stream).
    fake_comp = secrets.token_bytes(2048)
    # The "raw" data we claim is just any 32-byte buffer — sha256 needs
    # to match the AAD, so we declare its hash here. The actual
    # decompression failure happens before any sha256 verification.
    declared_orig_len = 4096
    declared_comp_len = len(fake_comp)
    declared_sha256 = get_default_backend().sha256(b"declared but irrelevant")

    cipher = _fabricate_ciphertext(
        password=password,
        salt=salt,
        nonce=nonce,
        plaintext=fake_comp,
        declared_orig_len=declared_orig_len,
        declared_comp_len=declared_comp_len,
        declared_sha256=declared_sha256,
    )

    with pytest.raises(RuntimeError, match="Decryption failed"):
        decrypt_to_raw(
            cipher=cipher,
            password=password,
            salt=salt,
            nonce=nonce,
            orig_len=declared_orig_len,
            comp_len=declared_comp_len,
            sha256=declared_sha256,
        )


def test_decomp_limit_default_with_zero_orig_len():
    """``orig_len = 0`` falls through to the 100 MiB ceiling. A small
    legitimate decompressed payload should pass without triggering the
    bomb branch — covers the else-arm of the ternary.
    """
    password = "TestPassword123!ValidSecure"
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    raw_data = b"hello world"
    comp = zlib.compress(raw_data, level=9)

    declared_orig_len = 0
    declared_comp_len = len(comp)
    declared_sha256 = get_default_backend().sha256(raw_data)

    cipher = _fabricate_ciphertext(
        password=password,
        salt=salt,
        nonce=nonce,
        plaintext=comp,
        declared_orig_len=declared_orig_len,
        declared_comp_len=declared_comp_len,
        declared_sha256=declared_sha256,
    )

    out = decrypt_to_raw(
        cipher=cipher,
        password=password,
        salt=salt,
        nonce=nonce,
        orig_len=declared_orig_len,
        comp_len=declared_comp_len,
        sha256=declared_sha256,
    )
    assert out == raw_data


# Sanity check that we didn't accidentally weaken the bomb threshold
# constant: if it changes, this test must be reconsidered together
# with `decomp_limit` in crypto.py.
def test_max_decomp_ratio_constant_unchanged():
    assert MAX_DECOMP_RATIO == 10
