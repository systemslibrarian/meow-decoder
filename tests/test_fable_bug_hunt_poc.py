"""Proof-of-concept tests for the top findings in Fable-Bug-Hunt-Results.md.

These tests *execute* the two highest-severity findings, turning
"confirmed by adversarial code review" into "demonstrated by a running
test". Each test asserts the CURRENT (vulnerable) behaviour and passes
today because the bug is present; a ``TODO(fix)`` note on each explains
how to invert the assertion once the fix lands, so the file doubles as a
regression guard.

Findings covered:
  * C1 (CRITICAL) - encoder emits a PQ-mode manifest with no PQ ciphertext
    that the decoder deterministically rejects (undecodable artifact).
  * H1 (HIGH) - Schrödinger decode path applies no upper bound to the
    attacker-controlled ``block_count``/``k_blocks`` before allocating.
"""

import struct

import pytest

from meow_decoder.crypto import (
    MAGIC,
    MAX_K_BLOCKS,
    MODE_MEOW5,
    Manifest,
    pack_manifest,
    unpack_manifest,
)
from meow_decoder.fountain import FountainDecoder
from meow_decoder.schrodinger_encode import SchrodingerManifest


# ---------------------------------------------------------------------------
# C1 (CRITICAL): pack_manifest happily serialises a MEOW5 (PQ) manifest that
# carries no PQ ciphertext; unpack_manifest then hard-rejects that exact shape.
# An encoder that reaches this state (use_pq=True with no receiver key) emits a
# permanently undecodable artifact -- and under --high-security the source is
# then securely wiped.  encode.py:127-145 / crypto.py:1704-1707.
# ---------------------------------------------------------------------------
def _mode_meow5_manifest_without_pq() -> Manifest:
    """A structurally valid MEOW5 manifest with pq_ciphertext=None.

    This is exactly what encode_file(use_pq=True, receiver_public_key=None)
    produces: mode byte says PQ, but the PQ trailer field is absent.
    """
    return Manifest(
        salt=b"\x00" * 16,
        nonce=b"\x00" * 12,
        orig_len=10,
        comp_len=10,
        cipher_len=10,
        sha256=b"\x00" * 32,
        block_size=512,
        k_blocks=1,
        hmac=b"\x00" * 32,
        ephemeral_public_key=None,
        pq_ciphertext=None,  # <-- the defect: PQ mode byte but no PQ ciphertext
        mode_byte=MODE_MEOW5,
    )


def test_c1_pq_mode_without_ciphertext_is_rejected_at_pack_time():
    """C1 (fixed): the encoder can no longer emit a PQ manifest with no PQ
    ciphertext.

    pack_manifest now performs mode/field consistency validation and fails
    closed, so the undecodable artifact that encode_file(use_pq=True) with no
    receiver keys used to emit -- and then securely wipe the source for under
    --high-security -- is UNCONSTRUCTABLE at encode time.
    """
    m = _mode_meow5_manifest_without_pq()

    # The ENCODER side now refuses: a MEOW5 mode byte whose required trailer
    # fields (ephemeral key / PQ ciphertext) are absent can no longer be
    # serialized into a broken, permanently-undecodable artifact.
    with pytest.raises(ValueError, match="undecodable manifest"):
        pack_manifest(m)


# ---------------------------------------------------------------------------
# H1 (HIGH): the Schrödinger decode path reads block_count/block_size from an
# unauthenticated manifest and hands them straight to the fountain decoder,
# which allocates vec![None; k_blocks] with no ceiling.  The main manifest
# path caps k_blocks at MAX_K_BLOCKS (1M); the Schrödinger path does not.
# schrodinger_decode.py:382 / schrodinger_encode.py:160-225 / decoder.rs:47.
# ---------------------------------------------------------------------------
def _schrodinger_manifest_bytes(block_count: int, block_size: int) -> bytes:
    """Build a minimal 382-byte v0x08 Schrödinger manifest blob.

    Only the block_count/block_size fields matter here; every other field is
    zero-filled. Mirrors the layout parsed by SchrodingerManifest.unpack().
    """
    blob = b"MEOW"
    blob += struct.pack("BB", 0x08, 0x00)  # version, flags
    blob += b"\x00" * 16  # salt_a
    blob += b"\x00" * 16  # salt_b
    blob += b"\x00" * 12  # nonce_a
    blob += b"\x00" * 12  # nonce_b
    blob += b"\x00" * 32  # reality_a_hmac
    blob += b"\x00" * 32  # reality_b_hmac
    blob += b"\x00" * 104  # metadata_a
    blob += b"\x00" * 104  # metadata_b
    blob += struct.pack(">IIQ", block_count, block_size, 0)  # block_count/size/superpos_len
    blob += b"\x00" * 16  # frame_mac_seed (v0x08)
    blob += b"\x00" * 16  # reserved
    assert len(blob) == 382
    return blob


def test_h1_schrodinger_manifest_rejects_absurd_block_count():
    """H1a (fixed): SchrodingerManifest.unpack now bounds block_count.

    An attacker-declared ~4.29e9 block_count (u32 field) is rejected at parse
    time, before it can reach the allocating fountain decoder.
    """
    absurd = 0xFFFFFFFF  # 4_294_967_295, ~4300x over MAX_K_BLOCKS
    assert absurd > MAX_K_BLOCKS

    with pytest.raises(ValueError):
        SchrodingerManifest.unpack(_schrodinger_manifest_bytes(absurd, 512))


def test_h1_fountain_decoder_rejects_k_blocks_over_u16_cap():
    """H1b (fixed): FountainDecoder rejects k_blocks above the u16 cap.

    Droplet indices are u16, so a valid artifact never has more than u16::MAX
    blocks; the decoder now mirrors the encoder's ceiling and validates BEFORE
    allocating, so an unauthenticated k_blocks can no longer force an unbounded
    allocation (OOM DoS).
    """
    over_u16_cap = 70_000  # > u16::MAX (65535), the encoder's ceiling
    assert over_u16_cap > 65535

    with pytest.raises(ValueError):
        FountainDecoder(k_blocks=over_u16_cap, block_size=1)
