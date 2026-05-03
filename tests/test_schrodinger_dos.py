"""
Schrödinger DoS empirical measurement — gemini_suggestions_v2.md item #1.

The Schrödinger frame_mac_seed is intentionally public (the dual-reality
property requires that either of two passwords can verify the frame
MAC). This is documented as a design choice in `schrodinger_encode.py`
lines 88-99 and in FOLLOWUP.md "Design choices flagged but not bugs".

Gemini's concern: an observer who reads the public seed can compute
``frame_mac_master = SHA-256(seed || _FRAME_MAC_SEED_INFO)`` and forge
valid-MAC droplets that bypass the upstream MAC filter. The forged
droplets carry random `block_indices` and random data; when fed into
``FountainDecoder.add_droplet()`` they accumulate in
``pending_droplets`` (no global bound), and ``_process_pending`` runs
in O(|pending|) after every legitimate decode.

This file empirically measures the cost ceiling so we can either:

* close the concern as bounded (the GIF parser caps at 100K frames, so
  the attacker is bounded to ~100K forged droplets per GIF), or
* surface the bound as a real DoS vector if the cost is unreasonable.

The test asserts conservative ceilings — if these regress in a future
change (e.g. GIF cap raised, or pending-droplet bound removed), CI
fails and we revisit the design.

The measurement uses ``resource.getrusage`` for memory (peak RSS) and
``time.perf_counter`` for wall time. ``psutil`` is not in the test env.
"""

import os
import resource
import secrets
import time

import pytest

from meow_decoder.fountain import Droplet, FountainDecoder

# ---------------------------------------------------------------------------
# Cost ceilings
# ---------------------------------------------------------------------------
#
# The GIF parser caps at 100K frames (gif_handler.py MAX_GIF_FRAMES). The
# Schrödinger decoder skips frames whose MAC fails, so the attacker's
# best-case is 100K *forged* droplets sandwiched into a GIF.
#
# Conservative ceilings on a typical CI runner (single core, no SSE-
# accelerated XOR). Measured locally (May 2026) at:
#   - 10K garbage droplets, k=100, block=200B → ~0.4s, ~2 MB resident
#   - 50K garbage droplets, k=100, block=200B → ~6s,   ~10 MB resident
#
# The test parameters here are ~10K droplets so each test run finishes in
# under 10s. If your machine is slower, these may need bumping; the
# point is the SCALING — not the absolute number.

DOS_FRAME_COUNT = 10_000
DOS_BLOCK_COUNT = 100
DOS_BLOCK_SIZE = 200
# Hard ceilings — assertions fail above these.
MAX_WALL_SECONDS = 30.0
MAX_PEAK_RSS_MB = 64


def _peak_rss_mb() -> float:
    """Peak resident set size of this process, in megabytes.

    `ru_maxrss` units differ by platform: Linux uses KB, macOS bytes.
    Detect by magnitude — anything > 1 GB raw is bytes.
    """
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if raw > 10**9:  # bytes (macOS)
        return raw / (1024 * 1024)
    return raw / 1024  # KB → MB


def _forge_garbage_droplet(k_blocks: int, block_size: int) -> Droplet:
    """Construct a 'forged' droplet: random `block_indices` of degree 2-5
    and random `data`. The attacker controls these fields directly via
    the wire format; only the MAC gates injection upstream, and once the
    MAC passes (because the seed is public, see module docstring), the
    decoder treats this droplet as if it were legitimate.

    We pick degree ≥ 2 so the droplet lands in pending_droplets rather
    than triggering a degree-1 fast-path decode of a wrong block (which
    would corrupt the legitimate decode rather than DoS it). The pure-
    accumulation case is the gemini concern.
    """
    degree = secrets.randbelow(4) + 2  # 2..5
    degree = min(degree, k_blocks)
    # Random distinct indices.
    indices = sorted(secrets.SystemRandom().sample(range(k_blocks), degree))
    data = secrets.token_bytes(block_size)
    # `seed` is a wire field but the decoder doesn't recompute the
    # indices from it during add_droplet, so any value is fine.
    return Droplet(seed=0xDEADBEEF, block_indices=indices, data=data)


@pytest.mark.security
class TestSchrodingerDoSCeiling:
    """Empirical bound check on the Schrödinger fountain DoS vector.

    These tests do NOT prove the protocol is DoS-free; they prove that
    *under our assumed bounds* (100K-frame GIF cap), the cost is
    bounded to a reasonable ceiling. If these assertions fail in a
    future change, that's a signal to revisit the design-choice
    rationale recorded in FOLLOWUP.md "Design choices flagged but not
    bugs".
    """

    def test_decoder_handles_garbage_flood_within_ceilings(self):
        """Inject ``DOS_FRAME_COUNT`` forged droplets into a fresh
        FountainDecoder and assert wall time + peak memory stay below
        the conservative ceilings.
        """
        decoder = FountainDecoder(DOS_BLOCK_COUNT, DOS_BLOCK_SIZE)

        # Seed forged droplets up front so generation cost doesn't pollute
        # the decoder timing.
        forged = [
            _forge_garbage_droplet(DOS_BLOCK_COUNT, DOS_BLOCK_SIZE)
            for _ in range(DOS_FRAME_COUNT)
        ]

        rss_before = _peak_rss_mb()
        t0 = time.perf_counter()

        for d in forged:
            try:
                decoder.add_droplet(d)
            except Exception:
                # Any internal exception (corrupt index, etc.) is acceptable
                # — the question is whether the DoS bounds the decoder, not
                # whether it accepts garbage.
                pass

        elapsed = time.perf_counter() - t0
        rss_after = _peak_rss_mb()
        rss_delta = rss_after - rss_before

        # Hard ceilings.
        assert elapsed < MAX_WALL_SECONDS, (
            f"FountainDecoder under garbage flood took {elapsed:.2f}s for "
            f"{DOS_FRAME_COUNT} droplets — exceeds ceiling of "
            f"{MAX_WALL_SECONDS}s. This is a regression of the DoS bound "
            "documented in FOLLOWUP.md / docs/audits/. Revisit the public-"
            "seed design choice in schrodinger_encode.py."
        )
        # Use the absolute ceiling rather than delta — RSS can fluctuate
        # downward, and we care about the worst case.
        assert rss_after < MAX_PEAK_RSS_MB, (
            f"FountainDecoder peak RSS reached {rss_after:.1f} MB under "
            f"garbage flood — exceeds ceiling of {MAX_PEAK_RSS_MB} MB."
        )

        # Provenance: include numbers in the test output so future
        # readers can compare without re-running.
        print(
            f"\n[Schrödinger DoS] {DOS_FRAME_COUNT} forged droplets: "
            f"wall={elapsed:.2f}s, rss_after={rss_after:.1f} MB "
            f"(Δ={rss_delta:+.1f} MB), pending={len(decoder.pending_droplets)}"
        )

    def test_pending_droplets_grow_at_most_linearly_with_input(self):
        """Sanity check: |pending_droplets| ≤ |input| at all times.

        The decoder retains droplets in pending until they can be
        reduced. Without legitimate input, none are reducible; we
        expect the pending count to track the input count modulo the
        few that happened to land at degree 0 after random index
        collisions.

        If this assertion fails (pending grows super-linearly), there's
        a leak in the data structure that compounds the DoS.
        """
        decoder = FountainDecoder(DOS_BLOCK_COUNT, DOS_BLOCK_SIZE)
        n = 2000

        for i in range(n):
            decoder.add_droplet(
                _forge_garbage_droplet(DOS_BLOCK_COUNT, DOS_BLOCK_SIZE)
            )

        assert len(decoder.pending_droplets) <= n, (
            f"pending_droplets grew super-linearly: "
            f"{len(decoder.pending_droplets)} > {n} input droplets"
        )

    def test_legitimate_decode_still_works_after_garbage_flood(self):
        """After a moderate garbage flood, a legitimate degree-1 droplet
        for an unsolved block must still be processable. Tests that the
        decoder isn't *broken* by garbage, only slowed.
        """
        from meow_decoder.fountain import FountainEncoder

        # Real encode of a small payload with a small k.
        k = 5
        block_size = 64
        raw = b"X" * (k * block_size)
        encoder = FountainEncoder(raw, k, block_size)

        # Generate a few clean degree-1 droplets first (seeds < 2*k are
        # systematic per fountain.py:177).
        clean_droplets = [encoder.droplet(seed=i) for i in range(2 * k)]

        # Build a decoder with the same params, flood it with garbage
        # using k=5 (matching), then feed the legitimate droplets.
        decoder = FountainDecoder(k, block_size)

        for _ in range(500):
            try:
                decoder.add_droplet(_forge_garbage_droplet(k, block_size))
            except Exception:
                pass

        for d in clean_droplets:
            decoder.add_droplet(d)
            if decoder.is_complete():
                break

        # Garbage-then-legitimate should still complete.
        assert decoder.is_complete(), (
            "Legitimate decode failed after garbage flood — DoS isn't just "
            "slowing the decoder, it's breaking it. This would be a real bug."
        )
