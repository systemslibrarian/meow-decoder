"""Cat Blink v2 codec: Python round-trip, erasure tolerance, and a
cross-language vector decoding frames produced by the JS reference.

See docs/CAT_BLINK_V2.md. No device/browser needed.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from meow_decoder import cat_blink_v2 as v2

DATA = Path(__file__).parent / "data" / "cat_blink_v2_vector.json"


def _payload(n: int, seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(n))


def test_clean_round_trip_various_sizes() -> None:
    for size in (1, 16, 40, 100, 250):
        payload = _payload(size, size * 7 + 1)
        frames = v2.encode(payload, block_size=32, redundancy=3.0)
        assert v2.decode(frames) == payload


def test_crc_rejects_corrupted_frame() -> None:
    payload = _payload(64, 99)
    frames = v2.encode(payload, block_size=32)
    bad = list(frames[2])
    bad[50] = "0" if bad[50] == "1" else "1"  # one misread blink
    assert v2.decode_frame("".join(bad)) is None


def _drop_and_shuffle(frames, drop_frac, seed):
    rng = random.Random(seed)
    kept = [f for f in frames if rng.random() >= drop_frac]
    rng.shuffle(kept)
    return kept


def test_erasure_tolerance() -> None:
    for drop in (0.1, 0.25, 0.4):
        payload = _payload(120, int(drop * 1000))
        frames = v2.encode(payload, block_size=32, redundancy=4.0)
        lossy = _drop_and_shuffle(frames, drop, 1234 + int(drop * 100))
        assert v2.decode(lossy) == payload


def test_excessive_loss_fails_cleanly() -> None:
    payload = _payload(120, 5)
    frames = v2.encode(payload, block_size=32, redundancy=4.0)
    shredded = _drop_and_shuffle(frames, 0.9, 42)
    result = v2.decode(shredded)
    # Never wrong bytes: either clean recovery or None.
    assert result is None or result == payload


def test_cross_language_vector_from_js() -> None:
    """Frames produced by web_demo/static/cat-blink-v2.js must decode here,
    proving the wire format (frame layout, CRC, whitening, bit order, droplet
    layout) is genuinely shared between JS and Python."""
    vec = json.loads(DATA.read_text())
    payload = bytes(vec["payload_bytes"])
    recovered = v2.decode(vec["frames"])
    assert recovered == payload

    # And a lossy subset of the JS frames still reconstructs.
    lossy = _drop_and_shuffle(vec["frames"], 0.25, 7)
    assert v2.decode(lossy) == payload
