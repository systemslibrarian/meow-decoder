#!/usr/bin/env python3
"""Regression tests for cat-mode blink-period refinement on compressed video.

Background
----------
Cat mode transmits 2 bits/frame by blinking two green eyes on screen; the
decoder (`_decode_cat_video`) recovers the bitstream from run lengths. The blink
period ``bp`` (in video frames) is first estimated from the 16-blink preamble,
then sharpened by `_refine_blink_period` using the median of single-blink runs.

The bug (fixed in commit 7101314, guarded here): on compressed / camera-captured
video (VP9, H.264, rolling shutter) the ON/OFF transitions produce spurious
1-2 frame runs. The old refinement counted those as "single blinks", dragging
the median *below* the true period — a correct 5.94-frame estimate collapsing
toward 4.0, which inflated the decoded bit count ~1.5x and broke every decode.

`_refine_blink_period` now (1) only considers runs inside a plausible band
around the current estimate and (2) clamps the result to the reliable
preamble-derived estimate. These tests lock in both the unit-level property and
the full generate -> VP9-compress -> decode round trip.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import _refine_blink_period  # noqa: E402


def _runs(lengths):
    """Build a run list in the (state, start, length) shape the decoder uses."""
    return [(("1", "0"), 0, int(length)) for length in lengths]


# --------------------------------------------------------------------------
# Unit tests: _refine_blink_period directly (fast, no cv2/ffmpeg needed)
# --------------------------------------------------------------------------


def test_clean_single_blinks_refine_to_true_period():
    """With clean single-blink runs the median sharpens the estimate as intended."""
    # True period 6; clean single-blink runs all ~6 frames, slightly noisy estimate.
    runs = _runs([6] * 30)
    assert _refine_blink_period(runs, 0, len(runs), initial_bp=5.6) == pytest.approx(6.0)


def test_transition_artifacts_do_not_collapse_bp():
    """The core regression: spurious short runs must NOT drag bp below the truth.

    Mirrors compressed video: 35 real single-blink runs (~6 frames) polluted by
    40 transition artifacts (1-3 frames, roughly one per blink boundary). The old
    unfiltered median collapsed to ~2.0 on this mix; the band-filtered + clamped
    version must stay at the true period.
    """
    real = [6] * 35
    artifacts = [1, 2, 3, 2] * 10  # 40 sub-blink transition runs
    runs = _runs(real + artifacts)
    preamble_estimate = 5.94  # spans 16 known blinks -> reliable

    refined = _refine_blink_period(runs, 0, len(runs), initial_bp=preamble_estimate)

    # Must stay essentially at the true period, never collapse toward the artifacts.
    assert refined == pytest.approx(6.0, abs=0.5)
    # Explicit guard against the observed failure (collapse to ~4.0).
    assert refined > 5.0


def test_refinement_clamped_to_preamble_estimate():
    """Even if artifacts dominate the band, the clamp prevents a wild refinement."""
    # Pathological: many runs at ~4 frames would pull a naive median to 4.0,
    # but that is <0.7 * 6.0, so the clamp must reject it and keep the estimate.
    runs = _runs([4] * 50)
    refined = _refine_blink_period(runs, 0, len(runs), initial_bp=6.0)
    assert refined >= 0.7 * 6.0


def test_too_few_runs_returns_initial_estimate():
    """Below the sample threshold the function leaves the preamble estimate alone."""
    runs = _runs([6] * 5)  # < 10 single-blink samples
    assert _refine_blink_period(runs, 0, len(runs), initial_bp=5.9) == pytest.approx(5.9)


# --------------------------------------------------------------------------
# Integration test: full generate -> VP9 compress -> decode round trip.
# Skipped automatically where cv2 / ffmpeg / the cat asset are unavailable.
# --------------------------------------------------------------------------

_HAS_CV2 = False
try:
    import cv2  # noqa: F401

    _HAS_CV2 = True
except Exception:  # pragma: no cover - environment dependent
    pass

_HAS_FFMPEG = shutil.which("ffmpeg") is not None


@pytest.mark.skipif(not (_HAS_CV2 and _HAS_FFMPEG), reason="needs cv2 + ffmpeg")
@pytest.mark.parametrize("speed_ms", [50, 100])
def test_vp9_compressed_video_decodes_to_exact_payload(speed_ms):
    """End-to-end: a VP9-compressed cat video decodes to the exact payload.

    This is the scenario that was broken: compression-induced transition
    artifacts collapsed bp and inflated the bitstream. The decode must recover
    the original bits and keep bp at the true period.
    """
    import hashlib

    import test_cat_e2e_speeds as gen
    from app import _decode_cat_video

    if not os.path.exists(gen.CAT_IMAGE_PATH):
        pytest.skip("cat carrier image not available")

    frames = gen.prepare_cat_frames()
    raw_bits = gen.hex_to_binary(hashlib.sha256(b"").hexdigest())  # 256-bit payload
    whitened = gen.whiten(raw_bits)

    clean_path = gen.generate_video(whitened, speed_ms, frames)
    vp9_fd, vp9_path = tempfile.mkstemp(suffix=".webm")
    os.close(vp9_fd)
    try:
        subprocess.run(
            ["ffmpeg", "-y", "-i", clean_path, "-c:v", "libvpx-vp9", "-b:v", "800k",
             "-deadline", "realtime", "-cpu-used", "5", vp9_path],
            check=True, capture_output=True,
        )
        result = _decode_cat_video(vp9_path)
    finally:
        os.unlink(clean_path)
        os.unlink(vp9_path)

    # _decode_cat_video returns the de-whitened payload bits.
    assert result["binary"] == raw_bits
    assert result["bits"] == len(raw_bits)

    # bp must hold at the true period (speed_ms at 60fps), not collapse.
    expected_bp = round(speed_ms / 1000.0 * gen.VIDEO_FPS)
    assert result["diagnostics"]["bp_refined"] == pytest.approx(expected_bp, abs=0.5)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
