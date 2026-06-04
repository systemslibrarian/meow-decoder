"""Regression guard for cat-mode blink-period refinement on compressed video.

`refine_blink_period` sharpens the blink-period (`bp`) estimate from the median
of single-blink run lengths. The bug it guards (fixed in commit 7101314): on
compressed / camera-captured video (VP9, H.264, rolling shutter), ON/OFF
transitions produce spurious 1-3 frame runs. The old refinement counted those as
"single blinks", dragging the median *below* the true period — a correct
5.94-frame estimate collapsing toward 4.0, inflating the decoded bit count ~1.5x
and breaking every decode.

These tests are pure (no OpenCV/Flask/ffmpeg) so they run in CI on every push.
The full generate -> VP9-compress -> decode round trip that exercises the real
`_decode_cat_video` lives in web_demo/test_cat_mode_refine_bp.py (local/manual,
needs ffmpeg + cv2).
"""

import pytest

from meow_decoder.cat_blink import refine_blink_period


def _runs(lengths):
    """Build a run list in the (state, start, length) shape the decoder uses."""
    return [(("1", "0"), 0, int(length)) for length in lengths]


def test_clean_single_blinks_refine_to_true_period():
    """With clean single-blink runs the median sharpens the estimate as intended."""
    runs = _runs([6] * 30)  # true period 6; noisy preamble estimate 5.6
    assert refine_blink_period(runs, 0, len(runs), initial_bp=5.6) == pytest.approx(6.0)


def test_transition_artifacts_do_not_collapse_bp():
    """Core regression: spurious short runs must NOT drag bp below the truth.

    Mirrors compressed video: 35 real single-blink runs (~6 frames) polluted by
    40 transition artifacts (1-3 frames, roughly one per blink boundary). The old
    unfiltered median collapsed to ~2.0 on this mix; the band-filtered + clamped
    version must stay at the true period.
    """
    real = [6] * 35
    artifacts = [1, 2, 3, 2] * 10  # 40 sub-blink transition runs
    runs = _runs(real + artifacts)

    refined = refine_blink_period(runs, 0, len(runs), initial_bp=5.94)

    assert refined == pytest.approx(6.0, abs=0.5)
    assert refined > 5.0  # explicit guard against the observed collapse to ~4.0


def test_refinement_clamped_to_preamble_estimate():
    """Even if artifacts dominate the band, the clamp prevents a wild refinement."""
    # Many runs at ~4 frames would pull a naive median to 4.0, but that is
    # < 0.7 * 6.0, so the clamp must reject it and keep the preamble estimate.
    runs = _runs([4] * 50)
    refined = refine_blink_period(runs, 0, len(runs), initial_bp=6.0)
    assert refined >= 0.7 * 6.0


def test_too_few_runs_returns_initial_estimate():
    """Below the sample threshold the function leaves the preamble estimate alone."""
    runs = _runs([6] * 5)  # < 10 single-blink samples
    assert refine_blink_period(runs, 0, len(runs), initial_bp=5.9) == pytest.approx(5.9)


def test_subslice_is_respected():
    """Only runs inside [start_idx, end_idx) are considered."""
    # 12 artifacts up front, then 20 clean single-blinks; refine only the tail.
    runs = _runs([1] * 12 + [6] * 20)
    refined = refine_blink_period(runs, 12, len(runs), initial_bp=5.9)
    assert refined == pytest.approx(6.0)
