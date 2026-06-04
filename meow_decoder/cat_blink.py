"""Cat-mode blink-protocol signal processing.

Cat mode transmits 2 bits per "blink frame" by toggling two green cat eyes on
screen; a receiver films the screen and the decoder recovers the bitstream from
run lengths. The blink period ``bp`` (measured in *video* frames) is first
estimated from the 16-blink preamble, then sharpened here using the median of
single-blink run lengths.

This module is intentionally dependency-free (pure Python, no OpenCV/Flask) so
the decode-reliability guard in ``tests/test_cat_blink.py`` can exercise the real
implementation in CI. ``web_demo/app.py`` imports ``refine_blink_period`` from
here for the server-side video decoder.
"""

from typing import List, Sequence, Tuple

# A run is (state, start_index, length); only length (index 2) is used here.
Run = Tuple[object, int, int]


def refine_blink_period(
    runs_list: Sequence[Run],
    start_idx: int,
    end_idx: int,
    initial_bp: float,
) -> float:
    """Refine the blink-period estimate using the median of single-blink runs.

    ~75% of runs in random 2-bit data are single-blink transitions. These give
    exact ``bp`` measurements, so their median is a much more accurate ``bp``
    than the 16-blink preamble alone.

    Robustness (the decode-reliability fix): real (compressed / camera-captured)
    video produces spurious short runs at ON/OFF transitions — VP9/H.264
    inter-frame blur and rolling shutter momentarily push a transitioning eye
    across the threshold. Those sub-blink runs were polluting the single-blink
    set and dragging the median well below the true period (observed: a correct
    5.94-frame preamble estimate collapsing to 4.0 on VP9 video, inflating the
    decoded bit count ~1.5x and breaking the decode). Two guards prevent that:

      1. Only count runs inside a plausible single-blink band around the current
         estimate, excluding the tiny transition artifacts.
      2. Never let the refined value stray far from the preamble-derived
         estimate, which is reliable (it spans exactly 16 known blinks).

    Args:
        runs_list: run-length-encoded eye states; each item's ``[2]`` is the
            run length in video frames.
        start_idx, end_idx: half-open slice of ``runs_list`` covering the data
            region.
        initial_bp: the preamble-derived blink period (frames). Reliable anchor.

    Returns:
        The refined blink period in video frames.
    """
    bp = initial_bp
    for _ in range(3):
        lo, hi = 0.5 * bp, 1.5 * bp  # plausible single-blink window
        single_blink_lengths: List[int] = [
            runs_list[i][2] for i in range(start_idx, end_idx) if lo <= runs_list[i][2] <= hi
        ]
        if len(single_blink_lengths) < 10:
            break
        single_blink_lengths.sort()
        new_bp = single_blink_lengths[len(single_blink_lengths) // 2]
        # Reject refinements that drift implausibly far from the reliable
        # preamble estimate — that only happens when artifacts dominate.
        if not (0.7 * initial_bp <= new_bp <= 1.4 * initial_bp):
            break
        if abs(new_bp - bp) < 1e-6:
            bp = float(new_bp)
            break
        bp = float(new_bp)
    return float(bp)
