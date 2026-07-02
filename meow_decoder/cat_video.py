"""Cat-mode video decoder (dependency-free: cv2 + numpy, no Flask).

Decodes the 2-bits-per-blink cat-mode video produced by the web encoder. Lives
in the package (not web_demo/app.py) so it and its golden fixtures can be tested
in CI without importing Flask. web_demo/app.py imports `decode_cat_video` from
here; the server route ffmpeg-converts uploads to MJPEG AVI before calling it.

See tests/golden/python/ for representative fixtures and tests/test_cat_video.py.
"""

from meow_decoder.cat_blink import refine_blink_period


def decode_cat_video(video_path):
    """
    Decode binary data from a Cat Mode video using NRZ run-length analysis.

    Key insight: each state transition in the video acts as a sync anchor.
    Run-length encoding preserves transition timing and is self-correcting,
    unlike center-sampling which drifts when blink period varies slightly.

    Pipeline:
    1. Read all frames, measure green intensity per eye
    2. Classify each frame as (left_on, right_on) using preamble-calibrated thresholds
    3. Run-length encode → debounce short noise runs
    4. NRZ decode: map each run to blink count via cumulative position tracking
    5. Auto-tune blink period by validating payload header
    """
    import cv2
    import numpy as np

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError("Could not open video file")

    fps = cap.get(cv2.CAP_PROP_FPS)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

    # WebM files from MediaRecorder often have invalid frame count/fps.
    # Handle this by reading frames until EOF if count is unreliable.
    if fps <= 0 or fps > 1000:
        fps = 30.0  # Default to 30 fps
    if total_frames <= 0 or total_frames > 1000000:
        total_frames = 100000  # Read until EOF, capped for safety

    # Step 1: Detect eye regions from a frame with visible green eyes.
    # The first frame may be during the dark lead-in (eyes OFF), so scan
    # multiple frames to find one where green eyes are actually visible.
    left_box, right_box = None, None
    cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
    scan_limit = min(total_frames, 200)  # Scan up to 200 frames
    for scan_i in range(scan_limit):
        ret, frame = cap.read()
        if not ret:
            break
        left_box, right_box = _detect_eye_regions_cv(frame)
        if left_box is not None and right_box is not None:
            break

    if left_box is None or right_box is None:
        cap.release()
        raise ValueError(
            "Could not detect cat eye regions in video. Ensure the cat image with green eyes is visible."
        )

    # Step 2: Read all frames and measure green intensity per eye, keeping
    # each frame's presentation timestamp. MediaRecorder WebM (and anything
    # re-encoded by messaging apps) is variable-frame-rate: a run's length in
    # FRAMES is meaningless as a duration there, so wall-clock timestamps are
    # the only reliable clock.
    #
    # Re-open instead of seeking: CAP_PROP_POS_FRAMES=0 silently fails to
    # rewind VFR WebM/VP8 with OpenCV's ffmpeg backend, leaving the read
    # positioned mid-stream after the eye-detection scan above.
    cap.release()
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError("Could not re-open video file for intensity pass")
    left_intensities = []
    right_intensities = []
    timestamps_ms = []

    # Read to EOF rather than trusting the container's frame count — VFR WebM
    # headers routinely under-report (observed: header 1801, readable 1870),
    # which would silently drop the postamble tail.
    hard_cap = 1_000_000
    while len(left_intensities) < hard_cap:
        ret, frame = cap.read()
        if not ret:
            break
        timestamps_ms.append(float(cap.get(cv2.CAP_PROP_POS_MSEC)))
        left_intensities.append(_measure_green_intensity(frame, left_box))
        right_intensities.append(_measure_green_intensity(frame, right_box))

    cap.release()

    # Resample onto a uniform 60 fps grid when frame timing is non-uniform.
    # This is exactly what the server's `ffmpeg -r 60` conversion does (hold
    # the last frame until the next timestamp), but works without ffmpeg and
    # therefore also on direct VFR reads.
    left_intensities, right_intensities, resampled = _resample_uniform(
        left_intensities, right_intensities, timestamps_ms
    )
    if resampled:
        fps = 60.0

    n_frames = len(left_intensities)
    if n_frames < 30:
        raise ValueError(f"Video too short ({n_frames} readable frames). Need at least 30.")

    left_arr = np.array(left_intensities)
    right_arr = np.array(right_intensities)

    # ========== HELPERS ==========

    def run_length_encode(states_list):
        runs = []
        cur_state = states_list[0]
        cur_start = 0
        cur_len = 1
        for i in range(1, len(states_list)):
            if states_list[i] == cur_state:
                cur_len += 1
            else:
                runs.append((cur_state, cur_start, cur_len))
                cur_state = states_list[i]
                cur_start = i
                cur_len = 1
        runs.append((cur_state, cur_start, cur_len))
        return runs

    def find_preamble(runs):
        """Find first long (1,1) → long (0,0) pattern."""
        on_idx = None
        for i, (state, start, length) in enumerate(runs):
            if state == (1, 1) and length >= 3:
                on_idx = i
                break
        if on_idx is None:
            return None, None
        off_idx = None
        for i in range(on_idx + 1, min(on_idx + 5, len(runs))):
            if runs[i][0] == (0, 0) and runs[i][2] >= 3:
                off_idx = i
                break
        return on_idx, off_idx

    def debounce_runs(runs, min_run_len):
        """Merge runs shorter than min_run_len into adjacent longer runs."""
        if min_run_len < 2 or len(runs) < 2:
            return runs
        debounced = list(runs)
        changed = True
        while changed:
            changed = False
            new_runs = []
            i = 0
            while i < len(debounced):
                state, start, length = debounced[i]
                if length < min_run_len and len(new_runs) > 0:
                    # Merge short run into previous
                    prev_state, prev_start, prev_length = new_runs[-1]
                    new_runs[-1] = (prev_state, prev_start, prev_length + length)
                    # Also absorb next run if it has the same state as prev
                    if i + 1 < len(debounced) and debounced[i + 1][0] == prev_state:
                        new_runs[-1] = (
                            prev_state,
                            prev_start,
                            prev_length + length + debounced[i + 1][2],
                        )
                        i += 1
                    changed = True
                else:
                    # Merge with previous if same state
                    if len(new_runs) > 0 and new_runs[-1][0] == state:
                        ps, pp, pl = new_runs[-1]
                        new_runs[-1] = (ps, pp, pl + length)
                    else:
                        new_runs.append((state, start, length))
                i += 1
            debounced = new_runs
        return debounced

    def decode_nrz(bp, runs_list, start_idx, end_idx):
        """NRZ decode: map run lengths to blink counts via per-run rounding.

        Each run independently determines its blink count from its own length.
        This avoids cumulative drift that occurs when blink period varies.
        Single-blink runs (state transitions) are always correct regardless of bp.
        """
        binary = ""
        for i in range(start_idx, end_idx):
            state, _, length = runs_list[i]
            num_blinks = max(1, int(length / bp + 0.5))
            bits = f"{state[0]}{state[1]}"
            binary += bits * num_blinks
        return binary

    def decode_nrz_adaptive(bp, runs_list, start_idx, end_idx, expected_bits=None):
        """NRZ decode with adaptive adjustment for ambiguous runs.

        When expected_bits is known and the basic per-run decode is close but off
        by a few bits, identifies the most ambiguous runs (closest to N.5 rounding
        boundary) and adjusts them to hit the exact expected count.
        """
        # First pass: decode and identify ambiguity scores
        run_data = []
        total_bits = 0
        for i in range(start_idx, end_idx):
            state, _, length = runs_list[i]
            ratio = length / bp
            num_blinks = max(1, int(ratio + 0.5))
            # Ambiguity = how close ratio is to a .5 boundary
            frac = ratio - int(ratio)
            ambiguity = abs(frac - 0.5)  # 0.0 = maximally ambiguous, 0.5 = unambiguous
            bits = f"{state[0]}{state[1]}"
            run_data.append((state, length, num_blinks, ambiguity, bits))
            total_bits += num_blinks * 2

        if expected_bits is None or total_bits == expected_bits:
            return "".join(bits * nb for _, _, nb, _, bits in run_data)

        # Adjust ambiguous runs to hit expected count
        diff_blinks = (total_bits - expected_bits) // 2  # positive = too many, negative = too few
        if abs(diff_blinks) > 8:
            # Too far off, don't adjust
            return "".join(bits * nb for _, _, nb, _, bits in run_data)

        # Sort runs by ambiguity (most ambiguous first)
        adjustable = [
            (i, rd) for i, rd in enumerate(run_data) if rd[2] > 1
        ]  # only runs with >1 blink
        adjustable.sort(key=lambda x: x[1][3])  # sort by ambiguity ascending

        adjusted = list(run_data)
        remaining = diff_blinks
        for idx, (state, length, nb, amb, bits) in adjustable:
            if remaining == 0:
                break
            if remaining > 0 and nb > 1:
                # Reduce by 1 blink
                adjusted[idx] = (state, length, nb - 1, amb, bits)
                remaining -= 1
            elif remaining < 0:
                # Increase by 1 blink
                adjusted[idx] = (state, length, nb + 1, amb, bits)
                remaining += 1

        return "".join(bits * nb for _, _, nb, _, bits in adjusted)

    # refine_bp is implemented at module scope (refine_blink_period) so it can
    # be unit-tested directly; the artifact-collapse guard it carries is the
    # cat-mode decode-reliability fix exercised by test_cat_mode_refine_bp.py.
    refine_bp = refine_blink_period

    def whiten(binary_str):
        """XOR binary string with deterministic PRNG to break up long same-state runs.

        This is critical for NRZ decoding reliability: the payload header has many
        leading zeros (13+ consecutive (0,0) blinks), which creates long merged runs
        that are ambiguous to decode with variable frame timing.

        Whitening spreads the data so max run length drops from ~13 to ~5 blinks.
        XOR is self-inverse: whiten(whiten(x)) == x.

        Uses same PRNG as JavaScript encoder (LCG with MEOW seed).
        """
        seed = 0x4D454F57  # "MEOW" in hex
        result = []
        for bit in binary_str:
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
            mask = (seed >> 16) & 1
            result.append(str(int(bit) ^ mask))
        return "".join(result)

    def check_header(binary_str):
        """Check if binary has valid payload header. Returns (orig_len, comp_len, expected_bits) or None.

        Checks the binary as-is. Caller must de-whiten first if needed.
        """
        if len(binary_str) < 64:
            return None
        try:
            orig = int(binary_str[:32], 2)
            comp = int(binary_str[32:64], 2)
            if orig <= 0 or orig > 100000 or comp <= 0 or comp > 100000:
                return None
            expected_bits = (68 + comp + 16) * 8
            return (orig, comp, expected_bits)
        except (ValueError, OverflowError):
            return None

    # Framing constants: ALT prefix (4 blinks) + postamble suffix (8 blinks)
    ALT_BITS = 8  # 4 ALT blinks × 2 bits/blink = '10011001'
    POST_BITS = 16  # 8 postamble blinks × 2 bits/blink = '11' * 8
    FRAMING_BITS = ALT_BITS + POST_BITS  # 24 total overhead bits

    def strip_framing(binary_str):
        """Strip ALT prefix (8 bits) and postamble suffix (16 bits) from decoded output.

        The ALT and postamble are included in the decode region to avoid
        boundary merge issues (e.g., when data's first/last blink has the same
        state as the adjacent ALT/postamble blink and they merge into one run).
        """
        if len(binary_str) >= ALT_BITS + POST_BITS:
            return binary_str[ALT_BITS:-POST_BITS]
        elif len(binary_str) > ALT_BITS:
            return binary_str[ALT_BITS:]
        return binary_str

    def find_data_region_in_runs(runs):
        """Find data start and end indices in a run list.

        Returns region that INCLUDES the ALT prefix and postamble suffix.
        These get stripped from the decoded output by strip_framing().
        """
        on_idx, off_idx = find_preamble(runs)
        if on_idx is None or off_idx is None:
            return None, None, None, None

        # Start right after OFF block — includes ALT blinks in decode region
        ds = off_idx + 1

        # Find postamble: last long (1,1) run — INCLUDE it in decode region
        bp_est = (runs[on_idx][2] + runs[off_idx][2]) / 16.0
        min_post = max(3, bp_est * 3)
        de = len(runs)
        for i in range(len(runs) - 1, ds, -1):
            if runs[i][0] == (1, 1) and runs[i][2] >= min_post:
                de = i + 1  # Include postamble run (strip from decoded output)
                break

        return on_idx, off_idx, ds, de

    # ========== PASS 1: Initial classification with global thresholds ==========
    left_thresh_init = (left_arr.max() + left_arr.min()) / 2
    right_thresh_init = (right_arr.max() + right_arr.min()) / 2

    states_init = [
        (1 if left_arr[i] > left_thresh_init else 0, 1 if right_arr[i] > right_thresh_init else 0)
        for i in range(n_frames)
    ]
    runs_init = run_length_encode(states_init)

    on_idx_init, off_idx_init = find_preamble(runs_init)
    if on_idx_init is None or off_idx_init is None:
        raise ValueError("Could not find preamble (sustained ON→OFF pattern) in video")

    # Get FRAME RANGES from initial preamble (stable across recalibrations)
    on_frame_start = runs_init[on_idx_init][1]
    on_frame_end = on_frame_start + runs_init[on_idx_init][2]
    off_frame_start = runs_init[off_idx_init][1]
    off_frame_end = off_frame_start + runs_init[off_idx_init][2]

    on_len = runs_init[on_idx_init][2]
    off_len = runs_init[off_idx_init][2]
    blink_period_est = (on_len + off_len) / 16.0

    # ========== CALIBRATE: per-eye thresholds from preamble ==========
    left_on_mean = float(np.mean(left_arr[on_frame_start:on_frame_end]))
    left_off_mean = float(np.mean(left_arr[off_frame_start:off_frame_end]))
    right_on_mean = float(np.mean(right_arr[on_frame_start:on_frame_end]))
    right_off_mean = float(np.mean(right_arr[off_frame_start:off_frame_end]))

    left_thresh = (left_on_mean + left_off_mean) / 2
    right_thresh = (right_on_mean + right_off_mean) / 2

    # ========== PASS 2: Re-classify with calibrated thresholds ==========
    states_cal = [
        (1 if left_arr[i] > left_thresh else 0, 1 if right_arr[i] > right_thresh else 0)
        for i in range(n_frames)
    ]
    runs_cal = run_length_encode(states_cal)

    # Find data region in calibrated runs
    _, _, data_start_raw, data_end_raw = find_data_region_in_runs(runs_cal)
    if data_start_raw is None:
        raise ValueError("Could not find data region after calibration")

    # ========== DEBOUNCE: filter short transition artifacts ==========
    # Debounce threshold: runs shorter than ~30% of blink period are noise
    min_run = max(2, int(blink_period_est * 0.3))
    runs_db = debounce_runs(runs_cal, min_run)

    # Re-find data region in debounced runs
    _, _, ds_db, de_db = find_data_region_in_runs(runs_db)
    if ds_db is None:
        # Fall back to raw runs
        runs_db = runs_cal
        ds_db = data_start_raw
        de_db = data_end_raw

    # Re-estimate bp from debounced preamble
    on_db, off_db = find_preamble(runs_db)
    if on_db is not None and off_db is not None:
        bp_db = (runs_db[on_db][2] + runs_db[off_db][2]) / 16.0
    else:
        bp_db = blink_period_est

    # ========== AUTO-TUNE blink period with NRZ ==========
    best_bp = None
    best_binary = None
    best_method = None

    # Refine bp using median of single-blink runs (much more accurate than preamble)
    bp_refined = refine_bp(runs_db, ds_db, de_db, bp_db)

    # Fractional fine-pass: the median of integer run lengths quantizes to a
    # whole frame, and when the true period sits between two integers (e.g.
    # 11.5 after VFR resampling) that half-frame error compounds across
    # multi-blink runs and mis-rounds them. The mean of in-band single-blink
    # runs recovers the fractional period.
    _single = [
        runs_db[i][2]
        for i in range(ds_db, de_db)
        if 0.75 * bp_refined <= runs_db[i][2] <= 1.25 * bp_refined
    ]
    if len(_single) >= 5:
        _bp_mean = sum(_single) / len(_single)
        if 0.8 * bp_refined <= _bp_mean <= 1.2 * bp_refined:
            bp_refined = _bp_mean
    bp_center = bp_refined
    bp_min = max(0.5, bp_center - 1.5)
    bp_max = bp_center + 1.5

    # Phase 0: Try refined bp with adaptive adjustment (most reliable for variable framerate)
    # First decode at refined bp to get expected_bits from header
    result_at_refined = decode_nrz(bp_refined, runs_db, ds_db, de_db)
    data_at_refined = strip_framing(result_at_refined)
    hdr_refined = check_header(whiten(data_at_refined))
    if hdr_refined is not None:
        _, _, expected_bits_refined = hdr_refined
        # Adaptive targets total bits including framing overhead
        result_adaptive_full = decode_nrz_adaptive(
            bp_refined, runs_db, ds_db, de_db, expected_bits_refined + FRAMING_BITS
        )
        data_adaptive = strip_framing(result_adaptive_full)
        adaptive_hdr = check_header(whiten(data_adaptive))
        if adaptive_hdr and len(data_adaptive) == adaptive_hdr[2]:
            best_bp = bp_refined
            best_binary = data_adaptive
            best_method = "nrz-adaptive"

    # Phase 1: exact match search with per-run decode (0.005 increments)
    if best_binary is None:
        for bp_x1000 in range(int(bp_min * 1000), int(bp_max * 1000) + 1, 5):
            bp = bp_x1000 / 1000.0
            result = decode_nrz(bp, runs_db, ds_db, de_db)
            data = strip_framing(result)
            hdr = check_header(whiten(data))
            if hdr is None:
                continue
            orig, comp, expected_bits = hdr
            if len(data) == expected_bits:
                best_bp = bp
                best_binary = data
                best_method = "nrz-debounced"
                break

    # Phase 2: also try raw (non-debounced) runs
    if best_binary is None:
        for bp_x1000 in range(int(bp_min * 1000), int(bp_max * 1000) + 1, 5):
            bp = bp_x1000 / 1000.0
            result = decode_nrz(bp, runs_cal, data_start_raw, data_end_raw)
            data = strip_framing(result)
            hdr = check_header(whiten(data))
            if hdr is None:
                continue
            orig, comp, expected_bits = hdr
            if len(data) == expected_bits:
                best_bp = bp
                best_binary = data
                best_method = "nrz-raw"
                break

    # Phase 3: adaptive adjustment at nearby bp values
    if best_binary is None:
        for runs_to_try, ds, de, label in [
            (runs_db, ds_db, de_db, "nrz-debounced"),
            (runs_cal, data_start_raw, data_end_raw, "nrz-raw"),
        ]:
            for bp_x1000 in range(int(bp_min * 1000), int(bp_max * 1000) + 1, 10):
                bp = bp_x1000 / 1000.0
                result = decode_nrz(bp, runs_to_try, ds, de)
                data = strip_framing(result)
                hdr = check_header(whiten(data))
                if hdr is None:
                    continue
                _, _, expected_bits = hdr
                diff = abs(len(data) - expected_bits)
                if diff <= 8:  # within ±4 blinks
                    result_adj_full = decode_nrz_adaptive(
                        bp, runs_to_try, ds, de, expected_bits + FRAMING_BITS
                    )
                    data_adj = strip_framing(result_adj_full)
                    adj_hdr = check_header(whiten(data_adj))
                    if adj_hdr and len(data_adj) == adj_hdr[2]:
                        best_bp = bp
                        best_binary = data_adj
                        best_method = f"{label}-adaptive"
                        break
            if best_binary is not None:
                break

    # Last resort: use refined bp with adaptive
    if best_binary is None:
        best_bp = bp_refined
        result = decode_nrz(best_bp, runs_db, ds_db, de_db)
        data = strip_framing(result)
        hdr = check_header(whiten(data))
        if hdr is not None:
            _, _, expected_bits = hdr
            result_full = decode_nrz_adaptive(
                best_bp, runs_db, ds_db, de_db, expected_bits + FRAMING_BITS
            )
            best_binary = strip_framing(result_full)
            best_method = "nrz-adaptive (last resort)"
        else:
            best_binary = data
            best_method = "nrz-debounced (untuned)"

    # De-whiten the decoded binary (reverse the whitening applied during encoding)
    best_binary = whiten(best_binary)

    data_blinks = len(best_binary) // 2

    # Diagnostics
    diag = {"method": best_method}
    hdr = check_header(best_binary)
    if hdr:
        diag["header_orig_len"] = hdr[0]
        diag["header_comp_len"] = hdr[1]
        diag["expected_bits"] = hdr[2]
        diag["actual_bits"] = len(best_binary)
        diag["bit_diff"] = len(best_binary) - hdr[2]
    diag["debounce_min_run"] = min_run
    diag["vfr_resampled"] = resampled
    diag["raw_runs"] = len(runs_cal)
    diag["debounced_runs"] = len(runs_db)
    diag["bp_from_preamble"] = round(bp_db, 3)
    diag["bp_refined"] = round(bp_refined, 3)

    return {
        "success": True,
        "binary": best_binary,
        "bits": len(best_binary),
        "data_frames": data_blinks,
        "blink_period": round(best_bp, 3),
        "blink_period_est": round(blink_period_est, 3),
        "video_fps": fps,
        "total_video_frames": n_frames,
        "estimated_blink_ms": round(best_bp / fps * 1000, 1) if fps > 0 else 0,
        "left_threshold": round(float(left_thresh), 1),
        "right_threshold": round(float(right_thresh), 1),
        "left_on_mean": round(float(left_on_mean), 1),
        "left_off_mean": round(float(left_off_mean), 1),
        "right_on_mean": round(float(right_on_mean), 1),
        "right_off_mean": round(float(right_off_mean), 1),
        "preamble_on_frames": f"{on_frame_start}-{on_frame_end}",
        "preamble_off_frames": f"{off_frame_start}-{off_frame_end}",
        "data_start_run": ds_db,
        "data_end_run": de_db,
        "total_runs": len(runs_db),
        "auto_tuned": best_bp != bp_db,
        "diagnostics": diag,
    }


def _resample_uniform(left, right, timestamps_ms, grid_fps=60.0):
    """Resample intensity series onto a uniform time grid via hold-last-value.

    Returns (left, right, resampled_flag). Only resamples when the container
    timestamps are usable (monotonic non-decreasing, positive span) AND frame
    timing is meaningfully non-uniform — constant-frame-rate input passes
    through untouched so existing CFR behavior (and its test coverage) is
    bit-identical.
    """
    n = len(timestamps_ms)
    if n < 30 or len(left) != n or len(right) != n:
        return left, right, False

    # Timestamp sanity: strictly usable clocks only. Some backends report 0
    # for every frame — that must fall back to frame-index timing.
    span = timestamps_ms[-1] - timestamps_ms[0]
    if span <= 0:
        return left, right, False
    deltas = []
    for i in range(1, n):
        d = timestamps_ms[i] - timestamps_ms[i - 1]
        if d < 0:
            return left, right, False
        if d > 0:
            deltas.append(d)
    if len(deltas) < n // 2:
        return left, right, False

    deltas.sort()
    med = deltas[len(deltas) // 2]
    if med <= 0:
        return left, right, False

    # Uniform enough already? (VFR shows up as max delta >> median — a held
    # frame spanning several blink periods.)
    if deltas[-1] <= med * 1.5 and deltas[0] >= med * 0.5:
        return left, right, False

    step = 1000.0 / grid_fps
    t0 = timestamps_ms[0]
    grid_n = int(span / step) + 1
    # Refuse absurd expansion (corrupt timestamps could ask for hours of grid).
    if grid_n > 500_000 or grid_n < 30:
        return left, right, False

    out_left = []
    out_right = []
    src = 0
    for g in range(grid_n):
        t = t0 + g * step
        while src + 1 < n and timestamps_ms[src + 1] <= t:
            src += 1
        out_left.append(left[src])
        out_right.append(right[src])
    return out_left, out_right, True


def _detect_eye_regions_cv(frame):
    """
    Detect left and right green eye regions in a BGR frame using OpenCV.
    Returns (left_box, right_box) as (x1, y1, x2, y2) tuples, or (None, None).
    """
    import cv2
    import numpy as np

    h, w = frame.shape[:2]

    # Convert to HSV for better green detection
    hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)

    # Green in HSV: Hue 35-85, Saturation > 50, Value > 80
    lower_green = np.array([35, 50, 80])
    upper_green = np.array([85, 255, 255])
    green_mask = cv2.inRange(hsv, lower_green, upper_green)

    # Only look in upper 65% (eyes are in the upper part)
    max_y = int(h * 0.65)
    green_mask[max_y:, :] = 0

    # Find green pixel coordinates
    coords = np.argwhere(green_mask > 0)  # (y, x) format
    if len(coords) < 20:
        return None, None

    ys, xs = coords[:, 0], coords[:, 1]
    min_x, max_x = int(np.min(xs)), int(np.max(xs))

    # Find the split between left and right eyes
    # Look for the column with fewest green pixels in the middle third
    mid_start = min_x + int((max_x - min_x) * 0.35)
    mid_end = min_x + int((max_x - min_x) * 0.65)

    min_count = float("inf")
    split_x = (min_x + max_x) // 2
    for x in range(mid_start, mid_end + 1):
        count = np.sum(xs == x)
        if count < min_count:
            min_count = count
            split_x = x

    # Build eye boxes robustly. The cat artwork is full of green that is NOT
    # an eye — glowing ear tips, a green cap logo, circuit traces — so a naive
    # min/max bounding box balloons to cover half the face (the "two giant
    # green circles" bug). Instead locate the densest green blob on each side
    # (the eye), keep only nearby pixels, take a percentile box, and clamp the
    # size so scattered outliers can't inflate it.
    left_mask = xs < split_x
    right_mask = xs >= split_x
    if np.sum(left_mask) < 10 or np.sum(right_mask) < 10:
        return None, None

    left_box = _eye_box_from_points(xs[left_mask], ys[left_mask], w, h)
    right_box = _eye_box_from_points(xs[right_mask], ys[right_mask], w, h)
    if left_box is None or right_box is None:
        return None, None

    return left_box, right_box


def _eye_box_from_points(xs, ys, w, h):
    """Tight, size-clamped eye box around the densest green cluster.

    xs/ys are the green-pixel coordinates on one side of the split. Returns
    (x1, y1, x2, y2) or None. Shared logic with the transmitter's JS
    autoDetectEyeRegions so transmit overlay and receiver sampling agree.
    """
    import numpy as np

    if len(xs) < 10:
        return None

    max_w = max(24, round(w * 0.16))
    max_h = max(24, round(h * 0.18))

    # Coarse 16px density grid → peak cell locates the eye and rejects the
    # scattered circuitry/ear/cap green that wrecks min/max.
    cell = 16
    gx = (xs // cell).astype(np.int64)
    gy = (ys // cell).astype(np.int64)
    keys = gx * 100000 + gy
    uniq, counts = np.unique(keys, return_counts=True)
    peak = uniq[int(np.argmax(counts))]
    pcx = (peak // 100000) * cell + cell / 2
    pcy = (peak % 100000) * cell + cell / 2

    near = (np.abs(xs - pcx) <= max_w) & (np.abs(ys - pcy) <= max_h)
    nx = xs[near]
    ny = ys[near]
    if len(nx) < 10:
        nx, ny = xs, ys

    x1, x2 = float(np.percentile(nx, 10)), float(np.percentile(nx, 90))
    y1, y2 = float(np.percentile(ny, 10)), float(np.percentile(ny, 90))
    cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
    if x2 - x1 > max_w:
        x1, x2 = cx - max_w / 2, cx + max_w / 2
    if y2 - y1 > max_h:
        y1, y2 = cy - max_h / 2, cy + max_h / 2

    pad = 4
    return (
        max(0, int(round(x1 - pad))),
        max(0, int(round(y1 - pad))),
        min(w, int(round(x2 + pad))),
        min(h, int(round(y2 + pad))),
    )


def _measure_green_intensity(frame, box):
    """Measure average green channel intensity within a bounding box."""
    x1, y1, x2, y2 = box
    roi = frame[y1:y2, x1:x2]
    if roi.size == 0:
        return 0.0
    # Green channel is index 1 in BGR
    return float(roi[:, :, 1].mean())
