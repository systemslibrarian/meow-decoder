"""
🐱 Meow Decoder Web Demo
Simple Flask web interface for encoding and decoding files with Cat Mode support
"""

import json
import base64
import logging
from meow_decoder.crypto_backend import get_handle_backend
from meow_decoder.crypto import encrypt_file_bytes_production, decrypt_to_raw_production
from meow_decoder.config import EncodingConfig, DecodingConfig
from meow_decoder.decode_gif import decode_gif
from meow_decoder.encode import encode_file
import os
import sys
import uuid
import shutil
import time
import secrets
import threading
from pathlib import Path
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, send_file, send_from_directory, flash

logger = logging.getLogger(__name__)

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


app = Flask(__name__)
app.secret_key = os.urandom(24)  # For flash messages


@app.route('/assets/<path:filename>')
def serve_asset(filename):
    """Serve files from the top-level assets/ directory."""
    assets_dir = Path(__file__).parent.parent / 'assets'
    return send_from_directory(assets_dir, filename)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB limit (iPhone HD video + uncompressed test videos)

# Directories
INSTANCE_DIR = Path(__file__).parent / "instance"
UPLOADS_DIR = INSTANCE_DIR / "uploads"
OUTPUTS_DIR = INSTANCE_DIR / "outputs"

# Ensure directories exist
INSTANCE_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)
OUTPUTS_DIR.mkdir(exist_ok=True)

# Allowed extensions
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "bin", "zip", "doc", "docx"}
ALLOWED_GIF_EXTENSIONS = {"gif"}

# Token to file mapping (in-memory, resets on server restart)
# audit-followup 11.2: guard all download_tokens mutations with a lock to avoid
# dict-corruption races in threaded Flask deployments (default dev server spawns
# worker threads). Python's GIL makes basic dict ops atomic but a
# list(dict.items()) iteration alongside a concurrent pop can still observe
# mutation. The lock is taken for the scope of cleanup and for each insert/pop.
download_tokens = {}
download_tokens_lock = threading.Lock()
MAX_DOWNLOAD_TOKENS = 1000


def cleanup_old_files(max_age_minutes=5):
    """Remove files older than max_age_minutes from instance/ directories."""
    cutoff = time.time() - (max_age_minutes * 60)

    for directory in [UPLOADS_DIR, OUTPUTS_DIR]:
        for item in directory.iterdir():
            if item.is_dir():
                # Remove entire request directory if old
                try:
                    if item.stat().st_mtime < cutoff:
                        shutil.rmtree(item, ignore_errors=True)
                except Exception:
                    pass

    # Evict stale download_tokens whose associated files are gone or expired
    cutoff_dt = datetime.now() - timedelta(minutes=max_age_minutes)
    with download_tokens_lock:
        stale_tokens = [
            t for t, info in download_tokens.items()
            if info.get("created", datetime.min) < cutoff_dt
        ]
        for t in stale_tokens:
            download_tokens.pop(t, None)

        # Hard cap: evict oldest tokens if over limit (WD-11)
        if len(download_tokens) > MAX_DOWNLOAD_TOKENS:
            sorted_tokens = sorted(
                download_tokens.items(),
                key=lambda x: x[1].get("created", datetime.min),
            )
            excess = len(download_tokens) - MAX_DOWNLOAD_TOKENS
            for t, _ in sorted_tokens[:excess]:
                download_tokens.pop(t, None)


def allowed_file(filename, allowed_set):
    """Check if file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set


def get_request_dir(base_dir):
    """Create unique per-request directory."""
    request_id = str(uuid.uuid4())
    request_dir = base_dir / request_id
    request_dir.mkdir(parents=True, exist_ok=True)
    return request_dir


@app.after_request
def set_security_headers(response):
    """Set security headers on every response (WD-04)."""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "worker-src 'self' blob:; "
        "frame-ancestors 'none';"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=()'
    return response


@app.before_request
def before_request():
    """Cleanup old files before each request."""
    cleanup_old_files(max_age_minutes=5)


@app.route("/")
def index():
    """Redirect to encode page."""
    return redirect(url_for("encode_page"))


@app.route("/encode", methods=["GET", "POST"])
def encode_page():
    """Encoding page."""
    if request.method == "POST":
        try:
            # Validate file upload
            if "file" not in request.files:
                flash("No file uploaded", "error")
                return redirect(request.url)

            file = request.files["file"]
            if file.filename == "":
                flash("No file selected", "error")
                return redirect(request.url)

            if not allowed_file(file.filename, ALLOWED_EXTENSIONS):
                flash(f'Invalid file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}', "error")
                return redirect(request.url)

            # Get form parameters
            password = request.form.get("password", "")
            duress_password = request.form.get("duress_password", "")
            mode = request.form.get("mode", "normal")
            redundancy = float(request.form.get("redundancy", "1.5"))

            # Validate redundancy
            if not (1.2 <= redundancy <= 2.0):
                flash("Redundancy must be between 1.2 and 2.0", "error")
                return redirect(request.url)

            # Setup directories
            request_dir = get_request_dir(UPLOADS_DIR)
            output_dir = get_request_dir(OUTPUTS_DIR)

            # Save uploaded file
            filename = secure_filename(file.filename)
            input_path = request_dir / filename
            file.save(str(input_path))

            # Check file size (additional check beyond Flask limit)
            if input_path.stat().st_size > 8 * 1024 * 1024:
                flash("File too large (maximum 8 MB)", "error")
                shutil.rmtree(request_dir, ignore_errors=True)
                return redirect(request.url)

            # Output GIF path
            output_filename = f"{input_path.stem}_meow.gif"
            output_path = output_dir / output_filename

            # Configure encoding
            config = EncodingConfig()
            config.redundancy = redundancy

            # Determine encoding mode and parameters
            use_duress = False
            carrier_images = None
            stego_level_val = 0

            if mode == "cat":
                # Cat mode: use bundled carrier image. encode_file now
                # auto-clamps stego_level to 1 when output is GIF (palette
                # quantisation can't preserve lsb_bits >= 2), so passing a
                # higher value is harmless — the user just gets a warning.
                # Pick level 2 (SUBTLE) here so the request to the encoder
                # documents intent; the actual embedding falls back to
                # VISIBLE for GIF output.
                cat_carrier = Path(__file__).parent.parent / "assets" / "demo_logo_eyes.gif"
                if cat_carrier.exists():
                    carrier_images = [cat_carrier]
                    stego_level_val = 2
                else:
                    flash("Warning: Cat carrier image not found, using plain QR codes", "warning")
            elif mode == "duress":
                # Duress + password-only is now supported via FIX-D3
                # mode_byte dispatch in unpack_manifest. Require the
                # duress password field; everything else uses the same
                # path as normal mode.
                use_duress = True
                if not duress_password:
                    flash("Duress mode requires a duress password", "error")
                    shutil.rmtree(request_dir, ignore_errors=True)
                    return redirect(request.url)
            elif mode == "schrodinger":
                # Note: schrodinger_encode_file is separate function
                flash(
                    "Schrödinger mode requires advanced CLI (not supported in web demo yet)",
                    "warning",
                )
                shutil.rmtree(request_dir, ignore_errors=True)
                return redirect(request.url)

            # Encode file
            try:
                stats = encode_file(
                    input_path=input_path,
                    output_path=output_path,
                    password=password,
                    config=config,
                    duress_password=duress_password if use_duress else None,
                    stego_level=stego_level_val,
                    carrier_images=carrier_images,
                    verbose=False,
                )

            except Exception as e:
                logger.exception("Encoding failed")
                flash("Encoding failed. Please check your input and try again.", "error")
                shutil.rmtree(request_dir, ignore_errors=True)
                shutil.rmtree(output_dir, ignore_errors=True)
                return redirect(request.url)

            # Generate download token
            token = str(uuid.uuid4())
            with download_tokens_lock:
                download_tokens[token] = {
                    "path": output_path,
                    "filename": output_filename,
                    "created": datetime.now(),
                    "mode": mode,
                    "original_filename": filename,
                }

            # Success! Show result page
            file_size = output_path.stat().st_size
            return render_template(
                "result.html",
                success=True,
                mode=mode,
                mode_emoji=get_mode_emoji(mode),
                output_filename=output_filename,
                file_size=format_size(file_size),
                download_token=token,
                original_filename=filename,
                qr_frames=stats.get("qr_frames", "N/A"),
                redundancy=f"{redundancy:.1f}×",
            )

        except Exception as e:
            logger.exception("Unexpected error in encode")
            flash("An unexpected error occurred. Please try again.", "error")
            return redirect(request.url)

    # GET request - show form
    return render_template("encode.html")


@app.route("/demo")
def demo_page():
    """Interactive demo page."""
    return render_template("demo.html")


@app.route("/webcam")
def webcam_page():
    """Webcam scanning page."""
    return render_template("webcam.html")


@app.route("/modes")
def modes_page():
    """All encryption modes showcase."""
    return render_template("modes.html")


@app.route("/cat-mode")
def cat_mode_page():
    """Interactive Cat Mode with blinking eyes."""
    return render_template("cat_mode.html")


@app.route("/cat-mode-download-video", methods=["POST"])
def cat_mode_download_video():
    """Save recorded video and return a download token."""
    import time as _time

    try:
        video = request.files.get("video")
        if not video:
            return json.dumps({"error": "No video file"}), 400

        token = secrets.token_hex(16)
        filename = f"cat_mode_{int(_time.time())}.webm"
        filepath = os.path.join(UPLOADS_DIR, f"{token}_{filename}")
        video.save(filepath)

        return (
            json.dumps(
                {
                    "success": True,
                    "download_url": f"/cat-mode-video/{token}/{filename}",
                    "filename": filename,
                }
            ),
            200,
            {"Content-Type": "application/json"},
        )
    except Exception as e:
        logger.exception("Cat mode video download failed")
        return json.dumps({"error": "Video processing failed"}), 500


@app.route("/cat-mode-video/<token>/<filename>")
def cat_mode_video_download(token, filename):
    """Serve a saved cat mode video for download."""
    from flask import send_file

    # WD-10: Validate token is hex (matches secrets.token_hex(16) format)
    if not token or not all(c in '0123456789abcdef' for c in token):
        return "Invalid token", 400
    filename = secure_filename(filename)
    if not filename:
        return "Invalid filename", 400
    filepath = os.path.join(UPLOADS_DIR, f"{token}_{filename}")
    # Defence-in-depth: ensure resolved path is under UPLOADS_DIR
    if not os.path.realpath(filepath).startswith(str(UPLOADS_DIR.resolve())):
        return "Invalid path", 400
    if not os.path.exists(filepath):
        return "Video not found or expired", 404
    return send_file(filepath, mimetype="video/webm", as_attachment=True, download_name=filename)


@app.route("/cat-mode-decode-video", methods=["POST"])
def cat_mode_decode_video():
    """
    Extract binary data from a Cat Mode video recording.
    Uses OpenCV to analyze eye brightness per frame and reconstruct the 2-bit-per-frame binary.

    Protocol:
    - Preamble: 8× ON(11), 8× OFF(00), 4× alternating (10,01,10,01)
    - Data: 2 bits per frame (left eye = bit[0], right eye = bit[1])
    - Postamble: 8× ON(11)
    """
    import cv2
    import numpy as np
    import tempfile
    import subprocess

    try:
        video = request.files.get("video")
        if not video:
            return json.dumps({"error": "No video file provided"}), 400

        # Save uploaded video
        with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as tmp:
            video.save(tmp.name)
            tmp_path = tmp.name

        # Convert to MJPEG AVI via ffmpeg (OpenCV can't read webm/VP9 reliably)
        avi_path = tmp_path + ".avi"
        try:
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-i",
                    tmp_path,
                    "-c:v",
                    "mjpeg",
                    "-q:v",
                    "2",
                    "-r",
                    "60",
                    avi_path,
                ],
                capture_output=True,
                timeout=120,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # If ffmpeg fails, try OpenCV directly as fallback
            # WARNING: OpenCV WebM/VP9 support is unreliable and drops frames!
            print(f"⚠️  ffmpeg conversion failed ({type(e).__name__}), falling back to OpenCV direct read")
            print("   Install ffmpeg for reliable Cat Mode video decoding: sudo apt-get install -y ffmpeg")
            avi_path = tmp_path

        try:
            result = _decode_cat_video(avi_path)
            return json.dumps(result), 200, {"Content-Type": "application/json"}
        finally:
            os.unlink(tmp_path)
            if avi_path != tmp_path and os.path.exists(avi_path):
                os.unlink(avi_path)

    except Exception as e:
        logger.exception("Cat mode video decode failed")
        return json.dumps({"error": "Video decode failed"}), 500, {"Content-Type": "application/json"}


def _decode_cat_video(video_path):
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

    # Step 2: Read all frames and measure green intensity per eye
    cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
    left_intensities = []
    right_intensities = []

    for i in range(total_frames):
        ret, frame = cap.read()
        if not ret:
            break
        left_intensities.append(_measure_green_intensity(frame, left_box))
        right_intensities.append(_measure_green_intensity(frame, right_box))

    cap.release()

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

    def refine_bp(runs_list, start_idx, end_idx, initial_bp):
        """Refine blink period estimate using median of single-blink run lengths.

        ~75% of runs in random 2-bit data are single-blink transitions.
        These give exact bp measurements. Using their median gives a much
        more accurate bp than the 16-blink preamble alone.

        Robustness: real (compressed / camera-captured) video produces spurious
        short runs at ON/OFF transitions — VP9/H.264 inter-frame blur and rolling
        shutter momentarily push a transitioning eye across the threshold. Those
        sub-blink runs were polluting the single-blink set and dragging the median
        well below the true period (observed: a correct 5.94-frame preamble
        estimate collapsing to 4.0 on VP9 video, inflating the decoded bit count
        ~1.5×). Two guards prevent that:
          1. Only count runs inside a plausible single-blink band around the
             current estimate, excluding the tiny transition artifacts.
          2. Never let the refined value stray far from the preamble-derived
             estimate, which is reliable (it spans exactly 16 known blinks).
        """
        bp = initial_bp
        for _ in range(3):
            lo, hi = 0.5 * bp, 1.5 * bp  # plausible single-blink window
            single_blink_lengths = [
                runs_list[i][2]
                for i in range(start_idx, end_idx)
                if lo <= runs_list[i][2] <= hi
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

    # Build bounding boxes with padding
    pad = 5
    left_mask = xs < split_x
    right_mask = xs >= split_x

    if np.sum(left_mask) < 10 or np.sum(right_mask) < 10:
        return None, None

    left_box = (
        max(0, int(np.min(xs[left_mask])) - pad),
        max(0, int(np.min(ys[left_mask])) - pad),
        min(w, int(np.max(xs[left_mask])) + pad),
        min(h, int(np.max(ys[left_mask])) + pad),
    )
    right_box = (
        max(0, int(np.min(xs[right_mask])) - pad),
        max(0, int(np.min(ys[right_mask])) - pad),
        min(w, int(np.max(xs[right_mask])) + pad),
        min(h, int(np.max(ys[right_mask])) + pad),
    )

    return left_box, right_box


def _measure_green_intensity(frame, box):
    """Measure average green channel intensity within a bounding box."""
    x1, y1, x2, y2 = box
    roi = frame[y1:y2, x1:x2]
    if roi.size == 0:
        return 0.0
    # Green channel is index 1 in BGR
    return float(roi[:, :, 1].mean())


@app.route("/cat-mode-encrypt-server", methods=["POST"])
def cat_mode_encrypt_server():
    """
    Server-side encryption for Cat Mode with full Argon2id + AES-256-GCM.
    Returns base64-encoded binary for eye blinking transmission.
    """
    try:
        import struct

        # Get form data
        message = request.form.get("message", "").strip()
        password = request.form.get("password", "").strip()

        if not message or not password:
            return json.dumps({"error": "Message and password are required"}), 400

        # Convert message to bytes
        message_bytes = message.encode("utf-8")

        # Encrypt with full Argon2id + AES-256-GCM
        # Returns: (compressed, sha256, salt, nonce, ciphertext, ephemeral_key, key_handle)
        # Disable length padding for Cat Mode - padding inflates small messages
        # (e.g. 17 bytes → 1024 bytes), making transmission 60× slower
        compressed, sha256_hash, salt, nonce, ciphertext, ephemeral_key, key_handle = (
            encrypt_file_bytes_production(
                raw=message_bytes,
                password=password,
                keyfile=None,
                receiver_public_key=None,  # No forward secrecy for Cat Mode
                use_length_padding=False,
            )
        )
        # Drop the key handle — we don't need the key after encryption
        try:
            get_handle_backend().drop(key_handle)
        except Exception:
            pass

        # Pack the encrypted data into a binary payload with AAD fields
        # Format: [orig_len (4B)] [comp_len (4B)] [sha256 (32B)] [salt (16B)] [nonce (12B)] [ciphertext (variable)]
        # Total header: 68 bytes
        orig_len = len(message_bytes)
        comp_len = len(compressed)
        header = struct.pack(">II", orig_len, comp_len) + sha256_hash + salt + nonce
        binary_payload = header + ciphertext

        # Convert to hex for efficient transmission
        # Hex is directly convertible to bits without the 33% overhead of base64→ASCII→bits
        payload_hex = binary_payload.hex()

        # Return as JSON
        return (
            json.dumps(
                {
                    "success": True,
                    "payload_hex": payload_hex,
                    "original_length": orig_len,
                    "encrypted_length": len(binary_payload),
                }
            ),
            200,
            {"Content-Type": "application/json"},
        )

    except Exception as e:
        logger.exception("Cat mode server encrypt failed")
        return json.dumps({"error": "Encryption failed"}), 500, {"Content-Type": "application/json"}


@app.route("/decode-cat-binary", methods=["POST"])
def decode_cat_binary():
    """Decode binary pattern from Cat Mode transmission."""
    try:
        import struct

        binary = request.form.get("binary", "").strip()
        password = request.form.get("password", "").strip()
        encryption_mode = request.form.get("encryption_mode", "server").strip()

        if not binary or not password:
            flash("Binary pattern and password are required", "error")
            return redirect(url_for("cat_mode_page"))

        # Validate binary
        if not all(c in "01" for c in binary):
            flash("Invalid binary pattern (must contain only 0s and 1s)", "error")
            return redirect(url_for("cat_mode_page"))

        # Convert binary to bytes (direct - each 8 bits = 1 byte)
        byte_chunks = [binary[i: i + 8] for i in range(0, len(binary), 8)]
        raw_bytes = bytes(int(byte, 2) for byte in byte_chunks if len(byte) == 8)

        try:
            # Payload is raw binary bytes (no base64 layer)
            binary_payload = raw_bytes

            # Extract components
            # Format: [orig_len (4B)] [comp_len (4B)] [sha256 (32B)] [salt (16B)] [nonce (12B)] [ciphertext]
            # Header: 68 bytes
            if len(binary_payload) < 68:
                flash("Invalid encrypted payload (too short)", "error")
                return redirect(url_for("cat_mode_page"))

            orig_len, comp_len = struct.unpack(">II", binary_payload[:8])
            # audit-phase-5-fix 5.5: reject absurd lengths before they reach the
            # decompression-limit calculation (avoids 40 GiB allocation ceiling).
            from meow_decoder.crypto import MAX_ORIG_LEN, MAX_COMP_LEN
            if orig_len > MAX_ORIG_LEN or comp_len > MAX_COMP_LEN:
                flash("Invalid encrypted payload (length bounds exceeded)", "error")
                return redirect(url_for("cat_mode_page"))
            sha256_hash = binary_payload[8:40]
            salt = binary_payload[40:56]
            nonce = binary_payload[56:68]
            ciphertext = binary_payload[68:]

            # Decrypt using decrypt_to_raw_production with full AAD
            decrypted_bytes = decrypt_to_raw_production(
                cipher=ciphertext,
                password=password,
                salt=salt,
                nonce=nonce,
                keyfile=None,
                orig_len=orig_len,
                comp_len=comp_len,
                sha256=sha256_hash,
            )

            # Convert bytes to string
            decoded_message = decrypted_bytes.decode("utf-8")
            flash("✅ Successfully decrypted with Argon2id + AES-256-GCM!", "success")
            return render_template("cat_mode.html", decoded_message=decoded_message)

        except Exception as e:
            logger.exception("Cat mode decryption failed")
            flash("Decryption failed. Please check your password and try again.", "error")
            return redirect(url_for("cat_mode_page"))

    except Exception as e:
        logger.exception("Cat binary decoding error")
        flash("Decoding error. Please check your input.", "error")

    return redirect(url_for("cat_mode_page"))


@app.route("/schrodinger", methods=["GET", "POST"])
def schrodinger_page():
    """Schrödinger Mode - Quantum dual-secret encoding."""
    if request.method == "POST":
        try:
            # Import here to avoid startup dependency
            from meow_decoder.schrodinger_encode import schrodinger_encode_file

            # Validate file uploads
            if "real_file" not in request.files or "decoy_file" not in request.files:
                flash("Both real and decoy files are required", "error")
                return redirect(request.url)

            real_file = request.files["real_file"]
            decoy_file = request.files["decoy_file"]

            if real_file.filename == "" or decoy_file.filename == "":
                flash("Please select both files", "error")
                return redirect(request.url)

            real_password = request.form.get("real_password", "").strip()
            decoy_password = request.form.get("decoy_password", "").strip()

            if not real_password or not decoy_password:
                flash("Both passwords are required", "error")
                return redirect(request.url)

            if real_password == decoy_password:
                flash("Real and decoy passwords must be different!", "error")
                return redirect(request.url)

            if len(real_password) < 8 or len(decoy_password) < 8:
                flash("Both passwords must be at least 8 characters", "error")
                return redirect(request.url)

            # Save uploaded files
            session_id = str(uuid.uuid4())
            session_dir = UPLOADS_DIR / session_id
            session_dir.mkdir(exist_ok=True)

            real_path = session_dir / secure_filename(real_file.filename)
            decoy_path = session_dir / secure_filename(decoy_file.filename)
            output_path = OUTPUTS_DIR / f"{session_id}_schrodinger.gif"

            real_file.save(real_path)
            decoy_file.save(decoy_path)

            # Encode with Schrödinger mode
            config = EncodingConfig(fps=10, redundancy=1.5)

            schrodinger_encode_file(
                real_input=real_path,
                decoy_input=decoy_path,
                output=output_path,
                real_password=real_password,
                decoy_password=decoy_password,
                config=config,
                auto_generate_decoy=False,
            )

            # Create download token
            token = str(uuid.uuid4())
            with download_tokens_lock:
                download_tokens[token] = {
                    "path": output_path,
                    "filename": "schrodinger_quantum.gif",
                    "created": datetime.now(),
                }

            flash(f"✅ Schrödinger encoding complete! Quantum superposition created.", "success")
            return redirect(url_for("download_file", token=token))

        except Exception as e:
            logger.exception("Schrödinger encoding error")
            flash("Encoding error. Please check your input and try again.", "error")
            return redirect(request.url)

    return render_template("schrodinger.html")


@app.route("/decode", methods=["GET", "POST"])
def decode_page():
    """Decoding page."""
    if request.method == "POST":
        try:
            # Validate file upload
            if "file" not in request.files:
                flash("No file uploaded", "error")
                return redirect(request.url)

            file = request.files["file"]
            if file.filename == "":
                flash("No file selected", "error")
                return redirect(request.url)

            if not allowed_file(file.filename, ALLOWED_GIF_EXTENSIONS):
                flash("Please upload a GIF file", "error")
                return redirect(request.url)

            # Get form parameters
            password = request.form.get("password", "")
            try_duress = request.form.get("try_duress") == "on"
            duress_password = request.form.get("duress_password", "") if try_duress else None

            # Setup directories
            request_dir = get_request_dir(UPLOADS_DIR)
            output_dir = get_request_dir(OUTPUTS_DIR)

            # Save uploaded GIF
            filename = secure_filename(file.filename)
            input_path = request_dir / filename
            file.save(str(input_path))

            # Decode to temporary output
            output_filename = "decoded_file"  # Will be renamed based on manifest
            output_path = output_dir / output_filename

            # Configure decoding
            config = DecodingConfig()

            # Attempt decode
            try:
                stats = decode_gif(
                    input_path=input_path,
                    output_path=output_path,
                    password=password,
                    config=config,
                    verbose=False,
                )

                # Get actual output file (decode_gif may add extension)
                if not output_path.exists():
                    # Check for output with extension
                    possible_outputs = list(output_dir.glob(f"{output_filename}*"))
                    if possible_outputs:
                        output_path = possible_outputs[0]
                    else:
                        raise FileNotFoundError("Decoding succeeded but output file not found")

                actual_filename = output_path.name

            except Exception as e:
                # Uniform error message (don't leak password accuracy)
                flash("Decoding failed. Please check your password and try again.", "error")
                shutil.rmtree(request_dir, ignore_errors=True)
                shutil.rmtree(output_dir, ignore_errors=True)
                return redirect(request.url)

            # Generate download token
            token = str(uuid.uuid4())
            with download_tokens_lock:
                download_tokens[token] = {
                    "path": output_path,
                    "filename": actual_filename,
                    "created": datetime.now(),
                }

            # Success!
            file_size = output_path.stat().st_size
            return render_template(
                "decode_result.html",
                success=True,
                output_filename=actual_filename,
                file_size=format_size(file_size),
                download_token=token,
                gif_filename=filename,
            )

        except Exception as e:
            # Uniform error message
            flash("Decoding failed. Please check your file and password.", "error")
            return redirect(request.url)

    # GET request - show form
    return render_template("decode.html")


@app.route("/decode-webcam", methods=["POST"])
def decode_webcam():
    """Decode data collected from webcam scanner."""
    try:
        payload = request.form.get("payload", "")
        password = request.form.get("password", "")

        if not payload:
            flash("No payload received from scanner", "error")
            return redirect(url_for("webcam_page"))

        # Setup directories
        request_dir = get_request_dir(UPLOADS_DIR)
        output_dir = get_request_dir(OUTPUTS_DIR)

        # Save payload to temp file
        import base64

        try:
            payload_bytes = base64.b64decode(payload)
        except:
            # Might be a single QR string
            payload_bytes = payload.encode()

        temp_input = request_dir / "scanned_data.bin"
        temp_input.write_bytes(payload_bytes)

        output_path = output_dir / "decoded_file"

        # Configure decoding
        config = DecodingConfig()

        # Attempt decode
        try:
            stats = decode_gif(
                input_path=temp_input,
                output_path=output_path,
                password=password,
                config=config,
                verbose=False,
            )

            # Get actual output file
            if not output_path.exists():
                possible_outputs = list(output_dir.glob("decoded_file*"))
                if possible_outputs:
                    output_path = possible_outputs[0]
                else:
                    raise FileNotFoundError("Decoding succeeded but output not found")

            actual_filename = output_path.name

        except Exception as e:
            flash("Decoding failed. Please check your password and try again.", "error")
            shutil.rmtree(request_dir, ignore_errors=True)
            shutil.rmtree(output_dir, ignore_errors=True)
            return redirect(url_for("webcam_page"))

        # Generate download token
        token = str(uuid.uuid4())
        with download_tokens_lock:
            download_tokens[token] = {
                "path": output_path,
                "filename": actual_filename,
                "created": datetime.now(),
            }

        # Success!
        file_size = output_path.stat().st_size
        return render_template(
            "decode_result.html",
            success=True,
            output_filename=actual_filename,
            file_size=format_size(file_size),
            download_token=token,
            gif_filename="webcam scan",
        )

    except Exception as e:
        flash("Unexpected error during webcam decode", "error")
        return redirect(url_for("webcam_page"))


@app.route("/download/<token>")
def download_file(token):
    """Download file by token."""
    # audit-followup 11.2: atomic read via .get() closes the check/read TOCTOU
    # race against cleanup_old_files() eviction.
    with download_tokens_lock:
        file_info = download_tokens.get(token)
    if file_info is None:
        flash("Download link expired or invalid", "error")
        return redirect(url_for("index"))

    file_path = file_info["path"]
    filename = file_info["filename"]

    if not file_path.exists():
        flash("File not found", "error")
        return redirect(url_for("index"))

    # Send file and cleanup
    response = send_file(
        file_path, as_attachment=True, download_name=filename, mimetype="application/octet-stream"
    )

    # Schedule cleanup after download — immediately purge files (WD-14)
    @response.call_on_close
    def cleanup():
        with download_tokens_lock:
            download_tokens.pop(token, None)
        try:
            if file_path.exists():
                file_path.unlink(missing_ok=True)
            if file_path.parent not in (OUTPUTS_DIR, UPLOADS_DIR):
                shutil.rmtree(file_path.parent, ignore_errors=True)
        except OSError:
            pass

    return response


def get_mode_emoji(mode):
    """Get emoji for encoding mode."""
    emojis = {"normal": "🔒", "cat": "😻", "duress": "⚠️", "schrodinger": "⚛️"}
    return emojis.get(mode, "🔒")


def format_size(size_bytes):
    """Format file size in human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


if __name__ == "__main__":
    import subprocess as _sp
    print("🐱 Meow Decoder Web Demo Starting...")
    print(f"   Instance directory: {INSTANCE_DIR.absolute()}")
    print(f"   Max file size: 8 MB (encode), 200 MB (video upload)")
    print(f"   Cat Mode: 😻 Enabled!")
    print(
        f"   Test Mode: {'✅ ON (fast Argon2id)' if os.environ.get('MEOW_TEST_MODE') else '🔒 OFF (production Argon2id)'}"
    )
    # Check ffmpeg availability (required for Cat Mode video decode)
    try:
        _sp.run(["ffmpeg", "-version"], capture_output=True, timeout=5, check=True)
        print("   ffmpeg:    ✅ Available (Cat Mode video decode ready)")
    except (FileNotFoundError, _sp.CalledProcessError, _sp.TimeoutExpired):
        print("   ffmpeg:    ⚠️  NOT FOUND — Cat Mode video upload/decode will be unreliable!")
        print("              Install with: sudo apt-get install -y ffmpeg")
    print()
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    app.run(debug=debug, host=host, port=5000, use_reloader=False)
