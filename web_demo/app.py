"""
🐱 Meow Decoder Web Demo
Simple Flask web interface for encoding and decoding files with Cat Mode support
"""

import json
import base64
import logging
from meow_decoder.crypto_backend import get_handle_backend
from meow_decoder.crypto import encrypt_file_bytes_production, decrypt_to_raw_production
from meow_decoder.cat_video import decode_cat_video
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


# The cat-mode video decoder lives in the dependency-free
# meow_decoder.cat_video module so it (and its golden fixtures) can be tested
# in CI without Flask. Alias kept for the route and web_demo integration tests.
_decode_cat_video = decode_cat_video

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
