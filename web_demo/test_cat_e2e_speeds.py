#!/usr/bin/env python3
"""
E2E Cat Mode test: encrypt → generate video → [refresh] → upload video → decode
Tests all 5 blink speeds × 3 trials each = 15 total roundtrips.

Simulates the user's exact flow:
1. POST /cat-mode-encrypt-server → get payload_hex
2. Convert hex→binary, whiten (matching JS exactly)
3. Generate synthetic video with preamble/data/postamble eye blink frames
4. Write video as AVI (constant framerate, MJPEG)
5. NEW SESSION (simulate browser refresh — no carryover state)
6. POST /cat-mode-decode-video → get decoded binary
7. POST /decode-cat-binary with decoded binary + password → check decryption success
"""

import os
import re
import sys
import struct
import time
import tempfile
import requests
import numpy as np
import cv2
from PIL import Image

BASE_URL = "http://localhost:5000"
MESSAGE = "Hello from E2E Cat Mode test!"
PASSWORD = "testpassword123"

_CSRF_META_RE = re.compile(r'name="csrf-token" content="([0-9a-f]+)"')


def fetch_csrf_token(session: "requests.Session") -> str:
    """GET the cat-mode page to establish a session and read its CSRF token."""
    resp = session.get(f"{BASE_URL}/cat-mode")
    match = _CSRF_META_RE.search(resp.text)
    return match.group(1) if match else ""

SPEEDS_MS = [200, 150, 100, 83, 50]
TRIALS = 3
VIDEO_FPS = 60  # Match the MediaRecorder captureStream(60) setting

# Cat image dimensions (canvas size in JS)
CANVAS_W, CANVAS_H = 743, 417
CAT_IMAGE_PATH = os.path.join(os.path.dirname(__file__), "static", "MeowDecoderDemo.png")

# Preamble/postamble constants (must match JS)
PREAMBLE_ON = 8
PREAMBLE_OFF = 8
PREAMBLE_ALT = 4
PREAMBLE_LEN = PREAMBLE_ON + PREAMBLE_OFF + PREAMBLE_ALT
POSTAMBLE_LEN = 8


def hex_to_binary(hex_str):
    """Convert hex string to binary bits (4 bits per hex char). Matches JS hexToBinary."""
    binary = ""
    for ch in hex_str:
        binary += bin(int(ch, 16))[2:].zfill(4)
    return binary


def whiten(binary_str):
    """XOR with LCG PRNG. Matches both JS whitenBinary and Python whiten exactly."""
    seed = 0x4D454F57  # "MEOW"
    result = []
    for bit in binary_str:
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        mask = (seed >> 16) & 1
        result.append(str(int(bit) ^ mask))
    return "".join(result)


def prepare_cat_frames():
    """Load cat image, detect eye regions, pre-render 4 blink frames as BGR numpy arrays."""
    img = Image.open(CAT_IMAGE_PATH).convert("RGBA")
    img = img.resize((CANVAS_W, CANVAS_H), Image.LANCZOS)
    arr = np.array(img)

    # Detect green pixels (same logic as JS autoDetectEyeRegions)
    r, g, b, a = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2], arr[:, :, 3]
    green_mask = (g > 100) & (g > r * 1.3) & (a > 100)
    max_y = int(CANVAS_H * 0.65)
    green_mask[max_y:, :] = False

    coords = np.argwhere(green_mask)
    assert len(coords) >= 20, f"Only {len(coords)} green pixels found"
    ys, xs = coords[:, 0], coords[:, 1]

    # Find eye split
    min_x, max_x = int(xs.min()), int(xs.max())
    mid_start = min_x + int((max_x - min_x) * 0.35)
    mid_end = min_x + int((max_x - min_x) * 0.65)

    from collections import Counter
    col_counts = Counter(xs[(xs >= mid_start) & (xs <= mid_end)])
    split_x = min(col_counts, key=col_counts.get) if col_counts else (min_x + max_x) // 2

    pad = 5
    left_mask = xs < split_x
    right_mask = xs >= split_x

    left_box = (
        max(0, int(xs[left_mask].min()) - pad),
        max(0, int(ys[left_mask].min()) - pad),
        min(CANVAS_W, int(xs[left_mask].max()) + pad),
        min(CANVAS_H, int(ys[left_mask].max()) + pad),
    )
    right_box = (
        max(0, int(xs[right_mask].min()) - pad),
        max(0, int(ys[right_mask].min()) - pad),
        min(CANVAS_W, int(xs[right_mask].max()) + pad),
        min(CANVAS_H, int(ys[right_mask].max()) + pad),
    )

    def darken_eye(frame, box):
        """Darken green pixels in a bounding box (same as JS darkenEye)."""
        x1, y1, x2, y2 = box
        roi = frame[y1:y2 + 1, x1:x2 + 1]
        r_roi = roi[:, :, 0].astype(float)
        g_roi = roi[:, :, 1].astype(float)
        a_roi = roi[:, :, 3].astype(float)
        mask = (g_roi > 100) & (g_roi > r_roi * 1.3) & (a_roi > 100)
        roi[mask, 0] = 0  # R
        roi[mask, 1] = 0  # G
        roi[mask, 2] = 0  # B

    # Pre-render 4 frames
    frame_on = arr.copy()  # 11: both eyes green
    frame_off = arr.copy()  # 00: both eyes dark
    darken_eye(frame_off, left_box)
    darken_eye(frame_off, right_box)
    frame_01 = arr.copy()  # 01: left dark, right green
    darken_eye(frame_01, left_box)
    frame_10 = arr.copy()  # 10: left green, right dark
    darken_eye(frame_10, right_box)

    # Convert RGBA → BGR for OpenCV
    def to_bgr(rgba):
        rgb = rgba[:, :, :3]
        return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)

    return {
        (True, True): to_bgr(frame_on),
        (False, False): to_bgr(frame_off),
        (False, True): to_bgr(frame_01),
        (True, False): to_bgr(frame_10),
    }


def get_frame_state(idx, whitened_binary):
    """Get (left_on, right_on) for frame index. Matches JS getFrameState."""
    data_frames = (len(whitened_binary) + 1) // 2

    if idx < PREAMBLE_ON:
        return (True, True)
    if idx < PREAMBLE_ON + PREAMBLE_OFF:
        return (False, False)
    if idx < PREAMBLE_LEN:
        alt_idx = idx - PREAMBLE_ON - PREAMBLE_OFF
        return (True, False) if alt_idx % 2 == 0 else (False, True)

    data_idx = idx - PREAMBLE_LEN
    if data_idx < data_frames:
        bit_idx = data_idx * 2
        left_bit = whitened_binary[bit_idx] == "1"
        right_bit = (
            whitened_binary[bit_idx + 1] == "1" if bit_idx + 1 < len(whitened_binary) else False
        )
        return (left_bit, right_bit)

    # Postamble
    return (True, True)


def generate_video(whitened_binary, speed_ms, frames_dict):
    """Generate an AVI video file simulating the cat eye blink transmission."""
    data_frames = (len(whitened_binary) + 1) // 2
    total_frames = PREAMBLE_LEN + data_frames + POSTAMBLE_LEN

    # Each "blink frame" lasts speed_ms milliseconds.
    # At VIDEO_FPS, each blink frame = (speed_ms / 1000) * VIDEO_FPS video frames
    frames_per_blink = max(1, round(speed_ms / 1000.0 * VIDEO_FPS))

    tmp = tempfile.NamedTemporaryFile(suffix=".avi", delete=False)
    tmp_path = tmp.name
    tmp.close()

    fourcc = cv2.VideoWriter_fourcc(*"MJPG")
    writer = cv2.VideoWriter(tmp_path, fourcc, VIDEO_FPS, (CANVAS_W, CANVAS_H))

    for blink_idx in range(total_frames):
        state = get_frame_state(blink_idx, whitened_binary)
        frame_bgr = frames_dict[state]
        for _ in range(frames_per_blink):
            writer.write(frame_bgr)

    writer.release()
    return tmp_path


def run_single_test(speed_ms, trial, frames_dict):
    """Run one full encode → video → refresh → decode cycle."""
    result = {
        "speed_ms": speed_ms,
        "trial": trial,
        "encrypt_ok": False,
        "video_frames": 0,
        "decode_video_ok": False,
        "decode_binary_ok": False,
        "decrypted_message": None,
        "error": None,
        "diagnostics": {},
    }

    try:
        # ===== STEP 1: Encrypt via server =====
        session_encode = requests.Session()
        encode_csrf = fetch_csrf_token(session_encode)
        resp = session_encode.post(
            f"{BASE_URL}/cat-mode-encrypt-server",
            data={"message": MESSAGE, "password": PASSWORD},
            headers={"X-CSRF-Token": encode_csrf},
        )
        if resp.status_code != 200:
            result["error"] = f"Encrypt failed: HTTP {resp.status_code}"
            return result

        enc_data = resp.json()
        if "error" in enc_data:
            result["error"] = f"Encrypt error: {enc_data['error']}"
            return result

        payload_hex = enc_data["payload_hex"]
        result["encrypt_ok"] = True
        result["encrypted_length"] = enc_data.get("encrypted_length", 0)

        # ===== STEP 2: Whiten (same as JS) =====
        raw_binary = hex_to_binary(payload_hex)
        whitened = whiten(raw_binary)

        # ===== STEP 3: Generate video =====
        video_path = generate_video(whitened, speed_ms, frames_dict)
        file_size = os.path.getsize(video_path)
        data_frames_count = (len(whitened) + 1) // 2
        total_blink_frames = PREAMBLE_LEN + data_frames_count + POSTAMBLE_LEN
        frames_per_blink = max(1, round(speed_ms / 1000.0 * VIDEO_FPS))
        total_video_frames = total_blink_frames * frames_per_blink
        result["video_frames"] = total_video_frames
        result["video_size_kb"] = round(file_size / 1024, 1)
        result["data_bits"] = len(raw_binary)

        # ===== STEP 4: FRESH SESSION (simulate browser refresh) =====
        session_decode = requests.Session()

        # Visit the cat-mode page first (like refreshing the browser)
        refresh_resp = session_decode.get(f"{BASE_URL}/cat-mode")
        if refresh_resp.status_code != 200:
            result["error"] = f"Refresh failed: HTTP {refresh_resp.status_code}"
            os.unlink(video_path)
            return result
        match = _CSRF_META_RE.search(refresh_resp.text)
        decode_csrf = match.group(1) if match else ""

        # ===== STEP 5: Upload video for decode =====
        with open(video_path, "rb") as f:
            resp_video = session_decode.post(
                f"{BASE_URL}/cat-mode-decode-video",
                files={"video": ("test_transmission.avi", f, "video/x-msvideo")},
                headers={"X-CSRF-Token": decode_csrf},
            )
        os.unlink(video_path)

        if resp_video.status_code != 200:
            result["error"] = f"Video decode HTTP {resp_video.status_code}: {resp_video.text[:200]}"
            return result

        video_result = resp_video.json()
        if not video_result.get("success"):
            result["error"] = f"Video decode failed: {video_result.get('error', 'unknown')}"
            return result

        decoded_binary = video_result["binary"]
        result["decode_video_ok"] = True
        result["decoded_bits"] = len(decoded_binary)
        result["diagnostics"] = video_result.get("diagnostics", {})
        result["blink_period"] = video_result.get("blink_period")
        result["decode_method"] = video_result.get("diagnostics", {}).get("method", "?")

        # ===== STEP 6: Verify binary matches =====
        result["binary_match"] = decoded_binary == raw_binary
        if decoded_binary != raw_binary:
            # Find first difference
            min_len = min(len(decoded_binary), len(raw_binary))
            diff_pos = next((i for i in range(min_len) if decoded_binary[i] != raw_binary[i]), min_len)
            result["first_diff_bit"] = diff_pos
            result["len_diff"] = len(decoded_binary) - len(raw_binary)

        # ===== STEP 7: Submit for decryption (uses the fresh session) =====
        resp_decrypt = session_decode.post(
            f"{BASE_URL}/decode-cat-binary",
            data={
                "binary": decoded_binary,
                "password": PASSWORD,
                "encryption_mode": "server",
                "csrf_token": decode_csrf,
            },
            allow_redirects=False,  # Don't follow redirect so we can check flash
        )

        # The endpoint redirects. If success, the redirect page contains the decoded message.
        # If fail, it redirects with flash error.
        if resp_decrypt.status_code in (301, 302):
            # Follow redirect and check response body
            redirect_resp = session_decode.get(
                f"{BASE_URL}{resp_decrypt.headers.get('Location', '/cat-mode')}",
            )
            body = redirect_resp.text

            if "Successfully decrypted" in body:
                result["decode_binary_ok"] = True
                # Extract decoded message from the page
                if "decoded_message" in body or MESSAGE in body:
                    result["decrypted_message"] = MESSAGE
            elif "too short" in body:
                result["error"] = "Invalid encrypted payload (too short)"
            elif "Decryption failed" in body:
                result["error"] = "Decryption failed (wrong binary or password)"
            else:
                result["error"] = f"Unknown response after decrypt"
        elif resp_decrypt.status_code == 200:
            body = resp_decrypt.text
            if "Successfully decrypted" in body:
                result["decode_binary_ok"] = True
                result["decrypted_message"] = MESSAGE
            else:
                result["error"] = "Decryption response 200 but no success marker"
        else:
            result["error"] = f"Decrypt HTTP {resp_decrypt.status_code}"

    except Exception as e:
        result["error"] = f"Exception: {type(e).__name__}: {e}"

    return result


def main():
    print("=" * 80)
    print("Cat Mode E2E Test: encrypt → video → REFRESH → upload → decode")
    print(f"Message: {MESSAGE!r}")
    print(f"Password: {PASSWORD!r}")
    print(f"Speeds: {SPEEDS_MS} ms")
    print(f"Trials per speed: {TRIALS}")
    print(f"Video FPS: {VIDEO_FPS}")
    print("=" * 80)

    # Pre-render cat frames (once)
    print("\nLoading cat image and pre-rendering blink frames...")
    frames_dict = prepare_cat_frames()
    print(f"  4 frames ready: {list(frames_dict.keys())}")

    # Verify server is up
    try:
        r = requests.get(f"{BASE_URL}/cat-mode", timeout=5)
        assert r.status_code == 200, f"Server returned {r.status_code}"
        print(f"  Server OK at {BASE_URL}")
    except Exception as e:
        print(f"  ERROR: Server not reachable: {e}")
        sys.exit(1)

    results = []
    total = len(SPEEDS_MS) * TRIALS

    for speed_ms in SPEEDS_MS:
        print(f"\n{'─' * 70}")
        print(f"  Speed: {speed_ms}ms ({1000/speed_ms:.1f} blinks/sec)")
        print(f"{'─' * 70}")

        for trial in range(1, TRIALS + 1):
            idx = len(results) + 1
            print(f"\n  [{idx}/{total}] Trial {trial}/3 @ {speed_ms}ms ... ", end="", flush=True)
            t0 = time.time()

            result = run_single_test(speed_ms, trial, frames_dict)
            elapsed = time.time() - t0

            results.append(result)

            if result["decode_binary_ok"]:
                print(f"✅ PASS ({elapsed:.1f}s) "
                      f"[{result.get('data_bits', '?')} bits, "
                      f"binary_match={result.get('binary_match', '?')}, "
                      f"method={result.get('decode_method', '?')}]")
            else:
                print(f"❌ FAIL ({elapsed:.1f}s) — {result.get('error', 'unknown')}")
                if result.get("decoded_bits"):
                    print(f"         decoded={result['decoded_bits']} bits vs expected={result.get('data_bits', '?')}")
                    print(f"         binary_match={result.get('binary_match', '?')}, "
                          f"len_diff={result.get('len_diff', '?')}, "
                          f"first_diff={result.get('first_diff_bit', '?')}")
                diag = result.get("diagnostics", {})
                if diag:
                    print(f"         diag: {diag}")

    # ===== SUMMARY =====
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"{'Speed':>8} {'Trial':>6} {'Encrypt':>8} {'VidDec':>8} {'Decrypt':>8} {'Match':>7} {'Bits':>6} {'Method':>20} {'Error'}")
    print("-" * 110)

    pass_count = 0
    fail_count = 0
    for r in results:
        status_enc = "✅" if r["encrypt_ok"] else "❌"
        status_vid = "✅" if r["decode_video_ok"] else "❌"
        status_dec = "✅" if r["decode_binary_ok"] else "❌"
        match = "✅" if r.get("binary_match") else ("❌" if r.get("binary_match") is not None else "—")
        bits = str(r.get("decoded_bits", "—"))
        method = r.get("decode_method", "—")
        error = r.get("error", "") or ""

        if r["decode_binary_ok"]:
            pass_count += 1
        else:
            fail_count += 1

        print(f"{r['speed_ms']:>6}ms {r['trial']:>5}  {status_enc:>8} {status_vid:>8} {status_dec:>8} {match:>7} {bits:>6} {method:>20} {error}")

    print("-" * 110)
    print(f"\nTotal: {pass_count} PASS, {fail_count} FAIL out of {total}")

    # Per-speed summary
    print(f"\nPer-speed results:")
    for speed_ms in SPEEDS_MS:
        speed_results = [r for r in results if r["speed_ms"] == speed_ms]
        passes = sum(1 for r in speed_results if r["decode_binary_ok"])
        print(f"  {speed_ms:>4}ms: {passes}/{TRIALS} passed")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
