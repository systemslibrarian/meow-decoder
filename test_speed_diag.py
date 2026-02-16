#!/usr/bin/env python3
"""
Diagnostic test: directly trace decoder behavior at different speeds.
Bypasses HTTP and subprocess for fast iteration.
"""

import cv2
import numpy as np
import struct
import json
import random
import os
import sys
import tempfile

sys.path.insert(0, "/workspaces/meow-decoder/web_demo")
sys.path.insert(0, "/workspaces/meow-decoder")
os.environ["MEOW_TEST_MODE"] = "1"

CAT_IMAGE = "/workspaces/meow-decoder/web_demo/static/MeowDecoderDemo.png"


def whiten(binary_str):
    seed = 0x4D454F57
    result = []
    for bit in binary_str:
        seed = ((seed * 1103515245) + 12345) & 0x7FFFFFFF
        mask = (seed >> 16) & 1
        result.append(str(int(bit) ^ mask))
    return "".join(result)


def hex_to_binary(hex_str):
    return "".join(format(int(c, 16), "04b") for c in hex_str)


def detect_eye_regions(frame):
    h, w = frame.shape[:2]
    hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
    lower_green = np.array([35, 50, 80])
    upper_green = np.array([85, 255, 255])
    green_mask = cv2.inRange(hsv, lower_green, upper_green)
    max_y = int(h * 0.65)
    green_mask[max_y:, :] = 0
    coords = np.argwhere(green_mask > 0)
    if len(coords) < 20:
        return None, None
    ys, xs = coords[:, 0], coords[:, 1]
    min_x, max_x = int(np.min(xs)), int(np.max(xs))
    mid_start = min_x + int((max_x - min_x) * 0.35)
    mid_end = min_x + int((max_x - min_x) * 0.65)
    min_count = float("inf")
    split_x = (min_x + max_x) // 2
    for x in range(mid_start, mid_end + 1):
        count = np.sum(xs == x)
        if count < min_count:
            min_count = count
            split_x = x
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


def darken_eye(frame, box):
    x1, y1, x2, y2 = box
    for y in range(y1, min(y2, frame.shape[0])):
        for x in range(x1, min(x2, frame.shape[1])):
            b, g, r = frame[y, x, 0], frame[y, x, 1], frame[y, x, 2]
            if g > 100 and g > r * 1.3:
                frame[y, x] = [0, 0, 0]


def make_frame(base_img, left_box, right_box, left_on, right_on):
    frame = base_img.copy()
    if not left_on:
        darken_eye(frame, left_box)
    if not right_on:
        darken_eye(frame, right_box)
    return frame


def encrypt_msg(message, password):
    """Encrypt using crypto directly."""
    from meow_decoder.crypto import encrypt_file_bytes

    message_bytes = message.encode("utf-8")
    compressed, sha256_hash, salt, nonce, ciphertext, _, _ = encrypt_file_bytes(
        raw=message_bytes,
        password=password,
        keyfile=None,
        receiver_public_key=None,
        use_length_padding=False,
    )
    orig_len = len(message_bytes)
    comp_len = len(compressed)
    header = struct.pack(">II", orig_len, comp_len) + sha256_hash + salt + nonce
    binary_payload = header + ciphertext
    return binary_payload.hex()


def build_tx(payload_hex):
    raw = hex_to_binary(payload_hex)
    whitened = whiten(raw)
    preamble = "11" * 8 + "00" * 8 + "10011001"
    postamble = "11" * 8
    return preamble + whitened + postamble


def gen_video(tx_binary, output_path, blink_ms, fps=60):
    """Generate PERFECT (zero variance) video."""
    base_img = cv2.imread(CAT_IMAGE)
    h, w = base_img.shape[:2]
    left_box, right_box = detect_eye_regions(base_img)

    frames_cache = {}
    for lo in (True, False):
        for ro in (True, False):
            frames_cache[(lo, ro)] = make_frame(base_img, left_box, right_box, lo, ro)

    blink_states = []
    for i in range(0, len(tx_binary), 2):
        pair = tx_binary[i : i + 2]
        if len(pair) < 2:
            break
        blink_states.append((pair[0] == "1", pair[1] == "1"))

    fpb = round(blink_ms * fps / 1000.0)

    fourcc = cv2.VideoWriter_fourcc(*"MJPG")
    writer = cv2.VideoWriter(output_path, fourcc, fps, (w, h))

    n_total = 0
    for lo, ro in blink_states:
        frame = frames_cache[(lo, ro)]
        for _ in range(fpb):
            writer.write(frame)
            n_total += 1
    writer.release()
    return n_total, fpb


def test_speed(speed_ms, msg="Test!!", pw="password1"):
    """Test a single speed and return detailed diagnostics."""
    # Encrypt
    payload_hex = encrypt_msg(msg, pw)
    expected_bits = len(payload_hex) * 4
    expected_raw = hex_to_binary(payload_hex)

    # Build transmission
    tx = build_tx(payload_hex)
    n_blinks = len(tx) // 2

    # Generate video
    with tempfile.NamedTemporaryFile(suffix=".avi", delete=False) as tmp:
        vpath = tmp.name
    n_frames, fpb = gen_video(tx, vpath, speed_ms)

    # Decode using the actual server function
    from app import _decode_cat_video

    result = _decode_cat_video(vpath)
    os.unlink(vpath)

    decoded = result["binary"]
    diag = result.get("diagnostics", {})
    bp_refined = diag.get("bp_refined", "?")
    method = diag.get("method", "?")

    match = decoded == expected_raw
    if not match:
        errors = sum(1 for a, b in zip(decoded, expected_raw) if a != b)
        len_diff = len(decoded) - len(expected_raw)
    else:
        errors = 0
        len_diff = 0

    return {
        "match": match,
        "errors": errors,
        "len_diff": len_diff,
        "expected_bits": expected_bits,
        "decoded_bits": len(decoded),
        "bp_refined": bp_refined,
        "method": method,
        "fpb_used": fpb,
        "n_blinks": n_blinks,
        "n_frames": n_frames,
    }


def main():
    # Speeds to test: focus on integer FPB values at 60fps
    # FPB = speed_ms * 60 / 1000
    # speed_ms = FPB * 1000 / 60
    # FPB 3 → 50ms, FPB 4 → 66.7ms, FPB 5 → 83.3ms, FPB 6 → 100ms
    # FPB 7 → 116.7ms, FPB 8 → 133.3ms, FPB 9 → 150ms, FPB 10 → 166.7ms
    # FPB 12 → 200ms, FPB 15 → 250ms, FPB 18 → 300ms

    messages = [
        ("Test!!", "password1"),
        ("Hello!", "secureP@2"),
        ("Meow!!", "catmode9!"),
        ("Short!", "longtest1"),
        ("ABCDEF", "mypasswd!"),
    ]

    # Test integer-FPB speeds
    speeds = [50, 67, 83, 100, 117, 133, 150, 167, 200, 250, 300]

    print("=" * 80)
    print("  SPEED DIAGNOSTIC — ZERO VARIANCE, DIRECT DECODE")
    print(f"  Testing {len(speeds)} speeds × {len(messages)} messages")
    print("=" * 80)

    results_table = {}

    for speed in speeds:
        fpb = round(speed * 60 / 1000.0)
        passes = 0
        total_errors = 0
        details = []

        for i, (msg, pw) in enumerate(messages):
            r = test_speed(speed, msg, pw)
            if r["match"]:
                passes += 1
            else:
                total_errors += r["errors"]
            details.append(r)

        results_table[speed] = (passes, total_errors, fpb, details)

        status = "✅" if passes == 5 else "⚠️" if passes >= 3 else "❌"
        print(
            f"  {speed:4d}ms (FPB={fpb:2d}): {passes}/5 {status}  "
            f"bp_refined={details[0]['bp_refined']}  method={details[0]['method']}"
        )

        if passes < 5:
            for i, r in enumerate(details):
                if not r["match"]:
                    print(
                        f"    └─ msg #{i+1}: {r['errors']} bit errors, "
                        f"decoded={r['decoded_bits']} expected={r['expected_bits']} "
                        f"diff={r['len_diff']}"
                    )

    # Summary
    print("\n" + "=" * 80)
    print("  SUMMARY")
    print(f"  {'Speed':>6} {'FPB':>4} {'Pass':>5} {'Errors':>7} {'Status'}")
    print(f"  {'─'*6} {'─'*4} {'─'*5} {'─'*7} {'─'*12}")
    for speed in speeds:
        passes, errors, fpb, _ = results_table[speed]
        status = "✅ RELIABLE" if passes == 5 else "⚠️ PARTIAL" if passes >= 3 else "❌ BROKEN"
        print(f"  {speed:4d}ms {fpb:4d}   {passes}/5  {errors:6d}   {status}")
    print("=" * 80)


if __name__ == "__main__":
    main()
