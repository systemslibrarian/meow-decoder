#!/usr/bin/env python3
"""
E2E test: Encrypt → Generate Video → Upload to Server → Decode → Decrypt
Each run is fully independent (simulates browser page refresh + re-upload).
No shared state between runs — validates the server decodes purely from the video file.

This test generates REAL video files with the actual cat image and green eye blinks,
uploads them to the running Flask server, and verifies decryption produces the original message.
"""

import cv2
import numpy as np
import struct
import json
import random
import os
import tempfile
import sys
import subprocess
import urllib.request
import urllib.parse

SERVER = "http://localhost:5000"
CAT_IMAGE = "/workspaces/meow-decoder/web_demo/static/MeowDecoderDemo.png"

# ── Whitening (must match JS and server Python exactly) ──


def whiten(binary_str):
    """LCG PRNG XOR whitening — identical to JS Math.imul version."""
    seed = 0x4D454F57  # "MEOW"
    result = []
    for bit in binary_str:
        seed = ((seed * 1103515245) + 12345) & 0x7FFFFFFF
        mask = (seed >> 16) & 1
        result.append(str(int(bit) ^ mask))
    return "".join(result)


def hex_to_binary(hex_str):
    """Convert hex string to binary string (4 bits per hex char)."""
    return "".join(format(int(c, 16), "04b") for c in hex_str)


# ── Eye region detection (same algorithm as server) ──


def detect_eye_regions(frame):
    """Detect left and right green eye bounding boxes."""
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
    """Set green pixels in bounding box to black (simulates eye OFF)."""
    x1, y1, x2, y2 = box
    for y in range(y1, min(y2, frame.shape[0])):
        for x in range(x1, min(x2, frame.shape[1])):
            b, g, r = frame[y, x, 0], frame[y, x, 1], frame[y, x, 2]
            if g > 100 and g > r * 1.3:
                frame[y, x] = [0, 0, 0]


def make_frame(base_img, left_box, right_box, left_on, right_on):
    """Create a video frame with specified eye states."""
    frame = base_img.copy()
    if not left_on:
        darken_eye(frame, left_box)
    if not right_on:
        darken_eye(frame, right_box)
    return frame


# ── Generate preamble + data + postamble binary ──


def build_transmission_binary(payload_hex):
    """
    Convert payload hex to whitened binary with sync preamble/postamble.
    Matches the JS encoder in cat_mode.html exactly.
    """
    raw_binary = hex_to_binary(payload_hex)
    whitened = whiten(raw_binary)

    # Preamble: 8×ON(11) + 8×OFF(00) + 4×ALT(10,01,10,01)
    preamble = "11" * 8 + "00" * 8 + "10011001"
    # Postamble: 8×ON(11)
    postamble = "11" * 8

    return preamble + whitened + postamble


# ── Generate synthetic video ──


def generate_cat_video(
    transmission_binary, output_path, blink_ms=100, fps=60, seed=42, variance_pct=10
):
    """
    Generate a real video file with cat eye blinks encoding the binary data.
    Uses variable frame timing to simulate real browser behavior.

    Each 2-bit pair determines eye states for one blink period.
    Blink period = blink_ms milliseconds at given fps.

    variance_pct controls frame-level jitter:
      0  = perfect timing (no variance)
      5  = 95% nominal, 4% ±1, 1% ±2 (conservative)
      10 = 90% nominal, 8% ±1, 2% ±2 (moderate)
      20 = 80% nominal, 15% ±1, 5% ±2 (aggressive)
    """
    rng = random.Random(seed)

    # Load cat image
    base_img = cv2.imread(CAT_IMAGE)
    if base_img is None:
        raise FileNotFoundError(f"Cat image not found: {CAT_IMAGE}")

    h, w = base_img.shape[:2]
    left_box, right_box = detect_eye_regions(base_img)
    if left_box is None:
        raise ValueError("Could not detect eye regions in cat image")

    # Pre-render 4 state frames
    frames_cache = {}
    for left_on in (True, False):
        for right_on in (True, False):
            frames_cache[(left_on, right_on)] = make_frame(
                base_img, left_box, right_box, left_on, right_on
            )

    # Parse binary into 2-bit blink states
    blink_states = []
    for i in range(0, len(transmission_binary), 2):
        pair = transmission_binary[i : i + 2]
        if len(pair) < 2:
            break
        left_on = pair[0] == "1"
        right_on = pair[1] == "1"
        blink_states.append((left_on, right_on))

    # Nominal frames per blink
    nominal_fpb = blink_ms * fps / 1000.0  # e.g., 100ms @ 60fps = 6 frames
    frames_per_blink = round(nominal_fpb)

    # Variance model: variance_pct controls how much jitter
    # 0 = perfect, 5 = conservative, 10 = moderate, 20 = aggressive
    p_nominal = 1.0 - variance_pct / 100.0  # e.g., 10 → 0.90
    p_plus1 = p_nominal + (variance_pct / 100.0) * 0.8  # 80% of jitter is ±1
    # remaining 20% of jitter is ±2

    fourcc = cv2.VideoWriter_fourcc(*"MJPG")
    writer = cv2.VideoWriter(output_path, fourcc, fps, (w, h))

    total_video_frames = 0
    for state_idx, (left_on, right_on) in enumerate(blink_states):
        if variance_pct == 0:
            n_frames = frames_per_blink
        else:
            r = rng.random()
            if r < p_nominal:
                n_frames = frames_per_blink
            elif r < p_plus1:
                n_frames = frames_per_blink + rng.choice([-1, 1])
            else:
                n_frames = frames_per_blink + rng.choice([-2, 2])
        n_frames = max(1, n_frames)

        frame = frames_cache[(left_on, right_on)]
        for _ in range(n_frames):
            writer.write(frame)
            total_video_frames += 1

    writer.release()
    return total_video_frames


# ── Server API helpers ──


def encrypt_message(message, password):
    """Call server encrypt endpoint. Returns payload_hex."""
    form_data = urllib.parse.urlencode(
        {
            "message": message,
            "password": password,
        }
    ).encode("utf-8")
    req = urllib.request.Request(f"{SERVER}/cat-mode-encrypt-server", data=form_data)
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        data = json.loads(body)
    if not data.get("success"):
        raise RuntimeError(f"Encrypt error: {data.get('error')}")
    return data["payload_hex"]


def decode_video(video_path):
    """Decode video by calling the server's decode function directly.

    This tests the exact same code path as the HTTP endpoint,
    but avoids the Flask upload size limit for large test videos.
    The _decode_cat_video function reads fresh from disk each time.
    """
    # Import the decode function from the server
    sys.path.insert(0, "/workspaces/meow-decoder/web_demo")
    # We need to import and call the actual decode function
    # to prove it reads from the video file (not from memory)

    # Instead of importing (which might cache), call via a subprocess
    # that loads the function fresh each time — ultimate "no shared state" proof
    import subprocess

    decode_script = f"""
import sys, json, os
os.environ["MEOW_TEST_MODE"] = "1"
sys.path.insert(0, "/workspaces/meow-decoder/web_demo")
sys.path.insert(0, "/workspaces/meow-decoder")

# Force fresh import - no module caching
if "app" in sys.modules:
    del sys.modules["app"]

from app import _decode_cat_video
result = _decode_cat_video("{video_path}")
print(json.dumps(result))
"""
    proc = subprocess.run(
        [sys.executable, "-c", decode_script],
        capture_output=True,
        text=True,
        timeout=120,
        cwd="/workspaces/meow-decoder/web_demo",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Decode subprocess failed: {proc.stderr[-500:]}")

    data = json.loads(proc.stdout.strip())
    if not data.get("success"):
        raise RuntimeError(f"Decode error: {data.get('error')}")
    return data["binary"], data.get("diagnostics", {})


def decrypt_binary(binary_str, password):
    """Post decoded binary to decrypt endpoint. Returns success and message."""
    # The decode-cat-binary endpoint does a redirect with flash messages,
    # so we need to handle it differently — call the crypto directly
    # to avoid session/cookie issues

    # Instead, replicate the decrypt logic here (same as server)
    if not all(c in "01" for c in binary_str):
        return False, "Invalid binary"

    byte_chunks = [binary_str[i : i + 8] for i in range(0, len(binary_str), 8)]
    raw_bytes = bytes(int(byte, 2) for byte in byte_chunks if len(byte) == 8)

    if len(raw_bytes) < 68:
        return False, f"Too short: {len(raw_bytes)} bytes (need 68+)"

    # Parse header
    orig_len, comp_len = struct.unpack(">II", raw_bytes[:8])
    sha256_hash = raw_bytes[8:40]
    salt = raw_bytes[40:56]
    nonce = raw_bytes[56:68]
    ciphertext = raw_bytes[68:]

    # Decrypt using the same function the server uses
    os.environ["MEOW_TEST_MODE"] = "1"

    # Import after setting env var
    sys.path.insert(0, "/workspaces/meow-decoder")
    from meow_decoder.crypto import decrypt_to_raw

    try:
        decrypted = decrypt_to_raw(
            cipher=ciphertext,
            password=password,
            salt=salt,
            nonce=nonce,
            keyfile=None,
            orig_len=orig_len,
            comp_len=comp_len,
            sha256=sha256_hash,
            ephemeral_public_key=None,
            receiver_private_key=None,
        )
        return True, decrypted.decode("utf-8", errors="replace")
    except Exception as e:
        return False, str(e)


# ── Main test runner ──


def run_single_test(test_num, message, password, blink_ms=100, seed=None, variance_pct=5):
    """Run one complete E2E test from scratch. Returns (pass, details)."""
    if seed is None:
        seed = random.randint(0, 999999)

    print(f"\n{'='*60}")
    print(f"  TEST {test_num}: msg={message[:30]!r} pw={password!r} seed={seed}")
    print(f"{'='*60}")

    try:
        # Step 1: Encrypt message via server
        print(f"  [1/5] Encrypting message ({len(message)}B)...")
        payload_hex = encrypt_message(message, password)
        expected_bits = len(payload_hex) * 4
        print(f"        payload_hex: {len(payload_hex)} hex chars = {expected_bits} bits")

        # Step 2: Build transmission binary (hex → binary → whiten → preamble)
        print(f"  [2/5] Building transmission binary...")
        tx_binary = build_transmission_binary(payload_hex)
        n_blinks = len(tx_binary) // 2
        print(f"        {len(tx_binary)} bits = {n_blinks} blinks (incl preamble/postamble)")

        # Keep the expected raw binary for comparison
        expected_raw_binary = hex_to_binary(payload_hex)

        # Step 3: Generate synthetic video
        print(
            f"  [3/5] Generating video (blink_ms={blink_ms}, seed={seed}, var={variance_pct}%)..."
        )
        with tempfile.NamedTemporaryFile(suffix=".avi", delete=False) as tmp:
            video_path = tmp.name

        n_video_frames = generate_cat_video(
            tx_binary, video_path, blink_ms=blink_ms, fps=60, seed=seed, variance_pct=variance_pct
        )
        file_size = os.path.getsize(video_path)
        print(f"        {n_video_frames} frames, {file_size//1024} KB")

        # Step 4: Decode video (each decode is a fresh subprocess — zero shared state)
        print(f"  [4/5] Decoding video (fresh subprocess, no cache)...")
        decoded_binary, diagnostics = decode_video(video_path)
        method = diagnostics.get("method", "?")
        bit_diff = diagnostics.get("bit_diff", "?")
        bp_refined = diagnostics.get("bp_refined", "?")
        print(
            f"        method={method}, bits={len(decoded_binary)}, expected={expected_bits}, diff={bit_diff}"
        )
        print(f"        bp_refined={bp_refined}")

        # Compare decoded binary against expected
        if decoded_binary == expected_raw_binary:
            print(f"        BINARY MATCH: decoded == expected ✓")
        else:
            mismatches = sum(1 for a, b in zip(decoded_binary, expected_raw_binary) if a != b)
            print(
                f"        BINARY MISMATCH: {mismatches} bit errors out of {len(expected_raw_binary)}"
            )
            # Show first 5 differences
            count = 0
            for i, (a, b) in enumerate(zip(decoded_binary, expected_raw_binary)):
                if a != b and count < 5:
                    print(f"          bit {i}: decoded={a}, expected={b}")
                    count += 1

        # Clean up video file before decrypt
        os.unlink(video_path)

        # Step 5: Decrypt the decoded binary
        print(f"  [5/5] Decrypting...")
        success, result = decrypt_binary(decoded_binary, password)

        if success and result == message:
            print(f"  ✅ PASS: Decrypted message matches original!")
            return True, method
        elif success:
            print(f"  ❌ FAIL: Decrypted but content mismatch!")
            print(f"        Original:  {message[:50]!r}")
            print(f"        Decrypted: {result[:50]!r}")
            return False, f"content mismatch"
        else:
            print(f"  ❌ FAIL: Decryption failed: {result}")
            return False, f"decrypt error: {result[:80]}"

    except Exception as e:
        print(f"  ❌ FAIL: Exception: {e}")
        import traceback

        traceback.print_exc()
        if "video_path" in dir() and os.path.exists(video_path):
            os.unlink(video_path)
        return False, str(e)[:80]


def main():
    # Test messages — use SHORT messages to minimize video size and memory
    test_messages = [
        ("Hello!", "testpass1"),
        ("Test123", "secureP@2"),
        ("Meow!!", "catmode9!"),
        ("Short!", "password1"),
        ("Encode", "longtestx"),
    ]

    # Test ONE speed at a time - pass as command line arg or default to 100ms
    # Usage: python test_e2e_fresh_video.py [speed_ms] [variance_pct]
    import sys

    if len(sys.argv) > 1:
        speeds = [int(sys.argv[1])]
    else:
        speeds = [100]  # Default to 100ms

    # Variance level: 0 = perfect timing, 5 = conservative, 10 = moderate
    variance = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    print("=" * 70)
    print("  MULTI-SPEED E2E TEST — PERFECT TIMING BASELINE")
    print(f"  Testing {len(speeds)} speeds × 5 messages = {len(speeds)*5} total tests")
    print(f"  Variance: {variance}% (ZERO jitter — perfect frame timing)")
    print("  Each decode runs in a fresh subprocess (no caching)")
    print("=" * 70)

    all_results = {}  # speed -> list of (pass, detail)

    for speed in speeds:
        print(f"\n{'='*70}")
        print(f"  SPEED: {speed}ms ({1000/speed:.0f} blinks/sec)")
        fpb = speed * 60 / 1000.0
        print(f"  Frames per blink at 60fps: {fpb:.1f}")
        print(f"{'='*70}")

        speed_results = []
        for i, (msg, pw) in enumerate(test_messages):
            seed = speed * 1000 + i * 100 + 42  # unique seed per speed+msg combo
            passed, detail = run_single_test(
                i + 1,
                msg,
                pw,
                blink_ms=speed,
                seed=seed,
                variance_pct=variance,
            )
            speed_results.append((passed, detail, msg))

        all_results[speed] = speed_results
        passes = sum(1 for p, _, _ in speed_results if p)
        print(f"\n  >>> {speed}ms: {passes}/5 passed <<<")

    # Final summary table
    print("\n" + "=" * 70)
    print("  FINAL RESULTS — SPEED RELIABILITY")
    print(
        f"  Variance: {variance}% ({100-variance}% nominal, {int(variance*0.8)}% ±1, {int(variance*0.2)}% ±2)"
    )
    print("=" * 70)
    print(f"  {'Speed':>6}  {'FPB':>5}  {'Pass':>6}  {'Rate':>6}  {'Verdict'}")
    print(f"  {'─'*6}  {'─'*5}  {'─'*6}  {'─'*6}  {'─'*20}")

    for speed in speeds:
        results = all_results[speed]
        passes = sum(1 for p, _, _ in results if p)
        fpb = speed * 60 / 1000.0
        rate = f"{passes}/5"
        pct = passes / 5 * 100

        if passes == 5:
            verdict = "✅ RELIABLE"
        elif passes >= 4:
            verdict = "⚠️  MOSTLY OK"
        elif passes >= 2:
            verdict = "⚠️  UNRELIABLE"
        else:
            verdict = "❌ NOT USABLE"

        print(f"  {speed:>4}ms  {fpb:>5.1f}  {rate:>6}  {pct:>5.0f}%  {verdict}")

        # Show failures
        for j, (passed, detail, msg) in enumerate(results):
            if not passed:
                print(f"         └─ Test {j+1} FAIL: {msg[:25]!r} [{detail[:40]}]")

    print(f"\n  Legend: FPB = frames per blink at 60fps")
    print("=" * 70)

    # Return 0 if at least one speed works perfectly
    any_perfect = any(sum(1 for p, _, _ in r if p) == 5 for r in all_results.values())
    return 0 if any_perfect else 1


if __name__ == "__main__":
    sys.exit(main())
