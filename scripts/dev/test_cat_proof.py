#!/usr/bin/env python3
"""
test_cat_proof.py — Definitive proof that Cat Mode encode→video→decode works.

Run from repo root:
    MEOW_TEST_MODE=1 python test_cat_proof.py

What this tests:
    1. Encrypt a message (MEOW test-mode Argon2id + AES-256-GCM)
    2. Build the exact transmission binary the JS encoder sends
       (preamble + whitened payload + postamble)
    3. Render a synthetic video file (.avi) with green eye blinks
       encoding each 2-bit pair (same pixel layout the browser canvas produces)
    4. Feed that video to _decode_cat_video() — the real server decoder
    5. Decrypt the decoded binary and compare to original message

Tests 4 speeds: 200ms, 150ms, 100ms, 83ms
One short message per speed to keep runtime under 60 seconds.

Exit 0 = all pass, Exit 1 = any failure.
"""

import numpy as np
import cv2
import os
import sys
import struct
import tempfile
import time

os.environ["MEOW_TEST_MODE"] = "1"
sys.path.insert(0, "/workspaces/meow-decoder")
sys.path.insert(0, "/workspaces/meow-decoder/web_demo")


# ─── PROTOCOL (must match JS cat_mode.html exactly) ──────────────────────────

def whiten(binary_str: str) -> str:
    """LCG PRNG XOR whitening — seed 0x4D454F57 ('MEOW')."""
    seed = 0x4D454F57
    out = []
    for bit in binary_str:
        seed = ((seed * 1103515245) + 12345) & 0x7FFFFFFF
        out.append(str(int(bit) ^ ((seed >> 16) & 1)))
    return "".join(out)


def hex_to_binary(hex_str: str) -> str:
    return "".join(format(int(c, 16), "04b") for c in hex_str)


def build_transmission(payload_hex: str):
    """
    Returns (tx_binary, raw_binary).
    tx_binary = what gets transmitted (preamble + whitened + postamble).
    raw_binary = the un-whitened payload bits; this is what the decoder returns.
    """
    raw = hex_to_binary(payload_hex)
    whitened = whiten(raw)
    preamble = "11" * 8 + "00" * 8 + "10011001"   # 36 bits = 18 intervals
    postamble = "11" * 8                             # 16 bits = 8 intervals
    return preamble + whitened + postamble, raw


# ─── ENCRYPT ─────────────────────────────────────────────────────────────────

def encrypt_message(message: str, password: str) -> str:
    """Encrypt using meow_decoder.crypto (test-mode Argon2id). Returns hex payload."""
    from meow_decoder.crypto import encrypt_file_bytes

    raw = message.encode("utf-8")
    compressed, sha256_hash, salt, nonce, ciphertext, _, _ = encrypt_file_bytes(
        raw=raw,
        password=password,
        keyfile=None,
        receiver_public_key=None,
        use_length_padding=False,
    )
    header = struct.pack(">II", len(raw), len(compressed)) + sha256_hash + salt + nonce
    return (header + ciphertext).hex()


# ─── VIDEO GENERATION ─────────────────────────────────────────────────────────

# Minimal synthetic frame: 200 × 100 dark background with two bright-green
# rectangles — left eye (x 20-70, y 15-55) and right eye (x 130-180, y 15-55).
# Eye regions sit in upper 65% of frame so _detect_eye_regions_cv() finds them.
# Each rectangle has ≥ 1750 bright-green pixels, well above the 10-pixel minimum.

FRAME_W, FRAME_H = 200, 100
EYE_L = (20, 15, 70, 55)    # x1, y1, x2, y2
EYE_R = (130, 15, 180, 55)  # x1, y1, x2, y2
GREEN_PIXEL = (10, 200, 10)   # BGR — high saturation green
DARK_PIXEL = (0, 0, 0)


def _make_base_frame() -> np.ndarray:
    """Dark frame with both eyes ON (bright green)."""
    frame = np.zeros((FRAME_H, FRAME_W, 3), dtype=np.uint8)
    x1, y1, x2, y2 = EYE_L
    frame[y1:y2, x1:x2] = GREEN_PIXEL
    x1, y1, x2, y2 = EYE_R
    frame[y1:y2, x1:x2] = GREEN_PIXEL
    return frame


def _apply_eye_state(base: np.ndarray, left_on: bool, right_on: bool) -> np.ndarray:
    frame = base.copy()
    if not left_on:
        x1, y1, x2, y2 = EYE_L
        frame[y1:y2, x1:x2] = DARK_PIXEL
    if not right_on:
        x1, y1, x2, y2 = EYE_R
        frame[y1:y2, x1:x2] = DARK_PIXEL
    return frame


def generate_video(tx_binary: str, output_path: str, blink_ms: int, fps: int = 60):
    """
    Write an AVI video to output_path encoding tx_binary as dual-eye blinks.
    Each 2-bit pair = one blink interval of `blink_ms` ms = fps*blink_ms/1000 frames.
    """
    frames_per_blink = max(1, round(blink_ms * fps / 1000.0))
    base = _make_base_frame()

    # Pre-render all 4 possible eye states
    state_frames = {
        (b1, b2): _apply_eye_state(base, b1 == "1", b2 == "1")
        for b1 in "01"
        for b2 in "01"
    }

    fourcc = cv2.VideoWriter_fourcc(*"MJPG")
    writer = cv2.VideoWriter(output_path, fourcc, fps, (FRAME_W, FRAME_H))
    if not writer.isOpened():
        raise RuntimeError(f"VideoWriter failed to open: {output_path}")

    count = 0
    for i in range(0, len(tx_binary) - 1, 2):
        b1, b2 = tx_binary[i], tx_binary[i + 1]
        frame = state_frames[(b1, b2)]
        for _ in range(frames_per_blink):
            writer.write(frame)
            count += 1

    writer.release()
    return count


# ─── DECRYPT ─────────────────────────────────────────────────────────────────

def decrypt_binary(decoded_binary: str, password: str):
    """Decrypt bytes recovered from video, return (success, message_or_error)."""
    from meow_decoder.crypto import decrypt_to_raw

    if not all(c in "01" for c in decoded_binary):
        return False, "Invalid binary"

    chunks = [decoded_binary[i: i + 8] for i in range(0, len(decoded_binary), 8)]
    raw = bytes(int(c, 2) for c in chunks if len(c) == 8)

    if len(raw) < 68:
        return False, f"Too short: {len(raw)} bytes (need ≥ 68)"

    orig_len, comp_len = struct.unpack(">II", raw[:8])
    sha256_hash = raw[8:40]
    salt = raw[40:56]
    nonce = raw[56:68]
    ciphertext = raw[68:]

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


# ─── TEST RUNNER ─────────────────────────────────────────────────────────────

# Inline decode script — runs in a COMPLETELY SEPARATE Python process.
# It has NO access to payload_hex, expected_binary, or any encryption result.
# Only inputs: video file path (on disk) and nothing else.
# This simulates a real user uploading the video on a different machine.
_DECODE_SUBPROCESS_SCRIPT = """\
import sys, json, os
os.environ["MEOW_TEST_MODE"] = "1"
sys.path.insert(0, "/workspaces/meow-decoder")
sys.path.insert(0, "/workspaces/meow-decoder/web_demo")
# Force fresh import — no module-level caching from parent process
for mod in list(sys.modules.keys()):
    if "app" in mod or "meow" in mod:
        del sys.modules[mod]
from app import _decode_cat_video
result = _decode_cat_video(sys.argv[1])
print(json.dumps(result))
"""


def decode_video_isolated(vpath: str) -> dict:
    """
    Decode a video in a FRESH subprocess that knows NOTHING about how the
    video was created — only the file path on disk.
    This is the same situation as a real user uploading the video.
    """
    import subprocess as _sp
    import json as _json
    import shutil

    python = shutil.which("python3") or sys.executable
    # Use the venv python if available
    venv_py = "/workspaces/meow-decoder/.venv/bin/python"
    if os.path.exists(venv_py):
        python = venv_py

    proc = _sp.run(
        [python, "-c", _DECODE_SUBPROCESS_SCRIPT, vpath],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "MEOW_TEST_MODE": "1"},
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Decoder subprocess exited {proc.returncode}:\n{proc.stderr[-800:]}"
        )
    return _json.loads(proc.stdout.strip())


def run_test(speed_ms: int, message: str, password: str, test_id: str) -> dict:
    """
    Full pipeline for one test case.

    ISOLATION GUARANTEE:
      Steps 1-3 (encrypt + generate video) happen in THIS process.
      Step 4 (decode video) runs in a FRESH subprocess that only receives
        the path to the .avi file — it has no access to payload_hex,
        expected_binary, or any encryption state.
      Step 5-6 (decrypt + compare) happen in THIS process.
    """
    t0 = time.monotonic()

    # Step 1: Encrypt
    payload_hex = encrypt_message(message, password)
    expected_binary = hex_to_binary(payload_hex)

    # Step 2: Build transmission
    tx_binary, raw_binary = build_transmission(payload_hex)
    assert raw_binary == expected_binary

    # Step 3: Generate video — write to temp file, then FORGET payload_hex
    with tempfile.NamedTemporaryFile(suffix=".avi", delete=False) as tmp:
        vpath = tmp.name

    try:
        n_frames = generate_video(tx_binary, vpath, speed_ms)
        file_kb = os.path.getsize(vpath) // 1024

        # Step 4: ISOLATED decode — subprocess only knows vpath
        # payload_hex / expected_binary / tx_binary are NOT passed in
        del tx_binary, raw_binary  # Explicitly remove from scope — cannot leak
        result = decode_video_isolated(vpath)
    finally:
        os.unlink(vpath)

    decoded_binary = result["binary"]
    diag = result.get("diagnostics", {})

    # Step 5: Compare bits
    binary_match = decoded_binary == expected_binary
    bit_errors = sum(a != b for a, b in zip(decoded_binary, expected_binary)) if not binary_match else 0
    len_diff = len(decoded_binary) - len(expected_binary)

    # Step 6: Decrypt
    decrypt_ok, decrypt_result = decrypt_binary(decoded_binary, password)
    message_match = decrypt_ok and decrypt_result == message

    elapsed = time.monotonic() - t0

    return {
        "id": test_id,
        "speed_ms": speed_ms,
        "message": message,
        "password": password,
        "pass": message_match,
        "binary_match": binary_match,
        "bit_errors": bit_errors,
        "len_diff": len_diff,
        "expected_bits": len(expected_binary),
        "decoded_bits": len(decoded_binary),
        "decrypt_ok": decrypt_ok,
        "decrypt_message": decrypt_result if decrypt_ok else None,
        "decrypt_error": decrypt_result if not decrypt_ok else None,
        "n_video_frames": n_frames,
        "file_kb": file_kb,
        "method": diag.get("method", "?"),
        "bp_refined": diag.get("bp_refined", "?"),
        "fpb": round(speed_ms * 60 / 1000.0, 1),
        "elapsed_s": round(elapsed, 1),
    }


# ─── MAIN ────────────────────────────────────────────────────────────────────

# One message per speed — kept short to minimise video size.
# Must be ≥1 byte (encrypts to ~70B header + ~17B ciphertext = ~700 bits).
TESTS = [
    (200, "Hello!",  "passw0rd1"),
    (150, "Meow!!",  "secureP@2"),
    (100, "Cat???",  "catmode9!"),
    (83, "Test!!",  "longtest1"),
]

if __name__ == "__main__":
    print("=" * 70)
    print("  CAT MODE PROOF  —  encode → video → decode → decrypt → verify")
    print(f"  MEOW_TEST_MODE={os.environ.get('MEOW_TEST_MODE','0')}")
    print(f"  Testing {len(TESTS)} speeds with 1 message each")
    print()
    print("  *** DECODE RUNS IN A FRESH SUBPROCESS ***")
    print("  The decoder process only receives the .avi file path.")
    print("  It has ZERO access to payload_hex, expected bits, or")
    print("  any encryption state from this process — same isolation")
    print("  as a real user uploading a video on a different machine.")
    print("=" * 70)

    total_t0 = time.monotonic()
    results = []

    for i, (speed, msg, pw) in enumerate(TESTS):
        fpb = round(speed * 60 / 1000.0, 1)
        print(f"\n  [{i+1}/{len(TESTS)}] {speed}ms (FPB={fpb})  msg={msg!r}  pw={pw!r}")
        print(f"  {'─'*60}")
        try:
            r = run_test(speed, msg, pw, f"T{i+1}")
            results.append(r)

            # Detailed line-by-line output
            print(f"  ✦ Video:    {r['n_video_frames']} frames, {r['file_kb']} KB, {r['elapsed_s']}s")
            print(f"  ✦ Expected: {r['expected_bits']} bits")
            print(f"  ✦ Decoded:  {r['decoded_bits']} bits  (diff={r['len_diff']:+d})")
            print(f"  ✦ Method:   {r['method']}  bp_refined={r['bp_refined']}")
            print(f"  ✦ Errors:   {r['bit_errors']} bit errors")
            if r['decrypt_ok']:
                print(f"  ✦ Decrypt:  OK → {r['decrypt_message']!r}")
            else:
                print(f"  ✦ Decrypt:  FAIL — {r['decrypt_error']}")

            status = "✅ PASS" if r['pass'] else "❌ FAIL"
            print(f"\n  {status}: {speed}ms")

        except Exception as e:
            import traceback
            print(f"  ❌ EXCEPTION: {e}")
            traceback.print_exc()
            results.append({
                "id": f"T{i+1}", "speed_ms": speed, "message": msg,
                "pass": False, "bit_errors": -1, "len_diff": 0,
                "expected_bits": 0, "decoded_bits": 0,
                "decrypt_ok": False, "decrypt_error": str(e),
                "method": "exception", "bp_refined": "?",
                "fpb": round(speed * 60 / 1000.0, 1),
                "elapsed_s": 0, "n_video_frames": 0, "file_kb": 0,
            })

    total_elapsed = time.monotonic() - total_t0

    # ── Summary table ──────────────────────────────────────────────────────────
    print("\n\n" + "=" * 70)
    print("  RESULTS SUMMARY")
    print(f"  {'Speed':>6}  {'FPB':>5}  {'Bits':>8}  {'Err':>5}  {'Decrypt':>8}  {'Result':>12}  {'Time':>6}")
    print(f"  {'─'*6}  {'─'*5}  {'─'*8}  {'─'*5}  {'─'*8}  {'─'*12}  {'─'*6}")

    n_pass = 0
    for r in results:
        status = "✅ PASS" if r["pass"] else "❌ FAIL"
        if r["pass"]:
            n_pass += 1
        dec = "OK" if r.get("decrypt_ok") else "FAIL"
        print(
            f"  {r['speed_ms']:>4}ms  {r['fpb']:>5.1f}"
            f"  {r.get('decoded_bits',0):>5}/{r.get('expected_bits',0):<5}"
            f"  {r.get('bit_errors',0):>5}"
            f"  {dec:>8}"
            f"  {status:>12}"
            f"  {r.get('elapsed_s',0):>5.1f}s"
        )

    print("=" * 70)
    print(f"  PASSED: {n_pass}/{len(results)}   Total time: {total_elapsed:.1f}s")
    print("=" * 70)

    if n_pass == len(results):
        print("\n  ✅✅✅  ALL TESTS PASSED — Cat Mode pipeline is WORKING  ✅✅✅\n")
        sys.exit(0)
    else:
        print(f"\n  ❌  {len(results)-n_pass} test(s) FAILED\n")
        sys.exit(1)
