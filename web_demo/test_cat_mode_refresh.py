#!/usr/bin/env python3
"""
Integration test: Cat Mode "download video → refresh → decrypt" flow.

Simulates the full user journey using Flask's built-in test client:
  1. Encrypt a message using test-mode crypto (Argon2id, no Rust required)
  2. Build a synthetic video encoding the binary payload
  3. Save the recorded video via /cat-mode-download-video
  4. Simulate a page refresh (new request session)
  5. Fetch the saved video back via /cat-mode-video/<token>/<filename>
  6. Upload the saved video via /cat-mode-decode-video  → extracts binary
  7. Decrypt the extracted binary using test-mode crypto
  8. Verify the decrypted message matches the original

This test proves that the post-refresh decrypt flow works correctly
without relying on sessionStorage or any shared in-memory state.

Note: The Flask endpoints /cat-mode-encrypt-server and /decode-cat-binary
use the Rust handle backend (meow_crypto_rs) which is only available in
production. These tests exercise the same encryption logic directly using
the test-mode Python crypto API (MEOW_TEST_MODE=1), which is equivalent
for correctness testing.
"""

import io
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

import cv2
import numpy as np
import pytest

# Ensure both the web_demo dir and repo root are on the path
_HERE = Path(__file__).parent
_REPO_ROOT = _HERE.parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_REPO_ROOT))

# Use fast Argon2id params for tests (also disables the production-mode guard
# on encrypt_file_bytes / decrypt_to_raw so we don't need the Rust backend)
os.environ["MEOW_TEST_MODE"] = "1"

from meow_decoder.crypto import encrypt_file_bytes, decrypt_to_raw  # noqa: E402
import app as flask_app  # noqa: E402  (must be after env var is set)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _whiten(binary_str: str) -> str:
    """XOR whitening — must match JavaScript encoder exactly."""
    seed = 0x4D454F57  # "MEOW"
    result = []
    for bit in binary_str:
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        mask = (seed >> 16) & 1
        result.append(str(int(bit) ^ mask))
    return "".join(result)


def _hex_to_binary(hex_str: str) -> str:
    return "".join(format(int(c, 16), "04b") for c in hex_str)


def _build_transmission_binary(payload_hex: str) -> str:
    """Build full preamble+data+postamble binary, matching the JS encoder."""
    raw = _hex_to_binary(payload_hex)
    whitened = _whiten(raw)
    preamble = "11" * 8 + "00" * 8 + "10011001"
    postamble = "11" * 8
    return preamble + whitened + postamble


def _encrypt_message(message: str, password: str):
    """
    Encrypt a message using test-mode crypto (no Rust backend required).

    Returns (binary_payload_bytes, payload_hex) matching the format produced
    by the /cat-mode-encrypt-server Flask endpoint.
    """
    message_bytes = message.encode("utf-8")
    compressed, sha256_hash, salt, nonce, ciphertext, _ephemeral_key, _raw_key = (
        encrypt_file_bytes(
            raw=message_bytes,
            password=password,
            keyfile=None,
            receiver_public_key=None,
            use_length_padding=False,
        )
    )
    orig_len = len(message_bytes)
    comp_len = len(compressed)
    header = struct.pack(">II", orig_len, comp_len) + sha256_hash + salt + nonce
    binary_payload = header + ciphertext
    return binary_payload, binary_payload.hex()


def _decrypt_binary(extracted_binary: str, password: str) -> str:
    """
    Decrypt a binary string produced by the video decode step.

    Replicates the logic of the /decode-cat-binary Flask endpoint but using
    the test-mode Python crypto API (no Rust handle backend required).
    """
    raw_bytes = bytes(
        int(extracted_binary[i: i + 8], 2)
        for i in range(0, len(extracted_binary) - 7, 8)
    )

    orig_len, comp_len = struct.unpack(">II", raw_bytes[:8])
    sha256_hash = raw_bytes[8:40]
    salt = raw_bytes[40:56]
    nonce = raw_bytes[56:68]
    ciphertext = raw_bytes[68:]

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
    return decrypted.decode("utf-8")


def _generate_synthetic_video(transmission_binary: str, blink_ms: int = 100) -> bytes:
    """
    Generate a minimal synthetic AVI video encoding the binary data.

    Uses a plain black frame with a bright green rectangle as the "eye".
    Left eye = bits 0,2,4,…  Right eye = bits 1,3,5,…
    Blink period = blink_ms ms at 60 fps.

    Uses MJPG codec (widely available via OpenCV) inside a temporary AVI file.
    """
    fps = 60
    width, height = 200, 120
    # MJPG is broadly supported in OpenCV builds and produces AVI files the
    # server-side decoder can read via cv2.VideoCapture.
    fourcc = cv2.VideoWriter_fourcc(*"MJPG")

    # Green channel intensity for "eye ON" state (BGR order)
    EYE_BRIGHTNESS = 220

    # Eye bounding boxes  (x1, y1, x2, y2)
    left_box = (20, 40, 70, 80)
    right_box = (130, 40, 180, 80)

    with tempfile.NamedTemporaryFile(suffix=".avi", delete=False) as tmp:
        tmp_path = tmp.name

    writer = cv2.VideoWriter(tmp_path, fourcc, fps, (width, height))

    def make_frame(left_on: bool, right_on: bool) -> np.ndarray:
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        for box, on in ((left_box, left_on), (right_box, right_on)):
            x1, y1, x2, y2 = box
            if on:
                frame[y1:y2, x1:x2] = [0, EYE_BRIGHTNESS, 0]   # bright green (BGR)
        return frame

    frames_per_blink = max(1, round(blink_ms * fps / 1000.0))

    for i in range(0, len(transmission_binary), 2):
        pair = transmission_binary[i : i + 2]
        if len(pair) < 2:
            break
        left_on = pair[0] == "1"
        right_on = pair[1] == "1"
        frame = make_frame(left_on, right_on)
        for _ in range(frames_per_blink):
            writer.write(frame)

    writer.release()

    with open(tmp_path, "rb") as f:
        video_bytes = f.read()
    os.unlink(tmp_path)
    return video_bytes


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def client():
    """Flask test client with TESTING mode enabled."""
    flask_app.app.config["TESTING"] = True
    flask_app.app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.app.test_client() as c:
        yield c


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestCatModeRefreshDecrypt:
    """
    Tests the full 'encrypt → download video → refresh → decrypt' cycle.
    """

    def test_encrypt_produces_valid_hex_payload(self):
        """Encryption produces a valid hex payload with correct header structure."""
        _, payload_hex = _encrypt_message("Hello Cat!", "testpass1")
        # Must be a valid hex string
        assert all(c in "0123456789abcdef" for c in payload_hex)
        # Minimum: 68 header bytes = 136 hex chars
        assert len(payload_hex) >= 136

    def test_video_download_endpoint_returns_url(self, client):
        """Step 2: /cat-mode-download-video saves video and returns download URL."""
        dummy_video = b"RIFF\x00\x00\x00\x00AVI "  # minimal bytes, non-zero size
        resp = client.post(
            "/cat-mode-download-video",
            data={"video": (io.BytesIO(dummy_video), "cat_mode_test.webm")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["success"] is True
        assert "download_url" in data
        assert data["download_url"].startswith("/cat-mode-video/")

    def test_video_download_then_re_download(self, client):
        """Step 2b: The saved video can be fetched back via its download URL."""
        video_bytes = b"\x00\x01\x02\x03" * 256  # 1 KB of dummy data
        save_resp = client.post(
            "/cat-mode-download-video",
            data={"video": (io.BytesIO(video_bytes), "test.webm")},
            content_type="multipart/form-data",
        )
        assert save_resp.status_code == 200
        save_data = json.loads(save_resp.data)
        download_url = save_data["download_url"]

        fetch_resp = client.get(download_url)
        assert fetch_resp.status_code == 200
        assert fetch_resp.data == video_bytes

    def test_full_encrypt_video_refresh_decrypt_cycle(self, client):
        """
        Full E2E: encrypt → build synthetic video → save video → 'refresh' page
        → fetch saved video → upload video → decode binary → decrypt → verify.

        The 'page refresh' is simulated by:
        - Saving the video to the server (step 3)
        - Fetching it back as a separate HTTP request (step 4)
        - Uploading the fetched bytes to /cat-mode-decode-video (step 5)

        There is NO sessionStorage between encrypt and decode — the only link
        is the video file bytes.
        """
        message = "SecretCat123"
        password = "password99!"

        # ── Step 1: Encrypt (matches /cat-mode-encrypt-server logic) ─────────
        _, payload_hex = _encrypt_message(message, password)

        # ── Step 2: Build transmission binary (mirrors JavaScript encoder) ──
        tx_binary = _build_transmission_binary(payload_hex)

        # ── Step 3: Generate a synthetic AVI video ───────────────────────────
        video_bytes = _generate_synthetic_video(tx_binary, blink_ms=100)
        assert len(video_bytes) > 0, "Video generation produced empty output"

        # ── Step 4: Save video (what the browser does after transmission) ────
        save_resp = client.post(
            "/cat-mode-download-video",
            data={"video": (io.BytesIO(video_bytes), "cat_mode_transmission.webm")},
            content_type="multipart/form-data",
        )
        assert save_resp.status_code == 200
        save_data = json.loads(save_resp.data)
        download_url = save_data["download_url"]

        # ── Step 5: Simulate page refresh — fetch saved video ────────────────
        fetch_resp = client.get(download_url)
        assert fetch_resp.status_code == 200
        downloaded_video = fetch_resp.data

        # ── Step 6: Upload downloaded video → extract binary ─────────────────
        decode_resp = client.post(
            "/cat-mode-decode-video",
            data={"video": (io.BytesIO(downloaded_video), "cat_mode_transmission.avi")},
            content_type="multipart/form-data",
        )
        assert decode_resp.status_code == 200
        decode_data = json.loads(decode_resp.data)
        assert decode_data.get("success"), (
            f"Video decode failed: {decode_data.get('error', 'Unknown error')}"
        )
        extracted_binary = decode_data["binary"]
        assert all(c in "01" for c in extracted_binary), "Binary contains non-binary chars"

        # ── Step 7: Decrypt using extracted binary ────────────────────────────
        decrypted_message = _decrypt_binary(extracted_binary, password)
        assert decrypted_message == message, (
            f"Decrypted message mismatch.\n"
            f"Expected:  {message!r}\n"
            f"Decrypted: {decrypted_message!r}"
        )

    def test_wrong_password_after_refresh_fails(self, client):
        """Decrypting with the wrong password after a refresh must raise an exception."""
        message = "WrongPasswordTest"
        password = "correctpass1"
        wrong_password = "wrongpass99"

        _, payload_hex = _encrypt_message(message, password)
        tx_binary = _build_transmission_binary(payload_hex)
        video_bytes = _generate_synthetic_video(tx_binary, blink_ms=100)

        decode_resp = client.post(
            "/cat-mode-decode-video",
            data={"video": (io.BytesIO(video_bytes), "test.avi")},
            content_type="multipart/form-data",
        )
        decode_data = json.loads(decode_resp.data)
        assert decode_data.get("success"), "Video decode should succeed"
        extracted_binary = decode_data["binary"]

        # Attempt to decrypt with the wrong password — must raise
        with pytest.raises(Exception):
            _decrypt_binary(extracted_binary, wrong_password)

