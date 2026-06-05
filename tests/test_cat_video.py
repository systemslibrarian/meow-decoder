"""CI golden test for the Python cat-mode video decoder.

Decodes the representative fixtures in tests/golden/python/ — real browser
MediaRecorder (VP8) captures of the production encode protocol — through the
same path the server uses (ffmpeg -> MJPEG AVI @60fps -> decode_cat_video) and
asserts they recover the known payload (SHA-256 of the empty string).

This imports meow_decoder.cat_video directly (no Flask), so unlike the
web_demo/ integration tests it can run in CI. It still needs cv2 + ffmpeg and
auto-skips where those are unavailable. See tests/golden/python/README.md.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

_HAS_FFMPEG = shutil.which("ffmpeg") is not None
try:
    import cv2  # noqa: F401

    _HAS_CV2 = True
except Exception:  # pragma: no cover - environment dependent
    _HAS_CV2 = False

GOLDEN_DIR = Path(__file__).parent / "golden" / "python"
EMPTY_SHA256_HEX = hashlib.sha256(b"").hexdigest()


def _hex_to_bits(hex_str):
    return "".join(bin(int(c, 16))[2:].zfill(4) for c in hex_str)


# Only constant-frame-rate (60/1) fixtures are used: the decode goes through
# ffmpeg's VFR->CFR resampling, which differs across ffmpeg versions and makes
# variable-frame-rate fixtures flaky in CI. A 60/1 fixture makes `ffmpeg -r 60`
# a no-op, so every environment reads identical frames. Keep ≥6 frames/blink
# (e.g. 100ms @ 60fps) for margin.
@pytest.mark.skipif(not (_HAS_CV2 and _HAS_FFMPEG), reason="needs cv2 + ffmpeg")
@pytest.mark.parametrize("fixture", ["cat_emptyhash_100ms.webm", "cat_emptyhash_200ms.webm"])
def test_python_golden_video_decodes_to_known_payload(fixture):
    """A real browser-captured cat video decodes to the exact empty-hash payload."""
    from meow_decoder.cat_video import decode_cat_video

    video = GOLDEN_DIR / fixture
    if not video.exists():
        pytest.skip(f"golden fixture missing: {video}")

    avi_fd, avi = tempfile.mkstemp(suffix=".avi")
    os.close(avi_fd)
    try:
        # Mirror the production route: convert to MJPEG AVI @60fps before decode.
        subprocess.run(
            ["ffmpeg", "-y", "-i", str(video), "-c:v", "mjpeg", "-q:v", "2", "-r", "60", avi],
            check=True,
            capture_output=True,
        )
        result = decode_cat_video(avi)
    finally:
        os.unlink(avi)

    expected = _hex_to_bits(EMPTY_SHA256_HEX)
    assert result["binary"] == expected
    assert result["bits"] == len(expected) == 256
