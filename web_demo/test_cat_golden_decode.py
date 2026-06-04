#!/usr/bin/env python3
"""Golden decode test for the Python cat-mode video decoder.

Decodes the representative fixtures in tests/golden/python/ — real browser
MediaRecorder (VP8) captures of the production encode protocol — through the
same path the server uses (ffmpeg -> MJPEG AVI @60fps -> _decode_cat_video) and
asserts they recover the known payload (SHA-256 of the empty string).

Unlike tests/golden/*.webm (which target the JavaScript decoder), these are
decodable by the Python server-side decoder. Needs cv2 + ffmpeg, so it
auto-skips where those are unavailable. See tests/golden/python/README.md.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

_HAS_CV2 = False
try:
    import cv2  # noqa: F401

    _HAS_CV2 = True
except Exception:  # pragma: no cover - environment dependent
    pass

_HAS_FFMPEG = shutil.which("ffmpeg") is not None

GOLDEN_DIR = Path(__file__).parent.parent / "tests" / "golden" / "python"
EMPTY_SHA256_HEX = hashlib.sha256(b"").hexdigest()


def _hex_to_bits(hex_str):
    return "".join(bin(int(c, 16))[2:].zfill(4) for c in hex_str)


@pytest.mark.skipif(not (_HAS_CV2 and _HAS_FFMPEG), reason="needs cv2 + ffmpeg")
@pytest.mark.parametrize("fixture", ["cat_emptyhash_100ms.webm", "cat_emptyhash_50ms.webm"])
def test_python_golden_video_decodes_to_known_payload(fixture):
    """A real browser-captured cat video decodes to the exact empty-hash payload."""
    from app import _decode_cat_video

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
        result = _decode_cat_video(avi)
    finally:
        os.unlink(avi)

    expected = _hex_to_bits(EMPTY_SHA256_HEX)
    assert result["binary"] == expected
    assert result["bits"] == len(expected) == 256


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
