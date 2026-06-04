#!/usr/bin/env python3
"""End-to-end VP9 decode check for cat mode (local/manual).

This exercises the *real* `_decode_cat_video` over a compressed VP9 video — the
scenario that was broken before commit 7101314 (compression-induced transition
artifacts collapsed the blink period and inflated the bitstream ~1.5x).

It needs OpenCV + ffmpeg + the cat asset, which are not part of the CI test
environment, so it auto-skips there. The fast, CI-native unit guard for the
underlying `refine_blink_period` algorithm lives in tests/test_cat_blink.py.
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


@pytest.mark.skipif(not (_HAS_CV2 and _HAS_FFMPEG), reason="needs cv2 + ffmpeg")
@pytest.mark.parametrize("speed_ms", [50, 100])
def test_vp9_compressed_video_decodes_to_exact_payload(speed_ms):
    """A VP9-compressed cat video decodes to the exact payload, bp not collapsed."""
    import test_cat_e2e_speeds as gen
    from app import _decode_cat_video

    if not os.path.exists(gen.CAT_IMAGE_PATH):
        pytest.skip("cat carrier image not available")

    frames = gen.prepare_cat_frames()
    raw_bits = gen.hex_to_binary(hashlib.sha256(b"").hexdigest())  # 256-bit payload
    whitened = gen.whiten(raw_bits)

    clean_path = gen.generate_video(whitened, speed_ms, frames)
    vp9_fd, vp9_path = tempfile.mkstemp(suffix=".webm")
    os.close(vp9_fd)
    try:
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-i",
                clean_path,
                "-c:v",
                "libvpx-vp9",
                "-b:v",
                "800k",
                "-deadline",
                "realtime",
                "-cpu-used",
                "5",
                vp9_path,
            ],
            check=True,
            capture_output=True,
        )
        result = _decode_cat_video(vp9_path)
    finally:
        os.unlink(clean_path)
        os.unlink(vp9_path)

    # _decode_cat_video returns the de-whitened payload bits.
    assert result["binary"] == raw_bits
    assert result["bits"] == len(raw_bits)

    # bp must hold at the true period (speed_ms at 60fps), not collapse.
    expected_bp = round(speed_ms / 1000.0 * gen.VIDEO_FPS)
    assert result["diagnostics"]["bp_refined"] == pytest.approx(expected_bp, abs=0.5)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
