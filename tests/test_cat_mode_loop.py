"""Reproducible Cat Mode optical-channel loop closure tests."""

from __future__ import annotations

import base64
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
import random
import shutil
import subprocess

import cv2
import numpy as np
from PIL import Image
import pytest

from meow_decoder.fountain import FountainDecoder, unpack_droplet
from meow_decoder.qr_code import QRCodeReader

ROOT = Path(__file__).resolve().parents[1]
E2E_SCRIPT = ROOT / "tests" / "e2e" / "cat-mode.spec.js"


@dataclass(frozen=True)
class ChannelProfile:
    gaussian_sigma: float
    motion_kernel: int
    shear_pixels: float
    jpeg_quality: int
    brightness: float
    gamma: float
    perspective_fraction: float
    drop_rate: float


CHANNEL_PROFILES = {
    "clean-0pct": ChannelProfile(0.0, 1, 0.0, 100, 1.0, 1.0, 0.0, 0.0),
    "mild-10pct": ChannelProfile(0.35, 3, 1.0, 92, 0.97, 1.03, 0.004, 0.10),
    "moderate-25pct": ChannelProfile(0.55, 3, 2.0, 84, 0.92, 1.08, 0.008, 0.25),
    "severe-40pct": ChannelProfile(0.75, 5, 3.0, 76, 0.86, 1.14, 0.012, 0.40),
}


@pytest.fixture(scope="session")
def cat_mode_capture(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict, list[Image.Image]]:
    """Drive the real browser sender once and return its first rendered loop."""
    node = shutil.which("node")
    if node is None:
        pytest.fail("Node.js is required for the Cat Mode Playwright harness")

    configured_capture_dir = os.environ.get("MEOW_CAT_CAPTURE_DIR")
    capture_dir = (
        # Anchor a relative value against ROOT: the node harness resolves it
        # there (and runs with cwd=ROOT), while pytest's CWD can be anywhere.
        (ROOT / configured_capture_dir).resolve()
        if configured_capture_dir
        else tmp_path_factory.mktemp("cat-mode-browser")
    )
    capture_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["MEOW_CAT_CAPTURE_DIR"] = str(capture_dir)
    result = subprocess.run(
        [node, str(E2E_SCRIPT)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            "Cat Mode Playwright capture failed\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    metadata = json.loads((capture_dir / "metadata.json").read_text(encoding="utf-8"))
    frames = [
        Image.open(capture_dir / capture["filename"]).convert("RGB")
        for capture in metadata["captures"]
    ]
    return metadata, frames


def _apply_optical_degradation(image: Image.Image, profile: ChannelProfile) -> Image.Image:
    """Apply a deterministic monitor-to-camera degradation pipeline."""
    frame = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2BGR)
    height, width = frame.shape[:2]

    if profile.gaussian_sigma > 0:
        frame = cv2.GaussianBlur(frame, (0, 0), profile.gaussian_sigma)

    if profile.motion_kernel > 1:
        kernel = np.zeros((profile.motion_kernel, profile.motion_kernel), dtype=np.float32)
        kernel[profile.motion_kernel // 2, :] = 1.0 / profile.motion_kernel
        frame = cv2.filter2D(frame, -1, kernel)

    if profile.shear_pixels > 0:
        map_x, map_y = np.meshgrid(
            np.arange(width, dtype=np.float32), np.arange(height, dtype=np.float32)
        )
        offsets = np.linspace(-profile.shear_pixels, profile.shear_pixels, height, dtype=np.float32)
        map_x = map_x - offsets[:, None]
        frame = cv2.remap(
            frame,
            map_x,
            map_y,
            interpolation=cv2.INTER_LINEAR,
            borderMode=cv2.BORDER_REPLICATE,
        )

    if profile.perspective_fraction > 0:
        inset = profile.perspective_fraction * min(width, height)
        source = np.float32([[0, 0], [width - 1, 0], [width - 1, height - 1], [0, height - 1]])
        target = np.float32(
            [
                [inset, inset * 0.4],
                [width - 1 - inset * 0.3, 0],
                [width - 1, height - 1 - inset],
                [0, height - 1 - inset * 0.2],
            ]
        )
        matrix = cv2.getPerspectiveTransform(source, target)
        frame = cv2.warpPerspective(
            frame,
            matrix,
            (width, height),
            flags=cv2.INTER_LINEAR,
            borderMode=cv2.BORDER_REPLICATE,
        )

    normalized = np.clip(frame.astype(np.float32) * profile.brightness / 255.0, 0.0, 1.0)
    normalized = np.power(normalized, profile.gamma)
    frame = np.clip(normalized * 255.0, 0, 255).astype(np.uint8)

    encode_ok, encoded = cv2.imencode(
        ".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), profile.jpeg_quality]
    )
    if not encode_ok:
        raise AssertionError("OpenCV failed to apply JPEG degradation")
    degraded = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
    return Image.fromarray(cv2.cvtColor(degraded, cv2.COLOR_BGR2RGB))


def _drop_frames(
    frames: list[Image.Image], drop_rate: float, *, seed: int = 20260717
) -> list[Image.Image]:
    drop_count = math.floor(len(frames) * drop_rate)
    dropped = set(random.Random(seed).sample(range(len(frames)), drop_count))
    return [frame for index, frame in enumerate(frames) if index not in dropped]


def _read_qr_payloads(frames: list[Image.Image]) -> list[str]:
    reader = QRCodeReader(preprocessing="normal")
    payloads: list[str] = []
    for frame in frames:
        for value in reader.read_image(frame):
            try:
                payloads.append(value.decode("ascii"))
            except (UnicodeDecodeError, AttributeError):
                continue
    return payloads


def _reconstruct_fountain_payload(payloads: list[str]) -> tuple[bytes, int, int]:
    decoder: FountainDecoder | None = None
    parameters: tuple[int, int, int] | None = None
    seen_seeds: set[int] = set()

    for payload in payloads:
        if not payload.startswith("FOUNTAIN:"):
            continue
        marker, k_text, block_text, length_text, droplet_text = payload.split(":", 4)
        assert marker == "FOUNTAIN"
        current = (int(k_text), int(block_text), int(length_text))
        if parameters is None:
            parameters = current
            decoder = FountainDecoder(*current)
        assert current == parameters, "Cat Mode mixed fountain sessions in one loop"

        packed = base64.b64decode(droplet_text, validate=True)
        droplet = unpack_droplet(packed, current[1])
        if droplet.seed in seen_seeds:
            continue
        seen_seeds.add(droplet.seed)
        assert decoder is not None
        if decoder.add_droplet(droplet):
            break

    assert decoder is not None, "No FOUNTAIN QR payload was decoded from screenshots"
    assert decoder.is_complete(), (
        f"Fountain decode incomplete: {decoder.decoded_count}/{decoder.k_blocks} blocks "
        f"from {len(seen_seeds)} unique droplets"
    )
    return decoder.get_data(), len(payloads), len(seen_seeds)


def test_cat_mode_headless_loop_closes(
    cat_mode_capture: tuple[dict, list[Image.Image]],
) -> None:
    """Tier 1: browser screenshots reconstruct the exact encrypted payload."""
    metadata, frames = cat_mode_capture
    recovered, qr_reads, unique_droplets = _reconstruct_fountain_payload(_read_qr_payloads(frames))

    assert recovered == metadata["encryptedPayload"].encode("utf-8")
    assert qr_reads >= metadata["kBlocks"]
    assert unique_droplets >= metadata["kBlocks"]


@pytest.mark.parametrize(
    "profile_name",
    list(CHANNEL_PROFILES),
    ids=list(CHANNEL_PROFILES),
)
def test_cat_mode_simulated_optical_channel(
    cat_mode_capture: tuple[dict, list[Image.Image]],
    profile_name: str,
    record_property: pytest.RecordProperty,
) -> None:
    """Tier 2: decode through quantified blur, shear, JPEG, lighting, warp, and loss."""
    metadata, clean_frames = cat_mode_capture
    profile = CHANNEL_PROFILES[profile_name]
    degraded = [_apply_optical_degradation(frame, profile) for frame in clean_frames]
    received = _drop_frames(degraded, profile.drop_rate)
    recovered, qr_reads, unique_droplets = _reconstruct_fountain_payload(
        _read_qr_payloads(received)
    )

    record_property("cat_mode_channel_profile", profile_name)
    record_property("cat_mode_frames_sent", len(clean_frames))
    record_property("cat_mode_frames_received", len(received))
    record_property("cat_mode_qr_reads", qr_reads)
    record_property("cat_mode_unique_droplets", unique_droplets)
    assert recovered == metadata["encryptedPayload"].encode("utf-8")
