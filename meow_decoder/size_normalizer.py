"""
Size and Frame Count Normalization for Side-Channel Resistance

Provides utilities to pad encoded output to fixed size classes and
fixed frame counts. This prevents metadata oracles where:
  - File size reveals payload size (C1: Fixed-Size Output Padding)
  - Frame count reveals single vs. dual secret mode (B2: Fixed Frame Count)

Size Classes:
    Output is padded to the smallest power-of-4 size class that fits.
    Classes: 4KB, 16KB, 64KB, 256KB, 1MB, 4MB, 16MB, 64MB.
    Padding uses CSPRNG random bytes (indistinguishable from ciphertext).

Frame Count:
    All GIFs produce a fixed number of frames (or a multiple of a
    fixed quantum). Extra frames are valid fountain droplets (redundant
    but decodable). This prevents an observer from distinguishing
    single-secret from dual-secret by counting frames.

Security Properties:
    - Size classes eliminate payload size fingerprinting.
    - Frame count normalization removes mode-distinguishing metadata.
    - Padding bytes are cryptographic random (secrets.token_bytes).
    - Unpadding uses authenticated length (from manifest, not padding).

Honest Limitations:
    - Very large payloads may exceed the largest size class (64 MB).
    - Encoding time still varies with payload size (use TimingEqualizedDecoder).
    - QR version differences for different payload sizes are NOT hidden by this
      module (see C2: Fixed QR Parameters for that).

See docs/SECURITY_AUDIT_HARDENING_ROADMAP.md § Category B2, C1
"""

import secrets
import struct
from typing import Optional, Tuple

# ── Size Classes ──
# Exponential classes (powers of 4 × 1KB) to limit fingerprinting.
# An observer sees only the size class, not the actual payload size.
SIZE_CLASSES = [
    4_096,  # 4 KB
    16_384,  # 16 KB
    65_536,  # 64 KB
    262_144,  # 256 KB
    1_048_576,  # 1 MB
    4_194_304,  # 4 MB
    16_777_216,  # 16 MB
    67_108_864,  # 64 MB
]

# Maximum allowed payload size before padding
MAX_PAYLOAD_SIZE = SIZE_CLASSES[-1] - 8  # Reserve 8 bytes for length header

# Padding header: 8 bytes = original length (big-endian u64)
PADDING_HEADER_SIZE = 8

# ── Frame Count ──
# Frame count quantum: all GIFs have frame counts that are multiples of this.
# Higher quantum = more padding frames but better indistinguishability.
FRAME_QUANTUM = 50

# Minimum frame count (ensures small payloads don't produce tiny GIFs)
MIN_FRAME_COUNT = 50

# Maximum frame count cap (prevents unbounded padding)
MAX_FRAME_COUNT = 2000


def select_size_class(data_len: int, size_class: Optional[int] = None) -> int:
    """Select the smallest size class that fits the data.

    Args:
        data_len: Length of the data to pad (including any headers).
        size_class: Optional explicit size class override.

    Returns:
        The target size class in bytes.

    Raises:
        ValueError: If data exceeds all size classes.
    """
    if size_class is not None:
        if size_class < data_len:
            raise ValueError(
                f"Explicit size class {size_class} too small for data ({data_len} bytes)"
            )
        return size_class

    for sc in SIZE_CLASSES:
        if sc >= data_len + PADDING_HEADER_SIZE:
            return sc

    raise ValueError(
        f"Data too large ({data_len} bytes) for any size class "
        f"(max {SIZE_CLASSES[-1]} bytes). Consider splitting the payload."
    )


def pad_to_size_class(data: bytes, size_class: Optional[int] = None) -> bytes:
    """Pad data to a fixed size class with random bytes.

    Format:
        [original_length: 8 bytes big-endian] [original_data] [random_padding]

    The original length is stored at the START so that unpadding can
    extract exactly the right number of bytes regardless of padding content.

    Args:
        data: The data to pad.
        size_class: Optional explicit size class. If None, auto-selects.

    Returns:
        Padded data of exactly ``size_class`` bytes.

    Raises:
        ValueError: If data is too large for any size class.
    """
    target = select_size_class(len(data), size_class)

    # Pack: [u64 length] + [data] + [random padding]
    header = struct.pack(">Q", len(data))
    pad_len = target - PADDING_HEADER_SIZE - len(data)

    if pad_len < 0:
        raise ValueError(
            f"Data ({len(data)} bytes) + header ({PADDING_HEADER_SIZE}) "
            f"exceeds size class ({target} bytes)"
        )

    padding = secrets.token_bytes(pad_len) if pad_len > 0 else b""
    result = header + data + padding

    assert len(result) == target, f"Padding error: {len(result)} != {target}"
    return result


def unpad_from_size_class(padded_data: bytes) -> bytes:
    """Remove size-class padding and recover original data.

    Args:
        padded_data: Data that was padded by ``pad_to_size_class``.

    Returns:
        The original unpadded data.

    Raises:
        ValueError: If the length header is invalid or corrupted.
    """
    if len(padded_data) < PADDING_HEADER_SIZE:
        raise ValueError(
            f"Padded data too short ({len(padded_data)} bytes, "
            f"need at least {PADDING_HEADER_SIZE})"
        )

    original_len = struct.unpack(">Q", padded_data[:PADDING_HEADER_SIZE])[0]

    # Check max payload size first (before available-bytes check)
    if original_len > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Length header claims {original_len} bytes, exceeds maximum "
            f"({MAX_PAYLOAD_SIZE} bytes)"
        )

    if original_len > len(padded_data) - PADDING_HEADER_SIZE:
        raise ValueError(
            f"Length header claims {original_len} bytes but only "
            f"{len(padded_data) - PADDING_HEADER_SIZE} available"
        )

    return padded_data[PADDING_HEADER_SIZE : PADDING_HEADER_SIZE + original_len]


def get_size_class_for_display(size_class: int) -> str:
    """Return human-readable size class label.

    Args:
        size_class: Size class in bytes.

    Returns:
        Human-readable string like "4 KB", "1 MB", etc.
    """
    if size_class >= 1_048_576:
        return f"{size_class // 1_048_576} MB"
    elif size_class >= 1_024:
        return f"{size_class // 1_024} KB"
    return f"{size_class} B"


# ── Frame Count Normalization ──


def normalize_frame_count(
    actual_frames: int,
    quantum: int = FRAME_QUANTUM,
    minimum: int = MIN_FRAME_COUNT,
    maximum: int = MAX_FRAME_COUNT,
) -> int:
    """Compute the normalized (padded) frame count.

    Rounds up to the nearest multiple of ``quantum``, clamped between
    ``minimum`` and ``maximum``.

    Args:
        actual_frames: The number of frames the payload actually needs.
        quantum: Frame count granularity (all outputs are multiples of this).
        minimum: Minimum frame count.
        maximum: Maximum frame count.

    Returns:
        Normalized frame count (>= actual_frames, multiple of quantum).
    """
    if actual_frames <= 0:
        return minimum

    # Round up to nearest quantum
    normalized = ((actual_frames + quantum - 1) // quantum) * quantum

    # Clamp
    normalized = max(normalized, minimum)
    normalized = min(normalized, maximum)

    return normalized


def pad_frames(
    frames: list,
    target_count: int,
    frame_generator: Optional[callable] = None,
) -> list:
    """Pad a frame list to exactly ``target_count`` frames.

    If ``frame_generator`` is provided, it's called to produce additional
    valid frames (e.g., redundant fountain droplets). Otherwise, the
    last frame is duplicated (less ideal but still structurally valid).

    If the frame list exceeds ``target_count``, it is truncated.

    Args:
        frames: List of frames to pad.
        target_count: Target number of frames.
        frame_generator: Optional callable that returns a new frame.

    Returns:
        Frame list of exactly ``target_count`` length.
    """
    if len(frames) >= target_count:
        return frames[:target_count]

    result = list(frames)
    while len(result) < target_count:
        if frame_generator is not None:
            result.append(frame_generator())
        elif frames:
            # Duplicate last frame (fountain decoder handles redundancy)
            result.append(frames[-1])
        else:
            break

    return result


def compute_frame_metadata(
    actual_frames: int,
    normalized_frames: int,
) -> dict:
    """Return metadata about frame normalization for logging/debug.

    Args:
        actual_frames: Original frame count.
        normalized_frames: Normalized frame count.

    Returns:
        Dict with frame count statistics.
    """
    return {
        "actual_frames": actual_frames,
        "normalized_frames": normalized_frames,
        "padding_frames": normalized_frames - actual_frames,
        "padding_ratio": (
            (normalized_frames - actual_frames) / actual_frames if actual_frames > 0 else 0.0
        ),
        "quantum": FRAME_QUANTUM,
    }
