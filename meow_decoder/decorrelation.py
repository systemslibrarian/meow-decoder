"""
Inter-File Decorrelation

Randomizes non-security-critical encoding parameters to prevent
an adversary from correlating multiple encoded files by their
structural fingerprint (frame count, timing, block size, etc.).

Usage:
    from meow_decoder.decorrelation import decorrelate_config

    config = EncodingConfig()
    decorrelate_config(config)  # Mutates config in-place

Security Properties:
    - Block size jittered within safe range
    - Redundancy factor jittered
    - FPS jittered within readable range
    - All randomness from os.urandom (CSPRNG)
    - Security-critical parameters (key size, error correction) are NOT modified
"""

import os
import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "decorrelate_config",
    "DecorrelationParams",
]


@dataclass
class DecorrelationParams:
    """
    Parameters controlling decorrelation ranges.

    All ranges are inclusive [min, max].
    """

    # Block size range (must fit in QR at error correction H)
    block_size_min: int = 400
    block_size_max: int = 700

    # Redundancy factor range (must be >= 1.2 for reliable decoding)
    redundancy_min: float = 1.3
    redundancy_max: float = 2.0

    # FPS range (must be readable by camera)
    fps_min: int = 1
    fps_max: int = 4

    # QR border jitter range
    border_min: int = 3
    border_max: int = 6

    # QR box size jitter range
    box_size_min: int = 10
    box_size_max: int = 18


def _csprng_int(low: int, high: int) -> int:
    """
    Generate a cryptographically random integer in [low, high].

    Uses os.urandom to avoid any PRNG state correlation.
    """
    if low > high:
        raise ValueError(f"low ({low}) must be <= high ({high})")
    if low == high:
        return low

    range_size = high - low + 1
    # Use rejection sampling for uniform distribution
    # 4 bytes gives us 2^32 range, more than enough
    while True:
        raw = struct.unpack(">I", os.urandom(4))[0]
        # Reject values that would cause modulo bias
        limit = (0xFFFFFFFF // range_size) * range_size
        if raw < limit:
            return low + (raw % range_size)


def _csprng_float(low: float, high: float) -> float:
    """
    Generate a cryptographically random float in [low, high].

    Uses os.urandom for uniform distribution.
    """
    if low > high:
        raise ValueError(f"low ({low}) must be <= high ({high})")
    # 8 bytes = 64-bit precision
    raw = struct.unpack(">Q", os.urandom(8))[0]
    # Map [0, 2^64 - 1] -> [0.0, 1.0)
    fraction = raw / (2**64)
    return low + fraction * (high - low)


def decorrelate_config(
    config,
    params: Optional[DecorrelationParams] = None,
) -> None:
    """
    Randomize non-security-critical encoding parameters in-place.

    This mutates the config object to use randomly selected values
    within safe operating ranges, preventing inter-file correlation.

    Args:
        config: An EncodingConfig (or any object with the relevant attributes).
        params: Decorrelation ranges. Uses defaults if None.

    Security:
        - DOES NOT modify: encryption keys, error correction level, QR version,
          forward secrecy settings, ratchet settings, or any crypto parameters
        - Only modifies: block_size, redundancy, fps, qr_border, qr_box_size
        - All modifications use CSPRNG (os.urandom)

    Note:
        Call this BEFORE encoding. The decoder recovers these parameters from
        the fountain code header and manifest, so no coordination is needed.
    """
    if params is None:
        params = DecorrelationParams()

    # Jitter block size (fountain code parameter — encoded in frame header)
    if hasattr(config, "block_size"):
        config.block_size = _csprng_int(params.block_size_min, params.block_size_max)

    # Jitter redundancy factor
    if hasattr(config, "redundancy"):
        # Round to 1 decimal place for cleanliness
        config.redundancy = round(
            _csprng_float(params.redundancy_min, params.redundancy_max), 1
        )

    # Jitter FPS (visual parameter — encoded in GIF timing)
    if hasattr(config, "fps"):
        config.fps = _csprng_int(params.fps_min, params.fps_max)

    # Jitter QR border (visual parameter)
    if hasattr(config, "qr_border"):
        config.qr_border = _csprng_int(params.border_min, params.border_max)

    # Jitter QR box size (visual parameter)
    if hasattr(config, "qr_box_size"):
        config.qr_box_size = _csprng_int(params.box_size_min, params.box_size_max)
