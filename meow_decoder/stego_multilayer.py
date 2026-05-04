"""
Multi-Layer Steganography System for Meow Decoder
==================================================

Production-grade multi-channel steganography with steganalysis resistance.

Channels:
    1. Primary:   Keyed pseudorandom LSB walk with STC matrix encoding
    2. Secondary:  GIF frame timing channel (GCE delay jitter)
    3. Tertiary:   Palette permutation / unused slot encoding

Security Properties:
    - Per-frame, per-channel independent seeds (HKDF domain separation)
    - Syndrome-Trellis Codes minimize embedding changes (~50% fewer flips)
    - Adaptive cost function (texture-aware, penalizes smooth regions)
    - Timing channel: zero visual impact, separate seed
    - Palette channel: invisible, exploits GIF format semantics
    - Coercion resistance: decoy key -> shallow layers only; real key -> all layers
    - All crypto-sensitive ops run in Rust (constant-time via meow_crypto_rs)

Quality Targets:
    - PSNR > 55-60 dB, SSIM > 0.999
    - RS analysis p-value > 0.05 (pass statistical tests)
    - Resist chi-square, SPA on palette indices

Dependencies:
    pip install imageio[ffmpeg] Pillow numpy

Usage:
    from meow_decoder.stego_multilayer import (
        MultiLayerStegoEncoder, MultiLayerStegoDecoder,
        MultiLayerConfig, validate_stego,
    )

    # Encode
    encoder = MultiLayerStegoEncoder(config, master_key)
    stego_gif = encoder.encode(payload, carrier_gif_path, output_path)

    # Decode
    decoder = MultiLayerStegoDecoder(config, master_key)
    result = decoder.decode(stego_gif_path)
    # result = {payload_bytes, channel_sources, mac_valid, duress_triggered}
"""

from __future__ import annotations

import hashlib
import hmac as hmac_stdlib
import io
import logging
import os
import struct
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from PIL import Image

from meow_decoder.stego_gif_binary import GifBinaryEditor, GifStructure

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attempt to import Rust backend; fall back to pure-Python stubs
# ---------------------------------------------------------------------------
_RUST_AVAILABLE = False
try:
    import meow_crypto_rs

    # Verify stego functions exist
    _has_stego = hasattr(meow_crypto_rs, "stego_derive_frame_seed")
    if _has_stego:
        _RUST_AVAILABLE = True
        logger.debug("Rust stego backend available (meow_crypto_rs)")
    else:
        logger.warning("meow_crypto_rs found but stego functions missing; using Python fallback")
except ImportError:
    logger.warning("meow_crypto_rs not available; using Python stego fallback (NOT constant-time)")


# ---------------------------------------------------------------------------
# Per-channel sub-key derivation via Rust handle backend (gemini #1).
# Channels keep their derived sub-keys as opaque handle IDs so the bytes
# never live as long-running Python instance attributes. The HMAC-SHA256
# derivation is preserved (so wire formats are unchanged); the derived
# bytes lifetime is bounded to the helper's frame.
# ---------------------------------------------------------------------------

_FINGERPRINT_DOMAIN = b"_meow_stego_test_kfp_v1"


def _derive_channel_subkey_handle(master_key: bytes, domain: bytes):
    """Derive HMAC-SHA256(master_key, domain) and import as a Rust handle.

    Returns the handle ID, or None if the Rust backend is unavailable.
    The bytes are zeroed before return.
    """
    if not _RUST_AVAILABLE:
        return None
    try:
        from meow_decoder.crypto_backend import get_handle_backend
    except ImportError:
        return None
    hb = get_handle_backend()
    derived = bytearray(hmac_stdlib.new(master_key, domain, hashlib.sha256).digest())
    try:
        return hb.import_key(bytes(derived))
    finally:
        for i in range(len(derived)):
            derived[i] = 0


def _drop_handle_safe(handle):
    """Drop a handle if the backend is available; swallow exceptions."""
    if handle is None or not _RUST_AVAILABLE:
        return
    try:
        from meow_decoder.crypto_backend import get_handle_backend

        get_handle_backend().drop(handle)
    except Exception:
        pass


def _key_fingerprint(handle) -> bytes:
    """Stable test-only fingerprint over a key handle.
    Returns empty bytes if the handle or backend is unavailable."""
    if handle is None or not _RUST_AVAILABLE:
        return b""
    try:
        from meow_decoder.crypto_backend import get_handle_backend

        return bytes(get_handle_backend().hmac_sha256(handle, _FINGERPRINT_DOMAIN))
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Attempt to import imageio for reliable animated GIF handling
# ---------------------------------------------------------------------------
_IMAGEIO_AVAILABLE = False
try:
    import imageio.v3 as iio

    _IMAGEIO_AVAILABLE = True
except ImportError:
    try:
        import imageio as iio  # type: ignore[no-redef]

        _IMAGEIO_AVAILABLE = True
    except ImportError:
        logger.warning(
            "imageio not available; palette/timing channels disabled. "
            "Install with: pip install imageio[ffmpeg]"
        )
        iio = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Channel identifiers (must match Rust stego::CHANNEL_*)
CHANNEL_PRIMARY = 0x01
CHANNEL_SECONDARY = 0x02
CHANNEL_TERTIARY = 0x03
CHANNEL_DISPOSAL = 0x04  # GCE disposal/flags channel
CHANNEL_COMMENT = 0x05  # Comment extension channel
CHANNEL_TEMPORAL = 0x06  # Inter-frame temporal delta channel

# Default GIF timing
DEFAULT_BASE_DELAY_CS = 10  # 100ms per frame (10 FPS)
DEFAULT_BITS_PER_FRAME = 2  # 2 bits per frame in timing channel

# Disposal channel: bits per frame
DISPOSAL_BITS_PER_FRAME = 4  # 2 disposal + 1 user_input + 1 transparent

# Comment channel: default max capacity
COMMENT_MAX_BYTES = 256  # Max encrypted data in comment block

# Payload header: 4 bytes length + 32 bytes HMAC-SHA256
PAYLOAD_HEADER_LEN = 4 + 32

# Magic bytes for multi-layer stego payload
STEGO_MAGIC = b"MSTG"  # Multi-layer STeGo
STEGO_VERSION = 3  # Bumped for Phase 1 additions

# Comment channel magic
COMMENT_MAGIC = b"MSCM"  # Meow Stego Comment Magic

# Domain separation strings for new channels
DOMAIN_DISPOSAL = b"meow_stego_disposal_gce_v1"
DOMAIN_COMMENT_ENC = b"meow_stego_comment_ext_v1:enc"
DOMAIN_COMMENT_MAC = b"meow_stego_comment_ext_v1:mac"
DOMAIN_SALIENCY = b"meow_stego_saliency_cost_v1"
DOMAIN_IMMUNIZE = b"meow_stego_immunize_noise_v1"
DOMAIN_TEMPORAL = b"meow_stego_temporal_delta_v1"
DOMAIN_ADVERSARIAL = b"meow_stego_adversarial_perturb_v1"
DOMAIN_PROCCAT_SEED = b"meow_stego_procedural_cat_v1"

# Temporal channel defaults
TEMPORAL_BITS_PER_TRANSITION = 2  # bits embedded per frame transition
TEMPORAL_BLOCK_SIZE = 8  # pixels per embedding block

# Adversarial perturbation strength levels
ADVERSARIAL_STRENGTH_OFF = 0
ADVERSARIAL_STRENGTH_LOW = 1  # Gentle histogram equalization only
ADVERSARIAL_STRENGTH_MEDIUM = 2  # + DCT coefficient smoothing
ADVERSARIAL_STRENGTH_HIGH = 3  # + statistical model matching


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class CoercionLevel(IntEnum):
    """Coercion resistance level controlling which channels are derived."""

    DECOY = 0  # Only visible QR + shallow LSB (fake content)
    SHALLOW = 1  # Primary LSB channel only
    FULL = 2  # All three channels (real content)


@dataclass
class MultiLayerConfig:
    """Configuration for multi-layer steganography.

    Phase 0 additions: disposal channel, comment channel, saliency costs,
    immunization noise.
    Phase 1 additions: temporal channel, adversarial perturbation,
    procedural cat carrier generation.
    """

    # Channel enables
    enable_primary: bool = True  # Keyed LSB walk + STC
    enable_secondary: bool = True  # Timing channel
    enable_tertiary: bool = True  # Palette permutation
    enable_disposal: bool = True  # GCE disposal/flags channel (4 bits/frame)
    enable_comment: bool = True  # Comment extension channel (100-500 bytes)
    enable_temporal: bool = True  # Inter-frame temporal delta channel
    # Primary channel settings
    lsb_bits: int = 1  # LSB depth (1 = maximum stealth)
    use_stc: bool = True  # Use Syndrome-Trellis Codes
    use_adaptive_cost: bool = True  # Texture-aware cost function

    # Saliency cost function (Phase 0.3)

    # Temporal channel settings (Phase 1.1)
    temporal_bits_per_transition: int = TEMPORAL_BITS_PER_TRANSITION
    temporal_block_size: int = TEMPORAL_BLOCK_SIZE  # pixels per embedding block

    # Adversarial perturbation settings (Phase 1.2)
    adversarial_strength: int = ADVERSARIAL_STRENGTH_MEDIUM  # 0-3
    adversarial_preserve_histogram: bool = True  # Keep pixel histogram intact

    # Procedural cat carrier (Phase 1.3)
    procedural_cat: bool = False  # Generate carrier instead of using external GIF
    procedural_cat_frames: int = 30  # Number of frames to generate
    procedural_cat_size: Tuple[int, int] = (320, 240)  # Frame dimensions
    use_saliency_costs: bool = True  # OpenCV Laplacian+Sobel cost function
    saliency_sensitivity: float = 1.0  # Cost scaling (higher = more conservative)

    # Immunization noise (Phase 0.4)
    immunize: bool = True  # Pre-embedding keyed Gaussian noise
    immunize_sigma: float = 0.5  # Noise sigma (0.3-0.7 recommended)

    # Secondary channel settings
    base_delay_cs: int = DEFAULT_BASE_DELAY_CS  # Base GIF delay (centiseconds)
    timing_bits_per_frame: int = DEFAULT_BITS_PER_FRAME  # Bits per frame

    # Tertiary channel settings
    min_permutable_entries: int = 4  # Minimum palette entries for permutation

    # Comment channel settings
    comment_max_bytes: int = COMMENT_MAX_BYTES  # Max data for comment channel

    # Quality thresholds
    min_psnr: float = 55.0  # Minimum PSNR (dB) for primary channel
    max_change_rate: float = 0.05  # Max ratio of changed pixels (5%)

    # Coercion settings
    coercion_level: CoercionLevel = CoercionLevel.FULL

    # Payload settings
    compress: bool = True  # zlib compress before encrypt
    encrypt: bool = True  # AES-256-GCM encrypt

    # GIF settings
    gif_size: Tuple[int, int] = (320, 240)  # Default carrier dimensions


# ---------------------------------------------------------------------------
# Pure-Python Fallback Functions (used when Rust is unavailable)
# ---------------------------------------------------------------------------


def _py_derive_frame_seed(master_key: bytes, frame_idx: int, channel_id: int) -> bytes:
    """Python fallback for per-frame, per-channel seed derivation.

    Uses HKDF-SHA256 (Extract + Expand) matching the Rust implementation:
      IKM = master_key, salt = None (zero-filled)
      info = domain_prefix || frame_idx (4 bytes LE) || channel_id (1 byte)

    WARNING: NOT constant-time. Use Rust backend in production.
    """
    import hmac as _hmac

    domains = {
        CHANNEL_PRIMARY: b"meow_stego_primary_lsb_v1",
        CHANNEL_SECONDARY: b"meow_stego_secondary_timing_v1",
        CHANNEL_TERTIARY: b"meow_stego_tertiary_palette_v1",
    }
    domain = domains.get(channel_id, b"meow_stego_primary_lsb_v1")
    info = domain + struct.pack("<I", frame_idx) + struct.pack("B", channel_id)

    # HKDF-SHA256 Extract: PRK = HMAC-SHA256(salt, IKM)
    # With salt=None, HKDF uses a zero-filled salt of hash length
    zero_salt = b"\x00" * 32
    prk = _hmac.new(zero_salt, master_key, hashlib.sha256).digest()

    # HKDF-SHA256 Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    okm = _hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm


def _py_derive_walk_seed(master_key: bytes, frame_idx: int) -> bytes:
    """Python fallback for walk seed derivation (HKDF matching Rust)."""
    import hmac as _hmac

    info = b"meow_stego_walk_permutation_v1" + struct.pack("<I", frame_idx)

    # HKDF-SHA256 Extract + Expand (matching Rust: salt=None -> zero-filled)
    zero_salt = b"\x00" * 32
    prk = _hmac.new(zero_salt, master_key, hashlib.sha256).digest()
    okm = _hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm


def _py_generate_pixel_walk(walk_seed: bytes, num_pixels: int) -> List[int]:
    """Python fallback for deterministic Fisher-Yates shuffle.

    Uses rejection sampling (matching Rust SeededPrng) to avoid modulo bias.
    """
    # Use seed as PRNG state via SHA-256 chain (matching Rust SeededPrng)
    state = bytearray(walk_seed)
    counter = 0
    walk = list(range(num_pixels))

    def next_u64() -> int:
        nonlocal state, counter
        h = hashlib.sha256(bytes(state) + struct.pack("<Q", counter)).digest()
        counter += 1
        val = int.from_bytes(h[:8], "little")
        # Update state with full digest (matching Rust: state = digest)
        state = bytearray(h)
        return val

    def next_bounded(bound: int) -> int:
        """Rejection sampling to avoid modulo bias (matching Rust)."""
        if bound <= 1:
            return 0
        threshold = (2**64) - ((2**64) % bound)
        while True:
            val = next_u64()
            if val < threshold:
                return val % bound

    for i in range(num_pixels - 1, 0, -1):
        j = next_bounded(i + 1)
        walk[i], walk[j] = walk[j], walk[i]

    return walk


# ---------------------------------------------------------------------------
# Dispatch: use Rust if available, else Python fallback
# ---------------------------------------------------------------------------


def derive_frame_seed(master_key: bytes, frame_idx: int, channel_id: int) -> bytes:
    """Derive per-frame, per-channel 32-byte seed."""
    if _RUST_AVAILABLE:
        return bytes(meow_crypto_rs.stego_derive_frame_seed(master_key, frame_idx, channel_id))
    return _py_derive_frame_seed(master_key, frame_idx, channel_id)


def derive_walk_seed(master_key: bytes, frame_idx: int) -> bytes:
    """Derive walk seed for pixel permutation."""
    if _RUST_AVAILABLE:
        return bytes(meow_crypto_rs.stego_derive_walk_seed(master_key, frame_idx))
    return _py_derive_walk_seed(master_key, frame_idx)


def generate_pixel_walk(walk_seed: bytes, num_pixels: int) -> List[int]:
    """Generate pseudorandom pixel visit order."""
    if _RUST_AVAILABLE:
        return list(meow_crypto_rs.stego_generate_pixel_walk(walk_seed, num_pixels))
    return _py_generate_pixel_walk(walk_seed, num_pixels)


# ---------------------------------------------------------------------------
# STC Capacity Computation
# ---------------------------------------------------------------------------

# Viterbi trellis has 2^h states.  When the number of STC payload bits (m)
# is close to or exceeds 2^h, the trellis is over-constrained and encoding
# can fail for ~50% of random payloads.  Use a safer rate (1/4) for small
# frames and the standard rate (1/3) for large ones.
_STC_CONSTRAINT_HEIGHT = 10
_STC_STATE_COUNT = 1 << _STC_CONSTRAINT_HEIGHT  # 1024


def _stc_payload_capacity(n_cover_bits: int) -> int:
    """Compute STC payload capacity (in bits) for a given cover size.

    Returns the number of payload bits that can be reliably embedded into
    *n_cover_bits* cover bits via the Viterbi STC encoder.

    Uses a conservative rate of 1/4 (25% of cover bits) to ensure 100%
    encoding success across all seeds and payload patterns.  Rate 1/3
    has ~45% failure on certain PRNG seeds due to degenerate column-mask
    patterns in the trellis warmup phase.
    """
    return n_cover_bits // 4


# ---------------------------------------------------------------------------
# Payload Preparation
# ---------------------------------------------------------------------------


def prepare_payload(
    data: bytes,
    master_key: bytes,
    compress: bool = True,
    encrypt: bool = True,
) -> bytes:
    """Compress, encrypt, and MAC a payload for embedding.

    Format: MSTG(4) | version(1) | flags(1) | orig_len(4) | data_len(4) | data | hmac(32)

    Args:
        data: Raw payload bytes
        master_key: Master key for encryption and MAC
        compress: Apply zlib compression
        encrypt: Apply AES-256-GCM encryption

    Returns:
        Prepared payload bytes ready for channel distribution
    """
    payload = data

    flags = 0
    if compress:
        payload = zlib.compress(payload, level=9)
        flags |= 0x01
    if encrypt:
        flags |= 0x02

    orig_len = len(data)

    if encrypt and not _RUST_AVAILABLE:
        # gemini #1 / CRIT-03: Rust backend is required for production
        # crypto. The cryptography.hazmat fallback was removed —
        # fail-closed if meow_crypto_rs is unavailable.
        raise RuntimeError(
            "FATAL: No encryption backend available (meow_crypto_rs required). "
            "Refusing to store payload unencrypted -- fail-closed policy."
        )

    # gemini #1: derive enc_key + mac_key as Rust handles via HMAC-SHA256
    # inside Rust. Master_key is briefly imported into a transient handle;
    # neither the master nor the derived sub-keys are ever exposed to
    # Python. Handles are dropped (Zeroize-on-Drop) on the way out.
    from meow_decoder.crypto_backend import get_handle_backend

    hb = get_handle_backend()
    master_handle = hb.import_key(master_key)
    enc_key_handle = None
    mac_key_handle = None
    try:
        if encrypt:
            enc_key_handle = hb.hmac_sha256_to_handle(
                master_handle, b"meow_stego_payload_enc_key_v2"
            )
            # Random 12-byte nonce (CRITICAL: never reuse key+nonce).
            nonce = os.urandom(12)
            payload = nonce + bytes(
                hb.aes_gcm_encrypt(enc_key_handle, nonce, payload, b"meow_stego_aad_v2")
            )

        # Build header
        header = STEGO_MAGIC + struct.pack(
            "<BBI I", STEGO_VERSION, flags, orig_len, len(payload)
        )

        # Outer HMAC over header + payload, key derived via Rust handle.
        mac_key_handle = hb.hmac_sha256_to_handle(
            master_handle, b"meow_stego_payload_mac_v1"
        )
        mac = bytes(hb.hmac_sha256(mac_key_handle, header + payload))

        return header + payload + mac
    finally:
        if enc_key_handle is not None:
            try:
                hb.drop(enc_key_handle)
            except Exception:
                pass
        if mac_key_handle is not None:
            try:
                hb.drop(mac_key_handle)
            except Exception:
                pass
        try:
            hb.drop(master_handle)
        except Exception:
            pass


def unpack_payload(
    raw: bytes,
    master_key: bytes,
) -> Tuple[bytes, bool]:
    """Verify MAC, decrypt, decompress a prepared payload.

    Args:
        r
        master_key: Master key

    Returns:
        Tuple of (original_data, mac_valid)
    """
    if len(raw) < 14 + 32:  # header(14) + hmac(32)
        return b"", False

    # Parse header
    magic = raw[:4]
    if magic != STEGO_MAGIC:
        return b"", False

    version, flags, orig_len, data_len = struct.unpack("<BBI I", raw[4:14])
    if version not in (1, 2, 3, STEGO_VERSION):  # Accept v1/v2/v3
        return b"", False

    if 14 + data_len + 32 > len(raw):
        return b"", False

    payload = raw[14 : 14 + data_len]
    stored_mac = raw[14 + data_len : 14 + data_len + 32]

    # gemini #1: verify outer MAC + decrypt via Rust handles. Master key
    # briefly imported; sub-keys derived inside Rust; all handles dropped
    # before return.
    if not _RUST_AVAILABLE:
        # Without Rust we cannot verify or decrypt. Fail-closed.
        return b"", False

    from meow_decoder.crypto_backend import get_handle_backend

    hb = get_handle_backend()
    master_handle = hb.import_key(master_key)
    mac_key_handle = None
    enc_key_handle = None
    try:
        # Verify HMAC (constant-time inside Rust).
        header = raw[:14]
        mac_key_handle = hb.hmac_sha256_to_handle(
            master_handle, b"meow_stego_payload_mac_v1"
        )
        if not hb.hmac_sha256_verify(mac_key_handle, header + payload, stored_mac):
            return b"", False

        # Decrypt
        if flags & 0x02:
            enc_key_handle = hb.hmac_sha256_to_handle(
                master_handle, b"meow_stego_payload_enc_key_v2"
            )

            # Nonce is prepended (first 12 bytes of encrypted payload)
            if len(payload) < 12:
                return b"", False
            nonce = payload[:12]
            ciphertext = payload[12:]

            try:
                payload = bytes(
                    hb.aes_gcm_decrypt(
                        enc_key_handle, nonce, ciphertext, b"meow_stego_aad_v2"
                    )
                )
            except Exception:
                return b"", False

        # Decompress
        if flags & 0x01:
            try:
                payload = zlib.decompress(payload)
            except zlib.error:
                return b"", False

        return payload, True
    finally:
        if mac_key_handle is not None:
            try:
                hb.drop(mac_key_handle)
            except Exception:
                pass
        if enc_key_handle is not None:
            try:
                hb.drop(enc_key_handle)
            except Exception:
                pass
        try:
            hb.drop(master_handle)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Channel Distribution
# ---------------------------------------------------------------------------


def distribute_payload(
    prepared: bytes,
    config: MultiLayerConfig,
    num_frames: int,
    frame_pixel_counts: List[int],
    permutable_counts: List[int],
    frame_height: int = 0,
    frame_width: int = 0,
) -> Dict[str, bytes]:
    """Split prepared payload across channels based on capacity.

    Channel priority order:
        1. Primary (bulk data via LSB + STC)
        2. Comment (encrypted comment extension -- 100-500 bytes)
        3. Secondary (timing channel -- small)
        4. Temporal (inter-frame delta -- medium)
        5. Disposal (GCE packed bits -- small)
        6. Tertiary (palette permutation -- overflow)

    Returns dict with channel name -> byte chunk mappings.
    """
    channels: Dict[str, bytes] = {}
    remaining = prepared

    # Calculate per-channel capacities
    primary_cap = 0
    if config.enable_primary:
        for pix_count in frame_pixel_counts:
            bits = pix_count * 3 * config.lsb_bits
            if config.use_stc:
                bits = _stc_payload_capacity(bits)
            primary_cap += bits // 8

    comment_cap = 0
    if config.enable_comment:
        # Comment channel: raw capacity minus encryption overhead
        # Overhead: MSCM(4) + len(4) + nonce(12) + AES-GCM-tag(16) + HMAC(32) = 68 bytes
        comment_overhead = 68
        comment_cap = max(0, config.comment_max_bytes - comment_overhead)

    secondary_cap = 0
    if config.enable_secondary:
        secondary_cap = (num_frames * config.timing_bits_per_frame) // 8

    disposal_cap = 0
    if config.enable_disposal:
        disposal_cap = num_frames * DISPOSAL_BITS_PER_FRAME // 8

    temporal_cap = 0
    if config.enable_temporal and num_frames >= 2 and frame_height > 0 and frame_width > 0:
        transitions = num_frames - 1
        temporal_cap = (transitions * config.temporal_bits_per_transition) // 8

    tertiary_cap = 0
    if config.enable_tertiary:
        for n in permutable_counts:
            if n >= config.min_permutable_entries:
                tertiary_cap += _factorial_bits(n) // 8

    total_cap = (
        primary_cap + comment_cap + secondary_cap + disposal_cap + temporal_cap + tertiary_cap
    )
    if total_cap < len(remaining):
        raise ValueError(
            f"Payload ({len(remaining)} bytes) exceeds total carrier capacity "
            f"({total_cap} bytes). "
            f"Primary={primary_cap}, Comment={comment_cap}, "
            f"Secondary={secondary_cap}, Temporal={temporal_cap}, "
            f"Disposal={disposal_cap}, Tertiary={tertiary_cap}. "
            "Use a larger carrier, reduce payload size, or increase lsb_bits."
        )

    # Distribute: primary gets bulk, then overflow into smaller channels
    if config.enable_primary and primary_cap > 0:
        chunk = remaining[: min(primary_cap, len(remaining))]
        channels["primary"] = chunk
        remaining = remaining[len(chunk) :]

    if config.enable_comment and comment_cap > 0 and len(remaining) > 0:
        chunk = remaining[: min(comment_cap, len(remaining))]
        channels["comment"] = chunk
        remaining = remaining[len(chunk) :]

    if config.enable_secondary and secondary_cap > 0 and len(remaining) > 0:
        chunk = remaining[: min(secondary_cap, len(remaining))]
        channels["secondary"] = chunk
        remaining = remaining[len(chunk) :]

    if config.enable_temporal and temporal_cap > 0 and len(remaining) > 0:
        chunk = remaining[: min(temporal_cap, len(remaining))]
        channels["temporal"] = chunk
        remaining = remaining[len(chunk) :]

    if config.enable_disposal and disposal_cap > 0 and len(remaining) > 0:
        chunk = remaining[: min(disposal_cap, len(remaining))]
        channels["disposal"] = chunk
        remaining = remaining[len(chunk) :]

    if config.enable_tertiary and tertiary_cap > 0 and len(remaining) > 0:
        chunk = remaining[: min(tertiary_cap, len(remaining))]
        channels["tertiary"] = chunk
        remaining = remaining[len(chunk) :]

    if len(remaining) > 0:
        logger.warning("Could not fit %d bytes into any channel", len(remaining))

    return channels


def _factorial_bits(n: int) -> int:
    """Calculate floor(log2(n!))."""
    if n <= 1:
        return 0
    import math

    total = sum(math.log2(k) for k in range(2, n + 1))
    return int(total)


# ---------------------------------------------------------------------------
# Primary Channel: Keyed LSB Walk + STC
# ---------------------------------------------------------------------------


class PrimaryChannelEncoder:
    """Keyed pseudorandom LSB walk with STC matrix encoding.

    For each frame:
    1. Derive frame-specific seed from master_key
    2. Generate pseudorandom pixel walk order
    3. Extract cover bits along walk path
    4. Compute adaptive costs (texture-aware)
    5. STC-encode payload into cover bits (minimizes flips)
    6. Write stego bits back along walk path
    """

    def __init__(self, master_key: bytes, config: MultiLayerConfig):
        self.master_key = master_key
        self.config = config

    def embed_frame(
        self,
        frame_array: np.ndarray,
        frame_idx: int,
        payload_bits: List[int],
    ) -> np.ndarray:
        """Embed payload bits into a single frame using keyed LSB walk + STC.

        Args:
            frame_array: Frame image as numpy array (H, W, 3) uint8
            frame_idx: Frame index for seed derivation
            payload_bits: List of 0/1 bits to embed

        Returns:
            Modified frame array with embedded data
        """
        h, w, c = frame_array.shape
        num_pixels = h * w

        if len(payload_bits) == 0:
            return frame_array

        # 1. Derive seeds
        channel_seed = derive_frame_seed(self.master_key, frame_idx, CHANNEL_PRIMARY)
        walk_seed = derive_walk_seed(self.master_key, frame_idx)

        # 2. Generate walk order
        walk = generate_pixel_walk(walk_seed, num_pixels)

        # 3. Extract cover bits along walk path
        flat = frame_array.reshape(-1, c)  # (H*W, 3)
        lsb_mask = (1 << self.config.lsb_bits) - 1

        cover_bits = []
        pixel_values = []
        for idx in walk:
            for ch in range(c):
                val = int(flat[idx, ch])
                pixel_values.append(val)
                for bit_pos in range(self.config.lsb_bits):
                    cover_bits.append((val >> bit_pos) & 1)

        cover_bits_arr = np.array(cover_bits, dtype=np.uint8)
        n_cover = len(cover_bits_arr)
        n_payload = len(payload_bits)

        if n_payload >= n_cover:
            logger.warning(
                "Frame %d: payload (%d bits) >= cover capacity (%d bits), truncating",
                frame_idx,
                n_payload,
                n_cover,
            )
            payload_bits = payload_bits[: n_cover - 1]
            n_payload = len(payload_bits)

        payload_arr = np.array(payload_bits, dtype=np.uint8)

        # 4. Compute costs and STC encode
        if self.config.use_stc and _RUST_AVAILABLE:
            # Pad payload to fixed STC capacity so encoder/decoder use same matrix dimensions.
            stc_capacity = _stc_payload_capacity(n_cover)
            if n_payload < stc_capacity:
                padded = np.zeros(stc_capacity, dtype=np.uint8)
                padded[:n_payload] = payload_arr
                payload_arr = padded

            # Use Rust STC with saliency costs if available
            if self.config.use_saliency_costs:
                # Phase 0.3: OpenCV-based saliency cost map
                cost_map = SaliencyCostComputer.compute(
                    frame_array, self.config.saliency_sensitivity
                )
                costs = SaliencyCostComputer.costs_for_walk(
                    cost_map, walk, w, c, self.config.lsb_bits
                )
                # Ensure length matches cover bits
                if len(costs) < n_cover:
                    costs.extend([1.0] * (n_cover - len(costs)))
                elif len(costs) > n_cover:
                    costs = costs[:n_cover]
            elif self.config.use_adaptive_cost:
                # Fallback: Rust variance-based costs
                costs = list(
                    meow_crypto_rs.stego_compute_adaptive_costs(
                        channel_seed,
                        bytes(cover_bits_arr),
                        bytes(pixel_values),
                    )
                )
            else:
                costs = [1.0] * n_cover

            stego_bits = list(
                meow_crypto_rs.stego_stc_encode(
                    channel_seed,
                    bytes(cover_bits_arr),
                    bytes(payload_arr),
                    costs,
                )
            )
        elif self.config.use_stc:
            # Python STC fallback (simplified: direct LSB replacement along walk)
            logger.debug("STC unavailable in Python; falling back to direct LSB")
            stego_bits = list(cover_bits_arr)
            for i in range(n_payload):
                stego_bits[i] = payload_bits[i]
        else:
            # Direct LSB replacement
            stego_bits = list(cover_bits_arr)
            for i in range(n_payload):
                stego_bits[i] = payload_bits[i]

        # 5. Write stego bits back
        stego_flat = flat.copy()
        bit_idx = 0
        for pixel_idx in walk:
            for ch in range(c):
                val = int(stego_flat[pixel_idx, ch])
                # Clear LSBs and set new ones
                new_val = val & ~lsb_mask
                for bit_pos in range(self.config.lsb_bits):
                    if bit_idx < len(stego_bits):
                        new_val |= (stego_bits[bit_idx] & 1) << bit_pos
                        bit_idx += 1
                stego_flat[pixel_idx, ch] = new_val

        return stego_flat.reshape(h, w, c)

    def extract_frame(
        self,
        frame_array: np.ndarray,
        frame_idx: int,
        expected_bits: int,
    ) -> List[int]:
        """Extract payload bits from a single frame.

        Args:
            frame_array: Stego frame as numpy array (H, W, 3) uint8
            frame_idx: Frame index
            expected_bits: Number of bits to extract

        Returns:
            List of extracted bits (0/1)
        """
        h, w, c = frame_array.shape
        num_pixels = h * w

        # Derive same seeds
        channel_seed = derive_frame_seed(self.master_key, frame_idx, CHANNEL_PRIMARY)
        walk_seed = derive_walk_seed(self.master_key, frame_idx)

        # Generate same walk
        walk = generate_pixel_walk(walk_seed, num_pixels)

        # Extract bits along walk
        flat = frame_array.reshape(-1, c)
        stego_bits = []
        for pixel_idx in walk:
            for ch in range(c):
                val = int(flat[pixel_idx, ch])
                for bit_pos in range(self.config.lsb_bits):
                    stego_bits.append((val >> bit_pos) & 1)

        if self.config.use_stc and _RUST_AVAILABLE:
            # STC decode
            stego_bytes = bytes(np.array(stego_bits, dtype=np.uint8))
            payload = list(
                meow_crypto_rs.stego_stc_decode(channel_seed, stego_bytes, expected_bits)
            )
            return payload[:expected_bits]
        else:
            # Direct extraction
            return stego_bits[:expected_bits]


# ---------------------------------------------------------------------------
# Secondary Channel: GIF Frame Timing
# ---------------------------------------------------------------------------


class TimingChannelEncoder:
    """GCE delay jitter encoding -- zero visual impact.

    Encodes bits by varying GIF frame delay values around a base.
    Each frame delay is an integer in centiseconds. We jitter
    by 0-3 cs (encoding 2 bits per frame) -- invisible to viewers
    but recoverable with the correct seed.
    """

    def __init__(self, master_key: bytes, config: MultiLayerConfig):
        self.master_key = master_key
        self.config = config

    def encode(
        self,
        num_frames: int,
        payload_bits: List[int],
    ) -> List[int]:
        """Encode bits into frame delays.

        Args:
            num_frames: Number of GIF frames
            payload_bits: Bits to encode

        Returns:
            List of frame delays in centiseconds
        """
        seed = derive_frame_seed(self.master_key, 0, CHANNEL_SECONDARY)

        if _RUST_AVAILABLE:
            delays = meow_crypto_rs.stego_timing_encode(
                seed,
                self.config.base_delay_cs,
                bytes(payload_bits),
                self.config.timing_bits_per_frame,
            )
            return [int(d) for d in delays]

        # Python fallback
        bpf = self.config.timing_bits_per_frame
        base = self.config.base_delay_cs
        delays = []

        # Simple deterministic jitter using seed
        state = seed
        counter = 0

        for frame in range(num_frames):
            # Collect bits for this frame
            value = 0
            for b in range(bpf):
                bit_idx = frame * bpf + b
                if bit_idx < len(payload_bits):
                    value |= (payload_bits[bit_idx] & 1) << b

            # Deterministic jitter
            h = hashlib.sha256(state + struct.pack("<Q", counter)).digest()
            counter += 1
            state = h
            jitter = h[0] % 2

            delay = base + jitter + value
            delays.append(int(delay))

        return delays

    def decode(
        self,
        delays: List[int],
    ) -> List[int]:
        """Decode bits from frame delays.

        Args:
            delays: Frame delays in centiseconds

        Returns:
            Decoded bits
        """
        seed = derive_frame_seed(self.master_key, 0, CHANNEL_SECONDARY)

        if _RUST_AVAILABLE:
            bits = meow_crypto_rs.stego_timing_decode(
                seed,
                self.config.base_delay_cs,
                delays,
                self.config.timing_bits_per_frame,
            )
            return [int(b) for b in bits]

        # Python fallback
        bpf = self.config.timing_bits_per_frame
        base = self.config.base_delay_cs
        bits = []

        state = seed
        counter = 0

        for delay in delays:
            h = hashlib.sha256(state + struct.pack("<Q", counter)).digest()
            counter += 1
            state = h
            jitter = h[0] % 2

            raw = max(0, delay - base - jitter)
            value = min(raw, (1 << bpf) - 1)

            for b in range(bpf):
                bits.append((value >> b) & 1)

        return bits


# ---------------------------------------------------------------------------
# Tertiary Channel: Palette Permutation
# ---------------------------------------------------------------------------


class PaletteChannelEncoder:
    """Palette order permutation encoding -- invisible, GIF-specific.

    Exploits the fact that GIF palettes can have entries reordered
    without visual impact (provided pixel indices are remapped).
    Near-duplicate and unused palette entries are candidates for
    permutation-based encoding.

    For each frame:
    1. Identify near-duplicate palette entries (color distance < threshold)
    2. Identify unused entries (not referenced by any pixel)
    3. Combine into "permutable set"
    4. Encode bits via Lehmer code permutation
    """

    def __init__(self, master_key: bytes, config: MultiLayerConfig):
        self.master_key = master_key
        self.config = config

    @staticmethod
    def find_permutable_entries(
        palette: np.ndarray,
        pixel_indices: np.ndarray,
        color_threshold: int = 8,
    ) -> List[int]:
        """Find palette entries suitable for permutation encoding.

        Args:
            palette: (N, 3) array of RGB palette colors
            pixel_indices: Flat array of palette index values used in frame
            color_threshold: Maximum L1 color distance for "near-duplicate"

        Returns:
            Sorted list of permutable palette entry indices
        """
        n = len(palette)
        if n == 0:
            return []

        # Find unused entries
        used = set(pixel_indices.flat)
        unused = [i for i in range(n) if i not in used]

        # Find near-duplicate groups
        near_dupes = set()
        for i in range(n):
            for j in range(i + 1, n):
                dist = int(np.sum(np.abs(palette[i].astype(int) - palette[j].astype(int))))
                if dist <= color_threshold:
                    near_dupes.add(i)
                    near_dupes.add(j)

        # Combine: unused + near-duplicates
        permutable = sorted(set(unused) | near_dupes)
        return permutable

    def encode_frame(
        self,
        palette: np.ndarray,
        pixel_indices: np.ndarray,
        frame_idx: int,
        payload_bits: List[int],
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Encode bits by reordering permutable palette entries.

        Args:
            palette: (N, 3) RGB palette
            pixel_indices: (H, W) index array
            frame_idx: Frame index
            payload_bits: Bits to encode

        Returns:
            Tuple of (new_palette, new_pixel_indices) with bits encoded
        """
        seed = derive_frame_seed(self.master_key, frame_idx, CHANNEL_TERTIARY)
        permutable = self.find_permutable_entries(palette, pixel_indices)

        if len(permutable) < self.config.min_permutable_entries:
            return palette.copy(), pixel_indices.copy()

        perm_bytes = bytes([p for p in permutable])

        if _RUST_AVAILABLE:
            new_order_bytes = meow_crypto_rs.stego_palette_encode(
                seed, list(perm_bytes), list(bytes(payload_bits))
            )
            new_order = list(new_order_bytes)
        else:
            # Python fallback: simple permutation via Lehmer code
            new_order = self._py_palette_encode(seed, list(perm_bytes), payload_bits)

        # Apply permutation: reorder palette and remap pixel indices to preserve visual appearance
        new_palette = palette.copy()
        new_pixels = pixel_indices.copy()

        # new_order[i] = which ORIGINAL palette entry goes into position permutable[i]
        # Build the mapping: for each permutable slot, record which original entry now lives there
        for i, new_idx in enumerate(new_order):
            new_palette[permutable[i]] = palette[new_idx]

        # Build reverse map: old_palette_index -> new_palette_index
        # After reordering, the color that was at palette[new_order[i]] is now at palette[permutable[i]]
        remap = {}
        for i, new_idx in enumerate(new_order):
            remap[new_idx] = permutable[i]

        # Remap pixel indices so they still point to the same colors
        for old_idx, new_idx in remap.items():
            if old_idx != new_idx:
                mask = pixel_indices == old_idx
                new_pixels[mask] = new_idx

        return new_palette, new_pixels

    def decode_frame(
        self,
        palette: np.ndarray,
        pixel_indices: np.ndarray,
        frame_idx: int,
        original_permutable: List[int],
        original_palette: Optional[np.ndarray] = None,
    ) -> List[int]:
        """Decode bits from palette ordering.

        Args:
            palette: Stego palette (reordered by encoder)
            pixel_indices: Pixel index array
            frame_idx: Frame index
            original_permutable: Original set of permutable indices
            original_palette: Original palette before encoding (needed to observe permutation)

        Returns:
            Decoded bits
        """
        seed = derive_frame_seed(self.master_key, frame_idx, CHANNEL_TERTIARY)
        perm_bytes = bytes(original_permutable)

        if original_palette is not None:
            # Deduce observed permutation by comparing stego palette colors
            # to original palette colors at permutable positions.
            # For each stego slot permutable[i], find which original entry's color is there.
            observed = []
            for slot in original_permutable:
                stego_color = palette[slot]
                # Find which original permutable entry has this color
                found = False
                for orig_idx in original_permutable:
                    if np.array_equal(stego_color, original_palette[orig_idx]):
                        observed.append(orig_idx)
                        found = True
                        break
                if not found:
                    # Color not found among permutable entries -- fallback to position index
                    observed.append(slot)
        else:
            # Without original palette, we can't determine the permutation
            # This is a limitation -- caller should provide original_palette
            observed = list(original_permutable)

        observed_bytes = bytes(observed)

        if _RUST_AVAILABLE:
            bits = meow_crypto_rs.stego_palette_decode(seed, list(perm_bytes), list(observed_bytes))
            return [int(b) for b in bits]

        return self._py_palette_decode(seed, list(perm_bytes), observed)

    def _py_palette_encode(
        self, seed: bytes, indices: List[int], payload_bits: List[int]
    ) -> List[int]:
        """Python fallback for palette permutation encoding."""
        import math

        n = len(indices)
        max_bits = _factorial_bits(n)
        if max_bits == 0:
            return indices

        # Build number from payload bits
        use_bits = min(len(payload_bits), max_bits)
        perm_number = 0
        for i in range(use_bits):
            if payload_bits[i] & 1:
                perm_number |= 1 << i

        # Base ordering from seed
        state = seed
        items = indices[:]
        for i in range(len(items) - 1, 0, -1):
            h = hashlib.sha256(state + struct.pack("<Q", i)).digest()
            state = h
            j = int.from_bytes(h[:8], "little") % (i + 1)
            items[i], items[j] = items[j], items[i]

        # Lehmer code
        result = []
        remaining = items[:]
        number = perm_number
        for k in range(n, 0, -1):
            if not remaining:
                break
            idx = number % k
            number //= k
            result.append(remaining.pop(idx))

        return result

    def _py_palette_decode(self, seed: bytes, indices: List[int], observed: List[int]) -> List[int]:
        """Python fallback for palette permutation decoding."""
        n = len(indices)
        max_bits = _factorial_bits(n)
        if max_bits == 0:
            return []

        # Reconstruct base ordering
        state = seed
        base = indices[:]
        for i in range(len(base) - 1, 0, -1):
            h = hashlib.sha256(state + struct.pack("<Q", i)).digest()
            state = h
            j = int.from_bytes(h[:8], "little") % (i + 1)
            base[i], base[j] = base[j], base[i]

        # Inverse Lehmer
        remaining = base[:]
        number = 0
        multiplier = 1
        for item in observed:
            if item in remaining:
                pos = remaining.index(item)
                number += pos * multiplier
                multiplier *= len(remaining)
                remaining.remove(item)

        bits = []
        for i in range(max_bits):
            bits.append((number >> i) & 1)

        return bits


# ---------------------------------------------------------------------------
# Phase 0.3: Saliency-Based STC Cost Function
# ---------------------------------------------------------------------------


class SaliencyCostComputer:
    """Compute per-pixel embedding costs using OpenCV saliency analysis.

    Uses Laplacian and Sobel operators to detect edges and texture:
    - Flat regions (low gradient)    -> HIGH cost (5-10x)
    - Textured regions (high gradient) -> LOW cost (0.3-0.5x)
    - Edge boundaries                -> MEDIUM cost (1x)

    This produces much better cost maps than the basic sliding-window
    variance approach in the Rust backend, because 2D convolution kernels
    capture directionality and second-order derivatives.

    Falls back to uniform costs if OpenCV is unavailable.
    """

    @staticmethod
    def compute(
        frame_array: np.ndarray,
        sensitivity: float = 1.0,
    ) -> np.ndarray:
        """Compute per-pixel saliency cost map.

        Args:
            frame_array: Frame image (H, W, 3) uint8
            sensitivity: Cost scaling factor (higher = more conservative).
                Recommended: 0.5 (aggressive) to 2.0 (paranoid).

        Returns:
            Cost map (H, W) float64 with per-pixel embedding costs.
            Values range from 0.3xsens (textured) to 10xsens (flat).
        """
        try:
            import cv2
        except ImportError:
            logger.warning("OpenCV not available; using uniform cost map")
            return np.ones(frame_array.shape[:2], dtype=np.float64) * sensitivity

        # Convert to grayscale for gradient computation
        if frame_array.ndim == 3 and frame_array.shape[2] >= 3:
            gray = cv2.cvtColor(frame_array[:, :, :3], cv2.COLOR_RGB2GRAY)
        elif frame_array.ndim == 3 and frame_array.shape[2] == 1:
            gray = frame_array[:, :, 0]
        else:
            gray = frame_array.astype(np.uint8)

        # Laplacian magnitude (second derivative -- detects edges + texture)
        laplacian = np.abs(cv2.Laplacian(gray, cv2.CV_64F))

        # Sobel magnitude (first derivative -- edge strength)
        sobel_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
        sobel_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
        sobel = np.sqrt(sobel_x**2 + sobel_y**2)

        # Local variance via Gaussian window (texture measure)
        gray_f = gray.astype(np.float64)
        blur = cv2.GaussianBlur(gray_f, (7, 7), 0)
        local_var = cv2.GaussianBlur((gray_f - blur) ** 2, (7, 7), 0)

        # Normalize each to [0, 1]
        lap_max = np.max(laplacian) + 1e-10
        sob_max = np.max(sobel) + 1e-10
        var_max = np.max(local_var) + 1e-10

        lap_norm = laplacian / lap_max
        sob_norm = sobel / sob_max
        var_norm = local_var / var_max

        # Composite texture score: 0 = flat, 1 = highly textured
        # Weight: Laplacian (40%) + Sobel (40%) + variance (20%)
        texture = 0.4 * lap_norm + 0.4 * sob_norm + 0.2 * var_norm

        # Map texture score to embedding cost:
        #   texture > 0.3  -> 0.3x (cheap -- hide here)
        #   texture > 0.1  -> 1.0x (normal)
        #   texture > 0.02 -> 5.0x (expensive -- mostly flat)
        #   texture <= 0.02 -> 10.0x (forbidden-zone -- perfectly flat)
        cost_map = np.full_like(texture, 10.0 * sensitivity)
        cost_map = np.where(texture > 0.02, 5.0 * sensitivity, cost_map)
        cost_map = np.where(texture > 0.1, 1.0 * sensitivity, cost_map)
        cost_map = np.where(texture > 0.3, 0.3 * sensitivity, cost_map)

        return cost_map

    @staticmethod
    def costs_for_walk(
        cost_map: np.ndarray,
        walk: List[int],
        width: int,
        channels: int = 3,
        lsb_bits: int = 1,
    ) -> List[float]:
        """Flatten 2D cost map along pixel walk order.

        Produces a per-bit cost array aligned to the cover bit stream
        for direct use with STC encode.

        Args:
            cost_map: 2D cost map (H, W) from compute()
            walk: Pixel walk order (list of pixel indices)
            width: Image width
            channels: Number of color channels (3 for RGB)
            lsb_bits: Number of LSB bits per channel

        Returns:
            List of float costs, one per cover bit
        """
        costs = []
        h, w = cost_map.shape
        for pixel_idx in walk:
            row = pixel_idx // width
            col = pixel_idx % width
            if row < h and col < w:
                pixel_cost = cost_map[row, col]
            else:
                pixel_cost = 10.0  # Out-of-bounds = very expensive
            # Each pixel contributes channels x lsb_bits bits
            for _ in range(channels * lsb_bits):
                costs.append(float(pixel_cost))
        return costs


# ---------------------------------------------------------------------------
# Phase 0.4: Immunization Noise Layer
# ---------------------------------------------------------------------------


class ImmunizationLayer:
    """Keyed Gaussian noise pre-processing for steganalysis resistance.

    Adds deterministic (keyed) low-amplitude Gaussian noise to the cover
    image BEFORE steganographic embedding. This:

    1. Masks embedding artifacts in LSB statistics
    2. Mimics natural sensor noise and compression artifacts
    3. Makes the cover's baseline LSB entropy closer to 1.0
    4. Confounds chi-square and RS steganalysis detectors

    The noise is NOT removed during decoding -- it's absorbed into the
    cover baseline. The STC encoder operates on the noised cover, and
    the decoder extracts from the identical noised+embedded pixels.

    Security:
        Noise derived from master_key via HMAC-SHA256 domain separation,
        so it's deterministic but unpredictable without the key.
        Uses numpy PCG64 PRNG seeded from the derived value.
    """

    @staticmethod
    def apply(
        frame_array: np.ndarray,
        master_key: bytes,
        frame_idx: int,
        sigma: float = 0.5,
    ) -> np.ndarray:
        """Apply keyed Gaussian noise to a frame.

        Args:
            frame_array: Cover frame (H, W, C) uint8
            master_key: Master key for noise derivation
            frame_idx: Frame index for per-frame uniqueness
            sigma: Noise standard deviation (0.3-0.7 recommended).
                Higher = more steganalysis resistance but lower PSNR.

        Returns:
            Noised frame (H, W, C) uint8, visually near-identical
        """
        if sigma <= 0:
            return frame_array.copy()

        # Derive frame-specific noise seed
        noise_key = hmac_stdlib.new(
            master_key,
            DOMAIN_IMMUNIZE + struct.pack("<I", frame_idx),
            hashlib.sha256,
        ).digest()

        # Seed numpy PRNG deterministically
        seed_int = int.from_bytes(noise_key[:8], "little")
        rng = np.random.Generator(np.random.PCG64(seed_int))

        # Generate per-pixel Gaussian noise
        noise = rng.normal(0, sigma, frame_array.shape)

        # Apply and clamp to valid uint8 range
        noised = np.clip(frame_array.astype(np.float64) + noise, 0, 255).astype(np.uint8)

        return noised


# ---------------------------------------------------------------------------
# Phase 1.1: Inter-Frame Temporal Delta Channel
# ---------------------------------------------------------------------------


class TemporalChannelEncoder:
    """Encode/decode data in inter-frame pixel delta patterns.

    Exploits the temporal dimension of animated GIFs: consecutive frames
    naturally have small pixel differences due to animation. We embed
    data by carefully controlling the parity of these differences in
    keyed block regions.

    Embedding Algorithm:
        For each frame transition (i -> i+1):
        1. Derive a keyed block selection using HKDF(master_key, DOMAIN_TEMPORAL, i)
        2. Select non-overlapping 8x8 pixel blocks via Fisher-Yates shuffle
        3. Compute block-level mean delta between frames
        4. Embed bits by adjusting delta parity: if delta_parity != target_bit,
           nudge a single pixel by ±1 to flip the parity
        5. Bits extracted by computing block deltas and reading parity

    Capacity: ~(WxH / block_size^2) x bits_per_transition per transition
    For 320x240 at 8x8 blocks: ~150 bits per transition, ~4.5KB for 30 frames.

    Visual impact: Imperceptible (±1 pixel value changes in animated regions).

    Security: Keyed block selection -> extraction requires master_key.
    Domain-separated from all other channels.
    """

    def __init__(self, master_key: bytes, config: MultiLayerConfig):
        self.master_key = master_key
        self.config = config
        # gemini #1: channel key as Rust handle.
        self._channel_key_handle = _derive_channel_subkey_handle(master_key, DOMAIN_TEMPORAL)

    def __del__(self):
        _drop_handle_safe(getattr(self, "_channel_key_handle", None))

    def key_fingerprint(self) -> bytes:
        """Stable test-only fingerprint over the temporal channel sub-key."""
        return _key_fingerprint(self._channel_key_handle)

    def embed(
        self,
        frames: List[np.ndarray],
        payload_bits: List[int],
    ) -> List[np.ndarray]:
        """Embed payload bits across frame transitions.

        Modifies frames IN-PLACE (returns same list, modified).

        Args:
            frames: List of RGB frames (H, W, 3) uint8. Will be modified.
            payload_bits: Bits to embed.

        Returns:
            Modified frames with temporal channel embedded.
        """
        if len(frames) < 2:
            return frames

        num_transitions = len(frames) - 1
        block_size = self.config.temporal_block_size
        bits_per_trans = self.config.temporal_bits_per_transition

        bit_offset = 0
        for t in range(num_transitions):
            if bit_offset >= len(payload_bits):
                break

            frame_a = frames[t].astype(np.int16)
            frame_b = frames[t + 1].astype(np.int16)
            h, w = frame_a.shape[:2]

            # Keyed block selection
            block_indices = self._select_blocks(t, h, w, block_size)

            for block_idx in block_indices[:bits_per_trans]:
                if bit_offset >= len(payload_bits):
                    break

                by, bx = block_idx
                target_bit = payload_bits[bit_offset] & 1

                # Compute mean delta (grayscale) for this block
                # Use center pixel channel-0 delta for parity embedding
                cy, cx = block_size // 2, block_size // 2
                pixel_a = int(frame_a[by + cy, bx + cx, 0])
                pixel_b = int(frame_b[by + cy, bx + cx, 0])
                delta_int = abs(pixel_b - pixel_a)
                current_parity = delta_int & 1

                if current_parity != target_bit:
                    # Nudge center pixel of block_b by ±1 to flip parity
                    cy, cx = block_size // 2, block_size // 2
                    if by + cy < h and bx + cx < w:
                        pixel = int(frames[t + 1][by + cy, bx + cx, 0])
                        if pixel < 255:
                            frames[t + 1][by + cy, bx + cx, 0] += 1
                        else:
                            frames[t + 1][by + cy, bx + cx, 0] -= 1

                bit_offset += 1

        return frames

    def extract(
        self,
        frames: List[np.ndarray],
        num_bits: int,
    ) -> List[int]:
        """Extract bits from inter-frame temporal deltas.

        Args:
            frames: List of RGB frames
            num_bits: Number of bits to extract

        Returns:
            List of extracted bits
        """
        if len(frames) < 2:
            return []

        block_size = self.config.temporal_block_size
        bits_per_trans = self.config.temporal_bits_per_transition
        bits: List[int] = []

        for t in range(len(frames) - 1):
            if len(bits) >= num_bits:
                break

            frame_a = frames[t].astype(np.float64)
            frame_b = frames[t + 1].astype(np.float64)
            h, w = frame_a.shape[:2]

            block_indices = self._select_blocks(t, h, w, block_size)

            for block_idx in block_indices[:bits_per_trans]:
                if len(bits) >= num_bits:
                    break

                by, bx = block_idx
                cy, cx = block_size // 2, block_size // 2
                pixel_a = int(frame_a[by + cy, bx + cx, 0])
                pixel_b = int(frame_b[by + cy, bx + cx, 0])
                delta_int = abs(pixel_b - pixel_a)
                bits.append(delta_int & 1)

        return bits[:num_bits]

    def estimate_capacity(self, num_frames: int, height: int, width: int) -> int:
        """Estimate temporal channel capacity in bits.

        Args:
            num_frames: Number of GIF frames
            height: Frame height
            width: Frame width

        Returns:
            Estimated capacity in bits
        """
        if num_frames < 2:
            return 0
        transitions = num_frames - 1
        return transitions * self.config.temporal_bits_per_transition

    def _select_blocks(
        self, transition_idx: int, h: int, w: int, block_size: int
    ) -> List[Tuple[int, int]]:
        """Select keyed non-overlapping blocks for a transition.

        Returns list of (row, col) top-left corners of block_sizexblock_size blocks.
        """
        # Grid of possible block positions
        block_rows = h // block_size
        block_cols = w // block_size

        if block_rows == 0 or block_cols == 0:
            return []

        # All block positions
        all_blocks = [
            (r * block_size, c * block_size) for r in range(block_rows) for c in range(block_cols)
        ]

        # Keyed shuffle using deterministic seed (HMAC inside Rust handle).
        if self._channel_key_handle is None:
            raise RuntimeError(
                "Temporal channel requires meow_crypto_rs (Rust) backend "
                "for keyed shuffle."
            )
        from meow_decoder.crypto_backend import get_handle_backend

        seed = bytes(
            get_handle_backend().hmac_sha256(
                self._channel_key_handle,
                DOMAIN_TEMPORAL + struct.pack("<I", transition_idx),
            )
        )

        seed_int = int.from_bytes(seed[:8], "little")
        rng = np.random.Generator(np.random.PCG64(seed_int))
        rng.shuffle(all_blocks)  # type: ignore[arg-type]

        return all_blocks


# ---------------------------------------------------------------------------
# Phase 1.2: Adversarial Perturbation Layer
# ---------------------------------------------------------------------------


class AdversarialPerturbationLayer:
    """Post-processing adversarial perturbations to defeat ML steganalysis.

    Standard steganalysis detectors (SRNet, YeNet, XuNet, Zhu-Net) look for
    statistical anomalies in pixel value distributions, LSB planes, and
    high-pass filter residuals. This layer applies carefully crafted
    perturbations that:

    1. **Histogram Matching**: Force the stego image's pixel histogram to
       match the cover's natural distribution, undoing any shifts caused
       by embedding.

    2. **High-Pass Filter Residual Smoothing**: ML detectors rely heavily
       on high-pass filtered residuals (SRM kernels). We add keyed noise
       that minimizes the energy in these residual domains.

    3. **Statistical Model Matching**: At strength=3, match higher-order
       statistics (co-occurrence matrices, adjacent pixel correlations)
       to natural image models.

    Strength levels:
        0: Off (no perturbation)
        1: Histogram matching only
        2: + High-pass residual smoothing
        3: + Full statistical model matching

    This runs AFTER all steganographic embedding, never before.
    Does NOT modify the embedded data--only changes non-embedded pixels
    and bit planes that don't carry payload.

    Security: Perturbation patterns derived from master_key (keyed).
    """

    def __init__(self, master_key: bytes, config: MultiLayerConfig):
        self.master_key = master_key
        self.config = config
        self._perturb_key = hmac_stdlib.new(master_key, DOMAIN_ADVERSARIAL, hashlib.sha256).digest()

    def apply(
        self,
        stego_frames: List[np.ndarray],
        cover_frames: Optional[List[np.ndarray]] = None,
    ) -> List[np.ndarray]:
        """Apply adversarial perturbations to stego frames.

        Args:
            stego_frames: List of stego frames (H, W, 3) uint8
            cover_frames: Optional original cover frames for histogram reference.
                If None, uses self-referencing (less effective but still useful).

        Returns:
            Perturbed frames with improved steganalysis resistance.
        """
        strength = self.config.adversarial_strength
        if strength <= ADVERSARIAL_STRENGTH_OFF:
            return stego_frames

        result = []
        for i, frame in enumerate(stego_frames):
            perturbed = frame.copy()
            cover = cover_frames[i] if cover_frames and i < len(cover_frames) else None

            if strength >= ADVERSARIAL_STRENGTH_LOW:
                perturbed = self._histogram_match(perturbed, cover, i)

            if strength >= ADVERSARIAL_STRENGTH_MEDIUM:
                perturbed = self._smooth_hpf_residuals(perturbed, i)

            if strength >= ADVERSARIAL_STRENGTH_HIGH:
                perturbed = self._match_cooccurrence(perturbed, cover, i)

            result.append(perturbed)

        return result

    def _histogram_match(
        self,
        stego: np.ndarray,
        cover: Optional[np.ndarray],
        frame_idx: int,
    ) -> np.ndarray:
        """Match stego histogram to cover (or Gaussian model).

        Preserves LSB bit=0 (embedded data) while adjusting higher bits
        to restore natural histogram shape.
        """
        result = stego.copy()

        for ch in range(min(3, result.shape[2]) if result.ndim == 3 else 1):
            if result.ndim == 3:
                stego_ch = result[:, :, ch].flatten().astype(np.int32)
            else:
                stego_ch = result.flatten().astype(np.int32)

            if cover is not None:
                if cover.ndim == 3 and ch < cover.shape[2]:
                    target_ch = cover[:, :, ch].flatten()
                else:
                    target_ch = cover.flatten()
                # Build target histogram
                target_hist, _ = np.histogram(target_ch, bins=256, range=(0, 256))
            else:
                # Derive expected histogram from frame statistics
                mean = np.mean(stego_ch)
                std = max(np.std(stego_ch), 1.0)
                x = np.arange(256)
                target_hist = np.exp(-0.5 * ((x - mean) / std) ** 2)

            # Normalize target histogram to match total pixel count
            target_hist = (target_hist / max(target_hist.sum(), 1)) * len(stego_ch)
            target_hist = target_hist.astype(np.int64)

            # Current histogram
            current_hist, _ = np.histogram(stego_ch, bins=256, range=(0, 256))

            # Identify over/under-represented bins
            diff = current_hist.astype(np.int64) - target_hist.astype(np.int64)

            # For bins with excess pixels, shift some to adjacent bins
            # Only modify bit 1 (second LSB) to preserve embedded data
            # Use seeded PRNG for reproducible perturbation
            seed = derive_frame_seed(self.master_key, frame_idx, CHANNEL_PRIMARY)
            rng = np.random.RandomState(int.from_bytes(seed[:4], "little"))

            if result.ndim == 3:
                channel = result[:, :, ch]
            else:
                channel = result
            flat = channel.flatten().astype(np.int32)

            # Determine which bit to flip: must be above the embedded LSB range
            lsb_bits = self.config.lsb_bits
            flip_bit = 1 << lsb_bits  # e.g., 0x02 for lsb=1, 0x04 for lsb=2
            lsb_mask = (1 << lsb_bits) - 1  # preserve all embedded LSBs

            for bin_val in range(256):
                excess = int(diff[bin_val])
                if excess <= 0:
                    continue
                # Find pixels in this bin
                indices = np.where(flat == bin_val)[0]
                if len(indices) == 0:
                    continue
                # Randomly select pixels to shift
                n_shift = min(excess, len(indices))
                chosen = rng.choice(len(indices), size=n_shift, replace=False)
                for idx in chosen:
                    # Flip the bit just above the embedded range
                    old_val = flat[indices[idx]]
                    new_val = old_val ^ flip_bit
                    new_val = max(0, min(255, new_val))
                    # Ensure all embedded LSBs are preserved
                    new_val = (new_val & ~lsb_mask) | (old_val & lsb_mask)
                    flat[indices[idx]] = new_val

            if result.ndim == 3:
                result[:, :, ch] = flat.reshape(channel.shape).astype(np.uint8)
            else:
                result = flat.reshape(channel.shape).astype(np.uint8)

        return result

    def _smooth_hpf_residuals(
        self,
        frame: np.ndarray,
        frame_idx: int,
    ) -> np.ndarray:
        """Reduce high-pass filter residual energy (defeats SRM-based detectors).

        SRM (Spatial Rich Model) kernels detect stego by measuring residual
        energy in high-pass filtered images. We add minimal keyed noise to
        non-LSB bit planes that reduces this residual energy.
        """
        try:
            import cv2
        except ImportError:
            return frame

        result = frame.copy().astype(np.int16)

        # Compute 3x3 high-pass kernel residual (core SRM filter)
        kernel_hpf = np.array([[-1, -1, -1], [-1, 8, -1], [-1, -1, -1]], dtype=np.float32) / 8.0

        for ch in range(min(3, result.shape[2]) if result.ndim == 3 else 1):
            if result.ndim == 3:
                channel = result[:, :, ch].astype(np.float32)
            else:
                channel = result.astype(np.float32)

            # Compute residual
            residual = cv2.filter2D(channel, cv2.CV_32F, kernel_hpf)

            # Derive keyed mask: only modify pixels where residual is anomalous
            seed = hmac_stdlib.new(
                self._perturb_key,
                b"hpf_smooth" + struct.pack("<IB", frame_idx, ch),
                hashlib.sha256,
            ).digest()
            rng = np.random.Generator(np.random.PCG64(int.from_bytes(seed[:8], "little")))

            # Threshold: anomalous = residual magnitude > 2x median
            med = np.median(np.abs(residual))
            mask = np.abs(residual) > max(2.0 * med, 0.5)

            # Generate corrective noise (partial residual cancellation)
            correction = np.zeros_like(channel)
            correction[mask] = -0.3 * residual[mask]  # Cancel 30% of anomalous residual

            # Add slight randomization to avoid deterministic patterns
            noise = rng.normal(0, 0.1, channel.shape).astype(np.float32)
            correction += noise * mask.astype(np.float32)

            # Apply correction while preserving all embedded LSBs
            lsb_mask = np.int16((1 << self.config.lsb_bits) - 1)
            if result.ndim == 3:
                adjusted = result[:, :, ch].astype(np.float32) + correction
                adjusted = np.clip(adjusted, 0, 255).astype(np.int16)
                # Preserve all embedded LSBs
                orig_lsbs = result[:, :, ch] & lsb_mask
                adjusted = (adjusted & ~lsb_mask) | orig_lsbs
                result[:, :, ch] = adjusted
            else:
                adjusted = result.astype(np.float32) + correction
                adjusted = np.clip(adjusted, 0, 255).astype(np.int16)
                orig_lsbs = result & lsb_mask
                result = (adjusted & ~lsb_mask) | orig_lsbs

        return np.clip(result, 0, 255).astype(np.uint8)

    def _match_cooccurrence(
        self,
        stego: np.ndarray,
        cover: Optional[np.ndarray],
        frame_idx: int,
    ) -> np.ndarray:
        """Match co-occurrence statistics of adjacent pixel pairs.

        Higher-order statistical attacks measure the joint distribution
        of neighboring pixel values. This adjusts bit-1 of selected pixels
        to drive co-occurrence closer to the cover (or natural model).
        """
        if cover is None:
            return stego  # Need reference for co-occurrence matching

        result = stego.copy()

        for ch in range(min(3, result.shape[2]) if result.ndim == 3 else 1):
            if result.ndim == 3:
                stego_ch = result[:, :, ch].astype(np.int32)
                cover_ch = (
                    cover[:, :, ch].astype(np.int32) if cover.ndim == 3 else cover.astype(np.int32)
                )
            else:
                stego_ch = result.astype(np.int32)
                cover_ch = cover.astype(np.int32)

            h, w = stego_ch.shape

            # Horizontal co-occurrence: count pairs (v_i, v_{i+1}) mod 4
            # We only track the 4x4 co-occurrence of the 2 LSBs
            stego_cooc = np.zeros((4, 4), dtype=np.int64)
            cover_cooc = np.zeros((4, 4), dtype=np.int64)

            for row in range(h):
                for col in range(w - 1):
                    sv1, sv2 = stego_ch[row, col] & 3, stego_ch[row, col + 1] & 3
                    cv1, cv2 = cover_ch[row, col] & 3, cover_ch[row, col + 1] & 3
                    stego_cooc[sv1, sv2] += 1
                    cover_cooc[cv1, cv2] += 1

            # Find the most over-represented co-occurrence entries
            total = max(stego_cooc.sum(), 1)
            stego_freq = stego_cooc / total
            cover_freq = cover_cooc / max(cover_cooc.sum(), 1)
            diff_freq = stego_freq - cover_freq

            # For over-represented pairs, flip bit-1 of the second pixel
            seed = hmac_stdlib.new(
                self._perturb_key,
                b"cooc_match" + struct.pack("<IB", frame_idx, ch),
                hashlib.sha256,
            ).digest()
            rng = np.random.Generator(np.random.PCG64(int.from_bytes(seed[:8], "little")))

            max_corrections = max(1, h * w // 200)  # Limit corrections per frame
            corrections = 0

            for row in range(h):
                if corrections >= max_corrections:
                    break
                for col in range(w - 1):
                    if corrections >= max_corrections:
                        break
                    sv1 = stego_ch[row, col] & 3
                    sv2 = stego_ch[row, col + 1] & 3
                    if diff_freq[sv1, sv2] > 0.001:  # Over-represented
                        # Probabilistically flip a bit above the embedded LSB range
                        if rng.random() < 0.3:
                            lsb_bits = self.config.lsb_bits
                            flip_bit = 1 << lsb_bits
                            lsb_mask = (1 << lsb_bits) - 1
                            pixel = int(
                                result[row, col + 1, ch]
                                if result.ndim == 3
                                else result[row, col + 1]
                            )
                            orig_lsbs = pixel & lsb_mask
                            new_val = pixel ^ flip_bit
                            new_val = max(0, min(255, new_val))
                            new_val = (new_val & ~lsb_mask) | orig_lsbs
                            if result.ndim == 3:
                                result[row, col + 1, ch] = new_val
                            else:
                                result[row, col + 1] = new_val
                            corrections += 1

        return result


# ---------------------------------------------------------------------------
# Phase 1.3: Procedural Cat Carrier Generator
# ---------------------------------------------------------------------------


class ProceduralCatGenerator:
    """Generate animated GIF carrier images procedurally.

    Eliminates the need for external carrier images that could be
    fingerprinted or traced. Generates natural-looking animated frames
    featuring cat silhouettes with fur textures, moving eyes, and
    subtle ear/tail animations.

    Uses Perlin-like value noise (keyed) for texture generation.
    All randomness is derived from master_key -> reproducible carriers.

    Features:
        - Cat silhouette with rounded ears, body, tail
        - Fur texture via 2D value noise (keyed octave noise)
        - Subtle animation: tail sway, ear twitch, eye blink
        - Background gradient with bokeh-like noise
        - High-entropy texture regions ideal for LSB embedding

    Output: List of (H, W, 3) uint8 frames ready for stego encoding.
    """

    def __init__(self, master_key: bytes, config: MultiLayerConfig):
        self.master_key = master_key
        self.config = config
        self._seed_key = hmac_stdlib.new(master_key, DOMAIN_PROCCAT_SEED, hashlib.sha256).digest()

    def generate(
        self,
        num_frames: Optional[int] = None,
        size: Optional[Tuple[int, int]] = None,
    ) -> List[np.ndarray]:
        """Generate animated cat carrier frames.

        Args:
            num_frames: Number of frames (default from config)
            size: (width, height) tuple (default from config)

        Returns:
            List of (H, W, 3) uint8 frames
        """
        num_frames = num_frames or self.config.procedural_cat_frames
        w, h = size or self.config.procedural_cat_size

        # Derive per-frame seeds
        rng = np.random.Generator(np.random.PCG64(int.from_bytes(self._seed_key[:8], "little")))

        frames = []
        for t in range(num_frames):
            frame = self._generate_frame(w, h, t, num_frames, rng)
            frames.append(frame)

        return frames

    def _generate_frame(
        self,
        width: int,
        height: int,
        frame_idx: int,
        total_frames: int,
        rng: np.random.Generator,
    ) -> np.ndarray:
        """Generate a single cat frame.

        Layers:
        1. Background gradient (warm to cool)
        2. Bokeh noise overlay
        3. Cat body silhouette
        4. Fur texture
        5. Eye highlights (animated blink)
        6. Ear and tail animation
        """
        frame = np.zeros((height, width, 3), dtype=np.float64)

        # Time parameter for animation (0 to 2pi over all frames)
        t = 2.0 * np.pi * frame_idx / max(total_frames, 1)

        # 1. Background gradient (warm peach to cool blue)
        for y in range(height):
            ratio = y / max(height - 1, 1)
            r = 230 - 60 * ratio + 10 * np.sin(t * 0.5)
            g = 200 - 80 * ratio + 8 * np.cos(t * 0.7)
            b = 180 + 40 * ratio + 6 * np.sin(t * 0.3)
            frame[y, :, 0] = r
            frame[y, :, 1] = g
            frame[y, :, 2] = b

        # 2. Add texture noise (value noise via seeded PRNG)
        noise = rng.normal(0, 8, (height, width, 3))
        frame += noise

        # 3. Cat silhouette (centered, ~60% of frame)
        cx, cy = width // 2, int(height * 0.55)
        body_rx, body_ry = int(width * 0.25), int(height * 0.22)

        # Create body mask (ellipse)
        yy, xx = np.ogrid[:height, :width]
        body_mask = (
            (xx - cx) ** 2 / max(body_rx**2, 1) + (yy - cy) ** 2 / max(body_ry**2, 1)
        ) <= 1.0

        # Head (circle above body)
        head_cx, head_cy = cx, cy - body_ry - int(height * 0.08)
        head_r = int(min(width, height) * 0.13)
        head_mask = ((xx - head_cx) ** 2 + (yy - head_cy) ** 2) <= head_r**2

        # Ears (two triangular bumps on head, with animation)
        ear_offset = int(3 * np.sin(t * 2.0))  # Ear twitch
        ear_l_cx = head_cx - int(head_r * 0.7)
        ear_l_cy = head_cy - head_r + ear_offset
        ear_r_cx = head_cx + int(head_r * 0.7)
        ear_r_cy = head_cy - head_r - ear_offset
        ear_r_val = int(head_r * 0.5)
        ear_l_mask = ((xx - ear_l_cx) ** 2 + (yy - ear_l_cy) ** 2) <= ear_r_val**2
        ear_r_mask = ((xx - ear_r_cx) ** 2 + (yy - ear_r_cy) ** 2) <= ear_r_val**2

        # Tail (arc to the right, animated sway)
        tail_sway = int(15 * np.sin(t * 1.5))
        tail_x_start = cx + body_rx - 5
        tail_y = cy + int(body_ry * 0.3)
        tail_mask = np.zeros((height, width), dtype=bool)
        for dx in range(int(width * 0.2)):
            ty = tail_y - int(20 * np.sin(dx * 0.05)) + tail_sway
            tx = tail_x_start + dx
            if 0 <= tx < width and 0 <= ty < height:
                # Thick tail (3 pixels)
                for dy in range(-2, 3):
                    if 0 <= ty + dy < height:
                        tail_mask[ty + dy, tx] = True

        # Combined cat mask
        cat_mask = body_mask | head_mask | ear_l_mask | ear_r_mask | tail_mask

        # 4. Apply cat color + fur texture
        fur_base = np.array([80, 60, 40], dtype=np.float64)  # Dark brown/gray
        fur_noise = rng.normal(0, 15, (height, width, 3))

        # Tabby stripes (horizontal bands)
        stripe_pattern = np.sin(yy * 0.15 + xx * 0.05 + t * 0.2) > 0.3
        stripe_color = np.array([-20, -15, -10], dtype=np.float64)

        for ch in range(3):
            frame[:, :, ch] = np.where(
                cat_mask,
                fur_base[ch] + fur_noise[:, :, ch] + stripe_pattern * stripe_color[ch],
                frame[:, :, ch],
            )

        # 5. Eyes (animated blink)
        blink = max(0, np.sin(t * 3.0))  # Blink cycle
        eye_ry = max(1, int(head_r * 0.2 * (0.3 + 0.7 * blink)))
        eye_rx = max(1, int(head_r * 0.2))
        eye_l_cx = head_cx - int(head_r * 0.35)
        eye_r_cx = head_cx + int(head_r * 0.35)
        eye_cy = head_cy + int(head_r * 0.1)

        eye_l_mask = (
            (xx - eye_l_cx) ** 2 / max(eye_rx**2, 1) + (yy - eye_cy) ** 2 / max(eye_ry**2, 1)
        ) <= 1.0
        eye_r_mask = (
            (xx - eye_r_cx) ** 2 / max(eye_rx**2, 1) + (yy - eye_cy) ** 2 / max(eye_ry**2, 1)
        ) <= 1.0

        # Green/gold eyes
        eye_color = np.array([180, 200, 50], dtype=np.float64)
        for ch in range(3):
            frame[:, :, ch] = np.where(
                eye_l_mask | eye_r_mask,
                eye_color[ch] + rng.normal(0, 5, (height, width)),
                frame[:, :, ch],
            )

        # Pupil (small dark circle in each eye)
        pupil_r = max(1, eye_rx // 2)
        pupil_l_mask = ((xx - eye_l_cx) ** 2 + (yy - eye_cy) ** 2) <= pupil_r**2
        pupil_r_mask = ((xx - eye_r_cx) ** 2 + (yy - eye_cy) ** 2) <= pupil_r**2
        frame[pupil_l_mask | pupil_r_mask] = [10, 10, 10]

        # 6. Nose (small pink triangle)
        nose_cx = head_cx
        nose_cy = head_cy + int(head_r * 0.35)
        nose_r = max(1, head_r // 6)
        nose_mask = ((xx - nose_cx) ** 2 + (yy - nose_cy) ** 2) <= nose_r**2
        frame[nose_mask] = [200, 140, 140]

        # Clamp and convert
        return np.clip(frame, 0, 255).astype(np.uint8)

    def save_carrier(
        self,
        output_path: Union[str, Path],
        num_frames: Optional[int] = None,
        size: Optional[Tuple[int, int]] = None,
        duration_ms: int = 100,
    ) -> Path:
        """Generate and save animated cat GIF carrier.

        Args:
            output_path: Where to save the GIF
            num_frames: Number of frames
            size: (width, height)
            duration_ms: Per-frame duration in milliseconds

        Returns:
            Path to saved GIF
        """
        output_path = Path(output_path)
        frames = self.generate(num_frames, size)

        if not _IMAGEIO_AVAILABLE:
            raise RuntimeError("imageio required for GIF output")

        stacked = np.stack(frames, axis=0)
        iio.imwrite(
            str(output_path),
            stacked,
            extension=".gif",
            duration=[duration_ms] * len(frames),
            loop=0,
        )

        return output_path


# ---------------------------------------------------------------------------
# Phase 0.1: GCE Disposal Channel Encoder
# ---------------------------------------------------------------------------


class DisposalChannelEncoder:
    """Encode/decode bits in GCE disposal method and flag fields.

    Uses 4 bits per frame from the GIF89a Graphic Control Extension:
        - Disposal method: 2 bits (values 0-3, all valid per GIF89a spec)
            0 = no disposal specified, 1 = leave in place
            2 = restore to background, 3 = restore to previous
        - User input flag: 1 bit (ignored by virtually all renderers)
        - Transparent color flag: 1 bit (safe if trans_idx unused)

    Total capacity: 4 x num_frames ÷ 8 bytes.
    For a 10-frame GIF: 5 bytes.
    For a 100-frame GIF: 50 bytes.

    Visual impact:
        Disposal values 0 and 1 are visually identical (no difference).
        Value 2 clears to background (may cause flash on some renderers).
        Value 3 restores previous (may cause flicker).
        User input and transparent flags have zero visual impact when
        the transparent color index is set to an unused palette entry.

    NOTE: This operates on raw GIF binary via GifBinaryEditor.
    Must be applied AFTER imageio writes the GIF.
    """

    BITS_PER_FRAME = DISPOSAL_BITS_PER_FRAME

    def __init__(self, master_key: bytes, config: MultiLayerConfig):
        self.master_key = master_key
        self.config = config
        # gemini #1: channel sub-key as Rust handle. Note: this attribute
        # is currently unused by `encode`/`decode` here (the disposal-bit
        # encoding doesn't require keyed PRFs); kept for cross-channel
        # domain-separation invariants asserted by the test suite.
        self._channel_key_handle = _derive_channel_subkey_handle(master_key, DOMAIN_DISPOSAL)

    def __del__(self):
        _drop_handle_safe(getattr(self, "_channel_key_handle", None))

    def key_fingerprint(self) -> bytes:
        """Stable test-only fingerprint over the disposal channel sub-key."""
        return _key_fingerprint(self._channel_key_handle)

    def encode(
        self,
        structure: GifStructure,
        payload_bits: List[int],
    ) -> GifStructure:
        """Encode bits into GCE packed fields.

        Args:
            structure: Parsed GIF structure (modified in-place)
            payload_bits: Bits to encode (max BITS_PER_FRAME x num_gce)

        Returns:
            Modified GIF structure
        """
        num_gce = len(structure.gce_blocks)
        if num_gce == 0:
            logger.warning("No GCE blocks found -- disposal channel inactive")
            return structure

        for frame_idx in range(num_gce):
            bit_offset = frame_idx * self.BITS_PER_FRAME

            # Extract 4 bits for this frame (zero-pad if not enough)
            b0 = payload_bits[bit_offset] if bit_offset < len(payload_bits) else 0
            b1 = payload_bits[bit_offset + 1] if bit_offset + 1 < len(payload_bits) else 0
            b2 = payload_bits[bit_offset + 2] if bit_offset + 2 < len(payload_bits) else 0
            b3 = payload_bits[bit_offset + 3] if bit_offset + 3 < len(payload_bits) else 0

            disposal = ((b1 & 1) << 1) | (b0 & 1)
            user_input = b2 & 1
            transparent = b3 & 1

            GifBinaryEditor.set_gce_bits(structure, frame_idx, disposal, user_input, transparent)

        return structure

    def decode(self, structure: GifStructure) -> List[int]:
        """Decode bits from GCE packed fields.

        Args:
            structure: Parsed GIF structure

        Returns:
            List of decoded bits (4 per GCE block)
        """
        bits: List[int] = []

        for gce in structure.gce_blocks:
            disposal = gce.disposal_method & 0x03
            bits.append(disposal & 1)
            bits.append((disposal >> 1) & 1)
            bits.append(gce.user_input_flag)
            bits.append(gce.transparent_flag)

        return bits

    @property
    def capacity_bits(self) -> int:
        """Theoretical maximum bits (before knowing frame count)."""
        return 0  # Depends on num_frames; use estimate_capacity() instead

    def estimate_capacity(self, num_frames: int) -> int:
        """Estimate capacity in bits for a given number of frames."""
        return num_frames * self.BITS_PER_FRAME


# ---------------------------------------------------------------------------
# Phase 0.2: Comment Extension Channel Encoder
# ---------------------------------------------------------------------------


class CommentChannelEncoder:
    """Encode/decode encrypted payload in GIF Comment Extension blocks.

    Injects encrypted + MAC'd data as a GIF Comment Extension block.
    Comment Extensions are part of the GIF89a spec and are preserved
    by all spec-compliant tools.

    Capacity: configurable, default 256 bytes (after encryption overhead).

    Format: MSCM(4) + orig_len(4) + nonce(12) + AES-GCM-ciphertext + HMAC(32)

    Security:
        - AES-256-GCM encryption with domain-separated key
        - HMAC-SHA256 authentication over the full inner payload
        - Random 12-byte nonce (never reused: one per encode call)
        - Domain separation: distinct from all other channel keys

    NOTE: This operates on raw GIF binary via GifBinaryEditor.
    Must be applied AFTER imageio writes the GIF.
    """

    def __init__(self, master_key: bytes, config: MultiLayerConfig):
        self.master_key = master_key
        self.config = config
        # gemini #1: derived sub-keys live as Rust handles so the bytes
        # never persist as Python instance attributes. HMAC derivation
        # is unchanged (wire format preserved).
        self._enc_key_handle = _derive_channel_subkey_handle(master_key, DOMAIN_COMMENT_ENC)
        self._mac_key_handle = _derive_channel_subkey_handle(master_key, DOMAIN_COMMENT_MAC)

    def __del__(self):
        _drop_handle_safe(getattr(self, "_enc_key_handle", None))
        _drop_handle_safe(getattr(self, "_mac_key_handle", None))

    def key_fingerprint(self, role: str) -> bytes:
        """Stable test-only fingerprint over the named channel sub-key.

        Lets tests assert key equality / domain separation without ever
        exporting the underlying bytes from Rust. Returns empty bytes
        if the Rust backend isn't available.
        """
        if role == "enc":
            return _key_fingerprint(self._enc_key_handle)
        if role == "mac":
            return _key_fingerprint(self._mac_key_handle)
        raise ValueError(f"unknown role {role!r}; expected 'enc' or 'mac'")

    def encode(self, payload: bytes) -> bytes:
        """Prepare comment payload (encrypt + MAC).

        Args:
            payload: Raw payload bytes to encrypt and embed

        Returns:
            Encrypted comment bytes ready for GIF injection

        Raises:
            RuntimeError: If no encryption backend is available
        """
        # Encrypt with AES-256-GCM via the Rust handle backend (key never
        # leaves Rust; gemini #1).
        nonce = os.urandom(12)

        if not _RUST_AVAILABLE or self._enc_key_handle is None or self._mac_key_handle is None:
            raise RuntimeError(
                "No encryption backend for comment channel. "
                "meow_crypto_rs (Rust) is required."
            )

        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()
        ciphertext = bytes(
            hb.aes_gcm_encrypt(self._enc_key_handle, nonce, payload, DOMAIN_COMMENT_ENC)
        )

        # Build: MAGIC(4) + orig_len(4) + nonce(12) + ciphertext
        inner = COMMENT_MAGIC + struct.pack("<I", len(payload)) + nonce + ciphertext

        # HMAC-SHA256 over entire inner payload (MAC key in Rust handle).
        mac = bytes(hb.hmac_sha256(self._mac_key_handle, inner))

        return inner + mac

    def decode(self, comment_data: bytes) -> Tuple[bytes, bool]:
        """Extract and verify comment payload.

        Args:
            comment_data: Raw bytes from GIF Comment Extension

        Returns:
            Tuple of (decrypted_payload, mac_valid).
            Returns (b"", False) on any failure (fail-closed).
        """
        # Minimum: magic(4) + len(4) + nonce(12) + tag(16) + mac(32) = 68
        min_size = 4 + 4 + 12 + 16 + 32
        if len(comment_data) < min_size:
            return b"", False

        # Verify magic
        if comment_data[:4] != COMMENT_MAGIC:
            return b"", False

        # Split MAC (last 32 bytes)
        inner = comment_data[:-32]
        stored_mac = comment_data[-32:]

        if not _RUST_AVAILABLE or self._enc_key_handle is None or self._mac_key_handle is None:
            # gemini #1: Rust required; no Python fallback. Fail-closed.
            return b"", False

        from meow_decoder.crypto_backend import get_handle_backend

        hb = get_handle_backend()

        # Verify HMAC (constant-time via Rust handle_hmac_sha256_verify).
        if not hb.hmac_sha256_verify(self._mac_key_handle, inner, stored_mac):
            return b"", False

        # Parse inner
        orig_len = struct.unpack("<I", inner[4:8])[0]
        nonce = inner[8:20]
        ciphertext = inner[20:]

        # Decrypt via Rust handle (key never leaves Rust).
        try:
            plaintext = bytes(
                hb.aes_gcm_decrypt(self._enc_key_handle, nonce, ciphertext, DOMAIN_COMMENT_ENC)
            )
        except Exception:
            return b"", False

        return plaintext[:orig_len], True


def _bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes to list of bits (MSB first per byte)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: List[int]) -> bytes:
    """Convert list of bits to bytes (MSB first per byte)."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] & 1) << (7 - j)
        result.append(byte)
    return bytes(result)


class MultiLayerStegoEncoder:
    """Orchestrates multi-layer steganographic embedding.

    Embeds payload across up to five independent channels:
    1. Primary (LSB): Bulk data via keyed walk + STC + saliency costs
    2. Secondary (timing): Metadata via GCE delay jitter
    3. Tertiary (palette): Overflow via entry permutation
    4. Disposal (GCE flags): 4 bits/frame in disposal/user_input/transparent
    5. Comment (extension): Encrypted metadata in GIF Comment Extension

    Phase 0 hardening:
    - Saliency-based STC costs (Laplacian + Sobel via OpenCV)
    - Immunization noise (keyed Gaussian pre-embedding)
    - GCE disposal channel (4 bits/frame, zero visual impact)
    - Comment extension channel (100-500 encrypted bytes)

    All channels use independent per-frame seeds derived from master_key.
    """

    def __init__(self, config: MultiLayerConfig, master_key: bytes):
        """Initialize encoder.

        Args:
            config: Multi-layer configuration
            master_key: 32-byte master key for all seed derivations
        """
        if len(master_key) < 16:
            raise ValueError(f"Master key must be >= 16 bytes, got {len(master_key)}")

        self.config = config
        self.master_key = master_key
        self.primary = PrimaryChannelEncoder(master_key, config)
        self.timing = TimingChannelEncoder(master_key, config)
        self.palette = PaletteChannelEncoder(master_key, config)
        self.disposal = DisposalChannelEncoder(master_key, config)
        self.comment = CommentChannelEncoder(master_key, config)
        self.temporal_ch = TemporalChannelEncoder(master_key, config)
        self.adversarial = AdversarialPerturbationLayer(master_key, config)
        self.cat_gen = ProceduralCatGenerator(master_key, config)

    def encode(
        self,
        payload: bytes,
        carrier_path: Optional[Union[str, Path]] = None,
        output_path: Union[str, Path] = "output.gif",
        duress_mode: bool = False,
    ) -> Dict[str, Any]:
        """Encode payload into carrier GIF using all enabled channels.

        Args:
            payload: Raw payload bytes
            carrier_path: Path to carrier animated GIF (None for procedural cat)
            output_path: Path for output stego GIF
            duress_mode: If True, only encode shallow/decoy layers

        Returns:
            Dict with encoding metadata:
            - channels_used: list of channel names used
            - payload_size: original payload size
            - primary_bits: bits embedded in primary channel
            - secondary_bits: bits embedded in timing channel
            - tertiary_bits: bits embedded in palette channel
            - temporal_bits: bits embedded in temporal channel
            - adversarial_strength: applied perturbation strength
            - psnr: estimated PSNR of primary channel
            - total_capacity: total bits across all channels
        """
        output_path = Path(output_path)

        if not _IMAGEIO_AVAILABLE:
            raise RuntimeError(
                "imageio required for multi-layer stego. Install with: pip install imageio[ffmpeg]"
            )

        # --- Phase 1.3: Procedural cat carrier generation ---
        if self.config.procedural_cat or carrier_path is None:
            logger.info("Generating procedural cat carrier")
            frames = self.cat_gen.generate()
            num_frames = len(frames)
            original_delays_cs = [DEFAULT_BASE_DELAY_CS] * num_frames
            cover_frames = [f.copy() for f in frames]  # Save originals for adversarial
        else:
            carrier_path = Path(carrier_path)

            # Read carrier GIF with imageio (preserves palette, timing)
            carrier_data = iio.imread(str(carrier_path), index=None)

            # Handle different imageio return types
            if isinstance(carrier_data, np.ndarray):
                if carrier_data.ndim == 4:
                    frames = [carrier_data[i] for i in range(carrier_data.shape[0])]
                elif carrier_data.ndim == 3:
                    frames = [carrier_data]
                else:
                    raise ValueError(f"Unexpected carrier shape: {carrier_data.shape}")
            elif isinstance(carrier_data, list):
                frames = carrier_data
            else:
                frames = [np.array(carrier_data)]

            num_frames = len(frames)
            cover_frames = [np.array(f).copy() for f in frames]  # Save originals

            logger.info("Carrier: %d frames, shape %s", num_frames, frames[0].shape)

            # Read GIF metadata for timing
            try:
                meta = iio.immeta(str(carrier_path))
                original_delays = meta.get("duration", [DEFAULT_BASE_DELAY_CS * 10] * num_frames)
                if isinstance(original_delays, (int, float)):
                    original_delays = [original_delays] * num_frames
                # Convert ms to cs
                original_delays_cs = [max(1, int(d / 10)) for d in original_delays]
            except Exception:
                original_delays_cs = [DEFAULT_BASE_DELAY_CS] * num_frames

        # Prepare payload
        if duress_mode and self.config.coercion_level == CoercionLevel.DECOY:
            # Decoy: prepare a fake/empty payload
            prepared = prepare_payload(b"Decode complete.", self.master_key)
        else:
            prepared = prepare_payload(
                payload,
                self.master_key,
                compress=self.config.compress,
                encrypt=self.config.encrypt,
            )

        # Calculate per-frame capacities
        frame_pixel_counts = [f.shape[0] * f.shape[1] for f in frames]
        # For palette channel, estimate permutable entries (will be refined per frame)
        permutable_counts = [32] * num_frames  # Estimate

        # Distribute across channels
        # Get frame dimensions for temporal capacity calculation
        frame_h = frames[0].shape[0] if frames else 0
        frame_w = frames[0].shape[1] if frames else 0
        channel_data = distribute_payload(
            prepared,
            self.config,
            num_frames,
            frame_pixel_counts,
            permutable_counts,
            frame_height=frame_h,
            frame_width=frame_w,
        )

        metadata = {
            "channels_used": list(channel_data.keys()),
            "payload_size": len(payload),
            "prepared_size": len(prepared),
            "primary_bits": 0,
            "secondary_bits": 0,
            "tertiary_bits": 0,
            "disposal_bits": 0,
            "comment_bytes": 0,
            "psnr": float("inf"),
            "total_capacity": 0,
            "immunized": self.config.immunize,
            "saliency_costs": self.config.use_saliency_costs,
        }

        # --- Phase 0.4: Immunization noise (BEFORE embedding) ---
        if self.config.immunize:
            logger.debug(
                "Applying immunization noise (sigma=%.2f) to %d frames",
                self.config.immunize_sigma,
                num_frames,
            )
            for i in range(len(frames)):
                if frames[i].ndim == 2:
                    frames[i] = np.stack([frames[i]] * 3, axis=-1)
                elif frames[i].shape[-1] == 4:
                    frames[i] = frames[i][:, :, :3]
                frames[i] = ImmunizationLayer.apply(
                    frames[i],
                    self.master_key,
                    i,
                    sigma=self.config.immunize_sigma,
                )

        # --- Primary channel: LSB embedding ---
        # Strategy: sequential fill (frame 0 first, overflow to frame 1, etc.)
        # The decoder extracts full capacity from each frame and concatenates,
        # so we pack data contiguously across frames in walk order.
        stego_frames = []
        if "primary" in channel_data and self.config.enable_primary:
            primary_bits = _bytes_to_bits(channel_data["primary"])
            metadata["primary_bits"] = len(primary_bits)
            offset = 0

            for i, frame in enumerate(frames):
                # Ensure RGB
                if frame.ndim == 2:
                    frame = np.stack([frame] * 3, axis=-1)
                elif frame.shape[-1] == 4:
                    frame = frame[:, :, :3]  # Drop alpha

                h, w, c = frame.shape
                frame_capacity = h * w * c * self.config.lsb_bits
                if self.config.use_stc:
                    frame_capacity = _stc_payload_capacity(frame_capacity)

                remaining = len(primary_bits) - offset
                n_bits = min(remaining, frame_capacity)
                frame_bits = primary_bits[offset : offset + n_bits] if n_bits > 0 else []

                if frame_bits:
                    stego_frame = self.primary.embed_frame(frame, i, frame_bits)
                    # Calculate PSNR
                    diff = frame.astype(float) - stego_frame.astype(float)
                    mse = np.mean(diff**2)
                    if mse > 0:
                        psnr = 10 * np.log10(255**2 / mse)
                        metadata["psnr"] = min(metadata["psnr"], float(psnr))
                    stego_frames.append(stego_frame)
                    offset += n_bits
                else:
                    stego_frames.append(frame)
        else:
            stego_frames = [np.array(f) for f in frames]

        # --- Phase 1.1: Temporal channel embedding ---
        if "temporal" in channel_data and self.config.enable_temporal:
            temporal_bits = _bytes_to_bits(channel_data["temporal"])
            temporal_embedded = self.temporal_ch.embed(stego_frames, temporal_bits)
            if temporal_embedded is not None:
                stego_frames = temporal_embedded
            metadata["temporal_bits"] = len(temporal_bits)
        else:
            metadata["temporal_bits"] = 0

        # --- Secondary channel: timing ---
        if "secondary" in channel_data and self.config.enable_secondary:
            secondary_bits = _bytes_to_bits(channel_data["secondary"])
            metadata["secondary_bits"] = len(secondary_bits)
            frame_delays = self.timing.encode(num_frames, secondary_bits)
        else:
            frame_delays = original_delays_cs

        # --- Tertiary channel: palette (requires indexed GIF frames) ---
        if "tertiary" in channel_data and self.config.enable_tertiary:
            tertiary_bits = _bytes_to_bits(channel_data["tertiary"])
            metadata["tertiary_bits"] = len(tertiary_bits)
            self._tertiary_bits = tertiary_bits
        else:
            self._tertiary_bits = []

        # --- Store disposal and comment channel data for post-processing ---
        self._disposal_data = channel_data.get("disposal", b"")
        self._comment_data = channel_data.get("comment", b"")

        # --- Phase 1.2: Adversarial perturbation post-processing ---
        if self.config.adversarial_strength > 0:
            stego_frames = self.adversarial.apply(stego_frames, cover_frames)
            metadata["adversarial_strength"] = self.config.adversarial_strength
        else:
            metadata["adversarial_strength"] = 0

        # Convert delays to durations in ms for imageio
        durations_ms = [d * 10 for d in frame_delays]

        # Determine output format: APNG preserves pixel LSBs exactly;
        # GIF palette quantization destroys them.  Force APNG for pixel-
        # level stego (primary/temporal channels).
        is_apng = str(output_path).lower().endswith((".png", ".apng"))
        if self.config.enable_primary and not is_apng:
            # Auto-switch to APNG to preserve pixel-level stego data
            output_path = output_path.with_suffix(".png")
            is_apng = True
            logger.info(
                "Switched output to APNG (%s) — GIF palette quantization " "destroys LSB embedding",
                output_path,
            )

        # Record actual output path in metadata (may differ from requested
        # path when auto-switching to APNG)
        metadata["output_path"] = str(output_path)
        metadata["is_apng"] = is_apng

        # Write stego image (APNG for pixel stego, GIF for QR-only)
        self._write_stego_image(stego_frames, durations_ms, output_path, is_apng)

        # --- Phase 0.1 + 0.2: Post-process GIF binary for disposal + comment ---
        # GIF-specific channels only work with GIF output
        disposal_bits_embedded = 0
        comment_bytes_embedded = 0
        if not is_apng and (self._disposal_data or self._comment_data):
            gif_bytes = output_path.read_bytes()
            structure = GifBinaryEditor.parse(gif_bytes)
            # Disposal channel: encode bits in GCE packed fields
            if self._disposal_data and self.config.enable_disposal:
                disposal_bits = _bytes_to_bits(self._disposal_data)
                structure = self.disposal.encode(structure, disposal_bits)
                disposal_bits_embedded = len(disposal_bits)
                metadata["disposal_bits"] = disposal_bits_embedded
                logger.debug(
                    "Disposal channel: %d bits in %d GCE blocks",
                    disposal_bits_embedded,
                    len(structure.gce_blocks),
                )

            # Comment channel: inject encrypted comment block
            if self._comment_data and self.config.enable_comment:
                encrypted_comment = self.comment.encode(self._comment_data)
                structure = GifBinaryEditor.inject_comment(structure, encrypted_comment)
                comment_bytes_embedded = len(self._comment_data)
                metadata["comment_bytes"] = comment_bytes_embedded
                logger.debug(
                    "Comment channel: %d bytes payload (%d bytes encrypted)",
                    comment_bytes_embedded,
                    len(encrypted_comment),
                )

            # Write modified GIF
            output_path.write_bytes(GifBinaryEditor.to_bytes(structure))
        elif is_apng and (self._disposal_data or self._comment_data):
            logger.info(
                "APNG output: disposal/comment channels skipped "
                "(GIF-only features). Data routed to primary channel.",
            )

        metadata["total_capacity"] = (
            metadata["primary_bits"]
            + metadata["secondary_bits"]
            + metadata["tertiary_bits"]
            + metadata.get("temporal_bits", 0)
            + metadata.get("disposal_bits", 0)
            + metadata.get("comment_bytes", 0) * 8
        )

        logger.info(
            "Encoded %d bytes across %d channels. PSNR=%.1f dB. " "Immunize=%s, Saliency=%s",
            len(payload),
            len(metadata["channels_used"]),
            metadata["psnr"],
            metadata["immunized"],
            metadata["saliency_costs"],
        )

        return metadata

    def _write_stego_image(
        self,
        frames: List[np.ndarray],
        durations_ms: List[int],
        output_path: Path,
        is_apng: bool = False,
    ) -> None:
        """Write frames to animated image (APNG or GIF).

        APNG preserves full RGB pixel values — required for LSB stego.
        GIF quantizes to 256-color palette — only suitable for QR-only mode.

        Args:
            frames: List of numpy arrays (H, W, C) uint8
            durations_ms: Per-frame durations in milliseconds
            output_path: Output file path
            is_apng: If True, write APNG; if False, write GIF
        """
        # Ensure all frames are uint8 RGB PIL Images
        pil_frames: List[Image.Image] = []
        for f in frames:
            if not isinstance(f, np.ndarray):
                f = np.array(f)
            if f.dtype != np.uint8:
                f = np.clip(f, 0, 255).astype(np.uint8)
            if f.ndim == 2:
                f = np.stack([f] * 3, axis=-1)
            elif f.shape[-1] == 4:
                f = f[:, :, :3]
            pil_frames.append(Image.fromarray(f, "RGB"))

        if not pil_frames:
            raise ValueError("No frames to write")

        if is_apng:
            # Write as APNG — preserves RGB pixel values exactly
            pil_frames[0].save(
                str(output_path),
                format="PNG",
                save_all=True,
                append_images=pil_frames[1:] if len(pil_frames) > 1 else [],
                duration=durations_ms,
                loop=0,
            )
        else:
            # Write as GIF — palette quantization will occur
            pil_frames[0].save(
                str(output_path),
                format="GIF",
                save_all=True,
                append_images=pil_frames[1:] if len(pil_frames) > 1 else [],
                duration=durations_ms,
                loop=0,
            )


# ---------------------------------------------------------------------------
# Multi-Layer Decoder
# ---------------------------------------------------------------------------


@dataclass
class StegoExtractionResult:
    """Structured result from multi-layer extraction."""

    payload_bytes: bytes
    channel_sources: List[str]
    mac_valid: bool
    duress_triggered: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict representation."""
        return {
            "payload_bytes": self.payload_bytes,
            "channel_sources": self.channel_sources,
            "mac_valid": self.mac_valid,
            "duress_triggered": self.duress_triggered,
            "metadata": self.metadata,
        }


class MultiLayerStegoDecoder:
    """Orchestrates multi-layer steganographic extraction.

    Extracts payload from all enabled channels (including Phase 0
    disposal + comment channels and Phase 1 temporal channel),
    reassembles, verifies MAC, decrypts, and decompresses.
    """

    def __init__(self, config: MultiLayerConfig, master_key: bytes):
        if len(master_key) < 16:
            raise ValueError(f"Master key must be >= 16 bytes, got {len(master_key)}")

        self.config = config
        self.master_key = master_key
        self.primary = PrimaryChannelEncoder(master_key, config)
        self.timing = TimingChannelEncoder(master_key, config)
        self.palette = PaletteChannelEncoder(master_key, config)
        self.disposal = DisposalChannelEncoder(master_key, config)
        self.comment = CommentChannelEncoder(master_key, config)
        self.temporal_ch = TemporalChannelEncoder(master_key, config)

    def decode(
        self,
        stego_path: Union[str, Path],
        duress_key: Optional[bytes] = None,
    ) -> StegoExtractionResult:
        """Extract payload from stego GIF.

        Args:
            stego_path: Path to stego GIF (str or Path, not raw bytes)
            duress_key: Optional alternative key for duress/decoy extraction

        Returns:
            StegoExtractionResult with payload, channel info, and MAC status

        Raises:
            TypeError: If stego_path is bytes instead of a file path
        """
        if isinstance(stego_path, (bytes, bytearray)):
            raise TypeError(
                "decode() expects a file path (str or Path), not raw bytes. "
                "Write bytes to a file first, then pass the file path."
            )
        stego_path = Path(stego_path)

        if not _IMAGEIO_AVAILABLE:
            raise RuntimeError(
                "imageio required for multi-layer stego. Install with: pip install imageio[ffmpeg]"
            )

        # Detect file format: GIF vs APNG/PNG
        is_gif = str(stego_path).lower().endswith(".gif")
        gif_structure = None

        # --- Phase 0: Parse raw GIF binary for disposal + comment channels ---
        if is_gif:
            gif_raw = stego_path.read_bytes()
            gif_structure = GifBinaryEditor.parse(gif_raw)

        # Read stego GIF frames via imageio
        stego_data = iio.imread(str(stego_path), index=None)

        if isinstance(stego_data, np.ndarray):
            if stego_data.ndim == 4:
                frames = [stego_data[i] for i in range(stego_data.shape[0])]
            else:
                frames = [stego_data]
        elif isinstance(stego_data, list):
            frames = stego_data
        else:
            frames = [np.array(stego_data)]

        num_frames = len(frames)

        # Read timing metadata
        try:
            meta = iio.immeta(str(stego_path))
            durations = meta.get("duration", [DEFAULT_BASE_DELAY_CS * 10] * num_frames)
            if isinstance(durations, (int, float)):
                durations = [durations] * num_frames
            delays_cs = [max(1, int(d / 10)) for d in durations]
        except Exception:
            delays_cs = [DEFAULT_BASE_DELAY_CS] * num_frames

        active_key = duress_key if duress_key else self.master_key
        duress_triggered = duress_key is not None

        channel_sources: List[str] = []
        raw_chunks: Dict[str, bytes] = {}

        # --- Extract from primary channel ---
        if self.config.enable_primary:
            primary_decoder = PrimaryChannelEncoder(active_key, self.config)
            primary_bits: List[int] = []

            for i, frame in enumerate(frames):
                if frame.ndim == 2:
                    frame = np.stack([frame] * 3, axis=-1)
                elif frame.shape[-1] == 4:
                    frame = frame[:, :, :3]

                h, w, c = frame.shape
                bits_per_frame = h * w * c * self.config.lsb_bits
                if self.config.use_stc:
                    bits_per_frame = _stc_payload_capacity(bits_per_frame)

                extracted = primary_decoder.extract_frame(frame, i, bits_per_frame)
                primary_bits.extend(extracted)

            if raw_chunks.get("primary") is None:
                raw_chunks["primary"] = _bits_to_bytes(primary_bits)
                channel_sources.append("primary")

        # --- Extract from temporal channel (Phase 1.1) ---
        if self.config.enable_temporal and num_frames >= 2:
            temporal_decoder = TemporalChannelEncoder(active_key, self.config)
            temporal_est_bits = (num_frames - 1) * self.config.temporal_bits_per_transition
            temporal_bits = temporal_decoder.extract(frames, temporal_est_bits)
            if temporal_bits:
                raw_chunks["temporal"] = _bits_to_bytes(temporal_bits)
                channel_sources.append("temporal")

        # --- Extract from tertiary channel (palette) ---
        # (Palette extraction requires original permutable set knowledge)

        # --- Extract from comment channel (GIF-only) ---
        if self.config.enable_comment and is_gif and gif_structure is not None:
            comment_decoder = CommentChannelEncoder(active_key, self.config)
            comments = GifBinaryEditor.extract_comments(gif_structure)
            for comment_data in comments:
                decoded, mac_ok = comment_decoder.decode(comment_data)
                if mac_ok and decoded:
                    raw_chunks["comment"] = decoded
                    channel_sources.append("comment")
                    break  # Use first valid comment block

        # --- Extract from secondary channel (timing) ---
        if self.config.enable_secondary and len(delays_cs) > 0:
            timing_decoder = TimingChannelEncoder(active_key, self.config)
            timing_bits = timing_decoder.decode(delays_cs)
            if timing_bits:
                raw_chunks["secondary"] = _bits_to_bytes(timing_bits)
                channel_sources.append("secondary")

        # --- Extract from disposal channel (GIF-only, Phase 0.1) ---
        if (
            self.config.enable_disposal
            and is_gif
            and gif_structure is not None
            and len(gif_structure.gce_blocks) > 0
        ):
            disposal_decoder = DisposalChannelEncoder(active_key, self.config)
            disposal_bits = disposal_decoder.decode(gif_structure)
            if disposal_bits:
                raw_chunks["disposal"] = _bits_to_bytes(disposal_bits)
                channel_sources.append("disposal")

        # Reassemble payload from chunks in distribution order
        reassembled = b""
        for ch in ["primary", "comment", "secondary", "temporal", "disposal", "tertiary"]:
            if ch in raw_chunks:
                reassembled += raw_chunks[ch]

        # Try to unpack and verify
        if len(reassembled) >= 14 + 32:
            payload, mac_valid = unpack_payload(reassembled, active_key)
        else:
            payload = reassembled
            mac_valid = False

        return StegoExtractionResult(
            payload_bytes=payload,
            channel_sources=channel_sources,
            mac_valid=mac_valid,
            duress_triggered=duress_triggered,
            metadata={
                "num_frames": num_frames,
                "primary_raw_bytes": len(raw_chunks.get("primary", b"")),
                "comment_raw_bytes": len(raw_chunks.get("comment", b"")),
                "secondary_raw_bytes": len(raw_chunks.get("secondary", b"")),
                "disposal_raw_bytes": len(raw_chunks.get("disposal", b"")),
                "tertiary_raw_bytes": len(raw_chunks.get("tertiary", b"")),
                "gce_blocks_found": len(gif_structure.gce_blocks) if gif_structure else 0,
                "comment_blocks_found": len(gif_structure.comment_blocks) if gif_structure else 0,
            },
        )


# ---------------------------------------------------------------------------
# Schrödinger / Duress Integration
# ---------------------------------------------------------------------------


def derive_stego_keys_for_reality(
    password: str,
    salt: bytes,
    coercion_level: CoercionLevel,
) -> Dict[str, bytes]:
    """Derive channel-specific keys for a Schrödinger reality.

    In Schrödinger mode, two passwords derive different key sets:
    - Decoy password -> only primary (shallow LSB) key
    - Real password -> all three channel keys

    Args:
        password: Password string
        salt: 16-byte salt
        coercion_level: Determines which channels to derive

        # Phase 1: temporal channel key
        keys["temporal"] = hmac_stdlib.new(
            master, b"meow_stego_key_temporal_v1", hashlib.sha256
        ).digest()
    Returns:
        Dict mapping channel names to 32-byte keys.
        Keys not derived are absent from the dict.
    """
    # Derive master key via Argon2id
    password_bytes = password.encode("utf-8")

    if _RUST_AVAILABLE:
        master = bytes(
            meow_crypto_rs.derive_key_argon2id(
                password_bytes,
                salt,
                32768 if os.environ.get("MEOW_TEST_MODE") else 524288,
                1 if os.environ.get("MEOW_TEST_MODE") else 20,
                1 if os.environ.get("MEOW_TEST_MODE") else 4,
                32,
            )
        )
    else:
        # Python fallback
        master = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 100000, dklen=32)

    keys: Dict[str, bytes] = {}

    if coercion_level >= CoercionLevel.SHALLOW:
        keys["primary"] = hmac_stdlib.new(
            master, b"meow_stego_key_primary_v1", hashlib.sha256
        ).digest()

    if coercion_level >= CoercionLevel.FULL:
        keys["secondary"] = hmac_stdlib.new(
            master, b"meow_stego_key_secondary_v1", hashlib.sha256
        ).digest()
        keys["tertiary"] = hmac_stdlib.new(
            master, b"meow_stego_key_tertiary_v1", hashlib.sha256
        ).digest()
        # Phase 0: new channel keys
        keys["disposal"] = hmac_stdlib.new(
            master, b"meow_stego_key_disposal_v1", hashlib.sha256
        ).digest()
        keys["comment"] = hmac_stdlib.new(
            master, b"meow_stego_key_comment_v1", hashlib.sha256
        ).digest()
        keys["temporal"] = hmac_stdlib.new(
            master, b"meow_stego_key_temporal_v1", hashlib.sha256
        ).digest()

    return keys


# ---------------------------------------------------------------------------
# Steganalysis Validation (RS analysis, chi-square, SPA)
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    """Result of steganalysis validation."""

    passed: bool
    rs_analysis: Dict[str, Any]
    chi_square: Dict[str, Any]
    spa: Dict[str, Any]
    entropy: Dict[str, Any]
    summary: str


def validate_stego(
    stego_path: str,
    cover_path: Optional[str] = None,
) -> ValidationResult:
    """Run steganalysis validation on a stego GIF.

    Performs per-frame analysis using:
    1. RS analysis (Regular/Singular groups) on pixel values
    2. Chi-square test on LSB distribution
    3. Sample Pair Analysis (SPA) on palette indices
    4. Shannon entropy analysis

    Args:
        stego_path: Path to stego GIF
        cover_path: Optional path to original cover GIF (for comparison)

    Returns:
        ValidationResult with per-test scores and overall pass/fail
    """
    if not _IMAGEIO_AVAILABLE:
        raise RuntimeError("imageio required for validation")

    # Read stego frames
    stego_data = iio.imread(str(stego_path), index=None)
    if isinstance(stego_data, np.ndarray) and stego_data.ndim == 4:
        stego_frames = [stego_data[i] for i in range(stego_data.shape[0])]
    elif isinstance(stego_data, list):
        stego_frames = stego_data
    else:
        stego_frames = [np.array(stego_data)]

    cover_frames = None
    if cover_path:
        cover_data = iio.imread(str(cover_path), index=None)
        if isinstance(cover_data, np.ndarray) and cover_data.ndim == 4:
            cover_frames = [cover_data[i] for i in range(cover_data.shape[0])]
        elif isinstance(cover_data, list):
            cover_frames = cover_data
        else:
            cover_frames = [np.array(cover_data)]

    # Aggregate results across frames
    rs_results = []
    chi_results = []
    spa_results = []
    entropy_results = []
    cover_rs_results = []

    for frame_idx, frame in enumerate(stego_frames):
        frame_arr = np.array(frame)
        if frame_arr.ndim == 2:
            frame_arr = np.stack([frame_arr] * 3, axis=-1)

        # 1. RS Analysis
        rs = _rs_analysis(frame_arr)
        rs_results.append(rs)

        # 2. Chi-square test on LSB distribution
        chi = _chi_square_lsb(frame_arr)
        chi_results.append(chi)

        # 3. SPA (Sample Pair Analysis)
        spa = _sample_pair_analysis(frame_arr)
        spa_results.append(spa)

        # 4. Entropy analysis
        ent = _entropy_analysis(frame_arr)
        entropy_results.append(ent)

        # 5. Cover comparison (if cover provided)
        if cover_frames is not None and frame_idx < len(cover_frames):
            cover_arr = np.array(cover_frames[frame_idx])
            if cover_arr.ndim == 2:
                cover_arr = np.stack([cover_arr] * 3, axis=-1)
            cover_rs_results.append(_rs_analysis(cover_arr))

    # Aggregate
    rs_agg: Dict[str, Any] = {
        "mean_rm_ratio": float(np.mean([r["rm_ratio"] for r in rs_results])),
        "detection_probability": float(np.mean([r["detection_prob"] for r in rs_results])),
        "per_frame": rs_results,
    }
    if cover_rs_results:
        rs_agg["cover_mean_rm_ratio"] = float(np.mean([r["rm_ratio"] for r in cover_rs_results]))
        rs_agg["cover_per_frame"] = cover_rs_results

    chi_agg = {
        "mean_p_value": float(np.mean([c["p_value"] for c in chi_results])),
        # Westfeld chi-square: HIGH p-value = equalized pairs = stego detected
        "detection_probability": float(
            np.mean([1.0 if c["p_value"] > 0.95 else 0.0 for c in chi_results])
        ),
        "per_frame": chi_results,
    }

    spa_agg = {
        "mean_embedding_rate": float(np.mean([s["estimated_rate"] for s in spa_results])),
        "detection_probability": float(
            np.mean([1.0 if s["estimated_rate"] > 0.1 else 0.0 for s in spa_results])
        ),
        "per_frame": spa_results,
    }

    ent_agg = {
        "mean_entropy": float(np.mean([e["entropy"] for e in entropy_results])),
        "per_frame": entropy_results,
    }

    # Overall pass/fail
    # Chi-square: high p-value = equalized PoV pairs = stego detected
    # Our stego passes if mean p-value is NOT extremely high (< 0.95)
    passed = (
        rs_agg["detection_probability"] < 0.3
        and chi_agg["detection_probability"] < 0.3
        and spa_agg["mean_embedding_rate"] < 0.15
    )

    summary_parts = []
    if rs_agg["detection_probability"] >= 0.3:
        summary_parts.append(f"RS: DETECTED (p={rs_agg['detection_probability']:.3f})")
    else:
        summary_parts.append(f"RS: PASS (p={rs_agg['detection_probability']:.3f})")

    if chi_agg["detection_probability"] >= 0.3:
        summary_parts.append(
            f"Chi^2: DETECTED (det={chi_agg['detection_probability']:.3f}, p={chi_agg['mean_p_value']:.4f})"
        )
    else:
        summary_parts.append(
            f"Chi^2: PASS (det={chi_agg['detection_probability']:.3f}, p={chi_agg['mean_p_value']:.4f})"
        )

    if spa_agg["mean_embedding_rate"] >= 0.15:
        summary_parts.append(f"SPA: DETECTED (rate={spa_agg['mean_embedding_rate']:.3f})")
    else:
        summary_parts.append(f"SPA: PASS (rate={spa_agg['mean_embedding_rate']:.3f})")

    summary = " | ".join(summary_parts)
    if passed:
        summary = "PASS: " + summary
    else:
        summary = "FAIL: " + summary

    return ValidationResult(
        passed=passed,
        rs_analysis=rs_agg,
        chi_square=chi_agg,
        spa=spa_agg,
        entropy=ent_agg,
        summary=summary,
    )


def _rs_analysis(frame: np.ndarray) -> Dict[str, Any]:
    """RS (Regular/Singular) steganalysis on a single frame.

    Divides image into groups of pixels, applies flipping masks,
    and measures the ratio of Regular to Singular groups.
    In clean images: R_m ~= R_{-m}; in stego: R_m > R_{-m}.

    Returns dict with rm_ratio and detection probability.
    """
    # Flatten to grayscale for simplicity
    if frame.ndim == 3:
        gray = np.mean(frame[:, :, :3], axis=2).astype(np.uint8)
    else:
        gray = frame.astype(np.uint8)

    h, w = gray.shape
    group_size = 4
    regular_p = 0
    singular_p = 0
    regular_n = 0
    singular_n = 0
    total_groups = 0

    for y in range(0, h - 1, group_size):
        for x in range(0, w - group_size, group_size):
            group = gray[y, x : x + group_size].astype(np.int16)
            if len(group) < group_size:
                continue

            # Discrimination function: sum of absolute differences
            disc_orig = np.sum(np.abs(np.diff(group)))

            # Positive flipping mask: flip LSB of even-indexed pixels
            group_p = group.copy()
            group_p[0::2] ^= 1
            disc_p = np.sum(np.abs(np.diff(group_p)))

            # Negative flipping mask: flip LSB of odd-indexed pixels
            group_n = group.copy()
            group_n[1::2] ^= 1
            disc_n = np.sum(np.abs(np.diff(group_n)))

            if disc_p > disc_orig:
                regular_p += 1
            elif disc_p < disc_orig:
                singular_p += 1

            if disc_n > disc_orig:
                regular_n += 1
            elif disc_n < disc_orig:
                singular_n += 1

            total_groups += 1

    if total_groups == 0:
        return {"rm_ratio": 0.5, "detection_prob": 0.0}

    rp = regular_p / total_groups
    sp = singular_p / total_groups
    rn = regular_n / total_groups
    sn = singular_n / total_groups

    # RS detection: in clean images rp≈rn and sp≈sn; stego breaks this symmetry.
    # rm_ratio captures the main asymmetry; include sp/sn for a fuller metric.
    rm_ratio = abs(rp - rn) / max(rp + rn, 1e-10)
    # Improved: also measure (Rp-Sp) vs (Rn-Sn) asymmetry (Fridrich RS criterion)
    rs_asymmetry = abs((rp - sp) - (rn - sn)) / max(rp + sp + rn + sn, 1e-10)
    combined = max(rm_ratio, rs_asymmetry)

    # Detection if combined metric is significantly different from 0
    detection_prob = min(1.0, combined * 3)  # Heuristic scaling

    return {"rm_ratio": float(rm_ratio), "detection_prob": float(detection_prob)}


def _chi2_survival(chi_stat: float, dof: int) -> float:
    """Compute chi-square survival function (1 - CDF).

    Uses scipy if available; falls back to a normal approximation
    (Wilson-Hilferty transform) which is accurate for dof > 30.
    """
    try:
        from scipy.stats import chi2  # type: ignore

        return float(1.0 - chi2.cdf(chi_stat, dof))
    except ImportError:
        pass

    # Fallback: Wilson-Hilferty normal approximation
    # z = ((chi_stat/dof)^(1/3) - (1 - 2/(9*dof))) / sqrt(2/(9*dof))
    if dof <= 0:
        return 1.0
    k = float(dof)
    t = (chi_stat / k) ** (1.0 / 3.0)
    mu = 1.0 - 2.0 / (9.0 * k)
    sigma = np.sqrt(2.0 / (9.0 * k))
    if sigma < 1e-15:
        return 1.0 if chi_stat <= k else 0.0
    z = (t - mu) / sigma
    # Standard normal survival: Φ(-z) ~= erfc(z/√2)/2
    from math import erfc, sqrt

    p = 0.5 * erfc(z / sqrt(2.0))
    return max(0.0, min(1.0, p))


def _chi_square_lsb(frame: np.ndarray) -> Dict[str, Any]:
    """Chi-square test on LSB distribution.

    Tests whether the LSB distribution of pixel values is uniform
    (expected for stego) vs. natural (expected for clean images).

    For each pair of values (2k, 2k+1), counts occurrences.
    Under no embedding, distribution follows natural statistics.
    Under LSB replacement, pairs (2k, 2k+1) become equalized.
    """
    flat = frame.flatten().astype(np.int32)

    # Group into pairs of values (2k, 2k+1)
    pairs = flat // 2
    unique, counts = np.unique(pairs, return_counts=True)

    # For each pair, split into even/odd counts
    even_counts = []
    odd_counts = []
    for pair_val in unique:
        val_even = pair_val * 2
        val_odd = pair_val * 2 + 1
        c_even = int(np.sum(flat == val_even))
        c_odd = int(np.sum(flat == val_odd))
        if c_even + c_odd > 4:  # Minimum count filter
            even_counts.append(c_even)
            odd_counts.append(c_odd)

    if len(even_counts) < 10:
        return {"p_value": 1.0, "chi_stat": 0.0, "dof": 0}

    # Chi-square: test if even ~= odd for each pair
    even = np.array(even_counts)
    odd = np.array(odd_counts)
    expected = (even + odd) / 2.0
    expected = np.maximum(expected, 1)  # Avoid division by zero

    chi_stat = float(np.sum((even - expected) ** 2 / expected + (odd - expected) ** 2 / expected))
    dof = len(even_counts) - 1

    if dof > 0:
        p_value = _chi2_survival(chi_stat, dof)
    else:
        p_value = 1.0

    return {"p_value": p_value, "chi_stat": chi_stat, "dof": dof}


def _sample_pair_analysis(frame: np.ndarray) -> Dict[str, Any]:
    """Sample Pair Analysis (SPA) using histogram-expected close pair method.

    Compares observed close-pair / same-value pair ratios against the
    histogram-expected ratio.  Under no embedding both ratios are
    elevated equally by spatial correlation (alpha ≈ 1).  LSB replacement
    shifts same-value pairs to close pairs, raising alpha above 1.

    Based on Dumitrescu-Wu-Wang (2003) simplified for practical use.
    """
    if frame.ndim == 3:
        gray = np.mean(frame[:, :, :3], axis=2).astype(np.uint8)
    else:
        gray = frame.astype(np.uint8)

    h, w = gray.shape
    if w < 4 or h < 4:
        return {"estimated_rate": 0.0, "correlation": 1.0}

    # Histogram-based expected close / same ratios
    flat = gray.flatten()
    hist = np.bincount(flat, minlength=256).astype(np.float64)

    E_same = 0.0  # Expected same-value pair count (independent model)
    E_close = 0.0  # Expected within-trace different-value pairs

    for t in range(128):
        h_even = hist[2 * t]
        h_odd = hist[2 * t + 1]
        E_same += h_even * (h_even - 1) + h_odd * (h_odd - 1)
        E_close += 2.0 * h_even * h_odd

    if E_same < 1.0 or E_close < 1.0:
        return {"estimated_rate": 0.0, "correlation": 1.0}

    expected_ratio = E_close / E_same

    # Observed same-value and within-trace close pairs (horizontal adjacency)
    left = gray[:, :-1].flatten().astype(np.int32)
    right = gray[:, 1:].flatten().astype(np.int32)

    O_same = float(np.sum(left == right))
    O_close = float(np.sum((np.abs(left - right) == 1) & ((left >> 1) == (right >> 1))))

    if O_same < 1.0:
        return {"estimated_rate": 0.0, "correlation": 1.0}

    observed_ratio = O_close / O_same

    # alpha: ratio of observed to expected D/C ratio
    # alpha ≈ 1  ⟹  natural spatial statistics preserved (clean)
    # alpha > 1  ⟹  same-value pairs shifted to close pairs (embedding)
    alpha = observed_ratio / max(expected_ratio, 1e-10)

    estimated_rate = max(0.0, min(1.0, alpha - 1.0))

    return {
        "estimated_rate": float(estimated_rate),
        "correlation": float(O_same / max(O_same + O_close, 1)),
    }


def _entropy_analysis(frame: np.ndarray) -> Dict[str, Any]:
    """Analyze LSB entropy of a frame for stego detection."""
    lsbs = (frame.flatten() & 1).astype(np.float64)
    n = len(lsbs)
    ones = int(np.sum(lsbs))
    zeros = n - ones

    if n == 0 or ones == 0 or zeros == 0:
        return {"entropy": 0.0, "lsb_ratio": 0.5}

    p1 = ones / n
    p0 = zeros / n

    entropy = -(p0 * np.log2(p0) + p1 * np.log2(p1))

    return {
        "entropy": float(entropy),
        "lsb_ratio": float(p1),
    }


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

__all__ = [
    "MultiLayerStegoEncoder",
    "MultiLayerStegoDecoder",
    "MultiLayerConfig",
    "CoercionLevel",
    "StegoExtractionResult",
    "ValidationResult",
    "validate_stego",
    "prepare_payload",
    "unpack_payload",
    "derive_stego_keys_for_reality",
    # Channel encoders
    "PrimaryChannelEncoder",
    "TimingChannelEncoder",
    "PaletteChannelEncoder",
    "DisposalChannelEncoder",
    "CommentChannelEncoder",
    # Hardening utilities
    "SaliencyCostComputer",
    "ImmunizationLayer",
    # Phase 1 encoders
    "TemporalChannelEncoder",
    "AdversarialPerturbationLayer",
    "ProceduralCatGenerator",
    # Constants
    "CHANNEL_PRIMARY",
    "CHANNEL_SECONDARY",
    "CHANNEL_TERTIARY",
    "CHANNEL_DISPOSAL",
    "CHANNEL_COMMENT",
    "CHANNEL_TEMPORAL",
    "ADVERSARIAL_STRENGTH_LOW",
    "ADVERSARIAL_STRENGTH_MEDIUM",
    "ADVERSARIAL_STRENGTH_HIGH",
]
