"""Cat Blink v2 — fountain-coded optical blink transport codec (Python port).

Reference implementation of the wire format in docs/CAT_BLINK_V2.md, matching
web_demo/static/cat-blink-v2.js bit-for-bit. Reuses the existing fountain
droplet layout via meow_decoder.fountain, so the blink path and QR path share
one FEC layer.

Pure functions over payload bytes <-> whitened bitstrings. The physical blink
packing (eye states, preamble, loop timing) lives in the emitter/sampler; this
module is the byte/bit/frame/FEC layer and is unit-testable without a camera.
"""

from __future__ import annotations

import struct
from typing import List, Optional

from meow_decoder.fountain import (
    FountainDecoder,
    FountainEncoder,
    pack_droplet,
    unpack_droplet,
)

SYNC = bytes((0xB1, 0x17, 0x5E))
VERSION = 0x02
_HEADER_LEN = len(SYNC) + 1 + 2 + 2 + 4  # sync+ver+k+bs+origlen = 12
_CRC_LEN = 2
_WHITEN_SEED = 0x4D454F57  # "MEOW"


def crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection/final-xor."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def whiten_bits(bit_str: str) -> str:
    """XOR a bitstring with the MEOW-LCG keystream (self-inverse, reseeded)."""
    seed = _WHITEN_SEED
    out = []
    for ch in bit_str:
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        mask = (seed >> 16) & 1
        out.append(str((ord(ch) - 48) ^ mask))
    return "".join(out)


dewhiten_bits = whiten_bits  # self-inverse


def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def bits_to_bytes(bit_str: str) -> bytes:
    n = len(bit_str) // 8
    return bytes(int(bit_str[i * 8 : i * 8 + 8], 2) for i in range(n))


def frame_droplet(
    droplet_bytes: bytes, k_blocks: int, block_size: int, original_length: int
) -> bytes:
    body = (
        bytes((VERSION,))
        + struct.pack(">H", k_blocks)
        + struct.pack(">H", block_size)
        + struct.pack(">I", original_length)
        + droplet_bytes
    )
    crc = crc16(body)
    return SYNC + body + struct.pack(">H", crc)


def encode(
    payload: bytes,
    block_size: int = 32,
    redundancy: float = 3.0,
    min_frames: int = 8,
) -> List[str]:
    """Encode a payload into whitened blink-frame bitstrings."""
    import math

    k_blocks = max(1, math.ceil(len(payload) / block_size))
    frame_count = max(min_frames, math.ceil(k_blocks * redundancy))
    enc = FountainEncoder(payload, k_blocks, block_size)
    frames = []
    for i in range(frame_count):
        droplet = enc.droplet(i)
        frame = frame_droplet(pack_droplet(droplet), k_blocks, block_size, len(payload))
        frames.append(whiten_bits(bytes_to_bits(frame)))
    return frames


def decode_frame(whitened_bits: str) -> Optional[dict]:
    """Parse one whitened frame; return None on SYNC/version/CRC failure."""
    if len(whitened_bits) < (_HEADER_LEN + _CRC_LEN) * 8:
        return None
    data = bits_to_bytes(dewhiten_bits(whitened_bits))
    if data[: len(SYNC)] != SYNC:
        return None
    o = len(SYNC)
    if data[o] != VERSION:
        return None
    o += 1
    k_blocks = struct.unpack_from(">H", data, o)[0]
    o += 2
    block_size = struct.unpack_from(">H", data, o)[0]
    o += 2
    original_length = struct.unpack_from(">I", data, o)[0]
    o += 4
    drop_start = o
    if len(data) < drop_start + 6:
        return None
    count = struct.unpack_from(">H", data, drop_start + 4)[0]
    drop_len = 4 + 2 + count * 2 + block_size
    crc_start = drop_start + drop_len
    if len(data) < crc_start + _CRC_LEN:
        return None
    got = struct.unpack_from(">H", data, crc_start)[0]
    want = crc16(data[len(SYNC) : crc_start])
    if got != want:
        return None
    return {
        "k_blocks": k_blocks,
        "block_size": block_size,
        "original_length": original_length,
        "droplet_bytes": data[drop_start : drop_start + drop_len],
    }


def decode(whitened_frames: List[str]) -> Optional[bytes]:
    """Decode a (possibly lossy, out-of-order) set of frames to the payload."""
    decoder = None
    original_length = None
    for wf in whitened_frames:
        f = decode_frame(wf)
        if f is None:
            continue  # dropped/corrupt frame — fountain tolerates it
        if decoder is None:
            decoder = FountainDecoder(f["k_blocks"], f["block_size"], f["original_length"])
            original_length = f["original_length"]
        decoder.add_droplet(unpack_droplet(f["droplet_bytes"], f["block_size"]))
        if decoder.is_complete():
            break
    if decoder is None or not decoder.is_complete():
        return None
    return decoder.get_data(original_length)
