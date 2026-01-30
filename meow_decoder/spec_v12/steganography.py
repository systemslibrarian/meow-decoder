"""
Steganography helpers for Meow Decoder v1.2/v1.3.1 spec.

Implements dynamic GIF insertion and extraction for MEOW-PAYLOAD blocks.
"""

from __future__ import annotations

from typing import Final

MEOW_PAYLOAD_MARKER: Final[bytes] = b"\x21\xFF\x0BMEOW-PAYLOAD"
GIF_HEADER_MIN_SIZE: Final[int] = 13  # Header (6) + Logical Screen Descriptor (7)


def find_gif_insertion_point(gif_data: bytes) -> int:
    """
    Find optimal insertion point for payload in GIF.

    Strategy:
    1. Look for first Application Extension (0x21 0xFF) or Comment Extension (0x21 0xFE)
    2. Insert after it
    3. Fallback to offset 13 if no extensions found

    Returns:
        Byte offset where payload should be inserted
    """
    if len(gif_data) < GIF_HEADER_MIN_SIZE:
        raise ValueError("Invalid GIF file (too short)")

    # Start scanning after LSD (offset 13)
    pos = GIF_HEADER_MIN_SIZE

    # Check for Global Color Table
    lsd_packed = gif_data[10]
    if lsd_packed & 0x80:  # GCT present
        gct_size = 2 << (lsd_packed & 0x07)  # 2^(N+1) colors
        gct_bytes = gct_size * 3
        pos += gct_bytes

    # Scan for first extension block
    while pos < len(gif_data) - 1:
        marker = gif_data[pos]

        if marker == 0x21:  # Extension introducer
            label = gif_data[pos + 1]

            if label == 0xFF:  # Application Extension
                # Skip this entire extension
                pos += 2  # Introducer + label
                if pos >= len(gif_data):
                    break
                block_size = gif_data[pos]
                pos += 1 + block_size

                # Skip sub-blocks
                while pos < len(gif_data):
                    sub_size = gif_data[pos]
                    pos += 1
                    if sub_size == 0:
                        break
                    pos += sub_size

                return pos

            if label == 0xFE:  # Comment Extension
                pos += 2
                while pos < len(gif_data):
                    sub_size = gif_data[pos]
                    pos += 1
                    if sub_size == 0:
                        break
                    pos += sub_size

                return pos

            # Other extension: skip
            pos += 2
            while pos < len(gif_data):
                sub_size = gif_data[pos]
                pos += 1
                if sub_size == 0:
                    break
                pos += sub_size

        elif marker == 0x2C:  # Image descriptor
            break
        elif marker == 0x3B:  # Trailer
            break
        else:
            pos += 1

    # Fallback: insert after LSD (+ GCT if present)
    offset = GIF_HEADER_MIN_SIZE
    lsd_packed = gif_data[10]
    if lsd_packed & 0x80:
        gct_size = 2 << (lsd_packed & 0x07)
        offset += gct_size * 3

    return offset


def embed_in_gif(carrier_gif: bytes, payload: bytes) -> bytes:
    """
    Embed payload in GIF application extension block.

    Format:
      0x21 0xFF 0x0B "MEOW-PAYLOAD" [sub-blocks with payload] 0x00
    """
    insertion_point = find_gif_insertion_point(carrier_gif)

    block = bytearray()
    block.append(0x21)
    block.append(0xFF)
    block.append(0x0B)
    block.extend(b"MEOW-PAYLOAD")

    for i in range(0, len(payload), 255):
        chunk = payload[i : i + 255]
        block.append(len(chunk))
        block.extend(chunk)

    block.append(0x00)

    return carrier_gif[:insertion_point] + bytes(block) + carrier_gif[insertion_point:]


def extract_from_gif(gif_data: bytes) -> bytes:
    """
    Extract payload from GIF application extension.

    Searches for "MEOW-PAYLOAD" application extension.
    """
    pos = gif_data.find(MEOW_PAYLOAD_MARKER)
    if pos == -1:
        raise ValueError("No embedded payload found")

    pos += len(MEOW_PAYLOAD_MARKER)

    payload = bytearray()
    while pos < len(gif_data):
        block_size = gif_data[pos]
        if block_size == 0:
            break
        pos += 1
        if pos + block_size > len(gif_data):
            raise ValueError("Malformed payload (truncated sub-block)")
        payload.extend(gif_data[pos : pos + block_size])
        pos += block_size

    return bytes(payload)
