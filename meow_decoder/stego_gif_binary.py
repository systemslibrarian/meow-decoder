"""
GIF Binary Editor for Meow Decoder Multi-Layer Steganography
============================================================

Low-level GIF89a binary manipulation for steganographic channels:
  - Disposal method channel: encode/decode bits in GCE packed fields
  - Comment extension channel: inject/extract encrypted metadata
  - Application extension manipulation

GIF89a Block Reference:
    GCE (0x21 0xF9):  packed[disposal:3|user_input:1|transparent:1] delay[2] trans_idx[1]
    Comment (0x21 0xFE): sub-blocks of [length][data...] terminated by 0x00
    Application (0x21 0xFF): [11-byte id] sub-blocks terminated by 0x00
    Image (0x2C): descriptor + [local color table] + LZW data
    Trailer (0x3B): end of GIF

Security note:
    All data embedded via these channels MUST be pre-encrypted and MAC'd
    by the caller. This module handles format manipulation only.
    Constant-time comparisons are NOT needed here (format bytes, not secrets).

Reference: GIF89a specification (CompuServe, 1990)
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class GceBlock:
    """Parsed Graphic Control Extension block.

    GCE packed byte layout:
        Bits 7-5: reserved (always 0)
        Bits 4-2: disposal method (0-7)
            0 = no disposal specified
            1 = do not dispose (leave in place)
            2 = restore to background color
            3 = restore to previous frame
            4-7 = reserved
        Bit 1: user input flag
        Bit 0: transparent color flag
    """

    offset: int  # Byte offset of the GCE packed byte in the GIF binary
    packed: int  # Packed byte value
    delay: int  # Frame delay in centiseconds
    transparent_idx: int  # Transparent color index

    @property
    def disposal_method(self) -> int:
        """Disposal method (3 bits, values 0-7)."""
        return (self.packed >> 2) & 0x07

    @property
    def user_input_flag(self) -> int:
        """User input flag (1 bit)."""
        return (self.packed >> 1) & 0x01

    @property
    def transparent_flag(self) -> int:
        """Transparent color flag (1 bit)."""
        return self.packed & 0x01


@dataclass
class CommentBlock:
    """Parsed Comment Extension block."""

    offset: int  # Byte offset of the 0x21 0xFE introducer
    end_offset: int  # Byte offset after the block terminator
    data: bytes  # Concatenated comment data from all sub-blocks


@dataclass
class GifStructure:
    """Parsed GIF structure with block locations."""

    raw: bytearray
    header: bytes  # "GIF89a" or "GIF87a"
    lsd_packed: int  # Logical Screen Descriptor packed byte
    gce_blocks: List[GceBlock] = field(default_factory=list)
    comment_blocks: List[CommentBlock] = field(default_factory=list)
    image_offsets: List[int] = field(default_factory=list)
    trailer_offset: int = -1

    @property
    def has_global_color_table(self) -> bool:
        return bool((self.lsd_packed >> 7) & 1)

    @property
    def global_color_table_size(self) -> int:
        if not self.has_global_color_table:
            return 0
        return 3 * (1 << ((self.lsd_packed & 0x07) + 1))


# ---------------------------------------------------------------------------
# GIF Binary Editor
# ---------------------------------------------------------------------------


class GifBinaryEditor:
    """Parse and modify GIF89a binary for steganographic channels.

    Thread-safety: NOT thread-safe. Create one instance per GIF.

    Usage:
        # Parse
        structure = GifBinaryEditor.parse(gif_bytes)

        # Modify GCE packed bytes (disposal channel)
        GifBinaryEditor.set_gce_bits(structure, 0, disposal=1, user_input=0, transparent=0)

        # Inject comment (comment channel)
        structure = GifBinaryEditor.inject_comment(structure, encrypted_data)

        # Serialize back
        gif_bytes = GifBinaryEditor.to_bytes(structure)
    """

    @staticmethod
    def parse(gif_data: bytes) -> GifStructure:
        """Parse GIF binary into structured block list.

        Args:
            gif_data: Complete GIF file bytes

        Returns:
            GifStructure with all block locations

        Raises:
            ValueError: If GIF is malformed
        """
        data = bytearray(gif_data)

        if len(data) < 13:
            raise ValueError(f"GIF too short ({len(data)} bytes, need >= 13)")

        # Verify header
        header = bytes(data[:6])
        if header not in (b"GIF87a", b"GIF89a"):
            raise ValueError(f"Invalid GIF header: {header!r}")

        lsd_packed = data[10]

        structure = GifStructure(raw=data, header=header, lsd_packed=lsd_packed)

        # Skip header (6) + Logical Screen Descriptor (7)
        pos = 13

        # Skip Global Color Table if present
        if structure.has_global_color_table:
            pos += structure.global_color_table_size

        # Walk through blocks
        while pos < len(data):
            byte = data[pos]

            if byte == 0x3B:  # Trailer
                structure.trailer_offset = pos
                break

            elif byte == 0x21:  # Extension introducer
                if pos + 1 >= len(data):
                    break
                ext_label = data[pos + 1]

                if ext_label == 0xF9:  # Graphic Control Extension
                    if pos + 7 <= len(data):
                        block_size = data[pos + 2]  # Should be 4
                        packed = data[pos + 3]
                        delay = struct.unpack_from("<H", data, pos + 4)[0]
                        trans_idx = data[pos + 6]

                        gce = GceBlock(
                            offset=pos + 3,  # Offset of packed byte
                            packed=packed,
                            delay=delay,
                            transparent_idx=trans_idx,
                        )
                        structure.gce_blocks.append(gce)
                        # GCE is always: 0x21 0xF9 0x04 [packed] [delay_lo] [delay_hi] [trans_idx] 0x00
                        pos += 2 + 1 + block_size + 1  # intro(2) + size(1) + data(4) + term(1)
                    else:
                        break

                elif ext_label == 0xFE:  # Comment Extension
                    comment_start = pos
                    pos += 2  # Skip introducer + label
                    comment_data = bytearray()
                    while pos < len(data):
                        sub_size = data[pos]
                        pos += 1
                        if sub_size == 0:
                            break
                        if pos + sub_size > len(data):
                            break
                        comment_data.extend(data[pos: pos + sub_size])
                        pos += sub_size
                    structure.comment_blocks.append(
                        CommentBlock(
                            offset=comment_start,
                            end_offset=pos,
                            data=bytes(comment_data),
                        )
                    )

                elif ext_label == 0xFF:  # Application Extension
                    pos += 2  # Skip introducer + label
                    if pos < len(data):
                        block_size = data[pos]
                        pos += 1 + block_size  # Size byte + app identifier
                        # Skip sub-blocks
                        while pos < len(data):
                            sub_size = data[pos]
                            pos += 1
                            if sub_size == 0:
                                break
                            pos += sub_size

                else:  # Unknown extension types (0x01 Plain Text, etc.)
                    pos += 2  # Skip introducer + label
                    while pos < len(data):
                        sub_size = data[pos]
                        pos += 1
                        if sub_size == 0:
                            break
                        pos += sub_size

            elif byte == 0x2C:  # Image Descriptor
                structure.image_offsets.append(pos)
                if pos + 10 > len(data):
                    break

                packed_id = data[pos + 9]
                has_lct = (packed_id >> 7) & 1
                lct_size = packed_id & 0x07

                pos += 10  # Skip image descriptor (10 bytes)

                # Skip Local Color Table
                if has_lct:
                    lct_entries = 1 << (lct_size + 1)
                    pos += lct_entries * 3

                # Skip LZW minimum code size
                if pos < len(data):
                    pos += 1

                # Skip image data sub-blocks
                while pos < len(data):
                    sub_size = data[pos]
                    pos += 1
                    if sub_size == 0:
                        break
                    pos += sub_size
            else:
                # Unknown byte - skip (shouldn't happen in valid GIF)
                logger.debug("Unknown byte 0x%02X at offset %d", byte, pos)
                pos += 1

        return structure

    @staticmethod
    def set_gce_bits(
        structure: GifStructure,
        frame_idx: int,
        disposal: int,
        user_input: int,
        transparent: int,
    ) -> None:
        """Set disposal method, user input flag, and transparency flag in GCE.

        Modifies the raw binary in-place.

        Args:
            structure: Parsed GIF structure (modified in-place)
            frame_idx: Frame index (0-based)
            disposal: Disposal method (0-7, 3 bits)
            user_input: User input flag (0 or 1)
            transparent: Transparent color flag (0 or 1)

        Raises:
            IndexError: If frame_idx is out of range
        """
        if frame_idx >= len(structure.gce_blocks):
            raise IndexError(
                f"Frame {frame_idx} out of range "
                f"(have {len(structure.gce_blocks)} GCE blocks)"
            )

        gce = structure.gce_blocks[frame_idx]
        # Preserve reserved bits (7-5), set disposal (4-2), user_input (1), transparent (0)
        packed = (
            (gce.packed & 0xE0)
            | ((disposal & 0x07) << 2)
            | ((user_input & 0x01) << 1)
            | (transparent & 0x01)
        )
        structure.raw[gce.offset] = packed
        gce.packed = packed

    @staticmethod
    def get_gce_bits(
        structure: GifStructure,
        frame_idx: int,
    ) -> Tuple[int, int, int]:
        """Read disposal, user_input, transparent from a GCE block.

        Returns:
            Tuple of (disposal, user_input, transparent)
        """
        if frame_idx >= len(structure.gce_blocks):
            raise IndexError(
                f"Frame {frame_idx} out of range "
                f"(have {len(structure.gce_blocks)} GCE blocks)"
            )
        gce = structure.gce_blocks[frame_idx]
        return (gce.disposal_method, gce.user_input_flag, gce.transparent_flag)

    @staticmethod
    def inject_comment(
        structure: GifStructure,
        data: bytes,
    ) -> GifStructure:
        """Inject a Comment Extension block into the GIF (before trailer).

        Args:
            structure: Parsed GIF structure
            data: Comment data bytes (will be split into ≤255-byte sub-blocks)

        Returns:
            New GifStructure with injected comment (re-parsed for correct offsets)

        Raises:
            ValueError: If trailer not found or data is empty
        """
        if not data:
            raise ValueError("Cannot inject empty comment")

        if structure.trailer_offset < 0:
            raise ValueError("GIF trailer (0x3B) not found; cannot inject comment")

        # Build Comment Extension block
        comment_block = bytearray([0x21, 0xFE])  # Introducer + Comment label

        # Split data into sub-blocks (max 255 bytes each)
        offset = 0
        while offset < len(data):
            chunk_size = min(255, len(data) - offset)
            comment_block.append(chunk_size)
            comment_block.extend(data[offset: offset + chunk_size])
            offset += chunk_size
        comment_block.append(0x00)  # Block terminator

        # Insert just before trailer
        insert_pos = structure.trailer_offset
        new_raw = (
            bytearray(structure.raw[:insert_pos])
            + comment_block
            + bytearray(structure.raw[insert_pos:])
        )

        # Re-parse to update all offsets
        return GifBinaryEditor.parse(bytes(new_raw))

    @staticmethod
    def remove_comments(structure: GifStructure) -> GifStructure:
        """Remove all Comment Extension blocks from the GIF.

        Returns:
            New GifStructure with comments removed
        """
        if not structure.comment_blocks:
            return structure

        # Remove blocks in reverse order (to preserve offsets)
        raw = bytearray(structure.raw)
        for cb in reversed(structure.comment_blocks):
            raw = raw[: cb.offset] + raw[cb.end_offset:]

        return GifBinaryEditor.parse(bytes(raw))

    @staticmethod
    def extract_comments(structure: GifStructure) -> List[bytes]:
        """Extract all comment block data from GIF.

        Returns:
            List of comment data bytes
        """
        return [cb.data for cb in structure.comment_blocks]

    @staticmethod
    def to_bytes(structure: GifStructure) -> bytes:
        """Serialize GIF structure back to bytes."""
        return bytes(structure.raw)
