"""
Tests for size_normalizer.py — Size Class Padding & Frame Count Normalization

Tests verify:
  - Size class selection picks smallest fitting class
  - Padding produces exact size class output
  - Unpadding recovers original data exactly
  - Round-trip (pad → unpad) is identity
  - Edge cases: empty data, max size, boundary sizes
  - Frame count normalization rounds up to quantum
  - Frame padding adds correct number of frames
  - Invalid inputs raise appropriate errors
  - Padding bytes are random (not predictable)
"""

import secrets
import struct
import pytest
from meow_decoder.size_normalizer import (
    SIZE_CLASSES,
    PADDING_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    FRAME_QUANTUM,
    MIN_FRAME_COUNT,
    MAX_FRAME_COUNT,
    select_size_class,
    pad_to_size_class,
    unpad_from_size_class,
    get_size_class_for_display,
    normalize_frame_count,
    pad_frames,
    compute_frame_metadata,
)


# ══════════════════════════════════════════════════════════════
#  Size Class Selection
# ══════════════════════════════════════════════════════════════


class TestSelectSizeClass:
    """Tests for select_size_class."""

    def test_small_data_selects_4kb(self):
        assert select_size_class(100) == 4_096

    def test_boundary_exact_fit(self):
        """Data + header that exactly fills 4KB should select 4KB."""
        max_data_for_4k = 4_096 - PADDING_HEADER_SIZE
        assert select_size_class(max_data_for_4k) == 4_096

    def test_boundary_overflow_selects_next(self):
        """Data + header that overflows 4KB should select 16KB."""
        too_big_for_4k = 4_096 - PADDING_HEADER_SIZE + 1
        assert select_size_class(too_big_for_4k) == 16_384

    def test_medium_data(self):
        assert select_size_class(50_000) == 65_536

    def test_large_data(self):
        assert select_size_class(2_000_000) == 4_194_304

    def test_explicit_override(self):
        assert select_size_class(100, size_class=65_536) == 65_536

    def test_explicit_override_too_small_raises(self):
        with pytest.raises(ValueError, match="too small"):
            select_size_class(100_000, size_class=4_096)

    def test_data_exceeds_all_classes_raises(self):
        with pytest.raises(ValueError, match="too large"):
            select_size_class(SIZE_CLASSES[-1] + 1)

    def test_empty_data_selects_4kb(self):
        assert select_size_class(0) == 4_096

    def test_each_class_boundary(self):
        """Each size class boundary should select correctly."""
        for i, sc in enumerate(SIZE_CLASSES):
            max_data = sc - PADDING_HEADER_SIZE
            assert select_size_class(max_data) == sc
            if i < len(SIZE_CLASSES) - 1:
                assert select_size_class(max_data + 1) == SIZE_CLASSES[i + 1]


# ══════════════════════════════════════════════════════════════
#  Padding / Unpadding
# ══════════════════════════════════════════════════════════════


class TestPadUnpad:
    """Tests for pad_to_size_class and unpad_from_size_class."""

    def test_roundtrip_small(self):
        data = b"hello world"
        padded = pad_to_size_class(data)
        recovered = unpad_from_size_class(padded)
        assert recovered == data

    def test_roundtrip_empty(self):
        data = b""
        padded = pad_to_size_class(data)
        recovered = unpad_from_size_class(padded)
        assert recovered == data

    def test_roundtrip_exact_boundary(self):
        """Data that exactly fills a size class (minus header)."""
        max_data = 4_096 - PADDING_HEADER_SIZE
        data = secrets.token_bytes(max_data)
        padded = pad_to_size_class(data)
        assert len(padded) == 4_096
        recovered = unpad_from_size_class(padded)
        assert recovered == data

    def test_padded_size_matches_class(self):
        for size in [10, 1000, 10_000, 100_000, 1_000_000]:
            data = secrets.token_bytes(size)
            padded = pad_to_size_class(data)
            assert len(padded) in SIZE_CLASSES, f"Size {len(padded)} not a valid size class"

    def test_padding_is_random(self):
        """Two pads of the same data should produce different padding bytes."""
        data = b"same data"
        pad1 = pad_to_size_class(data)
        pad2 = pad_to_size_class(data)
        # The data portion is the same, but padding should differ
        # (with overwhelming probability for 4KB - 17 bytes of random)
        assert pad1 != pad2

    def test_length_header_correct(self):
        data = b"test data 12345"
        padded = pad_to_size_class(data)
        stored_len = struct.unpack(">Q", padded[:8])[0]
        assert stored_len == len(data)

    def test_explicit_size_class(self):
        data = b"small"
        padded = pad_to_size_class(data, size_class=65_536)
        assert len(padded) == 65_536
        recovered = unpad_from_size_class(padded)
        assert recovered == data

    def test_roundtrip_various_sizes(self):
        """Roundtrip test across many sizes."""
        for size in [0, 1, 100, 1000, 4088, 4089, 10000, 50000, 100000]:
            data = secrets.token_bytes(size)
            padded = pad_to_size_class(data)
            recovered = unpad_from_size_class(padded)
            assert recovered == data, f"Roundtrip failed for size {size}"

    def test_unpad_corrupted_length_raises(self):
        """Corrupted length header should raise ValueError."""
        # Create padding claiming more data than available
        bad = struct.pack(">Q", 999_999_999) + b"\x00" * 100
        with pytest.raises(ValueError, match="claims"):
            unpad_from_size_class(bad)

    def test_unpad_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            unpad_from_size_class(b"\x00\x01\x02")

    def test_unpad_exceeds_max_raises(self):
        """Length exceeding MAX_PAYLOAD_SIZE should be rejected."""
        bad = struct.pack(">Q", MAX_PAYLOAD_SIZE + 1) + secrets.token_bytes(100)
        with pytest.raises(ValueError, match="exceeds maximum"):
            unpad_from_size_class(bad)


# ══════════════════════════════════════════════════════════════
#  Display Helpers
# ══════════════════════════════════════════════════════════════


class TestDisplayHelpers:
    """Tests for get_size_class_for_display."""

    def test_kilobytes(self):
        assert get_size_class_for_display(4_096) == "4 KB"
        assert get_size_class_for_display(16_384) == "16 KB"
        assert get_size_class_for_display(65_536) == "64 KB"
        assert get_size_class_for_display(262_144) == "256 KB"

    def test_megabytes(self):
        assert get_size_class_for_display(1_048_576) == "1 MB"
        assert get_size_class_for_display(4_194_304) == "4 MB"
        assert get_size_class_for_display(16_777_216) == "16 MB"
        assert get_size_class_for_display(67_108_864) == "64 MB"

    def test_bytes(self):
        assert get_size_class_for_display(512) == "512 B"


# ══════════════════════════════════════════════════════════════
#  Frame Count Normalization
# ══════════════════════════════════════════════════════════════


class TestNormalizeFrameCount:
    """Tests for normalize_frame_count."""

    def test_rounds_up_to_quantum(self):
        assert normalize_frame_count(1) == MIN_FRAME_COUNT
        assert normalize_frame_count(10) == MIN_FRAME_COUNT
        assert normalize_frame_count(49) == MIN_FRAME_COUNT
        assert normalize_frame_count(50) == 50
        assert normalize_frame_count(51) == 100
        assert normalize_frame_count(100) == 100
        assert normalize_frame_count(101) == 150

    def test_minimum_enforced(self):
        assert normalize_frame_count(0) == MIN_FRAME_COUNT
        assert normalize_frame_count(-5) == MIN_FRAME_COUNT
        assert normalize_frame_count(1) == MIN_FRAME_COUNT

    def test_maximum_enforced(self):
        assert normalize_frame_count(9999) == MAX_FRAME_COUNT
        assert normalize_frame_count(MAX_FRAME_COUNT + 1) == MAX_FRAME_COUNT

    def test_custom_quantum(self):
        assert normalize_frame_count(17, quantum=10) == 50  # rounds to 20 but min=50
        assert normalize_frame_count(55, quantum=10) == 60

    def test_custom_minimum(self):
        assert normalize_frame_count(5, minimum=20) == 50  # quantum rounds up

    def test_exact_quantum(self):
        """Exact multiples of quantum should not be rounded up."""
        assert normalize_frame_count(100) == 100
        assert normalize_frame_count(200) == 200
        assert normalize_frame_count(500) == 500


# ══════════════════════════════════════════════════════════════
#  Frame Padding
# ══════════════════════════════════════════════════════════════


class TestPadFrames:
    """Tests for pad_frames."""

    def test_pad_with_generator(self):
        frames = ["f1", "f2", "f3"]
        def gen(): return "extra"
        result = pad_frames(frames, 5, frame_generator=gen)
        assert len(result) == 5
        assert result[:3] == ["f1", "f2", "f3"]
        assert result[3:] == ["extra", "extra"]

    def test_pad_without_generator_duplicates_last(self):
        frames = ["f1", "f2"]
        result = pad_frames(frames, 4)
        assert len(result) == 4
        assert result == ["f1", "f2", "f2", "f2"]

    def test_no_padding_needed(self):
        frames = ["f1", "f2", "f3"]
        result = pad_frames(frames, 3)
        assert result == frames

    def test_truncate_if_too_many(self):
        frames = ["f1", "f2", "f3", "f4", "f5"]
        result = pad_frames(frames, 3)
        assert len(result) == 3
        assert result == ["f1", "f2", "f3"]

    def test_empty_frames_with_generator(self):
        frames = []
        def gen(): return "new"
        result = pad_frames(frames, 3, frame_generator=gen)
        assert len(result) == 3
        assert all(f == "new" for f in result)

    def test_empty_frames_without_generator(self):
        frames = []
        result = pad_frames(frames, 3)
        assert result == []  # Can't duplicate from empty list


# ══════════════════════════════════════════════════════════════
#  Frame Metadata
# ══════════════════════════════════════════════════════════════


class TestComputeFrameMetadata:
    """Tests for compute_frame_metadata."""

    def test_basic_metadata(self):
        meta = compute_frame_metadata(30, 50)
        assert meta["actual_frames"] == 30
        assert meta["normalized_frames"] == 50
        assert meta["padding_frames"] == 20
        assert abs(meta["padding_ratio"] - 20 / 30) < 0.001
        assert meta["quantum"] == FRAME_QUANTUM

    def test_no_padding(self):
        meta = compute_frame_metadata(50, 50)
        assert meta["padding_frames"] == 0
        assert meta["padding_ratio"] == 0.0

    def test_zero_actual_frames(self):
        meta = compute_frame_metadata(0, 50)
        assert meta["padding_ratio"] == 0.0  # Division by zero guard


# ══════════════════════════════════════════════════════════════
#  Constants
# ══════════════════════════════════════════════════════════════


class TestSizeNormalizerConstants:
    """Tests for module constants."""

    def test_size_classes_sorted(self):
        assert SIZE_CLASSES == sorted(SIZE_CLASSES)

    def test_size_classes_all_positive(self):
        assert all(sc > 0 for sc in SIZE_CLASSES)

    def test_size_classes_are_powers(self):
        """All size classes should be powers of 2."""
        for sc in SIZE_CLASSES:
            assert sc & (sc - 1) == 0, f"{sc} is not a power of 2"

    def test_frame_quantum_positive(self):
        assert FRAME_QUANTUM > 0

    def test_min_less_than_max_frames(self):
        assert MIN_FRAME_COUNT <= MAX_FRAME_COUNT

    def test_padding_header_size(self):
        assert PADDING_HEADER_SIZE == 8  # u64 big-endian
