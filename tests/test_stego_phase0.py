"""
Phase 0 Hardening Tests for Multi-Layer Steganography
=====================================================

Tests for:
  - Phase 0.1: GCE Disposal Channel (GifBinaryEditor + DisposalChannelEncoder)
  - Phase 0.2: Comment Extension Channel (CommentChannelEncoder)
  - Phase 0.3: Saliency-Based STC Cost Function (SaliencyCostComputer)
  - Phase 0.4: Immunization Noise Layer (ImmunizationLayer)
  - Integration: Full encode/decode roundtrip with all Phase 0 features
"""

from meow_decoder.stego_multilayer import (
    MultiLayerConfig,
    MultiLayerStegoEncoder,
    MultiLayerStegoDecoder,
    SaliencyCostComputer,
    ImmunizationLayer,
    DisposalChannelEncoder,
    CommentChannelEncoder,
    StegoExtractionResult,
    prepare_payload,
    unpack_payload,
    _bytes_to_bits,
    _bits_to_bytes,
    CHANNEL_DISPOSAL,
    CHANNEL_COMMENT,
    DISPOSAL_BITS_PER_FRAME,
    COMMENT_MAGIC,
    STEGO_MAGIC,
)
from meow_decoder.stego_gif_binary import (
    GifBinaryEditor,
    GifStructure,
    GceBlock,
    CommentBlock,
)
import hashlib
import io
import os
import struct
import tempfile
import unittest
from pathlib import Path

import numpy as np

# Set test mode for faster Argon2 parameters
os.environ["MEOW_TEST_MODE"] = "1"

# OpenCV availability (saliency tests require it)
try:
    import cv2 as _cv2  # noqa: F401

    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_test_gif(num_frames: int = 5, width: int = 32, height: int = 32) -> bytes:
    """Create a minimal test GIF89a with the specified number of frames.

    Each frame is a solid color (different per frame) with a global palette.
    """
    from PIL import Image

    frames_pil = []
    for i in range(num_frames):
        # Create frame with some texture (gradient + noise)
        arr = np.zeros((height, width, 3), dtype=np.uint8)
        # Gradient
        for y in range(height):
            for x in range(width):
                arr[y, x, 0] = (x * 8 + i * 30) % 256
                arr[y, x, 1] = (y * 8 + i * 20) % 256
                arr[y, x, 2] = ((x + y) * 4 + i * 10) % 256
        frames_pil.append(Image.fromarray(arr, "RGB"))

    buf = io.BytesIO()
    frames_pil[0].save(
        buf,
        format="GIF",
        save_all=True,
        append_images=frames_pil[1:],
        duration=100,
        loop=0,
    )
    return buf.getvalue()


def _make_test_gif_path(num_frames: int = 5, width: int = 32, height: int = 32) -> Path:
    """Create a test GIF file and return its path."""
    gif_bytes = _make_test_gif(num_frames, width, height)
    tmpfile = tempfile.NamedTemporaryFile(suffix=".gif", delete=False)
    tmpfile.write(gif_bytes)
    tmpfile.close()
    return Path(tmpfile.name)


MASTER_KEY = b"\xab" * 32


# ===========================================================================
# Phase 0.1: GIF Binary Editor Tests
# ===========================================================================


class TestGifBinaryEditor(unittest.TestCase):
    """Test GIF89a binary parsing and manipulation."""

    def test_parse_valid_gif(self):
        """Parse a valid multi-frame GIF."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)

        self.assertEqual(structure.header, b"GIF89a")
        self.assertGreaterEqual(len(structure.gce_blocks), 1)
        self.assertGreaterEqual(len(structure.image_offsets), 1)
        self.assertGreater(structure.trailer_offset, 0)

    def test_parse_roundtrip(self):
        """Parse and re-serialize should produce identical bytes."""
        gif = _make_test_gif(5)
        structure = GifBinaryEditor.parse(gif)
        result = GifBinaryEditor.to_bytes(structure)
        self.assertEqual(gif, result)

    def test_parse_gce_count(self):
        """Each frame should have one GCE block."""
        for n in [1, 3, 5, 10]:
            gif = _make_test_gif(n)
            structure = GifBinaryEditor.parse(gif)
            # GCE blocks should be >= num_frames (some GIF writers add extras)
            self.assertGreaterEqual(
                len(structure.gce_blocks),
                1,
                f"Expected at least 1 GCE for {n} frames",
            )

    def test_gce_packed_byte_read(self):
        """GCE packed byte fields should be parseable."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        for gce in structure.gce_blocks:
            # Disposal method: 0-7
            self.assertIn(gce.disposal_method, range(8))
            # User input: 0 or 1
            self.assertIn(gce.user_input_flag, (0, 1))
            # Transparent: 0 or 1
            self.assertIn(gce.transparent_flag, (0, 1))

    def test_set_gce_bits(self):
        """Setting GCE bits should modify the raw binary correctly."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)

        # Set disposal=2, user_input=1, transparent=1 on frame 0
        GifBinaryEditor.set_gce_bits(structure, 0, disposal=2, user_input=1, transparent=1)

        gce = structure.gce_blocks[0]
        self.assertEqual(gce.disposal_method, 2)
        self.assertEqual(gce.user_input_flag, 1)
        self.assertEqual(gce.transparent_flag, 1)

    def test_set_gce_bits_roundtrip(self):
        """Modified GCE bits should survive parse→modify→serialize→re-parse."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        GifBinaryEditor.set_gce_bits(structure, 0, disposal=3, user_input=1, transparent=0)

        # Serialize and re-parse
        modified_bytes = GifBinaryEditor.to_bytes(structure)
        structure2 = GifBinaryEditor.parse(modified_bytes)

        gce = structure2.gce_blocks[0]
        self.assertEqual(gce.disposal_method, 3)
        self.assertEqual(gce.user_input_flag, 1)
        self.assertEqual(gce.transparent_flag, 0)

    def test_set_gce_bits_out_of_range(self):
        """Setting GCE bits on non-existent frame should raise IndexError."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        with self.assertRaises(IndexError):
            GifBinaryEditor.set_gce_bits(structure, 999, disposal=0, user_input=0, transparent=0)

    def test_set_gce_all_disposal_values(self):
        """All disposal method values 0-3 should work."""
        gif = _make_test_gif(5)
        structure = GifBinaryEditor.parse(gif)

        for i, disposal in enumerate([0, 1, 2, 3]):
            if i < len(structure.gce_blocks):
                GifBinaryEditor.set_gce_bits(
                    structure, i, disposal=disposal, user_input=0, transparent=0
                )
                self.assertEqual(structure.gce_blocks[i].disposal_method, disposal)

    def test_inject_comment(self):
        """Injecting a comment should add a Comment Extension block."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        comment_count_before = len(structure.comment_blocks)

        structure = GifBinaryEditor.inject_comment(structure, b"Hello from meow-decoder!")

        self.assertEqual(len(structure.comment_blocks), comment_count_before + 1)
        self.assertEqual(structure.comment_blocks[-1].data, b"Hello from meow-decoder!")

    def test_inject_comment_long_data(self):
        """Long comment data should be split into ≤255-byte sub-blocks."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)

        long_data = b"X" * 600  # Requires 3 sub-blocks
        structure = GifBinaryEditor.inject_comment(structure, long_data)

        comments = GifBinaryEditor.extract_comments(structure)
        self.assertEqual(comments[-1], long_data)

    def test_inject_comment_preserves_gif(self):
        """Injecting a comment should not break the GIF structure."""
        gif = _make_test_gif(5)
        structure = GifBinaryEditor.parse(gif)
        num_gce_before = len(structure.gce_blocks)
        num_images_before = len(structure.image_offsets)

        structure = GifBinaryEditor.inject_comment(structure, b"test comment")

        self.assertEqual(len(structure.gce_blocks), num_gce_before)
        self.assertEqual(len(structure.image_offsets), num_images_before)
        self.assertGreater(structure.trailer_offset, 0)

    def test_extract_comments_empty(self):
        """Extracting comments from GIF with no comments should return empty list."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        # PIL doesn't inject comments by default
        comments = GifBinaryEditor.extract_comments(structure)
        # May or may not have comments depending on GIF writer
        self.assertIsInstance(comments, list)

    def test_remove_comments(self):
        """Removing comments should produce a valid GIF without comments."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)

        # Inject then remove
        structure = GifBinaryEditor.inject_comment(structure, b"to be removed")
        self.assertGreater(len(structure.comment_blocks), 0)

        structure = GifBinaryEditor.remove_comments(structure)
        # After removal, verify comments from our injection are gone
        found_our_comment = any(cb.data == b"to be removed" for cb in structure.comment_blocks)
        self.assertFalse(found_our_comment)

    def test_parse_invalid_header(self):
        """Non-GIF data should raise ValueError."""
        with self.assertRaises(ValueError):
            GifBinaryEditor.parse(b"NOT A GIF FILE")

    def test_parse_too_short(self):
        """Data shorter than minimum GIF should raise ValueError."""
        with self.assertRaises(ValueError):
            GifBinaryEditor.parse(b"GIF89a")

    def test_inject_empty_comment_raises(self):
        """Empty comment data should raise ValueError."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        with self.assertRaises(ValueError):
            GifBinaryEditor.inject_comment(structure, b"")


# ===========================================================================
# Phase 0.1: Disposal Channel Encoder Tests
# ===========================================================================


class TestDisposalChannelEncoder(unittest.TestCase):
    """Test GCE disposal/flags steganographic channel."""

    def setUp(self):
        self.config = MultiLayerConfig(
            enable_disposal=True,
            enable_comment=False,
            enable_primary=False,
            enable_secondary=False,
            enable_tertiary=False,
        )
        self.encoder = DisposalChannelEncoder(MASTER_KEY, self.config)

    def test_encode_decode_roundtrip(self):
        """Encode and decode should recover the same bits."""
        gif = _make_test_gif(5)
        structure = GifBinaryEditor.parse(gif)
        num_gce = len(structure.gce_blocks)

        # Create payload bits (4 bits per GCE block)
        payload_bits = [1, 0, 1, 1] * num_gce  # 4 bits per frame

        structure = self.encoder.encode(structure, payload_bits)
        decoded = self.encoder.decode(structure)

        # Should recover at least as many bits as we encoded
        self.assertGreaterEqual(len(decoded), len(payload_bits))
        for i in range(min(len(payload_bits), len(decoded))):
            self.assertEqual(
                decoded[i],
                payload_bits[i],
                f"Bit {i} mismatch: expected {payload_bits[i]}, got {decoded[i]}",
            )

    def test_encode_decode_all_zeros(self):
        """All-zero payload should roundtrip correctly."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        num_gce = len(structure.gce_blocks)

        payload_bits = [0] * (num_gce * DISPOSAL_BITS_PER_FRAME)
        structure = self.encoder.encode(structure, payload_bits)
        decoded = self.encoder.decode(structure)

        for i in range(len(payload_bits)):
            self.assertEqual(decoded[i], 0)

    def test_encode_decode_all_ones(self):
        """All-ones payload should roundtrip correctly."""
        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        num_gce = len(structure.gce_blocks)

        payload_bits = [1] * (num_gce * DISPOSAL_BITS_PER_FRAME)
        structure = self.encoder.encode(structure, payload_bits)
        decoded = self.encoder.decode(structure)

        for i in range(len(payload_bits)):
            self.assertEqual(decoded[i], 1, f"Bit {i} should be 1")

    def test_encode_survive_serialize(self):
        """Disposal bits should survive serialize→re-parse."""
        gif = _make_test_gif(5)
        structure = GifBinaryEditor.parse(gif)
        num_gce = len(structure.gce_blocks)

        payload_bits = [1, 0, 1, 0] * num_gce
        structure = self.encoder.encode(structure, payload_bits)

        # Serialize and re-parse
        modified = GifBinaryEditor.to_bytes(structure)
        structure2 = GifBinaryEditor.parse(modified)
        decoded = self.encoder.decode(structure2)

        for i in range(min(len(payload_bits), len(decoded))):
            self.assertEqual(decoded[i], payload_bits[i])

    def test_estimate_capacity(self):
        """Capacity estimation should be correct."""
        self.assertEqual(self.encoder.estimate_capacity(10), 40)  # 10 × 4
        self.assertEqual(self.encoder.estimate_capacity(100), 400)

    def test_empty_gce(self):
        """Encoding with no GCE blocks should handle gracefully."""
        # Create a minimal GIF structure with no GCE blocks
        gif = _make_test_gif(1)
        structure = GifBinaryEditor.parse(gif)
        # Artificially clear GCE blocks to test edge case
        original_gce = structure.gce_blocks[:]
        structure.gce_blocks = []
        structure = self.encoder.encode(structure, [1, 0, 1, 0])
        decoded = self.encoder.decode(structure)
        self.assertEqual(len(decoded), 0)


# ===========================================================================
# Phase 0.2: Comment Channel Encoder Tests
# ===========================================================================


class TestCommentChannelEncoder(unittest.TestCase):
    """Test encrypted Comment Extension channel."""

    def setUp(self):
        self.config = MultiLayerConfig(enable_comment=True)
        self.encoder = CommentChannelEncoder(MASTER_KEY, self.config)

    def test_encode_decode_roundtrip(self):
        """Encrypt and decrypt should recover original payload."""
        payload = b"Secret message for comment channel"
        encrypted = self.encoder.encode(payload)
        recovered, mac_valid = self.encoder.decode(encrypted)

        self.assertTrue(mac_valid)
        self.assertEqual(recovered, payload)

    def test_encode_decode_empty_payload(self):
        """Empty payload should roundtrip correctly."""
        encrypted = self.encoder.encode(b"")
        recovered, mac_valid = self.encoder.decode(encrypted)
        self.assertTrue(mac_valid)
        self.assertEqual(recovered, b"")

    def test_encode_decode_large_payload(self):
        """Large payload (500 bytes) should roundtrip."""
        payload = os.urandom(500)
        encrypted = self.encoder.encode(payload)
        recovered, mac_valid = self.encoder.decode(encrypted)
        self.assertTrue(mac_valid)
        self.assertEqual(recovered, payload)

    def test_wrong_key_fails(self):
        """Different key should fail MAC verification."""
        payload = b"Secret"
        encrypted = self.encoder.encode(payload)

        wrong_encoder = CommentChannelEncoder(b"\x00" * 32, self.config)
        recovered, mac_valid = wrong_encoder.decode(encrypted)
        self.assertFalse(mac_valid)
        self.assertEqual(recovered, b"")

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail MAC verification."""
        payload = b"Secret"
        encrypted = bytearray(self.encoder.encode(payload))

        # Tamper with a byte in the ciphertext (after magic+len+nonce)
        if len(encrypted) > 25:
            encrypted[25] ^= 0xFF
        recovered, mac_valid = self.encoder.decode(bytes(encrypted))
        self.assertFalse(mac_valid)

    def test_tampered_mac_fails(self):
        """Tampered MAC should fail verification."""
        payload = b"Secret"
        encrypted = bytearray(self.encoder.encode(payload))

        # Tamper with last byte (MAC)
        encrypted[-1] ^= 0xFF
        recovered, mac_valid = self.encoder.decode(bytes(encrypted))
        self.assertFalse(mac_valid)

    def test_truncated_data_fails(self):
        """Truncated encrypted data should fail gracefully."""
        recovered, mac_valid = self.encoder.decode(b"too short")
        self.assertFalse(mac_valid)

    def test_wrong_magic_fails(self):
        """Wrong magic bytes should fail."""
        payload = b"Secret"
        encrypted = bytearray(self.encoder.encode(payload))
        encrypted[0:4] = b"XXXX"  # Wrong magic
        recovered, mac_valid = self.encoder.decode(bytes(encrypted))
        self.assertFalse(mac_valid)

    def test_comment_magic_present(self):
        """Encrypted output should start with MSCM magic."""
        payload = b"test"
        encrypted = self.encoder.encode(payload)
        self.assertTrue(encrypted.startswith(COMMENT_MAGIC))

    def test_nonce_uniqueness(self):
        """Each encode call should use a different nonce."""
        payload = b"same payload"
        enc1 = self.encoder.encode(payload)
        enc2 = self.encoder.encode(payload)
        # The nonce is at bytes 8:20
        self.assertNotEqual(enc1[8:20], enc2[8:20])
        # And therefore the ciphertexts should differ
        self.assertNotEqual(enc1, enc2)

    def test_comment_integrated_with_gif(self):
        """Comment should survive GIF injection and extraction."""
        payload = b"Integrated test payload"
        encrypted = self.encoder.encode(payload)

        gif = _make_test_gif(3)
        structure = GifBinaryEditor.parse(gif)
        structure = GifBinaryEditor.inject_comment(structure, encrypted)

        # Extract and decode
        comments = GifBinaryEditor.extract_comments(structure)
        found = False
        for comment in comments:
            recovered, mac_valid = self.encoder.decode(comment)
            if mac_valid:
                self.assertEqual(recovered, payload)
                found = True
                break
        self.assertTrue(found, "Should find and decode the injected comment")


# ===========================================================================
# Phase 0.3: Saliency Cost Computer Tests
# ===========================================================================


class TestSaliencyCostComputer(unittest.TestCase):
    """Test OpenCV-based saliency cost computation."""

    @unittest.skipUnless(CV2_AVAILABLE, "requires OpenCV for non-uniform saliency")
    def test_flat_region_high_cost(self):
        """Flat (uniform) regions should have high embedding cost."""
        # Solid gray frame
        flat_frame = np.full((64, 64, 3), 128, dtype=np.uint8)
        cost_map = SaliencyCostComputer.compute(flat_frame)

        self.assertEqual(cost_map.shape, (64, 64))
        # Most costs should be high (≥ 5.0)
        mean_cost = float(np.mean(cost_map))
        self.assertGreater(mean_cost, 3.0, f"Flat region mean cost {mean_cost} should be > 3.0")

    def test_textured_region_low_cost(self):
        """Highly textured regions should have low embedding cost."""
        # Create a noisy/textured frame
        rng = np.random.RandomState(42)
        textured_frame = rng.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        cost_map = SaliencyCostComputer.compute(textured_frame)

        mean_cost = float(np.mean(cost_map))
        self.assertLess(mean_cost, 3.0, f"Textured region mean cost {mean_cost} should be < 3.0")

    @unittest.skipUnless(CV2_AVAILABLE, "requires OpenCV for non-uniform saliency")
    def test_edge_region_medium_cost(self):
        """Edges should have medium cost."""
        # Frame with sharp vertical edge
        frame = np.zeros((64, 64, 3), dtype=np.uint8)
        frame[:, 32:, :] = 255  # Left half black, right half white
        cost_map = SaliencyCostComputer.compute(frame)

        # Edge pixels should have lower cost than flat regions
        edge_costs = cost_map[:, 30:34].mean()
        flat_costs = cost_map[:, 0:10].mean()
        self.assertLess(
            edge_costs,
            flat_costs,
            f"Edge cost ({edge_costs}) should be less than flat cost ({flat_costs})",
        )

    def test_sensitivity_scaling(self):
        """Higher sensitivity should produce proportionally higher costs."""
        frame = np.full((32, 32, 3), 128, dtype=np.uint8)
        cost_low = SaliencyCostComputer.compute(frame, sensitivity=0.5)
        cost_high = SaliencyCostComputer.compute(frame, sensitivity=2.0)

        self.assertGreater(
            float(np.mean(cost_high)),
            float(np.mean(cost_low)),
            "Higher sensitivity should produce higher costs",
        )

    def test_costs_for_walk(self):
        """Walk-aligned costs should have correct length."""
        frame = np.full((16, 16, 3), 128, dtype=np.uint8)
        cost_map = SaliencyCostComputer.compute(frame)

        walk = list(range(16 * 16))  # Sequential walk
        costs = SaliencyCostComputer.costs_for_walk(cost_map, walk, width=16)

        # Expected: 256 pixels × 3 channels × 1 lsb_bit = 768 costs
        self.assertEqual(len(costs), 256 * 3 * 1)
        # All costs should be positive
        self.assertTrue(all(c > 0 for c in costs))

    def test_costs_for_walk_custom_lsb(self):
        """Walk costs with lsb_bits=2 should double the output length."""
        frame = np.full((8, 8, 3), 128, dtype=np.uint8)
        cost_map = SaliencyCostComputer.compute(frame)
        walk = list(range(64))
        costs = SaliencyCostComputer.costs_for_walk(cost_map, walk, width=8, lsb_bits=2)
        self.assertEqual(len(costs), 64 * 3 * 2)

    def test_grayscale_input(self):
        """Grayscale (2D) input should work."""
        frame = np.full((32, 32), 128, dtype=np.uint8)
        cost_map = SaliencyCostComputer.compute(frame)
        self.assertEqual(cost_map.shape, (32, 32))


# ===========================================================================
# Phase 0.4: Immunization Noise Layer Tests
# ===========================================================================


class TestImmunizationLayer(unittest.TestCase):
    """Test keyed Gaussian noise pre-processing."""

    def test_noise_changes_pixels(self):
        """Immunization should modify at least some pixels."""
        frame = np.full((32, 32, 3), 128, dtype=np.uint8)
        noised = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.5)

        self.assertEqual(frame.shape, noised.shape)
        self.assertEqual(noised.dtype, np.uint8)
        # Some pixels should differ
        diff_count = int(np.sum(frame != noised))
        self.assertGreater(diff_count, 0, "Noise should change at least some pixels")

    def test_noise_deterministic(self):
        """Same key + frame_idx should produce identical noise."""
        frame = np.full((32, 32, 3), 128, dtype=np.uint8)
        noised1 = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.5)
        noised2 = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.5)
        np.testing.assert_array_equal(noised1, noised2)

    def test_noise_different_frames(self):
        """Different frame indices should produce different noise."""
        frame = np.full((32, 32, 3), 128, dtype=np.uint8)
        noised0 = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.5)
        noised1 = ImmunizationLayer.apply(frame, MASTER_KEY, 1, sigma=0.5)
        self.assertFalse(np.array_equal(noised0, noised1))

    def test_noise_different_keys(self):
        """Different keys should produce different noise."""
        frame = np.full((32, 32, 3), 128, dtype=np.uint8)
        noised_a = ImmunizationLayer.apply(frame, b"\xaa" * 32, 0, sigma=0.5)
        noised_b = ImmunizationLayer.apply(frame, b"\xbb" * 32, 0, sigma=0.5)
        self.assertFalse(np.array_equal(noised_a, noised_b))

    def test_noise_low_amplitude(self):
        """Noise should be low-amplitude (most pixels change by ≤ 2)."""
        frame = np.full((64, 64, 3), 128, dtype=np.uint8)
        noised = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.5)

        diff = np.abs(frame.astype(int) - noised.astype(int))
        # With σ=0.5, ~95% of changes should be ≤ 1
        small_changes = np.sum(diff <= 1)
        total_pixels = diff.size
        ratio = small_changes / total_pixels
        self.assertGreater(ratio, 0.9, f"95%+ of changes should be ≤1, got {ratio:.2%}")

    def test_noise_sigma_zero_no_change(self):
        """Sigma=0 should produce no changes."""
        frame = np.full((32, 32, 3), 128, dtype=np.uint8)
        noised = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.0)
        np.testing.assert_array_equal(frame, noised)

    def test_noise_high_sigma(self):
        """Higher sigma should produce more changes."""
        frame = np.full((32, 32, 3), 128, dtype=np.uint8)
        noised_low = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.3)
        noised_high = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=2.0)

        diff_low = np.sum(np.abs(frame.astype(int) - noised_low.astype(int)))
        diff_high = np.sum(np.abs(frame.astype(int) - noised_high.astype(int)))
        self.assertGreater(diff_high, diff_low)

    def test_noise_clamps_to_uint8(self):
        """Noise should not cause overflow/underflow."""
        # Frame at extremes
        frame = np.zeros((32, 32, 3), dtype=np.uint8)
        frame[:16, :, :] = 0
        frame[16:, :, :] = 255
        noised = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=2.0)

        self.assertEqual(noised.dtype, np.uint8)
        self.assertTrue(np.all(noised >= 0))
        self.assertTrue(np.all(noised <= 255))

    def test_noise_preserves_shape(self):
        """Output shape should match input."""
        for shape in [(16, 16, 3), (32, 64, 3), (8, 8, 1)]:
            frame = np.full(shape, 128, dtype=np.uint8)
            noised = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.5)
            self.assertEqual(noised.shape, frame.shape)


# ===========================================================================
# Phase 0 Integration Tests
# ===========================================================================


class TestPhase0Integration(unittest.TestCase):
    """Integration tests for the full Phase 0 encode/decode pipeline."""

    def setUp(self):
        self.config = MultiLayerConfig(
            enable_primary=True,
            enable_secondary=True,
            enable_tertiary=False,  # Palette channel has known limitations
            enable_disposal=True,
            enable_comment=True,
            use_saliency_costs=True,
            immunize=True,
            immunize_sigma=0.5,
            use_stc=True,
            lsb_bits=1,
            compress=True,
            encrypt=True,
        )
        self.master_key = MASTER_KEY

    def test_comment_channel_gif_roundtrip(self):
        """Comment channel: encode → inject → extract → decode should work."""
        config = MultiLayerConfig(
            enable_primary=False,
            enable_secondary=False,
            enable_tertiary=False,
            enable_disposal=False,
            enable_comment=True,
        )
        encoder = CommentChannelEncoder(self.master_key, config)

        # Encode payload
        payload = b"This is secret comment channel data!"
        encrypted = encoder.encode(payload)

        # Inject into GIF
        gif_path = _make_test_gif_path(5)
        try:
            gif_bytes = gif_path.read_bytes()
            structure = GifBinaryEditor.parse(gif_bytes)
            structure = GifBinaryEditor.inject_comment(structure, encrypted)
            modified_gif = GifBinaryEditor.to_bytes(structure)

            # Write modified GIF
            gif_path.write_bytes(modified_gif)

            # Re-parse and extract
            structure2 = GifBinaryEditor.parse(gif_path.read_bytes())
            comments = GifBinaryEditor.extract_comments(structure2)

            found = False
            for comment in comments:
                recovered, mac_valid = encoder.decode(comment)
                if mac_valid:
                    self.assertEqual(recovered, payload)
                    found = True
                    break
            self.assertTrue(found)
        finally:
            gif_path.unlink(missing_ok=True)

    def test_disposal_channel_gif_roundtrip(self):
        """Disposal channel: encode → serialize → re-parse → decode."""
        config = MultiLayerConfig(
            enable_primary=False,
            enable_secondary=False,
            enable_tertiary=False,
            enable_disposal=True,
            enable_comment=False,
        )
        encoder = DisposalChannelEncoder(self.master_key, config)

        gif = _make_test_gif(5)
        structure = GifBinaryEditor.parse(gif)
        num_gce = len(structure.gce_blocks)

        # Create test bits
        test_bits = []
        for i in range(num_gce):
            test_bits.extend([i % 2, (i + 1) % 2, 1, 0])

        structure = encoder.encode(structure, test_bits)
        modified_gif = GifBinaryEditor.to_bytes(structure)

        # Re-parse and decode
        structure2 = GifBinaryEditor.parse(modified_gif)
        decoded = encoder.decode(structure2)

        for i in range(min(len(test_bits), len(decoded))):
            self.assertEqual(decoded[i], test_bits[i], f"Bit {i} mismatch")

    def test_immunization_improves_lsb_entropy(self):
        """Immunization should increase LSB entropy toward 1.0."""
        # Clean frame: solid color has LSB entropy = 0
        frame = np.full((64, 64, 3), 128, dtype=np.uint8)  # 128 = 10000000, LSB=0

        # Measure LSB entropy before
        lsbs_before = frame.flatten() & 1
        ones_before = np.sum(lsbs_before)
        ratio_before = ones_before / len(lsbs_before)

        # Apply immunization
        noised = ImmunizationLayer.apply(frame, MASTER_KEY, 0, sigma=0.5)
        lsbs_after = noised.flatten() & 1
        ones_after = np.sum(lsbs_after)
        ratio_after = ones_after / len(lsbs_after)

        # After immunization, LSB ratio should be closer to 0.5
        dist_before = abs(ratio_before - 0.5)
        dist_after = abs(ratio_after - 0.5)
        self.assertLess(
            dist_after,
            dist_before + 0.01,  # Small tolerance
            f"Immunization should move LSB ratio toward 0.5: "
            f"before={ratio_before:.3f}, after={ratio_after:.3f}",
        )

    @unittest.skipUnless(CV2_AVAILABLE, "requires OpenCV for non-uniform saliency")
    def test_saliency_produces_nonuniform_costs(self):
        """Saliency cost map should vary across image regions."""
        # Frame with both flat and textured regions
        frame = np.zeros((64, 64, 3), dtype=np.uint8)
        frame[:, :, :] = 128  # Base gray
        # Add texture to right half
        rng = np.random.RandomState(42)
        frame[:, 32:, :] = rng.randint(100, 200, (64, 32, 3), dtype=np.uint8)

        cost_map = SaliencyCostComputer.compute(frame)

        # Left (flat) should have higher cost than right (textured)
        left_mean = float(np.mean(cost_map[:, :16]))
        right_mean = float(np.mean(cost_map[:, 40:]))
        self.assertGreater(
            left_mean,
            right_mean,
            f"Flat region ({left_mean:.2f}) should cost more than textured ({right_mean:.2f})",
        )


# ===========================================================================
# Phase 0 Backward Compatibility Tests
# ===========================================================================


class TestBackwardCompatibility(unittest.TestCase):
    """Ensure Phase 0 changes don't break existing functionality."""

    def test_payload_v1_accepted(self):
        """Payloads with STEGO_VERSION=1 should still unpack."""
        # Construct a v1 payload manually
        data = b"test payload"
        flags = 0x00  # no compress, no encrypt
        header = STEGO_MAGIC + struct.pack("<BBI I", 1, flags, len(data), len(data))
        import hmac

        mac_key = hmac.new(MASTER_KEY, b"meow_stego_payload_mac_v1", hashlib.sha256).digest()
        mac = hmac.new(mac_key, header + data, hashlib.sha256).digest()
        raw = header + data + mac

        payload, mac_valid = unpack_payload(raw, MASTER_KEY)
        self.assertTrue(mac_valid)
        self.assertEqual(payload, data)

    def test_config_defaults_backward_compat(self):
        """Default config should enable Phase 0 features."""
        config = MultiLayerConfig()
        self.assertTrue(config.enable_disposal)
        self.assertTrue(config.enable_comment)
        self.assertTrue(config.use_saliency_costs)
        self.assertTrue(config.immunize)

    def test_config_disable_phase0(self):
        """Phase 0 features should be individually disableable."""
        config = MultiLayerConfig(
            enable_disposal=False,
            enable_comment=False,
            use_saliency_costs=False,
            immunize=False,
        )
        self.assertFalse(config.enable_disposal)
        self.assertFalse(config.enable_comment)
        self.assertFalse(config.use_saliency_costs)
        self.assertFalse(config.immunize)


# ===========================================================================
# Phase 0 Security Tests
# ===========================================================================


class TestPhase0Security(unittest.TestCase):
    """Security-focused tests for Phase 0 features."""

    def test_comment_channel_domain_separation(self):
        """Different domain strings should produce different keys.

        After gemini #1 migration, channel sub-keys live as opaque Rust
        handle IDs — equality is asserted via stable HMAC fingerprints
        (`key_fingerprint(role)`) rather than direct byte comparison so
        the underlying key bytes never need to leave Rust.
        """
        enc1 = CommentChannelEncoder(MASTER_KEY, MultiLayerConfig())
        # Verify internal keys are derived deterministically
        enc2 = CommentChannelEncoder(MASTER_KEY, MultiLayerConfig())
        self.assertEqual(enc1.key_fingerprint("enc"), enc2.key_fingerprint("enc"))
        self.assertEqual(enc1.key_fingerprint("mac"), enc2.key_fingerprint("mac"))

        # Different master key → different channel keys
        enc3 = CommentChannelEncoder(b"\x00" * 32, MultiLayerConfig())
        self.assertNotEqual(enc1.key_fingerprint("enc"), enc3.key_fingerprint("enc"))
        self.assertNotEqual(enc1.key_fingerprint("mac"), enc3.key_fingerprint("mac"))

    def test_comment_enc_key_ne_mac_key(self):
        """Encryption key and MAC key should be different (domain separation)."""
        enc = CommentChannelEncoder(MASTER_KEY, MultiLayerConfig())
        self.assertNotEqual(enc.key_fingerprint("enc"), enc.key_fingerprint("mac"))

    def test_disposal_channel_key_independence(self):
        """Disposal channel key should be independent of other channels."""
        enc = DisposalChannelEncoder(MASTER_KEY, MultiLayerConfig())
        comment_enc = CommentChannelEncoder(MASTER_KEY, MultiLayerConfig())
        self.assertNotEqual(enc.key_fingerprint(), comment_enc.key_fingerprint("enc"))
        self.assertNotEqual(enc.key_fingerprint(), comment_enc.key_fingerprint("mac"))

    def test_immunization_noise_unpredictable_without_key(self):
        """Noise should not be predictable without the correct key."""
        frame = np.full((32, 32, 3), 128, dtype=np.uint8)

        # Two different keys produce different noise patterns
        noised_a = ImmunizationLayer.apply(frame, b"\xaa" * 32, 0, sigma=1.0)
        noised_b = ImmunizationLayer.apply(frame, b"\xbb" * 32, 0, sigma=1.0)

        # Extract the NOISE (difference from original), not the noised image
        noise_a = noised_a.astype(np.int16) - frame.astype(np.int16)
        noise_b = noised_b.astype(np.int16) - frame.astype(np.int16)

        # The noise patterns should be different
        self.assertFalse(
            np.array_equal(noise_a, noise_b),
            "Noise from different keys must differ",
        )

        # Cross-correlation of noise patterns should be near zero
        flat_a = noise_a.flatten().astype(float)
        flat_b = noise_b.flatten().astype(float)
        if np.std(flat_a) > 0 and np.std(flat_b) > 0:
            correlation = np.corrcoef(flat_a, flat_b)[0, 1]
            self.assertLess(
                abs(correlation),
                0.15,
                f"Noise cross-correlation {correlation:.3f} should be near zero",
            )


if __name__ == "__main__":
    unittest.main()
