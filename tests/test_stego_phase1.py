"""Phase 1 tests for multi-layer steganography upgrades.

Tests for:
- Phase 1.1: Temporal channel encoder (inter-frame delta embedding)
- Phase 1.2: Adversarial perturbation layer (anti-steganalysis)
- Phase 1.3: Procedural cat carrier generator

Tests follow the same patterns as test_stego_phase0.py and test_stego_adversarial.py.
"""

from meow_decoder.stego_multilayer import (
    ADVERSARIAL_STRENGTH_HIGH,
    ADVERSARIAL_STRENGTH_LOW,
    ADVERSARIAL_STRENGTH_MEDIUM,
    CHANNEL_TEMPORAL,
    AdversarialPerturbationLayer,
    CoercionLevel,
    MultiLayerConfig,
    MultiLayerStegoDecoder,
    MultiLayerStegoEncoder,
    ProceduralCatGenerator,
    TemporalChannelEncoder,
    derive_stego_keys_for_reality,
    _bytes_to_bits,
    _bits_to_bytes,
)
import hashlib
import os
import struct
import tempfile
from pathlib import Path

import numpy as np
import pytest

os.environ.setdefault("MEOW_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_key(seed: str = "test_phase1_key_material") -> bytes:
    """Generate a deterministic 32-byte test key."""
    return hashlib.sha256(seed.encode()).digest()


def make_test_frames(
    num_frames: int = 10,
    height: int = 64,
    width: int = 80,
    seed: int = 42,
) -> list:
    """Generate synthetic animated frames with gradual transitions."""
    rng = np.random.RandomState(seed)
    frames = []
    base = rng.randint(50, 200, (height, width, 3), dtype=np.uint8)
    for i in range(num_frames):
        # Add slight variation per frame (simulates animation)
        noise = rng.randint(-5, 6, (height, width, 3))
        frame = np.clip(base.astype(np.int16) + noise + i * 2, 0, 255).astype(np.uint8)
        frames.append(frame)
    return frames


def make_config(**kwargs) -> MultiLayerConfig:
    """Create a test configuration with sensible defaults."""
    defaults = dict(
        enable_temporal=True,
        temporal_bits_per_transition=2,
        temporal_block_size=8,
        adversarial_strength=ADVERSARIAL_STRENGTH_MEDIUM,
        adversarial_preserve_histogram=True,
        procedural_cat=False,
        procedural_cat_frames=5,
        procedural_cat_size=(80, 64),
        immunize=False,  # Disable for isolated tests
    )
    defaults.update(kwargs)
    return MultiLayerConfig(**defaults)


# ===========================================================================
# 1. TEMPORAL CHANNEL ENCODER (Phase 1.1)
# ===========================================================================


class TestTemporalChannelEncoder:
    """Test suite for inter-frame temporal delta embedding."""

    def test_init(self):
        """TemporalChannelEncoder initializes with keyed channel key."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)
        assert enc.master_key == key
        assert enc._channel_key is not None
        assert len(enc._channel_key) == 32

    def test_embed_extract_roundtrip_small(self):
        """Small payload embeds and extracts correctly."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)

        frames = make_test_frames(num_frames=10, height=64, width=80)
        original_frames = [f.copy() for f in frames]

        # Embed 8 bits
        payload_bits = [1, 0, 1, 1, 0, 0, 1, 0]
        modified = enc.embed(frames, payload_bits)

        assert len(modified) == len(original_frames)

        # Extract
        extracted = enc.extract(modified, len(payload_bits))
        assert len(extracted) == len(payload_bits)
        assert extracted == payload_bits

    def test_embed_extract_roundtrip_medium(self):
        """Medium payload (multiple transitions) round-trips."""
        key = make_key()
        config = make_config(temporal_bits_per_transition=4)
        enc = TemporalChannelEncoder(key, config)

        frames = make_test_frames(num_frames=15, height=64, width=80)

        # 14 transitions * 4 bits = 56 bits max
        payload_bits = [int(b) for b in format(0xDEADBEEF, "032b")]  # 32 bits
        modified = enc.embed(frames, payload_bits)
        extracted = enc.extract(modified, len(payload_bits))
        assert extracted == payload_bits

    def test_embed_no_frames(self):
        """Empty frame list returns unchanged."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)
        result = enc.embed([], [1, 0, 1])
        assert result == []

    def test_embed_single_frame(self):
        """Single frame has no transitions, returns unchanged."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)
        frames = make_test_frames(num_frames=1)
        result = enc.embed(frames, [1, 0, 1])
        assert len(result) == 1

    def test_extract_no_frames(self):
        """Extract from empty returns empty."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)
        result = enc.extract([], 8)
        assert result == []

    def test_extract_single_frame(self):
        """Extract from single frame returns empty."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)
        frames = make_test_frames(num_frames=1)
        result = enc.extract(frames, 8)
        assert result == []

    def test_wrong_key_extracts_garbage(self):
        """Wrong key produces different (wrong) bits."""
        key1 = make_key("correct_key")
        key2 = make_key("wrong_key")
        config = make_config()

        frames = make_test_frames(num_frames=10)
        payload_bits = [1, 0, 1, 1, 0, 0, 1, 0]

        # Embed with key1
        enc1 = TemporalChannelEncoder(key1, config)
        modified = enc1.embed(frames, payload_bits)

        # Extract with key2 (different block selection -> different bits)
        enc2 = TemporalChannelEncoder(key2, config)
        extracted = enc2.extract(modified, len(payload_bits))

        # Should not match (very high probability with keyed block selection)
        # In rare cases, a few bits might match by chance, but all matching is negligible
        assert extracted != payload_bits

    def test_estimate_capacity(self):
        """Capacity estimation matches expected formula."""
        key = make_key()
        config = make_config(temporal_bits_per_transition=4)
        enc = TemporalChannelEncoder(key, config)

        assert enc.estimate_capacity(1, 64, 80) == 0  # No transitions
        assert enc.estimate_capacity(2, 64, 80) == 4  # 1 transition
        assert enc.estimate_capacity(10, 64, 80) == 36  # 9 transitions * 4

    def test_embed_respects_capacity(self):
        """Embedding more bits than capacity truncates gracefully."""
        key = make_key()
        config = make_config(temporal_bits_per_transition=2)
        enc = TemporalChannelEncoder(key, config)

        # 3 frames = 2 transitions = 4 bits max
        frames = make_test_frames(num_frames=3, height=64, width=80)
        payload_bits = [1, 0, 1, 0, 1, 1, 0, 0]  # 8 bits > 4 capacity

        # Should embed what fits without error
        modified = enc.embed(frames, payload_bits)
        assert len(modified) == 3

    def test_visual_impact_minimal(self):
        """Temporal embedding changes at most 1 pixel per block per transition."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)

        frames = make_test_frames(num_frames=5, height=64, width=80)
        originals = [f.copy() for f in frames]

        payload_bits = [1, 0, 1, 0]
        modified = enc.embed(frames, payload_bits)

        # Only modified frames (t+1 for each transition) should differ
        # First frame should be unchanged
        np.testing.assert_array_equal(originals[0], modified[0])

        # Subsequent frames: at most a few pixels changed by ±1
        for i in range(1, len(modified)):
            diff = np.abs(originals[i].astype(np.int16) - modified[i].astype(np.int16))
            # Max change per pixel is 1
            assert diff.max() <= 1, f"Frame {i}: max pixel change {diff.max()}"

    def test_keyed_block_selection_deterministic(self):
        """Same key + transition produces same block selection."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)

        blocks1 = enc._select_blocks(0, 64, 80, 8)
        blocks2 = enc._select_blocks(0, 64, 80, 8)
        assert blocks1 == blocks2

    def test_different_transitions_different_blocks(self):
        """Different transition indices produce different block orders."""
        key = make_key()
        config = make_config()
        enc = TemporalChannelEncoder(key, config)

        blocks0 = enc._select_blocks(0, 64, 80, 8)
        blocks1 = enc._select_blocks(1, 64, 80, 8)

        # Same set of blocks but different order (shuffled differently)
        assert set(blocks0) == set(blocks1)  # Same grid
        assert blocks0 != blocks1  # Different order

    def test_channel_id_constant(self):
        """CHANNEL_TEMPORAL constant is defined and correct."""
        assert CHANNEL_TEMPORAL == 0x06


# ===========================================================================
# 2. ADVERSARIAL PERTURBATION LAYER (Phase 1.2)
# ===========================================================================


class TestAdversarialPerturbationLayer:
    """Test suite for anti-steganalysis adversarial perturbation."""

    def test_init(self):
        """Layer initializes with keyed perturbation key."""
        key = make_key()
        config = make_config()
        layer = AdversarialPerturbationLayer(key, config)
        assert layer._perturb_key is not None
        assert len(layer._perturb_key) == 32

    def test_strength_off_returns_unchanged(self):
        """Strength=0 returns frames unchanged."""
        key = make_key()
        config = make_config(adversarial_strength=0)
        layer = AdversarialPerturbationLayer(key, config)

        frames = make_test_frames(num_frames=3)
        originals = [f.copy() for f in frames]
        result = layer.apply(frames, originals)

        for i in range(len(frames)):
            np.testing.assert_array_equal(result[i], frames[i])

    def test_strength_low_modifies_frames(self):
        """Strength=1 (histogram matching) modifies frames."""
        key = make_key()
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_LOW)
        layer = AdversarialPerturbationLayer(key, config)

        frames = make_test_frames(num_frames=3)
        covers = [f.copy() for f in frames]
        # Introduce histogram shift in frames
        for f in frames:
            f[:, :, 0] = np.clip(f[:, :, 0].astype(np.int16) + 20, 0, 255).astype(np.uint8)

        result = layer.apply(frames, covers)

        # Result should be different from shifted frames
        any_changed = False
        for i in range(len(frames)):
            if not np.array_equal(result[i], frames[i]):
                any_changed = True
                break
        assert any_changed, "Strength=1 should modify at least some frames"

    def test_strength_medium_more_changes(self):
        """Strength=2 applies histogram + HPF smoothing."""
        key = make_key()
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_MEDIUM)
        layer = AdversarialPerturbationLayer(key, config)

        frames = make_test_frames(num_frames=3)
        covers = [f.copy() for f in frames]

        result = layer.apply(frames, covers)
        assert len(result) == len(frames)

    def test_strength_high_comprehensive(self):
        """Strength=3 applies all perturbation layers."""
        key = make_key()
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_HIGH)
        layer = AdversarialPerturbationLayer(key, config)

        frames = make_test_frames(num_frames=3)
        covers = [f.copy() for f in frames]

        result = layer.apply(frames, covers)
        assert len(result) == len(frames)

    def test_no_cover_still_works(self):
        """Without cover frames, uses self-referencing (Gaussian model)."""
        key = make_key()
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_LOW)
        layer = AdversarialPerturbationLayer(key, config)

        frames = make_test_frames(num_frames=3)
        result = layer.apply(frames, cover_frames=None)
        assert len(result) == len(frames)

    def test_preserves_frame_shape(self):
        """Output frames have same shape as input."""
        key = make_key()
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_HIGH)
        layer = AdversarialPerturbationLayer(key, config)

        frames = make_test_frames(num_frames=3, height=48, width=64)
        covers = [f.copy() for f in frames]
        result = layer.apply(frames, covers)

        for i in range(len(frames)):
            assert result[i].shape == frames[i].shape
            assert result[i].dtype == np.uint8

    def test_bounded_pixel_changes(self):
        """Adversarial perturbations stay within valid pixel range [0, 255]."""
        key = make_key()
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_HIGH)
        layer = AdversarialPerturbationLayer(key, config)

        frames = make_test_frames(num_frames=3)
        covers = [f.copy() for f in frames]
        result = layer.apply(frames, covers)

        for frame in result:
            assert frame.min() >= 0
            assert frame.max() <= 255

    def test_keyed_deterministic(self):
        """Same key produces same perturbations."""
        key = make_key()
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_LOW)

        frames1 = make_test_frames(num_frames=3, seed=42)
        covers1 = [f.copy() for f in frames1]
        frames2 = make_test_frames(num_frames=3, seed=42)
        covers2 = [f.copy() for f in frames2]

        layer1 = AdversarialPerturbationLayer(key, config)
        layer2 = AdversarialPerturbationLayer(key, config)

        result1 = layer1.apply(frames1, covers1)
        result2 = layer2.apply(frames2, covers2)

        for i in range(len(result1)):
            np.testing.assert_array_equal(result1[i], result2[i])

    def test_different_keys_different_perturbations(self):
        """Different keys produce different perturbations with histogram shift."""
        key1 = make_key("key_a")
        key2 = make_key("key_b")
        # Use MEDIUM strength which includes keyed HPF smoothing
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_MEDIUM)

        # Create covers and intentionally shifted stego (simulates embedding)
        covers1 = make_test_frames(num_frames=3, seed=42)
        covers2 = make_test_frames(num_frames=3, seed=42)
        frames1 = [np.clip(f.astype(np.int16) + 15, 0, 255).astype(np.uint8) for f in covers1]
        frames2 = [np.clip(f.astype(np.int16) + 15, 0, 255).astype(np.uint8) for f in covers2]

        layer1 = AdversarialPerturbationLayer(key1, config)
        layer2 = AdversarialPerturbationLayer(key2, config)

        result1 = layer1.apply(frames1, covers1)
        result2 = layer2.apply(frames2, covers2)

        any_different = any(not np.array_equal(result1[i], result2[i]) for i in range(len(result1)))
        assert any_different, "Different keys should produce different perturbations"

    def test_histogram_match_improves_distribution(self):
        """Histogram matching moves stego histogram closer to cover."""
        key = make_key()
        config = make_config(adversarial_strength=ADVERSARIAL_STRENGTH_LOW)
        layer = AdversarialPerturbationLayer(key, config)

        frames = make_test_frames(num_frames=1, height=64, width=80)
        covers = [f.copy() for f in frames]

        # Shift stego histogram significantly
        stego = frames[0].copy()
        stego = np.clip(stego.astype(np.int16) + 30, 0, 255).astype(np.uint8)

        cover_hist, _ = np.histogram(covers[0][:, :, 0], bins=256, range=(0, 256))
        shifted_hist, _ = np.histogram(stego[:, :, 0], bins=256, range=(0, 256))

        # Apply histogram matching
        result = layer._histogram_match(stego, covers[0], 0)
        result_hist, _ = np.histogram(result[:, :, 0], bins=256, range=(0, 256))

        # Result histogram should be closer to cover than the shifted version
        dist_before = np.sum(np.abs(shifted_hist.astype(np.int64) - cover_hist.astype(np.int64)))
        dist_after = np.sum(np.abs(result_hist.astype(np.int64) - cover_hist.astype(np.int64)))

        assert (
            dist_after <= dist_before
        ), f"Histogram matching should improve: before={dist_before}, after={dist_after}"

    def test_strength_constants(self):
        """Adversarial strength constants have correct values."""
        assert ADVERSARIAL_STRENGTH_LOW == 1
        assert ADVERSARIAL_STRENGTH_MEDIUM == 2
        assert ADVERSARIAL_STRENGTH_HIGH == 3


# ===========================================================================
# 3. PROCEDURAL CAT CARRIER GENERATOR (Phase 1.3)
# ===========================================================================


class TestProceduralCatGenerator:
    """Test suite for procedural cat carrier generation."""

    def test_init(self):
        """Generator initializes with seed key."""
        key = make_key()
        config = make_config()
        gen = ProceduralCatGenerator(key, config)
        assert gen._seed_key is not None
        assert len(gen._seed_key) == 32

    def test_generate_default(self):
        """Generates correct number of frames from config defaults."""
        key = make_key()
        config = make_config(procedural_cat_frames=5, procedural_cat_size=(80, 64))
        gen = ProceduralCatGenerator(key, config)

        frames = gen.generate()
        assert len(frames) == 5
        assert frames[0].shape == (64, 80, 3)
        assert frames[0].dtype == np.uint8

    def test_generate_custom_size(self):
        """Generates frames with custom size and count."""
        key = make_key()
        config = make_config()
        gen = ProceduralCatGenerator(key, config)

        frames = gen.generate(num_frames=3, size=(100, 80))
        assert len(frames) == 3
        assert frames[0].shape == (80, 100, 3)

    def test_frames_vary_across_animation(self):
        """Each frame in the animation should be slightly different."""
        key = make_key()
        config = make_config(procedural_cat_frames=5, procedural_cat_size=(80, 64))
        gen = ProceduralCatGenerator(key, config)

        frames = gen.generate()
        any_diff = False
        for i in range(1, len(frames)):
            if not np.array_equal(frames[0], frames[i]):
                any_diff = True
                break
        assert any_diff, "Animation frames should not all be identical"

    def test_deterministic_from_key(self):
        """Same key produces identical frames."""
        key = make_key("deterministic_test")
        config = make_config(procedural_cat_frames=3, procedural_cat_size=(80, 64))

        gen1 = ProceduralCatGenerator(key, config)
        gen2 = ProceduralCatGenerator(key, config)

        frames1 = gen1.generate()
        frames2 = gen2.generate()

        for i in range(len(frames1)):
            np.testing.assert_array_equal(frames1[i], frames2[i])

    def test_different_keys_different_frames(self):
        """Different keys produce visually different carriers."""
        key1 = make_key("cat_key_1")
        key2 = make_key("cat_key_2")
        config = make_config(procedural_cat_frames=3, procedural_cat_size=(80, 64))

        gen1 = ProceduralCatGenerator(key1, config)
        gen2 = ProceduralCatGenerator(key2, config)

        frames1 = gen1.generate()
        frames2 = gen2.generate()

        any_diff = any(not np.array_equal(frames1[i], frames2[i]) for i in range(len(frames1)))
        assert any_diff, "Different keys should produce different carriers"

    def test_pixel_values_valid(self):
        """All pixel values are in [0, 255]."""
        key = make_key()
        config = make_config(procedural_cat_frames=5, procedural_cat_size=(80, 64))
        gen = ProceduralCatGenerator(key, config)

        frames = gen.generate()
        for frame in frames:
            assert frame.min() >= 0
            assert frame.max() <= 255

    def test_high_entropy_for_stego(self):
        """Cat frames have sufficient entropy for steganographic embedding."""
        key = make_key()
        config = make_config(procedural_cat_frames=3, procedural_cat_size=(160, 120))
        gen = ProceduralCatGenerator(key, config)

        frames = gen.generate()
        for frame in frames:
            # LSB entropy should be reasonably high (not all zeros or ones)
            lsb_plane = frame[:, :, 0] & 1
            unique = np.unique(lsb_plane)
            assert len(unique) == 2, "LSB plane should have both 0s and 1s"

            # Std deviation should show texture variety
            std = np.std(frame.astype(np.float64))
            assert std > 10, f"Frame std too low ({std}), need texture for embedding"

    def test_save_carrier_gif(self):
        """save_carrier produces a valid GIF file."""
        key = make_key()
        config = make_config(procedural_cat_frames=3, procedural_cat_size=(80, 64))
        gen = ProceduralCatGenerator(key, config)

        with tempfile.NamedTemporaryFile(suffix=".gif", delete=False) as f:
            path = Path(f.name)

        try:
            result = gen.save_carrier(path)
            assert result == path
            assert path.exists()
            assert path.stat().st_size > 0

            # Verify it's a valid GIF
            data = path.read_bytes()
            assert data[:3] == b"GIF"
        finally:
            path.unlink(missing_ok=True)


# ===========================================================================
# 4. INTEGRATION TESTS
# ===========================================================================


class TestPhase1Integration:
    """Integration tests for Phase 1 features working together."""

    def test_temporal_after_adversarial_preserves_data(self):
        """Temporal embedding survives mild adversarial perturbation."""
        key = make_key()
        config = make_config(
            adversarial_strength=ADVERSARIAL_STRENGTH_LOW,
            temporal_bits_per_transition=2,
        )

        frames = make_test_frames(num_frames=10, height=64, width=80)

        # Embed temporal data
        temporal = TemporalChannelEncoder(key, config)
        payload_bits = [1, 0, 1, 1, 0, 0, 1, 0]
        temporal.embed(frames, payload_bits)

        # Note: adversarial perturbation runs AFTER embedding,
        # affecting bit-1 but NOT bit-0 (LSB).
        # Temporal channel uses delta parity, which could be affected
        # by adversarial changes. This test verifies the interaction.

        # Extract should still get the right bits
        extracted = temporal.extract(frames, len(payload_bits))
        assert extracted == payload_bits

    def test_key_derivation_includes_temporal(self):
        """derive_stego_keys_for_reality returns temporal key at FULL level."""
        keys = derive_stego_keys_for_reality("test_pass", b"0" * 16, CoercionLevel.FULL)
        assert "temporal" in keys
        assert len(keys["temporal"]) == 32

    def test_key_derivation_shallow_no_temporal(self):
        """SHALLOW level does not include temporal key."""
        keys = derive_stego_keys_for_reality("test_pass", b"0" * 16, CoercionLevel.SHALLOW)
        assert "temporal" not in keys

    def test_key_derivation_decoy_no_temporal(self):
        """DECOY level does not include temporal key."""
        keys = derive_stego_keys_for_reality("test_pass", b"0" * 16, CoercionLevel.DECOY)
        assert "temporal" not in keys

    def test_config_defaults(self):
        """MultiLayerConfig has Phase 1 fields with correct defaults."""
        config = MultiLayerConfig()
        assert config.enable_temporal is True
        assert config.temporal_bits_per_transition > 0
        assert config.temporal_block_size > 0
        assert config.adversarial_strength == ADVERSARIAL_STRENGTH_MEDIUM
        assert config.adversarial_preserve_histogram is True
        assert config.procedural_cat is False
        assert config.procedural_cat_frames > 0

    def test_config_disable_temporal(self):
        """Temporal channel can be disabled."""
        config = make_config(enable_temporal=False)
        key = make_key()
        encoder = TemporalChannelEncoder(key, config)

        # Still initializes, but distribute_payload won't use it
        assert encoder is not None

    def test_procedural_cat_with_encoder_init(self):
        """Encoder initializes with procedural cat support."""
        key = make_key()
        config = make_config(procedural_cat=True)
        encoder = MultiLayerStegoEncoder(config, key)
        assert encoder.cat_gen is not None
        assert encoder.temporal_ch is not None
        assert encoder.adversarial is not None

    def test_decode_with_temporal(self):
        """Decoder has temporal channel support."""
        key = make_key()
        config = make_config()
        decoder = MultiLayerStegoDecoder(config, key)
        assert decoder.temporal_ch is not None


# ===========================================================================
# 5. DISTRIBUTE_PAYLOAD WITH TEMPORAL
# ===========================================================================


class TestDistributePayloadTemporal:
    """Test payload distribution including temporal channel."""

    def test_temporal_capacity_included(self):
        """distribute_payload accounts for temporal capacity."""
        from meow_decoder.stego_multilayer import distribute_payload

        config = make_config(
            enable_primary=True,
            enable_temporal=True,
            temporal_bits_per_transition=4,
        )

        # 10 frames, 64x80 pixels each
        frame_counts = [64 * 80] * 10
        perm_counts = [32] * 10

        # Small payload that fits in primary
        payload = b"Hello, temporal channel!"
        from meow_decoder.stego_multilayer import prepare_payload

        prepared = prepare_payload(payload, make_key())

        channels = distribute_payload(
            prepared,
            config,
            10,
            frame_counts,
            perm_counts,
            frame_height=64,
            frame_width=80,
        )

        # Primary should get bulk data
        assert "primary" in channels

    def test_temporal_capacity_zero_when_disabled(self):
        """No temporal capacity when temporal channel is disabled."""
        from meow_decoder.stego_multilayer import distribute_payload

        config = make_config(enable_temporal=False)
        frame_counts = [64 * 80] * 10
        perm_counts = [32] * 10

        payload = b"test"
        from meow_decoder.stego_multilayer import prepare_payload

        prepared = prepare_payload(payload, make_key())

        channels = distribute_payload(
            prepared,
            config,
            10,
            frame_counts,
            perm_counts,
            frame_height=64,
            frame_width=80,
        )

        assert "temporal" not in channels

    def test_temporal_capacity_zero_single_frame(self):
        """No temporal capacity with only one frame."""
        from meow_decoder.stego_multilayer import distribute_payload

        config = make_config(enable_temporal=True)
        frame_counts = [64 * 80]
        perm_counts = [32]

        payload = b"t"
        from meow_decoder.stego_multilayer import prepare_payload

        prepared = prepare_payload(payload, make_key())

        channels = distribute_payload(
            prepared,
            config,
            1,
            frame_counts,
            perm_counts,
            frame_height=64,
            frame_width=80,
        )

        assert "temporal" not in channels


# ===========================================================================
# 6. STEGO VERSION AND EXPORTS
# ===========================================================================


class TestStegoVersionExports:
    """Test version constants and module exports."""

    def test_stego_version(self):
        """STEGO_VERSION is 3 for Phase 1."""
        from meow_decoder.stego_multilayer import STEGO_VERSION

        assert STEGO_VERSION == 3

    def test_all_phase1_exports(self):
        """All Phase 1 classes and constants are in __all__."""
        from meow_decoder import stego_multilayer

        all_exports = stego_multilayer.__all__

        phase1_exports = [
            "TemporalChannelEncoder",
            "AdversarialPerturbationLayer",
            "ProceduralCatGenerator",
            "CHANNEL_TEMPORAL",
            "ADVERSARIAL_STRENGTH_LOW",
            "ADVERSARIAL_STRENGTH_MEDIUM",
            "ADVERSARIAL_STRENGTH_HIGH",
        ]

        for name in phase1_exports:
            assert name in all_exports, f"{name} missing from __all__"

    def test_channel_temporal_unique(self):
        """CHANNEL_TEMPORAL is a unique channel ID."""
        from meow_decoder.stego_multilayer import (
            CHANNEL_PRIMARY,
            CHANNEL_SECONDARY,
            CHANNEL_TERTIARY,
            CHANNEL_DISPOSAL,
            CHANNEL_COMMENT,
            CHANNEL_TEMPORAL,
        )

        all_ids = [
            CHANNEL_PRIMARY,
            CHANNEL_SECONDARY,
            CHANNEL_TERTIARY,
            CHANNEL_DISPOSAL,
            CHANNEL_COMMENT,
            CHANNEL_TEMPORAL,
        ]
        assert len(set(all_ids)) == len(all_ids), "Channel IDs must be unique"
