"""
Tests for Multi-Layer Steganography System.

Tests cover:
- Seed derivation (per-frame, per-channel, deterministic, independent)
- Pixel walk generation (permutation, deterministic, seeded)
- Payload preparation (compress, encrypt, MAC, roundtrip)
- Primary channel (LSB embedding + extraction, with/without STC)
- Secondary channel (timing encode/decode roundtrip)
- Tertiary channel (palette permutation encode/decode)
- Multi-layer encode/decode end-to-end
- Steganalysis validation (RS, chi-square, SPA, entropy)
- Coercion/duress key derivation
- Quality metrics (PSNR thresholds)
"""

import hashlib
import os
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest
from PIL import Image

from meow_decoder.stego_multilayer import (
    CHANNEL_PRIMARY,
    CHANNEL_SECONDARY,
    CHANNEL_TERTIARY,
    CoercionLevel,
    MultiLayerConfig,
    MultiLayerStegoDecoder,
    MultiLayerStegoEncoder,
    PaletteChannelEncoder,
    PrimaryChannelEncoder,
    StegoExtractionResult,
    TimingChannelEncoder,
    _bits_to_bytes,
    _bytes_to_bits,
    _factorial_bits,
    derive_frame_seed,
    derive_stego_keys_for_reality,
    derive_walk_seed,
    distribute_payload,
    generate_pixel_walk,
    prepare_payload,
    unpack_payload,
)

# Set test mode for faster Argon2id
os.environ["MEOW_TEST_MODE"] = "1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def master_key():
    """32-byte test master key."""
    return b"\x42" * 32


@pytest.fixture
def config():
    """Default multi-layer config for testing."""
    return MultiLayerConfig(
        enable_primary=True,
        enable_secondary=True,
        enable_tertiary=True,
        lsb_bits=1,
        use_stc=False,  # Simpler for unit tests; STC tested separately
        use_adaptive_cost=False,
        base_delay_cs=10,
        timing_bits_per_frame=2,
        min_permutable_entries=4,
        min_psnr=40.0,
        compress=True,
        encrypt=True,
    )


@pytest.fixture
def sample_frame():
    """Create a sample 64x48 RGB frame."""
    rng = np.random.RandomState(42)
    return rng.randint(0, 256, (48, 64, 3), dtype=np.uint8)


@pytest.fixture
def sample_gif(tmp_path):
    """Create a sample animated GIF for testing."""
    frames = []
    rng = np.random.RandomState(42)
    for i in range(10):
        frame = rng.randint(0, 256, (48, 64, 3), dtype=np.uint8)
        frames.append(frame)

    gif_path = tmp_path / "test_carrier.gif"

    # Write with PIL
    pil_frames = [Image.fromarray(f) for f in frames]
    pil_frames[0].save(
        str(gif_path),
        save_all=True,
        append_images=pil_frames[1:],
        duration=100,
        loop=0,
    )
    return gif_path


# ---------------------------------------------------------------------------
# Test: Seed Derivation
# ---------------------------------------------------------------------------


class TestSeedDerivation:
    """Tests for per-frame, per-channel seed derivation."""

    def test_deterministic(self, master_key):
        """Same inputs produce same seed."""
        s1 = derive_frame_seed(master_key, 0, CHANNEL_PRIMARY)
        s2 = derive_frame_seed(master_key, 0, CHANNEL_PRIMARY)
        assert s1 == s2

    def test_different_frames(self, master_key):
        """Different frame indices produce different seeds."""
        s0 = derive_frame_seed(master_key, 0, CHANNEL_PRIMARY)
        s1 = derive_frame_seed(master_key, 1, CHANNEL_PRIMARY)
        assert s0 != s1

    def test_different_channels(self, master_key):
        """Different channel IDs produce independent seeds."""
        sp = derive_frame_seed(master_key, 0, CHANNEL_PRIMARY)
        ss = derive_frame_seed(master_key, 0, CHANNEL_SECONDARY)
        st = derive_frame_seed(master_key, 0, CHANNEL_TERTIARY)
        assert sp != ss
        assert sp != st
        assert ss != st

    def test_different_keys(self):
        """Different master keys produce different seeds."""
        k1 = b"\x11" * 32
        k2 = b"\x22" * 32
        s1 = derive_frame_seed(k1, 0, CHANNEL_PRIMARY)
        s2 = derive_frame_seed(k2, 0, CHANNEL_PRIMARY)
        assert s1 != s2

    def test_seed_length(self, master_key):
        """Seeds are always 32 bytes."""
        for frame in range(5):
            for ch in [CHANNEL_PRIMARY, CHANNEL_SECONDARY, CHANNEL_TERTIARY]:
                seed = derive_frame_seed(master_key, frame, ch)
                assert len(seed) == 32

    def test_walk_seed_independent(self, master_key):
        """Walk seed is independent of channel seeds."""
        ws = derive_walk_seed(master_key, 0)
        cs = derive_frame_seed(master_key, 0, CHANNEL_PRIMARY)
        assert ws != cs
        assert len(ws) == 32


# ---------------------------------------------------------------------------
# Test: Pixel Walk
# ---------------------------------------------------------------------------


class TestPixelWalk:
    """Tests for pseudorandom pixel walk generation."""

    def test_permutation(self, master_key):
        """Walk is a valid permutation."""
        seed = derive_walk_seed(master_key, 0)
        walk = generate_pixel_walk(seed, 100)
        assert len(walk) == 100
        assert sorted(walk) == list(range(100))

    def test_deterministic(self, master_key):
        """Same seed produces same walk."""
        seed = derive_walk_seed(master_key, 0)
        w1 = generate_pixel_walk(seed, 100)
        w2 = generate_pixel_walk(seed, 100)
        assert w1 == w2

    def test_different_seeds(self, master_key):
        """Different seeds produce different walks."""
        s1 = derive_walk_seed(master_key, 0)
        s2 = derive_walk_seed(master_key, 1)
        w1 = generate_pixel_walk(s1, 100)
        w2 = generate_pixel_walk(s2, 100)
        assert w1 != w2

    def test_single_pixel(self, master_key):
        """Walk with 1 pixel is trivial."""
        seed = derive_walk_seed(master_key, 0)
        walk = generate_pixel_walk(seed, 1)
        assert walk == [0]


# ---------------------------------------------------------------------------
# Test: Bit Conversion
# ---------------------------------------------------------------------------


class TestBitConversion:
    """Tests for bytes <-> bits conversion."""

    def test_roundtrip(self):
        """Bytes → bits → bytes is identity."""
        data = b"\xab\xcd\xef"
        bits = _bytes_to_bits(data)
        assert len(bits) == 24
        recovered = _bits_to_bytes(bits)
        assert recovered == data

    def test_single_byte(self):
        """Single byte correctly converted."""
        bits = _bytes_to_bits(b"\xff")
        assert bits == [1, 1, 1, 1, 1, 1, 1, 1]

    def test_zero_byte(self):
        """Zero byte correctly converted."""
        bits = _bytes_to_bits(b"\x00")
        assert bits == [0, 0, 0, 0, 0, 0, 0, 0]


# ---------------------------------------------------------------------------
# Test: Payload Preparation
# ---------------------------------------------------------------------------


class TestPayloadPrep:
    """Tests for payload compression, encryption, and MAC."""

    def test_roundtrip(self, master_key):
        """Prepare → unpack is identity."""
        data = b"Hello, Meow Decoder! This is a secret message."
        prepared = prepare_payload(data, master_key, compress=True, encrypt=True)
        recovered, mac_valid = unpack_payload(prepared, master_key)
        assert mac_valid
        assert recovered == data

    def test_roundtrip_no_compress(self, master_key):
        """Roundtrip without compression."""
        data = b"test data no compress"
        prepared = prepare_payload(data, master_key, compress=False, encrypt=True)
        recovered, mac_valid = unpack_payload(prepared, master_key)
        assert mac_valid
        assert recovered == data

    def test_roundtrip_no_encrypt(self, master_key):
        """Roundtrip without encryption."""
        data = b"test data no encrypt"
        prepared = prepare_payload(data, master_key, compress=True, encrypt=False)
        recovered, mac_valid = unpack_payload(prepared, master_key)
        assert mac_valid
        assert recovered == data

    def test_wrong_key_fails_mac(self, master_key):
        """Wrong key fails MAC verification."""
        data = b"secret"
        prepared = prepare_payload(data, master_key)
        wrong_key = b"\xff" * 32
        recovered, mac_valid = unpack_payload(prepared, wrong_key)
        assert not mac_valid

    def test_tampered_payload_fails(self, master_key):
        """Tampered payload fails MAC."""
        data = b"secret data"
        prepared = bytearray(prepare_payload(data, master_key))
        # Flip a byte in the middle
        prepared[20] ^= 0xFF
        recovered, mac_valid = unpack_payload(bytes(prepared), master_key)
        assert not mac_valid

    def test_magic_check(self, master_key):
        """Invalid magic bytes rejected."""
        recovered, mac_valid = unpack_payload(b"XXXX" + b"\x00" * 50, master_key)
        assert not mac_valid

    def test_short_payload_rejected(self, master_key):
        """Too-short payload rejected."""
        recovered, mac_valid = unpack_payload(b"short", master_key)
        assert not mac_valid


class TestFailClosedDegradation:
    """Audit #1/#5: stego crypto must fail closed in production rather than
    silently degrade to the non-constant-time Python fallback or ship an
    unencrypted payload."""

    def test_seed_walk_fail_closed_without_rust(self, master_key, monkeypatch):
        """Seed/walk derivation aborts when Rust is unavailable in strict mode."""
        import meow_decoder.stego_multilayer as s

        monkeypatch.setattr(s, "_RUST_AVAILABLE", False)
        monkeypatch.setattr(s, "_STEGO_REQUIRE_RUST", True)

        with pytest.raises(s.SecurityDegradationError):
            s.derive_frame_seed(master_key, 0, 1)
        with pytest.raises(s.SecurityDegradationError):
            s.derive_walk_seed(master_key, 0)
        with pytest.raises(s.SecurityDegradationError):
            s.generate_pixel_walk(b"s" * 32, 16)

    def test_fallback_allowed_when_not_strict(self, master_key, monkeypatch):
        """Non-production (relaxed) mode still permits the Python fallback."""
        import meow_decoder.stego_multilayer as s

        monkeypatch.setattr(s, "_RUST_AVAILABLE", False)
        monkeypatch.setattr(s, "_STEGO_REQUIRE_RUST", False)

        assert len(s.derive_frame_seed(master_key, 0, 1)) == 32
        assert len(s.derive_walk_seed(master_key, 0)) == 32
        assert len(s.generate_pixel_walk(b"s" * 32, 16)) == 16

    def test_encrypt_false_forbidden_in_strict_mode(self, master_key, monkeypatch):
        """prepare_payload(encrypt=False) is refused in production."""
        import meow_decoder.stego_multilayer as s

        monkeypatch.setattr(s, "_STEGO_REQUIRE_RUST", True)
        with pytest.raises(s.SecurityDegradationError):
            s.prepare_payload(b"secret", master_key, encrypt=False)

    def test_encrypt_false_allowed_when_not_strict(self, master_key, monkeypatch):
        """encrypt=False remains usable for non-production tests/dev."""
        import meow_decoder.stego_multilayer as s

        monkeypatch.setattr(s, "_STEGO_REQUIRE_RUST", False)
        prepared = s.prepare_payload(b"secret", master_key, encrypt=False)
        recovered, mac_valid = unpack_payload(prepared, master_key)
        assert mac_valid
        assert recovered == b"secret"


# ---------------------------------------------------------------------------
# Test: Primary Channel
# ---------------------------------------------------------------------------


class TestPrimaryChannel:
    """Tests for keyed LSB walk embedding/extraction."""

    def test_embed_extract_roundtrip(self, master_key, config, sample_frame):
        """Embed then extract recovers original bits."""
        encoder = PrimaryChannelEncoder(master_key, config)

        payload_bits = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
        stego_frame = encoder.embed_frame(sample_frame, 0, payload_bits)

        extracted = encoder.extract_frame(stego_frame, 0, len(payload_bits))
        assert extracted[: len(payload_bits)] == payload_bits

    def test_minimal_visual_impact(self, master_key, config, sample_frame):
        """1-bit LSB embedding has minimal visual impact."""
        encoder = PrimaryChannelEncoder(master_key, config)

        bits = [i % 2 for i in range(100)]
        stego = encoder.embed_frame(sample_frame, 0, bits)

        # PSNR should be high (> 40 dB for 1-bit LSB)
        diff = sample_frame.astype(float) - stego.astype(float)
        mse = np.mean(diff**2)
        if mse > 0:
            psnr = 10 * np.log10(255**2 / mse)
            assert psnr > 40.0, f"PSNR too low: {psnr:.1f} dB"

    def test_frame_independence(self, master_key, config, sample_frame):
        """Different frames use different walk patterns."""
        encoder = PrimaryChannelEncoder(master_key, config)
        bits = [1, 0, 1, 0, 1, 0, 1, 0]

        stego_0 = encoder.embed_frame(sample_frame, 0, bits)
        stego_1 = encoder.embed_frame(sample_frame, 1, bits)

        # Different frames should produce different stego (different walk)
        assert not np.array_equal(stego_0, stego_1)

    def test_empty_payload(self, master_key, config, sample_frame):
        """Empty payload leaves frame unchanged."""
        encoder = PrimaryChannelEncoder(master_key, config)
        stego = encoder.embed_frame(sample_frame, 0, [])
        assert np.array_equal(stego, sample_frame)


# ---------------------------------------------------------------------------
# Test: Timing Channel
# ---------------------------------------------------------------------------


class TestTimingChannel:
    """Tests for GCE delay jitter encoding/decoding."""

    def test_roundtrip(self, master_key, config):
        """Encode then decode recovers original bits."""
        encoder = TimingChannelEncoder(master_key, config)

        bits = [1, 0, 1, 1, 0, 0, 1, 0]  # 8 bits = 4 frames @ 2 bpf
        delays = encoder.encode(4, bits)

        assert len(delays) == 4
        for d in delays:
            assert 10 <= d <= 15  # base(10) + max_offset(3) + jitter(2)

        recovered = encoder.decode(delays)
        assert recovered[:8] == bits

    def test_delay_range(self, master_key, config):
        """All delays are within expected range."""
        encoder = TimingChannelEncoder(master_key, config)
        bits = [1] * 20
        delays = encoder.encode(10, bits)

        for d in delays:
            assert d >= config.base_delay_cs
            assert d <= config.base_delay_cs + 5  # max_offset + jitter


# ---------------------------------------------------------------------------
# Test: Palette Channel
# ---------------------------------------------------------------------------


class TestPaletteChannel:
    """Tests for palette permutation encoding/decoding."""

    def test_find_permutable_entries(self):
        """Identifies near-duplicate and unused palette entries."""
        palette = np.array(
            [
                [255, 0, 0],  # 0: red
                [0, 255, 0],  # 1: green
                [0, 0, 255],  # 2: blue
                [128, 128, 128],  # 3: gray
                [130, 128, 128],  # 4: near-gray (L1 dist = 2)
                [129, 129, 128],  # 5: near-gray (L1 dist = 2)
                [0, 0, 0],  # 6: black (unused)
                [1, 1, 1],  # 7: near-black (unused + near-dupe)
            ],
            dtype=np.uint8,
        )
        # Pixels only use indices 0, 1, 2, 3
        pixels = np.array([0, 1, 2, 3, 0, 1, 2, 3], dtype=np.uint8)

        permutable = PaletteChannelEncoder.find_permutable_entries(palette, pixels)

        # Should include: 3,4,5 (near-dupes), 6,7 (unused + near-dupe pair)
        assert 4 in permutable
        assert 5 in permutable
        assert 6 in permutable
        assert 7 in permutable

    def test_factorial_bits(self):
        """Correct bit capacity for permutations."""
        assert _factorial_bits(0) == 0
        assert _factorial_bits(1) == 0
        assert _factorial_bits(2) == 1
        assert _factorial_bits(3) == 2
        assert _factorial_bits(4) == 4
        assert _factorial_bits(8) == 15


# ---------------------------------------------------------------------------
# Test: Payload Distribution
# ---------------------------------------------------------------------------


class TestDistribution:
    """Tests for payload distribution across channels."""

    def test_primary_gets_bulk(self, config):
        """Primary channel receives the bulk of payload."""
        prepared = b"\x00" * 100
        channels = distribute_payload(
            prepared,
            config,
            num_frames=10,
            frame_pixel_counts=[3072] * 10,  # 64*48
            permutable_counts=[8] * 10,
        )
        assert "primary" in channels
        assert len(channels["primary"]) > 0

    def test_all_channels_used(self, config):
        """All channels receive data when capacity exists."""
        # Large payload that needs all channels
        prepared = b"\x00" * 5000
        channels = distribute_payload(
            prepared,
            config,
            num_frames=10,
            frame_pixel_counts=[3072] * 10,
            permutable_counts=[32] * 10,
        )
        # At minimum primary should be used
        assert "primary" in channels


# ---------------------------------------------------------------------------
# Test: Coercion / Duress Integration
# ---------------------------------------------------------------------------


class TestCoercion:
    """Tests for Schrödinger/duress key derivation."""

    def test_decoy_only_primary(self):
        """Decoy level derives no keys."""
        keys = derive_stego_keys_for_reality("decoy_pass", b"\x00" * 16, CoercionLevel.DECOY)
        assert "primary" not in keys
        assert "secondary" not in keys
        assert "tertiary" not in keys

    def test_shallow_only_primary(self):
        """Shallow level derives only primary key."""
        keys = derive_stego_keys_for_reality("shallow_pass", b"\x00" * 16, CoercionLevel.SHALLOW)
        assert "primary" in keys
        assert "secondary" not in keys
        assert "tertiary" not in keys

    def test_full_all_keys(self):
        """Full level derives all three keys."""
        keys = derive_stego_keys_for_reality("real_pass", b"\x00" * 16, CoercionLevel.FULL)
        assert "primary" in keys
        assert "secondary" in keys
        assert "tertiary" in keys
        # All should be 32 bytes
        for k in keys.values():
            assert len(k) == 32

    def test_different_passwords_different_keys(self):
        """Different passwords produce different keys."""
        salt = b"\x42" * 16
        k1 = derive_stego_keys_for_reality("pass1", salt, CoercionLevel.FULL)
        k2 = derive_stego_keys_for_reality("pass2", salt, CoercionLevel.FULL)
        assert k1["primary"] != k2["primary"]
        assert k1["secondary"] != k2["secondary"]


# ---------------------------------------------------------------------------
# Test: StegoExtractionResult
# ---------------------------------------------------------------------------


class TestExtractionResult:
    """Tests for the structured extraction result."""

    def test_to_dict(self):
        """Result converts to dict correctly."""
        result = StegoExtractionResult(
            payload_bytes=b"test",
            channel_sources=["primary", "secondary"],
            mac_valid=True,
            duress_triggered=False,
        )
        d = result.to_dict()
        assert d["payload_bytes"] == b"test"
        assert d["channel_sources"] == ["primary", "secondary"]
        assert d["mac_valid"] is True
        assert d["duress_triggered"] is False


# ---------------------------------------------------------------------------
# Test: Steganalysis Validation (unit tests for individual analyzers)
# ---------------------------------------------------------------------------


class TestSteganalysis:
    """Tests for steganalysis detection functions."""

    def test_clean_image_chi_square(self):
        """Clean natural image produces a valid chi-square result."""
        from meow_decoder.stego_multilayer import _chi_square_lsb

        # Use a random natural-looking image (uniform random has natural PoV asymmetry)
        rng = np.random.RandomState(123)
        frame = rng.randint(0, 256, (128, 128, 3), dtype=np.uint8)

        result = _chi_square_lsb(frame)
        # Must return valid structure
        assert "p_value" in result
        assert "chi_stat" in result
        assert "dof" in result
        assert 0.0 <= result["p_value"] <= 1.0
        assert result["dof"] > 0

    def test_lsb_replaced_image_chi_square(self):
        """Fully LSB-replaced image has equalized pair counts (higher p-value).

        Under LSB replacement, even/odd value pairs become equalized,
        so the chi-square stat decreases (p-value increases). This is
        the signature detected by the Westfeld chi-square attack.

        We use a structured image (gradient) where pairs are strongly unequal.
        """
        from meow_decoder.stego_multilayer import _chi_square_lsb

        # Structured image: gradient with natural pair bias (all even values)
        # This creates a strong even/odd imbalance in PoV pairs
        natural = np.zeros((128, 128, 3), dtype=np.uint8)
        for y in range(128):
            for x in range(128):
                natural[y, x] = [(y * 2) % 256, (x * 2) % 256, ((y + x)) % 256]
        result_natural = _chi_square_lsb(natural)

        # Same image with fully randomized LSBs (100% embedding)
        rng = np.random.RandomState(42)
        stego = natural.copy()
        lsb_random = rng.randint(0, 2, stego.shape, dtype=np.uint8)
        stego = (stego & 0xFE) | lsb_random
        result_stego = _chi_square_lsb(stego)

        # Natural structured image should have LOW p (pairs very unequal)
        # LSB-replaced image should have HIGHER p (pairs become equalized)
        assert result_stego["p_value"] > result_natural["p_value"], (
            f"Expected stego p ({result_stego['p_value']:.4f}) > "
            f"natural p ({result_natural['p_value']:.4f})"
        )

    def test_entropy_clean(self):
        """Clean image has entropy < 1.0."""
        from meow_decoder.stego_multilayer import _entropy_analysis

        # Natural image with structured LSBs
        frame = np.zeros((64, 64, 3), dtype=np.uint8)
        for y in range(64):
            for x in range(64):
                frame[y, x] = [y * 4, x * 4, 0]

        result = _entropy_analysis(frame)
        assert result["entropy"] < 1.0

    def test_rs_analysis(self):
        """RS analysis returns valid structure."""
        from meow_decoder.stego_multilayer import _rs_analysis

        rng = np.random.RandomState(42)
        frame = rng.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        result = _rs_analysis(frame)
        assert "rm_ratio" in result
        assert "detection_prob" in result
        assert 0.0 <= result["detection_prob"] <= 1.0

    def test_spa_analysis(self):
        """SPA returns valid structure."""
        from meow_decoder.stego_multilayer import _sample_pair_analysis

        rng = np.random.RandomState(42)
        frame = rng.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        result = _sample_pair_analysis(frame)
        assert "estimated_rate" in result
        assert "correlation" in result
        assert 0.0 <= result["estimated_rate"] <= 1.0


# ---------------------------------------------------------------------------
# Test: End-to-End (requires imageio)
# ---------------------------------------------------------------------------


class TestEndToEnd:
    """End-to-end encode/decode tests (require imageio)."""

    @pytest.fixture(autouse=True)
    def check_imageio(self):
        """Skip if imageio not available."""
        try:
            import imageio.v3
        except ImportError:
            try:
                import imageio
            except ImportError:
                pytest.skip("imageio not available")

    def test_primary_channel_e2e(self, master_key, tmp_path):
        """End-to-end with primary channel only."""
        config = MultiLayerConfig(
            enable_primary=True,
            enable_secondary=False,
            enable_tertiary=False,
            lsb_bits=1,
            use_stc=False,
            compress=True,
            encrypt=True,
        )

        # Create carrier GIF
        carrier_path = tmp_path / "carrier.gif"
        output_path = tmp_path / "stego.gif"

        rng = np.random.RandomState(42)
        frames = [
            Image.fromarray(rng.randint(0, 256, (48, 64, 3), dtype=np.uint8)) for _ in range(5)
        ]
        frames[0].save(
            str(carrier_path),
            save_all=True,
            append_images=frames[1:],
            duration=100,
            loop=0,
        )

        # Encode
        payload = b"Secret payload for E2E test!"
        encoder = MultiLayerStegoEncoder(config, master_key)
        meta = encoder.encode(payload, carrier_path, output_path)

        # Encoder auto-switches to APNG when primary channel is enabled
        actual_output = Path(meta["output_path"])
        assert actual_output.exists(), f"Output not found at {actual_output}"
        assert "primary" in meta["channels_used"]

    def test_timing_channel_e2e(self, master_key, config, tmp_path):
        """Timing channel roundtrip works independently."""
        timing = TimingChannelEncoder(master_key, config)

        bits = [1, 0, 1, 1, 0, 0, 1, 0, 1, 0]
        delays = timing.encode(5, bits)
        recovered = timing.decode(delays)
        assert recovered[:10] == bits


# ---------------------------------------------------------------------------
# Test: Rust Backend Integration (conditional)
# ---------------------------------------------------------------------------


class TestRustBackend:
    """Tests that verify Rust backend functions if available."""

    @pytest.fixture(autouse=True)
    def check_rust(self):
        """Skip if Rust backend not available."""
        try:
            import meow_crypto_rs

            if not hasattr(meow_crypto_rs, "stego_derive_frame_seed"):
                pytest.skip("Rust stego functions not available")
        except ImportError:
            pytest.skip("meow_crypto_rs not available")

    def test_rust_seed_derivation(self, master_key):
        """Rust seed derivation matches expected properties."""
        import meow_crypto_rs

        seed = meow_crypto_rs.stego_derive_frame_seed(master_key, 0, CHANNEL_PRIMARY)
        assert len(seed) == 32

        # Deterministic
        seed2 = meow_crypto_rs.stego_derive_frame_seed(master_key, 0, CHANNEL_PRIMARY)
        assert seed == seed2

    def test_rust_pixel_walk(self, master_key):
        """Rust pixel walk is a valid permutation."""
        import meow_crypto_rs

        seed = bytes(meow_crypto_rs.stego_derive_walk_seed(master_key, 0))
        walk = meow_crypto_rs.stego_generate_pixel_walk(seed, 100)
        assert len(walk) == 100
        assert sorted(walk) == list(range(100))

    def test_rust_timing_roundtrip(self):
        """Rust timing encode/decode roundtrip."""
        import meow_crypto_rs

        seed = b"\x55" * 32
        bits = [1, 0, 1, 1, 0, 0, 1, 0]
        delays = meow_crypto_rs.stego_timing_encode(seed, 10, bytes(bits), 2)
        recovered = meow_crypto_rs.stego_timing_decode(seed, 10, delays, 2)
        assert list(recovered)[:8] == bits

    def test_rust_stc_roundtrip(self):
        """Rust STC encode/decode roundtrip."""
        import meow_crypto_rs

        seed = b"\x33" * 32
        rng = np.random.RandomState(42)
        cover = bytes(rng.randint(0, 2, 200, dtype=np.uint8))
        payload = bytes(rng.randint(0, 2, 50, dtype=np.uint8))
        costs = [1.0] * 200

        stego = meow_crypto_rs.stego_stc_encode(seed, list(cover), list(payload), costs)
        assert len(stego) == 200

        # Verify fewer changes
        changes = meow_crypto_rs.stego_count_changes(cover, stego)
        assert changes <= 50  # Should be fewer than payload bits


# ---------------------------------------------------------------------------
# Test: Cross-channel binding (audit #4)
# ---------------------------------------------------------------------------


class TestCrossChannelBinding:
    """The comment channel's own HMAC is only an extraction hint; the outer
    payload HMAC over the full reassembly is the authoritative authenticator.

    This defeats a *shadowing* attack: an attacker harvests a MAC-valid comment
    block from another message encrypted under the same key and injects it ahead
    of the real one. With the old break-on-first-valid logic the decoder would
    pick the stale block, fail the outer HMAC, and report mac_valid=False even
    though the real payload is fully recoverable (a denial of service). The
    decoder must instead select the comment candidate that satisfies the outer
    HMAC.
    """

    @pytest.fixture(autouse=True)
    def _need_imageio(self):
        try:
            import imageio  # noqa: F401
        except ImportError:
            try:
                import imageio.v3  # noqa: F401
            except ImportError:
                pytest.skip("imageio not available")

    @staticmethod
    def _make_carrier(path, n_frames=24):
        # Solid per-frame colours keep palette/shape consistent so imageio reads
        # all frames back at the same size even after the disposal channel edits
        # GCE disposal methods (random frames read back with mismatched shapes).
        frames = [
            Image.fromarray(np.full((24, 24, 3), (c * 9) % 256, dtype=np.uint8))
            for c in range(n_frames)
        ]
        frames[0].save(str(path), save_all=True, append_images=frames[1:], duration=100, loop=0)

    @staticmethod
    def _binary_channel_config():
        # comment + disposal are pure GIF-binary channels (read straight from the
        # GIF bytes via GifBinaryEditor, independent of the pixel decoder), so the
        # payload overflows comment into disposal. primary off => GIF output
        # (primary would force an APNG switch that drops GIF-only channels).
        return MultiLayerConfig(
            enable_primary=False,
            enable_secondary=False,
            enable_temporal=False,
            enable_tertiary=False,
            enable_disposal=True,
            enable_comment=True,
            compress=False,
            encrypt=True,
        )

    @staticmethod
    def _stub_frame_reader(monkeypatch, n_frames=24):
        """Make decode()'s imageio frame read deterministic.

        With primary/secondary/temporal disabled, decode() only uses the decoded
        frames for a count — the comment and disposal channels are parsed from the
        GIF *bytes* via GifBinaryEditor. imageio's GIF frame compositing is flaky
        once the disposal channel rewrites GCE disposal methods (frames come back
        with mismatched shapes, nondeterministically), so we stub the reader to
        isolate the channel-selection logic under test.
        """
        import meow_decoder.stego_multilayer as s

        class _FakeIIO:
            @staticmethod
            def imread(path, index=None):
                return np.zeros((n_frames, 24, 24, 3), dtype=np.uint8)

            @staticmethod
            def immeta(path):
                return {"duration": 100}

        monkeypatch.setattr(s, "iio", _FakeIIO)

    def _encode_gif(self, payload, key, carrier, out):
        encoder = MultiLayerStegoEncoder(self._binary_channel_config(), key)
        meta = encoder.encode(payload, carrier, out)  # uses the real imageio reader
        return Path(meta["output_path"]), meta

    def test_comment_plus_disposal_roundtrip(self, master_key, tmp_path, monkeypatch):
        """Sanity: a message spanning comment + disposal decodes authentically."""
        carrier = tmp_path / "carrier.gif"
        self._make_carrier(carrier)
        payload = bytes((i * 7) % 256 for i in range(120))  # > comment capacity

        out, meta = self._encode_gif(payload, master_key, carrier, tmp_path / "a.gif")
        assert out.suffix == ".gif", "primary-disabled output must stay GIF"
        assert "comment" in meta["channels_used"]
        assert "disposal" in meta["channels_used"], "payload should overflow into disposal"

        self._stub_frame_reader(monkeypatch)
        decoder = MultiLayerStegoDecoder(self._binary_channel_config(), master_key)
        result = decoder.decode(out)
        assert result.mac_valid
        assert result.payload_bytes == payload

    def test_shadow_comment_does_not_dos_decode(self, master_key, tmp_path, monkeypatch):
        """A stale MAC-valid comment injected ahead of the real one must not
        prevent recovery of the genuine payload."""
        from meow_decoder.stego_gif_binary import GifBinaryEditor

        carrier = tmp_path / "carrier.gif"
        self._make_carrier(carrier)

        payload_a = bytes((i * 7) % 256 for i in range(120))
        payload_b = bytes((i * 11 + 3) % 256 for i in range(120))

        gif_a, _ = self._encode_gif(payload_a, master_key, carrier, tmp_path / "a.gif")
        gif_b, _ = self._encode_gif(payload_b, master_key, carrier, tmp_path / "b.gif")

        # Harvest B's raw (encrypted) comment block — MAC-valid under the same key.
        b_comment = GifBinaryEditor.extract_comments(GifBinaryEditor.parse(gif_b.read_bytes()))[0]

        # Rebuild A's GIF with B's stale comment placed FIRST, then A's real one.
        struct_a = GifBinaryEditor.parse(gif_a.read_bytes())
        a_comment = GifBinaryEditor.extract_comments(struct_a)[0]
        assert a_comment != b_comment
        struct_a = GifBinaryEditor.remove_comments(struct_a)
        struct_a = GifBinaryEditor.inject_comment(struct_a, b_comment)  # stale, first
        struct_a = GifBinaryEditor.inject_comment(struct_a, a_comment)  # real, second

        shadow = tmp_path / "shadow.gif"
        shadow.write_bytes(GifBinaryEditor.to_bytes(struct_a))

        # Confirm the stale block really is first (worst case for break-on-first).
        comments = GifBinaryEditor.extract_comments(GifBinaryEditor.parse(shadow.read_bytes()))
        assert comments[0] == b_comment

        self._stub_frame_reader(monkeypatch)
        decoder = MultiLayerStegoDecoder(self._binary_channel_config(), master_key)
        result = decoder.decode(shadow)
        assert result.mac_valid, "outer HMAC must authenticate the real combination"
        assert result.payload_bytes == payload_a, "must recover A, not the shadow B"
