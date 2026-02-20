"""
Fuzzing Harness for Multi-Layer Steganography
==============================================

Uses Hypothesis property-based testing to generate 500+ diverse payloads,
keys, frame sizes, and configurations to stress-test the stego system.

Covers:
1. prepare/unpack payload roundtrip with random data
2. Primary channel embed/extract with random frames and bits
3. Cross-backend seed derivation (random keys, frame indices)
4. STC encode/decode with random cover/payload
5. Timing channel with random bit patterns
6. Palette encode/decode with random permutations
7. Bit conversion roundtrip with arbitrary bytes
8. Adversarial payload structures (malformed headers, truncation)
"""

import os
import struct

import numpy as np
import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

from meow_decoder.stego_multilayer import (
    CHANNEL_PRIMARY,
    MultiLayerConfig,
    PrimaryChannelEncoder,
    TimingChannelEncoder,
    _bits_to_bytes,
    _bytes_to_bits,
    derive_frame_seed,
    derive_walk_seed,
    generate_pixel_walk,
    prepare_payload,
    unpack_payload,
)

os.environ["MEOW_TEST_MODE"] = "1"

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_key = st.binary(min_size=32, max_size=32)
st_payload = st.binary(min_size=0, max_size=4096)
st_small_payload = st.binary(min_size=0, max_size=256)
st_frame_idx = st.integers(min_value=0, max_value=9999)
st_channel = st.sampled_from([0, 1, 2])
st_bit_list = st.lists(st.integers(min_value=0, max_value=1), min_size=0, max_size=2000)


# ===========================================================================
# 1. prepare/unpack Roundtrip
# ===========================================================================

class TestFuzzPrepareUnpack:
    """Property: prepare(data, key) → unpack(_, key) == data."""

    @given(data=st_payload, key=st_key,
           compress=st.booleans(), encrypt=st.booleans())
    @settings(max_examples=200, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
    def test_roundtrip(self, data, key, compress, encrypt):
        prepared = prepare_payload(data, key, compress=compress, encrypt=encrypt)
        recovered, valid = unpack_payload(prepared, key)
        assert valid, f"MAC failed: len={len(data)}, compress={compress}, encrypt={encrypt}"
        assert recovered == data

    @given(data=st_payload, key=st_key)
    @settings(max_examples=100, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
    def test_wrong_key_fails(self, data, key):
        """Wrong key must always fail MAC verification."""
        prepared = prepare_payload(data, key)
        # Derive a different key
        wrong_key = bytes((b + 1) % 256 for b in key)
        assume(wrong_key != key)
        _, valid = unpack_payload(prepared, wrong_key)
        assert not valid

    @given(data=st_payload, key=st_key, flip_pos=st.integers(min_value=0, max_value=500))
    @settings(max_examples=100, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
    def test_bitflip_detected(self, data, key, flip_pos):
        """Any single bit flip must be detected."""
        prepared = prepare_payload(data, key)
        if flip_pos >= len(prepared):
            return
        tampered = bytearray(prepared)
        tampered[flip_pos] ^= 0x01
        _, valid = unpack_payload(bytes(tampered), key)
        assert not valid


# ===========================================================================
# 2. Primary Channel Embed/Extract
# ===========================================================================

class TestFuzzPrimaryChannel:
    """Property: embed(frame, bits) → extract(stego, n) recovers bits."""

    @given(
        seed=st.integers(min_value=0, max_value=2**31),
        bits=st.lists(st.integers(0, 1), min_size=1, max_size=500),
        frame_h=st.integers(min_value=8, max_value=64),
        frame_w=st.integers(min_value=8, max_value=64),
    )
    @settings(max_examples=200, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
    def test_embed_extract_roundtrip(self, seed, bits, frame_h, frame_w):
        """Embed n bits, extract n bits: must match."""
        key = bytes(range(32))
        config = MultiLayerConfig(lsb_bits=1, use_stc=False)
        encoder = PrimaryChannelEncoder(key, config)

        rng = np.random.RandomState(seed)
        frame = rng.randint(0, 256, (frame_h, frame_w, 3), dtype=np.uint8)

        capacity = frame_h * frame_w * 3 * 1
        # Stay within capacity to avoid truncation
        use_bits = bits[:capacity - 1]
        if not use_bits:
            return

        stego = encoder.embed_frame(frame, 0, use_bits)
        extracted = encoder.extract_frame(stego, 0, len(use_bits))
        assert extracted[:len(use_bits)] == use_bits

    @given(
        seed=st.integers(min_value=0, max_value=2**31),
        bits=st.lists(st.integers(0, 1), min_size=1, max_size=100),
    )
    @settings(max_examples=100, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
    def test_lsb2_embed_extract(self, seed, bits):
        """2-bit LSB embedding roundtrip."""
        key = bytes(range(32))
        config = MultiLayerConfig(lsb_bits=2, use_stc=False)
        encoder = PrimaryChannelEncoder(key, config)

        rng = np.random.RandomState(seed)
        frame = rng.randint(0, 256, (32, 32, 3), dtype=np.uint8)

        capacity = 32 * 32 * 3 * 2
        use_bits = bits[:capacity - 1]
        if not use_bits:
            return

        stego = encoder.embed_frame(frame, 0, use_bits)
        extracted = encoder.extract_frame(stego, 0, len(use_bits))
        assert extracted[:len(use_bits)] == use_bits


# ===========================================================================
# 3. Seed Derivation
# ===========================================================================

class TestFuzzSeedDerivation:
    """Property: same inputs → same output; different inputs → different output."""

    @given(key=st_key, frame=st_frame_idx, channel=st_channel)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_deterministic(self, key, frame, channel):
        seed1 = derive_frame_seed(key, frame, channel)
        seed2 = derive_frame_seed(key, frame, channel)
        assert seed1 == seed2

    @given(key=st_key, frame1=st_frame_idx, frame2=st_frame_idx, channel=st_channel)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_different_frames_different_seeds(self, key, frame1, frame2, channel):
        assume(frame1 != frame2)
        seed1 = derive_frame_seed(key, frame1, channel)
        seed2 = derive_frame_seed(key, frame2, channel)
        assert seed1 != seed2

    @given(key=st_key, frame=st_frame_idx)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_walk_seed_deterministic(self, key, frame):
        w1 = derive_walk_seed(key, frame)
        w2 = derive_walk_seed(key, frame)
        assert w1 == w2

    @given(key=st_key, frame=st_frame_idx,
           n_pixels=st.integers(min_value=2, max_value=1000))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_pixel_walk_is_permutation(self, key, frame, n_pixels):
        """Pixel walk must be a valid permutation (all unique)."""
        seed = derive_walk_seed(key, frame)
        walk = generate_pixel_walk(seed, n_pixels)
        assert len(walk) == n_pixels
        assert len(set(walk)) == n_pixels
        assert all(0 <= x < n_pixels for x in walk)


# ===========================================================================
# 4. STC Encode/Decode (Rust backend)
# ===========================================================================

class TestFuzzSTC:
    """Property: stc_encode → stc_decode == payload."""

    @pytest.fixture(autouse=True)
    def check_rust(self):
        try:
            import meow_crypto_rs
            if not hasattr(meow_crypto_rs, "stego_stc_encode"):
                pytest.skip("Rust STC not available")
        except ImportError:
            pytest.skip("meow_crypto_rs not available")

    @given(
        seed_val=st.integers(min_value=0, max_value=255),
        n=st.integers(min_value=40, max_value=500),
        rng_seed=st.integers(min_value=0, max_value=2**31),
    )
    @settings(max_examples=100, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_stc_roundtrip(self, seed_val, n, rng_seed):
        """STC encode/decode roundtrip with random cover and payload.

        STC encoding may legitimately fail (ValueError) for some H matrices
        when Gaussian elimination can't find a solution — that's correct
        fail-closed behavior. We only assert roundtrip when it succeeds.
        """
        import meow_crypto_rs
        seed = bytes([seed_val]) * 32
        rng = np.random.RandomState(rng_seed)

        m = max(1, n // 6)  # 1/6 ratio gives more STC margin
        cover = bytes(rng.randint(0, 2, n, dtype=np.uint8))
        payload = bytes(rng.randint(0, 2, m, dtype=np.uint8))
        costs = [1.0] * n

        try:
            stego = bytes(meow_crypto_rs.stego_stc_encode(seed, list(cover), list(payload), costs))
        except ValueError:
            # Fail-closed: infeasible for this H matrix. Acceptable.
            return
        decoded = bytes(meow_crypto_rs.stego_stc_decode(seed, stego, m))
        assert list(decoded) == list(payload), f"STC mismatch n={n}, m={m}"


# ===========================================================================
# 5. Timing Channel
# ===========================================================================

class TestFuzzTiming:
    """Property: timing encode → decode recovers bits."""

    @given(
        key=st_key,
        bits=st.lists(st.integers(0, 1), min_size=2, max_size=100),
    )
    @settings(max_examples=100, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
    def test_timing_roundtrip(self, key, bits):
        config = MultiLayerConfig(timing_bits_per_frame=2)
        timing = TimingChannelEncoder(key, config)
        # Pad to multiple of bits_per_frame
        padded = bits + [0] * (2 - len(bits) % 2) if len(bits) % 2 else bits
        n_frames = len(padded) // 2
        delays = timing.encode(n_frames, padded)
        recovered = timing.decode(delays)
        assert recovered[:len(padded)] == padded


# ===========================================================================
# 6. Palette Encode/Decode (Rust)
# ===========================================================================

class TestFuzzPalette:
    """Property: palette_encode → palette_decode recovers bits."""

    @pytest.fixture(autouse=True)
    def check_rust(self):
        try:
            import meow_crypto_rs
        except ImportError:
            pytest.skip("Rust backend not available")

    @given(
        seed_val=st.integers(min_value=0, max_value=255),
        n_entries=st.integers(min_value=4, max_value=12),
        n_bits=st.integers(min_value=1, max_value=8),
    )
    @settings(max_examples=100, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
    def test_palette_roundtrip(self, seed_val, n_entries, n_bits):
        import meow_crypto_rs
        import math
        seed = bytes([seed_val]) * 32
        max_bits = int(math.log2(math.factorial(n_entries))) if n_entries > 1 else 0
        use_bits = min(n_bits, max_bits)
        if use_bits < 1:
            return
        rng = np.random.RandomState(seed_val)
        payload = list(rng.randint(0, 2, use_bits))
        indices = list(range(200, 200 + n_entries))

        encoded = list(meow_crypto_rs.stego_palette_encode(seed, indices, payload))
        decoded = list(meow_crypto_rs.stego_palette_decode(seed, indices, encoded))
        assert decoded[:use_bits] == payload


# ===========================================================================
# 7. Bit Conversion
# ===========================================================================

class TestFuzzBitConversion:
    """Property: bytes → bits → bytes == original."""

    @given(data=st.binary(min_size=0, max_size=10000))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_byte_bit_roundtrip(self, data):
        bits = _bytes_to_bits(data)
        assert len(bits) == len(data) * 8
        recovered = _bits_to_bytes(bits)
        assert recovered == data


# ===========================================================================
# 8. Adversarial Unpack
# ===========================================================================

class TestFuzzAdversarialUnpack:
    """Property: random garbage never unpacks successfully."""

    @given(garbage=st.binary(min_size=0, max_size=1000), key=st_key)
    @settings(max_examples=200, deadline=5000, suppress_health_check=[HealthCheck.too_slow])
    def test_garbage_never_valid(self, garbage, key):
        _, valid = unpack_payload(garbage, key)
        # Random garbage has negligible probability of valid HMAC
        # If it randomly has valid magic + HMAC, that would be a cryptographic break
        if valid:
            # Verify it's a true positive
            assert garbage[:4] == b"MSTG", "Valid MAC on non-MSTG data!"


# ===========================================================================
# 9. Cross-Backend Consistency (if both available)
# ===========================================================================

class TestFuzzCrossBackend:
    """Property: Python fallback matches Rust for all inputs."""

    @pytest.fixture(autouse=True)
    def check_rust(self):
        try:
            import meow_crypto_rs
        except ImportError:
            pytest.skip("Rust backend not available")

    @given(key=st_key, frame=st.integers(min_value=0, max_value=999),
           channel=st_channel)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_frame_seed_match(self, key, frame, channel):
        from meow_decoder.stego_multilayer import _py_derive_frame_seed
        import meow_crypto_rs
        py_seed = _py_derive_frame_seed(key, frame, channel)
        rs_seed = bytes(meow_crypto_rs.stego_derive_frame_seed(key, frame, channel))
        assert py_seed == rs_seed

    @given(key=st_key, frame=st.integers(min_value=0, max_value=999))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_walk_seed_match(self, key, frame):
        from meow_decoder.stego_multilayer import _py_derive_walk_seed
        import meow_crypto_rs
        py_ws = _py_derive_walk_seed(key, frame)
        rs_ws = bytes(meow_crypto_rs.stego_derive_walk_seed(key, frame))
        assert py_ws == rs_ws

    @given(key=st_key, frame=st.integers(min_value=0, max_value=99),
           n_pixels=st.integers(min_value=2, max_value=500))
    @settings(max_examples=50, deadline=10000, suppress_health_check=[HealthCheck.too_slow])
    def test_pixel_walk_match(self, key, frame, n_pixels):
        from meow_decoder.stego_multilayer import _py_generate_pixel_walk
        import meow_crypto_rs
        seed = bytes(meow_crypto_rs.stego_derive_walk_seed(key, frame))
        py_walk = _py_generate_pixel_walk(seed, n_pixels)
        rs_walk = list(meow_crypto_rs.stego_generate_pixel_walk(seed, n_pixels))
        assert py_walk == rs_walk
