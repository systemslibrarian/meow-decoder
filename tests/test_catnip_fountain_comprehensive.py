
import random
import meow_decoder.catnip_fountain as catnip_fountain

# Imports from merged file
import pytest
import struct
from meow_decoder.catnip_fountain import (
    Kibble,
    CatNapDistribution,
    CatnipFountain,
    KibbleCollector,
    pack_kibble,
    unpack_kibble,
)
def test_cat_nap_distribution_probabilities():
    dist = catnip_fountain.CatNapDistribution(num_posts=10)
    assert abs(sum(dist.probabilities) - 1.0) < 1e-6
    rng = random.Random(123)
    depth = dist.sample_nap_depth(rng)
    assert 1 <= depth <= 10


def test_catnip_fountain_rejects_oversized_data():
    data = b"x" * 33
    try:
        catnip_fountain.CatnipFountain(data, num_posts=4, post_size=8)
        assert False, "Expected ValueError for oversized data"
    except ValueError as exc:
        assert "Too much data" in str(exc)


def test_kibble_pack_unpack_roundtrip():
    kibble = catnip_fountain.Kibble(seed=1, scratching_post_indices=[0, 2], data=b"abcd")
    packed = catnip_fountain.pack_kibble(kibble)
    unpacked = catnip_fountain.unpack_kibble(packed, post_size=4)
    assert unpacked.seed == 1
    assert unpacked.scratching_post_indices == [0, 2]
    assert unpacked.data == b"abcd"


def test_kibble_collector_reconstructs_data():
    data = b"hello world"
    num_posts = 3
    post_size = 4
    total = num_posts * post_size
    padded = data.ljust(total, b"\x00")

    fountain = catnip_fountain.CatnipFountain(padded, num_posts, post_size)
    collector = catnip_fountain.KibbleCollector(num_posts, post_size)

    for idx, post in enumerate(fountain.scratching_posts):
        collector.collect_kibble(seed=idx, post_indices=[idx], data=post)

    assert collector.is_satisfied()
    reconstructed = collector.get_reconstructed_data()
    assert reconstructed == padded


# ===============================================================
# Merged from test_coverage_boost_catnip.py
# ===============================================================


class TestCatnipFountainInit:
    def test_data_too_large(self):
        """Data larger than num_posts * post_size should raise."""
        with pytest.raises(ValueError, match="Too much data"):
            CatnipFountain(b"\x00" * 200, num_posts=2, post_size=50)

    def test_data_padded(self):
        """Data smaller than total gets padded."""
        fountain = CatnipFountain(b"\x01" * 50, num_posts=5, post_size=20)
        assert len(fountain.scratching_posts) == 5
        for post in fountain.scratching_posts:
            assert len(post) == 20


class TestDispenseKibbles:
    def test_dispense_kibbles(self):
        """Test dispense_kibbles returns list of kibbles."""
        data = b"test data for fountain" * 5
        fountain = CatnipFountain(data, num_posts=5, post_size=25)
        kibbles = fountain.dispense_kibbles(10)
        assert len(kibbles) == 10
        for k in kibbles:
            assert isinstance(k, Kibble)
            assert len(k.data) == 25
            assert len(k.scratching_post_indices) > 0


class TestCatNapDistribution:
    def test_sample_fallback(self):
        """Test edge case where sample_nap_depth returns num_posts."""
        import random

        dist = CatNapDistribution(5)
        rng = random.Random(42)

        # Force the fallback by setting cumulative so p never matches
        original_cumulative = dist.cumulative[:]
        dist.cumulative = [0.0] * (dist.num_posts + 1)  # all zeros

        result = dist.sample_nap_depth(rng)
        assert result == 5  # num_posts fallback

        dist.cumulative = original_cumulative


class TestKibbleCollectorEdgeCases:
    def test_get_data_not_satisfied(self):
        """Getting data before collection is complete should raise."""
        collector = KibbleCollector(num_posts=5, post_size=10)
        with pytest.raises(RuntimeError, match="Not enough kibbles"):
            collector.get_reconstructed_data()

    def test_collect_when_already_satisfied(self):
        """Collecting after satisfaction returns True immediately."""
        data = b"A" * 20
        fountain = CatnipFountain(data, num_posts=2, post_size=10)
        collector = KibbleCollector(num_posts=2, post_size=10)

        # Feed enough kibbles to satisfy
        for i in range(100):
            k = fountain.drop_kibble()
            if collector.collect_kibble(k.seed, k.scratching_post_indices, k.data):
                break

        assert collector.is_satisfied()

        # Now collecting another should return True immediately
        k = fountain.drop_kibble()
        assert collector.collect_kibble(k.seed, k.scratching_post_indices, k.data) is True

    def test_collect_all_known_indices(self):
        """Kibble where all indices are already solved gets discarded."""
        data = b"A" * 10 + b"B" * 10
        fountain = CatnipFountain(data, num_posts=2, post_size=10)
        collector = KibbleCollector(num_posts=2, post_size=10)

        # Manually set both posts as solved
        collector.scratching_posts[0] = b"A" * 10
        collector.scratching_posts[1] = b"B" * 10
        collector.posts_found = 2

        # Any kibble should be handled gracefully
        k = fountain.drop_kibble()
        result = collector.collect_kibble(k.seed, k.scratching_post_indices, k.data)
        assert result is True


class TestFullRoundtrip:
    def test_encode_decode_roundtrip(self):
        """Full CatnipFountain → KibbleCollector roundtrip."""
        data = b"Hello Catnip Fountain! This is test data." * 3
        post_size = 20
        num_posts = (len(data) + post_size - 1) // post_size

        fountain = CatnipFountain(data, num_posts=num_posts, post_size=post_size)
        collector = KibbleCollector(num_posts=num_posts, post_size=post_size)

        for i in range(num_posts * 5):
            k = fountain.drop_kibble()
            if collector.collect_kibble(k.seed, k.scratching_post_indices, k.data):
                break

        assert collector.is_satisfied()
        result = collector.get_reconstructed_data()
        assert result[: len(data)] == data

    def test_stash_processing(self):
        """Test that stash processing works with multi-index kibbles."""
        data = b"ABCDEFGHIJ" * 4  # 40 bytes
        post_size = 10
        num_posts = 4

        fountain = CatnipFountain(data, num_posts=num_posts, post_size=post_size)
        collector = KibbleCollector(num_posts=num_posts, post_size=post_size)

        # Feed many kibbles — some will go to stash, then get resolved
        for i in range(num_posts * 10):
            k = fountain.drop_kibble()
            if collector.collect_kibble(k.seed, k.scratching_post_indices, k.data):
                break

        assert collector.is_satisfied()
        result = collector.get_reconstructed_data()
        assert result[: len(data)] == data


class TestPackUnpackKibble:
    def test_pack_unpack_roundtrip(self):
        """pack_kibble → unpack_kibble should be identity."""
        k = Kibble(
            seed=42,
            scratching_post_indices=[0, 3, 7],
            data=b"\xab" * 20,
        )
        packed = pack_kibble(k)
        unpacked = unpack_kibble(packed, post_size=20)

        assert unpacked.seed == 42
        assert unpacked.scratching_post_indices == [0, 3, 7]
        assert unpacked.data == b"\xab" * 20
