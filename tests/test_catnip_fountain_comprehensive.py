import random

import meow_decoder.catnip_fountain as catnip_fountain


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
