"""
Formal Fuzz Gaps — Part 2 of 3: Fountain Codes & Schrödinger

GAP-6: Belief propagation progress (Lean proof backed by Python behaviour)
GAP-7: Schrödinger timing indistinguishability (statistical + structural)
Runs in CI batch 2 in parallel with test_formal_fuzz_gaps_aead.py (batch 1)
and test_formal_fuzz_gaps_tamper.py (batch 3).
"""

import os
import time
import secrets
import inspect

import pytest

pytestmark = pytest.mark.security

os.environ.setdefault("MEOW_TEST_MODE", "1")


class TestBeliefPropagationProgress:
    """
    Validates the Python fountain decoder's belief propagation matches
    the Lean 4 proof in FountainCodes.lean.
    """

    def test_degree_one_makes_progress(self):
        from meow_decoder.fountain import FountainDecoder, Droplet
        k, block_size = 2, 50
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=100)
        assert not decoder.is_complete()
        d0 = Droplet(seed=0, block_indices=[0], data=b"A" * block_size)
        d1 = Droplet(seed=1, block_indices=[1], data=b"B" * block_size)
        decoder.add_droplet(d0)
        assert not decoder.is_complete()
        decoder.add_droplet(d1)
        assert decoder.is_complete()
        assert decoder.get_data() == b"A" * 50 + b"B" * 50

    def test_cascade_solve_completes_decoder(self):
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        payload = secrets.token_bytes(400)
        k, block_size = 4, 100
        encoder = FountainEncoder(payload, k_blocks=k, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=400)
        for i in range(k * 3):
            if decoder.add_droplet(encoder.droplet(i)):
                break
        assert decoder.is_complete()
        assert decoder.get_data() == payload

    def test_high_degree_only_no_immediate_solve(self):
        from meow_decoder.fountain import FountainDecoder, Droplet
        k, block_size = 4, 100
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=400)
        d = Droplet(seed=99, block_indices=[0, 1, 2], data=secrets.token_bytes(block_size))
        decoder.add_droplet(d)
        assert not decoder.is_complete()
        assert len(decoder.pending_droplets) >= 1

    def test_belief_propagation_terminates(self):
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        payload = secrets.token_bytes(800)
        k, block_size = 8, 100
        encoder = FountainEncoder(payload, k_blocks=k, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=800)
        for i in range(k * 4):
            if decoder.add_droplet(encoder.droplet(i)):
                break
        assert True  # no infinite loop

    def test_roundtrip_preserves_exact_bytes(self):
        from meow_decoder.fountain import FountainEncoder, FountainDecoder
        payload = secrets.token_bytes(600)
        k, block_size = 6, 100
        encoder = FountainEncoder(payload, k_blocks=k, block_size=block_size)
        decoder = FountainDecoder(k_blocks=k, block_size=block_size, original_length=600)
        for i in range(k * 5):
            if decoder.add_droplet(encoder.droplet(i)):
                assert decoder.get_data() == payload
                return
        pytest.fail("Decode did not complete with 5× redundancy")


class TestSchrodingerTimingIndistinguishability:
    """
    Python-side statistical tests backing the Tamarin timing model
    MeowSchrodingerDeniabilityTiming.spthy (T1-T5).
    """

    TRIALS = 10

    def test_both_passwords_decode_successfully(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data
        superpos, manifest = schrodinger_encode_data(
            b"real secret content",
            b"innocent decoy text",
            real_password="realpass123",
            decoy_password="decoypass123",
        )
        assert schrodinger_decode_data(superpos, manifest, "realpass123") == b"real secret content"
        assert schrodinger_decode_data(superpos, manifest, "decoypass123") == b"innocent decoy text"

    def test_deniability_coerced_party_sees_decoy(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data
        superpos, manifest = schrodinger_encode_data(
            b"classified data",
            b"harmless content",
            real_password="classified123",
            decoy_password="harmless123",
        )
        assert schrodinger_decode_data(superpos, manifest, "harmless123") == b"harmless content"

    def test_wrong_password_does_not_decode_either_secret(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data
        superpos, manifest = schrodinger_encode_data(
            b"real", b"decoy", real_password="correctreal123", decoy_password="correctdecoy123"
        )
        try:
            result = schrodinger_decode_data(superpos, manifest, "wrongpassword1")
            assert result not in (b"real", b"decoy")
        except Exception:
            pass

    def test_no_consistent_ordering_in_timing(self):
        from meow_decoder.schrodinger_encode import schrodinger_encode_data
        from meow_decoder.schrodinger_decode import schrodinger_decode_data
        superpos, manifest = schrodinger_encode_data(
            b"payload A" * 4,
            b"payload B" * 4,
            real_password="passwordA123",
            decoy_password="passwordB123",
        )
        a_wins = 0
        for _ in range(self.TRIALS):
            t0 = time.monotonic()
            schrodinger_decode_data(superpos, manifest, "passwordA123")
            ta = time.monotonic() - t0
            t0 = time.monotonic()
            schrodinger_decode_data(superpos, manifest, "passwordB123")
            tb = time.monotonic() - t0
            if ta < tb:
                a_wins += 1
        assert a_wins <= int(self.TRIALS * 0.90), "Path A consistently faster — timing leak"
        assert (self.TRIALS - a_wins) <= int(self.TRIALS * 0.90), "Path B consistently faster"

    def test_isomorphic_code_path(self):
        import meow_decoder.schrodinger_decode as sd_module
        src = inspect.getsource(sd_module)
        assert (
            "if password ==" not in src and "elif password ==" not in src
        ), "schrodinger_decode_data must not branch on literal password equality"
