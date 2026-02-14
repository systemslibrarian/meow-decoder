"""
Monte Carlo stress tests for fountain codes.

Validates statistical guarantees of the Luby Transform (LT) codec under
realistic loss conditions. These tests run many trials to ensure the
fountain code implementation meets its theoretical success rate bounds.

Reference: Luby, M. "LT Codes" FOCS 2002 - success probability ≥ 1-δ
with (1+ε)k received droplets under Robust Soliton(k, c, δ).

Run with: pytest tests/test_fountain_montecarlo.py -v
Run in CI: pytest -m slow tests/test_fountain_montecarlo.py -v
"""

import pytest
import secrets
import random
import statistics
from dataclasses import dataclass
from typing import List, Tuple
from meow_decoder.fountain import (
    FountainEncoder,
    FountainDecoder,
    pack_droplet,
    unpack_droplet,
)


@dataclass
class TrialResult:
    """Result of a single fountain code trial."""

    success: bool
    droplets_sent: int
    droplets_received: int
    attempts: int


def run_fountain_trial(
    data: bytes,
    k_blocks: int,
    block_size: int,
    drop_rate: float,
    max_attempts_multiplier: float = 4.0,
    seed: int | None = None,
) -> TrialResult:
    """
    Run a single fountain encode/decode trial with simulated packet loss.

    Args:
        data: Data to encode
        k_blocks: Number of source blocks
        block_size: Size of each block in bytes
        drop_rate: Fraction of packets to drop (0.0 to 1.0)
        max_attempts_multiplier: Max droplets = k_blocks * multiplier
        seed: Random seed for reproducibility

    Returns:
        TrialResult with success/failure and statistics
    """
    if seed is not None:
        random.seed(seed)

    encoder = FountainEncoder(data, k_blocks, block_size)
    decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))

    droplets_sent = 0
    droplets_received = 0
    max_attempts = int(k_blocks * max_attempts_multiplier)

    for _ in range(max_attempts):
        droplet = encoder.droplet()
        droplets_sent += 1

        # Simulate packet loss
        if random.random() > drop_rate:
            # Packet received - simulate pack/unpack through QR
            packed = pack_droplet(droplet)
            unpacked = unpack_droplet(packed, block_size)
            decoder.add_droplet(unpacked)
            droplets_received += 1

        if decoder.is_complete():
            break

    # Verify correctness if complete
    success = False
    if decoder.is_complete():
        try:
            decoded = decoder.get_data()
            success = decoded == data
        except Exception:
            success = False

    return TrialResult(
        success=success,
        droplets_sent=droplets_sent,
        droplets_received=droplets_received,
        attempts=droplets_sent,
    )


def run_monte_carlo(
    n_trials: int,
    data_size: int,
    k_blocks: int,
    block_size: int,
    drop_rate: float,
    max_attempts_multiplier: float = 4.0,
) -> Tuple[float, List[TrialResult]]:
    """
    Run Monte Carlo trials and return success rate.

    Args:
        n_trials: Number of trials to run
        data_size: Size of random data per trial
        k_blocks: Number of source blocks
        block_size: Block size in bytes
        drop_rate: Packet drop rate
        max_attempts_multiplier: Max droplets factor

    Returns:
        (success_rate, list of TrialResult)
    """
    results: List[TrialResult] = []

    for trial in range(n_trials):
        # Fresh random data each trial
        data = secrets.token_bytes(data_size)

        # Use trial number as part of seed for reproducibility but variation
        result = run_fountain_trial(
            data=data,
            k_blocks=k_blocks,
            block_size=block_size,
            drop_rate=drop_rate,
            max_attempts_multiplier=max_attempts_multiplier,
            seed=trial * 31337,  # Reproducible but varied
        )
        results.append(result)

    success_count = sum(1 for r in results if r.success)
    success_rate = success_count / n_trials

    return success_rate, results


@pytest.mark.slow
class TestMonteCarlo30PercentLoss:
    """Monte Carlo tests at 30% packet loss rate."""

    @pytest.mark.parametrize(
        "k_blocks,block_size,data_size",
        [
            (10, 100, 800),  # Small: 10 blocks, 100B each
            (20, 200, 3500),  # Medium: 20 blocks, 200B each
            (50, 256, 10000),  # Large: 50 blocks, 256B each
        ],
    )
    def test_30_percent_loss_1000_trials(self, k_blocks, block_size, data_size):
        """
        1000 trials at 30% loss should achieve ≥99.5% success rate.

        At 30% loss with 4× redundancy (sending 4k droplets), receiver gets
        ~2.8k droplets on average. With k blocks and systematic optimization
        (first 2k droplets are degree-1), decode is virtually guaranteed.
        """
        n_trials = 1000
        drop_rate = 0.30
        target_success_rate = 0.995  # 99.5%

        success_rate, results = run_monte_carlo(
            n_trials=n_trials,
            data_size=data_size,
            k_blocks=k_blocks,
            block_size=block_size,
            drop_rate=drop_rate,
            max_attempts_multiplier=4.0,
        )

        # Calculate statistics
        received_counts = [r.droplets_received for r in results]
        avg_received = statistics.mean(received_counts)
        failures = [r for r in results if not r.success]

        # Report
        print(f"\n--- 30% Loss Test (k={k_blocks}, bs={block_size}) ---")
        print(f"Trials: {n_trials}")
        print(f"Success rate: {success_rate:.4f} ({success_rate * 100:.2f}%)")
        print(f"Avg droplets received: {avg_received:.1f}")
        print(f"Failures: {len(failures)}")

        assert success_rate >= target_success_rate, (
            f"Success rate {success_rate:.4f} below target {target_success_rate}. "
            f"Failures: {len(failures)}/{n_trials}"
        )


@pytest.mark.slow
class TestMonteCarlo50PercentLoss:
    """Monte Carlo tests at 50% packet loss rate."""

    @pytest.mark.parametrize(
        "k_blocks,block_size,data_size,target_rate",
        [
            (10, 100, 800, 0.99),  # Small - 99% target (systematic helps)
            (20, 200, 3500, 0.85),  # Medium - 85% (2× effective redundancy is marginal)
        ],
    )
    def test_50_percent_loss_1000_trials(self, k_blocks, block_size, data_size, target_rate):
        """
        1000 trials at 50% loss - target varies by k_blocks.

        At 50% loss with 4× redundancy, receiver gets ~2× k droplets on average.
        This is marginal for LT codes (need ~1.5×k). Small k benefits from
        systematic optimization, larger k shows diminishing returns.
        """
        n_trials = 1000
        drop_rate = 0.50
        target_success_rate = target_rate

        success_rate, results = run_monte_carlo(
            n_trials=n_trials,
            data_size=data_size,
            k_blocks=k_blocks,
            block_size=block_size,
            drop_rate=drop_rate,
            max_attempts_multiplier=4.0,
        )

        # Calculate statistics
        received_counts = [r.droplets_received for r in results]
        avg_received = statistics.mean(received_counts)
        failures = [r for r in results if not r.success]

        print(f"\n--- 50% Loss Test (k={k_blocks}, bs={block_size}) ---")
        print(f"Trials: {n_trials}")
        print(f"Success rate: {success_rate:.4f} ({success_rate * 100:.2f}%)")
        print(f"Avg droplets received: {avg_received:.1f}")
        print(f"Failures: {len(failures)}")

        assert success_rate >= target_success_rate, (
            f"Success rate {success_rate:.4f} below target {target_success_rate}. "
            f"Failures: {len(failures)}/{n_trials}"
        )


@pytest.mark.slow
class TestMonteCarloExtreme:
    """Extreme loss scenarios to validate failure modes."""

    def test_70_percent_loss_graceful_degradation(self):
        """
        At 70% loss, success rate should still be reasonable (≥80%).

        This tests the graceful degradation of fountain codes under
        extreme conditions. Not a hard requirement but useful baseline.
        """
        n_trials = 500
        k_blocks = 10
        block_size = 100
        data_size = 800
        drop_rate = 0.70
        target_success_rate = 0.80  # 80% - more lenient

        success_rate, results = run_monte_carlo(
            n_trials=n_trials,
            data_size=data_size,
            k_blocks=k_blocks,
            block_size=block_size,
            drop_rate=drop_rate,
            max_attempts_multiplier=6.0,  # More redundancy for extreme loss
        )

        print(f"\n--- 70% Loss Extreme Test ---")
        print(f"Trials: {n_trials}")
        print(f"Success rate: {success_rate:.4f} ({success_rate * 100:.2f}%)")

        # This is informational - we expect degradation but not total failure
        assert (
            success_rate >= target_success_rate
        ), f"Success rate {success_rate:.4f} below {target_success_rate} at 70% loss"


class TestStatisticalProperties:
    """Tests for statistical properties of fountain codes."""

    def test_droplet_efficiency(self):
        """
        Verify that (1+ε)k droplets are typically sufficient.

        Per Luby FOCS 2002, ~1.5k droplets should suffice with high probability.
        We measure how many droplets are actually needed.
        """
        n_trials = 200
        k_blocks = 20
        block_size = 100
        data_size = 1800

        received_to_complete: List[int] = []

        for trial in range(n_trials):
            data = secrets.token_bytes(data_size)
            random.seed(trial * 42)

            encoder = FountainEncoder(data, k_blocks, block_size)
            decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))

            received = 0
            max_droplets = k_blocks * 5

            for _ in range(max_droplets):
                droplet = encoder.droplet()
                # No packet loss in this test
                decoder.add_droplet(droplet)
                received += 1

                if decoder.is_complete():
                    received_to_complete.append(received)
                    break

        assert len(received_to_complete) == n_trials, "Some trials didn't complete"

        avg_needed = statistics.mean(received_to_complete)
        max_needed = max(received_to_complete)
        efficiency = k_blocks / avg_needed  # Closer to 1.0 is better

        print(f"\n--- Droplet Efficiency Test ---")
        print(f"k_blocks: {k_blocks}")
        print(f"Avg droplets needed: {avg_needed:.2f}")
        print(f"Max droplets needed: {max_needed}")
        print(f"Efficiency ratio: {efficiency:.4f} (1.0 = optimal)")
        print(f"Overhead: {(avg_needed / k_blocks - 1) * 100:.1f}%")

        # With systematic optimization, first 2k are degree-1, so we should
        # complete near k_blocks with high probability
        assert (
            avg_needed <= k_blocks * 1.5
        ), f"Avg droplets needed ({avg_needed:.2f}) exceeds 1.5× k_blocks ({k_blocks * 1.5})"

    def test_decode_progress_monotonic(self):
        """
        Verify that decoded block count never decreases.

        This is a sanity check on the belief propagation implementation.
        """
        data = secrets.token_bytes(2000)
        k_blocks = 20
        block_size = 128

        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))

        prev_count = 0

        for _ in range(k_blocks * 3):
            droplet = encoder.droplet()
            decoder.add_droplet(droplet)

            current_count = decoder.decoded_count
            assert (
                current_count >= prev_count
            ), f"Decoded count decreased: {prev_count} -> {current_count}"
            prev_count = current_count

            if decoder.is_complete():
                break

        assert decoder.is_complete()


class TestFrameReorderAndDuplicates:
    """Tests for out-of-order and duplicate frame handling."""

    def test_out_of_order_frames(self):
        """
        Decoding should succeed even when frames arrive out of order.
        """
        n_trials = 100
        k_blocks = 15
        block_size = 100
        data_size = 1200

        successes = 0

        for trial in range(n_trials):
            data = secrets.token_bytes(data_size)
            random.seed(trial)

            encoder = FountainEncoder(data, k_blocks, block_size)
            decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))

            # Generate all droplets first
            droplets = encoder.generate_droplets(k_blocks * 2)

            # Shuffle order
            random.shuffle(droplets)

            # Add in shuffled order
            for droplet in droplets:
                decoder.add_droplet(droplet)
                if decoder.is_complete():
                    break

            if decoder.is_complete():
                decoded = decoder.get_data()
                if decoded == data:
                    successes += 1

        success_rate = successes / n_trials
        print(f"\n--- Out-of-Order Test ---")
        print(f"Success rate: {success_rate:.4f}")

        assert success_rate >= 0.99, f"Out-of-order success rate too low: {success_rate}"

    def test_duplicate_frames_handled(self):
        """
        Duplicate frames should be handled gracefully (as redundant).
        """
        n_trials = 100
        k_blocks = 10
        block_size = 100
        data_size = 800

        successes = 0

        for trial in range(n_trials):
            data = secrets.token_bytes(data_size)
            random.seed(trial)

            encoder = FountainEncoder(data, k_blocks, block_size)
            decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))

            # Generate droplets with duplicates
            droplets = encoder.generate_droplets(k_blocks * 2)

            # Inject duplicates: repeat random droplets
            duplicated = droplets.copy()
            for _ in range(k_blocks):
                dup_idx = random.randint(0, len(droplets) - 1)
                duplicated.append(droplets[dup_idx])

            random.shuffle(duplicated)

            # Add all (including duplicates)
            for droplet in duplicated:
                decoder.add_droplet(droplet)
                if decoder.is_complete():
                    break

            if decoder.is_complete():
                decoded = decoder.get_data()
                if decoded == data:
                    successes += 1

        success_rate = successes / n_trials
        print(f"\n--- Duplicate Frames Test ---")
        print(f"Success rate: {success_rate:.4f}")

        assert success_rate >= 0.99, f"Duplicate handling success rate too low: {success_rate}"


class TestEdgeCases:
    """Edge case tests for fountain codes."""

    def test_minimum_k_blocks(self):
        """Test with minimum viable k_blocks (k=2)."""
        n_trials = 100
        k_blocks = 2
        block_size = 50
        data_size = 80

        successes = 0

        for trial in range(n_trials):
            data = secrets.token_bytes(data_size)

            encoder = FountainEncoder(data, k_blocks, block_size)
            decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))

            for _ in range(k_blocks * 3):
                droplet = encoder.droplet()
                decoder.add_droplet(droplet)
                if decoder.is_complete():
                    break

            if decoder.is_complete():
                decoded = decoder.get_data()
                if decoded == data:
                    successes += 1

        assert successes == n_trials, f"k=2 failed {n_trials - successes} times"

    def test_single_block(self):
        """Test with k=1 (degenerate case)."""
        data = secrets.token_bytes(100)
        k_blocks = 1
        block_size = 128

        encoder = FountainEncoder(data, k_blocks, block_size)
        decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))

        droplet = encoder.droplet()
        decoder.add_droplet(droplet)

        assert decoder.is_complete()
        decoded = decoder.get_data()
        assert decoded == data

    def test_large_k_blocks(self):
        """Test with large k_blocks (k=100)."""
        n_trials = 10
        k_blocks = 100
        block_size = 100
        data_size = 9500

        for trial in range(n_trials):
            data = secrets.token_bytes(data_size)

            encoder = FountainEncoder(data, k_blocks, block_size)
            decoder = FountainDecoder(k_blocks, block_size, original_length=len(data))

            for _ in range(k_blocks * 2):
                droplet = encoder.droplet()
                decoder.add_droplet(droplet)
                if decoder.is_complete():
                    break

            assert decoder.is_complete(), f"Trial {trial} failed to complete"
            decoded = decoder.get_data()
            assert decoded == data, f"Trial {trial} data mismatch"
