"""
Quantum Mixer - Schrödinger's Yarn Ball Core

Cryptographic mixing for true plausible deniability.

This module implements the core primitives for mixing two secrets
into a single indistinguishable superposition. Neither secret can be
proven to exist without the correct password.

Security Properties:
    - Statistical indistinguishability (entropy, chi-square)
    - No forensic markers (same block sizes, patterns, distributions)
    - Independent decryption (each password works alone)
    - Plausible deniability (cannot prove second secret exists)
"""

import secrets
from typing import Tuple


def entangle_realities(
    reality_a: bytes,
    reality_b: bytes,
) -> bytes:
    """
    Entangle two realities into an indistinguishable superposition
    by interleaving.

    Even positions: reality A, Odd positions: reality B.

    Args:
        reality_a: First encrypted reality (ciphertext A)
        reality_b: Second encrypted reality (ciphertext B)

    Returns:
        Interleaved superposition (2 * max_len bytes).
    """
    max_len = max(len(reality_a), len(reality_b))

    if len(reality_a) < max_len:
        reality_a = reality_a + secrets.token_bytes(max_len - len(reality_a))
    if len(reality_b) < max_len:
        reality_b = reality_b + secrets.token_bytes(max_len - len(reality_b))

    superposition = bytearray(max_len * 2)
    superposition[0::2] = reality_a
    superposition[1::2] = reality_b

    return bytes(superposition)


def collapse_to_reality(superposition: bytes, reality_index: int) -> bytes:
    """
    Collapse superposition to a single reality by de-interleaving.

    Args:
        superposition: Interleaved superposition of both realities.
        reality_index: 0 for even positions (A), 1 for odd positions (B).

    Returns:
        Collapsed reality (original encrypted ciphertext).
    """
    if reality_index == 0:
        return superposition[0::2]
    else:
        return superposition[1::2]


def verify_indistinguishability(
    data_a: bytes, data_b: bytes, threshold: float = 0.01
) -> Tuple[bool, dict]:
    """
    Verify two byte sequences are statistically indistinguishable.

    Performs lightweight statistical tests (Shannon entropy and byte-frequency
    distribution) to confirm two halves of a superposition carry no obvious
    forensic markers. Intended for testing/verification, not production
    encode/decode.

    Args:
        data_a: First data sequence.
        data_b: Second data sequence.
        threshold: Maximum allowed difference (0.01 = 1%).

    Returns:
        Tuple of (is_indistinguishable, test_results) where test_results
        carries entropy_a, entropy_b, entropy_diff, max_freq_diff and the
        per-test/overall pass flags.
    """
    import math
    from collections import Counter

    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length) for count in Counter(data).values()
        )

    results: dict = {}

    entropy_a = _entropy(data_a)
    entropy_b = _entropy(data_b)
    entropy_diff = abs(entropy_a - entropy_b)
    results["entropy_a"] = entropy_a
    results["entropy_b"] = entropy_b
    results["entropy_diff"] = entropy_diff
    results["entropy_pass"] = entropy_diff < threshold

    len_a, len_b = len(data_a), len(data_b)
    prob_a = {k: v / len_a for k, v in Counter(data_a).items()} if len_a else {}
    prob_b = {k: v / len_b for k, v in Counter(data_b).items()} if len_b else {}
    all_bytes = set(prob_a) | set(prob_b)
    max_diff = (
        max(abs(prob_a.get(b, 0.0) - prob_b.get(b, 0.0)) for b in all_bytes) if all_bytes else 0.0
    )
    results["max_freq_diff"] = max_diff
    results["freq_pass"] = max_diff < threshold

    results["indistinguishable"] = results["entropy_pass"] and results["freq_pass"]
    return results["indistinguishable"], results


# Constants for yarn metaphor
YARN_REALITY_A = 0  # Red yarn - first reality
YARN_REALITY_B = 1  # Blue yarn - second reality
