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


# Constants for yarn metaphor
YARN_REALITY_A = 0  # Red yarn - first reality
YARN_REALITY_B = 1  # Blue yarn - second reality
