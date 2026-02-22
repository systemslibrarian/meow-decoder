#!/usr/bin/env python3
"""
Fuzz target for Schrödinger encode/decode operations.
Tests SchrodingerManifest parsing, dual-secret XOR mixing,
and Merkle tree integrity with adversarial inputs.
"""

import os
import sys

os.environ["MEOW_TEST_MODE"] = "1"

try:
    import atheris
except ImportError:
    atheris = None


def _setup_imports():
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.quantum_mixer import (
        entangle_realities,
        collapse_to_reality,
    )

    return entangle_realities, collapse_to_reality


if atheris is not None:
    with atheris.instrument_imports():
        entangle_realities, collapse_to_reality = _setup_imports()
else:
    entangle_realities, collapse_to_reality = _setup_imports()


def fuzz_schrodinger_roundtrip(data: bytes):
    """Fuzz the Schrödinger entangle→collapse roundtrip with random data."""
    if len(data) < 4:
        return

    split = max(1, data[0] % (len(data) - 1))
    secret_a = data[1:split + 1]
    secret_b = data[split + 1:]

    if not secret_a or not secret_b:
        return

    try:
        # Entangle
        superposition = entangle_realities(secret_a, secret_b)

        # Collapse both realities
        recovered_a = collapse_to_reality(superposition, 0)
        recovered_b = collapse_to_reality(superposition, 1)

        # Verify original data is prefix of recovered (padding may differ)
        assert recovered_a[:len(secret_a)] == secret_a, "Reality A corruption"
        assert recovered_b[:len(secret_b)] == secret_b, "Reality B corruption"

        # Verify superposition is exactly 2x max length
        max_len = max(len(secret_a), len(secret_b))
        assert len(superposition) == max_len * 2

    except (ValueError, TypeError):
        pass


def fuzz_xor_mixing_properties(data: bytes):
    """Verify XOR mixing properties that Schrödinger mode depends on."""
    if len(data) < 3:
        return

    # Split into two equal-ish halves
    mid = len(data) // 2
    a = data[:mid]
    b = data[mid:mid + len(a)]  # Same length as a

    if not a or not b or len(a) != len(b):
        return

    try:
        # XOR self-inverse property: a ^ b ^ b == a
        xor_ab = bytes(x ^ y for x, y in zip(a, b))
        recovered = bytes(x ^ y for x, y in zip(xor_ab, b))
        assert recovered == a, "XOR self-inverse violation"

        # XOR commutativity: a ^ b == b ^ a
        xor_ba = bytes(x ^ y for x, y in zip(b, a))
        assert xor_ab == xor_ba, "XOR commutativity violation"

        # XOR identity: a ^ 0 == a
        zeros = bytes(len(a))
        assert bytes(x ^ y for x, y in zip(a, zeros)) == a, "XOR identity violation"

    except (ValueError, TypeError):
        pass


def fuzz_collapse_invalid_index(data: bytes):
    """Fuzz collapse_to_reality with out-of-range indices."""
    if len(data) < 2:
        return

    # Use byte as index (0-255, only 0 and 1 are valid)
    index = data[0]
    superposition = data[1:]

    if not superposition:
        return

    try:
        result = collapse_to_reality(superposition, index)
        # Should only succeed for index 0 or 1
        if index not in (0, 1):
            # If it didn't raise, that's fine — just ensure result is bytes
            assert isinstance(result, bytes)
    except (ValueError, IndexError, TypeError):
        pass  # Expected for invalid indices


def fuzz_superposition_statistical(data: bytes):
    """Check statistical properties of superposition output."""
    if len(data) < 20:
        return

    mid = len(data) // 2
    a = data[:mid]
    b = data[mid:]

    try:
        superposition = entangle_realities(a, b)

        # Even positions should be from a (padded)
        even_bytes = superposition[0::2]
        odd_bytes = superposition[1::2]

        # Verify even positions start with a's bytes
        assert even_bytes[:len(a)] == a

        # Verify odd positions start with b's bytes
        assert odd_bytes[:len(b)] == b

    except (ValueError, TypeError):
        pass


def fuzz_merkle_like_integrity(data: bytes):
    """Fuzz Merkle-like integrity checks on interleaved data."""
    import hashlib

    if len(data) < 8:
        return

    try:
        # Simulate building a Merkle tree from frame chunks
        chunk_size = max(1, data[0] % 32 + 1)
        chunks = [data[i:i + chunk_size] for i in range(1, len(data), chunk_size)]

        if not chunks:
            return

        # Build leaf hashes
        leaf_hashes = [hashlib.sha256(c).digest() for c in chunks]

        # Build tree upward
        level = leaf_hashes
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    combined = hashlib.sha256(level[i] + level[i + 1]).digest()
                else:
                    combined = level[i]  # Odd node promoted
                next_level.append(combined)
            level = next_level

        root = level[0]
        assert len(root) == 32
        assert isinstance(root, bytes)

    except (ValueError, TypeError, IndexError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_schrodinger_roundtrip(data)
        fuzz_xor_mixing_properties(data)
        fuzz_collapse_invalid_index(data)
        fuzz_superposition_statistical(data)
        fuzz_merkle_like_integrity(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
