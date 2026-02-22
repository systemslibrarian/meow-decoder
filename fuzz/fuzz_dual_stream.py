#!/usr/bin/env python3
"""
Fuzz target for dual-stream encoding/decoding.
Tests interleaved stream parsing, manifest deserialization,
and quantum_mixer operations with adversarial inputs.
"""

import os
import sys
import struct

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
        YARN_REALITY_A,
        YARN_REALITY_B,
    )
    from meow_decoder.dual_stream import DualStreamManifest

    return entangle_realities, collapse_to_reality, YARN_REALITY_A, YARN_REALITY_B, DualStreamManifest


if atheris is not None:
    with atheris.instrument_imports():
        entangle_realities, collapse_to_reality, YARN_REALITY_A, YARN_REALITY_B, DualStreamManifest = _setup_imports()
else:
    entangle_realities, collapse_to_reality, YARN_REALITY_A, YARN_REALITY_B, DualStreamManifest = _setup_imports()


def fuzz_entangle_realities(data: bytes):
    """Fuzz entangle_realities with random-length inputs."""
    if len(data) < 2:
        return

    split = data[0] % len(data)
    reality_a = data[1:split + 1]
    reality_b = data[split + 1:]

    if not reality_a or not reality_b:
        return

    try:
        superposition = entangle_realities(reality_a, reality_b)

        # Verify structural properties
        max_len = max(len(reality_a), len(reality_b))
        assert len(superposition) == max_len * 2, (
            f"Superposition length {len(superposition)} != 2 * {max_len}"
        )

        # Verify collapse recovers correct bytes
        collapsed_a = collapse_to_reality(superposition, YARN_REALITY_A)
        collapsed_b = collapse_to_reality(superposition, YARN_REALITY_B)

        assert len(collapsed_a) == max_len
        assert len(collapsed_b) == max_len

        # First len(reality_a) bytes of collapsed_a must match reality_a
        # (rest is random padding)
        assert collapsed_a[:len(reality_a)] == reality_a

        # First len(reality_b) bytes of collapsed_b must match reality_b
        assert collapsed_b[:len(reality_b)] == reality_b

    except (ValueError, TypeError):
        pass  # Expected for edge-case inputs


def fuzz_collapse_to_reality(data: bytes):
    """Fuzz collapse_to_reality with arbitrary data and indices."""
    if len(data) < 2:
        return

    reality_index = data[0] % 4  # 0, 1 are valid; 2, 3 test invalid

    try:
        result = collapse_to_reality(data[1:], reality_index)
        if reality_index in (0, 1):
            # Valid index: result should be half the length (rounded)
            expected_len = len(data[1:]) // 2 + (
                len(data[1:]) % 2 if reality_index == 0 else 0
            )
            assert isinstance(result, bytes)
    except (ValueError, IndexError, TypeError):
        pass  # Expected for invalid indices or empty input


def fuzz_dual_stream_manifest_unpack(data: bytes):
    """Fuzz DualStreamManifest deserialization from raw bytes."""
    if len(data) < 10:
        return

    try:
        # Try to interpret fuzzed data as a manifest
        if len(data) >= 382:
            # Attempt to parse the wire format manually
            magic = data[:4]
            if magic != b"MEOW":
                return  # Skip obviously invalid

            version = data[4]
            flags = data[5]

            salt_a = data[6:22]
            salt_b = data[22:38]
            nonce_a = data[38:50]
            nonce_b = data[50:62]
            hmac_a = data[62:94]
            hmac_b = data[94:126]
            metadata_a = data[126:230]
            metadata_b = data[230:334]

            if len(data) >= 354:
                block_count, block_size, superposition_len, target_frames = struct.unpack(
                    ">IIQI", data[334:354]
                )

                manifest = DualStreamManifest(
                    salt_a=salt_a,
                    salt_b=salt_b,
                    nonce_a=nonce_a,
                    nonce_b=nonce_b,
                    hmac_a=hmac_a,
                    hmac_b=hmac_b,
                    metadata_a=metadata_a,
                    metadata_b=metadata_b,
                    block_count=block_count,
                    block_size=block_size,
                    superposition_len=superposition_len,
                    target_frames=target_frames,
                    magic=magic,
                    version=version,
                    flags=flags,
                )

                # Verify pack_core_for_auth doesn't crash
                core = manifest.pack_core_for_auth()
                assert isinstance(core, bytes)
                assert len(core) > 0

    except (struct.error, ValueError, TypeError, OverflowError):
        pass  # Expected for malformed data
    except Exception as e:
        error_msg = str(e).lower()
        if any(x in error_msg for x in ["manifest", "invalid", "short", "overflow"]):
            pass
        else:
            raise


def fuzz_entangle_empty_edge(data: bytes):
    """Edge case: one or both realities are very short."""
    try:
        # Single byte realities
        a = data[:1] if len(data) >= 1 else b"\x00"
        b_data = data[1:2] if len(data) >= 2 else b"\x00"

        result = entangle_realities(a, b_data)
        assert len(result) == 2  # max(1, 1) * 2

        # Large disparity in sizes
        if len(data) > 10:
            short = data[:1]
            long = data[1:]
            result2 = entangle_realities(short, long)
            assert len(result2) == len(long) * 2

    except (ValueError, TypeError):
        pass


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    def combined_fuzz(data: bytes):
        fuzz_entangle_realities(data)
        fuzz_collapse_to_reality(data)
        fuzz_dual_stream_manifest_unpack(data)
        fuzz_entangle_empty_edge(data)

    atheris.Setup(sys.argv, combined_fuzz)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
