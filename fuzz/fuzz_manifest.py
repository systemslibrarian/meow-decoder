#!/usr/bin/env python3
"""
Fuzz target for manifest parsing.
Uses Atheris (Google's Python fuzzing engine).
"""

import sys

try:
    import atheris
except ImportError:  # pragma: no cover - only used in fuzzing environments
    atheris = None


def _setup_imports():
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from meow_decoder.crypto import unpack_manifest, Manifest

    return unpack_manifest, Manifest


if atheris is not None:
    # Instrument modules before importing
    with atheris.instrument_imports():
        unpack_manifest, Manifest = _setup_imports()
else:
    unpack_manifest, Manifest = _setup_imports()


def fuzz_unpack_manifest(data: bytes):
    """Fuzz the manifest unpacking function."""
    try:
        manifest = unpack_manifest(data)

        # If we got a manifest, verify its fields are sane
        if manifest:
            assert isinstance(manifest.salt, bytes)
            assert isinstance(manifest.nonce, bytes)
            assert isinstance(manifest.orig_len, int)
            assert isinstance(manifest.comp_len, int)
            assert isinstance(manifest.cipher_len, int)
            assert isinstance(manifest.sha256, bytes)
            assert isinstance(manifest.block_size, int)
            assert isinstance(manifest.k_blocks, int)
            assert isinstance(manifest.hmac, bytes)

            # Check lengths
            assert len(manifest.salt) == 16
            assert len(manifest.nonce) == 12
            assert len(manifest.sha256) == 32
            assert len(manifest.hmac) == 32

            # Optional fields
            if manifest.ephemeral_public_key:
                assert len(manifest.ephemeral_public_key) == 32
            if manifest.pq_ciphertext:
                # MEOW5 (ML-KEM-768) = 1088 bytes; MEOW4 (ML-KEM-1024) = 1568 bytes
                assert len(manifest.pq_ciphertext) in (1088, 1568), (
                    f"Unexpected PQ ciphertext length: {len(manifest.pq_ciphertext)}"
                )

    except ValueError:
        # Expected for invalid input
        pass
    except AssertionError:
        # Our own assertions fired — re-raise so atheris records it as a crash
        raise
    except Exception as e:
        # Unexpected exceptions are bugs
        if "too short" in str(e).lower():
            pass  # Expected
        elif "invalid" in str(e).lower():
            pass  # Expected
        elif "wrong size" in str(e).lower():
            pass  # Expected (PQ ciphertext size validation)
        else:
            raise


def main():
    if atheris is None:
        raise RuntimeError("atheris is required to run fuzz targets")

    # Setup fuzzing
    atheris.Setup(sys.argv, fuzz_unpack_manifest)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
