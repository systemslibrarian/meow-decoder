"""
Generate fountain-code golden vectors from the current Python encoder.

These vectors form the acceptance criteria for the Rust + WASM
unification (see ``docs/FOUNTAIN_RUST_WASM_MIGRATION.md`` Phase 0).

Run from repo root:

    python scripts/dev/generate_fountain_golden_vectors.py

The script writes:

* ``tests/golden/fountain/<k>_<bs>_<seed>.bin`` — one binary droplet
  per (k_blocks, block_size, seed) tuple, in the wire format documented
  in the migration plan.
* ``tests/golden/fountain/manifest.json`` — index with metadata so the
  regression test can validate every vector.

Re-run only if you have a deliberate reason to regenerate (e.g.
adopting a new RNG). Re-running invalidates every previously-encoded
GIF; do not do this lightly.
"""

import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from meow_decoder.fountain import FountainEncoder  # noqa: E402

OUT_DIR = REPO / "tests" / "golden" / "fountain"

# Carefully-chosen tuples covering small/medium/large k and block_size.
# total_size = k_blocks * block_size; the source data is a deterministic
# byte pattern so the generator is reproducible. See the migration plan
# for rationale on the chosen ranges.
VECTORS = [
    # (k_blocks, block_size, seed)
    (2, 32, 0),
    (2, 32, 1),
    (2, 32, 7),
    (10, 64, 0),
    (10, 64, 5),
    (10, 64, 21),
    (10, 64, 100),
    (100, 128, 0),
    (100, 128, 50),
    (100, 128, 199),
    (100, 128, 1000),
    (1000, 256, 0),
    (1000, 256, 999),
    (1000, 256, 1999),
    (1000, 256, 5000),
    (1000, 256, 12345),
]


def make_source(total_size: int) -> bytes:
    """Deterministic source bytes derived from total_size — keeps the
    generator reproducible without shipping a 256MB blob.

    Pattern: bytes are ``(i * 31 + 17) mod 256`` — fast to verify
    in the Rust port and unlikely to coincide with any natural data.
    """
    return bytes(((i * 31 + 17) & 0xFF) for i in range(total_size))


def droplet_to_wire(droplet) -> bytes:
    """Serialise a droplet to the production wire format. Mirrors
    `meow_decoder.fountain.pack_droplet`.

    seed:        u32 BIG-endian
    block_count: u16 BIG-endian
    block_indices: [u16; block_count] BIG-endian
    data:        [u8; block_size]
    """
    head = struct.pack(">IH", droplet.seed, len(droplet.block_indices))
    indices = struct.pack(f">{len(droplet.block_indices)}H", *droplet.block_indices)
    return head + indices + droplet.data


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"format_version": 1, "vectors": []}

    for k_blocks, block_size, seed in VECTORS:
        total_size = k_blocks * block_size
        source = make_source(total_size)
        encoder = FountainEncoder(source, k_blocks, block_size)
        droplet = encoder.droplet(seed=seed)

        # Defensive: verify the encoder respects the seed parameter.
        if droplet.seed != seed:
            raise RuntimeError(
                f"encoder reset seed: requested {seed}, got {droplet.seed}"
            )

        wire = droplet_to_wire(droplet)
        fname = f"k{k_blocks}_b{block_size}_s{seed}.bin"
        (OUT_DIR / fname).write_bytes(wire)

        manifest["vectors"].append(
            {
                "file": fname,
                "k_blocks": k_blocks,
                "block_size": block_size,
                "seed": seed,
                "total_size": total_size,
                "block_indices": list(droplet.block_indices),
                "data_sha256_prefix": _sha256_prefix(droplet.data),
                "wire_size": len(wire),
            }
        )

    (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Wrote {len(manifest['vectors'])} golden vectors to {OUT_DIR}")


def _sha256_prefix(data: bytes) -> str:
    """First 16 hex chars of sha256(data) — short fingerprint for the
    manifest. Full data lives in the .bin file; this is just a quick-
    check value the regression test can dump on failure."""
    import hashlib

    return hashlib.sha256(data).hexdigest()[:16]


if __name__ == "__main__":
    main()
