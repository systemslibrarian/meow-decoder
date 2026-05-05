# Fountain Code Golden Vectors

Reference outputs of the Python LT encoder
(`meow_decoder.fountain.FountainEncoder`) for a frozen set of
`(k_blocks, block_size, seed)` tuples. They serve as the cross-language
acceptance bar for the Rust + WASM fountain unification — see
`docs/FOUNTAIN_RUST_WASM_MIGRATION.md`.

**Do not regenerate these casually.** Regenerating means previously-
encoded GIFs encoded by a different RNG / distribution implementation
will no longer decode — every existing recipient becomes a broken
recipient. The migration plan documents the conditions under which
regeneration is acceptable.

## Layout

* `manifest.json` — index. Each entry pins `k_blocks`, `block_size`,
  `seed`, the resulting `block_indices` list, and an `sha256` prefix
  of the data section. Format `version` is locked; bumping it is a
  breaking change.
* `k<K>_b<BS>_s<SEED>.bin` — one file per vector, in the wire format
  documented below.

## Wire format

```text
seed:           u64  little-endian
block_count:    u16  little-endian
block_indices: [u16; block_count] little-endian
data:          [u8;  block_size]
```

Total size = `8 + 2 + 2*block_count + block_size` bytes.

## Source data

The source bytes that the encoder XORs over are deterministic:

```python
source = bytes(((i * 31 + 17) & 0xFF) for i in range(k_blocks * block_size))
```

This pattern is duplicated in `scripts/dev/generate_fountain_golden_vectors.py`
and the regression test `tests/test_fountain_golden_vectors.py`. The
Rust port must reproduce the same pattern in its own test fixtures.

## Regenerating

From repo root:

```bash
python scripts/dev/generate_fountain_golden_vectors.py
```

After regeneration, `tests/test_fountain_golden_vectors.py` should
still pass. If it does not, the algorithm changed and the change must
be documented in the migration plan and accompanied by a major
version bump.

## Why these specific tuples?

Coverage matrix:

| `k_blocks` | rationale |
|---:|---|
| 2 | smallest sane fountain — exercises the systematic-droplet branch (`seed < 2*k`). |
| 10 | typical small-payload encoding. |
| 100 | typical medium-payload encoding. |
| 1000 | the largest supported `k_blocks` — exercises the Robust Soliton tail of the distribution. |

For each `k`, multiple `seed` values exercise both the systematic
branch (seeds < `2*k_blocks`) and the rng-driven branch (seeds ≥
`2*k_blocks`), and a few large seeds in the rng path to surface
distribution drift if any.

`block_size` scales modestly with `k` to keep total file size below
350KB even for the largest vector.
