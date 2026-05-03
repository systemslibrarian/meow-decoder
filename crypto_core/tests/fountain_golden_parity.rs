//! Phase 1f acceptance test: byte-identical parity against the 16
//! Python-generated fountain golden vectors under
//! `tests/golden/fountain/*.bin` (one directory up, in the workspace
//! root).
//!
//! See `docs/FOUNTAIN_RUST_WASM_MIGRATION.md` for the migration plan
//! and `tests/golden/fountain/README.md` for the wire format and
//! source-data convention.
//!
//! If this test passes, the Rust encoder produces droplets bit-for-bit
//! identical to the Python encoder for every (k, block_size, seed)
//! tuple in the golden manifest. That's the cross-language acceptance
//! bar for Phases 2 (PyO3) and 3 (WASM).

#![cfg(feature = "fountain")]

use crypto_core::meow_fountain::encoder::FountainEncoder;
use crypto_core::meow_fountain::wire::Droplet;

/// Walk up from this crate's root to the workspace root so we can
/// load the shared golden-vector fixtures.
fn workspace_root() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // pop "crypto_core" → workspace root
    p
}

/// Mirror of `_make_source` in
/// `scripts/dev/generate_fountain_golden_vectors.py` and
/// `tests/test_fountain_golden_vectors.py`. Must stay byte-identical.
fn make_source(total_size: usize) -> Vec<u8> {
    (0..total_size)
        .map(|i| ((i.wrapping_mul(31).wrapping_add(17)) & 0xFF) as u8)
        .collect()
}

/// Manifest entry shape — minimum fields needed to drive a parity check.
#[derive(serde::Deserialize)]
struct Vector {
    file: String,
    k_blocks: usize,
    block_size: usize,
    seed: u32,
    total_size: usize,
    block_indices: Vec<u16>,
}

#[derive(serde::Deserialize)]
struct Manifest {
    format_version: u32,
    vectors: Vec<Vector>,
}

#[test]
fn rust_encoder_matches_all_golden_vectors() {
    let root = workspace_root();
    let manifest_path = root.join("tests/golden/fountain/manifest.json");
    let manifest_json = match std::fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            // If the fixtures aren't checked out (e.g. partial clone),
            // skip rather than fail. The Python-side regression test
            // covers the same surface and runs under different CI
            // conditions.
            eprintln!(
                "fountain golden vectors not present at {}: {}; skipping",
                manifest_path.display(),
                e
            );
            return;
        }
    };
    let manifest: Manifest = serde_json::from_str(&manifest_json).expect("manifest.json parses");
    assert_eq!(manifest.format_version, 1, "manifest format version");

    let mut failed = Vec::new();
    let mut checked = 0usize;

    for v in &manifest.vectors {
        let source = make_source(v.total_size);
        let enc =
            FountainEncoder::new(&source, v.k_blocks, v.block_size).expect("encoder construction");
        let droplet: Droplet = enc.droplet(v.seed);
        let actual_wire = droplet.to_wire();

        let golden_path = root.join("tests/golden/fountain").join(&v.file);
        let expected_wire = std::fs::read(&golden_path)
            .unwrap_or_else(|e| panic!("read {}: {}", golden_path.display(), e));

        if actual_wire != expected_wire {
            failed.push(format!(
                "{}: rust ≠ python (k={}, b={}, seed={}, indices got={:?} want={:?})",
                v.file, v.k_blocks, v.block_size, v.seed, droplet.block_indices, v.block_indices
            ));
        }
        checked += 1;
    }

    assert!(checked >= 16, "expected ≥ 16 vectors, checked {checked}");
    assert!(
        failed.is_empty(),
        "Rust encoder diverged from Python on {} of {} golden vectors:\n{}",
        failed.len(),
        checked,
        failed.join("\n")
    );
}
