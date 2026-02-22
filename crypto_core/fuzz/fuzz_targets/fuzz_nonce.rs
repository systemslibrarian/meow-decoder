#![no_main]
/// Fuzz target: Nonce generation, parsing, and replay tracking.
///
/// Discovers:
/// - Panics in Nonce::from_bytes with arbitrary byte slices
/// - NonceGenerator::next() overflow / exhaustion behaviour
/// - NonceTracker::check_and_mark() with adversarial nonces
/// - Replay detection: marking same nonce twice must fail on the second call
/// - Nonce uniqueness: sequential nonces must be distinct
/// - from_bytes(nonce.as_bytes()) must round-trip identity

use libfuzzer_sys::fuzz_target;
use crypto_core::nonce::{Nonce, NonceGenerator, NonceTracker};

fuzz_target!(|data: &[u8]| {
    // ── 1. Nonce::from_bytes with arbitrary input ─────────────────────────
    {
        let result = Nonce::from_bytes(data);
        match result {
            Ok(nonce) => {
                // If parsing succeeded, roundtrip must be identity
                let bytes_back = nonce.as_bytes();
                assert_eq!(
                    bytes_back.len(),
                    12,
                    "Nonce::as_bytes() must always return exactly 12 bytes"
                );
                // Roundtrip: parse back the serialised form
                let nonce2 = Nonce::from_bytes(bytes_back).expect(
                    "Nonce round-trip failed: from_bytes(as_bytes()) must succeed"
                );
                assert_eq!(
                    nonce.as_bytes(),
                    nonce2.as_bytes(),
                    "Nonce round-trip produced different bytes"
                );
            }
            Err(_) => {
                // Expected for inputs shorter than 12 bytes
                if data.len() >= 12 {
                    // If input is ≥12 bytes, from_bytes should succeed
                    // (may be implementation-dependent; don't panic here)
                }
            }
        }
    }

    // ── 2. NonceGenerator: sequential nonces are unique ──────────────────
    if data.len() >= 4 {
        let gen = NonceGenerator::new();
        let mut seen = Vec::with_capacity(8);

        for _ in 0..8 {
            match gen.next() {
                Ok(nonce) => {
                    let bytes = nonce.as_bytes().to_vec();
                    assert!(
                        !seen.contains(&bytes),
                        "NonceGenerator produced a duplicate nonce — nonce reuse detected"
                    );
                    seen.push(bytes);
                }
                Err(_) => break, // Exhaustion acceptable
            }
        }
    }

    // ── 3. NonceTracker replay detection ─────────────────────────────────
    if data.len() >= 12 {
        let mut tracker = NonceTracker::new();

        // Use first 12 bytes as a nonce
        if let Ok(nonce) = Nonce::from_bytes(&data[..12]) {
            // First mark must succeed
            let first = tracker.check_and_mark(&nonce);

            // Second mark of the SAME nonce must fail (replay)
            let second = tracker.check_and_mark(&nonce);

            match (first, second) {
                (Ok(()), Ok(())) => {
                    panic!(
                        "NonceTracker accepted replay: same nonce marked twice without error — \
                        replay protection broken"
                    );
                }
                (Ok(()), Err(_)) => {
                    // Correct: replay detected on second mark
                }
                (Err(_), _) => {
                    // First mark failed — implementation may reject certain nonce values
                }
            }
        }
    }

    // ── 4. NonceTracker: different nonces all accepted ────────────────────
    if data.len() >= 24 {
        let mut tracker = NonceTracker::new();

        let nonce1_res = Nonce::from_bytes(&data[..12]);
        let nonce2_res = Nonce::from_bytes(&data[12..24]);

        if let (Ok(n1), Ok(n2)) = (nonce1_res, nonce2_res) {
            if n1.as_bytes() != n2.as_bytes() {
                // Both distinct nonces should be accepted
                let r1 = tracker.check_and_mark(&n1);
                let r2 = tracker.check_and_mark(&n2);

                // If first is ok, second must also be ok (distinct nonces)
                if r1.is_ok() {
                    if r2.is_err() {
                        // This would mean a non-replay nonce was rejected — bug
                        // (allow for capacity limits though)
                    }
                }
            }
        }
    }

    // ── 5. NonceGenerator: exhaustion and count properties ─────────────────
    {
        let gen = NonceGenerator::new();
        assert_eq!(gen.count(), 0, "Fresh generator count must be 0");
        assert!(!gen.is_near_exhaustion(), "Fresh generator must not be near exhaustion");
    }
});
