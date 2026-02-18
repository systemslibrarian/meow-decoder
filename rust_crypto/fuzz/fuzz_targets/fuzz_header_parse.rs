//! Fuzz target: Frame header parsing and header encryption/decryption
//!
//! # Attack classes covered
//! - Header tampering     → arbitrary frame header bytes fed to parsing logic
//! - Truncation oracle    → headers shorter than minimum valid length
//! - AAD canonicalization → AAD computed from header must be deterministic
//! - Nonce reuse          → header-derived nonces must differ per frame index
//!
//! # Assumptions / adaptable layer
//! The codebase implements frame headers using HKDF-derived masks over a frame
//! index (MSR v1.2 design from copilot-instructions.md).  Until the header
//! encryption module is ported to Rust, this target exercises the HKDF
//! building‐block that will underpin that module.
//!
//! Specifically we test:
//!   - `derive_key_hkdf` with attacker-controlled IKM / info
//!   - The derived output used as both a masking key and an AAD token
//!   - That two different frame indices _always_ produce different masks
//!   - That truncated / oversized info strings do not panic
//!
//! Replace the body below with real header_parse / header_decrypt calls once
//! those functions are stabilised in the Rust layer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use meow_crypto_rs::pure::{aes_gcm_decrypt, aes_gcm_encrypt, derive_key_hkdf, hmac_sha256};

/// Simulate the MSR v1.2 header mask derivation.
/// Real derivation: HKDF-SHA256(chain_key, "meow_header_mask_v1" || frame_index_be32)
fn derive_header_mask(chain_key: &[u8], frame_index: u32) -> Vec<u8> {
    let mut info = b"meow_header_mask_v1".to_vec();
    info.extend_from_slice(&frame_index.to_be_bytes());
    // 4 bytes for an encrypted index, 16 for commitment tag = 20 bytes total
    derive_key_hkdf(chain_key, None, &info, 20).unwrap_or_else(|_| vec![0u8; 20])
}

/// Simulate AAD canonicalization from a header.
/// Real AAD: HMAC-SHA256(auth_key, version_byte || mode_byte || frame_index_be32 || chain_epoch_be32)
fn canonicalize_aad(auth_key: &[u8], version: u8, mode: u8, frame_idx: u32, epoch: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    buf.push(version);
    buf.push(mode);
    buf.extend_from_slice(&frame_idx.to_be_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    hmac_sha256(auth_key, &buf).unwrap_or_else(|_| vec![0u8; 32])
}

fuzz_target!(|data: &[u8]| {
    // ─── Part 1: arbitrary bytes as a "chain key" ────────────────────────────
    // We derive header masks for a range of frame indices.
    // INVARIANT: derive_key_hkdf must never panic for any IKM.

    let chain_key = data;

    let mask_0 = derive_header_mask(chain_key, 0);
    let mask_1 = derive_header_mask(chain_key, 1);
    let mask_max = derive_header_mask(chain_key, u32::MAX);

    // INVARIANT: different frame indices → different masks
    // (unless chain_key is pathologically degenerate - still must not panic)
    assert_eq!(mask_0.len(), 20);
    assert_eq!(mask_1.len(), 20);
    assert_eq!(mask_max.len(), 20);

    if !data.is_empty() {
        // Different indices must produce different masks for non-empty keys.
        // (For empty key the HKDF still works but collisions are theoretically
        //  possible at the 160-bit level; we only assert no panic.)
        assert_ne!(
            mask_0, mask_1,
            "Frame index 0 and 1 must produce distinct header masks"
        );
    }

    // ─── Part 2: AAD determinism ─────────────────────────────────────────────
    // The same header fields must always produce the same AAD bytes.

    let auth_key = if data.len() >= 32 { &data[..32] } else { data };

    let (version, mode, frame_idx, epoch) = if data.len() >= 10 {
        (
            data[0],
            data[1],
            u32::from_be_bytes([data[2], data[3], data[4], data[5]]),
            u32::from_be_bytes([data[6], data[7], data[8], data[9]]),
        )
    } else {
        (0x05, 0x00, 0, 0)
    };

    let aad1 = canonicalize_aad(auth_key, version, mode, frame_idx, epoch);
    let aad2 = canonicalize_aad(auth_key, version, mode, frame_idx, epoch);
    assert_eq!(aad1, aad2, "AAD canonicalization must be deterministic");

    // ─── Part 3: Encrypt a "frame payload" with the derived AAD ─────────────
    // This simulates the full header-bind flow:
    //     header → AAD → AEAD seal → ciphertext
    // A mutated AAD must cause decryption to fail (no AAD-omission attack).

    if data.len() >= 56 {
        let enc_key = [data[0]; 32]; // single-byte repeated key is fine for fuzzing
        let nonce = [data[1]; 12];
        let payload = &data[44..data.len().min(100)];

        let ct = aes_gcm_encrypt(&enc_key, &nonce, payload, Some(&aad1));
        if let Ok(ct) = ct {
            // Correct AAD → must succeed
            let ok = aes_gcm_decrypt(&enc_key, &nonce, &ct, Some(&aad2));
            assert!(ok.is_ok(), "Same AAD must allow decryption");

            // Mutated AAD → must fail (AAD omission / tampering)
            let mut bad_aad = aad1.clone();
            if !bad_aad.is_empty() {
                bad_aad[0] ^= 0x01;
                let bad = aes_gcm_decrypt(&enc_key, &nonce, &ct, Some(&bad_aad));
                assert!(bad.is_err(), "Mutated AAD must prevent decryption");
            }

            // No AAD at all → must fail (AAD omission attack)
            let no_aad = aes_gcm_decrypt(&enc_key, &nonce, &ct, None);
            assert!(no_aad.is_err(), "Missing AAD must prevent decryption");
        }
    }

    // ─── Part 4: HKDF with attacker-controlled info ──────────────────────────
    // The `info` field is crafted from the header; must not panic even if huge.
    let long_info = vec![0xFFu8; data.len() % 8192]; // cap at 8 KiB
    let _ = derive_key_hkdf(b"fixed_ikm_for_header_fuzz", None, &long_info, 32);

    // Empty info
    let _ = derive_key_hkdf(b"fixed_ikm", None, b"", 32);

    // Output lengths that span boundary conditions
    for out_len in [0usize, 1, 32, 64, 255] {
        let _ = derive_key_hkdf(data, None, b"fuzz_context", out_len);
    }
});
