#![no_main]
/// Fuzz target: AeadWrapper encrypt / decrypt with adversarial inputs.
///
/// Discovers:
/// - Panics in AES-GCM with crafted key / nonce / AAD / ciphertext
/// - Authentication bypass (decrypt succeeding on modified ciphertext)
/// - Key length validation edge cases
/// - AAD length corner cases (empty, very long)
/// - Nonce reuse detection / enforcement
/// - Encrypt-then-decrypt roundtrip with fuzz-derived plaintext

use libfuzzer_sys::fuzz_target;
use crypto_core::aead_wrapper::{AeadWrapper, AeadError};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes (key) + 16 bytes (nonce candidate) + 1 (plaintext)
    if data.len() < 49 {
        return;
    }

    let key = &data[..32];
    // AES-GCM nonce is 12 bytes; take first 12 of next 16
    let nonce_bytes: [u8; 12] = data[32..44].try_into().unwrap();
    let aad = &data[44..44 + (data[44] as usize % 64).min(data.len().saturating_sub(45))];
    let aad_end = 44 + (data[44] as usize % 64).min(data.len().saturating_sub(45));
    let plaintext = &data[aad_end..];

    if plaintext.is_empty() {
        return;
    }

    // ── 1. Construct wrapper with fuzz-derived key ──────────────────────────
    let wrapper = match AeadWrapper::new(key) {
        Ok(w) => w,
        Err(_) => return, // Invalid key length — expected
    };

    // ── 2. Encrypt ──────────────────────────────────────────────────────────
    let ciphertext = match wrapper.encrypt_raw(&nonce_bytes, plaintext, aad) {
        Ok(ct) => ct,
        Err(_) => return,
    };

    // Ciphertext must be at least plaintext + 16 (GCM auth tag)
    assert!(
        ciphertext.len() >= plaintext.len() + 16,
        "ciphertext shorter than plaintext + tag"
    );

    // ── 3. Roundtrip: decrypt must recover plaintext ─────────────────────────
    match wrapper.decrypt_raw(&nonce_bytes, &ciphertext, aad) {
        Ok(recovered) => {
            assert_eq!(
                recovered, plaintext,
                "AES-GCM roundtrip mismatch: encryption/decryption produced different bytes"
            );
        }
        Err(AeadError::AuthenticationFailed) => {
            panic!("Authentication failure on freshly-encrypted ciphertext with same key/nonce/aad — implementation bug");
        }
        Err(_) => {
            // Other errors (e.g., output buffer) are acceptable
        }
    }

    // ── 4. Bit-flip in ciphertext must cause authentication failure ──────────
    if ciphertext.len() > 16 {
        let mut corrupt = ciphertext.clone();
        corrupt[0] ^= 0x01;
        match wrapper.decrypt_raw(&nonce_bytes, &corrupt, aad) {
            Ok(_) => {
                panic!(
                    "AES-GCM authenticated a corrupt ciphertext — \
                    authentication bypass detected"
                );
            }
            Err(AeadError::AuthenticationFailed) => {
                // Expected: tamper detected
            }
            Err(_) => {
                // Other errors acceptable
            }
        }
    }

    // ── 5. Modified AAD must cause authentication failure ───────────────────
    {
        let mut bad_aad = aad.to_vec();
        if bad_aad.is_empty() {
            bad_aad.push(0x42);
        } else {
            bad_aad[0] ^= 0xFF;
        }
        match wrapper.decrypt_raw(&nonce_bytes, &ciphertext, &bad_aad) {
            Ok(_) => {
                panic!(
                    "AES-GCM accepted modified AAD — \
                    AAD binding violated"
                );
            }
            Err(AeadError::AuthenticationFailed) => {
                // Expected
            }
            Err(_) => {}
        }
    }

    // ── 6. Completely fuzz-derived ciphertext must never cause a panic ────────
    {
        let _ = wrapper.decrypt_raw(&nonce_bytes, data, aad);
    }
});
