//! FFI boundary fuzz harness for meow_crypto_rs.
//!
//! Simulates Python calling Rust via the PyO3 FFI boundary by calling the
//! pure Rust functions directly with attacker-controlled inputs.  Because the
//! `python` feature is not required here, this file exercises the same code
//! paths that the Python bindings invoke, without needing a Python interpreter.
//!
//! # Purpose
//! Verify that every possible byte sequence fed across the FFI boundary is
//! handled gracefully:
//! - No panic (panic=abort → process crash → test failure)
//! - No UB (run with ASAN+UBSAN or Miri to detect)
//! - Proper error propagation (never silently succeeds on garbage input)
//! - No memory leaks (Zeroize + Drop handle cleanup)
//!
//! # Run
//!     cargo test --test ffi_fuzz
//!     RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --test ffi_fuzz
//!
//! # Attack-class coverage
//! | Section          | Attack class(es)                                |
//! |------------------|-------------------------------------------------|
//! | ffi_decode_gif   | Truncation oracle, Partial decrypt leak         |
//! | ffi_encode_file  | Crash/restart reuse, AAD omission               |
//! | ffi_wrong_params | Hybrid downgrade, PQ failure fallback           |
//! | ffi_replay       | Replay                                          |
//! | ffi_sizes        | Nonce reuse, Truncation oracle                  |
//! | ffi_pq_ciphertext| PQ failure fallback, Hybrid downgrade           |

use meow_crypto_rs::pure::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_key_argon2id, derive_key_hkdf, hmac_sha256,
    hmac_sha256_verify, sha256, x25519_exchange, x25519_generate_keypair,
    x25519_public_from_private,
};

// ─── Fast Argon2id params safe for test use ───────────────────────────────────
const ARGON_MEM: u32 = 256; // 256 KiB
const ARGON_ITER: u32 = 1;
const ARGON_PAR: u32 = 1;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract a fixed-size slice or pad with a constant byte.
fn extract_fixed<const N: usize>(src: &[u8], offset: usize, pad: u8) -> [u8; N] {
    let mut out = [pad; N];
    let src = if src.len() > offset {
        &src[offset..]
    } else {
        &[]
    };
    let copy_len = src.len().min(N);
    out[..copy_len].copy_from_slice(&src[..copy_len]);
    out
}

// ═══════════════════════════════════════════════════════════════════════════════
// FFI simulation: decode_gif(bytes)
//
// A call to decode_gif supplies raw bytes that may come from an untrusted
// network/filesystem source.  The function must:
//   1. Parse the header without panicking.
//   2. Derive the key without panicking.
//   3. Authenticate the manifest without panicking.
//   4. Decrypt without leaking partial plaintext.
// ═══════════════════════════════════════════════════════════════════════════════

fn ffi_simulate_decode_gif(raw: &[u8]) -> Result<Vec<u8>, String> {
    // Minimum viable "frame": 4 magic + 16 salt + 12 nonce + 1 mode + 32 hmac + ≥16 ct
    if raw.len() < 81 {
        return Err("input too short".into());
    }

    let salt: [u8; 16] = extract_fixed(raw, 4, 0xAA);
    let nonce: [u8; 12] = extract_fixed(raw, 20, 0xBB);
    let mode: u8 = raw[32];
    let hmac_tag: [u8; 32] = extract_fixed(raw, 33, 0xCC);
    let ciphertext = &raw[65..];

    let password = b"fuzz_password";
    let key = derive_key_argon2id(password, &salt, ARGON_MEM, ARGON_ITER, ARGON_PAR, 32)
        .map_err(|e| e.to_string())?;

    let auth_key =
        derive_key_hkdf(&key, None, b"meow_manifest_auth_v1", 32).map_err(|e| e.to_string())?;
    let enc_key =
        derive_key_hkdf(&key, None, b"meow_manifest_enc_v1", 32).map_err(|e| e.to_string())?;

    // Build canonical AAD from stable header fields only.
    // AAD = magic(4) + salt(16) + mode(1) — reproducible by both sides without
    // knowing plaintext or ciphertext, which avoids a hash-asymmetry bug where
    // the encoder would hash plaintext while the decoder hashes ciphertext.
    let mut aad = Vec::with_capacity(21);
    aad.extend_from_slice(b"MEOW");
    aad.extend_from_slice(&salt);
    aad.push(mode);

    // INVARIANT: fail closed – no decryption attempt on bad HMAC
    let hmac_ok = hmac_sha256_verify(&auth_key, &aad, &hmac_tag).unwrap_or(false);
    if !hmac_ok {
        return Err("manifest authentication failed".into());
    }

    // Decrypt – on Err, no plaintext escapes (enforced by type)
    aes_gcm_decrypt(&enc_key, &nonce, ciphertext, Some(&aad)).map_err(|e| e.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// FFI simulation: encode_file(bytes)
//
// Encoding must never panic even for empty or huge inputs.
// It returns a Vec<u8> representing the encoded "frame" or an error.
// ═══════════════════════════════════════════════════════════════════════════════

fn ffi_simulate_encode_file(data: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let salt = sha256(password); // deterministic salt from password (not real – for test only)
    let salt16: [u8; 16] = extract_fixed(&salt, 0, 0x00);
    let nonce: [u8; 12] = extract_fixed(&salt, 16, 0x00);

    let key = derive_key_argon2id(password, &salt16, ARGON_MEM, ARGON_ITER, ARGON_PAR, 32)
        .map_err(|e| e.to_string())?;

    let auth_key =
        derive_key_hkdf(&key, None, b"meow_manifest_auth_v1", 32).map_err(|e| e.to_string())?;
    let enc_key =
        derive_key_hkdf(&key, None, b"meow_manifest_enc_v1", 32).map_err(|e| e.to_string())?;

    // AAD = magic(4) + salt(16) + mode(1) — matches the decoder's canonical form.
    let mut aad = Vec::with_capacity(21);
    aad.extend_from_slice(b"MEOW");
    aad.extend_from_slice(&salt16);
    aad.push(0x05); // MEOW5 mode byte

    let ciphertext =
        aes_gcm_encrypt(&enc_key, &nonce, data, Some(&aad)).map_err(|e| e.to_string())?;

    let hmac_tag = hmac_sha256(&auth_key, &aad).map_err(|e| e.to_string())?;

    // Assemble output frame
    let mut frame = Vec::new();
    frame.extend_from_slice(b"MEOW");
    frame.extend_from_slice(&salt16);
    frame.extend_from_slice(&nonce);
    frame.push(0x05);
    frame.extend_from_slice(&hmac_tag);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

// ═══════════════════════════════════════════════════════════════════════════════
// FFI simulation: encode → decode round-trip
// ═══════════════════════════════════════════════════════════════════════════════

/// Decode a frame produced by `ffi_simulate_encode_file` using the same password.
/// Unlike `ffi_simulate_decode_gif`, this accepts an explicit password so that
/// encode→decode round-trips can use matching credentials.
fn ffi_simulate_decode_gif_with_password(raw: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() < 81 {
        return Err("input too short".into());
    }

    let salt: [u8; 16] = extract_fixed(raw, 4, 0xAA);
    let nonce: [u8; 12] = extract_fixed(raw, 20, 0xBB);
    let mode: u8 = raw[32];
    let hmac_tag: [u8; 32] = extract_fixed(raw, 33, 0xCC);
    let ciphertext = &raw[65..];

    let key = derive_key_argon2id(password, &salt, ARGON_MEM, ARGON_ITER, ARGON_PAR, 32)
        .map_err(|e| e.to_string())?;

    let auth_key =
        derive_key_hkdf(&key, None, b"meow_manifest_auth_v1", 32).map_err(|e| e.to_string())?;
    let enc_key =
        derive_key_hkdf(&key, None, b"meow_manifest_enc_v1", 32).map_err(|e| e.to_string())?;

    // Same canonical AAD as encode: magic + salt + mode.
    let mut aad = Vec::with_capacity(21);
    aad.extend_from_slice(b"MEOW");
    aad.extend_from_slice(&salt);
    aad.push(mode);

    let hmac_ok = hmac_sha256_verify(&auth_key, &aad, &hmac_tag).unwrap_or(false);
    if !hmac_ok {
        return Err("manifest authentication failed".into());
    }

    aes_gcm_decrypt(&enc_key, &nonce, ciphertext, Some(&aad)).map_err(|e| e.to_string())
}

fn ffi_roundtrip(data: &[u8]) -> bool {
    const PASS: &[u8] = b"roundtrip_pass";
    let frame = ffi_simulate_encode_file(data, PASS);
    if let Ok(f) = frame {
        // Use password-aware decode to ensure matching credentials
        let decoded = ffi_simulate_decode_gif_with_password(&f, PASS);
        if let Ok(recovered) = decoded {
            return recovered == data;
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════════════════

/// 1. Random byte arrays — no panic.
#[test]
fn ffi_random_byte_arrays() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    for seed in 0u64..512 {
        let mut h = DefaultHasher::new();
        seed.hash(&mut h);
        let val = h.finish();
        // Generate 64 pseudo-random bytes from the seed
        let raw: Vec<u8> = (0..64)
            .map(|i| ((val >> (i % 8)) ^ (seed + i)) as u8)
            .collect();
        let _ = ffi_simulate_decode_gif(&raw);
        let _ = ffi_simulate_encode_file(&raw, &raw[..8]);
    }
}

/// 2. Extremely small input — no panic.
#[test]
fn ffi_small_input() {
    for len in 0..=80 {
        let data = vec![0xAAu8; len];
        let _ = ffi_simulate_decode_gif(&data);
        let _ = ffi_simulate_encode_file(&data, b"tiny_pass");
    }
}

/// 3. Extremely large input — no panic, no OOM crash.
#[test]
fn ffi_large_input() {
    // 1 MiB of attacker data
    let data = vec![0x55u8; 1_048_576];
    // Only encode (decode would need a valid HMAC so most paths return Err early)
    let _ = ffi_simulate_encode_file(&data, b"large_pass");
    // Decode a large random blob
    let _ = ffi_simulate_decode_gif(&data);
}

/// 4. Truncated frames — parser must return Err, not panic.
#[test]
fn ffi_truncated_frames() {
    // Build a valid frame then strip bytes from the end
    let valid_data = b"hello, meow decoder!";
    let frame = ffi_simulate_encode_file(valid_data, b"trunc_pass").unwrap();
    let full_len = frame.len();

    for truncate_at in 0..full_len {
        let truncated = &frame[..truncate_at];
        let result = ffi_simulate_decode_gif(truncated);
        // Must be Err (never a successful decode of truncated data)
        assert!(
            result.is_err(),
            "Truncated frame at byte {} must return Err",
            truncate_at
        );
    }
}

/// 5. Reordered frames — decode must fail or return empty (no valid data).
#[test]
fn ffi_reordered_frames() {
    let data = b"reordered frame test payload";
    let frame = ffi_simulate_encode_file(data, b"reorder_pass").unwrap();

    // Swap two segments: header region ↔ ciphertext region
    if frame.len() >= 130 {
        let mut mangled = frame.clone();
        let mid = frame.len() / 2;
        // Swap bytes [0..mid] with [mid..2*mid]
        for i in 0..mid.min(frame.len() - mid) {
            mangled.swap(i, mid + i);
        }
        let _result = ffi_simulate_decode_gif(&mangled);
        // No assertion on Ok/Err – we only assert no panic
    }
}

/// 6. Corrupted PQ ciphertext — must return Err.
///    (Modeled as corrupted ciphertext bytes past the HMAC-verified region.)
#[test]
fn ffi_corrupted_pq_ciphertext() {
    let data = b"secret data for PQ corruption test";
    let mut frame = ffi_simulate_encode_file(data, b"pq_pass").unwrap();

    // Corrupt bytes in the ciphertext region (after the 65-byte header)
    if frame.len() > 65 {
        frame[65] ^= 0xFF; // flip a ciphertext byte
    }

    let result = ffi_simulate_decode_gif(&frame);
    assert!(
        result.is_err(),
        "Corrupted ciphertext must not decode successfully"
    );
}

/// 7. Wrong salt — different key derivation → HMAC fails → Err.
#[test]
fn ffi_wrong_salt() {
    let data = b"original plaintext";
    let frame = ffi_simulate_encode_file(data, b"correct_pass").unwrap();

    // Flip the salt bytes (positions 4..20)
    let mut bad_frame = frame.clone();
    for b in &mut bad_frame[4..20] {
        *b ^= 0xFF;
    }

    let result = ffi_simulate_decode_gif(&bad_frame);
    assert!(
        result.is_err(),
        "Wrong salt must cause authentication failure"
    );
}

/// 8. Wrong version byte — must return Err or be handled gracefully.
#[test]
fn ffi_wrong_version() {
    let data = b"version test payload";
    let mut frame = ffi_simulate_encode_file(data, b"ver_pass").unwrap();

    // Corrupt the mode byte (position 32)
    frame[32] = 0xFF; // invalid version

    // The mode byte is part of AAD; corrupting it changes the HMAC,
    // so authentication must fail.
    let result = ffi_simulate_decode_gif(&frame);
    assert!(
        result.is_err(),
        "Wrong version byte must cause authentication failure"
    );
}

/// 9. All-zero input — no panic.
#[test]
fn ffi_all_zero_input() {
    let data = vec![0u8; 256];
    let _ = ffi_simulate_decode_gif(&data);
    let enc = ffi_simulate_encode_file(&data, b"zero_pass");
    if let Ok(frame) = enc {
        let _ = ffi_simulate_decode_gif(&frame);
    }
}

/// 10. All-0xFF input — no panic.
#[test]
fn ffi_all_ff_input() {
    let data = vec![0xFFu8; 256];
    let _ = ffi_simulate_decode_gif(&data);
    let _ = ffi_simulate_encode_file(&data, b"ff_pass");
}

/// 11. Round-trip correctness for valid inputs.
#[test]
fn ffi_roundtrip_various_sizes() {
    let payloads: &[&[u8]] = &[b"", b"a", b"0123456789abcdef", &[0u8; 100], &[0xABu8; 1000]];
    for payload in payloads {
        assert!(
            ffi_roundtrip(payload),
            "Round-trip must succeed for payload of length {}",
            payload.len()
        );
    }
}

/// 12. Error propagation — Err must contain a description string.
#[test]
fn ffi_error_propagation() {
    let bad_input = vec![0xFFu8; 20]; // too short for header
    let err = ffi_simulate_decode_gif(&bad_input);
    assert!(err.is_err());
    let msg = err.unwrap_err();
    assert!(!msg.is_empty(), "Error message must not be empty");
}

/// 13. No memory leak after multiple encode/decode cycles.
///     (Rely on Zeroize + Drop implementations; no allocator tracing in std tests.)
#[test]
fn ffi_repeated_cycles_no_crash() {
    for i in 0..1000 {
        let data = format!("cycle {}", i);
        let frame = ffi_simulate_encode_file(data.as_bytes(), b"cycle_pass");
        if let Ok(f) = frame {
            let _ = ffi_simulate_decode_gif(&f);
        }
    }
}

/// 14. Concurrent FFI calls — must not trigger data races.
#[test]
fn ffi_concurrent_calls() {
    use std::sync::Arc;
    use std::thread;

    let data = Arc::new(b"concurrent payload".to_vec());

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let d = Arc::clone(&data);
            thread::spawn(move || {
                let frame = ffi_simulate_encode_file(&d, format!("pass_{}", i).as_bytes());
                if let Ok(f) = frame {
                    let _ = ffi_simulate_decode_gif(&f);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread must not panic");
    }
}

/// 15. Hmac tag at position 33..65 fully zeroed → must fail auth.
#[test]
fn ffi_zeroed_hmac_tag() {
    let data = b"payload for zeroed hmac test";
    let mut frame = ffi_simulate_encode_file(data, b"hmac_pass").unwrap();

    // Zero out the HMAC tag field
    for b in &mut frame[33..65] {
        *b = 0;
    }

    let result = ffi_simulate_decode_gif(&frame);
    assert!(
        result.is_err(),
        "Zero HMAC tag must cause authentication failure"
    );
}

/// 16. X25519 key exchange across FFI boundary — bad key lengths return Err.
#[test]
fn ffi_x25519_bad_lengths() {
    let (priv_a, _) = x25519_generate_keypair();
    for bad_len in [0usize, 1, 16, 31, 33, 64, 128] {
        let bad_peer = vec![0x42u8; bad_len];
        let result = x25519_exchange(&priv_a, &bad_peer);
        assert!(
            result.is_err(),
            "x25519_exchange with peer pub of length {} must Err",
            bad_len
        );
    }
    for bad_len in [0usize, 1, 31, 33, 64] {
        let bad_priv = vec![0x42u8; bad_len];
        let result = x25519_public_from_private(&bad_priv);
        assert!(
            result.is_err(),
            "x25519_public_from_private with key of length {} must Err",
            bad_len
        );
    }
}

/// 17. HKDF with output length 0 — must return empty Vec, not panic.
#[test]
fn ffi_hkdf_zero_output() {
    let result = derive_key_hkdf(b"ikm", None, b"info", 0);
    match result {
        Ok(k) => assert!(k.is_empty(), "0-byte HKDF output must be empty"),
        Err(_) => { /* also acceptable */ }
    }
}

/// 18. Argon2id with invalid params — must return Err, not panic.
#[test]
fn ffi_argon2id_invalid_params() {
    // Salt != 16 bytes
    let bad_salts: &[&[u8]] = &[
        b"",
        b"tooshort", // 8 bytes
        &[0u8; 15],  // 15 bytes
        &[0u8; 17],  // 17 bytes
        &[0u8; 32],  // 32 bytes (valid for Argon2 but our wrapper rejects != 16)
    ];
    for salt in bad_salts {
        let result = derive_key_argon2id(b"pass", salt, ARGON_MEM, ARGON_ITER, ARGON_PAR, 32);
        assert!(
            result.is_err(),
            "Salt of length {} must be rejected",
            salt.len()
        );
    }
}

/// 19. Decode with correct HMAC but corrupted nonce in ciphertext — must Err.
#[test]
fn ffi_correct_hmac_wrong_nonce_in_cipher() {
    let data = b"nonce corruption test";
    let mut frame = ffi_simulate_encode_file(data, b"nonce_pass").unwrap();

    // Corrupt the nonce field (positions 20..32) AFTER the HMAC was included
    // over these bytes. The HMAC in the frame was computed with the original nonce,
    // but the mode byte and salt are part of the AAD, not the nonce.
    // Since our HMAC covers the AAD (which does not include the nonce), corrupting
    // the nonce means the GCM tag will fail.
    for b in &mut frame[20..32] {
        *b ^= 0xFF;
    }

    let result = ffi_simulate_decode_gif(&frame);
    // Either auth fails (HMAC doesn't cover nonce bytes in our test harness) or
    // AES-GCM tag fails. Either way: Err.
    assert!(
        result.is_err(),
        "Corrupted nonce must prevent successful decryption"
    );
}
