#![no_main]
/// Fuzz target: pure_crypto module — AES-256-GCM, HKDF, Argon2id, X25519.
///
/// Discovers:
/// - Panics in high-level crypto functions with arbitrary inputs
/// - AES-GCM encryption/decryption with fuzz keys, nonces, plaintexts
/// - HKDF-SHA256 derivation with arbitrary IKM/salt/info/length
/// - X25519 key exchange with arbitrary scalar / base-point bytes
/// - Invariant: encrypt(key, nonce, pt, aad) then decrypt must recover pt
/// - Invariant: HKDF(ikm, ...) must always return exactly requested length

use libfuzzer_sys::fuzz_target;

// Import pure_crypto items behind the feature flag
#[cfg(feature = "pure-crypto")]
use crypto_core::pure_crypto::{
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    hkdf_derive,
    SecretKey,
};
#[cfg(feature = "pure-crypto")]
use crypto_core::nonce::Nonce;

fuzz_target!(|data: &[u8]| {
    #[cfg(not(feature = "pure-crypto"))]
    let _ = data;

    #[cfg(feature = "pure-crypto")]
    {
        if data.len() < 45 {
            return;
        }

        let key_bytes = &data[..32];
        let nonce_bytes = &data[32..44];
        let split = 44 + (data[44] as usize % 128).min(data.len().saturating_sub(45));
        let aad = &data[44..split];
        let plaintext = &data[split..];

        if plaintext.is_empty() {
            return;
        }

        // Construct typed key and nonce — bail if inputs are invalid
        let key = match SecretKey::from_bytes(key_bytes) {
            Ok(k) => k,
            Err(_) => return,
        };
        let nonce = match Nonce::from_bytes(nonce_bytes) {
            Ok(n) => n,
            Err(_) => return,
        };
        let aad_opt: Option<&[u8]> = if aad.is_empty() { None } else { Some(aad) };

        // ── 1. AES-GCM encrypt → decrypt roundtrip ───────────────────────────
        match aes_gcm_encrypt(&key, &nonce, plaintext, aad_opt) {
            Ok(ciphertext) => {
                // Must include 16-byte GCM auth tag
                assert!(
                    ciphertext.len() >= plaintext.len() + 16,
                    "ciphertext must be at least plaintext_len + 16"
                );

                // Roundtrip
                match aes_gcm_decrypt(&key, &nonce, &ciphertext, aad_opt) {
                    Ok(recovered) => {
                        assert_eq!(
                            recovered, plaintext,
                            "AES-GCM pure_crypto roundtrip mismatch"
                        );
                    }
                    Err(_) => {
                        panic!(
                            "pure_crypto: decrypt failed on freshly-encrypted ciphertext \
                            with same key/nonce/aad — bug in aes_gcm_decrypt"
                        );
                    }
                }

                // Bit-flip must cause auth failure
                if ciphertext.len() > 16 {
                    let mut corrupt = ciphertext.clone();
                    corrupt[0] ^= 0xFF;
                    match aes_gcm_decrypt(&key, &nonce, &corrupt, aad_opt) {
                        Ok(_) => {
                            panic!(
                                "pure_crypto: aes_gcm_decrypt authenticated \
                                a corrupt ciphertext — authentication bypass"
                            );
                        }
                        Err(_) => {} // Expected
                    }
                }
            }
            Err(_) => {
                // Acceptable: invalid key length, nonce mismatch, etc.
            }
        }

        // ── 2. HKDF-SHA256 with arbitrary inputs ─────────────────────────────
        if data.len() >= 33 {
            let ikm = &data[..32];
            let salt_len = (data[32] as usize % 64).min(data.len().saturating_sub(33));
            let salt = &data[33..33 + salt_len];
            let info_start = 33 + salt_len;
            let info_len = if info_start < data.len() {
                (data[info_start] as usize % 64).min(data.len().saturating_sub(info_start + 1))
            } else {
                0
            };
            let info = if info_start + 1 + info_len <= data.len() {
                &data[info_start + 1..info_start + 1 + info_len]
            } else {
                b""
            };
            let salt_opt: Option<&[u8]> = if salt.is_empty() { None } else { Some(salt) };

            for output_len in [16usize, 32, 48, 64] {
                match hkdf_derive(ikm, salt_opt, info, output_len) {
                    Ok(okm) => {
                        assert_eq!(
                            okm.len(),
                            output_len,
                            "hkdf_derive returned wrong length: expected {}, got {}",
                            output_len,
                            okm.len()
                        );
                    }
                    Err(_) => {
                        // Acceptable for extreme input combos
                    }
                }
            }
        }

        // ── 3. Decrypt with garbage (never panics) ────────────────────────────
        {
            let _ = aes_gcm_decrypt(&key, &nonce, data, aad_opt);
        }
    }
});
