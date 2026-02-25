//! Property-based tests for crypto_core using proptest.
//!
//! Covers AEAD roundtrip, tamper detection, nonce uniqueness, HMAC/SHA-256
//! determinism, key validation, and ciphertext length invariants.
//!
//! Added 2026-02-25 to close audit gap: "crypto_core has zero proptest
//! despite declaring the dependency."

use crypto_core::{AeadWrapper, NonceGenerator, KEY_SIZE, TAG_SIZE};
use proptest::prelude::*;

// =============================================================================
// Strategy helpers
// =============================================================================

/// Generates a random 32-byte AES-256 key.
fn arb_key() -> impl Strategy<Value = [u8; KEY_SIZE]> {
    proptest::array::uniform32(any::<u8>())
}

/// Generates arbitrary plaintext up to 4 KiB.
fn arb_plaintext() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..4096)
}

/// Generates arbitrary AAD up to 1 KiB.
fn arb_aad() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..1024)
}

// =============================================================================
// AEAD property tests
// =============================================================================

proptest! {
    /// AEAD-001 / INV-001: Encrypt-then-decrypt roundtrip must recover plaintext.
    #[test]
    fn prop_aead_roundtrip(
        key in arb_key(),
        plaintext in arb_plaintext(),
        aad in arb_aad(),
    ) {
        let wrapper = AeadWrapper::new(&key).expect("valid key");
        let (nonce, ciphertext) = wrapper.encrypt(&plaintext, &aad).expect("encrypt");
        let recovered = wrapper.decrypt(&nonce, &ciphertext, &aad).expect("decrypt");
        prop_assert_eq!(recovered.data(), plaintext.as_slice());
    }

    /// Ciphertext length invariant: |ct| == |pt| + TAG_SIZE (16 bytes).
    #[test]
    fn prop_ciphertext_length(
        key in arb_key(),
        plaintext in arb_plaintext(),
        aad in arb_aad(),
    ) {
        let wrapper = AeadWrapper::new(&key).expect("valid key");
        let (_nonce, ciphertext) = wrapper.encrypt(&plaintext, &aad).expect("encrypt");
        prop_assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
    }

    /// INV-002: Any single-bit flip in ciphertext must cause decryption failure.
    #[test]
    fn prop_tamper_detected(
        key in arb_key(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..512),
        aad in arb_aad(),
        flip_pos in 0usize..528,  // will be clamped to ct length
    ) {
        let wrapper = AeadWrapper::new(&key).expect("valid key");
        let (nonce, mut ciphertext) = wrapper.encrypt(&plaintext, &aad).expect("encrypt");

        // Flip one bit
        let pos = flip_pos % ciphertext.len();
        ciphertext[pos] ^= 0x01;

        let result = wrapper.decrypt(&nonce, &ciphertext, &aad);
        prop_assert!(result.is_err(), "Tampered ciphertext must be rejected");
    }

    /// Wrong AAD must cause decryption failure.
    #[test]
    fn prop_wrong_aad_rejected(
        key in arb_key(),
        plaintext in arb_plaintext(),
        aad1 in arb_aad(),
        aad2 in arb_aad(),
    ) {
        prop_assume!(aad1 != aad2);
        let wrapper = AeadWrapper::new(&key).expect("valid key");
        let (nonce, ciphertext) = wrapper.encrypt(&plaintext, &aad1).expect("encrypt");
        let result = wrapper.decrypt(&nonce, &ciphertext, &aad2);
        prop_assert!(result.is_err(), "Wrong AAD must be rejected");
    }

    /// Wrong key must cause decryption failure.
    #[test]
    fn prop_wrong_key_rejected(
        key1 in arb_key(),
        key2 in arb_key(),
        plaintext in arb_plaintext(),
        aad in arb_aad(),
    ) {
        prop_assume!(key1 != key2);
        let w1 = AeadWrapper::new(&key1).expect("valid key");
        let w2 = AeadWrapper::new(&key2).expect("valid key");
        let (nonce, ciphertext) = w1.encrypt(&plaintext, &aad).expect("encrypt");
        let result = w2.decrypt(&nonce, &ciphertext, &aad);
        prop_assert!(result.is_err(), "Wrong key must be rejected");
    }

    /// Invalid key sizes must be rejected.
    #[test]
    fn prop_invalid_key_size_rejected(
        key_len in (0usize..64).prop_filter("not 32", |l| *l != KEY_SIZE),
    ) {
        let key = vec![0xABu8; key_len];
        let result = AeadWrapper::new(&key);
        prop_assert!(result.is_err(), "Key of size {} must be rejected", key_len);
    }

    /// Truncated ciphertext must be rejected.
    #[test]
    fn prop_truncated_ciphertext_rejected(
        key in arb_key(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
        aad in arb_aad(),
        trim in 1usize..17,
    ) {
        let wrapper = AeadWrapper::new(&key).expect("valid key");
        let (nonce, ciphertext) = wrapper.encrypt(&plaintext, &aad).expect("encrypt");
        let truncated = &ciphertext[..ciphertext.len().saturating_sub(trim)];
        let result = wrapper.decrypt(&nonce, truncated, &aad);
        prop_assert!(result.is_err(), "Truncated ciphertext must be rejected");
    }
}

// =============================================================================
// Nonce property tests
// =============================================================================

proptest! {
    /// Nonce generator produces pairwise-distinct values.
    #[test]
    fn prop_nonce_uniqueness(batch_size in 10usize..500) {
        let gen = NonceGenerator::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..batch_size {
            let nonce = gen.next().expect("not exhausted");
            let bytes = *nonce.as_bytes();
            prop_assert!(seen.insert(bytes), "Nonce collision detected");
        }
    }
}

// =============================================================================
// pure_crypto property tests (feature-gated)
// =============================================================================

#[cfg(feature = "pure-crypto")]
mod pure_crypto_props {
    use super::*;
    use crypto_core::pure_crypto::*;

    proptest! {
        /// HMAC-SHA256 verify roundtrip: hmac_verify(k, d, hmac(k, d)) == true.
        #[test]
        fn prop_hmac_roundtrip(
            key in proptest::collection::vec(any::<u8>(), 1..128),
            data in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let tag = hmac_sha256(&key, &data);
            prop_assert!(hmac_sha256_verify(&key, &data, &tag));
        }

        /// HMAC-SHA256 wrong key must not verify.
        #[test]
        fn prop_hmac_wrong_key(
            key1 in proptest::collection::vec(any::<u8>(), 1..64),
            key2 in proptest::collection::vec(any::<u8>(), 1..64),
            data in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            prop_assume!(key1 != key2);
            let tag = hmac_sha256(&key1, &data);
            prop_assert!(!hmac_sha256_verify(&key2, &data, &tag));
        }

        /// SHA-256 is deterministic and produces 32 bytes.
        #[test]
        fn prop_sha256_deterministic(
            data in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let h1 = sha256(&data);
            let h2 = sha256(&data);
            prop_assert_eq!(h1.len(), 32);
            prop_assert_eq!(h1, h2);
        }

        /// SHA-256 collision resistance (different inputs → different hashes, probabilistic).
        #[test]
        fn prop_sha256_collision_resistance(
            data1 in proptest::collection::vec(any::<u8>(), 1..256),
            data2 in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(data1 != data2);
            let h1 = sha256(&data1);
            let h2 = sha256(&data2);
            prop_assert_ne!(h1, h2, "SHA-256 collision (astronomically unlikely)");
        }

        /// HKDF determinism: same inputs → same output.
        #[test]
        fn prop_hkdf_deterministic(
            ikm in proptest::collection::vec(any::<u8>(), 16..64),
            info in proptest::collection::vec(any::<u8>(), 0..64),
            length in 16usize..64,
        ) {
            let out1 = hkdf_derive(&ikm, None, &info, length).expect("hkdf");
            let out2 = hkdf_derive(&ikm, None, &info, length).expect("hkdf");
            prop_assert_eq!(&out1, &out2);
            prop_assert_eq!(out1.len(), length);
        }

        /// constant_time_eq is reflexive and rejects different-length inputs.
        #[test]
        fn prop_constant_time_eq_reflexive(
            data in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            prop_assert!(constant_time_eq(&data, &data));
        }

        /// constant_time_eq rejects differing inputs.
        #[test]
        fn prop_constant_time_eq_rejects(
            data1 in proptest::collection::vec(any::<u8>(), 1..256),
            data2 in proptest::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(data1 != data2);
            prop_assert!(!constant_time_eq(&data1, &data2));
        }
    }
}
