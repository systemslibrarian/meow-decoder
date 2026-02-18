//! Comprehensive Tests for meow_crypto_rs
//!
//! This test module provides thorough coverage of the Rust crypto backend
//! by calling through `meow_crypto_rs::pure` to ensure tarpaulin tracks coverage.
//!
//! Includes:
//! - Happy path tests
//! - Edge cases and boundary conditions
//! - Error handling
//! - Security properties (constant-time, key validation, etc.)
//! - Cross-function integration tests
//!
//! Run with: cargo test --test comprehensive_tests

use std::collections::HashSet;

// Import through pure module for coverage tracking
use meow_crypto_rs::pure::{self, CryptoError};

// Raw crate imports only for AAD (Payload) tests not exposed through pure
use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    Aes256Gcm, Nonce,
};

// =============================================================================
// ARGON2ID KEY DERIVATION TESTS
// =============================================================================

mod argon2id_tests {
    use super::*;

    #[test]
    fn test_basic_derivation() {
        let password = b"test_password";
        let salt = [0u8; 16];

        let key = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_deterministic_derivation() {
        let password = b"consistent_password";
        let salt = [0x42u8; 16];

        let key1 = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
        let key2 = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();

        assert_eq!(key1, key2, "Same inputs should produce same outputs");
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [0x42u8; 16];

        let key1 = pure::derive_key_argon2id(b"password1", &salt, 1024, 1, 1, 32).unwrap();
        let key2 = pure::derive_key_argon2id(b"password2", &salt, 1024, 1, 1, 32).unwrap();

        assert_ne!(
            key1, key2,
            "Different passwords should produce different keys"
        );
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = b"same_password";

        let key1 = pure::derive_key_argon2id(password, &[0x11u8; 16], 1024, 1, 1, 32).unwrap();
        let key2 = pure::derive_key_argon2id(password, &[0x22u8; 16], 1024, 1, 1, 32).unwrap();

        assert_ne!(key1, key2, "Different salts should produce different keys");
    }

    #[test]
    fn test_various_output_lengths() {
        let password = b"test";
        let salt = [0u8; 16];

        for output_len in [16, 32, 48, 64] {
            let key = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, output_len).unwrap();
            assert_eq!(key.len(), output_len);
        }
    }

    #[test]
    fn test_empty_password() {
        let salt = [0u8; 16];
        let key = pure::derive_key_argon2id(b"", &salt, 1024, 1, 1, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_unicode_password() {
        let password = "日本語パスワード🐱".as_bytes();
        let salt = [0u8; 16];
        let key = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_large_password() {
        let password = vec![b'A'; 1024 * 1024]; // 1 MB password
        let salt = [0u8; 16];
        let key = pure::derive_key_argon2id(&password, &salt, 1024, 1, 1, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_higher_memory_and_iterations() {
        let password = b"secure_password";
        let salt = [0x55u8; 16];
        let key = pure::derive_key_argon2id(password, &salt, 8192, 3, 2, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_invalid_salt_length() {
        let result = pure::derive_key_argon2id(b"pass", &[0u8; 15], 1024, 1, 1, 32);
        assert!(matches!(result, Err(CryptoError::InvalidSaltLength { .. })));
    }
}

// =============================================================================
// HKDF TESTS
// =============================================================================

mod hkdf_tests {
    use super::*;

    #[test]
    fn test_basic_hkdf() {
        let ikm = b"input key material";
        let salt = b"salt value";
        let info = b"context info";

        let okm = pure::derive_key_hkdf(ikm, Some(salt), info, 42).unwrap();
        assert_eq!(okm.len(), 42);
        assert!(okm.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hkdf_extract_expand_separate() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        // Combined
        let okm1 = pure::derive_key_hkdf(ikm, Some(salt), info, 32).unwrap();

        // Separate extract + expand
        let prk = pure::hkdf_extract(Some(salt), ikm);
        let okm2 = pure::hkdf_expand(&prk, info, 32).unwrap();

        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"ikm without salt";
        let info = b"info";

        let okm = pure::derive_key_hkdf(ikm, None, info, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_empty_info() {
        let ikm = b"ikm";
        let salt = b"salt";

        let okm = pure::derive_key_hkdf(ikm, Some(salt), b"", 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_various_lengths() {
        let ikm = b"ikm";
        let salt = b"salt";
        let info = b"info";

        for len in [1, 16, 32, 64, 128, 255] {
            let okm = pure::derive_key_hkdf(ikm, Some(salt), info, len).unwrap();
            assert_eq!(okm.len(), len);
        }
    }

    #[test]
    fn test_hkdf_max_length() {
        let ikm = b"ikm";
        let okm = pure::derive_key_hkdf(ikm, None, b"", 255 * 32).unwrap();
        assert_eq!(okm.len(), 255 * 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let okm1 = pure::derive_key_hkdf(b"ikm", Some(b"salt"), b"info", 32).unwrap();
        let okm2 = pure::derive_key_hkdf(b"ikm", Some(b"salt"), b"info", 32).unwrap();
        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_hkdf_different_info_different_output() {
        let okm1 = pure::derive_key_hkdf(b"ikm", Some(b"salt"), b"info1", 32).unwrap();
        let okm2 = pure::derive_key_hkdf(b"ikm", Some(b"salt"), b"info2", 32).unwrap();
        assert_ne!(okm1, okm2);
    }

    #[test]
    fn test_hkdf_extract_output_length() {
        let prk = pure::hkdf_extract(Some(b"salt"), b"ikm");
        assert_eq!(prk.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_hkdf_expand_invalid_prk() {
        let result = pure::hkdf_expand(&[0u8; 10], b"info", 32);
        assert!(matches!(result, Err(CryptoError::InvalidPrkLength)));
    }
}

// =============================================================================
// AES-256-GCM TESTS
// =============================================================================

mod aes_gcm_tests {
    use super::*;

    #[test]
    fn test_basic_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Hello, world!";

        let ct = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let pt = pure::aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_encrypt_with_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";
        let aad = b"Associated data";

        let ct = pure::aes_gcm_encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();
        let pt = pure::aes_gcm_decrypt(&key, &nonce, &ct, Some(aad)).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aad_mismatch_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";

        let ct = pure::aes_gcm_encrypt(&key, &nonce, plaintext, Some(b"correct_aad")).unwrap();
        let result = pure::aes_gcm_decrypt(&key, &nonce, &ct, Some(b"wrong_aad"));
        assert!(result.is_err(), "Decryption should fail with wrong AAD");
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x99u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";

        let ct = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let result = pure::aes_gcm_decrypt(&wrong_key, &nonce, &ct, None);
        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let wrong_nonce = [0x99u8; 12];
        let plaintext = b"Secret message";

        let ct = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let result = pure::aes_gcm_decrypt(&key, &wrong_nonce, &ct, None);
        assert!(result.is_err(), "Decryption should fail with wrong nonce");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";

        let mut ct = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        ct[0] ^= 0xFF;
        let result = pure::aes_gcm_decrypt(&key, &nonce, &ct, None);
        assert!(
            result.is_err(),
            "Decryption should fail with tampered ciphertext"
        );
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];

        let ct = pure::aes_gcm_encrypt(&key, &nonce, &[], None).unwrap();
        assert_eq!(ct.len(), 16); // Just auth tag
        let pt = pure::aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB

        let ct = pure::aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16);
        let pt = pure::aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_ciphertext_length() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];

        for len in [0, 1, 16, 100, 1000] {
            let plaintext = vec![0u8; len];
            let ct = pure::aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();
            assert_eq!(ct.len(), len + 16);
        }
    }

    #[test]
    fn test_nonce_uniqueness_matters() {
        let key = [0x42u8; 32];
        let plaintext = b"Same plaintext";

        let ct1 = pure::aes_gcm_encrypt(&key, &[0x01u8; 12], plaintext, None).unwrap();
        let ct2 = pure::aes_gcm_encrypt(&key, &[0x02u8; 12], plaintext, None).unwrap();

        assert_ne!(
            ct1, ct2,
            "Different nonces should produce different ciphertexts"
        );
    }

    #[test]
    fn test_deterministic_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Deterministic test";

        let ct1 = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let ct2 = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();

        assert_eq!(
            ct1, ct2,
            "Same key/nonce/plaintext should produce same ciphertext"
        );
    }

    #[test]
    fn test_invalid_key_length() {
        let result = pure::aes_gcm_encrypt(&[0u8; 31], &[0u8; 12], b"test", None);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let result = pure::aes_gcm_encrypt(&[0u8; 32], &[0u8; 11], b"test", None);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength { .. })
        ));
    }

    #[test]
    fn test_ciphertext_too_short() {
        let result = pure::aes_gcm_decrypt(&[0u8; 32], &[0u8; 12], &[0u8; 15], None);
        assert!(matches!(result, Err(CryptoError::CiphertextTooShort)));
    }

    // Test using raw Payload API for AAD length mismatch
    #[test]
    fn test_aad_length_mismatch_via_raw() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Data with AAD";
        let aad = b"authenticated_data";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap();

        let short_aad = &aad[..10];
        let result = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: short_aad,
            },
        );
        assert!(result.is_err(), "Truncated AAD should fail");
    }
}

// =============================================================================
// HMAC-SHA256 TESTS
// =============================================================================

mod hmac_tests {
    use super::*;

    #[test]
    fn test_basic_hmac() {
        let tag = pure::hmac_sha256(b"secret key", b"message to authenticate").unwrap();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_hmac_verify_success() {
        let key = b"secret key";
        let message = b"message to authenticate";

        let tag = pure::hmac_sha256(key, message).unwrap();
        assert!(pure::hmac_sha256_verify(key, message, &tag).unwrap());
    }

    #[test]
    fn test_hmac_verify_wrong_message() {
        let key = b"secret key";
        let tag = pure::hmac_sha256(key, b"original message").unwrap();
        assert!(!pure::hmac_sha256_verify(key, b"tampered message", &tag).unwrap());
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let message = b"message";
        let tag = pure::hmac_sha256(b"secret key", message).unwrap();
        assert!(!pure::hmac_sha256_verify(b"wrong key!", message, &tag).unwrap());
    }

    #[test]
    fn test_hmac_deterministic() {
        let tag1 = pure::hmac_sha256(b"key", b"message").unwrap();
        let tag2 = pure::hmac_sha256(b"key", b"message").unwrap();
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_hmac_empty_message() {
        let tag = pure::hmac_sha256(b"key", b"").unwrap();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_hmac_various_key_lengths() {
        let message = b"message";
        for key_len in [1, 16, 32, 64, 128, 256] {
            let key = vec![0x42u8; key_len];
            let tag = pure::hmac_sha256(&key, message).unwrap();
            assert_eq!(tag.len(), 32);
        }
    }
}

// =============================================================================
// SHA-256 TESTS
// =============================================================================

mod sha256_tests {
    use super::*;

    #[test]
    fn test_basic_hash() {
        let hash = pure::sha256(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_known_vector() {
        let hash = pure::sha256(b"abc");
        let expected =
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_empty_input() {
        let hash = pure::sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_deterministic() {
        let h1 = pure::sha256(b"test data");
        let h2 = pure::sha256(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_inputs() {
        let h1 = pure::sha256(b"input1");
        let h2 = pure::sha256(b"input2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_incremental_vs_whole() {
        // SHA-256 of whole vs parts should use same algorithm
        // Here we just verify the pure function works for various sizes
        let h_empty = pure::sha256(b"");
        let h_short = pure::sha256(b"abc");
        let h_long = pure::sha256(&vec![0xAAu8; 10000]);

        assert_eq!(h_empty.len(), 32);
        assert_eq!(h_short.len(), 32);
        assert_eq!(h_long.len(), 32);

        assert_ne!(h_empty, h_short);
        assert_ne!(h_short, h_long);
    }
}

// =============================================================================
// X25519 KEY EXCHANGE TESTS
// =============================================================================

mod x25519_tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (priv_key, pub_key) = pure::x25519_generate_keypair();
        assert_eq!(priv_key.len(), 32);
        assert_eq!(pub_key.len(), 32);
    }

    #[test]
    fn test_key_exchange_symmetric() {
        let (priv_a, pub_a) = pure::x25519_generate_keypair();
        let (priv_b, pub_b) = pure::x25519_generate_keypair();

        let shared_a = pure::x25519_exchange(&priv_a, &pub_b).unwrap();
        let shared_b = pure::x25519_exchange(&priv_b, &pub_a).unwrap();

        assert_eq!(shared_a, shared_b, "Shared secrets should be equal");
    }

    #[test]
    fn test_public_key_derivation() {
        let (priv_key, pub_key) = pure::x25519_generate_keypair();
        let derived = pure::x25519_public_from_private(&priv_key).unwrap();
        assert_eq!(derived, pub_key);
    }

    #[test]
    fn test_different_keypairs_different_shared() {
        let (priv_a, _) = pure::x25519_generate_keypair();
        let (_, pub_b1) = pure::x25519_generate_keypair();
        let (_, pub_b2) = pure::x25519_generate_keypair();

        let shared1 = pure::x25519_exchange(&priv_a, &pub_b1).unwrap();
        let shared2 = pure::x25519_exchange(&priv_a, &pub_b2).unwrap();
        assert_ne!(shared1, shared2);
    }

    #[test]
    fn test_deterministic_from_bytes() {
        let secret_bytes = [0x42u8; 32];
        let pub1 = pure::x25519_public_from_private(&secret_bytes).unwrap();
        let pub2 = pure::x25519_public_from_private(&secret_bytes).unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_shared_secret_not_zero() {
        let (priv_a, _) = pure::x25519_generate_keypair();
        let (_, pub_b) = pure::x25519_generate_keypair();

        let shared = pure::x25519_exchange(&priv_a, &pub_b).unwrap();
        assert!(shared.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_invalid_key_length() {
        let result = pure::x25519_exchange(&[0u8; 31], &[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_x25519_rfc7748_test_vector() {
        let alice_secret: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_secret: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];

        let pub_a = pure::x25519_public_from_private(&alice_secret).unwrap();
        let pub_b = pure::x25519_public_from_private(&bob_secret).unwrap();

        let shared_a = pure::x25519_exchange(&alice_secret, &pub_b).unwrap();
        let shared_b = pure::x25519_exchange(&bob_secret, &pub_a).unwrap();

        assert_eq!(shared_a, shared_b, "Shared secrets must match");

        let expected: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        assert_eq!(shared_a, expected);
    }
}

// =============================================================================
// CONSTANT-TIME COMPARISON TESTS
// =============================================================================

mod constant_time_tests {
    use super::*;

    #[test]
    fn test_equal_slices() {
        assert!(pure::constant_time_compare(b"hello", b"hello"));
    }

    #[test]
    fn test_unequal_slices() {
        assert!(!pure::constant_time_compare(b"hello", b"world"));
    }

    #[test]
    fn test_different_lengths() {
        assert!(!pure::constant_time_compare(b"short", b"longer string"));
    }

    #[test]
    fn test_single_bit_difference() {
        let a = [0x00, 0x00, 0x00, 0x00];
        let b = [0x00, 0x00, 0x00, 0x01];
        assert!(!pure::constant_time_compare(&a, &b));
    }

    #[test]
    fn test_empty_slices() {
        assert!(pure::constant_time_compare(&[], &[]));
    }

    #[test]
    fn test_large_equal_slices() {
        let a = vec![0x42u8; 10000];
        let b = vec![0x42u8; 10000];
        assert!(pure::constant_time_compare(&a, &b));
    }
}

// =============================================================================
// ML-KEM-768 (POST-QUANTUM) TESTS
// =============================================================================

#[cfg(feature = "pq")]
mod mlkem_tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (sk, pk) = pure::mlkem768_keygen();
        // ML-KEM-768 key sizes
        assert!(!sk.is_empty());
        assert!(!pk.is_empty());
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let (sk, pk) = pure::mlkem768_keygen();

        let (ss_enc, ct) = pure::mlkem768_encapsulate(&pk).unwrap();
        let ss_dec = pure::mlkem768_decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec, "Shared secrets should match");
    }

    #[test]
    fn test_different_keypairs_different_shared() {
        let (sk1, pk1) = pure::mlkem768_keygen();
        let (sk2, pk2) = pure::mlkem768_keygen();

        let (ss1, ct1) = pure::mlkem768_encapsulate(&pk1).unwrap();
        let (ss2, _ct2) = pure::mlkem768_encapsulate(&pk2).unwrap();

        // Different public keys -> different shared secrets
        assert_ne!(ss1, ss2);

        // Wrong secret key -> wrong shared secret
        let ss_wrong = pure::mlkem768_decapsulate(&sk2, &ct1).unwrap();
        assert_ne!(ss1, ss_wrong);
    }

    #[test]
    fn test_shared_secret_length() {
        let (_sk, pk) = pure::mlkem768_keygen();
        let (ss, _ct) = pure::mlkem768_encapsulate(&pk).unwrap();

        // ML-KEM shared secrets are 32 bytes
        assert_eq!(ss.len(), 32);
    }

    #[test]
    fn test_determinism_from_same_seed() {
        // Multiple keypairs should be different (random)
        let (_sk1, pk1) = pure::mlkem768_keygen();
        let (_sk2, pk2) = pure::mlkem768_keygen();

        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_encapsulate_multiple_times() {
        let (sk, pk) = pure::mlkem768_keygen();

        let (ss1, ct1) = pure::mlkem768_encapsulate(&pk).unwrap();
        let (ss2, ct2) = pure::mlkem768_encapsulate(&pk).unwrap();

        assert_ne!(ct1, ct2);
        assert_ne!(ss1, ss2);

        // Both can be decapsulated
        let dec1 = pure::mlkem768_decapsulate(&sk, &ct1).unwrap();
        let dec2 = pure::mlkem768_decapsulate(&sk, &ct2).unwrap();

        assert_eq!(ss1, dec1);
        assert_eq!(ss2, dec2);
    }

    #[test]
    fn test_invalid_public_key() {
        let result = pure::mlkem768_encapsulate(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_private_key() {
        let (_sk, pk) = pure::mlkem768_keygen();
        let (_ss, ct) = pure::mlkem768_encapsulate(&pk).unwrap();
        let result = pure::mlkem768_decapsulate(&[0u8; 10], &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ciphertext() {
        let (sk, _pk) = pure::mlkem768_keygen();
        let result = pure::mlkem768_decapsulate(&sk, &[0u8; 10]);
        assert!(result.is_err());
    }
}

// =============================================================================
// ZEROIZE TESTS
// =============================================================================

mod zeroize_tests {
    use super::*;

    #[test]
    fn test_secure_zero_slice() {
        let mut secret = vec![0x42u8; 32];
        pure::secure_zero(&mut secret);
        assert!(secret.iter().all(|&b| b == 0), "Memory should be zeroed");
    }

    #[test]
    fn test_secure_zero_array() {
        let mut secret = [0x42u8; 32];
        pure::secure_zero(&mut secret);
        assert!(secret.iter().all(|&b| b == 0), "Memory should be zeroed");
    }

    #[test]
    fn test_secure_zero_empty() {
        let mut empty: Vec<u8> = vec![];
        pure::secure_zero(&mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_secure_zero_large() {
        let mut data = vec![0xFFu8; 4096];
        pure::secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}

// =============================================================================
// SECURE RANDOM TESTS
// =============================================================================

mod random_tests {
    use super::*;

    #[test]
    fn test_random_bytes_length() {
        let buffer = pure::secure_random(32);
        assert_eq!(buffer.len(), 32);
    }

    #[test]
    fn test_random_bytes_not_zero() {
        let buffer = pure::secure_random(32);
        assert!(buffer.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_bytes_unique() {
        let buf1 = pure::secure_random(32);
        let buf2 = pure::secure_random(32);
        assert_ne!(buf1, buf2, "Random outputs should be unique");
    }

    #[test]
    fn test_random_bytes_various_lengths() {
        for len in [1, 16, 32, 64, 128, 256, 1024] {
            let buffer = pure::secure_random(len);
            assert_eq!(buffer.len(), len);
        }
    }

    #[test]
    fn test_random_distribution() {
        let mut seen = HashSet::new();
        // Generate enough random bytes to likely see all values
        for _ in 0..100 {
            let bytes = pure::secure_random(256);
            for &b in &bytes {
                seen.insert(b);
            }
            if seen.len() == 256 {
                break;
            }
        }
        assert!(seen.len() > 200, "Random distribution seems poor");
    }
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_full_encryption_workflow() {
        // Full workflow through pure module:
        // 1. Derive key with Argon2id
        // 2. Generate random nonce
        // 3. Encrypt with AES-GCM
        // 4. Create HMAC over ciphertext
        // 5. Verify and decrypt

        let password = b"user_password";
        let salt = [0x42u8; 16];
        let plaintext = b"This is a secret message!";

        // 1. Key derivation
        let key = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();

        // 2. Generate nonce
        let nonce_bytes = pure::secure_random(12);
        let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();

        // 3. Encrypt
        let ciphertext = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();

        // 4. HMAC
        let tag = pure::hmac_sha256(&key, &ciphertext).unwrap();

        // 5. Verify HMAC
        assert!(pure::hmac_sha256_verify(&key, &ciphertext, &tag).unwrap());

        // 6. Decrypt
        let decrypted = pure::aes_gcm_decrypt(&key, &nonce, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn test_hybrid_key_exchange() {
        // Simulate hybrid (X25519 + ML-KEM) key exchange

        // Classical X25519
        let (priv_a, pub_a) = pure::x25519_generate_keypair();
        let (priv_b, pub_b) = pure::x25519_generate_keypair();

        let shared_x25519_a = pure::x25519_exchange(&priv_a, &pub_b).unwrap();
        let shared_x25519_b = pure::x25519_exchange(&priv_b, &pub_a).unwrap();
        assert_eq!(shared_x25519_a, shared_x25519_b);

        // Post-quantum ML-KEM
        let (bob_mlkem_sk, bob_mlkem_pk) = pure::mlkem768_keygen();
        let (shared_mlkem_enc, ct) = pure::mlkem768_encapsulate(&bob_mlkem_pk).unwrap();
        let shared_mlkem_dec = pure::mlkem768_decapsulate(&bob_mlkem_sk, &ct).unwrap();
        assert_eq!(shared_mlkem_enc, shared_mlkem_dec);

        // Combine via HKDF
        let mut combined = Vec::new();
        combined.extend_from_slice(&shared_x25519_a);
        combined.extend_from_slice(&shared_mlkem_enc);

        let final_key = pure::derive_key_hkdf(&combined, None, b"hybrid key", 32).unwrap();
        assert_eq!(final_key.len(), 32);
    }

    #[test]
    fn test_hkdf_domain_separation() {
        let ikm = b"master key material";
        let salt = b"salt";

        let encryption_key =
            pure::derive_key_hkdf(ikm, Some(salt), b"meow_encryption_v1", 32).unwrap();
        let hmac_key = pure::derive_key_hkdf(ikm, Some(salt), b"meow_hmac_v1", 32).unwrap();
        let frame_key = pure::derive_key_hkdf(ikm, Some(salt), b"meow_frame_mac_v1", 32).unwrap();

        assert_ne!(encryption_key, hmac_key);
        assert_ne!(encryption_key, frame_key);
        assert_ne!(hmac_key, frame_key);
    }

    #[test]
    fn test_aad_binding() {
        // Test that AAD properly binds metadata to encryption
        // This test uses raw aes_gcm Payload API since pure module
        // doesn't expose AAD parameter directly
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"secret";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let aad1 = b"filesize:1024";
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: aad1,
                },
            )
            .unwrap();

        let dec = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: aad1,
                },
            )
            .unwrap();
        assert_eq!(dec, plaintext);

        // Wrong AAD should fail
        let aad2 = b"filesize:2048";
        let result = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: aad2,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_backend_info() {
        let info = pure::backend_info();
        assert!(!info.is_empty());
    }
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_aes_gcm_minimum_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];

        // Encrypt empty plaintext
        let ct = pure::aes_gcm_encrypt(&key, &nonce, b"", None).unwrap();
        assert_eq!(ct.len(), 16); // auth tag only

        let pt = pure::aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_binary_data_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext: Vec<u8> = (0..=255).collect();

        let ct = pure::aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();
        let pt = pure::aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_null_bytes_in_data() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"hello\x00world\x00\x00";

        let ct = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let pt = pure::aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    }

    #[test]
    fn test_sha256_empty() {
        let hash = pure::sha256(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_constant_time_compare_timing() {
        // Verify constant-time comparison returns correct results
        // for edge cases
        let a = vec![0xFFu8; 1000];
        let mut b = a.clone();
        assert!(pure::constant_time_compare(&a, &b));
        b[999] = 0xFE;
        assert!(!pure::constant_time_compare(&a, &b));
    }
}
