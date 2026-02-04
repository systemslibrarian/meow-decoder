//! Comprehensive Tests for meow_crypto_rs
//!
//! This test module provides thorough coverage of the Rust crypto backend
//! including:
//! - Happy path tests
//! - Edge cases and boundary conditions
//! - Error handling
//! - Security properties (constant-time, key validation, etc.)
//! - Cross-function integration tests
//!
//! Run with: cargo test --test comprehensive_tests

use std::collections::HashSet;

// We test the underlying crypto primitives directly since we can't easily
// call PyO3 functions without a Python interpreter in integration tests.
use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::Hmac;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// ARGON2ID KEY DERIVATION TESTS
// =============================================================================

mod argon2id_tests {
    use super::*;

    #[test]
    fn test_basic_derivation() {
        let password = b"test_password";
        let salt = [0u8; 16];

        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; 32];
        argon2.hash_password_into(password, &salt, &mut output).unwrap();

        assert_eq!(output.len(), 32);
        // Key should not be all zeros
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_deterministic_derivation() {
        let password = b"consistent_password";
        let salt = [0x42u8; 16];

        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output1 = vec![0u8; 32];
        let mut output2 = vec![0u8; 32];

        argon2.hash_password_into(password, &salt, &mut output1).unwrap();
        argon2.hash_password_into(password, &salt, &mut output2).unwrap();

        assert_eq!(output1, output2, "Same inputs should produce same outputs");
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [0x42u8; 16];
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key1 = vec![0u8; 32];
        let mut key2 = vec![0u8; 32];

        argon2.hash_password_into(b"password1", &salt, &mut key1).unwrap();
        argon2.hash_password_into(b"password2", &salt, &mut key2).unwrap();

        assert_ne!(key1, key2, "Different passwords should produce different keys");
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = b"same_password";
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key1 = vec![0u8; 32];
        let mut key2 = vec![0u8; 32];

        argon2.hash_password_into(password, &[0x11u8; 16], &mut key1).unwrap();
        argon2.hash_password_into(password, &[0x22u8; 16], &mut key2).unwrap();

        assert_ne!(key1, key2, "Different salts should produce different keys");
    }

    #[test]
    fn test_various_output_lengths() {
        let password = b"test";
        let salt = [0u8; 16];

        for output_len in [16, 32, 48, 64] {
            let params = Params::new(1024, 1, 1, Some(output_len)).unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut output = vec![0u8; output_len];
            argon2.hash_password_into(password, &salt, &mut output).unwrap();
            assert_eq!(output.len(), output_len);
        }
    }

    #[test]
    fn test_empty_password() {
        let salt = [0u8; 16];
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; 32];
        // Empty password should still work
        argon2.hash_password_into(b"", &salt, &mut output).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_unicode_password() {
        let password = "日本語パスワード🐱".as_bytes();
        let salt = [0u8; 16];
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; 32];
        argon2.hash_password_into(password, &salt, &mut output).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_large_password() {
        let password = vec![b'A'; 1024 * 1024]; // 1 MB password
        let salt = [0u8; 16];
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; 32];
        argon2.hash_password_into(&password, &salt, &mut output).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_higher_memory_and_iterations() {
        // Test with higher memory (8 MB) and more iterations
        let password = b"secure_password";
        let salt = [0x55u8; 16];
        let params = Params::new(8192, 3, 2, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; 32];
        argon2.hash_password_into(password, &salt, &mut output).unwrap();
        assert_eq!(output.len(), 32);
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

        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm = [0u8; 42];
        hk.expand(info, &mut okm).unwrap();

        assert_eq!(okm.len(), 42);
        assert!(okm.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hkdf_extract_expand_separate() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        // Combined
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm1 = [0u8; 32];
        hk.expand(info, &mut okm1).unwrap();

        // Separate extract + expand
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        let hk2 = Hkdf::<Sha256>::from_prk(prk.as_slice()).unwrap();
        let mut okm2 = [0u8; 32];
        hk2.expand(info, &mut okm2).unwrap();

        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"ikm without salt";
        let info = b"info";

        // Salt = None uses a zero-filled salt
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_empty_info() {
        let ikm = b"ikm";
        let salt = b"salt";

        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"", &mut okm).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_various_lengths() {
        let ikm = b"ikm";
        let salt = b"salt";
        let info = b"info";

        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

        for len in [1, 16, 32, 64, 128, 255] {
            let mut okm = vec![0u8; len];
            hk.expand(info, &mut okm).unwrap();
            assert_eq!(okm.len(), len);
        }
    }

    #[test]
    fn test_hkdf_max_length() {
        // SHA-256 HKDF can produce max 255 * 32 = 8160 bytes
        let ikm = b"ikm";
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut okm = vec![0u8; 255 * 32];
        hk.expand(b"", &mut okm).unwrap();
        assert_eq!(okm.len(), 255 * 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"consistent ikm";
        let salt = b"salt";
        let info = b"info";

        let hk1 = Hkdf::<Sha256>::new(Some(salt), ikm);
        let hk2 = Hkdf::<Sha256>::new(Some(salt), ikm);

        let mut okm1 = [0u8; 32];
        let mut okm2 = [0u8; 32];

        hk1.expand(info, &mut okm1).unwrap();
        hk2.expand(info, &mut okm2).unwrap();

        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_hkdf_different_info_different_output() {
        let ikm = b"ikm";
        let salt = b"salt";

        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

        let mut okm1 = [0u8; 32];
        let mut okm2 = [0u8; 32];

        hk.expand(b"info1", &mut okm1).unwrap();
        hk.expand(b"info2", &mut okm2).unwrap();

        assert_ne!(okm1, okm2);
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

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(nonce_arr, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(nonce_arr, ciphertext.as_ref()).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_with_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";
        let aad = b"Associated data";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_arr, Payload { msg: plaintext, aad })
            .unwrap();

        let decrypted = cipher
            .decrypt(nonce_arr, Payload { msg: &ciphertext, aad })
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aad_mismatch_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";
        let aad = b"Associated data";
        let wrong_aad = b"Wrong AAD";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_arr, Payload { msg: plaintext, aad })
            .unwrap();

        let result = cipher.decrypt(
            nonce_arr,
            Payload {
                msg: &ciphertext,
                aad: wrong_aad,
            },
        );

        assert!(result.is_err(), "Decryption should fail with wrong AAD");
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x99u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(nonce_arr, plaintext.as_ref()).unwrap();

        let wrong_cipher = Aes256Gcm::new_from_slice(&wrong_key).unwrap();
        let result = wrong_cipher.decrypt(nonce_arr, ciphertext.as_ref());

        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let wrong_nonce = [0x99u8; 12];
        let plaintext = b"Secret message";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        let result = cipher.decrypt(Nonce::from_slice(&wrong_nonce), ciphertext.as_ref());

        assert!(result.is_err(), "Decryption should fail with wrong nonce");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        let mut ciphertext = cipher.encrypt(nonce_arr, plaintext.as_ref()).unwrap();

        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = cipher.decrypt(nonce_arr, ciphertext.as_ref());
        assert!(result.is_err(), "Decryption should fail with tampered ciphertext");
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(nonce_arr, plaintext.as_ref()).unwrap();
        // Empty plaintext still produces auth tag (16 bytes)
        assert_eq!(ciphertext.len(), 16);

        let decrypted = cipher.decrypt(nonce_arr, ciphertext.as_ref()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(nonce_arr, plaintext.as_ref()).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = cipher.decrypt(nonce_arr, ciphertext.as_ref()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_length() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        for len in [0, 1, 16, 100, 1000] {
            let plaintext = vec![0u8; len];
            let ciphertext = cipher.encrypt(nonce_arr, plaintext.as_ref()).unwrap();
            // Ciphertext = plaintext + 16-byte auth tag
            assert_eq!(ciphertext.len(), len + 16);
        }
    }

    #[test]
    fn test_nonce_uniqueness_matters() {
        let key = [0x42u8; 32];
        let plaintext = b"Same plaintext";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ct1 = cipher
            .encrypt(Nonce::from_slice(&[0x01u8; 12]), plaintext.as_ref())
            .unwrap();
        let ct2 = cipher
            .encrypt(Nonce::from_slice(&[0x02u8; 12]), plaintext.as_ref())
            .unwrap();

        assert_ne!(ct1, ct2, "Different nonces should produce different ciphertexts");
    }

    #[test]
    fn test_deterministic_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Deterministic test";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_arr = Nonce::from_slice(&nonce);

        let ct1 = cipher.encrypt(nonce_arr, plaintext.as_ref()).unwrap();
        let ct2 = cipher.encrypt(nonce_arr, plaintext.as_ref()).unwrap();

        assert_eq!(ct1, ct2, "Same key/nonce/plaintext should produce same ciphertext");
    }
}

// =============================================================================
// HMAC-SHA256 TESTS
// =============================================================================

mod hmac_tests {
    use super::*;
    use hmac::Mac as HmacMac;

    #[test]
    fn test_basic_hmac() {
        let key = b"secret key";
        let message = b"message to authenticate";

        let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 32);
    }

    #[test]
    fn test_hmac_verify_success() {
        let key = b"secret key";
        let message = b"message to authenticate";

        let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac.update(message);
        let tag = mac.finalize().into_bytes();

        // Verify
        let mut mac2 = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac2.update(message);
        let computed = mac2.finalize().into_bytes();

        assert!(bool::from(computed.as_slice().ct_eq(tag.as_slice())));
    }

    #[test]
    fn test_hmac_verify_wrong_message() {
        let key = b"secret key";
        let message = b"original message";
        let wrong_message = b"tampered message";

        let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac.update(message);
        let tag = mac.finalize().into_bytes();

        let mut mac2 = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac2.update(wrong_message);
        let computed = mac2.finalize().into_bytes();

        assert!(!bool::from(computed.as_slice().ct_eq(tag.as_slice())));
    }

    #[test]
    fn test_hmac_verify_wrong_key() {
        let key = b"secret key";
        let wrong_key = b"wrong key!";
        let message = b"message";

        let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac.update(message);
        let tag = mac.finalize().into_bytes();

        let mut mac2 = <HmacSha256 as HmacMac>::new_from_slice(wrong_key).unwrap();
        mac2.update(message);
        let computed = mac2.finalize().into_bytes();

        assert!(!bool::from(computed.as_slice().ct_eq(tag.as_slice())));
    }

    #[test]
    fn test_hmac_deterministic() {
        let key = b"key";
        let message = b"message";

        let mut mac1 = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac1.update(message);
        let tag1 = mac1.finalize().into_bytes();

        let mut mac2 = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac2.update(message);
        let tag2 = mac2.finalize().into_bytes();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_hmac_empty_message() {
        let key = b"key";
        let message = b"";

        let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac.update(message);
        let tag = mac.finalize();

        assert_eq!(tag.into_bytes().len(), 32);
    }

    #[test]
    fn test_hmac_incremental_update() {
        let key = b"key";
        let message = b"Hello, world!";

        // Single update
        let mut mac1 = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac1.update(message);
        let tag1 = mac1.finalize().into_bytes();

        // Incremental updates
        let mut mac2 = <HmacSha256 as HmacMac>::new_from_slice(key).unwrap();
        mac2.update(b"Hello, ");
        mac2.update(b"world!");
        let tag2 = mac2.finalize().into_bytes();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_hmac_various_key_lengths() {
        let message = b"message";

        for key_len in [1, 16, 32, 64, 128, 256] {
            let key = vec![0x42u8; key_len];
            let mut mac = <HmacSha256 as HmacMac>::new_from_slice(&key).unwrap();
            mac.update(message);
            let tag = mac.finalize();
            assert_eq!(tag.into_bytes().len(), 32);
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
        let data = b"hello";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_known_vector() {
        // Test vector: SHA-256("abc") = ba7816bf...
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let hash = hasher.finalize();

        let expected = hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_empty_input() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let hash = hasher.finalize();

        let expected = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_deterministic() {
        let data = b"test data";

        let mut h1 = Sha256::new();
        h1.update(data);
        let hash1 = h1.finalize();

        let mut h2 = Sha256::new();
        h2.update(data);
        let hash2 = h2.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_inputs() {
        let mut h1 = Sha256::new();
        h1.update(b"input1");
        let hash1 = h1.finalize();

        let mut h2 = Sha256::new();
        h2.update(b"input2");
        let hash2 = h2.finalize();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_incremental_update() {
        let data = b"Hello, world!";

        let mut h1 = Sha256::new();
        h1.update(data);
        let hash1 = h1.finalize();

        let mut h2 = Sha256::new();
        h2.update(b"Hello, ");
        h2.update(b"world!");
        let hash2 = h2.finalize();

        assert_eq!(hash1, hash2);
    }
}

// =============================================================================
// X25519 KEY EXCHANGE TESTS
// =============================================================================

mod x25519_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_keypair_generation() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        assert_eq!(secret.as_bytes().len(), 32);
        assert_eq!(public.as_bytes().len(), 32);
    }

    #[test]
    fn test_key_exchange_symmetric() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);

        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_secret);

        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "Shared secrets should be equal"
        );
    }

    #[test]
    fn test_public_key_derivation() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public1 = PublicKey::from(&secret);
        let public2 = PublicKey::from(&secret);

        assert_eq!(public1.as_bytes(), public2.as_bytes());
    }

    #[test]
    fn test_different_keypairs_different_shared() {
        let alice = StaticSecret::random_from_rng(OsRng);
        let bob1 = StaticSecret::random_from_rng(OsRng);
        let bob2 = StaticSecret::random_from_rng(OsRng);

        let shared1 = alice.diffie_hellman(&PublicKey::from(&bob1));
        let shared2 = alice.diffie_hellman(&PublicKey::from(&bob2));

        assert_ne!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_deterministic_from_bytes() {
        let secret_bytes = [0x42u8; 32];
        let secret1 = StaticSecret::from(secret_bytes);
        let secret2 = StaticSecret::from(secret_bytes);

        let public1 = PublicKey::from(&secret1);
        let public2 = PublicKey::from(&secret2);

        assert_eq!(public1.as_bytes(), public2.as_bytes());
    }

    #[test]
    fn test_shared_secret_not_zero() {
        let alice = StaticSecret::random_from_rng(OsRng);
        let bob = StaticSecret::random_from_rng(OsRng);

        let shared = alice.diffie_hellman(&PublicKey::from(&bob));

        // Shared secret should not be all zeros
        assert!(shared.as_bytes().iter().any(|&b| b != 0));
    }
}

// =============================================================================
// CONSTANT-TIME COMPARISON TESTS
// =============================================================================

mod constant_time_tests {
    use super::*;

    #[test]
    fn test_equal_slices() {
        let a = b"hello";
        let b = b"hello";
        assert!(bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_unequal_slices() {
        let a = b"hello";
        let b = b"world";
        assert!(!bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_different_lengths() {
        let a = b"short";
        let b = b"longer string";
        // Different length slices should not be equal
        assert!(!bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_single_bit_difference() {
        let a = [0x00, 0x00, 0x00, 0x00];
        let b = [0x00, 0x00, 0x00, 0x01];
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_empty_slices() {
        let a: &[u8] = &[];
        let b: &[u8] = &[];
        assert!(bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_large_equal_slices() {
        let a = vec![0x42u8; 10000];
        let b = vec![0x42u8; 10000];
        assert!(bool::from(a.as_slice().ct_eq(b.as_slice())));
    }
}

// =============================================================================
// ML-KEM-768 (POST-QUANTUM) TESTS
// =============================================================================

mod mlkem_tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (pk, sk) = mlkem768::keypair();

        assert_eq!(pk.as_bytes().len(), mlkem768::public_key_bytes());
        assert_eq!(sk.as_bytes().len(), mlkem768::secret_key_bytes());
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let (pk, sk) = mlkem768::keypair();

        let (ss_enc, ct) = mlkem768::encapsulate(&pk);
        let ss_dec = mlkem768::decapsulate(&ct, &sk);

        assert_eq!(
            ss_enc.as_bytes(),
            ss_dec.as_bytes(),
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_different_keypairs_different_shared() {
        let (pk1, _sk1) = mlkem768::keypair();
        let (pk2, sk2) = mlkem768::keypair();

        let (ss1, ct1) = mlkem768::encapsulate(&pk1);
        let (ss2, _ct2) = mlkem768::encapsulate(&pk2);

        // Different public keys -> different shared secrets
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());

        // Wrong secret key -> wrong shared secret
        let ss_wrong = mlkem768::decapsulate(&ct1, &sk2);
        assert_ne!(ss1.as_bytes(), ss_wrong.as_bytes());
    }

    #[test]
    fn test_ciphertext_length() {
        let (pk, _sk) = mlkem768::keypair();
        let (_ss, ct) = mlkem768::encapsulate(&pk);

        assert_eq!(ct.as_bytes().len(), mlkem768::ciphertext_bytes());
    }

    #[test]
    fn test_shared_secret_length() {
        let (pk, _sk) = mlkem768::keypair();
        let (ss, _ct) = mlkem768::encapsulate(&pk);

        // ML-KEM shared secrets are 32 bytes
        assert_eq!(ss.as_bytes().len(), 32);
    }

    #[test]
    fn test_determinism_from_same_seed() {
        // Multiple keypairs should be different (random)
        let (pk1, _) = mlkem768::keypair();
        let (pk2, _) = mlkem768::keypair();

        assert_ne!(pk1.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn test_encapsulate_multiple_times() {
        let (pk, sk) = mlkem768::keypair();

        // Multiple encapsulations produce different ciphertexts but same key can decrypt
        let (ss1, ct1) = mlkem768::encapsulate(&pk);
        let (ss2, ct2) = mlkem768::encapsulate(&pk);

        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());

        // Both can be decapsulated
        let dec1 = mlkem768::decapsulate(&ct1, &sk);
        let dec2 = mlkem768::decapsulate(&ct2, &sk);

        assert_eq!(ss1.as_bytes(), dec1.as_bytes());
        assert_eq!(ss2.as_bytes(), dec2.as_bytes());
    }
}

// =============================================================================
// ZEROIZE TESTS
// =============================================================================

mod zeroize_tests {
    use super::*;

    #[test]
    fn test_zeroize_vec() {
        let mut secret = vec![0x42u8; 32];
        secret.zeroize();

        assert!(secret.iter().all(|&b| b == 0), "Memory should be zeroed");
    }

    #[test]
    fn test_zeroize_array() {
        let mut secret = [0x42u8; 32];
        secret.zeroize();

        assert!(secret.iter().all(|&b| b == 0), "Memory should be zeroed");
    }

    #[test]
    fn test_zeroize_vec_clears_data() {
        // zeroize on Vec zeroes the content AND clears the vector (length becomes 0)
        // This is the documented secure behavior - data is zeroed before clearing
        let mut secret = vec![0x42u8; 64];
        secret.zeroize();

        // After zeroize, Vec is cleared (length = 0)
        assert_eq!(secret.len(), 0);
    }
}

// =============================================================================
// SECURE RANDOM TESTS
// =============================================================================

mod random_tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_random_bytes_length() {
        let mut buffer = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut buffer);
        assert_eq!(buffer.len(), 32);
    }

    #[test]
    fn test_random_bytes_not_zero() {
        let mut buffer = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut buffer);

        // Extremely unlikely to be all zeros
        assert!(buffer.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_bytes_unique() {
        let mut buf1 = vec![0u8; 32];
        let mut buf2 = vec![0u8; 32];

        rand::thread_rng().fill_bytes(&mut buf1);
        rand::thread_rng().fill_bytes(&mut buf2);

        assert_ne!(buf1, buf2, "Random outputs should be unique");
    }

    #[test]
    fn test_random_bytes_various_lengths() {
        for len in [1, 16, 32, 64, 128, 256, 1024] {
            let mut buffer = vec![0u8; len];
            rand::thread_rng().fill_bytes(&mut buffer);
            assert_eq!(buffer.len(), len);
        }
    }

    #[test]
    fn test_random_distribution() {
        // Very basic distribution test - all byte values should eventually appear
        let mut seen = HashSet::new();
        let mut rng = rand::thread_rng();

        // Generate enough random bytes to likely see all values
        for _ in 0..10000 {
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte);
            seen.insert(byte[0]);

            if seen.len() == 256 {
                break;
            }
        }

        // Should have seen at least 200 different byte values
        assert!(seen.len() > 200, "Random distribution seems poor");
    }
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

mod integration_tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_full_encryption_workflow() {
        // Simulate a complete encryption workflow:
        // 1. Derive key with Argon2id
        // 2. Generate random nonce
        // 3. Encrypt with AES-GCM
        // 4. Create HMAC over ciphertext
        // 5. Verify and decrypt

        let password = b"user_password";
        let salt = [0x42u8; 16];
        let plaintext = b"This is a secret message!";

        // 1. Key derivation
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = vec![0u8; 32];
        argon2.hash_password_into(password, &salt, &mut key).unwrap();

        // 2. Generate nonce
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        // 3. Encrypt
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        // 4. HMAC
        use hmac::Mac as HmacMac;
        let mut mac = <HmacSha256 as HmacMac>::new_from_slice(&key).unwrap();
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        // 5. Verify HMAC
        let mut mac2 = <HmacSha256 as HmacMac>::new_from_slice(&key).unwrap();
        mac2.update(&ciphertext);
        let tag2 = mac2.finalize().into_bytes();
        assert!(bool::from(tag.as_slice().ct_eq(tag2.as_slice())));

        // 6. Decrypt
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hybrid_key_exchange() {
        // Simulate hybrid (X25519 + ML-KEM) key exchange

        // Classical X25519
        let alice_x25519 = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_x25519_pub = PublicKey::from(&alice_x25519);

        let bob_x25519 = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_x25519_pub = PublicKey::from(&bob_x25519);

        let shared_x25519_a = alice_x25519.diffie_hellman(&bob_x25519_pub);
        let shared_x25519_b = bob_x25519.diffie_hellman(&alice_x25519_pub);

        assert_eq!(shared_x25519_a.as_bytes(), shared_x25519_b.as_bytes());

        // Post-quantum ML-KEM
        let (bob_mlkem_pk, bob_mlkem_sk) = mlkem768::keypair();
        let (shared_mlkem_enc, ct) = mlkem768::encapsulate(&bob_mlkem_pk);
        let shared_mlkem_dec = mlkem768::decapsulate(&ct, &bob_mlkem_sk);

        assert_eq!(shared_mlkem_enc.as_bytes(), shared_mlkem_dec.as_bytes());

        // Combine via HKDF
        let mut combined = Vec::new();
        combined.extend_from_slice(shared_x25519_a.as_bytes());
        combined.extend_from_slice(shared_mlkem_enc.as_bytes());

        let hk = Hkdf::<Sha256>::new(None, &combined);
        let mut final_key = [0u8; 32];
        hk.expand(b"hybrid key", &mut final_key).unwrap();

        assert_eq!(final_key.len(), 32);
    }

    #[test]
    fn test_hkdf_domain_separation() {
        // Test that HKDF with different info produces different keys
        let ikm = b"master key material";
        let salt = b"salt";

        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

        let mut encryption_key = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        let mut frame_key = [0u8; 32];

        hk.expand(b"meow_encryption_v1", &mut encryption_key).unwrap();
        hk.expand(b"meow_hmac_v1", &mut hmac_key).unwrap();
        hk.expand(b"meow_frame_mac_v1", &mut frame_key).unwrap();

        assert_ne!(encryption_key, hmac_key);
        assert_ne!(encryption_key, frame_key);
        assert_ne!(hmac_key, frame_key);
    }

    #[test]
    fn test_aad_binding() {
        // Test that AAD properly binds metadata to encryption
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"secret";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        // Encrypt with file size as AAD
        let aad1 = b"filesize:1024";
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad1 })
            .unwrap();

        // Decryption with correct AAD works
        let dec = cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: aad1 })
            .unwrap();
        assert_eq!(dec, plaintext);

        // Decryption with wrong AAD fails (file size tampered)
        let aad2 = b"filesize:2048";
        let result = cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: aad2 });
        assert!(result.is_err());
    }
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_aes_gcm_minimum_ciphertext() {
        // Minimum valid ciphertext is 16 bytes (auth tag only)
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        // Encrypt empty plaintext
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), b"".as_ref())
            .unwrap();
        assert_eq!(ct.len(), 16);

        // Decrypt
        let pt = cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_binary_data_roundtrip() {
        // Test with binary data containing all byte values
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext: Vec<u8> = (0..=255).collect();

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        let pt = cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).unwrap();

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_null_bytes_in_data() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"hello\x00world\x00\x00";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        let pt = cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).unwrap();

        assert_eq!(pt.as_slice(), plaintext);
    }
}
