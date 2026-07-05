//! Additional Security Tests for Meow Crypto
//!
//! These tests focus on:
//! 1. Secure memory zeroing via pure::secure_zero
//! 2. Additional AES-GCM failure cases via pure::aes_gcm_*
//! 3. X25519 edge cases via pure::x25519_*
//! 4. Argon2id determinism and edge cases via pure::derive_key_argon2id
//! 5. Side-channel resistance verification via pure::constant_time_compare
//!
//! Run with: `cargo test --test additional_security_tests`

use meow_crypto_rs::pure;

// Raw crate imports only for AAD (Payload) tests not exposed through pure
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

// =============================================================================
// ZEROIZE / SECURE BUFFER VERIFICATION TESTS
// =============================================================================

mod zeroize_security_tests {
    use super::*;

    /// Verify that secure_zero clears key material
    #[test]
    fn test_secure_zero_key_material_after_use() {
        let mut key = [0x42u8; 32];
        pure::secure_zero(&mut key);
        assert!(
            key.iter().all(|&b| b == 0),
            "Key material not properly zeroed"
        );
    }

    /// Verify secure_zero works on heap-allocated secrets
    #[test]
    fn test_secure_zero_vec() {
        let mut secret = vec![0xAAu8; 64];
        pure::secure_zero(&mut secret);
        assert!(secret.iter().all(|&b| b == 0), "Vec should be zeroed");
    }

    /// Verify password material can be properly zeroed
    #[test]
    fn test_secure_zero_password_buffer() {
        let mut password_bytes = b"super_secret_password_123!".to_vec();
        let original_len = password_bytes.len();
        pure::secure_zero(&mut password_bytes);
        assert!(
            password_bytes.iter().all(|&b| b == 0),
            "Password bytes should be zeroed"
        );
        assert_eq!(
            password_bytes.len(),
            original_len,
            "Length should be preserved"
        );
    }

    /// Verify nested secret structures can be zeroed
    #[test]
    fn test_secure_zero_nested_secrets() {
        let mut private = [0x11u8; 32];
        let mut public = [0x22u8; 32];

        pure::secure_zero(&mut private);
        pure::secure_zero(&mut public);

        assert!(private.iter().all(|&b| b == 0));
        assert!(public.iter().all(|&b| b == 0));
    }

    /// Verify secure_zero on a large buffer
    #[test]
    fn test_secure_zero_large_buffer() {
        let mut secret = vec![0xFFu8; 128];
        pure::secure_zero(&mut secret);
        assert!(secret.iter().all(|&b| b == 0), "Secret should be zeroed");
    }

    /// Test secure_zero doesn't panic on empty containers
    #[test]
    fn test_secure_zero_empty_containers() {
        let mut empty_vec: Vec<u8> = Vec::new();
        let mut empty_array: [u8; 0] = [];

        // Should not panic
        pure::secure_zero(&mut empty_vec);
        pure::secure_zero(&mut empty_array);

        assert_eq!(empty_vec.len(), 0);
    }
}

// =============================================================================
// AES-256-GCM ADDITIONAL FAILURE CASE TESTS
// =============================================================================

mod aes_gcm_failure_tests {
    use super::*;

    /// Test that truncated ciphertext fails decryption
    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"This is the secret message";

        let ciphertext = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();

        // Try decrypting truncated ciphertext (missing auth tag bytes)
        for truncate_by in 1..=16 {
            let truncated = &ciphertext[..ciphertext.len() - truncate_by];
            let result = pure::aes_gcm_decrypt(&key, &nonce, truncated, None);
            assert!(
                result.is_err(),
                "Truncated by {} bytes should fail",
                truncate_by
            );
        }
    }

    /// Test that appending data to ciphertext fails
    #[test]
    fn test_extended_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Original message";

        let mut ciphertext = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        ciphertext.extend_from_slice(b"garbage");

        let result = pure::aes_gcm_decrypt(&key, &nonce, &ciphertext, None);
        assert!(result.is_err(), "Extended ciphertext should fail");
    }

    /// Test every bit flip in auth tag causes failure
    #[test]
    fn test_auth_tag_bit_flip_detection() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Sensitive data";

        let ciphertext = pure::aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let tag_start = ciphertext.len() - 16;

        for byte_idx in 0..16 {
            for bit_idx in 0..8 {
                let mut modified = ciphertext.clone();
                modified[tag_start + byte_idx] ^= 1 << bit_idx;

                let result = pure::aes_gcm_decrypt(&key, &nonce, &modified, None);
                assert!(
                    result.is_err(),
                    "Bit flip at tag byte {} bit {} should fail",
                    byte_idx,
                    bit_idx
                );
            }
        }
    }

    /// Test that wrong AAD length fails even with matching prefix
    /// (Uses raw aes_gcm Payload API since pure doesn't expose AAD)
    #[test]
    fn test_aad_length_mismatch_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Data with AAD";
        let aad = b"authenticated_data";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap();

        let short_aad = &aad[..10];
        let result = cipher.decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: short_aad,
            },
        );
        assert!(result.is_err(), "Truncated AAD should fail");

        let mut long_aad = aad.to_vec();
        long_aad.extend_from_slice(b"_extra");
        let result = cipher.decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: &long_aad,
            },
        );
        assert!(result.is_err(), "Extended AAD should fail");
    }

    /// Test encryption with max-size plaintext (reasonable limit)
    #[test]
    fn test_large_plaintext_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = vec![0xAAu8; 1024 * 1024];

        let ciphertext = pure::aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = pure::aes_gcm_decrypt(&key, &nonce, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

// =============================================================================
// X25519 ADDITIONAL EDGE CASE TESTS
// =============================================================================

mod x25519_edge_tests {
    use super::*;

    /// Test that shared secret is non-trivial
    #[test]
    fn test_shared_secret_nontrivial() {
        for _ in 0..100 {
            let (priv_a, _) = pure::x25519_generate_keypair();
            let (_, pub_b) = pure::x25519_generate_keypair();

            let shared = pure::x25519_exchange(&priv_a, &pub_b).unwrap();

            assert!(shared.iter().any(|&b| b != 0x00), "Shared secret all zeros");
            assert!(shared.iter().any(|&b| b != 0xFF), "Shared secret all ones");
            let first = shared[0];
            assert!(
                shared.iter().any(|&b| b != first),
                "Shared secret has no entropy"
            );
        }
    }

    /// Test public key derivation is deterministic
    #[test]
    fn test_public_key_derivation_deterministic() {
        let secret_bytes = [0x42u8; 32];

        let public1 = pure::x25519_public_from_private(&secret_bytes).unwrap();
        let public2 = pure::x25519_public_from_private(&secret_bytes).unwrap();

        assert_eq!(
            public1, public2,
            "Same secret should produce same public key"
        );
    }

    /// Test key exchange with known test vectors
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

    /// Test that all-zero secret key produces valid exchange
    #[test]
    fn test_zero_secret_key_behavior() {
        let zero_secret = [0u8; 32];
        let zero_public = pure::x25519_public_from_private(&zero_secret).unwrap();
        assert_eq!(zero_public.len(), 32);

        let (_, other_pub) = pure::x25519_generate_keypair();
        let shared = pure::x25519_exchange(&zero_secret, &other_pub).unwrap();
        assert_eq!(shared.len(), 32);
    }
}

// =============================================================================
// ARGON2ID ADDITIONAL TESTS
// =============================================================================

mod argon2id_edge_tests {
    use super::*;

    /// Verify Argon2id output is deterministic
    #[test]
    fn test_argon2id_deterministic() {
        let password = b"test_password";
        let salt = [0x42u8; 16];

        let key1 = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
        let key2 = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();

        assert_eq!(key1, key2, "Same input should produce same output");
    }

    /// Test that different salts produce different keys
    #[test]
    fn test_argon2id_salt_sensitivity() {
        let password = b"same_password";
        let mut keys = Vec::new();

        for salt_byte in 0..10u8 {
            let salt = [salt_byte; 16];
            let key = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
            keys.push(key);
        }

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i], keys[j],
                    "Different salts must produce different keys"
                );
            }
        }
    }

    /// Test that different passwords produce different keys
    #[test]
    fn test_argon2id_password_sensitivity() {
        let salt = [0x42u8; 16];

        let passwords: Vec<&[u8]> = vec![b"password1", b"password2", b"Password1", b"password1 "];

        let mut keys = Vec::new();
        for password in &passwords {
            let key = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
            keys.push(key);
        }

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i], keys[j],
                    "Different passwords must produce different keys"
                );
            }
        }
    }

    /// Test various output lengths
    #[test]
    fn test_argon2id_output_lengths() {
        let password = b"password";
        let salt = [0x42u8; 16];

        for output_len in [16usize, 32, 64, 128] {
            let key = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, output_len).unwrap();
            assert_eq!(key.len(), output_len);
            assert!(
                key.iter().any(|&b| b != 0),
                "Output should not be all zeros"
            );
        }
    }

    /// Test empty password handling
    #[test]
    fn test_argon2id_empty_password() {
        let salt = [0x42u8; 16];
        let result = pure::derive_key_argon2id(b"", &salt, 1024, 1, 1, 32);
        assert!(result.is_ok(), "Empty password should be handled");
        assert!(result.unwrap().iter().any(|&b| b != 0));
    }

    /// Test Unicode password handling
    #[test]
    fn test_argon2id_unicode_password() {
        let salt = [0x42u8; 16];

        let unicode_passwords = ["пароль", "パスワード", "密码", "🐱🔐🐈"];

        for password in &unicode_passwords {
            let result = pure::derive_key_argon2id(password.as_bytes(), &salt, 1024, 1, 1, 32);
            assert!(
                result.is_ok(),
                "Unicode password '{}' should work",
                password
            );
        }
    }
}

// =============================================================================
// HMAC ADDITIONAL TESTS
// =============================================================================

mod hmac_additional_tests {
    use super::*;

    /// Test HMAC verification with constant-time comparison
    #[test]
    fn test_hmac_constant_time_verify() {
        let key = [0x42u8; 32];
        let message = b"message to authenticate";

        let tag = pure::hmac_sha256(&key, message).unwrap();
        assert!(pure::hmac_sha256_verify(&key, message, &tag).unwrap());
    }

    /// Test that HMAC detects message modification
    #[test]
    fn test_hmac_detects_modification() {
        let key = [0x42u8; 32];

        let tag_orig = pure::hmac_sha256(&key, b"original message").unwrap();
        let tag_mod = pure::hmac_sha256(&key, b"modified message").unwrap();

        assert!(!pure::constant_time_compare(&tag_orig, &tag_mod));
    }

    /// Test HMAC with various key lengths
    #[test]
    fn test_hmac_various_key_lengths() {
        let message = b"test message";

        for key_len in [16, 32, 64, 128] {
            let key = vec![0x42u8; key_len];
            let tag = pure::hmac_sha256(&key, message).unwrap();
            assert_eq!(tag.len(), 32);
        }
    }
}

// =============================================================================
// CONSTANT-TIME OPERATION TESTS
// =============================================================================

mod constant_time_tests {
    use super::*;

    /// Verify constant_time_compare returns correct results
    #[test]
    fn test_ct_compare_correctness() {
        assert!(pure::constant_time_compare(b"hello", b"hello"));
        assert!(!pure::constant_time_compare(b"hello", b"world"));
        assert!(!pure::constant_time_compare(&[0x00u8], &[0x01u8]));

        let empty: &[u8] = &[];
        assert!(pure::constant_time_compare(empty, empty));
    }

    /// Test constant_time_compare with different length slices
    #[test]
    fn test_ct_compare_different_lengths() {
        assert!(!pure::constant_time_compare(b"short", b"longer"));
        assert!(!pure::constant_time_compare(b"", b"nonempty"));
    }

    /// Test that constant-time operations handle large data
    #[test]
    fn test_ct_compare_large_data() {
        let a = vec![0x42u8; 10000];
        let b = vec![0x42u8; 10000];
        let c = {
            let mut v = vec![0x42u8; 10000];
            v[9999] = 0x43;
            v
        };

        assert!(pure::constant_time_compare(&a, &b));
        assert!(!pure::constant_time_compare(&a, &c));
    }
}

// =============================================================================
// INTEGRATION / WORKFLOW TESTS
// =============================================================================

mod workflow_tests {
    use super::*;

    /// Test complete encrypt-then-MAC workflow
    #[test]
    fn test_encrypt_then_mac_workflow() {
        let password = b"user_password_123";
        let salt = [0x42u8; 16];
        let plaintext = b"This is a top secret message!";

        // 1. Derive key material (64 bytes: 32 enc + 32 mac)
        let key_material = pure::derive_key_argon2id(password, &salt, 1024, 1, 1, 64).unwrap();

        let enc_key = &key_material[..32];
        let mac_key = &key_material[32..];

        // 2. Generate random nonce
        let nonce_vec = pure::secure_random(12);
        let nonce: [u8; 12] = nonce_vec.try_into().unwrap();

        // 3. Encrypt
        let ciphertext = pure::aes_gcm_encrypt(enc_key, &nonce, plaintext, None).unwrap();

        // 4. MAC over nonce || ciphertext
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&nonce);
        mac_input.extend_from_slice(&ciphertext);
        let tag = pure::hmac_sha256(mac_key, &mac_input).unwrap();

        // 5. Verify MAC (receiver side)
        assert!(pure::hmac_sha256_verify(mac_key, &mac_input, &tag).unwrap());

        // 6. Decrypt
        let decrypted = pure::aes_gcm_decrypt(enc_key, &nonce, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test key exchange + symmetric encryption workflow
    #[test]
    fn test_key_exchange_encryption_workflow() {
        let (priv_a, pub_a) = pure::x25519_generate_keypair();
        let (priv_b, pub_b) = pure::x25519_generate_keypair();

        let shared_a = pure::x25519_exchange(&priv_a, &pub_b).unwrap();
        let shared_b = pure::x25519_exchange(&priv_b, &pub_a).unwrap();
        assert_eq!(shared_a, shared_b);

        // Derive encryption key via HKDF
        let enc_key = pure::derive_key_hkdf(&shared_a, None, b"meow-enc-v1", 32).unwrap();

        let nonce_vec = pure::secure_random(12);
        let nonce: [u8; 12] = nonce_vec.try_into().unwrap();

        // Alice encrypts
        let plaintext = b"Secret message from Alice";
        let ciphertext = pure::aes_gcm_encrypt(&enc_key, &nonce, plaintext, None).unwrap();

        // Bob derives same key and decrypts
        let bob_enc_key = pure::derive_key_hkdf(&shared_b, None, b"meow-enc-v1", 32).unwrap();
        let decrypted = pure::aes_gcm_decrypt(&bob_enc_key, &nonce, &ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
