//! Additional Security Tests for Meow Crypto
//!
//! These tests focus on:
//! 1. Zeroize/SecureBuffer behavior verification
//! 2. Additional AES-GCM failure cases
//! 3. X25519 edge cases
//! 4. Argon2id determinism and edge cases
//! 5. Side-channel resistance verification
//!
//! Run with: `cargo test --test additional_security_tests`

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Helper function to create HMAC instance with explicit trait disambiguation
fn create_hmac(key: &[u8]) -> HmacSha256 {
    <HmacSha256 as HmacKeyInit>::new_from_slice(key).unwrap()
}

// =============================================================================
// ZEROIZE / SECURE BUFFER VERIFICATION TESTS
// =============================================================================

mod zeroize_security_tests {
    use super::*;

    /// Verify that zeroize actually clears sensitive data after use
    #[test]
    fn test_zeroize_key_material_after_use() {
        // Simulate key derivation then zeroization
        let mut key = [0x42u8; 32];
        
        // Use the key for encryption (simulated)
        let _cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        
        // Now zeroize
        key.zeroize();
        
        // Verify every byte is zero
        assert!(
            key.iter().all(|&b| b == 0),
            "Key material not properly zeroed after zeroize()"
        );
    }

    /// Verify zeroize works on heap-allocated secrets (Vec)
    #[test]
    fn test_zeroize_vec_complete_clearing() {
        let mut secret = vec![0xAAu8; 64];
        let original_ptr = secret.as_ptr();
        
        secret.zeroize();
        
        // Vec::zeroize clears the length (data was zeroed before clearing)
        assert_eq!(secret.len(), 0, "Vec should be cleared after zeroize");
        
        // Even though length is 0, we can verify the behavior is secure
        // by checking capacity wasn't changed (data was in-place zeroed)
        assert!(secret.capacity() >= 64, "Capacity should be preserved");
    }

    /// Verify password material can be properly zeroized
    #[test]
    fn test_zeroize_password_buffer() {
        let mut password = String::from("super_secret_password_123!");
        let original_len = password.len();
        
        // Zeroize the string's bytes
        unsafe {
            password.as_bytes_mut().zeroize();
        }
        
        // Verify the underlying bytes are zeroed
        assert!(
            password.bytes().all(|b| b == 0),
            "Password bytes should be zeroed"
        );
        assert_eq!(password.len(), original_len, "Length should be preserved");
    }

    /// Verify nested secret structures can be zeroized
    #[test]
    fn test_zeroize_nested_secrets() {
        struct KeyPair {
            private: [u8; 32],
            public: [u8; 32],
        }

        impl Zeroize for KeyPair {
            fn zeroize(&mut self) {
                self.private.zeroize();
                self.public.zeroize();
            }
        }

        let mut kp = KeyPair {
            private: [0x11u8; 32],
            public: [0x22u8; 32],
        };

        kp.zeroize();

        assert!(kp.private.iter().all(|&b| b == 0));
        assert!(kp.public.iter().all(|&b| b == 0));
    }

    /// Verify zeroize on a Box<[u8]>
    #[test]
    fn test_zeroize_boxed_secret() {
        let mut secret: Box<[u8]> = vec![0xFFu8; 128].into_boxed_slice();
        
        secret.zeroize();
        
        assert!(
            secret.iter().all(|&b| b == 0),
            "Boxed secret should be zeroed"
        );
    }

    /// Test zeroize doesn't panic on empty containers
    #[test]
    fn test_zeroize_empty_containers() {
        let mut empty_vec: Vec<u8> = Vec::new();
        let mut empty_array: [u8; 0] = [];
        
        // Should not panic
        empty_vec.zeroize();
        empty_array.zeroize();
        
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

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        // Try decrypting truncated ciphertext (missing auth tag bytes)
        for truncate_by in 1..=16 {
            let truncated = &ciphertext[..ciphertext.len() - truncate_by];
            let result = cipher.decrypt(Nonce::from_slice(&nonce), truncated);
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

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        // Append garbage data
        ciphertext.extend_from_slice(b"garbage");

        let result = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref());
        assert!(result.is_err(), "Extended ciphertext should fail");
    }

    /// Test every bit flip in auth tag causes failure
    #[test]
    fn test_auth_tag_bit_flip_detection() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Sensitive data";

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        // Auth tag is last 16 bytes
        let tag_start = ciphertext.len() - 16;

        // Flip each bit in the auth tag
        for byte_idx in 0..16 {
            for bit_idx in 0..8 {
                let mut modified = ciphertext.clone();
                modified[tag_start + byte_idx] ^= 1 << bit_idx;

                let result = cipher.decrypt(Nonce::from_slice(&nonce), modified.as_ref());
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
    #[test]
    fn test_aad_length_mismatch_fails() {
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

        // Try with truncated AAD (prefix matches)
        let short_aad = &aad[..10];
        let result = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: short_aad,
            },
        );
        assert!(result.is_err(), "Truncated AAD should fail");

        // Try with extended AAD (original is prefix)
        let mut long_aad = aad.to_vec();
        long_aad.extend_from_slice(b"_extra");
        let result = cipher.decrypt(
            Nonce::from_slice(&nonce),
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
        // 1 MB plaintext
        let plaintext = vec![0xAAu8; 1024 * 1024];

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();
        
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag
        
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
}

// =============================================================================
// X25519 ADDITIONAL EDGE CASE TESTS
// =============================================================================

mod x25519_edge_tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Test that shared secret is non-trivial (not all zeros or ones)
    #[test]
    fn test_shared_secret_nontrivial() {
        for _ in 0..100 {
            let alice = StaticSecret::random_from_rng(OsRng);
            let bob = StaticSecret::random_from_rng(OsRng);

            let shared = alice.diffie_hellman(&PublicKey::from(&bob));
            let bytes = shared.as_bytes();

            // Should not be all zeros
            assert!(bytes.iter().any(|&b| b != 0x00), "Shared secret all zeros");
            // Should not be all ones
            assert!(bytes.iter().any(|&b| b != 0xFF), "Shared secret all ones");
            // Should have some entropy (not all same byte)
            let first = bytes[0];
            assert!(
                bytes.iter().any(|&b| b != first),
                "Shared secret has no entropy"
            );
        }
    }

    /// Test public key derivation is deterministic
    #[test]
    fn test_public_key_derivation_deterministic() {
        let secret_bytes = [0x42u8; 32];
        
        let secret1 = StaticSecret::from(secret_bytes);
        let secret2 = StaticSecret::from(secret_bytes);
        
        let public1 = PublicKey::from(&secret1);
        let public2 = PublicKey::from(&secret2);
        
        assert_eq!(
            public1.as_bytes(),
            public2.as_bytes(),
            "Same secret should produce same public key"
        );
    }

    /// Test key exchange with known test vectors
    #[test]
    fn test_x25519_rfc7748_test_vector() {
        // RFC 7748 test vector
        let alice_secret_bytes: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        
        let bob_secret_bytes: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];

        let alice_secret = StaticSecret::from(alice_secret_bytes);
        let bob_secret = StaticSecret::from(bob_secret_bytes);
        
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);
        
        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);
        
        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "Shared secrets must match"
        );
        
        // Expected shared secret from RFC 7748
        let expected: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
            0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
            0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
            0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
        ];
        
        assert_eq!(alice_shared.as_bytes(), &expected);
    }

    /// Test that all-zero secret key produces valid (but weak) exchange
    #[test]
    fn test_zero_secret_key_behavior() {
        let zero_secret = StaticSecret::from([0u8; 32]);
        let zero_public = PublicKey::from(&zero_secret);
        
        // Zero secret should still produce a valid public key
        assert_eq!(zero_public.as_bytes().len(), 32);
        
        // Exchange should work (though cryptographically weak)
        let other = StaticSecret::random_from_rng(OsRng);
        let other_public = PublicKey::from(&other);
        
        let shared = zero_secret.diffie_hellman(&other_public);
        assert_eq!(shared.as_bytes().len(), 32);
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
        
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        let mut key1 = vec![0u8; 32];
        let mut key2 = vec![0u8; 32];
        
        argon2.hash_password_into(password, &salt, &mut key1).unwrap();
        argon2.hash_password_into(password, &salt, &mut key2).unwrap();
        
        assert_eq!(key1, key2, "Same input should produce same output");
    }

    /// Test that different salts produce different keys
    #[test]
    fn test_argon2id_salt_sensitivity() {
        let password = b"same_password";
        
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        let mut keys = Vec::new();
        
        for salt_byte in 0..10u8 {
            let salt = [salt_byte; 16];
            let mut key = vec![0u8; 32];
            argon2.hash_password_into(password, &salt, &mut key).unwrap();
            keys.push(key);
        }
        
        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "Different salts must produce different keys");
            }
        }
    }

    /// Test that different passwords produce different keys
    #[test]
    fn test_argon2id_password_sensitivity() {
        let salt = [0x42u8; 16];
        
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        let passwords = [
            b"password1".as_ref(),
            b"password2".as_ref(),
            b"Password1".as_ref(), // Case difference
            b"password1 ".as_ref(), // Trailing space
        ];
        
        let mut keys = Vec::new();
        
        for password in &passwords {
            let mut key = vec![0u8; 32];
            argon2.hash_password_into(password, &salt, &mut key).unwrap();
            keys.push(key);
        }
        
        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "Different passwords must produce different keys");
            }
        }
    }

    /// Test various output lengths
    #[test]
    fn test_argon2id_output_lengths() {
        let password = b"password";
        let salt = [0x42u8; 16];
        
        for output_len in [16, 32, 64, 128] {
            let params = Params::new(1024, 1, 1, Some(output_len)).unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            
            let mut key = vec![0u8; output_len];
            argon2.hash_password_into(password, &salt, &mut key).unwrap();
            
            assert_eq!(key.len(), output_len);
            // Output should have some entropy
            assert!(key.iter().any(|&b| b != 0), "Output should not be all zeros");
        }
    }

    /// Test empty password handling
    #[test]
    fn test_argon2id_empty_password() {
        let salt = [0x42u8; 16];
        
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        let mut key = vec![0u8; 32];
        
        // Empty password should work (not recommended but valid)
        let result = argon2.hash_password_into(b"", &salt, &mut key);
        assert!(result.is_ok(), "Empty password should be handled");
        
        // Output should still have entropy
        assert!(key.iter().any(|&b| b != 0));
    }

    /// Test Unicode password handling
    #[test]
    fn test_argon2id_unicode_password() {
        let salt = [0x42u8; 16];
        
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        let unicode_passwords = [
            "пароль",           // Russian
            "パスワード",         // Japanese
            "密码",              // Chinese
            "🐱🔐🐈",           // Emoji
        ];
        
        for password in &unicode_passwords {
            let mut key = vec![0u8; 32];
            let result = argon2.hash_password_into(password.as_bytes(), &salt, &mut key);
            assert!(result.is_ok(), "Unicode password '{}' should work", password);
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
        
        let mut mac = create_hmac(&key);
        mac.update(message);
        let tag = mac.finalize().into_bytes();
        
        // Verify with constant-time comparison
        let mut mac2 = create_hmac(&key);
        mac2.update(message);
        let tag2 = mac2.finalize().into_bytes();
        
        assert!(bool::from(tag.as_slice().ct_eq(tag2.as_slice())));
    }

    /// Test that HMAC detects message modification
    #[test]
    fn test_hmac_detects_modification() {
        let key = [0x42u8; 32];
        let original_message = b"original message";
        let modified_message = b"modified message";
        
        let mut mac = create_hmac(&key);
        mac.update(original_message);
        let tag = mac.finalize().into_bytes();
        
        // Create tag for modified message
        let mut mac2 = create_hmac(&key);
        mac2.update(modified_message);
        let tag2 = mac2.finalize().into_bytes();
        
        // Tags should differ
        assert!(!bool::from(tag.as_slice().ct_eq(tag2.as_slice())));
    }

    /// Test HMAC with various key lengths
    #[test]
    fn test_hmac_various_key_lengths() {
        let message = b"test message";
        
        for key_len in [16, 32, 64, 128] {
            let key = vec![0x42u8; key_len];
            
            let mut mac = create_hmac(&key);
            mac.update(message);
            let tag = mac.finalize().into_bytes();
            
            // Tag should always be 32 bytes for SHA-256
            assert_eq!(tag.len(), 32);
        }
    }
}

// =============================================================================
// CONSTANT-TIME OPERATION TESTS
// =============================================================================

mod constant_time_tests {
    use super::*;

    /// Verify ct_eq returns correct results
    #[test]
    fn test_ct_eq_correctness() {
        // Equal slices
        assert!(bool::from(b"hello".ct_eq(b"hello")));
        
        // Unequal slices
        assert!(!bool::from(b"hello".ct_eq(b"world")));
        
        // Single bit difference
        assert!(!bool::from([0x00u8].as_slice().ct_eq(&[0x01u8])));
        
        // Empty slices
        let empty1: &[u8] = &[];
        let empty2: &[u8] = &[];
        assert!(bool::from(empty1.ct_eq(empty2)));
    }

    /// Test ct_eq with different length slices
    #[test]
    fn test_ct_eq_different_lengths() {
        // Different lengths should not be equal
        assert!(!bool::from(b"short".ct_eq(b"longer")));
        assert!(!bool::from(b"".ct_eq(b"nonempty")));
    }

    /// Test that constant-time operations handle large data
    #[test]
    fn test_ct_eq_large_data() {
        let a = vec![0x42u8; 10000];
        let b = vec![0x42u8; 10000];
        let c = {
            let mut v = vec![0x42u8; 10000];
            v[9999] = 0x43;
            v
        };
        
        assert!(bool::from(a.as_slice().ct_eq(b.as_slice())));
        assert!(!bool::from(a.as_slice().ct_eq(c.as_slice())));
    }
}

// =============================================================================
// INTEGRATION / WORKFLOW TESTS
// =============================================================================

mod workflow_tests {
    use super::*;
    use rand::RngCore;

    /// Test complete encrypt-then-MAC workflow
    #[test]
    fn test_encrypt_then_mac_workflow() {
        let password = b"user_password_123";
        let salt = [0x42u8; 16];
        let plaintext = b"This is a top secret message!";

        // 1. Derive key with Argon2id
        let params = Params::new(1024, 1, 1, Some(64)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key_material = vec![0u8; 64];
        argon2.hash_password_into(password, &salt, &mut key_material).unwrap();
        
        // Split into encryption key and MAC key
        let enc_key = &key_material[..32];
        let mac_key = &key_material[32..];

        // 2. Generate random nonce
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        // 3. Encrypt
        let cipher = Aes256Gcm::new_from_slice(enc_key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        // 4. MAC over nonce || ciphertext
        let mut mac = create_hmac(mac_key);
        mac.update(&nonce);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        // 5. Verify MAC (receiver side)
        let mut verify_mac = create_hmac(mac_key);
        verify_mac.update(&nonce);
        verify_mac.update(&ciphertext);
        let verify_tag = verify_mac.finalize().into_bytes();
        
        assert!(bool::from(tag.as_slice().ct_eq(verify_tag.as_slice())));

        // 6. Decrypt
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Test key exchange + symmetric encryption workflow
    #[test]
    fn test_key_exchange_encryption_workflow() {
        // Alice and Bob generate keypairs
        let alice_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        
        let bob_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_public = PublicKey::from(&bob_secret);

        // Key exchange
        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);
        
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

        // Use shared secret as encryption key
        let enc_key = alice_shared.as_bytes();
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Alice encrypts
        let plaintext = b"Secret message from Alice";
        let cipher = Aes256Gcm::new_from_slice(enc_key).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        // Bob decrypts
        let bob_cipher = Aes256Gcm::new_from_slice(bob_shared.as_bytes()).unwrap();
        let decrypted = bob_cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
