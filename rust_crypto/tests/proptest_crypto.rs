//! Property-Based Tests for Meow Crypto
//!
//! Uses proptest to generate random inputs and verify invariants
//! through the `meow_crypto_rs::pure` module for coverage tracking.
//!
//! Run with: `cargo test --test proptest_crypto`

use meow_crypto_rs::pure;

// Raw crate imports only for AAD (Payload) tests not exposed through pure
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use proptest::prelude::*;

// =============================================================================
// AES-256-GCM PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Encryption followed by decryption returns original plaintext
    #[test]
    fn aes_gcm_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12),
    ) {
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let ciphertext = pure::aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();
        let decrypted = pure::aes_gcm_decrypt(&key, &nonce, &ciphertext, None).unwrap();

        prop_assert_eq!(decrypted, plaintext);
    }

    /// Property: Ciphertext length = plaintext length + 16 (auth tag)
    #[test]
    fn aes_gcm_ciphertext_length(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12),
    ) {
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let ciphertext = pure::aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();

        prop_assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    /// Property: Wrong key fails decryption
    #[test]
    fn aes_gcm_wrong_key_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        key1 in prop::collection::vec(any::<u8>(), 32..=32),
        key2 in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12),
    ) {
        prop_assume!(key1 != key2);

        let key1: [u8; 32] = key1.try_into().unwrap();
        let key2: [u8; 32] = key2.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let ciphertext = pure::aes_gcm_encrypt(&key1, &nonce, &plaintext, None).unwrap();
        let result = pure::aes_gcm_decrypt(&key2, &nonce, &ciphertext, None);
        prop_assert!(result.is_err());
    }

    /// Property: AAD mismatch fails decryption
    /// (Uses raw aes_gcm Payload API since pure doesn't expose AAD)
    #[test]
    fn aes_gcm_aad_mismatch_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        aad1 in prop::collection::vec(any::<u8>(), 1..64),
        aad2 in prop::collection::vec(any::<u8>(), 1..64),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12),
    ) {
        prop_assume!(aad1 != aad2);

        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad1,
                },
            )
            .unwrap();

        let result = cipher.decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad2,
            },
        );

        prop_assert!(result.is_err());
    }

    /// Property: Any bit flip in ciphertext causes decryption failure
    #[test]
    fn aes_gcm_bit_flip_detected(
        plaintext in prop::collection::vec(any::<u8>(), 16..256),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12),
        flip_position in 0usize..1000,
    ) {
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let ciphertext = pure::aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();

        let flip_idx = flip_position % ciphertext.len();
        let mut tampered = ciphertext.clone();
        tampered[flip_idx] ^= 0x01;

        let result = pure::aes_gcm_decrypt(&key, &nonce, &tampered, None);
        prop_assert!(result.is_err());
    }
}

// =============================================================================
// X25519 PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Shared secrets are symmetric (Alice→Bob == Bob→Alice)
    #[test]
    fn x25519_shared_secret_symmetric(
        alice_bytes in prop::collection::vec(any::<u8>(), 32..=32),
        bob_bytes in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        let alice_bytes: [u8; 32] = alice_bytes.try_into().unwrap();
        let bob_bytes: [u8; 32] = bob_bytes.try_into().unwrap();

        let pub_a = pure::x25519_public_from_private(&alice_bytes).unwrap();
        let pub_b = pure::x25519_public_from_private(&bob_bytes).unwrap();

        let shared_a = pure::x25519_exchange(&alice_bytes, &pub_b).unwrap();
        let shared_b = pure::x25519_exchange(&bob_bytes, &pub_a).unwrap();

        prop_assert_eq!(shared_a, shared_b);
    }

    /// Property: Public key derivation is deterministic
    #[test]
    fn x25519_public_key_deterministic(
        secret_bytes in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        let secret_bytes: [u8; 32] = secret_bytes.try_into().unwrap();

        let public1 = pure::x25519_public_from_private(&secret_bytes).unwrap();
        let public2 = pure::x25519_public_from_private(&secret_bytes).unwrap();

        prop_assert_eq!(public1, public2);
    }

    /// Property: Shared secret is always 32 bytes
    #[test]
    fn x25519_shared_secret_length(
        alice_bytes in prop::collection::vec(any::<u8>(), 32..=32),
        bob_bytes in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        let alice_bytes: [u8; 32] = alice_bytes.try_into().unwrap();
        let bob_bytes: [u8; 32] = bob_bytes.try_into().unwrap();

        let pub_b = pure::x25519_public_from_private(&bob_bytes).unwrap();
        let shared = pure::x25519_exchange(&alice_bytes, &pub_b).unwrap();

        prop_assert_eq!(shared.len(), 32);
    }
}

// =============================================================================
// ARGON2ID PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Same password + salt always produces same key
    #[test]
    fn argon2id_deterministic(
        password in prop::collection::vec(any::<u8>(), 0..128),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        let salt: [u8; 16] = salt.try_into().unwrap();

        let key1 = pure::derive_key_argon2id(&password, &salt, 1024, 1, 1, 32).unwrap();
        let key2 = pure::derive_key_argon2id(&password, &salt, 1024, 1, 1, 32).unwrap();

        prop_assert_eq!(key1, key2);
    }

    /// Property: Different passwords produce different keys
    #[test]
    fn argon2id_password_sensitivity(
        password1 in prop::collection::vec(any::<u8>(), 1..64),
        password2 in prop::collection::vec(any::<u8>(), 1..64),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        prop_assume!(password1 != password2);
        let salt: [u8; 16] = salt.try_into().unwrap();

        let key1 = pure::derive_key_argon2id(&password1, &salt, 1024, 1, 1, 32).unwrap();
        let key2 = pure::derive_key_argon2id(&password2, &salt, 1024, 1, 1, 32).unwrap();

        prop_assert_ne!(key1, key2);
    }

    /// Property: Different salts produce different keys
    #[test]
    fn argon2id_salt_sensitivity(
        password in prop::collection::vec(any::<u8>(), 1..64),
        salt1 in prop::collection::vec(any::<u8>(), 16..=16),
        salt2 in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        prop_assume!(salt1 != salt2);
        let salt1: [u8; 16] = salt1.try_into().unwrap();
        let salt2: [u8; 16] = salt2.try_into().unwrap();

        let key1 = pure::derive_key_argon2id(&password, &salt1, 1024, 1, 1, 32).unwrap();
        let key2 = pure::derive_key_argon2id(&password, &salt2, 1024, 1, 1, 32).unwrap();

        prop_assert_ne!(key1, key2);
    }

    /// Property: Output has expected length
    #[test]
    fn argon2id_output_length(
        password in prop::collection::vec(any::<u8>(), 1..64),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        output_len in 16usize..128,
    ) {
        let salt: [u8; 16] = salt.try_into().unwrap();

        let key = pure::derive_key_argon2id(&password, &salt, 1024, 1, 1, output_len).unwrap();

        prop_assert_eq!(key.len(), output_len);
    }
}

// =============================================================================
// HMAC-SHA256 PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: HMAC is deterministic
    #[test]
    fn hmac_deterministic(
        key in prop::collection::vec(any::<u8>(), 16..128),
        message in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let tag1 = pure::hmac_sha256(&key, &message).unwrap();
        let tag2 = pure::hmac_sha256(&key, &message).unwrap();

        prop_assert!(pure::constant_time_compare(&tag1, &tag2));
    }

    /// Property: Different messages produce different tags
    #[test]
    fn hmac_message_sensitivity(
        key in prop::collection::vec(any::<u8>(), 16..128),
        message1 in prop::collection::vec(any::<u8>(), 1..512),
        message2 in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(message1 != message2);

        let tag1 = pure::hmac_sha256(&key, &message1).unwrap();
        let tag2 = pure::hmac_sha256(&key, &message2).unwrap();

        prop_assert!(!pure::constant_time_compare(&tag1, &tag2));
    }

    /// Property: HMAC tag is always 32 bytes
    #[test]
    fn hmac_tag_length(
        key in prop::collection::vec(any::<u8>(), 16..128),
        message in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let tag = pure::hmac_sha256(&key, &message).unwrap();

        prop_assert_eq!(tag.len(), 32);
    }
}

// =============================================================================
// SHA-256 PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: SHA-256 is deterministic
    #[test]
    fn sha256_deterministic(
        data in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let hash1 = pure::sha256(&data);
        let hash2 = pure::sha256(&data);

        prop_assert_eq!(hash1, hash2);
    }

    /// Property: Different data produces different hashes
    #[test]
    fn sha256_collision_resistance(
        data1 in prop::collection::vec(any::<u8>(), 1..512),
        data2 in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(data1 != data2);

        let hash1 = pure::sha256(&data1);
        let hash2 = pure::sha256(&data2);

        prop_assert_ne!(hash1, hash2);
    }

    /// Property: SHA-256 output is always 32 bytes
    #[test]
    fn sha256_output_length(
        data in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let hash = pure::sha256(&data);
        prop_assert_eq!(hash.len(), 32);
    }
}

// =============================================================================
// SECURE ZERO PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: After secure_zero, all bytes are zero
    #[test]
    fn secure_zero_clears_all_bytes(
        data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let mut buffer = data.clone();
        pure::secure_zero(&mut buffer);

        prop_assert!(buffer.iter().all(|&b| b == 0));
    }

    /// Property: Secure zero on array clears all bytes
    #[test]
    fn secure_zero_array(
        byte in any::<u8>(),
    ) {
        let mut arr = [byte; 64];
        pure::secure_zero(&mut arr);

        prop_assert!(arr.iter().all(|&b| b == 0));
    }
}

// =============================================================================
// CONSTANT-TIME PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: constant_time_compare returns true for equal slices
    #[test]
    fn ct_compare_equal_slices(
        data in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assert!(pure::constant_time_compare(&data, &data));
    }

    /// Property: constant_time_compare returns false for unequal slices
    #[test]
    fn ct_compare_unequal_slices(
        data1 in prop::collection::vec(any::<u8>(), 1..256),
        data2 in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(data1 != data2);
        prop_assert!(!pure::constant_time_compare(&data1, &data2));
    }
}

// =============================================================================
// INTEGRATION PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Full encrypt-decrypt cycle preserves data
    #[test]
    fn full_encryption_roundtrip(
        password in ".{8,32}",
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        nonce in prop::collection::vec(any::<u8>(), 12..=12),
    ) {
        let salt: [u8; 16] = salt.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        // Derive key
        let key = pure::derive_key_argon2id(password.as_bytes(), &salt, 1024, 1, 1, 32).unwrap();

        // Encrypt
        let ciphertext = pure::aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();

        // Decrypt
        let decrypted = pure::aes_gcm_decrypt(&key, &nonce, &ciphertext, None).unwrap();

        prop_assert_eq!(decrypted, plaintext);
    }
}
