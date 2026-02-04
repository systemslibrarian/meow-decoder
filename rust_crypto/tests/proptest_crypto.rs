//! Property-Based Tests for Meow Crypto
//!
//! Uses proptest to generate random inputs and verify invariants.
//!
//! Run with: `cargo test --test proptest_crypto`

use proptest::prelude::*;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Helper function to create HMAC instance (disambiguates trait methods)
fn create_hmac(key: &[u8]) -> HmacSha256 {
    <HmacSha256 as HmacKeyInit>::new_from_slice(key).unwrap()
}

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

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .unwrap();

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

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

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
        // Skip if keys happen to be equal
        prop_assume!(key1 != key2);

        let key1: [u8; 32] = key1.try_into().unwrap();
        let key2: [u8; 32] = key2.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let cipher1 = Aes256Gcm::new_from_slice(&key1).unwrap();
        let cipher2 = Aes256Gcm::new_from_slice(&key2).unwrap();

        let ciphertext = cipher1
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        let result = cipher2.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref());
        prop_assert!(result.is_err());
    }

    /// Property: AAD mismatch fails decryption
    #[test]
    fn aes_gcm_aad_mismatch_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        aad1 in prop::collection::vec(any::<u8>(), 1..64),
        aad2 in prop::collection::vec(any::<u8>(), 1..64),
        key in prop::collection::vec(any::<u8>(), 32..=32),
        nonce in prop::collection::vec(any::<u8>(), 12..=12),
    ) {
        // Skip if AADs happen to be equal
        prop_assume!(aad1 != aad2);

        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad1,
                },
            )
            .unwrap();

        let result = cipher.decrypt(
            Nonce::from_slice(&nonce),
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

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        let flip_idx = flip_position % ciphertext.len();
        let mut tampered = ciphertext.clone();
        tampered[flip_idx] ^= 0x01;

        let result = cipher.decrypt(Nonce::from_slice(&nonce), tampered.as_ref());
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

        let alice = StaticSecret::from(alice_bytes);
        let bob = StaticSecret::from(bob_bytes);

        let alice_public = PublicKey::from(&alice);
        let bob_public = PublicKey::from(&bob);

        let alice_shared = alice.diffie_hellman(&bob_public);
        let bob_shared = bob.diffie_hellman(&alice_public);

        prop_assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    /// Property: Public key derivation is deterministic
    #[test]
    fn x25519_public_key_deterministic(
        secret_bytes in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        let secret_bytes: [u8; 32] = secret_bytes.try_into().unwrap();

        let secret1 = StaticSecret::from(secret_bytes);
        let secret2 = StaticSecret::from(secret_bytes);

        let public1 = PublicKey::from(&secret1);
        let public2 = PublicKey::from(&secret2);

        prop_assert_eq!(public1.as_bytes(), public2.as_bytes());
    }

    /// Property: Shared secret is always 32 bytes
    #[test]
    fn x25519_shared_secret_length(
        alice_bytes in prop::collection::vec(any::<u8>(), 32..=32),
        bob_bytes in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        let alice_bytes: [u8; 32] = alice_bytes.try_into().unwrap();
        let bob_bytes: [u8; 32] = bob_bytes.try_into().unwrap();

        let alice = StaticSecret::from(alice_bytes);
        let bob = StaticSecret::from(bob_bytes);

        let bob_public = PublicKey::from(&bob);
        let shared = alice.diffie_hellman(&bob_public);

        prop_assert_eq!(shared.as_bytes().len(), 32);
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

        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key1 = vec![0u8; 32];
        let mut key2 = vec![0u8; 32];

        argon2.hash_password_into(&password, &salt, &mut key1).unwrap();
        argon2.hash_password_into(&password, &salt, &mut key2).unwrap();

        prop_assert_eq!(key1, key2);
    }

    /// Property: Different passwords produce different keys
    #[test]
    fn argon2id_password_sensitivity(
        password1 in prop::collection::vec(any::<u8>(), 1..64),
        password2 in prop::collection::vec(any::<u8>(), 1..64),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        // Skip if passwords happen to be equal
        prop_assume!(password1 != password2);

        let salt: [u8; 16] = salt.try_into().unwrap();

        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key1 = vec![0u8; 32];
        let mut key2 = vec![0u8; 32];

        argon2.hash_password_into(&password1, &salt, &mut key1).unwrap();
        argon2.hash_password_into(&password2, &salt, &mut key2).unwrap();

        prop_assert_ne!(key1, key2);
    }

    /// Property: Different salts produce different keys
    #[test]
    fn argon2id_salt_sensitivity(
        password in prop::collection::vec(any::<u8>(), 1..64),
        salt1 in prop::collection::vec(any::<u8>(), 16..=16),
        salt2 in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        // Skip if salts happen to be equal
        prop_assume!(salt1 != salt2);

        let salt1: [u8; 16] = salt1.try_into().unwrap();
        let salt2: [u8; 16] = salt2.try_into().unwrap();

        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key1 = vec![0u8; 32];
        let mut key2 = vec![0u8; 32];

        argon2.hash_password_into(&password, &salt1, &mut key1).unwrap();
        argon2.hash_password_into(&password, &salt2, &mut key2).unwrap();

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

        let params = Params::new(1024, 1, 1, Some(output_len)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = vec![0u8; output_len];
        argon2.hash_password_into(&password, &salt, &mut key).unwrap();

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
        let mut mac1 = create_hmac(&key);
        let mut mac2 = create_hmac(&key);

        mac1.update(&message);
        mac2.update(&message);

        let tag1 = mac1.finalize().into_bytes();
        let tag2 = mac2.finalize().into_bytes();

        prop_assert!(bool::from(tag1.as_slice().ct_eq(tag2.as_slice())));
    }

    /// Property: Different messages produce different tags
    #[test]
    fn hmac_message_sensitivity(
        key in prop::collection::vec(any::<u8>(), 16..128),
        message1 in prop::collection::vec(any::<u8>(), 1..512),
        message2 in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(message1 != message2);

        let mut mac1 = create_hmac(&key);
        let mut mac2 = create_hmac(&key);

        mac1.update(&message1);
        mac2.update(&message2);

        let tag1 = mac1.finalize().into_bytes();
        let tag2 = mac2.finalize().into_bytes();

        prop_assert!(!bool::from(tag1.as_slice().ct_eq(tag2.as_slice())));
    }

    /// Property: HMAC tag is always 32 bytes
    #[test]
    fn hmac_tag_length(
        key in prop::collection::vec(any::<u8>(), 16..128),
        message in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut mac = create_hmac(&key);
        mac.update(&message);
        let tag = mac.finalize().into_bytes();

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
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&data);

        prop_assert_eq!(hash1.as_slice(), hash2.as_slice());
    }

    /// Property: Different data produces different hashes
    #[test]
    fn sha256_collision_resistance(
        data1 in prop::collection::vec(any::<u8>(), 1..512),
        data2 in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(data1 != data2);

        let hash1 = Sha256::digest(&data1);
        let hash2 = Sha256::digest(&data2);

        // Note: This is probabilistic - collision probability is 2^-256
        prop_assert_ne!(hash1.as_slice(), hash2.as_slice());
    }

    /// Property: SHA-256 output is always 32 bytes
    #[test]
    fn sha256_output_length(
        data in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let hash = Sha256::digest(&data);
        prop_assert_eq!(hash.len(), 32);
    }
}

// =============================================================================
// ZEROIZE PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: After zeroize, all bytes are zero
    #[test]
    fn zeroize_clears_all_bytes(
        data in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let mut buffer = data.clone();
        buffer.zeroize();

        prop_assert!(buffer.is_empty() || buffer.iter().all(|&b| b == 0));
    }

    /// Property: Zeroize on array clears all bytes
    #[test]
    fn zeroize_array(
        byte in any::<u8>(),
    ) {
        let mut arr = [byte; 64];
        arr.zeroize();

        prop_assert!(arr.iter().all(|&b| b == 0));
    }
}

// =============================================================================
// CONSTANT-TIME PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: ct_eq returns true for equal slices
    #[test]
    fn ct_eq_equal_slices(
        data in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assert!(bool::from(data.as_slice().ct_eq(data.as_slice())));
    }

    /// Property: ct_eq returns false for unequal slices
    #[test]
    fn ct_eq_unequal_slices(
        data1 in prop::collection::vec(any::<u8>(), 1..256),
        data2 in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(data1 != data2);
        prop_assert!(!bool::from(data1.as_slice().ct_eq(data2.as_slice())));
    }
}

// =============================================================================
// INTEGRATION PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Full encrypt-decrypt cycle preserves data
    #[test]
    fn full_encryption_roundtrip(
        password in ".{8,32}",  // Password between 8-32 chars
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        salt in prop::collection::vec(any::<u8>(), 16..=16),
        nonce in prop::collection::vec(any::<u8>(), 12..=12),
    ) {
        let salt: [u8; 16] = salt.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        // Derive key
        let params = Params::new(1024, 1, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = vec![0u8; 32];
        argon2.hash_password_into(password.as_bytes(), &salt, &mut key).unwrap();

        let key_arr: [u8; 32] = key.try_into().unwrap();

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&key_arr).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .unwrap();

        // Decrypt
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .unwrap();

        prop_assert_eq!(decrypted, plaintext);
    }
}
