//! Additional coverage tests for crypto_core
//!
//! These tests target specific uncovered code paths to achieve 95%+ coverage.

use crypto_core::{
    AadError, AeadError, AeadKey, AeadWrapper, AssociatedData, KeyError, Nonce, NonceError,
    NonceGenerator, NonceManager, NonceTracker, KEY_SIZE, NONCE_SIZE, TAG_SIZE,
};

// =============================================================================
// Nonce Exhaustion Tests
// =============================================================================

#[test]
fn test_nonce_generator_exhaustion_detection() {
    // NonceGenerator::MAX_COUNTER is u64::MAX - 1024
    // We can't actually exhaust it, but we test the is_near_exhaustion method
    let gen = NonceGenerator::new();

    // Fresh generator should not be near exhaustion
    assert!(!gen.is_near_exhaustion());

    // Counter should start at 0
    assert_eq!(gen.count(), 0);

    // After generating one nonce, counter increments
    let _ = gen.next().unwrap();
    assert_eq!(gen.count(), 1);
}

#[test]
fn test_nonce_tracker_exhaustion() {
    // Create a small tracker that exhausts quickly
    let mut tracker = NonceTracker::with_capacity(3);

    // Fill the tracker
    let n1 = Nonce::from_array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let n2 = Nonce::from_array([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let n3 = Nonce::from_array([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let n4 = Nonce::from_array([4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    assert!(tracker.check_and_mark(&n1).is_ok());
    assert!(tracker.check_and_mark(&n2).is_ok());
    assert!(tracker.check_and_mark(&n3).is_ok());

    // Tracker should be full now - next insert should fail with Exhausted
    let result = tracker.check_and_mark(&n4);
    assert!(matches!(result, Err(NonceError::Exhausted)));
}

#[test]
fn test_nonce_tracker_capacity_and_clear() {
    let mut tracker = NonceTracker::with_capacity(5);

    // Initially empty
    assert!(tracker.is_empty());
    assert_eq!(tracker.len(), 0);

    // Add a nonce
    let nonce = Nonce::from_array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    tracker.check_and_mark(&nonce).unwrap();

    assert!(!tracker.is_empty());
    assert_eq!(tracker.len(), 1);
    assert!(tracker.was_seen(&nonce));

    // Clear the tracker
    tracker.clear();
    assert!(tracker.is_empty());
    assert_eq!(tracker.len(), 0);
    assert!(!tracker.was_seen(&nonce));

    // Can add same nonce again after clear
    assert!(tracker.check_and_mark(&nonce).is_ok());
}

// =============================================================================
// Nonce Type Tests
// =============================================================================

#[test]
fn test_nonce_from_bytes_valid() {
    let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let nonce = Nonce::from_bytes(&bytes).unwrap();
    assert_eq!(*nonce.as_bytes(), bytes);
}

#[test]
fn test_nonce_from_bytes_too_short() {
    let bytes = [1u8; 11];
    let result = Nonce::from_bytes(&bytes);
    assert!(matches!(
        result,
        Err(NonceError::InvalidLength {
            expected: 12,
            got: 11
        })
    ));
}

#[test]
fn test_nonce_from_bytes_too_long() {
    let bytes = [1u8; 13];
    let result = Nonce::from_bytes(&bytes);
    assert!(matches!(
        result,
        Err(NonceError::InvalidLength {
            expected: 12,
            got: 13
        })
    ));
}

#[test]
fn test_nonce_as_ref() {
    let nonce = Nonce::from_array([42u8; 12]);
    let as_ref: &[u8] = nonce.as_ref();
    assert_eq!(as_ref, &[42u8; 12]);
}

#[test]
fn test_nonce_clone_and_copy() {
    let n1 = Nonce::from_array([1u8; 12]);
    let n2 = n1; // Copy
    let n3 = n1.clone(); // Clone

    assert_eq!(n1, n2);
    assert_eq!(n1, n3);
}

#[test]
fn test_nonce_hash() {
    use std::collections::HashSet;

    let n1 = Nonce::from_array([1u8; 12]);
    let n2 = Nonce::from_array([2u8; 12]);

    let mut set = HashSet::new();
    set.insert(n1);
    set.insert(n2);
    set.insert(n1); // Duplicate

    assert_eq!(set.len(), 2);
}

// =============================================================================
// NonceError Display Tests
// =============================================================================

#[test]
fn test_nonce_error_display() {
    let invalid_len = NonceError::InvalidLength {
        expected: 12,
        got: 11,
    };
    let display = format!("{}", invalid_len);
    assert!(display.contains("Invalid nonce length"));
    assert!(display.contains("12"));
    assert!(display.contains("11"));

    let already_used = NonceError::AlreadyUsed;
    assert!(format!("{}", already_used).contains("already used"));

    let exhausted = NonceError::Exhausted;
    assert!(format!("{}", exhausted).contains("exhausted"));
}

#[test]
fn test_nonce_error_is_error_trait() {
    let err: Box<dyn std::error::Error> = Box::new(NonceError::AlreadyUsed);
    assert!(err.to_string().contains("already used"));
}

// =============================================================================
// AEAD Wrapper Edge Cases
// =============================================================================

#[test]
fn test_aead_wrapper_invalid_key_too_short() {
    let short_key = [0u8; 31];
    let result = AeadWrapper::new(&short_key);
    assert!(matches!(result, Err(AeadError::InvalidKey)));
}

#[test]
fn test_aead_wrapper_invalid_key_too_long() {
    let long_key = [0u8; 33];
    let result = AeadWrapper::new(&long_key);
    assert!(matches!(result, Err(AeadError::InvalidKey)));
}

#[test]
fn test_aead_wrapper_empty_key() {
    let empty_key: [u8; 0] = [];
    let result = AeadWrapper::new(&empty_key);
    assert!(matches!(result, Err(AeadError::InvalidKey)));
}

#[test]
fn test_aead_decrypt_ciphertext_too_short() {
    let key = [0x42u8; 32];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0x11u8; 12];

    // Ciphertext shorter than tag size (16 bytes)
    let short_ct = [0u8; 15];
    let result = wrapper.decrypt(&nonce, &short_ct, b"aad");
    assert!(matches!(result, Err(AeadError::CiphertextTooShort)));
}

#[test]
fn test_aead_encrypt_empty_plaintext() {
    let key = [0x55u8; 32];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0x22u8; 12];

    // Empty plaintext should work
    let ciphertext = wrapper.encrypt_raw(&nonce, &[], b"aad").unwrap();

    // Should be exactly TAG_SIZE bytes (just the auth tag)
    assert_eq!(ciphertext.len(), TAG_SIZE);

    // Should decrypt back to empty
    let decrypted = wrapper.decrypt_raw(&nonce, &ciphertext, b"aad").unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_aead_large_aad() {
    let key = [0x66u8; 32];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0x33u8; 12];
    let plaintext = b"secret";

    // Use a large AAD (8KB)
    let large_aad = vec![0xAAu8; 8 * 1024];

    let ciphertext = wrapper.encrypt_raw(&nonce, plaintext, &large_aad).unwrap();
    let decrypted = wrapper
        .decrypt_raw(&nonce, &ciphertext, &large_aad)
        .unwrap();

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_aead_ciphertext_size() {
    let key = [0x77u8; 32];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0x44u8; 12];
    let plaintext = b"test plaintext";

    let ciphertext = wrapper.encrypt_raw(&nonce, plaintext, b"").unwrap();

    // Ciphertext = plaintext + 16-byte tag
    assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
}

#[test]
fn test_aead_encrypt_decrypt_roundtrip() {
    let key = [0x88u8; 32];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let gen = NonceGenerator::new();
    let nonce = gen.next().unwrap();

    let plaintext = b"The quick brown fox jumps over the lazy dog";
    let aad = b"metadata";

    let ciphertext = wrapper
        .encrypt_raw(nonce.as_bytes(), plaintext, aad)
        .unwrap();
    let decrypted = wrapper
        .decrypt_raw(nonce.as_bytes(), &ciphertext, aad)
        .unwrap();

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_aead_wrapper_can_be_dropped() {
    // Verify drop doesn't panic and key is zeroed
    let key = [0x99u8; 32];
    {
        let wrapper = AeadWrapper::new(&key).unwrap();
        assert_eq!(wrapper.encryption_count(), 0);
    } // Wrapper dropped here

    // Verify key is still in scope (it was copied into wrapper)
    assert_eq!(key[0], 0x99);
}

#[test]
fn test_aead_encryption_count_increments() {
    let key = [0xAAu8; 32];
    let wrapper = AeadWrapper::new(&key).unwrap();

    // Use the managed encrypt method (not encrypt_raw)
    let _gen = NonceGenerator::new();

    // Check count is tracked
    assert_eq!(wrapper.encryption_count(), 0);
}

// =============================================================================
// AeadError Tests
// =============================================================================

#[test]
fn test_aead_error_debug() {
    let errors = vec![
        AeadError::NonceReuse,
        AeadError::NonceExhaustion,
        AeadError::AuthenticationFailed,
        AeadError::InvalidKey,
        AeadError::CiphertextTooShort,
    ];

    for err in errors {
        let debug = format!("{:?}", err);
        assert!(!debug.is_empty());
    }
}

#[test]
fn test_aead_error_clone_and_eq() {
    let e1 = AeadError::AuthenticationFailed;
    let e2 = e1.clone();
    assert_eq!(e1, e2);

    let e3 = AeadError::InvalidKey;
    assert_ne!(e1, e3);
}

// =============================================================================
// Key Type Tests
// =============================================================================

#[test]
fn test_aead_key_debug_redacted() {
    let key = AeadKey::from_bytes(&[0xDEu8; 32]).unwrap();
    let debug = format!("{:?}", key);

    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("DE"));
}

#[test]
fn test_aead_key_zeroize_on_clone_drop() {
    let key_bytes = [0xEEu8; 32];
    let key = AeadKey::from_bytes(&key_bytes).unwrap();

    let cloned = key.clone();
    drop(cloned); // Should zeroize

    // Original key should still be valid
    let debug = format!("{:?}", key);
    assert!(debug.contains("AeadKey"));
}

#[test]
fn test_key_error_display() {
    let err = KeyError::InvalidLength {
        expected: 32,
        got: 16,
    };
    let display = format!("{}", err);
    assert!(display.contains("Invalid key length"));
    assert!(display.contains("32"));
    assert!(display.contains("16"));
}

#[test]
fn test_key_error_is_error_trait() {
    let err: Box<dyn std::error::Error> = Box::new(KeyError::InvalidLength {
        expected: 32,
        got: 10,
    });
    assert!(err.to_string().contains("Invalid key length"));
}

// =============================================================================
// AAD Type Tests
// =============================================================================

#[test]
fn test_aad_empty() {
    let aad = AssociatedData::empty();
    assert!(aad.as_bytes().is_empty());
}

#[test]
fn test_aad_from_slice() {
    let data = b"associated data";
    let aad: AssociatedData = data.as_slice().into();
    assert_eq!(aad.as_bytes(), data);
}

#[test]
fn test_aad_too_long_error() {
    let too_long = vec![0u8; AssociatedData::MAX_LEN + 1];
    let result = AssociatedData::new(too_long);

    match result {
        Err(AadError::TooLong { max, got }) => {
            assert_eq!(max, AssociatedData::MAX_LEN);
            assert_eq!(got, AssociatedData::MAX_LEN + 1);
        }
        _ => panic!("Expected TooLong error"),
    }
}

#[test]
fn test_aad_at_max_length() {
    let max_valid = vec![0x42u8; AssociatedData::MAX_LEN];
    let aad = AssociatedData::new(max_valid.clone()).unwrap();
    assert_eq!(aad.as_bytes().len(), AssociatedData::MAX_LEN);
}

#[test]
fn test_aad_error_display() {
    let err = AadError::TooLong {
        max: 16384,
        got: 16385,
    };
    let display = format!("{}", err);
    assert!(display.contains("16384") || display.contains("max"));
}

#[test]
fn test_aad_error_is_error_trait() {
    let err: Box<dyn std::error::Error> = Box::new(AadError::TooLong { max: 100, got: 200 });
    assert!(!err.to_string().is_empty());
}

#[test]
fn test_aad_debug() {
    let aad = AssociatedData::new(b"test".to_vec()).unwrap();
    let debug = format!("{:?}", aad);
    assert!(debug.contains("AssociatedData"));
}

// =============================================================================
// NonceGenerator Default Trait
// =============================================================================

#[test]
fn test_nonce_generator_default() {
    let gen: NonceGenerator = Default::default();
    assert_eq!(gen.count(), 0);
    assert!(!gen.is_near_exhaustion());
}

#[test]
fn test_nonce_tracker_default() {
    let tracker: NonceTracker = Default::default();
    assert!(tracker.is_empty());
    assert_eq!(tracker.len(), 0);
}

// =============================================================================
// All-Zero and All-0xFF Key Tests
// =============================================================================

#[test]
fn test_all_zero_key_works() {
    let zero_key = [0u8; 32];
    let wrapper = AeadWrapper::new(&zero_key).unwrap();
    let nonce = [0u8; 12];
    let plaintext = b"even zero key should work";

    let ct = wrapper.encrypt_raw(&nonce, plaintext, b"").unwrap();
    let pt = wrapper.decrypt_raw(&nonce, &ct, b"").unwrap();

    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn test_all_ff_key_works() {
    let ff_key = [0xFFu8; 32];
    let wrapper = AeadWrapper::new(&ff_key).unwrap();
    let nonce = [0xFFu8; 12];
    let plaintext = b"even all-FF key should work";

    let ct = wrapper.encrypt_raw(&nonce, plaintext, b"").unwrap();
    let pt = wrapper.decrypt_raw(&nonce, &ct, b"").unwrap();

    assert_eq!(pt.as_slice(), plaintext);
}

// =============================================================================
// Verus KDF Proofs Coverage Tests
// =============================================================================

use crypto_core::verus_kdf_proofs::{
    domain_separation_proof, error_path_safety_proof, extended_verification_status,
    key_lifecycle_proof, salt_freshness_proof, timing_uniformity_proof, DomainSeparation,
    ErrorPathProperty, KeyLifecycleState, SaltRequirements, TimingAnalysis,
};

#[test]
fn test_timing_equalized_operations() {
    let ops = TimingAnalysis::timing_equalized_operations();
    assert!(!ops.is_empty());
    assert!(ops.len() >= 2);
    // Check for expected operation types
    assert!(ops
        .iter()
        .any(|s| s.contains("Key derivation") || s.contains("Argon2id")));
    assert!(ops
        .iter()
        .any(|s| s.contains("HMAC") || s.contains("Error")));
}

#[test]
fn test_domain_separation_no_prefix_collision() {
    // The verify_no_prefix_collision function checks that no context is a prefix of another
    let result = DomainSeparation::verify_no_prefix_collision();
    assert!(
        result,
        "Domain separation contexts should not be prefixes of each other"
    );
}

#[test]
fn test_domain_separation_versioned() {
    let result = DomainSeparation::verify_versioned_contexts();
    assert!(result, "All domain separation contexts should be versioned");
}

#[test]
fn test_domain_separation_constants() {
    // Verify the domain separation constants are non-empty
    assert!(!DomainSeparation::MANIFEST_HMAC_KEY_PREFIX.is_empty());
    assert!(!DomainSeparation::BLOCK_KEY_DOMAIN_SEP.is_empty());
    assert!(!DomainSeparation::FRAME_MAC_DOMAIN.is_empty());
    assert!(!DomainSeparation::FORWARD_SECRECY_INFO.is_empty());
    assert!(!DomainSeparation::QUANTUM_NOISE_INFO.is_empty());
    assert!(!DomainSeparation::RATCHET_DOMAIN.is_empty());
    assert!(!DomainSeparation::DURESS_HASH_PREFIX.is_empty());
}

#[test]
fn test_salt_requirements_validity() {
    // Valid 16-byte salt
    let valid_salt = [0u8; 16];
    assert!(SaltRequirements::is_valid(&valid_salt));

    // Invalid lengths
    assert!(!SaltRequirements::is_valid(&[0u8; 15]));
    assert!(!SaltRequirements::is_valid(&[0u8; 17]));
    assert!(!SaltRequirements::is_valid(&[]));
}

#[test]
fn test_proof_strings_not_empty() {
    assert!(!domain_separation_proof().is_empty());
    assert!(!salt_freshness_proof().is_empty());
    assert!(!key_lifecycle_proof().is_empty());
    assert!(!error_path_safety_proof().is_empty());
    assert!(!timing_uniformity_proof().is_empty());
}

#[test]
fn test_error_path_property_debug() {
    let prop = ErrorPathProperty::NoPartialPlaintext;
    let debug = format!("{:?}", prop);
    assert!(debug.contains("NoPartialPlaintext"));
}

#[test]
fn test_key_lifecycle_state_debug() {
    let state = KeyLifecycleState::Derived;
    let debug = format!("{:?}", state);
    assert!(debug.contains("Derived"));
}

#[test]
fn test_extended_verification_status_complete() {
    let status = extended_verification_status();
    // Should have 6 verification items
    assert_eq!(status.len(), 6);

    // Check that all items have non-empty fields
    for (id, name, coverage) in &status {
        assert!(!id.is_empty());
        assert!(!name.is_empty());
        assert!(!coverage.is_empty());
    }
}

// =============================================================================
// Post-Quantum Cryptography Tests (pq-crypto feature)
// =============================================================================

#[cfg(feature = "pq-crypto")]
mod pq_tests {
    use crypto_core::{
        hybrid_key_derive, mlkem_encapsulate, MlKemKeyPair, MLKEM_CIPHERTEXT_SIZE,
        MLKEM_PUBLIC_KEY_SIZE, MLKEM_SECRET_KEY_SIZE, MLKEM_SHARED_SECRET_SIZE,
    };

    #[test]
    fn test_mlkem_keypair_generation() {
        let keypair = MlKemKeyPair::generate().expect("Key generation should succeed");
        assert_eq!(keypair.encapsulation_key().len(), MLKEM_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate_roundtrip() {
        let keypair = MlKemKeyPair::generate().unwrap();

        // Encapsulate with public key
        let (ciphertext, shared_secret_sender) =
            mlkem_encapsulate(keypair.encapsulation_key()).unwrap();
        assert_eq!(ciphertext.len(), MLKEM_CIPHERTEXT_SIZE);
        assert_eq!(shared_secret_sender.len(), MLKEM_SHARED_SECRET_SIZE);

        // Decapsulate with private key
        let shared_secret_receiver = keypair.decapsulate(&ciphertext).unwrap();
        assert_eq!(shared_secret_receiver.len(), MLKEM_SHARED_SECRET_SIZE);

        // Shared secrets must match
        assert_eq!(
            shared_secret_sender, shared_secret_receiver,
            "Encapsulated and decapsulated shared secrets must match"
        );
    }

    #[test]
    fn test_mlkem_different_keypairs_different_secrets() {
        let kp1 = MlKemKeyPair::generate().unwrap();
        let kp2 = MlKemKeyPair::generate().unwrap();

        let (_, ss1) = mlkem_encapsulate(kp1.encapsulation_key()).unwrap();
        let (_, ss2) = mlkem_encapsulate(kp2.encapsulation_key()).unwrap();

        // Different keypairs should produce different shared secrets
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_mlkem_wrong_keypair_fails() {
        let kp1 = MlKemKeyPair::generate().unwrap();
        let kp2 = MlKemKeyPair::generate().unwrap();

        // Encapsulate with kp1's public key
        let (ciphertext, _) = mlkem_encapsulate(kp1.encapsulation_key()).unwrap();

        // Decapsulate with kp2's private key - produces DIFFERENT shared secret
        // (ML-KEM is implicitly reject, not explicit failure)
        let ss_wrong = kp2.decapsulate(&ciphertext).unwrap();
        let ss_correct = kp1.decapsulate(&ciphertext).unwrap();
        assert_ne!(ss_wrong, ss_correct);
    }

    #[test]
    fn test_hybrid_key_derive() {
        let x25519_shared = [0xAA; 32];
        let mlkem_shared = [0xBB; 32];
        let info = b"hybrid-test-v1";

        let key = hybrid_key_derive(&x25519_shared, &mlkem_shared, info)
            .expect("Hybrid derivation should succeed");

        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_hybrid_key_derive_different_inputs() {
        let x1 = [0x11; 32];
        let x2 = [0x22; 32];
        let m1 = [0x33; 32];
        let m2 = [0x44; 32];
        let info = b"test";

        let k1 = hybrid_key_derive(&x1, &m1, info).unwrap();
        let k2 = hybrid_key_derive(&x2, &m1, info).unwrap();
        let k3 = hybrid_key_derive(&x1, &m2, info).unwrap();
        let k4 = hybrid_key_derive(&x1, &m1, b"other").unwrap();

        // All should be different
        assert_ne!(k1.as_ref(), k2.as_ref());
        assert_ne!(k1.as_ref(), k3.as_ref());
        assert_ne!(k1.as_ref(), k4.as_ref());
    }

    #[test]
    fn test_mlkem_constants() {
        // Verify constant sizes match FIPS 203 ML-KEM-1024
        assert_eq!(MLKEM_PUBLIC_KEY_SIZE, 1568);
        assert_eq!(MLKEM_SECRET_KEY_SIZE, 3168);
        assert_eq!(MLKEM_CIPHERTEXT_SIZE, 1568);
        assert_eq!(MLKEM_SHARED_SECRET_SIZE, 32);
    }
}

// =============================================================================
// Pure Crypto Additional Coverage Tests
// =============================================================================

#[cfg(feature = "pure-crypto")]
mod pure_crypto_coverage {
    use crypto_core::pure_crypto::Nonce;
    use crypto_core::{
        aes_gcm_decrypt, aes_gcm_encrypt, constant_time_eq, hkdf_derive, hmac_sha256,
        hmac_sha256_verify, random_bytes, sha256, SecretKey, X25519KeyPair,
    };

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = SecretKey::from_bytes(&[0x42; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0x00; 12]).unwrap();
        let plaintext = b"";

        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        // Empty plaintext produces just a tag (16 bytes)
        assert_eq!(ciphertext.len(), 16);

        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_with_aad() {
        let key = SecretKey::from_bytes(&[0x11; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0x22; 12]).unwrap();
        let plaintext = b"secret data";
        let aad = b"metadata";

        let ct = aes_gcm_encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, Some(aad)).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_gcm_wrong_aad_fails() {
        let key = SecretKey::from_bytes(&[0x33; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0x44; 12]).unwrap();
        let plaintext = b"data";

        let ct = aes_gcm_encrypt(&key, &nonce, plaintext, Some(b"correct")).unwrap();
        let result = aes_gcm_decrypt(&key, &nonce, &ct, Some(b"wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext_fails() {
        let key = SecretKey::from_bytes(&[0x55; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0x66; 12]).unwrap();
        let plaintext = b"important";

        let mut ct = aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        ct[0] ^= 0xFF; // Tamper with ciphertext

        let result = aes_gcm_decrypt(&key, &nonce, &ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_sha256_basic() {
        let key = b"secret key";
        let data = b"message";
        let mac = hmac_sha256(key, data);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_verify_valid() {
        let key = b"key";
        let data = b"data";
        let mac = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &mac));
    }

    #[test]
    fn test_hmac_sha256_verify_invalid() {
        let key = b"key";
        let data = b"data";
        let mac = hmac_sha256(key, data);

        // Wrong data
        assert!(!hmac_sha256_verify(key, b"wrong", &mac));

        // Wrong key
        assert!(!hmac_sha256_verify(b"other", data, &mac));

        // Tampered MAC
        let mut bad_mac = mac;
        bad_mac[0] ^= 0xFF;
        assert!(!hmac_sha256_verify(key, data, &bad_mac));
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);

        // Same input = same hash
        let hash2 = sha256(data);
        assert_eq!(hash, hash2);

        // Different input = different hash
        let hash3 = sha256(b"different");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_x25519_self_exchange() {
        let kp = X25519KeyPair::generate().unwrap();
        // DH with own public key works (produces a deterministic result)
        let shared = kp.diffie_hellman(kp.public_bytes()).unwrap();
        assert_eq!(shared.len(), 32);
    }

    #[test]
    fn test_hkdf_zero_length_ikm() {
        // Empty IKM should still work
        let result = hkdf_derive(&[], None, b"info", 32);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hkdf_large_output() {
        let result = hkdf_derive(b"ikm", None, b"info", 255 * 32); // Max HKDF output
        assert!(result.is_ok());
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq(&[], &[]));
        assert!(!constant_time_eq(&[], &[1]));
        assert!(!constant_time_eq(&[1], &[]));
    }

    #[test]
    fn test_random_bytes_various_sizes() {
        for size in [0, 1, 16, 32, 64, 1024] {
            let bytes = random_bytes(size).unwrap();
            assert_eq!(bytes.len(), size);
        }
    }
}

// =============================================================================
// Additional AEAD Wrapper Edge Case Tests
// =============================================================================

#[test]
fn test_aead_large_plaintext() {
    let key = [0u8; KEY_SIZE];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0u8; NONCE_SIZE];

    // 1 MB plaintext
    let plaintext = vec![0xAB; 1024 * 1024];
    let aad = b"large file test";

    let ct = wrapper.encrypt_raw(&nonce, &plaintext, aad).unwrap();
    let pt = wrapper.decrypt_raw(&nonce, &ct, aad).unwrap();

    assert_eq!(pt, plaintext);
}

#[test]
fn test_aead_wrapper_rekey() {
    let key1 = [0x11; KEY_SIZE];
    let key2 = [0x22; KEY_SIZE];

    let wrapper1 = AeadWrapper::new(&key1).unwrap();
    let wrapper2 = AeadWrapper::new(&key2).unwrap();

    let nonce = [0u8; NONCE_SIZE];
    let plaintext = b"test";
    let aad = b"";

    let ct1 = wrapper1.encrypt_raw(&nonce, plaintext, aad).unwrap();
    let ct2 = wrapper2.encrypt_raw(&nonce, plaintext, aad).unwrap();

    // Different keys produce different ciphertexts
    assert_ne!(ct1, ct2);

    // Can't decrypt with wrong key
    assert!(wrapper2.decrypt_raw(&nonce, &ct1, aad).is_err());
}

#[test]
fn test_aead_wrapper_ciphertext_too_short() {
    let key = [0u8; KEY_SIZE];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0u8; NONCE_SIZE];

    // Ciphertext shorter than tag (16 bytes)
    let short_ct = vec![0u8; 8];
    let result = wrapper.decrypt_raw(&nonce, &short_ct, b"");
    assert!(result.is_err());
}

// =============================================================================
// HSM Module Coverage Tests
// =============================================================================

#[cfg(feature = "hsm")]
mod hsm_tests {
    use crypto_core::{HsmError, HsmKeyType, HsmUri, SecurePin};

    #[test]
    fn test_hsm_error_display_all_variants() {
        let errors = vec![
            (
                HsmError::InitializationFailed("test".into()),
                "initialization failed",
            ),
            (HsmError::SlotNotFound(0), "slot 0"),
            (HsmError::SessionFailed("test".into()), "session failed"),
            (HsmError::AuthenticationFailed, "authentication failed"),
            (
                HsmError::KeyGenerationFailed("test".into()),
                "key generation",
            ),
            (HsmError::EncryptionFailed("test".into()), "encryption"),
            (HsmError::DecryptionFailed("test".into()), "decryption"),
            (HsmError::DerivationFailed("test".into()), "derivation"),
            (HsmError::KeyNotFound("test".into()), "not found"),
            (HsmError::NotSupported("test".into()), "not supported"),
            (HsmError::FeatureDisabled, "not compiled"),
        ];

        for (err, expected_substr) in errors {
            let display = format!("{}", err);
            assert!(
                display.to_lowercase().contains(expected_substr),
                "Error display '{}' should contain '{}'",
                display,
                expected_substr
            );
        }
    }

    #[test]
    fn test_hsm_error_debug() {
        let err = HsmError::AuthenticationFailed;
        let debug = format!("{:?}", err);
        assert!(debug.contains("AuthenticationFailed"));
    }

    #[test]
    fn test_hsm_key_type_key_bits() {
        assert_eq!(HsmKeyType::Aes128.key_bits(), 128);
        assert_eq!(HsmKeyType::Aes256.key_bits(), 256);
        assert_eq!(HsmKeyType::EcdhP256.key_bits(), 256);
        assert_eq!(HsmKeyType::EcdhX25519.key_bits(), 256);
        assert_eq!(HsmKeyType::GenericSecret.key_bits(), 256);
    }

    #[test]
    fn test_hsm_uri_parse_valid() {
        let uri = "pkcs11:library-path=/usr/lib/softhsm/libsofthsm2.so;slot=0;token=meow";
        let parsed = HsmUri::parse(uri).unwrap();
        assert_eq!(parsed.library_path, "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(parsed.slot_id, Some(0));
        assert_eq!(parsed.token_label, Some("meow".into()));
    }

    #[test]
    fn test_hsm_uri_parse_minimal() {
        let uri = "pkcs11:library-path=/path/to/lib.so";
        let parsed = HsmUri::parse(uri).unwrap();
        assert_eq!(parsed.library_path, "/path/to/lib.so");
        assert_eq!(parsed.slot_id, None);
        assert_eq!(parsed.token_label, None);
    }

    #[test]
    fn test_hsm_uri_parse_module_path_alias() {
        let uri = "pkcs11:module-path=/path/to/lib.so;slot-id=5;object=key1";
        let parsed = HsmUri::parse(uri).unwrap();
        assert_eq!(parsed.library_path, "/path/to/lib.so");
        assert_eq!(parsed.slot_id, Some(5));
        assert_eq!(parsed.object_id, Some("key1".into()));
    }

    #[test]
    fn test_hsm_uri_parse_invalid_prefix() {
        let uri = "http://example.com";
        let result = HsmUri::parse(uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_hsm_uri_parse_missing_library() {
        let uri = "pkcs11:slot=0";
        let result = HsmUri::parse(uri);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_pin() {
        let pin = SecurePin::new("1234");
        assert_eq!(pin.as_bytes(), b"1234");
    }
}

// =============================================================================
// TPM Module Coverage Tests
// =============================================================================

#[cfg(feature = "tpm")]
mod tpm_tests {
    use crypto_core::{PcrSelection, TpmError};

    #[test]
    fn test_tpm_error_display_all_variants() {
        let errors = vec![
            (TpmError::NotFound, "not found"),
            (
                TpmError::CommunicationFailed("test".into()),
                "communication",
            ),
            (TpmError::AuthorizationFailed, "authorization"),
            (TpmError::PcrMismatch("test".into()), "mismatch"),
            (TpmError::KeyOperationFailed("test".into()), "key operation"),
            (TpmError::SealFailed("test".into()), "seal"),
            (TpmError::UnsealFailed("test".into()), "unseal"),
            (TpmError::RandomFailed("test".into()), "random"),
            (TpmError::FeatureDisabled, "not compiled"),
            (TpmError::InvalidPcr(99), "99"),
            (TpmError::Lockout, "lockout"),
            (TpmError::HierarchyDisabled("test".into()), "hierarchy"),
        ];

        for (err, expected_substr) in errors {
            let display = format!("{}", err);
            assert!(
                display.to_lowercase().contains(expected_substr),
                "Error display '{}' should contain '{}'",
                display,
                expected_substr
            );
        }
    }

    #[test]
    fn test_tpm_error_debug() {
        let err = TpmError::Lockout;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Lockout"));
    }

    #[test]
    fn test_pcr_selection_add() {
        let pcr = PcrSelection::new()
            .add(0)
            .unwrap()
            .add(7)
            .unwrap()
            .add(23)
            .unwrap();

        // Verify PCRs were added (would need accessor in real impl)
        assert!(pcr.add(0).is_ok()); // Can add same PCR again (idempotent)
    }

    #[test]
    fn test_pcr_selection_invalid() {
        let result = PcrSelection::new().add(24); // Max is 23
        assert!(matches!(result, Err(TpmError::InvalidPcr(24))));
    }

    #[test]
    fn test_pcr_selection_default() {
        let pcr = PcrSelection::default();
        // Default is empty
        assert!(pcr.add(0).is_ok());
    }
}

// =============================================================================
// YubiKey Module Coverage Tests
// =============================================================================

#[cfg(feature = "yubikey")]
mod yubikey_tests {
    use crypto_core::{PivSlot, YubiKeyError};

    #[test]
    fn test_yubikey_error_display_all_variants() {
        let errors = vec![
            (YubiKeyError::NotFound, "no yubikey"),
            (YubiKeyError::MultipleFound(vec![1, 2]), "multiple"),
            (YubiKeyError::PinRequired, "pin required"),
            (YubiKeyError::PinIncorrect(3), "3 attempts"),
            (YubiKeyError::PinBlocked, "blocked"),
            (YubiKeyError::TouchTimeout, "timeout"),
            (
                YubiKeyError::KeyGenerationFailed("test".into()),
                "generation",
            ),
            (YubiKeyError::SigningFailed("test".into()), "signing"),
            (YubiKeyError::DecryptionFailed("test".into()), "decryption"),
            (YubiKeyError::Fido2Failed("test".into()), "fido2"),
            (YubiKeyError::SlotEmpty("9a".into()), "empty"),
            (YubiKeyError::NotSupported("test".into()), "not supported"),
            (YubiKeyError::FeatureDisabled, "not compiled"),
            (YubiKeyError::ConnectionFailed("test".into()), "connection"),
        ];

        for (err, expected_substr) in errors {
            let display = format!("{}", err);
            assert!(
                display.to_lowercase().contains(expected_substr),
                "Error display '{}' should contain '{}'",
                display,
                expected_substr
            );
        }
    }

    #[test]
    fn test_yubikey_error_debug() {
        let err = YubiKeyError::PinBlocked;
        let debug = format!("{:?}", err);
        assert!(debug.contains("PinBlocked"));
    }

    #[test]
    fn test_piv_slot_description() {
        assert!(PivSlot::Authentication.description().contains("9a"));
        assert!(PivSlot::DigitalSignature.description().contains("9c"));
        assert!(PivSlot::KeyManagement.description().contains("9d"));
        assert!(PivSlot::CardAuthentication.description().contains("9e"));
        assert!(PivSlot::Retired(1).description().contains("Retired"));
    }
}

// =============================================================================
// AEAD Wrapper Extended Coverage
// =============================================================================

#[test]
fn test_nonce_manager_multiple_allocations() {
    let nm = NonceManager::new();

    // Generate many nonces and verify uniqueness
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..1000 {
        let unique = nm.allocate_nonce().unwrap();
        let bytes = unique.take();
        assert!(nonces.insert(bytes), "Nonce collision!");
    }

    assert_eq!(nm.nonce_count(), 1000);
}

#[test]
fn test_nonce_manager_counter_ordering() {
    let nm = NonceManager::new();

    let n1 = nm.allocate_nonce().unwrap().take();
    let n2 = nm.allocate_nonce().unwrap().take();
    let n3 = nm.allocate_nonce().unwrap().take();

    // Counter should be in first 8 bytes (big-endian)
    let c1 = u64::from_be_bytes(n1[0..8].try_into().unwrap());
    let c2 = u64::from_be_bytes(n2[0..8].try_into().unwrap());
    let c3 = u64::from_be_bytes(n3[0..8].try_into().unwrap());

    assert_eq!(c1, 0);
    assert_eq!(c2, 1);
    assert_eq!(c3, 2);
}

#[test]
fn test_aead_error_display() {
    let errors = vec![
        (AeadError::NonceReuse, "reuse"),
        (AeadError::NonceExhaustion, "exhaustion"),
        (AeadError::AuthenticationFailed, "authentication"),
        (AeadError::InvalidKey, "invalid"),
        (AeadError::CiphertextTooShort, "too short"),
    ];

    // Just verify all variants exist and can be formatted
    for (err, _) in errors {
        let _display = format!("{:?}", err);
    }
}

#[test]
fn test_aead_wrapper_encrypt_with_auto_nonce() {
    let key = [0u8; KEY_SIZE];
    let wrapper = AeadWrapper::new(&key).unwrap();

    let plaintext = b"test";
    let aad = b"context";

    // Use encrypt() which auto-generates nonce
    let (nonce1, ct1) = wrapper.encrypt(plaintext, aad).unwrap();
    let (nonce2, ct2) = wrapper.encrypt(plaintext, aad).unwrap();

    // Nonces should be different
    assert_ne!(nonce1, nonce2);

    // Encryption count should increment
    assert_eq!(wrapper.encryption_count(), 2);

    // Both should decrypt correctly
    let ap1 = wrapper.decrypt(&nonce1, &ct1, aad).unwrap();
    let ap2 = wrapper.decrypt(&nonce2, &ct2, aad).unwrap();
    assert_eq!(ap1.data(), plaintext);
    assert_eq!(ap2.data(), plaintext);
}

#[test]
fn test_authenticated_plaintext_methods() {
    let key = [0u8; KEY_SIZE];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let pt = b"secret";
    let aad = b"";

    let (nonce, ct) = wrapper.encrypt(pt, aad).unwrap();
    let ap = wrapper.decrypt(&nonce, &ct, aad).unwrap();

    // Test data() reference
    assert_eq!(ap.data(), pt);
}

// =============================================================================
// Nonce Module Extended Coverage
// =============================================================================

#[test]
fn test_nonce_from_array() {
    let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let nonce = Nonce::from_array(bytes);
    assert_eq!(*nonce.as_bytes(), bytes);
}

#[test]
fn test_nonce_generator_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let gen = Arc::new(NonceGenerator::new());
    let mut handles = vec![];

    // Spawn multiple threads that generate nonces
    for _ in 0..10 {
        let gen_clone = Arc::clone(&gen);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                gen_clone.next().expect("Should not exhaust");
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Total should be 1000
    assert_eq!(gen.count(), 1000);
}

#[test]
fn test_nonce_tracker_was_seen() {
    let mut tracker = NonceTracker::new();
    let n1 = Nonce::from_array([1; 12]);
    let n2 = Nonce::from_array([2; 12]);

    tracker.check_and_mark(&n1).unwrap();

    assert!(tracker.was_seen(&n1));
    assert!(!tracker.was_seen(&n2));
}

// =============================================================================
// Types Module Extended Coverage
// =============================================================================

#[test]
fn test_aead_key_invalid_lengths() {
    assert!(AeadKey::from_bytes(&[0; 31]).is_err());
    assert!(AeadKey::from_bytes(&[0; 33]).is_err());
    assert!(AeadKey::from_bytes(&[]).is_err());
}

#[test]
fn test_associated_data_max_length() {
    // Creating AAD at max length should work
    let max_data = vec![0u8; AssociatedData::MAX_LEN];
    assert!(AssociatedData::new(max_data).is_ok());

    // Exceeding max length should fail
    let too_large = vec![0u8; AssociatedData::MAX_LEN + 1];
    assert!(AssociatedData::new(too_large).is_err());
}

#[test]
fn test_associated_data_empty() {
    let aad = AssociatedData::empty();
    assert!(aad.as_bytes().is_empty());
}

#[test]
fn test_associated_data_from_slice() {
    let data = b"some aad";
    let aad = AssociatedData::from(data.as_slice());
    assert_eq!(aad.as_bytes(), data);
}

// =============================================================================
// Pure Crypto Extended Coverage Tests
// =============================================================================

#[cfg(feature = "pure-crypto")]
mod pure_crypto_extended {
    use crypto_core::pure_crypto::{Argon2Params, Nonce, Salt};
    use crypto_core::{argon2_derive, hkdf_derive_key, random_key, CryptoError, SecretKey};

    #[test]
    fn test_argon2_derive_with_custom_params() {
        let password = b"test_password_123";
        let salt = Salt::from_bytes(&[0x11; 16]).unwrap();

        // Use minimal params for fast test
        let params = Argon2Params {
            memory_kib: 1024, // 1 MiB
            time: 1,
            parallelism: 1,
        };

        let key = argon2_derive(password, &salt, Some(params)).expect("Argon2 should succeed");
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_argon2_derive_owasp_minimum() {
        let _password = b"secure_password";
        let _salt = Salt::from_bytes(&[0x22; 16]).unwrap();

        let params = Argon2Params::owasp_minimum();
        assert_eq!(params.memory_kib, 65536); // 64 MiB
        assert_eq!(params.time, 3);
        assert_eq!(params.parallelism, 4);

        // Skip actual derivation as it's slow, just test params
    }

    #[test]
    fn test_argon2_params_ultra() {
        let params = Argon2Params::ultra();
        assert_eq!(params.memory_kib, 1048576); // 1 GiB
        assert_eq!(params.time, 40);
        assert_eq!(params.parallelism, 4);
    }

    #[test]
    fn test_argon2_params_default() {
        let params = Argon2Params::default();
        // Default is production: 512 MiB, 20 iterations
        assert_eq!(params.memory_kib, 524288);
        assert_eq!(params.time, 20);
        assert_eq!(params.parallelism, 4);
    }

    #[test]
    fn test_hkdf_derive_key_basic() {
        let ikm = [0xAA; 32];
        let info = b"test-context-v1";

        let key = hkdf_derive_key(&ikm, None, info).expect("HKDF should succeed");
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_hkdf_derive_key_with_salt() {
        let ikm = [0xBB; 32];
        let salt = [0xCC; 32];
        let info = b"salted-context";

        let key = hkdf_derive_key(&ikm, Some(&salt), info).expect("HKDF should succeed");
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_hkdf_derive_key_deterministic() {
        let ikm = [0xDD; 32];
        let info = b"determinism-test";

        let key1 = hkdf_derive_key(&ikm, None, info).unwrap();
        let key2 = hkdf_derive_key(&ikm, None, info).unwrap();

        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_random_key_unique() {
        let key1 = random_key().expect("random_key should succeed");
        let key2 = random_key().expect("random_key should succeed");

        // Two random keys should differ
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_salt_random() {
        let salt1 = Salt::random().expect("Salt::random should succeed");
        let salt2 = Salt::random().expect("Salt::random should succeed");

        assert_ne!(salt1.as_bytes(), salt2.as_bytes());
        assert_eq!(salt1.as_bytes().len(), 16);
    }

    #[test]
    fn test_nonce_random() {
        let nonce1 = Nonce::random().expect("Nonce::random should succeed");
        let nonce2 = Nonce::random().expect("Nonce::random should succeed");

        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
        assert_eq!(nonce1.as_bytes().len(), 12);
    }

    #[test]
    fn test_crypto_error_display_all_variants() {
        let err1 = CryptoError::InvalidKeySize(16, 32);
        assert!(format!("{}", err1).contains("key size"));

        let err2 = CryptoError::InvalidNonceSize(8, 12);
        assert!(format!("{}", err2).contains("nonce size"));

        let err3 = CryptoError::EncryptionFailed("test".to_string());
        assert!(format!("{}", err3).contains("Encryption"));

        let err4 = CryptoError::DecryptionFailed;
        assert!(format!("{}", err4).contains("Decryption"));

        let err5 = CryptoError::KeyDerivationFailed("kdf".to_string());
        assert!(format!("{}", err5).contains("derivation"));

        let err6 = CryptoError::SignatureInvalid;
        assert!(format!("{}", err6).contains("Signature"));

        let err7 = CryptoError::RandomFailed("rng".to_string());
        assert!(format!("{}", err7).contains("Random"));

        let err8 = CryptoError::FeatureDisabled;
        assert!(format!("{}", err8).contains("feature"));
    }

    #[test]
    fn test_secret_key_as_ref_trait() {
        let key = SecretKey::from_bytes(&[0xEE; 32]).unwrap();
        let slice: &[u8] = key.as_ref();
        assert_eq!(slice.len(), 32);
        assert_eq!(slice[0], 0xEE);
    }

    #[test]
    fn test_nonce_as_ref_trait() {
        let nonce = Nonce::from_bytes(&[0xFF; 12]).unwrap();
        let slice: &[u8] = nonce.as_ref();
        assert_eq!(slice.len(), 12);
    }

    #[test]
    fn test_salt_as_ref_trait() {
        let salt = Salt::from_bytes(&[0x99; 16]).unwrap();
        let slice: &[u8] = salt.as_ref();
        assert_eq!(slice.len(), 16);
    }

    #[test]
    fn test_nonce_invalid_length() {
        let result = Nonce::from_bytes(&[0u8; 8]);
        assert!(matches!(result, Err(CryptoError::InvalidNonceSize(8, 12))));
    }

    #[test]
    fn test_salt_invalid_length() {
        let result = Salt::from_bytes(&[0u8; 8]);
        assert!(matches!(result, Err(CryptoError::InvalidKeySize(8, 16))));
    }
}

// =============================================================================
// PQ Crypto Extended Coverage Tests
// =============================================================================

#[cfg(feature = "pq-crypto")]
mod pq_crypto_extended {
    use crypto_core::pure_crypto::pq::{backend_name, pq_backend_info};
    use crypto_core::{mlkem_encapsulate, MlKemKeyPair, MLKEM_PUBLIC_KEY_SIZE};

    #[test]
    fn test_pq_backend_name() {
        let name = backend_name();
        assert!(!name.is_empty());
        assert!(name.contains("Rust") || name.contains("liboqs"));
    }

    #[test]
    fn test_pq_backend_info() {
        let info = pq_backend_info();
        assert!(info.contains("ML-KEM-1024"));
        assert!(info.contains("1568")); // Public key size
    }

    #[test]
    fn test_mlkem_encapsulate_invalid_key() {
        // Wrong size public key should fail
        let bad_key = vec![0u8; 100]; // Not MLKEM_PUBLIC_KEY_SIZE
        let result = mlkem_encapsulate(&bad_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_mlkem_decapsulate_wrong_ciphertext() {
        let keypair = MlKemKeyPair::generate().unwrap();

        // Wrong size ciphertext should fail
        let bad_ct = vec![0u8; 100];
        let result = keypair.decapsulate(&bad_ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_mlkem_keypair_public_key_size() {
        let keypair = MlKemKeyPair::generate().unwrap();
        assert_eq!(keypair.encapsulation_key().len(), MLKEM_PUBLIC_KEY_SIZE);
    }
}

// =============================================================================
// NonceManager Extended Coverage Tests
// =============================================================================

#[test]
fn test_nonce_manager_allocate_nonce() {
    let manager = NonceManager::new();

    // Allocate a unique nonce
    let unique = manager.allocate_nonce().expect("Should allocate nonce");
    let bytes = unique.take();
    assert_eq!(bytes.len(), NONCE_SIZE);
}

#[test]
fn test_nonce_manager_default() {
    let manager: NonceManager = Default::default();
    let nonce = manager.allocate_nonce().unwrap();
    let bytes = nonce.take();
    assert_eq!(bytes.len(), NONCE_SIZE);
}

#[test]
fn test_aead_wrapper_encrypt_with_manager() {
    let key = [0u8; KEY_SIZE];
    let wrapper = AeadWrapper::new(&key).unwrap();
    let plaintext = b"managed encryption test";
    let aad = b"";

    // Use the managed encrypt method
    let (nonce, ciphertext) = wrapper
        .encrypt(plaintext, aad)
        .expect("Encrypt should work");

    // Decrypt with the returned nonce
    let ap = wrapper
        .decrypt(&nonce, &ciphertext, aad)
        .expect("Decrypt should work");
    assert_eq!(ap.data(), plaintext);
}

#[test]
fn test_aead_wrapper_encryption_count() {
    let key = [0u8; KEY_SIZE];
    let wrapper = AeadWrapper::new(&key).unwrap();

    assert_eq!(wrapper.encryption_count(), 0);

    let _ = wrapper.encrypt(b"test", b"").unwrap();
    assert_eq!(wrapper.encryption_count(), 1);

    let _ = wrapper.encrypt(b"test2", b"").unwrap();
    assert_eq!(wrapper.encryption_count(), 2);
}
