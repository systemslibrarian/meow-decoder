//! Comprehensive coverage tests for crypto_core crate.
//!
//! Targets 95%+ coverage of all modules: pure_crypto, aead_wrapper, nonce, types,
//! hsm (stubs), tpm (stubs), yubikey_piv (stubs), verus_proofs, verus_kdf_proofs.
//!
//! This file supplements existing tests with thorough edge-case and branch coverage.

use crypto_core::*;

// ─── AeadWrapper extended tests ─────────────────────────────────────────────

mod aead_wrapper_tests {
    use super::*;

    #[test]
    fn test_invalid_key_length_short() {
        let key = [0u8; 16];
        let result = AeadWrapper::new(&key);
        assert_eq!(result.err(), Some(AeadError::InvalidKey));
    }

    #[test]
    fn test_invalid_key_length_long() {
        let key = [0u8; 64];
        let result = AeadWrapper::new(&key);
        assert_eq!(result.err(), Some(AeadError::InvalidKey));
    }

    #[test]
    fn test_encrypt_increments_counter() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        assert_eq!(wrapper.encryption_count(), 0);

        let _ = wrapper.encrypt(b"msg1", b"aad").unwrap();
        assert_eq!(wrapper.encryption_count(), 1);

        let _ = wrapper.encrypt(b"msg2", b"aad").unwrap();
        assert_eq!(wrapper.encryption_count(), 2);
    }

    #[test]
    fn test_encrypt_produces_unique_nonces() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let (nonce1, _) = wrapper.encrypt(b"msg1", b"aad").unwrap();
        let (nonce2, _) = wrapper.encrypt(b"msg2", b"aad").unwrap();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_decrypt_ciphertext_too_short() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let nonce = [0u8; NONCE_SIZE];
        let short_ct = [0u8; TAG_SIZE - 1];
        let result = wrapper.decrypt(&nonce, &short_ct, b"aad");
        assert_eq!(result.err(), Some(AeadError::CiphertextTooShort));
    }

    #[test]
    fn test_decrypt_raw_ciphertext_too_short() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let nonce = [0u8; NONCE_SIZE];
        let result = wrapper.decrypt_raw(&nonce, &[0u8; TAG_SIZE - 1], b"aad");
        assert_eq!(result.err(), Some(AeadError::CiphertextTooShort));
    }

    #[test]
    fn test_encrypt_raw_decrypt_raw_roundtrip() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let nonce = [0x11u8; NONCE_SIZE];
        let plaintext = b"raw roundtrip test";
        let aad = b"associated";

        let ct = wrapper.encrypt_raw(&nonce, plaintext, aad).unwrap();
        let pt = wrapper.decrypt_raw(&nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_wrong_key_decrypt_fails() {
        let wrapper1 = AeadWrapper::new(&[0x11u8; 32]).unwrap();
        let wrapper2 = AeadWrapper::new(&[0x22u8; 32]).unwrap();

        let (nonce, ct) = wrapper1.encrypt(b"secret", b"aad").unwrap();
        let result = wrapper2.decrypt(&nonce, &ct, b"aad");
        assert_eq!(result.err(), Some(AeadError::AuthenticationFailed));
    }

    #[test]
    fn test_tampered_aad_fails() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let (nonce, ct) = wrapper.encrypt(b"data", b"correct_aad").unwrap();
        let result = wrapper.decrypt(&nonce, &ct, b"wrong_aad");
        assert_eq!(result.err(), Some(AeadError::AuthenticationFailed));
    }

    #[test]
    fn test_empty_plaintext() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let (nonce, ct) = wrapper.encrypt(b"", b"aad").unwrap();
        assert_eq!(ct.len(), TAG_SIZE); // Only auth tag
        let auth = wrapper.decrypt(&nonce, &ct, b"aad").unwrap();
        assert!(auth.data().is_empty());
    }

    #[test]
    fn test_empty_aad() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let (nonce, ct) = wrapper.encrypt(b"message", b"").unwrap();
        let auth = wrapper.decrypt(&nonce, &ct, b"").unwrap();
        assert_eq!(auth.data(), b"message");
    }

    #[test]
    fn test_authenticated_plaintext_into_data() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let (nonce, ct) = wrapper.encrypt(b"consume me", b"aad").unwrap();
        let auth = wrapper.decrypt(&nonce, &ct, b"aad").unwrap();
        let data: Vec<u8> = auth.into_data();
        assert_eq!(data, b"consume me");
    }

    #[test]
    fn test_large_plaintext() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let large = vec![0xFFu8; 100_000];
        let (nonce, ct) = wrapper.encrypt(&large, b"aad").unwrap();
        let auth = wrapper.decrypt(&nonce, &ct, b"aad").unwrap();
        assert_eq!(auth.data(), large.as_slice());
    }

    #[test]
    fn test_large_aad() {
        let wrapper = AeadWrapper::new(&[0x42u8; 32]).unwrap();
        let large_aad = vec![0xAAu8; 10_000];
        let (nonce, ct) = wrapper.encrypt(b"msg", &large_aad).unwrap();
        let auth = wrapper.decrypt(&nonce, &ct, &large_aad).unwrap();
        assert_eq!(auth.data(), b"msg");
    }

    #[test]
    fn test_aead_error_debug_clone_eq() {
        let e1 = AeadError::NonceReuse;
        let e2 = e1.clone();
        assert_eq!(e1, e2);

        let e3 = AeadError::NonceExhaustion;
        assert_ne!(e1, e3);

        let e4 = AeadError::AuthenticationFailed;
        let e5 = AeadError::InvalidKey;
        let e6 = AeadError::CiphertextTooShort;

        // Debug coverage
        assert!(!format!("{:?}", e1).is_empty());
        assert!(!format!("{:?}", e3).is_empty());
        assert!(!format!("{:?}", e4).is_empty());
        assert!(!format!("{:?}", e5).is_empty());
        assert!(!format!("{:?}", e6).is_empty());
    }

    #[test]
    fn test_nonce_manager_default() {
        let nm = NonceManager::default();
        assert_eq!(nm.nonce_count(), 0);
    }

    #[test]
    fn test_unique_nonce_take() {
        let nm = NonceManager::new();
        let nonce = nm.allocate_nonce().unwrap();
        let bytes = nonce.take();
        assert_eq!(bytes.len(), NONCE_SIZE);
    }
}

// ─── Nonce module extended tests ────────────────────────────────────────────

mod nonce_tests {
    use super::*;

    #[test]
    fn test_nonce_from_array() {
        let arr = [0x42u8; 12];
        let nonce = Nonce::from_array(arr);
        assert_eq!(nonce.as_bytes(), &arr);
    }

    #[test]
    fn test_nonce_from_bytes_valid() {
        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();
        assert_eq!(nonce.as_ref().len(), 12);
    }

    #[test]
    fn test_nonce_from_bytes_invalid_short() {
        let err = Nonce::from_bytes(&[0u8; 8]);
        assert!(matches!(
            err,
            Err(NonceError::InvalidLength {
                expected: 12,
                got: 8
            })
        ));
    }

    #[test]
    fn test_nonce_from_bytes_invalid_long() {
        let err = Nonce::from_bytes(&[0u8; 16]);
        assert!(matches!(
            err,
            Err(NonceError::InvalidLength {
                expected: 12,
                got: 16
            })
        ));
    }

    #[test]
    fn test_nonce_hash() {
        use std::collections::HashSet;
        let n1 = Nonce::from_array([1u8; 12]);
        let n2 = Nonce::from_array([2u8; 12]);
        let n3 = Nonce::from_array([1u8; 12]);

        let mut set = HashSet::new();
        set.insert(n1);
        set.insert(n2);
        set.insert(n3); // Duplicate of n1

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_nonce_copy_clone() {
        let n1 = Nonce::from_array([0x33u8; 12]);
        let n2 = n1; // Copy
        let n3 = n1.clone(); // Clone
        assert_eq!(n1, n2);
        assert_eq!(n1, n3);
    }

    #[test]
    fn test_nonce_error_display() {
        let e1 = NonceError::InvalidLength {
            expected: 12,
            got: 8,
        };
        assert!(format!("{}", e1).contains("12"));
        assert!(format!("{}", e1).contains("8"));

        let e2 = NonceError::AlreadyUsed;
        assert!(format!("{}", e2).contains("already used") || format!("{}", e2).contains("Already"));

        let e3 = NonceError::Exhausted;
        assert!(format!("{}", e3).contains("exhausted") || format!("{}", e3).contains("Exhausted"));
    }

    #[test]
    fn test_nonce_error_is_error() {
        let err: &dyn std::error::Error = &NonceError::AlreadyUsed;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_nonce_generator_new_default() {
        let gen1 = NonceGenerator::new();
        let gen2 = NonceGenerator::default();
        assert_eq!(gen1.count(), 0);
        assert_eq!(gen2.count(), 0);
    }

    #[test]
    fn test_nonce_generator_next() {
        let gen = NonceGenerator::new();
        let n1 = gen.next().unwrap();
        let n2 = gen.next().unwrap();
        assert_ne!(n1, n2);
        assert_eq!(gen.count(), 2);
    }

    #[test]
    fn test_nonce_generator_is_near_exhaustion() {
        let gen = NonceGenerator::new();
        assert!(!gen.is_near_exhaustion());
    }

    #[test]
    fn test_nonce_tracker_new_default() {
        let t1 = NonceTracker::new();
        let t2 = NonceTracker::default();
        assert_eq!(t1.len(), 0);
        assert_eq!(t2.len(), 0);
        assert!(t1.is_empty());
    }

    #[test]
    fn test_nonce_tracker_check_and_mark() {
        let mut tracker = NonceTracker::new();
        let nonce = Nonce::from_array([1u8; 12]);

        assert!(!tracker.was_seen(&nonce));
        tracker.check_and_mark(&nonce).unwrap();
        assert!(tracker.was_seen(&nonce));
        assert_eq!(tracker.len(), 1);

        // Second check should fail
        let err = tracker.check_and_mark(&nonce);
        assert_eq!(err, Err(NonceError::AlreadyUsed));
    }

    #[test]
    fn test_nonce_tracker_with_capacity() {
        let mut tracker = NonceTracker::with_capacity(2);

        tracker
            .check_and_mark(&Nonce::from_array([1u8; 12]))
            .unwrap();
        tracker
            .check_and_mark(&Nonce::from_array([2u8; 12]))
            .unwrap();

        // Third should fail (capacity 2)
        let err = tracker.check_and_mark(&Nonce::from_array([3u8; 12]));
        assert_eq!(err, Err(NonceError::Exhausted));
    }

    #[test]
    fn test_nonce_tracker_clear() {
        let mut tracker = NonceTracker::new();
        let nonce = Nonce::from_array([1u8; 12]);

        tracker.check_and_mark(&nonce).unwrap();
        assert_eq!(tracker.len(), 1);

        tracker.clear();
        assert_eq!(tracker.len(), 0);
        assert!(tracker.is_empty());

        // Can re-add after clear
        tracker.check_and_mark(&nonce).unwrap();
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_nonce_tracker_many_nonces() {
        let mut tracker = NonceTracker::new();
        for i in 0u32..1000 {
            let mut bytes = [0u8; 12];
            bytes[0..4].copy_from_slice(&i.to_be_bytes());
            let nonce = Nonce::from_array(bytes);
            tracker.check_and_mark(&nonce).unwrap();
        }
        assert_eq!(tracker.len(), 1000);
    }
}

// ─── Types module extended tests ────────────────────────────────────────────

mod types_tests {
    use super::*;

    #[test]
    fn test_aead_key_valid_length() {
        let key = AeadKey::from_bytes(&[0x42u8; 32]);
        assert!(key.is_ok());
    }

    #[test]
    fn test_aead_key_invalid_lengths() {
        for len in [0, 1, 15, 16, 31, 33, 64] {
            let bytes = vec![0u8; len];
            let err = AeadKey::from_bytes(&bytes);
            assert!(matches!(err, Err(KeyError::InvalidLength { .. })));
        }
    }

    #[test]
    fn test_aead_key_debug_redacted() {
        let key = AeadKey::from_bytes(&[0xFFu8; 32]).unwrap();
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        // Must not contain any key bytes
        assert!(!debug.contains("255"));
        assert!(!debug.contains("0xff"));
    }

    #[test]
    fn test_aead_key_clone() {
        let key1 = AeadKey::from_bytes(&[0x42u8; 32]).unwrap();
        let _key2 = key1.clone();
        // Clone succeeds without panic; content equality can't be checked
        // externally since as_bytes is pub(crate)
    }

    #[test]
    fn test_key_error_display() {
        let err = KeyError::InvalidLength {
            expected: 32,
            got: 16,
        };
        let display = format!("{}", err);
        assert!(display.contains("32"));
        assert!(display.contains("16"));
    }

    #[test]
    fn test_key_error_debug_clone_eq() {
        let e1 = KeyError::InvalidLength {
            expected: 32,
            got: 16,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
        assert!(!format!("{:?}", e1).is_empty());
    }

    #[test]
    fn test_associated_data_new() {
        let aad = AssociatedData::new(vec![1, 2, 3]).unwrap();
        assert_eq!(aad.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_associated_data_empty() {
        let aad = AssociatedData::empty();
        assert!(aad.as_bytes().is_empty());
    }

    #[test]
    fn test_associated_data_max_length() {
        let bytes = vec![0u8; AssociatedData::MAX_LEN];
        let aad = AssociatedData::new(bytes).unwrap();
        assert_eq!(aad.as_bytes().len(), AssociatedData::MAX_LEN);
    }

    #[test]
    fn test_associated_data_too_long() {
        let bytes = vec![0u8; AssociatedData::MAX_LEN + 1];
        let err = AssociatedData::new(bytes);
        assert!(matches!(err, Err(AadError::TooLong { .. })));
    }

    #[test]
    fn test_associated_data_from_slice() {
        let bytes: &[u8] = &[10, 20, 30];
        let aad: AssociatedData = bytes.into();
        assert_eq!(aad.as_bytes(), bytes);
    }

    #[test]
    fn test_aad_error_display() {
        let err = AadError::TooLong {
            max: 16384,
            got: 20000,
        };
        let display = format!("{}", err);
        assert!(display.contains("16384"));
        assert!(display.contains("20000"));
    }

    #[test]
    fn test_aad_error_debug_clone_eq() {
        let e1 = AadError::TooLong {
            max: 100,
            got: 200,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
        assert!(!format!("{:?}", e1).is_empty());
    }

    #[test]
    fn test_associated_data_clone_debug() {
        let aad = AssociatedData::new(vec![1, 2, 3]).unwrap();
        let cloned = aad.clone();
        assert_eq!(aad.as_bytes(), cloned.as_bytes());
        assert!(!format!("{:?}", aad).is_empty());
    }
}

// ─── pure_crypto extended tests ─────────────────────────────────────────────

#[cfg(feature = "pure-crypto")]
mod pure_crypto_tests {
    use crypto_core::pure_crypto::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt_roundtrip_various_sizes() {
        let key = SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();

        for size in [0, 1, 15, 16, 17, 255, 1024, 65536] {
            let plaintext = vec![0xAAu8; size];
            let ct = aes_gcm_encrypt(&key, &nonce, &plaintext, None).unwrap();
            let pt = aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
            assert_eq!(pt, plaintext, "Failed at size {}", size);
        }
    }

    #[test]
    fn test_aes_gcm_all_zero_key() {
        let key = SecretKey::from_bytes(&[0u8; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();
        let ct = aes_gcm_encrypt(&key, &nonce, b"zero key test", None).unwrap();
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, b"zero key test");
    }

    #[test]
    fn test_aes_gcm_all_ff_key() {
        let key = SecretKey::from_bytes(&[0xFFu8; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0xFFu8; 12]).unwrap();
        let ct = aes_gcm_encrypt(&key, &nonce, b"ff key test", None).unwrap();
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, b"ff key test");
    }

    #[test]
    fn test_aes_gcm_different_aad() {
        let key = SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();
        let plaintext = b"test";

        let ct_no_aad = aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let _ct_empty_aad = aes_gcm_encrypt(&key, &nonce, plaintext, Some(b"")).unwrap();
        let ct_some_aad = aes_gcm_encrypt(&key, &nonce, plaintext, Some(b"aad")).unwrap();

        // None and empty AAD produce same, but differ from non-empty
        assert_ne!(ct_no_aad, ct_some_aad);
    }

    #[test]
    fn test_aes_ctr_crypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 16];
        let data = b"CTR mode data for round trip";

        let encrypted = aes_ctr_crypt(&key, &nonce, data, 0).unwrap();
        assert_ne!(encrypted.as_slice(), data);

        let decrypted = aes_ctr_crypt(&key, &nonce, &encrypted, 0).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes_ctr_crypt_with_offset() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 16];

        // Encrypt same data at different offsets produces different ciphertext
        let ct0 = aes_ctr_crypt(&key, &nonce, b"test", 0).unwrap();
        let ct16 = aes_ctr_crypt(&key, &nonce, b"test", 16).unwrap();
        assert_ne!(ct0, ct16);

        // But decrypting at the right offset recovers plaintext
        let pt0 = aes_ctr_crypt(&key, &nonce, &ct0, 0).unwrap();
        let pt16 = aes_ctr_crypt(&key, &nonce, &ct16, 16).unwrap();
        assert_eq!(pt0, b"test");
        assert_eq!(pt16, b"test");
    }

    #[test]
    fn test_aes_ctr_crypt_partial_block_offset() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 16];

        let data = b"partial offset test data";
        // Non-block-aligned offset (e.g., 7)
        let ct = aes_ctr_crypt(&key, &nonce, data, 7).unwrap();
        let pt = aes_ctr_crypt(&key, &nonce, &ct, 7).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn test_aes_ctr_crypt_invalid_key_length() {
        let err = aes_ctr_crypt(&[0u8; 16], &[0u8; 16], b"data", 0);
        assert!(matches!(err, Err(CryptoError::InvalidKeySize(16, 32))));
    }

    #[test]
    fn test_aes_ctr_crypt_invalid_nonce_length() {
        let err = aes_ctr_crypt(&[0u8; 32], &[0u8; 12], b"data", 0);
        assert!(matches!(err, Err(CryptoError::InvalidNonceSize(12, 16))));
    }

    #[test]
    fn test_aes_ctr_crypt_empty_data() {
        let result = aes_ctr_crypt(&[0u8; 32], &[0u8; 16], b"", 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_argon2_derive_with_minimal_params() {
        let password = b"test_password";
        let salt = Salt::from_bytes(&[0xAAu8; 16]).unwrap();
        let params = Argon2Params {
            memory_kib: 1024,
            time: 1,
            parallelism: 1,
        };
        let key = argon2_derive(password, &salt, Some(params)).unwrap();
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_argon2_derive_different_salts_produce_different_keys() {
        let password = b"same_password";
        let params = Argon2Params {
            memory_kib: 1024,
            time: 1,
            parallelism: 1,
        };

        let salt1 = Salt::from_bytes(&[0x11u8; 16]).unwrap();
        let salt2 = Salt::from_bytes(&[0x22u8; 16]).unwrap();

        let key1 = argon2_derive(password, &salt1, Some(params)).unwrap();
        let key2 = argon2_derive(password, &salt2, Some(params)).unwrap();
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_argon2_derive_empty_password() {
        let salt = Salt::from_bytes(&[0u8; 16]).unwrap();
        let params = Argon2Params {
            memory_kib: 1024,
            time: 1,
            parallelism: 1,
        };
        let key = argon2_derive(b"", &salt, Some(params)).unwrap();
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_hkdf_derive_various_lengths() {
        let ikm = b"input keying material";
        for len in [16, 32, 48, 64, 128] {
            let okm = hkdf_derive(ikm, Some(b"salt"), b"info", len).unwrap();
            assert_eq!(okm.len(), len, "Wrong length for {}", len);
        }
    }

    #[test]
    fn test_hkdf_derive_no_salt() {
        let result = hkdf_derive(b"ikm", None, b"info", 32).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hkdf_derive_key_returns_32() {
        let key = hkdf_derive_key(b"ikm", Some(b"salt"), b"info").unwrap();
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_hkdf_domain_separation() {
        let ikm = b"same ikm";
        let salt = Some(b"same salt".as_slice());

        let okm1 = hkdf_derive(ikm, salt, b"domain_A", 32).unwrap();
        let okm2 = hkdf_derive(ikm, salt, b"domain_B", 32).unwrap();
        assert_ne!(okm1, okm2);
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let key = b"test key";
        let data = b"test data";
        let mac1 = hmac_sha256(key, data);
        let mac2 = hmac_sha256(key, data);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_key_sensitivity() {
        let data = b"message";
        let mac1 = hmac_sha256(b"key_a", data);
        let mac2 = hmac_sha256(b"key_b", data);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_message_sensitivity() {
        let key = b"key";
        let mac1 = hmac_sha256(key, b"msg_a");
        let mac2 = hmac_sha256(key, b"msg_b");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha256_empty_inputs() {
        let mac1 = hmac_sha256(b"", b"data");
        assert_eq!(mac1.len(), 32);

        let mac2 = hmac_sha256(b"key", b"");
        assert_eq!(mac2.len(), 32);

        let mac3 = hmac_sha256(b"", b"");
        assert_eq!(mac3.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_verify_correct() {
        let key = b"secret key";
        let data = b"authenticated data";
        let mac = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &mac));
    }

    #[test]
    fn test_hmac_sha256_verify_wrong_tag() {
        let key = b"secret key";
        let data = b"data";
        let mut mac = hmac_sha256(key, data);
        mac[0] ^= 0x01;
        assert!(!hmac_sha256_verify(key, data, &mac));
    }

    #[test]
    fn test_sha256_known_empty() {
        let hash = sha256(b"");
        // SHA-256 of empty string
        let expected = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_known_abc() {
        let hash = sha256(b"abc");
        let expected = hex::decode(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_collision_resistance() {
        let h1 = sha256(b"input_A");
        let h2 = sha256(b"input_B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq(&[], &[]));
    }

    #[test]
    fn test_random_bytes_length() {
        for len in [0, 1, 16, 32, 64, 1024] {
            let bytes = random_bytes(len).unwrap();
            assert_eq!(bytes.len(), len);
        }
    }

    #[test]
    fn test_random_bytes_uniqueness() {
        let r1 = random_bytes(32).unwrap();
        let r2 = random_bytes(32).unwrap();
        assert_ne!(r1, r2); // Probabilistically guaranteed
    }

    #[test]
    fn test_random_key_uniqueness() {
        let k1 = random_key().unwrap();
        let k2 = random_key().unwrap();
        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn test_x25519_keypair_generate() {
        let kp = X25519KeyPair::generate().unwrap();
        assert_eq!(kp.public_bytes().len(), 32);
        assert_eq!(kp.secret_bytes().len(), 32);
    }

    #[test]
    fn test_x25519_dh_symmetric() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared_alice = alice.diffie_hellman(bob.public_bytes()).unwrap();
        let shared_bob = bob.diffie_hellman(alice.public_bytes()).unwrap();
        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn test_x25519_different_keypairs() {
        let kp1 = X25519KeyPair::generate().unwrap();
        let kp2 = X25519KeyPair::generate().unwrap();
        assert_ne!(kp1.public_bytes(), kp2.public_bytes());
    }

    #[test]
    fn test_secret_key_from_bytes_valid() {
        let key = SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
        assert_eq!(key.as_bytes()[0], 0x42);
    }

    #[test]
    fn test_secret_key_from_bytes_invalid() {
        assert!(SecretKey::from_bytes(&[0u8; 16]).is_err());
        assert!(SecretKey::from_bytes(&[0u8; 0]).is_err());
        assert!(SecretKey::from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_secret_key_as_ref() {
        let key = SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
        let r: &[u8] = key.as_ref();
        assert_eq!(r.len(), 32);
    }

    #[test]
    fn test_nonce_random() {
        let n1 = Nonce::random().unwrap();
        let n2 = Nonce::random().unwrap();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn test_salt_random() {
        let s1 = Salt::random().unwrap();
        let s2 = Salt::random().unwrap();
        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn test_salt_from_bytes_valid() {
        let salt = Salt::from_bytes(&[0u8; 16]).unwrap();
        assert_eq!(salt.as_bytes().len(), 16);
    }

    #[test]
    fn test_salt_from_bytes_invalid() {
        assert!(Salt::from_bytes(&[0u8; 8]).is_err());
        assert!(Salt::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_salt_as_ref() {
        let salt = Salt::from_bytes(&[0x42u8; 16]).unwrap();
        let r: &[u8] = salt.as_ref();
        assert_eq!(r.len(), 16);
    }

    #[test]
    fn test_nonce_from_bytes_and_as_bytes() {
        let bytes = [0x11u8; 12];
        let nonce = Nonce::from_bytes(&bytes).unwrap();
        assert_eq!(*nonce.as_bytes(), bytes);
    }

    #[test]
    fn test_nonce_as_ref_trait() {
        let nonce = Nonce::from_bytes(&[0x22u8; 12]).unwrap();
        let r: &[u8] = nonce.as_ref();
        assert_eq!(r[0], 0x22);
    }

    #[test]
    fn test_crypto_error_display_all() {
        let errors: Vec<CryptoError> = vec![
            CryptoError::InvalidKeySize(16, 32),
            CryptoError::InvalidNonceSize(8, 12),
            CryptoError::EncryptionFailed("test".to_string()),
            CryptoError::DecryptionFailed,
            CryptoError::KeyDerivationFailed("kdf fail".to_string()),
            CryptoError::SignatureInvalid,
            CryptoError::RandomFailed("rng fail".to_string()),
            CryptoError::FeatureDisabled,
        ];

        for err in &errors {
            let display = format!("{}", err);
            assert!(!display.is_empty(), "Empty display for {:?}", err);
            let debug = format!("{:?}", err);
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_crypto_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(CryptoError::DecryptionFailed);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_argon2_params_default() {
        let p = Argon2Params::default();
        assert_eq!(p.memory_kib, constants::ARGON2_MEMORY_KIB);
        assert_eq!(p.time, constants::ARGON2_TIME);
        assert_eq!(p.parallelism, constants::ARGON2_PARALLELISM);
    }

    #[test]
    fn test_argon2_params_owasp_minimum() {
        let p = Argon2Params::owasp_minimum();
        assert_eq!(p.memory_kib, 65536);
        assert_eq!(p.time, 3);
        assert_eq!(p.parallelism, 4);
    }

    #[test]
    fn test_argon2_params_ultra() {
        let p = Argon2Params::ultra();
        assert_eq!(p.memory_kib, 1048576);
        assert_eq!(p.time, 40);
    }

    #[test]
    fn test_argon2_params_copy() {
        let p1 = Argon2Params::owasp_minimum();
        let p2 = p1; // Copy
        assert_eq!(p1.memory_kib, p2.memory_kib);
    }
}

// ─── PQ crypto tests ───────────────────────────────────────────────────────

#[cfg(feature = "pq-crypto")]
mod pq_crypto_tests {
    use crypto_core::pure_crypto::pq::*;
    #[test]
    fn test_mlkem_keypair_generate() {
        let kp = MlKemKeyPair::generate().unwrap();
        assert!(!kp.encapsulation_key().is_empty());
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate_roundtrip() {
        let kp = MlKemKeyPair::generate().unwrap();
        let (ct, shared_enc) = mlkem_encapsulate(kp.encapsulation_key()).unwrap();
        let shared_dec = kp.decapsulate(&ct).unwrap();
        assert_eq!(shared_enc, shared_dec);
    }

    #[test]
    fn test_mlkem_encapsulate_invalid_key() {
        let result = mlkem_encapsulate(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mlkem_shared_secret_size() {
        let kp = MlKemKeyPair::generate().unwrap();
        let (_ct, shared) = mlkem_encapsulate(kp.encapsulation_key()).unwrap();
        assert_eq!(shared.len(), MLKEM_SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_hybrid_key_derive() {
        let x_shared = [0x11u8; 32];
        let pq_shared = [0x22u8; 32];
        let info = b"hybrid_test";

        let key = hybrid_key_derive(&x_shared, &pq_shared, info).unwrap();
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_hybrid_key_derive_different_inputs() {
        let info = b"test";
        let k1 = hybrid_key_derive(&[0x11u8; 32], &[0x22u8; 32], info).unwrap();
        let k2 = hybrid_key_derive(&[0x33u8; 32], &[0x44u8; 32], info).unwrap();
        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn test_pq_backend_info() {
        let info = pq_backend_info();
        assert!(info.contains("ML-KEM-1024"));
        assert!(info.contains("Post-Quantum"));
    }

    #[test]
    fn test_backend_name() {
        let name = backend_name();
        assert!(!name.is_empty());
    }
}

// ─── Constants tests ────────────────────────────────────────────────────────

#[cfg(feature = "pure-crypto")]
mod constants_tests {
    use crypto_core::pure_crypto::constants::*;

    #[test]
    fn test_all_constants() {
        assert_eq!(AES_KEY_SIZE, 32);
        assert_eq!(AES_NONCE_SIZE, 12);
        assert_eq!(AES_TAG_SIZE, 16);
        assert_eq!(X25519_KEY_SIZE, 32);
        assert_eq!(SHA256_SIZE, 32);
        assert_eq!(HMAC_SIZE, 32);
        assert_eq!(ARGON2_SALT_SIZE, 16);
    }
}

// ─── Integration tests ─────────────────────────────────────────────────────

#[cfg(feature = "pure-crypto")]
mod integration_tests {
    use crypto_core::pure_crypto::*;

    #[test]
    fn test_full_encrypt_then_mac_pipeline() {
        // Derive key from password
        let salt = Salt::from_bytes(&[0xAAu8; 16]).unwrap();
        let params = Argon2Params {
            memory_kib: 1024,
            time: 1,
            parallelism: 1,
        };
        let key = argon2_derive(b"testing_password", &salt, Some(params)).unwrap();

        // Encrypt
        let nonce = Nonce::from_bytes(&[0x11u8; 12]).unwrap();
        let plaintext = b"This is a secret message for the pipeline test";
        let aad = b"manifest_v2";
        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();

        // Compute HMAC over ciphertext
        let mac = hmac_sha256(key.as_ref(), &ciphertext);

        // Verify HMAC
        assert!(hmac_sha256_verify(key.as_ref(), &ciphertext, &mac));

        // Decrypt
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hkdf_derived_key_for_encryption() {
        let master = b"master keying material from password";
        let derived_key = hkdf_derive_key(master, Some(b"salt"), b"enc_key_v1").unwrap();

        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();
        let ct = aes_gcm_encrypt(&derived_key, &nonce, b"derived encryption", None).unwrap();
        let pt = aes_gcm_decrypt(&derived_key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, b"derived encryption");
    }

    #[test]
    fn test_x25519_then_hkdf_then_encrypt() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared = alice.diffie_hellman(bob.public_bytes()).unwrap();

        // Derive encryption key from shared secret
        let enc_key = hkdf_derive_key(&shared, Some(b"salt"), b"meow_enc_key").unwrap();

        let nonce = Nonce::from_bytes(&[0x42u8; 12]).unwrap();
        let ct = aes_gcm_encrypt(&enc_key, &nonce, b"x25519 test", Some(b"aad")).unwrap();
        let pt = aes_gcm_decrypt(&enc_key, &nonce, &ct, Some(b"aad")).unwrap();
        assert_eq!(pt, b"x25519 test");
    }

    #[test]
    fn test_aes_ctr_encrypt_then_mac() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 16];
        let data = b"CTR mode with MAC";

        // Encrypt with CTR
        let ct = aes_ctr_crypt(&key, &nonce, data, 0).unwrap();

        // MAC over nonce || ciphertext
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&nonce);
        mac_input.extend_from_slice(&ct);
        let mac = hmac_sha256(&key, &mac_input);

        // Verify MAC
        assert!(hmac_sha256_verify(&key, &mac_input, &mac));

        // Decrypt
        let pt = aes_ctr_crypt(&key, &nonce, &ct, 0).unwrap();
        assert_eq!(pt, data);
    }
}
