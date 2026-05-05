//! Coverage boost tests for crypto_core
//!
//! Targets specific uncovered code paths identified by tarpaulin lcov analysis.
//! Focus: secure_alloc.rs Display/Error impls, pure_crypto.rs ML-DSA functions,
//! ML-KEM error paths, and aead_wrapper edge cases.

// =============================================================================
// SecureAlloc Coverage
// =============================================================================

mod secure_alloc_coverage {
    use crypto_core::secure_alloc::{SecureAllocError, SecureBox};

    #[test]
    fn test_secure_alloc_error_display_mmap() {
        let err = SecureAllocError::MmapFailed(22);
        let msg = format!("{}", err);
        assert!(msg.contains("mmap failed"));
        assert!(msg.contains("22"));
    }

    #[test]
    fn test_secure_alloc_error_display_mprotect() {
        let err = SecureAllocError::MprotectFailed(13);
        let msg = format!("{}", err);
        assert!(msg.contains("mprotect failed"));
        assert!(msg.contains("13"));
    }

    #[test]
    fn test_secure_alloc_error_display_zero_size() {
        let err = SecureAllocError::ZeroSize;
        let msg = format!("{}", err);
        assert!(msg.contains("zero-size"));
    }

    #[test]
    fn test_secure_alloc_error_is_error_trait() {
        let err = SecureAllocError::ZeroSize;
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_secure_alloc_error_debug() {
        let err = SecureAllocError::MmapFailed(5);
        let debug = format!("{:?}", err);
        assert!(debug.contains("MmapFailed"));
    }

    #[test]
    fn test_secure_box_is_locked() {
        let sbox = SecureBox::new([0u8; 32]).expect("alloc failed");
        // is_locked() returns bool depending on mlock success (best-effort)
        let _locked = sbox.is_locked();
    }

    #[test]
    fn test_secure_box_data_size() {
        let sbox = SecureBox::new([0u8; 64]).expect("alloc failed");
        assert_eq!(sbox.data_size(), 64);
    }

    #[test]
    fn test_secure_box_total_size() {
        let sbox = SecureBox::new([0u8; 32]).expect("alloc failed");
        // Total size must be larger than data size (includes guard pages)
        assert!(sbox.total_size() > sbox.data_size());
    }

    #[test]
    fn test_secure_box_deref_mut() {
        let mut sbox = SecureBox::new([0u8; 32]).expect("alloc failed");
        // Exercise DerefMut
        let data: &mut [u8; 32] = &mut *sbox;
        data[0] = 0xFF;
        data[31] = 0xAA;
        assert_eq!(sbox[0], 0xFF);
        assert_eq!(sbox[31], 0xAA);
    }

    #[test]
    fn test_secure_box_debug_format() {
        let sbox = SecureBox::new([0x42u8; 16]).expect("alloc failed");
        let debug = format!("{:?}", sbox);
        assert!(debug.contains("SecureBox"));
        assert!(debug.contains("data_size"));
        assert!(debug.contains("mlocked"));
        assert!(debug.contains("total_size"));
        // Must NOT leak the actual data
        assert!(!debug.contains("66")); // 0x42 = 66 decimal
    }

    #[test]
    fn test_secure_box_zero_size_error() {
        let result = SecureBox::new(());
        assert!(result.is_err());
        if let Err(e) = result {
            let msg = format!("{}", e);
            assert!(msg.contains("zero-size"));
        }
    }

    #[test]
    fn test_secure_box_send_sync() {
        // Verify SecureBox is Send + Sync
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<SecureBox<[u8; 32]>>();
        assert_sync::<SecureBox<[u8; 32]>>();
    }

    #[test]
    fn test_secure_box_large_multi_page() {
        // Allocate something that spans multiple pages (typically 4096 bytes per page)
        let sbox = SecureBox::new([0xCDu8; 8192]).expect("alloc failed");
        assert_eq!(sbox.data_size(), 8192);
        assert_eq!(sbox[0], 0xCD);
        assert_eq!(sbox[8191], 0xCD);
        // Should have at least 3 pages worth of total size
        assert!(sbox.total_size() >= 3 * 4096);
    }

    #[test]
    fn test_secure_box_drop_with_mlock() {
        // Create and immediately drop to exercise the Drop path with mlocked memory
        let sbox = SecureBox::new([0xFFu8; 128]).expect("alloc failed");
        let was_locked = sbox.is_locked();
        drop(sbox);
        // If locked, the Drop impl calls munlock before munmap
        let _ = was_locked; // just verify no panic
    }
}

// =============================================================================
// ML-DSA-65 Signing Coverage (FIPS 204)
// =============================================================================

#[cfg(feature = "pq-crypto")]
mod mldsa65_coverage {
    use crypto_core::pure_crypto::pq;

    #[test]
    fn test_mldsa65_keygen_sign_verify_roundtrip() {
        let (seed, vk_bytes) = pq::mldsa65_keygen().expect("keygen failed");
        assert_eq!(seed.len(), 32);
        assert_eq!(vk_bytes.len(), pq::MLDSA65_PUBLIC_KEY_SIZE);

        let message = b"Hello, post-quantum world!";
        let sig = pq::mldsa65_sign(&seed, message).expect("sign failed");
        assert_eq!(sig.len(), pq::MLDSA65_SIGNATURE_SIZE);

        let valid = pq::mldsa65_verify(&vk_bytes, message, &sig).expect("verify failed");
        assert!(valid);
    }

    #[test]
    fn test_mldsa65_verify_wrong_message() {
        let (seed, vk_bytes) = pq::mldsa65_keygen().expect("keygen failed");
        let sig = pq::mldsa65_sign(&seed, b"correct message").expect("sign failed");

        let valid =
            pq::mldsa65_verify(&vk_bytes, b"wrong message", &sig).expect("verify should not err");
        assert!(!valid, "Signature should not verify with wrong message");
    }

    #[test]
    fn test_mldsa65_sign_invalid_seed_length() {
        let result = pq::mldsa65_sign(&[0u8; 16], b"message");
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa65_verify_invalid_public_key_length() {
        let result = pq::mldsa65_verify(&[0u8; 32], b"message", &[0u8; 3309]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa65_verify_invalid_signature_length() {
        let (_, vk_bytes) = pq::mldsa65_keygen().expect("keygen failed");
        let result = pq::mldsa65_verify(&vk_bytes, b"message", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa65_sign_empty_message() {
        let (seed, vk_bytes) = pq::mldsa65_keygen().expect("keygen failed");
        let sig = pq::mldsa65_sign(&seed, b"").expect("sign empty message");
        let valid = pq::mldsa65_verify(&vk_bytes, b"", &sig).expect("verify");
        assert!(valid);
    }

    #[test]
    fn test_mldsa65_sign_large_message() {
        let (seed, vk_bytes) = pq::mldsa65_keygen().expect("keygen failed");
        let message = vec![0xABu8; 10000];
        let sig = pq::mldsa65_sign(&seed, &message).expect("sign large message");
        let valid = pq::mldsa65_verify(&vk_bytes, &message, &sig).expect("verify");
        assert!(valid);
    }

    #[test]
    fn test_mldsa65_different_keys_fail_verify() {
        let (seed1, _vk1) = pq::mldsa65_keygen().expect("keygen 1");
        let (_, vk2) = pq::mldsa65_keygen().expect("keygen 2");
        let sig = pq::mldsa65_sign(&seed1, b"msg").expect("sign");
        let valid = pq::mldsa65_verify(&vk2, b"msg", &sig).expect("verify");
        assert!(!valid, "Cross-key verification should fail");
    }
}

// =============================================================================
// ML-KEM Error Path Coverage
// =============================================================================

#[cfg(feature = "pq-crypto")]
mod mlkem_error_coverage {
    use crypto_core::pure_crypto::pq;

    #[test]
    fn test_mlkem_encapsulate_invalid_key_length() {
        // Too short key
        let result = pq::mlkem_encapsulate(&[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mlkem_decapsulate_invalid_ciphertext_length() {
        let kp = pq::MlKemKeyPair::generate().expect("keygen");
        // Wrong ciphertext length
        let result = kp.decapsulate(&[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mlkem_keypair_encapsulation_key() {
        let kp = pq::MlKemKeyPair::generate().expect("keygen");
        let ek = kp.encapsulation_key();
        assert_eq!(ek.len(), pq::MLKEM_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate_roundtrip() {
        let kp = pq::MlKemKeyPair::generate().expect("keygen");
        let (ct, shared1) = pq::mlkem_encapsulate(kp.encapsulation_key()).expect("encaps");
        assert_eq!(ct.len(), pq::MLKEM_CIPHERTEXT_SIZE);
        assert_eq!(shared1.len(), pq::MLKEM_SHARED_SECRET_SIZE);

        let shared2 = kp.decapsulate(&ct).expect("decaps");
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_mlkem_backend_name() {
        let name = pq::backend_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_mlkem_pq_backend_info() {
        let info = pq::pq_backend_info();
        assert!(info.contains("Post-Quantum Backend"));
        assert!(info.contains("ML-KEM-1024"));
    }

    #[test]
    fn test_mlkem_hybrid_key_derive() {
        let x25519_shared = [0x11u8; 32];
        let mlkem_shared = [0x22u8; 32];
        let key = pq::hybrid_key_derive(&x25519_shared, &mlkem_shared, b"test-info")
            .expect("hybrid derive");
        assert_eq!(key.as_bytes().len(), 32);
        // Verify deterministic
        let key2 = pq::hybrid_key_derive(&x25519_shared, &mlkem_shared, b"test-info")
            .expect("hybrid derive 2");
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_mlkem_constants() {
        assert_eq!(pq::MLKEM_PUBLIC_KEY_SIZE, 1568);
        assert_eq!(pq::MLKEM_SECRET_KEY_SIZE, 3168);
        assert_eq!(pq::MLKEM_CIPHERTEXT_SIZE, 1568);
        assert_eq!(pq::MLKEM_SHARED_SECRET_SIZE, 32);
        assert_eq!(pq::MLDSA65_PUBLIC_KEY_SIZE, 1952);
        assert_eq!(pq::MLDSA65_SIGNATURE_SIZE, 3309);
    }
}

// =============================================================================
// AeadWrapper additional edge cases
// =============================================================================

mod aead_wrapper_edge_cases {
    use crypto_core::*;

    #[test]
    fn test_aead_encrypt_empty_plaintext() {
        let key = [0x42u8; KEY_SIZE];
        let wrapper = AeadWrapper::new(&key).expect("wrapper");
        // Empty plaintext is valid (produces nonce + auth tag)
        let (nonce, ct) = wrapper.encrypt(b"", b"aad").expect("encrypt empty");
        assert_eq!(ct.len(), TAG_SIZE); // Just the auth tag
                                        // Verify we can decrypt it back
        let pt = wrapper.decrypt(&nonce, &ct, b"aad").expect("decrypt");
        assert_eq!(pt.data(), b"");
    }

    #[test]
    fn test_aead_decrypt_short_ciphertext() {
        let key = [0x42u8; KEY_SIZE];
        let wrapper = AeadWrapper::new(&key).expect("wrapper");
        let nonce = [0u8; NONCE_SIZE];
        // Ciphertext shorter than tag size should fail
        let result = wrapper.decrypt(&nonce, &[0u8; 15], b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_encrypt_raw_decrypt_raw() {
        let key = [0x42u8; KEY_SIZE];
        let wrapper = AeadWrapper::new(&key).expect("wrapper");
        let nonce = [0xAAu8; NONCE_SIZE];
        let ct = wrapper
            .encrypt_raw(&nonce, b"hello", b"aad")
            .expect("encrypt_raw");
        let pt = wrapper
            .decrypt_raw(&nonce, &ct, b"aad")
            .expect("decrypt_raw");
        assert_eq!(pt, b"hello");
    }
}

// =============================================================================
// Pure crypto additional edge cases
// =============================================================================

#[cfg(feature = "pure-crypto")]
mod pure_crypto_edge_cases {
    use crypto_core::*;

    #[test]
    fn test_hmac_sha256_empty_key() {
        // HMAC-SHA256 accepts any key length including empty
        let tag = hmac_sha256(b"", b"data");
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_verify_wrong_tag() {
        let tag = hmac_sha256(b"key", b"data");
        let wrong_tag = [0u8; 32];
        assert!(!hmac_sha256_verify(b"key", b"data", &wrong_tag));
        assert!(hmac_sha256_verify(b"key", b"data", &tag));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        // SHA-256 of empty string is well-known
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_random_bytes_length() {
        let bytes = random_bytes(64).expect("random");
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn test_random_key_is_32_bytes() {
        let key = random_key().expect("random key");
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_crypto_error_display_variants() {
        let errors = vec![
            CryptoError::InvalidKeySize(16, 32),
            CryptoError::InvalidNonceSize(8, 12),
            CryptoError::EncryptionFailed("test".into()),
            CryptoError::DecryptionFailed,
            CryptoError::KeyDerivationFailed("test".into()),
            CryptoError::SignatureInvalid,
            CryptoError::RandomFailed("test".into()),
            CryptoError::FeatureDisabled,
        ];
        for err in &errors {
            let msg = format!("{}", err);
            assert!(!msg.is_empty());
        }
        // Verify Debug
        for err in &errors {
            let dbg = format!("{:?}", err);
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn test_hkdf_derive_key() {
        let key =
            hkdf_derive_key(b"input key material", Some(b"salt"), b"info").expect("hkdf derive");
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_argon2_derive() {
        let salt = Salt::random().expect("salt");
        let params = Argon2Params {
            memory_kib: 1024,
            time: 1,
            parallelism: 1,
        };
        let key = argon2_derive(b"password", &salt, Some(params)).expect("argon2");
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_argon2_params_presets() {
        let owasp = Argon2Params::owasp_minimum();
        assert_eq!(owasp.memory_kib, 65536);
        assert_eq!(owasp.time, 3);

        let ultra = Argon2Params::ultra();
        assert_eq!(ultra.memory_kib, 1048576);
        assert_eq!(ultra.time, 40);

        let default = Argon2Params::default();
        assert!(default.memory_kib > 0);
    }

    #[test]
    fn test_salt_from_bytes() {
        let bytes = [0xABu8; 16];
        let salt = Salt::from_bytes(&bytes).expect("salt from bytes");
        assert_eq!(salt.as_bytes(), &bytes);
    }

    #[test]
    fn test_salt_from_bytes_wrong_len() {
        let result = Salt::from_bytes(&[0u8; 8]);
        assert!(result.is_err());
    }

    #[test]
    fn test_x25519_keypair_exchange() {
        let kp1 = X25519KeyPair::generate().expect("keygen1");
        let kp2 = X25519KeyPair::generate().expect("keygen2");

        let shared1 = kp1.diffie_hellman(kp2.public_bytes()).expect("dh1");
        let shared2 = kp2.diffie_hellman(kp1.public_bytes()).expect("dh2");

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_x25519_keypair_bytes_access() {
        let kp = X25519KeyPair::generate().expect("keygen");
        assert_eq!(kp.public_bytes().len(), 32);
        assert_eq!(kp.secret_bytes().len(), 32);
    }

    #[test]
    fn test_nonce_from_bytes_valid() {
        use crypto_core::pure_crypto::Nonce as PureNonce;
        let nonce = PureNonce::from_bytes(&[0u8; 12]).expect("nonce");
        assert_eq!(nonce.as_bytes().len(), 12);
    }

    #[test]
    fn test_nonce_from_bytes_invalid() {
        use crypto_core::pure_crypto::Nonce as PureNonce;
        let result = PureNonce::from_bytes(&[0u8; 8]);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_key_from_bytes() {
        let key = SecretKey::from_bytes(&[0x55u8; 32]).expect("key");
        assert_eq!(key.as_bytes()[0], 0x55);
    }

    #[test]
    fn test_secret_key_from_bytes_wrong_len() {
        let result = SecretKey::from_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_pure() {
        use crypto_core::pure_crypto;
        let key = SecretKey::from_bytes(&[0x42u8; 32]).expect("key");
        let nonce = pure_crypto::Nonce::random().expect("nonce");
        let ct = aes_gcm_encrypt(&key, &nonce, b"hello world", Some(b"aad")).expect("enc");
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, Some(b"aad")).expect("dec");
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn test_aes_gcm_decrypt_wrong_key() {
        use crypto_core::pure_crypto;
        let key1 = SecretKey::from_bytes(&[0x42u8; 32]).expect("key1");
        let key2 = SecretKey::from_bytes(&[0x43u8; 32]).expect("key2");
        let nonce = pure_crypto::Nonce::random().expect("nonce");
        let ct = aes_gcm_encrypt(&key1, &nonce, b"secret", None).expect("enc");
        let result = aes_gcm_decrypt(&key2, &nonce, &ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_derive_raw() {
        let output = hkdf_derive(b"ikm", Some(b"salt"), b"info", 64).expect("hkdf");
        assert_eq!(output.len(), 64);
    }
}
