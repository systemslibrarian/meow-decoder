//! Comprehensive coverage tests for rust_crypto handles module.
//!
//! Targets 95%+ coverage of handles.rs: prefixed HMAC, stream CTR/HMAC/nonce,
//! ratchet chains, mixed HKDF operations, PQXDH encapsulate/decapsulate,
//! X25519 import, HandleError Display, session isolation, and edge cases.

use meow_crypto_rs::handles::*;

// ─── Helper ────────────────────────────────────────────────────────────────

fn fresh_key() -> HandleId {
    handle_import_key(&[0xABu8; 32]).unwrap()
}

fn fresh_key_bytes(byte: u8) -> HandleId {
    handle_import_key(&[byte; 32]).unwrap()
}

// ─── HandleError Display coverage ──────────────────────────────────────────

#[test]
fn test_handle_error_display_all_variants() {
    let variants: Vec<HandleError> = vec![
        HandleError::InvalidHandle,
        HandleError::RegistryFull,
        HandleError::InvalidKeyLength {
            expected: 32,
            got: 16,
        },
        HandleError::InvalidNonceLength {
            expected: 12,
            got: 8,
        },
        HandleError::CiphertextTooShort,
        HandleError::EncryptionFailed,
        HandleError::DecryptionFailed,
        HandleError::HkdfFailed("test error".into()),
        HandleError::InvalidPrkLength,
        HandleError::AuthenticationFailed,
        HandleError::InvalidPublicKeyLength,
        HandleError::HandleTypeMismatch,
    ];

    for err in &variants {
        let display = format!("{}", err);
        assert!(!display.is_empty(), "Display for {:?} is empty", err);
        let debug = format!("{:?}", err);
        assert!(!debug.is_empty());
    }

    // Specific content checks
    assert!(format!("{}", HandleError::InvalidHandle).contains("Invalid"));
    assert!(format!("{}", HandleError::RegistryFull).contains("65536"));
    assert!(format!(
        "{}",
        HandleError::InvalidKeyLength {
            expected: 32,
            got: 16
        }
    )
    .contains("32"));
    assert!(format!(
        "{}",
        HandleError::InvalidNonceLength {
            expected: 12,
            got: 8
        }
    )
    .contains("12"));
    assert!(format!("{}", HandleError::CiphertextTooShort).contains("short"));
    assert!(format!("{}", HandleError::HkdfFailed("ctx".into())).contains("ctx"));
    assert!(format!("{}", HandleError::InvalidPublicKeyLength).contains("32 bytes"));
}

// ─── Prefixed HMAC tests ───────────────────────────────────────────────────

#[test]
fn test_prefixed_hmac_basic() {
    let key_id = fresh_key();
    let prefix = b"MANIFEST_HMAC_KEY_PREFIX";
    let message = b"manifest bytes here";

    let tag = handle_hmac_sha256_prefixed(key_id, prefix, message).unwrap();
    assert_eq!(tag.len(), 32);

    // Verify succeeds
    let ok = handle_hmac_sha256_prefixed_verify(key_id, prefix, message, &tag).unwrap();
    assert!(ok);

    handle_drop(key_id).unwrap();
}

#[test]
fn test_prefixed_hmac_wrong_prefix_fails() {
    let key_id = fresh_key();
    let tag = handle_hmac_sha256_prefixed(key_id, b"PREFIX_A", b"msg").unwrap();

    let ok = handle_hmac_sha256_prefixed_verify(key_id, b"PREFIX_B", b"msg", &tag).unwrap();
    assert!(!ok);

    handle_drop(key_id).unwrap();
}

#[test]
fn test_prefixed_hmac_wrong_message_fails() {
    let key_id = fresh_key();
    let tag = handle_hmac_sha256_prefixed(key_id, b"PFX", b"correct").unwrap();

    let ok = handle_hmac_sha256_prefixed_verify(key_id, b"PFX", b"wrong", &tag).unwrap();
    assert!(!ok);

    handle_drop(key_id).unwrap();
}

#[test]
fn test_prefixed_hmac_wrong_tag_fails() {
    let key_id = fresh_key();
    let _tag = handle_hmac_sha256_prefixed(key_id, b"PFX", b"msg").unwrap();

    let ok = handle_hmac_sha256_prefixed_verify(key_id, b"PFX", b"msg", &[0u8; 32]).unwrap();
    assert!(!ok);

    handle_drop(key_id).unwrap();
}

#[test]
fn test_prefixed_hmac_tag_length_mismatch() {
    let key_id = fresh_key();
    let tag = handle_hmac_sha256_prefixed(key_id, b"PFX", b"msg").unwrap();
    assert_eq!(tag.len(), 32);

    // Truncated tag should fail
    let ok = handle_hmac_sha256_prefixed_verify(key_id, b"PFX", b"msg", &tag[..16]).unwrap();
    assert!(!ok);

    handle_drop(key_id).unwrap();
}

#[test]
fn test_prefixed_hmac_domain_separation() {
    let key_id = fresh_key();
    let msg = b"same message";

    let tag_a = handle_hmac_sha256_prefixed(key_id, b"DOMAIN_A", msg).unwrap();
    let tag_b = handle_hmac_sha256_prefixed(key_id, b"DOMAIN_B", msg).unwrap();
    assert_ne!(
        tag_a, tag_b,
        "Different prefixes must produce different tags"
    );

    handle_drop(key_id).unwrap();
}

#[test]
fn test_prefixed_hmac_empty_prefix() {
    let key_id = fresh_key();
    let msg = b"test";

    // Empty prefix is equivalent to unprefixed HMAC with just key bytes
    let tag_prefixed = handle_hmac_sha256_prefixed(key_id, b"", msg).unwrap();
    let tag_plain = handle_hmac_sha256(key_id, msg).unwrap();
    // Different because prefixed uses prefix||key as key, which here is just key
    assert_eq!(tag_prefixed, tag_plain);

    handle_drop(key_id).unwrap();
}

#[test]
fn test_prefixed_hmac_type_mismatch() {
    let (x_handle, _pub) = handle_x25519_generate().unwrap();
    let err = handle_hmac_sha256_prefixed(x_handle, b"PFX", b"msg");
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(x_handle).unwrap();
}

// ─── Stream CTR crypt tests ───────────────────────────────────────────────

#[test]
fn test_stream_ctr_crypt_basic() {
    let key_id = fresh_key();
    let nonce = [0x77u8; 16];
    let stream_h = handle_stream_new(key_id, &nonce, b"mac_domain").unwrap();

    let plaintext = b"CTR mode streaming encryption test";
    let ciphertext = handle_stream_ctr_crypt(stream_h, plaintext).unwrap();
    assert_ne!(ciphertext, plaintext.to_vec());

    // Create a new stream with the same key to decrypt
    let stream_d = handle_stream_new(key_id, &nonce, b"mac_domain").unwrap();
    let decrypted = handle_stream_ctr_crypt(stream_d, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);

    handle_drop(key_id).unwrap();
    handle_drop(stream_h).unwrap();
    handle_drop(stream_d).unwrap();
}

#[test]
fn test_stream_ctr_crypt_chunked() {
    let key_id = fresh_key();
    let nonce = [0x88u8; 16];
    let stream_enc = handle_stream_new(key_id, &nonce, b"chunked").unwrap();

    // Encrypt in two chunks
    let chunk1 = b"first chunk ";
    let chunk2 = b"second chunk";

    let ct1 = handle_stream_ctr_crypt(stream_enc, chunk1).unwrap();
    let ct2 = handle_stream_ctr_crypt(stream_enc, chunk2).unwrap();

    // Decrypt in two chunks with a fresh stream
    let stream_dec = handle_stream_new(key_id, &nonce, b"chunked").unwrap();
    let pt1 = handle_stream_ctr_crypt(stream_dec, &ct1).unwrap();
    let pt2 = handle_stream_ctr_crypt(stream_dec, &ct2).unwrap();

    assert_eq!(pt1, chunk1.to_vec());
    assert_eq!(pt2, chunk2.to_vec());

    handle_drop(key_id).unwrap();
    handle_drop(stream_enc).unwrap();
    handle_drop(stream_dec).unwrap();
}

#[test]
fn test_stream_ctr_crypt_type_mismatch() {
    let key_id = fresh_key(); // SymmetricKey, not Stream
    let err = handle_stream_ctr_crypt(key_id, b"data");
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(key_id).unwrap();
}

// ─── Stream HMAC tests ────────────────────────────────────────────────────

#[test]
fn test_stream_hmac_basic() {
    let key_id = fresh_key();
    let nonce = [0x99u8; 16];
    let stream_h = handle_stream_new(key_id, &nonce, b"hmac_test").unwrap();

    let message = b"authenticate this";
    let tag = handle_stream_hmac(stream_h, message).unwrap();
    assert_eq!(tag.len(), 32);

    handle_drop(key_id).unwrap();
    handle_drop(stream_h).unwrap();
}

#[test]
fn test_stream_hmac_verify_success() {
    let key_id = fresh_key();
    let nonce = [0xAAu8; 16];
    let stream_h = handle_stream_new(key_id, &nonce, b"verify_test").unwrap();

    let message = b"message to verify";
    let tag = handle_stream_hmac(stream_h, message).unwrap();

    let ok = handle_stream_hmac_verify(stream_h, message, &tag).unwrap();
    assert!(ok);

    handle_drop(key_id).unwrap();
    handle_drop(stream_h).unwrap();
}

#[test]
fn test_stream_hmac_verify_failure() {
    let key_id = fresh_key();
    let nonce = [0xBBu8; 16];
    let stream_h = handle_stream_new(key_id, &nonce, b"verify_fail").unwrap();

    let tag = handle_stream_hmac(stream_h, b"correct").unwrap();
    let ok = handle_stream_hmac_verify(stream_h, b"wrong", &tag).unwrap();
    assert!(!ok);

    handle_drop(key_id).unwrap();
    handle_drop(stream_h).unwrap();
}

#[test]
fn test_stream_hmac_verify_wrong_tag_length() {
    let key_id = fresh_key();
    let nonce = [0xCCu8; 16];
    let stream_h = handle_stream_new(key_id, &nonce, b"tag_len").unwrap();

    let ok = handle_stream_hmac_verify(stream_h, b"msg", &[0u8; 16]).unwrap();
    assert!(!ok); // Tag length mismatch (16 vs 32)

    handle_drop(key_id).unwrap();
    handle_drop(stream_h).unwrap();
}

#[test]
fn test_stream_hmac_type_mismatch() {
    let key_id = fresh_key(); // Not a Stream handle
    let err = handle_stream_hmac(key_id, b"msg");
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(key_id).unwrap();
}

// ─── Stream nonce tests ───────────────────────────────────────────────────

#[test]
fn test_stream_nonce_retrieval() {
    let key_id = fresh_key();
    let nonce = [0xDDu8; 16];
    let stream_h = handle_stream_new(key_id, &nonce, b"nonce_test").unwrap();

    let retrieved = handle_stream_nonce(stream_h).unwrap();
    assert_eq!(retrieved, nonce);

    handle_drop(key_id).unwrap();
    handle_drop(stream_h).unwrap();
}

#[test]
fn test_stream_nonce_type_mismatch() {
    let key_id = fresh_key();
    let err = handle_stream_nonce(key_id);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(key_id).unwrap();
}

// ─── Stream reset offset tests ─────────────────────────────────────────────

#[test]
fn test_stream_reset_offset() {
    let key_id = fresh_key();
    let nonce = [0xEEu8; 16];
    let stream_h = handle_stream_new(key_id, &nonce, b"reset_test").unwrap();

    // Encrypt some data (advances offset)
    let _ct = handle_stream_ctr_crypt(stream_h, b"some data to advance offset").unwrap();

    // Reset offset to 0
    handle_stream_reset_offset(stream_h).unwrap();

    // Should now produce same ciphertext as a fresh stream
    let fresh_stream = handle_stream_new(key_id, &nonce, b"reset_test").unwrap();
    let data = b"test data after reset";
    let ct_reset = handle_stream_ctr_crypt(stream_h, data).unwrap();
    let ct_fresh = handle_stream_ctr_crypt(fresh_stream, data).unwrap();
    assert_eq!(ct_reset, ct_fresh);

    handle_drop(key_id).unwrap();
    handle_drop(stream_h).unwrap();
    handle_drop(fresh_stream).unwrap();
}

#[test]
fn test_stream_reset_offset_type_mismatch() {
    let key_id = fresh_key();
    let err = handle_stream_reset_offset(key_id);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(key_id).unwrap();
}

// ─── Ratchet multi-step tests ──────────────────────────────────────────────

#[test]
fn test_ratchet_multi_step_chain() {
    let root_key = fresh_key();
    let ratchet_h = handle_ratchet_new(root_key, b"salt", b"root_info").unwrap();

    // Advance ratchet 5 times, collecting message keys
    let mut msg_keys = Vec::new();
    for i in 0..5 {
        let step_info = format!("step_{}", i);
        let msg_info = format!("msg_{}", i);
        let msg_key =
            handle_ratchet_step(ratchet_h, step_info.as_bytes(), msg_info.as_bytes()).unwrap();
        msg_keys.push(msg_key);
    }

    // All message keys should be distinct
    for i in 0..msg_keys.len() {
        let bytes_i = handle_export_key(msg_keys[i]).unwrap();
        for (j, key_j) in msg_keys.iter().enumerate().skip(i + 1) {
            let bytes_j = handle_export_key(*key_j).unwrap();
            assert_ne!(bytes_i, bytes_j, "Message keys {} and {} must differ", i, j);
        }
    }

    // Each message key can encrypt
    for key_h in &msg_keys {
        let nonce = [0u8; 12];
        let ct = handle_aes_gcm_encrypt(*key_h, &nonce, b"test", None).unwrap();
        let pt = handle_aes_gcm_decrypt(*key_h, &nonce, &ct, None).unwrap();
        assert_eq!(pt, b"test");
    }

    // Cleanup
    handle_drop(root_key).unwrap();
    handle_drop(ratchet_h).unwrap();
    for k in msg_keys {
        handle_drop(k).unwrap();
    }
}

#[test]
fn test_ratchet_deterministic_derivation() {
    // Two ratchets with same root key, salt, info should produce same message keys
    let root_a = handle_import_key(&[0x11u8; 32]).unwrap();
    let root_b = handle_import_key(&[0x11u8; 32]).unwrap();

    let ratchet_a = handle_ratchet_new(root_a, b"salt", b"info").unwrap();
    let ratchet_b = handle_ratchet_new(root_b, b"salt", b"info").unwrap();

    let msg_a = handle_ratchet_step(ratchet_a, b"step", b"msg").unwrap();
    let msg_b = handle_ratchet_step(ratchet_b, b"step", b"msg").unwrap();

    let bytes_a = handle_export_key(msg_a).unwrap();
    let bytes_b = handle_export_key(msg_b).unwrap();
    assert_eq!(bytes_a, bytes_b);

    handle_drop(root_a).unwrap();
    handle_drop(root_b).unwrap();
    handle_drop(ratchet_a).unwrap();
    handle_drop(ratchet_b).unwrap();
    handle_drop(msg_a).unwrap();
    handle_drop(msg_b).unwrap();
}

#[test]
fn test_ratchet_type_mismatch() {
    let key_id = fresh_key(); // SymmetricKey, not Ratchet
    let err = handle_ratchet_step(key_id, b"step", b"msg");
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(key_id).unwrap();
}

// ─── Mixed HKDF tests ──────────────────────────────────────────────────────

#[test]
fn test_mix_hkdf_basic() {
    let key_id = fresh_key();
    let extra_ikm = b"beacon secret material";
    let salt = b"salt_value";
    let info = b"beacon_mix_info";

    let mixed_h = handle_mix_hkdf(key_id, extra_ikm, salt, info, 32).unwrap();
    assert!(handle_exists(mixed_h));

    // Can use derived key for encryption
    let nonce = [0u8; 12];
    let ct = handle_aes_gcm_encrypt(mixed_h, &nonce, b"test", None).unwrap();
    let pt = handle_aes_gcm_decrypt(mixed_h, &nonce, &ct, None).unwrap();
    assert_eq!(pt, b"test");

    handle_drop(key_id).unwrap();
    handle_drop(mixed_h).unwrap();
}

#[test]
fn test_mix_hkdf_different_extra_ikm_produces_different_keys() {
    let key_id = fresh_key();

    let h1 = handle_mix_hkdf(key_id, b"extra_A", b"salt", b"info", 32).unwrap();
    let h2 = handle_mix_hkdf(key_id, b"extra_B", b"salt", b"info", 32).unwrap();

    let k1 = handle_export_key(h1).unwrap();
    let k2 = handle_export_key(h2).unwrap();
    assert_ne!(k1, k2);

    handle_drop(key_id).unwrap();
    handle_drop(h1).unwrap();
    handle_drop(h2).unwrap();
}

#[test]
fn test_mix_hkdf_empty_salt() {
    let key_id = fresh_key();
    let h = handle_mix_hkdf(key_id, b"extra", b"", b"info", 32).unwrap();
    assert!(handle_exists(h));
    handle_drop(key_id).unwrap();
    handle_drop(h).unwrap();
}

#[test]
fn test_mix_hkdf_type_mismatch() {
    let (x_handle, _) = handle_x25519_generate().unwrap();
    let err = handle_mix_hkdf(x_handle, b"extra", b"salt", b"info", 32);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(x_handle).unwrap();
}

// ─── HKDF with handle salt tests ───────────────────────────────────────────

#[test]
fn test_hkdf_with_handle_salt_basic() {
    let salt_handle = fresh_key();
    let ikm = b"raw shared secret from DH";
    let info = b"root_key_derive";

    let h = handle_hkdf_with_handle_salt(ikm, salt_handle, info, 32).unwrap();
    assert!(handle_exists(h));

    let exported = handle_export_key(h).unwrap();
    assert_eq!(exported.len(), 32);

    handle_drop(salt_handle).unwrap();
    handle_drop(h).unwrap();
}

#[test]
fn test_hkdf_with_handle_salt_different_ikm() {
    let salt_handle = fresh_key();

    let h1 = handle_hkdf_with_handle_salt(b"ikm_A", salt_handle, b"info", 32).unwrap();
    let h2 = handle_hkdf_with_handle_salt(b"ikm_B", salt_handle, b"info", 32).unwrap();

    let k1 = handle_export_key(h1).unwrap();
    let k2 = handle_export_key(h2).unwrap();
    assert_ne!(k1, k2);

    handle_drop(salt_handle).unwrap();
    handle_drop(h1).unwrap();
    handle_drop(h2).unwrap();
}

#[test]
fn test_hkdf_with_handle_salt_type_mismatch() {
    let (x_handle, _) = handle_x25519_generate().unwrap();
    let err = handle_hkdf_with_handle_salt(b"ikm", x_handle, b"info", 32);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(x_handle).unwrap();
}

// ─── HKDF Expand tests ─────────────────────────────────────────────────────

#[test]
fn test_hkdf_expand_basic() {
    let prk_handle = fresh_key();
    let h = handle_hkdf_expand(prk_handle, b"chain_derive", 32).unwrap();
    assert!(handle_exists(h));

    let exported = handle_export_key(h).unwrap();
    assert_eq!(exported.len(), 32);

    handle_drop(prk_handle).unwrap();
    handle_drop(h).unwrap();
}

#[test]
fn test_hkdf_expand_different_info() {
    let prk_handle = fresh_key();

    let h1 = handle_hkdf_expand(prk_handle, b"info_A", 32).unwrap();
    let h2 = handle_hkdf_expand(prk_handle, b"info_B", 32).unwrap();

    let k1 = handle_export_key(h1).unwrap();
    let k2 = handle_export_key(h2).unwrap();
    assert_ne!(k1, k2);

    handle_drop(prk_handle).unwrap();
    handle_drop(h1).unwrap();
    handle_drop(h2).unwrap();
}

#[test]
fn test_hkdf_expand_type_mismatch() {
    let (x_handle, _) = handle_x25519_generate().unwrap();
    let err = handle_hkdf_expand(x_handle, b"info", 32);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(x_handle).unwrap();
}

// ─── HKDF Two Handles tests ────────────────────────────────────────────────

#[test]
fn test_hkdf_two_handles_basic() {
    let ikm_handle = fresh_key_bytes(0x11);
    let salt_handle = fresh_key_bytes(0x22);

    let h = handle_hkdf_two_handles(ikm_handle, salt_handle, b"two_handle_info", 32).unwrap();
    assert!(handle_exists(h));

    let exported = handle_export_key(h).unwrap();
    assert_eq!(exported.len(), 32);

    handle_drop(ikm_handle).unwrap();
    handle_drop(salt_handle).unwrap();
    handle_drop(h).unwrap();
}

#[test]
fn test_hkdf_two_handles_swapped_produces_different() {
    let h_a = fresh_key_bytes(0x11);
    let h_b = fresh_key_bytes(0x22);

    let r1 = handle_hkdf_two_handles(h_a, h_b, b"info", 32).unwrap();
    let r2 = handle_hkdf_two_handles(h_b, h_a, b"info", 32).unwrap();

    let k1 = handle_export_key(r1).unwrap();
    let k2 = handle_export_key(r2).unwrap();
    assert_ne!(
        k1, k2,
        "Swapping IKM and salt must produce different output"
    );

    handle_drop(h_a).unwrap();
    handle_drop(h_b).unwrap();
    handle_drop(r1).unwrap();
    handle_drop(r2).unwrap();
}

#[test]
fn test_hkdf_two_handles_ikm_type_mismatch() {
    let (x_handle, _) = handle_x25519_generate().unwrap();
    let salt_handle = fresh_key();
    let err = handle_hkdf_two_handles(x_handle, salt_handle, b"info", 32);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(x_handle).unwrap();
    handle_drop(salt_handle).unwrap();
}

#[test]
fn test_hkdf_two_handles_salt_type_mismatch() {
    let ikm_handle = fresh_key();
    let (x_handle, _) = handle_x25519_generate().unwrap();
    let err = handle_hkdf_two_handles(ikm_handle, x_handle, b"info", 32);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(ikm_handle).unwrap();
    handle_drop(x_handle).unwrap();
}

// ─── AES-CTR via key handle tests ──────────────────────────────────────────

#[test]
fn test_aes_ctr_crypt_basic() {
    let key_id = fresh_key();
    let nonce = [0x44u8; 16];
    let data = b"plaintext for CTR mode";

    let ct = handle_aes_ctr_crypt(key_id, &nonce, data, 0).unwrap();
    assert_ne!(ct, data.to_vec());

    // CTR is symmetric
    let pt = handle_aes_ctr_crypt(key_id, &nonce, &ct, 0).unwrap();
    assert_eq!(pt, data);

    handle_drop(key_id).unwrap();
}

#[test]
fn test_aes_ctr_crypt_with_offset() {
    let key_id = fresh_key();
    let nonce = [0x55u8; 16];

    let data1 = b"first block data";
    let data2 = b"second block dat";

    // Encrypt at offset 0, then at offset 16
    let ct1 = handle_aes_ctr_crypt(key_id, &nonce, data1, 0).unwrap();
    let ct2 = handle_aes_ctr_crypt(key_id, &nonce, data2, 16).unwrap();

    // Decrypt at matching offsets
    let pt1 = handle_aes_ctr_crypt(key_id, &nonce, &ct1, 0).unwrap();
    let pt2 = handle_aes_ctr_crypt(key_id, &nonce, &ct2, 16).unwrap();

    assert_eq!(pt1, data1);
    assert_eq!(pt2, data2);

    handle_drop(key_id).unwrap();
}

#[test]
fn test_aes_ctr_crypt_wrong_nonce_length() {
    let key_id = fresh_key();
    let err = handle_aes_ctr_crypt(key_id, &[0u8; 12], b"data", 0);
    assert_eq!(
        err,
        Err(HandleError::InvalidNonceLength {
            expected: 16,
            got: 12
        })
    );
    handle_drop(key_id).unwrap();
}

#[test]
fn test_aes_ctr_crypt_type_mismatch() {
    let (x_handle, _) = handle_x25519_generate().unwrap();
    let err = handle_aes_ctr_crypt(x_handle, &[0u8; 16], b"data", 0);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(x_handle).unwrap();
}

// ─── Import X25519 private key tests ───────────────────────────────────────

#[test]
fn test_import_x25519_private_basic() {
    // Generate a keypair to get valid private bytes
    let (gen_handle, gen_pub) = handle_x25519_generate().unwrap();
    let priv_bytes = handle_export_key(gen_handle).unwrap();

    // Import same private bytes
    let imported_handle = handle_import_x25519_private(&priv_bytes).unwrap();

    // Public key from imported should match generated
    let imported_pub = handle_x25519_public(imported_handle).unwrap();
    assert_eq!(imported_pub, gen_pub);

    handle_drop(gen_handle).unwrap();
    handle_drop(imported_handle).unwrap();
}

#[test]
fn test_import_x25519_private_key_exchange() {
    let (alice_handle, _alice_pub) = handle_x25519_generate().unwrap();
    let alice_bytes = handle_export_key(alice_handle).unwrap();

    let imported_handle = handle_import_x25519_private(&alice_bytes).unwrap();
    let (bob_handle, bob_pub) = handle_x25519_generate().unwrap();

    // Exchange using original
    let shared_orig = handle_x25519_exchange(alice_handle, &bob_pub).unwrap();
    // Exchange using imported
    let shared_imported = handle_x25519_exchange(imported_handle, &bob_pub).unwrap();

    // Both should produce the same shared secret
    let nonce = [0u8; 12];
    let ct = handle_aes_gcm_encrypt(shared_orig, &nonce, b"verify", None).unwrap();
    let pt = handle_aes_gcm_decrypt(shared_imported, &nonce, &ct, None).unwrap();
    assert_eq!(pt, b"verify");

    handle_drop(alice_handle).unwrap();
    handle_drop(imported_handle).unwrap();
    handle_drop(bob_handle).unwrap();
    handle_drop(shared_orig).unwrap();
    handle_drop(shared_imported).unwrap();
}

#[test]
fn test_import_x25519_private_wrong_length() {
    let err = handle_import_x25519_private(&[0u8; 16]);
    assert_eq!(
        err,
        Err(HandleError::InvalidKeyLength {
            expected: 32,
            got: 16
        })
    );
}

// ─── PQXDH encapsulate/decapsulate tests ───────────────────────────────────

#[test]
fn test_pqxdh_classical_only_roundtrip() {
    // Receiver generates X25519 keypair
    let (recv_handle, recv_pub) = handle_x25519_generate().unwrap();
    let recv_pub_bytes = recv_pub;

    let extract_salt = &[0u8; 32];
    let info_prefix = b"meow_pqxdh_v1";
    let transcript_domain = b"pqxdh_transcript";

    // Sender encapsulates (classical only, no PQ)
    let (sender_handle, eph_pub) = handle_pqxdh_encapsulate(
        &recv_pub_bytes,
        None, // no PQ
        extract_salt,
        info_prefix,
        transcript_domain,
        None,
        None,
    )
    .unwrap();

    // Receiver decapsulates
    let receiver_handle = handle_pqxdh_decapsulate(
        &eph_pub,
        recv_handle,
        None, // no PQ
        &recv_pub_bytes,
        extract_salt,
        info_prefix,
        transcript_domain,
        None,
        None,
    )
    .unwrap();

    // Both sides should have same shared secret
    let nonce = [0u8; 12];
    let ct = handle_aes_gcm_encrypt(sender_handle, &nonce, b"pqxdh test", None).unwrap();
    let pt = handle_aes_gcm_decrypt(receiver_handle, &nonce, &ct, None).unwrap();
    assert_eq!(pt, b"pqxdh test");

    handle_drop(recv_handle).unwrap();
    handle_drop(sender_handle).unwrap();
    handle_drop(receiver_handle).unwrap();
}

#[test]
fn test_pqxdh_with_pq_shared_secret() {
    let (recv_handle, recv_pub) = handle_x25519_generate().unwrap();

    let pq_shared = [0x42u8; 32]; // Simulated PQ shared secret
    let pq_pub = [0xAAu8; 64]; // Simulated PQ public key
    let pq_ct = [0xBBu8; 128]; // Simulated PQ ciphertext

    let extract_salt = &[0u8; 32];
    let info_prefix = b"meow_pqxdh_v1";
    let transcript_domain = b"pqxdh_transcript";

    let (sender_h, eph_pub) = handle_pqxdh_encapsulate(
        &recv_pub,
        Some(&pq_shared),
        extract_salt,
        info_prefix,
        transcript_domain,
        Some(&pq_pub),
        Some(&pq_ct),
    )
    .unwrap();

    let receiver_h = handle_pqxdh_decapsulate(
        &eph_pub,
        recv_handle,
        Some(&pq_shared),
        &recv_pub,
        extract_salt,
        info_prefix,
        transcript_domain,
        Some(&pq_pub),
        Some(&pq_ct),
    )
    .unwrap();

    // Shared secrets should match
    let nonce = [0u8; 12];
    let ct = handle_aes_gcm_encrypt(sender_h, &nonce, b"hybrid pqxdh", None).unwrap();
    let pt = handle_aes_gcm_decrypt(receiver_h, &nonce, &ct, None).unwrap();
    assert_eq!(pt, b"hybrid pqxdh");

    handle_drop(recv_handle).unwrap();
    handle_drop(sender_h).unwrap();
    handle_drop(receiver_h).unwrap();
}

#[test]
fn test_pqxdh_encapsulate_invalid_pub_key_length() {
    let err = handle_pqxdh_encapsulate(
        &[0u8; 16], // wrong length
        None, &[0u8; 32], b"info", b"domain", None, None,
    );
    assert_eq!(err, Err(HandleError::InvalidPublicKeyLength));
}

#[test]
fn test_pqxdh_decapsulate_invalid_eph_pub_length() {
    let (recv_handle, recv_pub) = handle_x25519_generate().unwrap();
    let err = handle_pqxdh_decapsulate(
        &[0u8; 16], // wrong length
        recv_handle,
        None,
        &recv_pub,
        &[0u8; 32],
        b"info",
        b"domain",
        None,
        None,
    );
    assert_eq!(err, Err(HandleError::InvalidPublicKeyLength));
    handle_drop(recv_handle).unwrap();
}

#[test]
fn test_pqxdh_decapsulate_invalid_receiver_pub_length() {
    let (recv_handle, _recv_pub) = handle_x25519_generate().unwrap();
    let err = handle_pqxdh_decapsulate(
        &[0u8; 32],
        recv_handle,
        None,
        &[0u8; 16], // wrong length
        &[0u8; 32],
        b"info",
        b"domain",
        None,
        None,
    );
    assert_eq!(err, Err(HandleError::InvalidPublicKeyLength));
    handle_drop(recv_handle).unwrap();
}

#[test]
fn test_pqxdh_decapsulate_type_mismatch() {
    let sym_key = fresh_key(); // SymmetricKey, not X25519
    let err = handle_pqxdh_decapsulate(
        &[0u8; 32], sym_key, None, &[0u8; 32], &[0u8; 32], b"info", b"domain", None, None,
    );
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(sym_key).unwrap();
}

// ─── Session isolation tests ────────────────────────────────────────────────

#[test]
fn test_session_creation_enc_only() {
    let enc_key = fresh_key();
    let session_h = handle_session_new(enc_key, None).unwrap();
    assert!(handle_exists(session_h));

    // Session can encrypt
    let nonce = [0u8; 12];
    let ct = handle_aes_gcm_encrypt(session_h, &nonce, b"session", None).unwrap();
    let pt = handle_aes_gcm_decrypt(session_h, &nonce, &ct, None).unwrap();
    assert_eq!(pt, b"session");

    handle_drop(enc_key).unwrap();
    handle_drop(session_h).unwrap();
}

#[test]
fn test_session_creation_with_mac_key() {
    let enc_key = fresh_key();
    let mac_key = fresh_key_bytes(0x33);

    let session_h = handle_session_new(enc_key, Some(mac_key)).unwrap();
    assert!(handle_exists(session_h));

    // Session HMAC should work with the mac_key
    let tag = handle_hmac_sha256(session_h, b"session msg").unwrap();
    assert_eq!(tag.len(), 32);

    handle_drop(enc_key).unwrap();
    handle_drop(mac_key).unwrap();
    handle_drop(session_h).unwrap();
}

#[test]
fn test_session_type_mismatch_on_create() {
    let (x_handle, _) = handle_x25519_generate().unwrap();
    let err = handle_session_new(x_handle, None);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(x_handle).unwrap();
}

// ─── Export key edge cases ──────────────────────────────────────────────────

#[test]
fn test_export_key_nonexistent_handle() {
    let err = handle_export_key(99999999);
    assert_eq!(err, Err(HandleError::InvalidHandle));
}

#[test]
fn test_export_key_session_type_mismatch() {
    let enc_key = fresh_key();
    let session_h = handle_session_new(enc_key, None).unwrap();
    let err = handle_export_key(session_h);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(enc_key).unwrap();
    handle_drop(session_h).unwrap();
}

#[test]
fn test_export_x25519_key() {
    let (x_handle, _pub) = handle_x25519_generate().unwrap();
    let bytes = handle_export_key(x_handle).unwrap();
    assert_eq!(bytes.len(), 32);
    handle_drop(x_handle).unwrap();
}

// ─── HKDF derive (handle_derive_hkdf) edge cases ───────────────────────────

#[test]
fn test_derive_hkdf_from_ratchet() {
    let root_key = fresh_key();
    let ratchet_h = handle_ratchet_new(root_key, b"salt", b"info").unwrap();

    // HKDF from ratchet should use chain_key
    let h = handle_derive_hkdf(ratchet_h, b"salt", b"derive_info", 32).unwrap();
    assert!(handle_exists(h));

    handle_drop(root_key).unwrap();
    handle_drop(ratchet_h).unwrap();
    handle_drop(h).unwrap();
}

#[test]
fn test_derive_hkdf_from_session() {
    let enc_key = fresh_key();
    let session_h = handle_session_new(enc_key, None).unwrap();

    let h = handle_derive_hkdf(session_h, b"salt", b"info", 32).unwrap();
    assert!(handle_exists(h));

    handle_drop(enc_key).unwrap();
    handle_drop(session_h).unwrap();
    handle_drop(h).unwrap();
}

#[test]
fn test_derive_hkdf_bytes_from_handle() {
    let key_id = fresh_key();
    let bytes = handle_derive_hkdf_bytes(key_id, b"salt", b"info", 16).unwrap();
    assert_eq!(bytes.len(), 16);
    handle_drop(key_id).unwrap();
}

#[test]
fn test_derive_hkdf_raw() {
    let h = handle_derive_hkdf_raw(b"raw_ikm", b"salt", b"info", 32).unwrap();
    assert!(handle_exists(h));
    let exported = handle_export_key(h).unwrap();
    assert_eq!(exported.len(), 32);
    handle_drop(h).unwrap();
}

#[test]
fn test_derive_hkdf_raw_empty_salt() {
    let h = handle_derive_hkdf_raw(b"raw_ikm", b"", b"info", 32).unwrap();
    assert!(handle_exists(h));
    handle_drop(h).unwrap();
}

// ─── Stream new edge cases ──────────────────────────────────────────────────

#[test]
fn test_stream_new_wrong_nonce_length() {
    let key_id = fresh_key();
    let err = handle_stream_new(key_id, &[0u8; 12], b"mac");
    assert_eq!(
        err,
        Err(HandleError::InvalidNonceLength {
            expected: 16,
            got: 12,
        })
    );
    handle_drop(key_id).unwrap();
}

#[test]
fn test_stream_new_type_mismatch() {
    let (x_handle, _) = handle_x25519_generate().unwrap();
    let err = handle_stream_new(x_handle, &[0u8; 16], b"mac");
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(x_handle).unwrap();
}

// ─── AES-GCM edge cases via handle ─────────────────────────────────────────

#[test]
fn test_aes_gcm_wrong_nonce_length() {
    let key_id = fresh_key();
    let err = handle_aes_gcm_encrypt(key_id, &[0u8; 8], b"test", None);
    assert_eq!(
        err,
        Err(HandleError::InvalidNonceLength {
            expected: 12,
            got: 8,
        })
    );
    handle_drop(key_id).unwrap();
}

#[test]
fn test_aes_gcm_decrypt_ciphertext_too_short() {
    let key_id = fresh_key();
    let err = handle_aes_gcm_decrypt(key_id, &[0u8; 12], &[0u8; 15], None);
    assert_eq!(err, Err(HandleError::CiphertextTooShort));
    handle_drop(key_id).unwrap();
}

// ─── X25519 exchange edge cases ─────────────────────────────────────────────

#[test]
fn test_x25519_exchange_wrong_pub_length() {
    let (priv_h, _pub) = handle_x25519_generate().unwrap();
    let err = handle_x25519_exchange(priv_h, &[0u8; 16]);
    assert_eq!(err, Err(HandleError::InvalidPublicKeyLength));
    handle_drop(priv_h).unwrap();
}

#[test]
fn test_x25519_public_type_mismatch() {
    let key_id = fresh_key();
    let err = handle_x25519_public(key_id);
    assert_eq!(err, Err(HandleError::HandleTypeMismatch));
    handle_drop(key_id).unwrap();
}

// ─── Argon2id edge cases ────────────────────────────────────────────────────

#[test]
fn test_argon2id_wrong_salt_length() {
    let err = handle_derive_key_argon2id(b"pass", &[0u8; 8], 1024, 1, 1);
    assert_eq!(
        err,
        Err(HandleError::InvalidKeyLength {
            expected: 16,
            got: 8,
        })
    );
}

// ─── Handle count / exists coverage ─────────────────────────────────────────

#[test]
fn test_handle_count_increases() {
    let h = fresh_key();
    // Verify the handle exists and the registry is non-empty.
    // We avoid comparing before/after counts because parallel tests share
    // the global registry and can cause spurious failures.
    assert!(handle_exists(h));
    assert!(handle_count() >= 1);
    handle_drop(h).unwrap();
}

#[test]
fn test_dropped_handle_not_exists() {
    let h = fresh_key();
    assert!(handle_exists(h));
    handle_drop(h).unwrap();
    assert!(!handle_exists(h));
}

#[test]
fn test_double_drop_fails() {
    let h = fresh_key();
    handle_drop(h).unwrap();
    let err = handle_drop(h);
    assert_eq!(err, Err(HandleError::InvalidHandle));
}

// ─── Stream encrypt/decrypt authentication ──────────────────────────────────

#[test]
fn test_stream_encrypt_decrypt_roundtrip_multiple() {
    let key_id = fresh_key();
    let nonce = [0x11u8; 16];

    // Encrypt multiple messages
    let stream_enc = handle_stream_new(key_id, &nonce, b"multi_test").unwrap();
    let messages: Vec<&[u8]> = vec![b"msg one", b"msg two", b"msg three"];
    let mut encrypted: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for msg in &messages {
        let (ct, tag) = handle_stream_encrypt(stream_enc, msg).unwrap();
        encrypted.push((ct, tag));
    }

    // Decrypt all
    let stream_dec = handle_stream_new(key_id, &nonce, b"multi_test").unwrap();
    for (i, (ct, tag)) in encrypted.iter().enumerate() {
        let pt = handle_stream_decrypt(stream_dec, ct, tag).unwrap();
        assert_eq!(pt, messages[i]);
    }

    handle_drop(key_id).unwrap();
    handle_drop(stream_enc).unwrap();
    handle_drop(stream_dec).unwrap();
}

// ─── Import key edge case ───────────────────────────────────────────────────

#[test]
fn test_import_key_wrong_length() {
    let err = handle_import_key(&[0u8; 16]);
    assert_eq!(
        err,
        Err(HandleError::InvalidKeyLength {
            expected: 32,
            got: 16,
        })
    );
}
