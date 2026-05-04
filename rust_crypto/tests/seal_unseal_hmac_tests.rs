//! Integration tests for the seal/unseal/hmac-to-handle primitives
//! added during the gemini #1 Rust-handle migration work.
//!
//! Lives under `rust_crypto/tests/` so it falls under the
//! `rust_crypto/tests/**` paths-ignore in `.github/codeql/codeql-config.yml`
//! — test fixtures here use deterministic 12-byte nonces and 32-byte
//! keys, which CodeQL's "Hard-coded cryptographic value" query would
//! otherwise flag in production-source `mod tests` blocks.

use meow_crypto_rs::handles::{
    handle_aes_gcm_encrypt, handle_drop, handle_exists, handle_hmac_sha256,
    handle_hmac_sha256_to_handle, handle_import_key, handle_seal_key, handle_unseal_key,
    HandleError,
};

#[test]
fn seal_unseal_roundtrip() {
    let payload = handle_import_key(&[0x77u8; 32]).unwrap();
    let kek = handle_import_key(&[0x88u8; 32]).unwrap();
    let nonce = [0x99u8; 12];
    let aad = b"meow_seal_aad_v1";

    let sealed = handle_seal_key(payload, kek, &nonce, Some(aad)).unwrap();
    // Ciphertext = 32 (key) + 16 (GCM tag).
    assert_eq!(sealed.len(), 48);

    let recovered = handle_unseal_key(&sealed, kek, &nonce, Some(aad)).unwrap();
    // Verify the recovered handle holds the same key (encrypt the same
    // plaintext with each and compare ciphertexts under a fixed nonce).
    let test_nonce = [0u8; 12];
    let ct_orig = handle_aes_gcm_encrypt(payload, &test_nonce, b"x", None).unwrap();
    let ct_recovered = handle_aes_gcm_encrypt(recovered, &test_nonce, b"x", None).unwrap();
    assert_eq!(ct_orig, ct_recovered);

    handle_drop(payload).unwrap();
    handle_drop(kek).unwrap();
    handle_drop(recovered).unwrap();
}

#[test]
fn seal_unseal_aad_mismatch() {
    let payload = handle_import_key(&[0x77u8; 32]).unwrap();
    let kek = handle_import_key(&[0x88u8; 32]).unwrap();
    let nonce = [0x99u8; 12];

    let sealed = handle_seal_key(payload, kek, &nonce, Some(b"aad-A")).unwrap();
    let err = handle_unseal_key(&sealed, kek, &nonce, Some(b"aad-B"));
    assert_eq!(err, Err(HandleError::DecryptionFailed));

    handle_drop(payload).unwrap();
    handle_drop(kek).unwrap();
}

#[test]
fn seal_unseal_wrong_kek() {
    let payload = handle_import_key(&[0x77u8; 32]).unwrap();
    let kek_a = handle_import_key(&[0x88u8; 32]).unwrap();
    let kek_b = handle_import_key(&[0xBBu8; 32]).unwrap();
    let nonce = [0x99u8; 12];

    let sealed = handle_seal_key(payload, kek_a, &nonce, None).unwrap();
    let err = handle_unseal_key(&sealed, kek_b, &nonce, None);
    assert_eq!(err, Err(HandleError::DecryptionFailed));

    handle_drop(payload).unwrap();
    handle_drop(kek_a).unwrap();
    handle_drop(kek_b).unwrap();
}

#[test]
fn seal_invalid_nonce_length() {
    let payload = handle_import_key(&[0x77u8; 32]).unwrap();
    let kek = handle_import_key(&[0x88u8; 32]).unwrap();
    let bad_nonce = [0u8; 11]; // wrong length
    let err = handle_seal_key(payload, kek, &bad_nonce, None);
    assert!(matches!(err, Err(HandleError::InvalidNonceLength { .. })));
    handle_drop(payload).unwrap();
    handle_drop(kek).unwrap();
}

#[test]
fn hmac_to_handle_matches_hmac_then_import() {
    // The handle-derived key must match what we'd get from
    // handle_hmac_sha256 → handle_import_key (just without the
    // round-trip via Python bytes).
    let kek = handle_import_key(&[0xAAu8; 32]).unwrap();
    let derived_h = handle_hmac_sha256_to_handle(kek, b"derive_me_v1").unwrap();
    assert!(handle_exists(derived_h));

    // Manual path
    let manual_tag = handle_hmac_sha256(kek, b"derive_me_v1").unwrap();
    let manual_h = handle_import_key(&manual_tag).unwrap();

    // Both should encrypt b"x" to the same ciphertext under fixed nonce.
    let nonce = [0u8; 12];
    let ct1 = handle_aes_gcm_encrypt(derived_h, &nonce, b"x", None).unwrap();
    let ct2 = handle_aes_gcm_encrypt(manual_h, &nonce, b"x", None).unwrap();
    assert_eq!(ct1, ct2);

    handle_drop(kek).unwrap();
    handle_drop(derived_h).unwrap();
    handle_drop(manual_h).unwrap();
}

#[test]
fn hmac_to_handle_different_messages_diverge() {
    let kek = handle_import_key(&[0xBBu8; 32]).unwrap();
    let h1 = handle_hmac_sha256_to_handle(kek, b"msg-A").unwrap();
    let h2 = handle_hmac_sha256_to_handle(kek, b"msg-B").unwrap();

    let nonce = [0u8; 12];
    let ct1 = handle_aes_gcm_encrypt(h1, &nonce, b"x", None).unwrap();
    let ct2 = handle_aes_gcm_encrypt(h2, &nonce, b"x", None).unwrap();
    assert_ne!(ct1, ct2);

    handle_drop(kek).unwrap();
    handle_drop(h1).unwrap();
    handle_drop(h2).unwrap();
}
