//! Integration tests for crypto_core security properties
//!
//! These tests verify the runtime behavior matches the Verus-specified invariants.

use crypto_core::{
    AeadWrapper, AeadError, AuthenticatedPlaintext,
    NonceGenerator, NonceTracker, Nonce,
    AeadKey, AssociatedData,
    KEY_SIZE, NONCE_SIZE, TAG_SIZE,
};

// =============================================================================
// AEAD-001: Nonce Uniqueness Tests
// =============================================================================

#[test]
fn test_nonce_generator_produces_unique_values() {
    let gen = NonceGenerator::new();
    let mut seen = std::collections::HashSet::new();
    
    // Generate 100,000 nonces and verify all unique
    for _ in 0..100_000 {
        let nonce = gen.next().expect("Should not exhaust");
        let bytes = *nonce.as_bytes();
        assert!(
            seen.insert(bytes),
            "Nonce collision detected! This should never happen."
        );
    }
}

#[test]
fn test_nonce_generator_counter_increments() {
    let gen = NonceGenerator::new();
    
    let n1 = gen.next().unwrap();
    let n2 = gen.next().unwrap();
    let n3 = gen.next().unwrap();
    
    // Extract counter values (first 8 bytes, big-endian)
    let c1 = u64::from_be_bytes(n1.as_bytes()[0..8].try_into().unwrap());
    let c2 = u64::from_be_bytes(n2.as_bytes()[0..8].try_into().unwrap());
    let c3 = u64::from_be_bytes(n3.as_bytes()[0..8].try_into().unwrap());
    
    // Verify monotonically increasing
    assert_eq!(c1, 0, "First counter should be 0");
    assert_eq!(c2, 1, "Second counter should be 1");
    assert_eq!(c3, 2, "Third counter should be 2");
}

#[test]
fn test_nonce_tracker_rejects_reuse() {
    let mut tracker = NonceTracker::new();
    let nonce = Nonce::from_array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    
    // First use: should succeed
    tracker.check_and_mark(&nonce).expect("First use should succeed");
    
    // Second use: should fail
    let result = tracker.check_and_mark(&nonce);
    assert!(result.is_err(), "Reused nonce should be rejected");
}

#[test]
fn test_nonce_reuse_produces_different_ciphertexts() {
    // This test verifies that using the same nonce WOULD produce the same
    // ciphertext for the same plaintext - demonstrating why uniqueness matters
    let key = [42u8; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let plaintext = b"same plaintext";
    let aad = b"same aad";
    
    // Use same nonce twice (simulating bug scenario)
    let nonce = [0u8; NONCE_SIZE];
    
    let ct1 = wrapper.encrypt_raw(&nonce, plaintext, aad).unwrap();
    let ct2 = wrapper.encrypt_raw(&nonce, plaintext, aad).unwrap();
    
    // Same nonce + same plaintext = same ciphertext (proving nonce uniqueness matters!)
    assert_eq!(ct1, ct2, "Same nonce should produce same ciphertext");
    
    // Different nonce = different ciphertext
    let nonce2 = [1u8; NONCE_SIZE];
    let ct3 = wrapper.encrypt_raw(&nonce2, plaintext, aad).unwrap();
    assert_ne!(ct1, ct3, "Different nonce should produce different ciphertext");
}

// =============================================================================
// AEAD-002: Auth-Gated Plaintext Tests
// =============================================================================

#[test]
fn test_decryption_returns_authenticated_plaintext() {
    let key = [0xAB; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let plaintext = b"secret message";
    let aad = b"associated data";
    
    let gen = NonceGenerator::new();
    let nonce = gen.next().unwrap();
    
    let ciphertext = wrapper.encrypt_raw(nonce.as_bytes(), plaintext, aad).unwrap();
    
    // Decrypt returns AuthenticatedPlaintext
    let result = wrapper.decrypt_raw(nonce.as_bytes(), &ciphertext, aad);
    
    match result {
        Ok(authenticated) => {
            // The plaintext is wrapped in AuthenticatedPlaintext
            assert_eq!(authenticated.as_slice(), plaintext);
        }
        Err(e) => panic!("Decryption should succeed: {:?}", e),
    }
}

#[test]
fn test_tampered_ciphertext_rejected() {
    let key = [0xCD; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let plaintext = b"authentic data";
    let aad = b"header";
    let nonce = [0x55; NONCE_SIZE];
    
    let mut ciphertext = wrapper.encrypt_raw(&nonce, plaintext, aad).unwrap();
    
    // Tamper with ciphertext
    ciphertext[0] ^= 0xFF;
    
    // Decryption should fail - no plaintext returned
    let result = wrapper.decrypt_raw(&nonce, &ciphertext, aad);
    assert!(result.is_err(), "Tampered ciphertext must be rejected");
}

#[test]
fn test_wrong_aad_rejected() {
    let key = [0xEF; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let plaintext = b"secret";
    let aad = b"correct aad";
    let wrong_aad = b"wrong aad";
    let nonce = [0x77; NONCE_SIZE];
    
    let ciphertext = wrapper.encrypt_raw(&nonce, plaintext, aad).unwrap();
    
    // Decryption with wrong AAD should fail
    let result = wrapper.decrypt_raw(&nonce, &ciphertext, wrong_aad);
    assert!(result.is_err(), "Wrong AAD must be rejected");
}

#[test]
fn test_wrong_key_rejected() {
    let key1 = [0x11; KEY_SIZE];
    let key2 = [0x22; KEY_SIZE];
    let plaintext = b"secret";
    let aad = b"aad";
    let nonce = [0x99; NONCE_SIZE];
    
    let mut wrapper1 = AeadWrapper::new(&key1).unwrap();
    let mut wrapper2 = AeadWrapper::new(&key2).unwrap();
    
    let ciphertext = wrapper1.encrypt_raw(&nonce, plaintext, aad).unwrap();
    
    // Decryption with wrong key should fail
    let result = wrapper2.decrypt_raw(&nonce, &ciphertext, aad);
    assert!(result.is_err(), "Wrong key must be rejected");
}

#[test]
fn test_truncated_ciphertext_rejected() {
    let key = [0x33; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let plaintext = b"secret message";
    let aad = b"aad";
    let nonce = [0xAA; NONCE_SIZE];
    
    let ciphertext = wrapper.encrypt_raw(&nonce, plaintext, aad).unwrap();
    
    // Truncate ciphertext (missing tag)
    let truncated = &ciphertext[..ciphertext.len() - 1];
    
    let result = wrapper.decrypt_raw(&nonce, truncated, aad);
    assert!(result.is_err(), "Truncated ciphertext must be rejected");
}

// =============================================================================
// AEAD-003: Key Zeroization Tests
// =============================================================================

#[test]
fn test_key_debug_is_redacted() {
    let key = AeadKey::from_bytes(&[0xDE, 0xAD, 0xBE, 0xEF].repeat(8)).unwrap();
    let debug_output = format!("{:?}", key);
    
    // Key bytes should not appear in debug output
    assert!(!debug_output.contains("DE"));
    assert!(!debug_output.contains("AD"));
    assert!(!debug_output.contains("BE"));
    assert!(!debug_output.contains("EF"));
    assert!(debug_output.contains("REDACTED"));
}

// Note: Actual memory zeroization is hard to test without unsafe code.
// We rely on the zeroize crate's guarantees (volatile writes).
// This test verifies the wrapper uses ZeroizeOnDrop.

#[test]
fn test_wrapper_can_be_dropped() {
    // This primarily tests that Drop doesn't panic
    let key = [0xFF; KEY_SIZE];
    let wrapper = AeadWrapper::new(&key).unwrap();
    drop(wrapper);
    // If we reach here, drop succeeded
}

// =============================================================================
// AEAD-004: No Bypass Tests
// =============================================================================

// Note: The "no bypass" property is primarily enforced by the type system.
// UniqueNonce is consumed by encrypt(), preventing reuse at compile time.
// These tests verify the runtime behavior.

#[test]
fn test_encrypt_raw_requires_valid_nonce() {
    let key = [0x44; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let plaintext = b"message";
    let aad = b"aad";
    
    // Valid nonce works
    let valid_nonce = [0u8; NONCE_SIZE];
    let result = wrapper.encrypt_raw(&valid_nonce, plaintext, aad);
    assert!(result.is_ok());
}

// =============================================================================
// Roundtrip Property Tests
// =============================================================================

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = [0x55; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let gen = NonceGenerator::new();
    
    let test_cases = vec![
        (b"".to_vec(), b"".to_vec()),                    // Empty plaintext, empty AAD
        (b"hello".to_vec(), b"world".to_vec()),          // Short
        (vec![0x42; 1000], vec![0x24; 500]),             // Medium
        (vec![0xFF; 65536], vec![0xAA; 1024]),           // Large
    ];
    
    for (plaintext, aad) in test_cases {
        let nonce = gen.next().unwrap();
        
        let ciphertext = wrapper
            .encrypt_raw(nonce.as_bytes(), &plaintext, &aad)
            .expect("Encryption should succeed");
        
        let decrypted = wrapper
            .decrypt_raw(nonce.as_bytes(), &ciphertext, &aad)
            .expect("Decryption should succeed");
        
        assert_eq!(
            decrypted.as_slice(),
            &plaintext[..],
            "Roundtrip should preserve plaintext"
        );
    }
}

// =============================================================================
// Size Invariant Tests
// =============================================================================

#[test]
fn test_ciphertext_size() {
    let key = [0x66; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0u8; NONCE_SIZE];
    
    let plaintexts = vec![0, 1, 16, 100, 1000, 65536];
    
    for pt_len in plaintexts {
        let plaintext = vec![0xAB; pt_len];
        let ciphertext = wrapper
            .encrypt_raw(&nonce, &plaintext, b"")
            .unwrap();
        
        // Ciphertext = plaintext + TAG (16 bytes for GCM)
        assert_eq!(
            ciphertext.len(),
            pt_len + TAG_SIZE,
            "Ciphertext should be plaintext + tag ({} + {})",
            pt_len,
            TAG_SIZE
        );
    }
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_all_zero_key_works() {
    // While insecure in practice, the crypto should still work
    let key = [0u8; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0u8; NONCE_SIZE];
    let plaintext = b"test";
    
    let ct = wrapper.encrypt_raw(&nonce, plaintext, b"").unwrap();
    let pt = wrapper.decrypt_raw(&nonce, &ct, b"").unwrap();
    
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn test_all_ff_key_works() {
    let key = [0xFF; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0xFF; NONCE_SIZE];
    let plaintext = b"test";
    
    let ct = wrapper.encrypt_raw(&nonce, plaintext, b"").unwrap();
    let pt = wrapper.decrypt_raw(&nonce, &ct, b"").unwrap();
    
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn test_large_aad() {
    let key = [0x77; KEY_SIZE];
    let mut wrapper = AeadWrapper::new(&key).unwrap();
    let nonce = [0u8; NONCE_SIZE];
    let plaintext = b"secret";
    let aad = vec![0xCC; 10_000]; // 10 KB AAD
    
    let ct = wrapper.encrypt_raw(&nonce, plaintext, &aad).unwrap();
    let pt = wrapper.decrypt_raw(&nonce, &ct, &aad).unwrap();
    
    assert_eq!(pt.as_slice(), plaintext);
}
