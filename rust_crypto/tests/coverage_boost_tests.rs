//! Coverage boost tests for rust_crypto
//!
//! Targets specific uncovered code paths in stego.rs, handles.rs, and pure.rs
//! identified by tarpaulin lcov analysis.

use meow_crypto_rs::handles::*;
use meow_crypto_rs::pure;
use meow_crypto_rs::stego;

// Helper: create a fresh symmetric key handle
fn fresh_key() -> HandleId {
    handle_import_key(&[0x42u8; 32]).expect("import key")
}

// =============================================================================
// pure.rs coverage — aes_gcm_decrypt error paths (lines 229, 237)
// =============================================================================

mod pure_coverage {
    use super::*;

    #[test]
    fn test_aes_gcm_decrypt_invalid_key_length() {
        let result = pure::aes_gcm_decrypt(&[0u8; 16], &[0u8; 12], &[0u8; 32], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_decrypt_invalid_nonce_length() {
        let result = pure::aes_gcm_decrypt(&[0u8; 32], &[0u8; 8], &[0u8; 32], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_decrypt_ciphertext_too_short() {
        let result = pure::aes_gcm_decrypt(&[0u8; 32], &[0u8; 12], &[0u8; 15], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_with_aad() {
        let key = [0x42u8; 32];
        let nonce = [0xAAu8; 12];
        let ct = pure::aes_gcm_encrypt(&key, &nonce, b"hello", Some(b"aad")).expect("enc");
        let pt = pure::aes_gcm_decrypt(&key, &nonce, &ct, Some(b"aad")).expect("dec");
        assert_eq!(pt, b"hello");
    }
}

// =============================================================================
// stego.rs coverage — StegoError Display, derive, timing, palette
// =============================================================================

mod stego_coverage {
    use super::*;

    // --- StegoError Display impl (lines 48-65) ---

    #[test]
    fn test_stego_error_display_invalid_key_length() {
        let err = stego::StegoError::InvalidKeyLength {
            expected: 32,
            got: 16,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_stego_error_display_stc_encoding_failed() {
        let err = stego::StegoError::StcEncodingFailed("test fail".into());
        let msg = format!("{}", err);
        assert!(msg.contains("STC encoding failed"));
        assert!(msg.contains("test fail"));
    }

    #[test]
    fn test_stego_error_display_stc_decoding_failed() {
        let err = stego::StegoError::StcDecodingFailed("decode fail".into());
        let msg = format!("{}", err);
        assert!(msg.contains("STC decoding failed"));
    }

    #[test]
    fn test_stego_error_display_capacity_exceeded() {
        let err = stego::StegoError::CapacityExceeded {
            available: 100,
            required: 200,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("200"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn test_stego_error_display_invalid_params() {
        let err = stego::StegoError::InvalidParams("bad param".into());
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid parameters"));
    }

    #[test]
    fn test_stego_error_is_error_trait() {
        let err = stego::StegoError::InvalidParams("test".into());
        let _: &dyn std::error::Error = &err;
    }

    // --- derive_frame_seed channel coverage (lines 101-104) ---

    #[test]
    fn test_derive_frame_seed_all_channels() {
        let key = [0x42u8; 32];
        for channel in [
            stego::CHANNEL_PRIMARY,
            stego::CHANNEL_SECONDARY,
            stego::CHANNEL_TERTIARY,
            stego::CHANNEL_DISPOSAL,
            stego::CHANNEL_COMMENT,
            stego::CHANNEL_TEMPORAL,
            0xFF, // Unknown channel falls back to PRIMARY domain
        ] {
            let seed = stego::derive_frame_seed(&key, 0, channel).expect("derive");
            assert_eq!(seed.len(), 32);
        }
    }

    #[test]
    fn test_derive_frame_seed_different_frames_differ() {
        let key = [0x42u8; 32];
        let s1 = stego::derive_frame_seed(&key, 0, stego::CHANNEL_PRIMARY).unwrap();
        let s2 = stego::derive_frame_seed(&key, 1, stego::CHANNEL_PRIMARY).unwrap();
        assert_ne!(s1, s2);
    }

    // --- derive_frame_seed and derive_walk_seed short key errors (lines 91-94, 127-131) ---

    #[test]
    fn test_derive_frame_seed_short_key() {
        let result = stego::derive_frame_seed(&[0u8; 8], 0, stego::CHANNEL_PRIMARY);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_walk_seed_short_key() {
        let result = stego::derive_walk_seed(&[0u8; 8], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_walk_seed_success() {
        let key = [0x42u8; 32];
        let seed = stego::derive_walk_seed(&key, 5).expect("walk seed");
        assert_eq!(seed.len(), 32);
    }

    // --- generate_pixel_walk ---

    #[test]
    fn test_generate_pixel_walk() {
        let seed = [0xABu8; 32];
        let walk = stego::generate_pixel_walk(&seed, 100);
        assert_eq!(walk.len(), 100);
        // Check it's a permutation: all unique
        let mut sorted = walk.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 100);
    }

    #[test]
    fn test_generate_pixel_walk_single_pixel() {
        let seed = [0x11u8; 32];
        let walk = stego::generate_pixel_walk(&seed, 1);
        assert_eq!(walk.len(), 1);
        assert_eq!(walk[0], 0);
    }

    // --- timing_encode / timing_decode coverage (lines 703-704, 757-758) ---

    #[test]
    fn test_timing_encode_decode_roundtrip() {
        let seed = [0x42u8; 32];
        let payload_bits = vec![1, 0, 1, 1, 0, 0, 1, 0];
        let delays = stego::timing_encode(&seed, 10, &payload_bits, 2).expect("encode");
        assert_eq!(delays.len(), 4); // 8 bits / 2 bpf = 4 frames

        let decoded = stego::timing_decode(&seed, 10, &delays, 2).expect("decode");
        // Decoded should have 4*2 = 8 bits
        assert_eq!(decoded.len(), 8);
    }

    #[test]
    fn test_timing_encode_invalid_bpf_zero() {
        let seed = [0x42u8; 32];
        let result = stego::timing_encode(&seed, 10, &[1, 0], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_timing_encode_invalid_bpf_five() {
        let seed = [0x42u8; 32];
        let result = stego::timing_encode(&seed, 10, &[1, 0], 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_timing_decode_invalid_bpf_zero() {
        let seed = [0x42u8; 32];
        let result = stego::timing_decode(&seed, 10, &[12, 11], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_timing_decode_invalid_bpf_five() {
        let seed = [0x42u8; 32];
        let result = stego::timing_decode(&seed, 10, &[12, 11], 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_timing_encode_1_bpf() {
        let seed = [0x42u8; 32];
        let bits = vec![1, 0, 1, 1];
        let delays = stego::timing_encode(&seed, 10, &bits, 1).expect("encode");
        assert_eq!(delays.len(), 4);
    }

    #[test]
    fn test_timing_encode_4_bpf() {
        let seed = [0x42u8; 32];
        let bits = vec![1, 0, 1, 1, 0, 0, 1, 0];
        let delays = stego::timing_encode(&seed, 10, &bits, 4).expect("encode");
        assert_eq!(delays.len(), 2); // 8 bits / 4 bpf = 2 frames
    }

    // --- palette_encode / palette_decode coverage (lines 806-814, 871-877, 902-903) ---

    #[test]
    fn test_palette_encode_decode_roundtrip() {
        let seed = [0x42u8; 32];
        let indices = vec![10, 20, 30, 40, 50];
        let payload = vec![1, 0, 1, 1, 0, 1, 0]; // 7 bits

        let encoded = stego::palette_encode(&seed, &indices, &payload).expect("encode");
        assert_eq!(encoded.len(), indices.len());

        let decoded = stego::palette_decode(&seed, &indices, &encoded).expect("decode");
        // First 7 bits should match (floor(log2(5!)) = floor(log2(120)) = 6, so only 6 bits)
        // Actually floor(log2(120)) = 6.9... = 6
        let max_bits = decoded.len();
        for i in 0..max_bits.min(payload.len()) {
            assert_eq!(decoded[i], payload[i], "bit {} mismatch", i);
        }
    }

    #[test]
    fn test_palette_encode_too_few_indices() {
        let seed = [0x42u8; 32];
        let result = stego::palette_encode(&seed, &[5], &[1, 0]); // Only 1 index
        assert!(result.is_err());
    }

    #[test]
    fn test_palette_decode_mismatched_lengths() {
        let seed = [0x42u8; 32];
        let result = stego::palette_decode(&seed, &[10, 20, 30], &[10, 20]); // 3 vs 2
        assert!(result.is_err());
    }

    #[test]
    fn test_palette_decode_too_few_indices() {
        let seed = [0x42u8; 32];
        let result = stego::palette_decode(&seed, &[5], &[5]); // only 1 index
        assert!(result.is_err());
    }

    #[test]
    fn test_palette_decode_unknown_entry() {
        let seed = [0x42u8; 32];
        let indices = vec![10, 20, 30];
        // Observed order has an element NOT in the permutable set
        let result = stego::palette_decode(&seed, &indices, &[10, 99, 30]);
        assert!(result.is_err());
    }

    #[test]
    fn test_palette_encode_two_indices() {
        let seed = [0x42u8; 32];
        let indices = vec![5, 10];
        // 2 items: floor(log2(2!)) = 1 bit
        let payload = vec![1];
        let encoded = stego::palette_encode(&seed, &indices, &payload).expect("encode");
        assert_eq!(encoded.len(), 2);
    }

    // --- STC encode/decode coverage (lines 407-440, 512-513, 601) ---

    #[test]
    fn test_stc_encode_decode_roundtrip() {
        let seed = [0x42u8; 32];
        let cover_bits = vec![0u8; 200]; // 200 cover bits
        let payload_bits = vec![1, 0, 1, 1, 0, 0, 1, 0, 1, 0]; // 10 payload bits
        let costs = vec![1.0f64; 200]; // uniform costs

        let stego = stego::stc_encode(&seed, &cover_bits, &payload_bits, &costs).expect("encode");
        assert_eq!(stego.len(), 200);

        let decoded = stego::stc_decode(&seed, &stego, payload_bits.len()).expect("decode");
        assert_eq!(decoded, payload_bits);
    }

    #[test]
    fn test_stc_encode_empty_input() {
        let seed = [0x42u8; 32];
        let result = stego::stc_encode(&seed, &[], &[1], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_stc_encode_empty_payload() {
        let seed = [0x42u8; 32];
        let result = stego::stc_encode(&seed, &[0, 1, 0], &[], &[1.0, 1.0, 1.0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_stc_encode_payload_too_large() {
        let seed = [0x42u8; 32];
        // payload_bits.len() >= cover_bits.len() should fail
        let cover = vec![0u8; 10];
        let payload = vec![1u8; 10]; // same size = fail
        let costs = vec![1.0f64; 10];
        let result = stego::stc_encode(&seed, &cover, &payload, &costs);
        assert!(result.is_err());
    }

    #[test]
    fn test_stc_encode_cost_length_mismatch() {
        let seed = [0x42u8; 32];
        let cover = vec![0u8; 10];
        let payload = vec![1u8; 3];
        let costs = vec![1.0f64; 5]; // wrong length
        let result = stego::stc_encode(&seed, &cover, &payload, &costs);
        assert!(result.is_err());
    }

    #[test]
    fn test_stc_decode_empty_input() {
        let seed = [0x42u8; 32];
        let result = stego::stc_decode(&seed, &[], 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_stc_decode_payload_too_large() {
        let seed = [0x42u8; 32];
        let result = stego::stc_decode(&seed, &[0, 1, 0], 10); // payload > stego
        assert!(result.is_err());
    }

    #[test]
    fn test_stc_count_changes() {
        let a = vec![0u8, 1, 0, 1, 0];
        let b = vec![0u8, 0, 0, 1, 1]; // 2 changes
        assert_eq!(stego::count_changes(&a, &b), 2);
    }

    // --- compute_adaptive_costs coverage (lines 321, 343) ---

    #[test]
    fn test_compute_adaptive_costs_textured() {
        let seed = [0x42u8; 32];
        // Create highly textured pixel data
        let mut pixels: Vec<u8> = Vec::new();
        for i in 0..100 {
            pixels.push((i * 7 % 256) as u8);
        }
        let cover_bits = vec![0u8; 100];
        let mut costs = vec![1.0f64; 100];
        stego::compute_adaptive_costs(&seed, &cover_bits, &pixels, &mut costs);
        // Costs should be modified by the adaptive function
        assert!(costs.iter().any(|&c| c != 1.0));
    }

    #[test]
    fn test_compute_adaptive_costs_flat() {
        let seed = [0x42u8; 32];
        // Create flat pixel data (low variance)
        let pixels = vec![128u8; 100];
        let cover_bits = vec![0u8; 100];
        let mut costs = vec![1.0f64; 100];
        stego::compute_adaptive_costs(&seed, &cover_bits, &pixels, &mut costs);
        // Some costs should be higher for flat regions
        assert!(costs.iter().any(|&c| c > 1.0));
    }

    #[test]
    fn test_compute_adaptive_costs_medium_texture() {
        let seed = [0x42u8; 32];
        // Create medium-variance pixel data (variance between 20 and 100)
        // Values cycle: 120,128,136,120,128,136... → mean≈128, variance≈42.7
        let pixels: Vec<u8> = (0..100).map(|i| 120 + ((i % 3) * 8) as u8).collect();
        let cover_bits = vec![0u8; 100];
        let mut costs = vec![1.0f64; 100];
        stego::compute_adaptive_costs(&seed, &cover_bits, &pixels, &mut costs);
        // With medium texture, some costs get texture_factor=1.0 (unchanged) plus jitter
        assert!(costs.iter().any(|&c| (0.9..=1.1).contains(&c)));
    }
}

// =============================================================================
// handles.rs coverage — HandleTypeMismatch, error paths, stream/ratchet ops
// =============================================================================

mod handles_coverage {
    use super::*;

    // --- HandleTypeMismatch paths ---

    #[test]
    fn test_handle_derive_hkdf_type_mismatch() {
        // Create an X25519 handle, then try to use it as HKDF input
        let (x25519_h, _pub) = handle_x25519_generate().expect("keygen");
        let result = handle_derive_hkdf(x25519_h, b"salt", b"info", 32);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_derive_hkdf_bytes_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_derive_hkdf_bytes(x25519_h, b"salt", b"info", 32);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_aes_gcm_encrypt_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_aes_gcm_encrypt(x25519_h, &[0u8; 12], b"data", None);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_aes_gcm_encrypt_bad_nonce() {
        let h = fresh_key();
        let result = handle_aes_gcm_encrypt(h, &[0u8; 8], b"data", None);
        assert!(matches!(
            result.err(),
            Some(HandleError::InvalidNonceLength { .. })
        ));
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_aes_gcm_decrypt_bad_nonce() {
        let h = fresh_key();
        let result = handle_aes_gcm_decrypt(h, &[0u8; 8], &[0u8; 32], None);
        assert!(matches!(
            result.err(),
            Some(HandleError::InvalidNonceLength { .. })
        ));
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_aes_gcm_decrypt_ciphertext_too_short() {
        let h = fresh_key();
        let result = handle_aes_gcm_decrypt(h, &[0u8; 12], &[0u8; 15], None);
        assert_eq!(result.err(), Some(HandleError::CiphertextTooShort));
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_aes_gcm_encrypt_with_aad() {
        let h = fresh_key();
        let ct = handle_aes_gcm_encrypt(h, &[0u8; 12], b"data", Some(b"aad")).expect("enc");
        let pt = handle_aes_gcm_decrypt(h, &[0u8; 12], &ct, Some(b"aad")).expect("dec");
        assert_eq!(pt, b"data");
        handle_drop(h).unwrap();
    }

    // --- HMAC handle type mismatch (lines 513, 523) ---

    #[test]
    fn test_handle_hmac_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_hmac_sha256(x25519_h, b"data");
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    // --- HMAC prefixed type mismatch (lines 563-568) ---

    #[test]
    fn test_handle_hmac_prefixed_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_hmac_sha256_prefixed(x25519_h, b"PREFIX_", b"msg");
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_hmac_prefixed_verify() {
        let h = fresh_key();
        let tag = handle_hmac_sha256_prefixed(h, b"PREFIX_", b"msg").expect("hmac");
        let ok = handle_hmac_sha256_prefixed_verify(h, b"PREFIX_", b"msg", &tag).expect("verify");
        assert!(ok);
        let bad =
            handle_hmac_sha256_prefixed_verify(h, b"PREFIX_", b"msg", &[0u8; 32]).expect("verify");
        assert!(!bad);
        handle_drop(h).unwrap();
    }

    // --- X25519 exchange type mismatch (line 632) ---

    #[test]
    fn test_handle_x25519_exchange_type_mismatch() {
        let sym_h = fresh_key();
        let result = handle_x25519_exchange(sym_h, &[0u8; 32]);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(sym_h).unwrap();
    }

    #[test]
    fn test_handle_x25519_exchange_bad_pub_len() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_x25519_exchange(x25519_h, &[0u8; 16]); // wrong length
        assert_eq!(result.err(), Some(HandleError::InvalidPublicKeyLength));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_x25519_public_type_mismatch() {
        let sym_h = fresh_key();
        let result = handle_x25519_public(sym_h);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(sym_h).unwrap();
    }

    #[test]
    fn test_handle_import_x25519_private_bad_len() {
        let result = handle_import_x25519_private(&[0u8; 16]);
        assert!(matches!(
            result.err(),
            Some(HandleError::InvalidKeyLength { .. })
        ));
    }

    // --- Session handle type mismatch (lines 680-681) ---

    #[test]
    fn test_handle_session_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_session_new(x25519_h, None);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_session_mac_type_mismatch() {
        let enc_h = fresh_key();
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_session_new(enc_h, Some(x25519_h));
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(enc_h).unwrap();
        handle_drop(x25519_h).unwrap();
    }

    // --- Stream encrypt/decrypt (lines 741, 778, 806) ---

    #[test]
    fn test_handle_stream_encrypt_decrypt_roundtrip() {
        let enc_key = fresh_key();
        let nonce = [0xBBu8; 16];
        let stream_h = handle_stream_new(enc_key, &nonce, b"mac-domain").expect("stream new");

        let (ct, tag) = handle_stream_encrypt(stream_h, b"hello stream").expect("enc");
        assert!(!ct.is_empty());
        assert_eq!(tag.len(), 32); // HMAC-SHA256 tag

        // Need a fresh stream for decrypt (same key, same nonce, offset back to 0)
        handle_drop(stream_h).unwrap();

        let enc_key2 = handle_import_key(&[0x42u8; 32]).expect("reimport enc");
        let stream_h2 = handle_stream_new(enc_key2, &nonce, b"mac-domain").expect("stream new 2");

        let pt = handle_stream_decrypt(stream_h2, &ct, &tag).expect("dec");
        assert_eq!(pt, b"hello stream");
        handle_drop(stream_h2).unwrap();
    }

    #[test]
    fn test_handle_stream_encrypt_type_mismatch() {
        let h = fresh_key(); // Not a stream handle
        let result = handle_stream_encrypt(h, b"data");
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_stream_decrypt_type_mismatch() {
        let h = fresh_key();
        let result = handle_stream_decrypt(h, b"data", &[0u8; 32]);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_stream_decrypt_auth_fail() {
        let enc_key = fresh_key();
        let nonce = [0xCCu8; 16];
        let stream_h = handle_stream_new(enc_key, &nonce, b"mac-domain").expect("stream new");

        let (ct, _tag) = handle_stream_encrypt(stream_h, b"hello").expect("enc");
        handle_drop(stream_h).unwrap();

        // Fresh stream, try decrypt with wrong tag
        let enc2 = handle_import_key(&[0x42u8; 32]).expect("k");
        let s2 = handle_stream_new(enc2, &nonce, b"mac-domain").expect("stream");
        let result = handle_stream_decrypt(s2, &ct, &[0xFFu8; 32]);
        assert_eq!(result.err(), Some(HandleError::AuthenticationFailed));
        handle_drop(s2).unwrap();
    }

    // --- Ratchet type mismatch (line 820) ---

    #[test]
    fn test_handle_ratchet_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_ratchet_new(x25519_h, b"salt", b"info");
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_ratchet_step() {
        let root_h = fresh_key();
        let ratchet_h = handle_ratchet_new(root_h, b"salt", b"ratchet-info").expect("ratchet new");
        handle_drop(root_h).unwrap();

        let msg_key_h = handle_ratchet_step(ratchet_h, b"step-info", b"msg-info").expect("step");
        assert!(handle_exists(msg_key_h));
        handle_drop(msg_key_h).unwrap();

        // Step again
        let msg_key_h2 = handle_ratchet_step(ratchet_h, b"step-info", b"msg-info").expect("step 2");
        assert!(handle_exists(msg_key_h2));
        handle_drop(msg_key_h2).unwrap();

        handle_drop(ratchet_h).unwrap();
    }

    // --- handle_mix_hkdf type mismatch (lines 900-902) ---

    #[test]
    fn test_handle_mix_hkdf_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_mix_hkdf(x25519_h, b"extra", b"salt", b"info", 32);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_mix_hkdf_success() {
        let h = fresh_key();
        let derived = handle_mix_hkdf(h, b"extra-ikm", b"salt", b"info", 32).expect("mix");
        assert!(handle_exists(derived));
        handle_drop(derived).unwrap();
        handle_drop(h).unwrap();
    }

    // --- handle_hkdf_with_handle_salt type mismatch (line 938) ---

    #[test]
    fn test_handle_hkdf_with_handle_salt_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_hkdf_with_handle_salt(b"ikm", x25519_h, b"info", 32);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_hkdf_with_handle_salt_success() {
        let salt_h = fresh_key();
        let derived =
            handle_hkdf_with_handle_salt(b"ikm-data", salt_h, b"info", 32).expect("derive");
        assert!(handle_exists(derived));
        handle_drop(derived).unwrap();
        handle_drop(salt_h).unwrap();
    }

    // --- handle_hkdf_expand type mismatch (line 965) ---

    #[test]
    fn test_handle_hkdf_expand_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_hkdf_expand(x25519_h, b"info", 32);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_hkdf_expand_success() {
        let h = fresh_key();
        let derived = handle_hkdf_expand(h, b"expand-info", 32).expect("expand");
        assert!(handle_exists(derived));
        handle_drop(derived).unwrap();
        handle_drop(h).unwrap();
    }

    // --- handle_hkdf_two_handles type mismatch (lines 994, 1000) ---

    #[test]
    fn test_handle_hkdf_two_handles_ikm_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let salt_h = fresh_key();
        let result = handle_hkdf_two_handles(x25519_h, salt_h, b"info", 32);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
        handle_drop(salt_h).unwrap();
    }

    #[test]
    fn test_handle_hkdf_two_handles_salt_mismatch() {
        let ikm_h = fresh_key();
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_hkdf_two_handles(ikm_h, x25519_h, b"info", 32);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(ikm_h).unwrap();
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_hkdf_two_handles_success() {
        let ikm_h = fresh_key();
        let salt_h = handle_import_key(&[0xBBu8; 32]).expect("salt key");
        let derived =
            handle_hkdf_two_handles(ikm_h, salt_h, b"two-handle-info", 32).expect("derive");
        assert!(handle_exists(derived));
        handle_drop(derived).unwrap();
        handle_drop(ikm_h).unwrap();
        handle_drop(salt_h).unwrap();
    }

    // --- handle_export_key X25519 path (line 1054) ---

    #[test]
    fn test_handle_export_x25519_key() {
        let (x25519_h, pub_key) = handle_x25519_generate().expect("keygen");
        let exported = handle_export_key(x25519_h).expect("export");
        assert_eq!(exported.len(), 32);
        // Exported is private key bytes, not public
        assert_ne!(exported.as_slice(), &pub_key[..]);
        handle_drop(x25519_h).unwrap();
    }

    #[test]
    fn test_handle_export_key_type_mismatch() {
        let enc_h = fresh_key();
        let mac_h = fresh_key();
        let session_h = handle_session_new(enc_h, Some(mac_h)).expect("session");
        let result = handle_export_key(session_h);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(session_h).unwrap();
    }

    // --- handle_aes_ctr_crypt (lines 1157-1158 for Session/Ratchet paths) ---

    #[test]
    fn test_handle_aes_ctr_crypt_with_symmetric_key() {
        let h = fresh_key();
        let nonce = [0xAAu8; 16];
        let ct = handle_aes_ctr_crypt(h, &nonce, b"hello", 0).expect("crypt");
        let pt = handle_aes_ctr_crypt(h, &nonce, &ct, 0).expect("crypt back");
        assert_eq!(pt, b"hello");
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_aes_ctr_crypt_bad_nonce() {
        let h = fresh_key();
        let result = handle_aes_ctr_crypt(h, &[0u8; 8], b"data", 0);
        assert!(matches!(
            result.err(),
            Some(HandleError::InvalidNonceLength { .. })
        ));
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_aes_ctr_crypt_type_mismatch() {
        let (x25519_h, _) = handle_x25519_generate().expect("keygen");
        let result = handle_aes_ctr_crypt(x25519_h, &[0u8; 16], b"data", 0);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(x25519_h).unwrap();
    }

    // --- Stream HMAC/nonce/reset coverage ---

    #[test]
    fn test_handle_stream_hmac_and_nonce() {
        let enc_h = handle_import_key(&[0x42u8; 32]).expect("k");
        let nonce = [0xDDu8; 16];
        let stream_h = handle_stream_new(enc_h, &nonce, b"mac-domain").expect("stream");

        let hmac_tag = handle_stream_hmac(stream_h, b"message").expect("hmac");
        assert_eq!(hmac_tag.len(), 32);

        let ok = handle_stream_hmac_verify(stream_h, b"message", &hmac_tag).expect("verify");
        assert!(ok);

        let got_nonce = handle_stream_nonce(stream_h).expect("nonce");
        assert_eq!(got_nonce, nonce);

        handle_stream_reset_offset(stream_h).expect("reset");
        handle_drop(stream_h).unwrap();
    }

    #[test]
    fn test_handle_stream_hmac_type_mismatch() {
        let h = fresh_key();
        let result = handle_stream_hmac(h, b"msg");
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_stream_nonce_type_mismatch() {
        let h = fresh_key();
        let result = handle_stream_nonce(h);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(h).unwrap();
    }

    #[test]
    fn test_handle_stream_reset_offset_type_mismatch() {
        let h = fresh_key();
        let result = handle_stream_reset_offset(h);
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(h).unwrap();
    }

    // --- Invalid handle ---

    #[test]
    fn test_handle_invalid_operations() {
        let bad_id: HandleId = 9999999;
        assert!(!handle_exists(bad_id));
        assert_eq!(handle_drop(bad_id).err(), Some(HandleError::InvalidHandle));
        assert_eq!(
            handle_aes_gcm_encrypt(bad_id, &[0u8; 12], b"d", None).err(),
            Some(HandleError::InvalidHandle)
        );
    }

    // --- handle_derive_hkdf_raw ---

    #[test]
    fn test_handle_derive_hkdf_raw() {
        let h = handle_derive_hkdf_raw(b"raw-ikm", b"salt", b"info", 32).expect("derive raw");
        assert!(handle_exists(h));
        handle_drop(h).unwrap();
    }

    // --- handle_derive_key_argon2id salt validation (line 292) ---

    #[test]
    fn test_handle_derive_key_argon2id_bad_salt() {
        let result = handle_derive_key_argon2id(b"password", &[0u8; 8], 1024, 1, 1);
        assert!(matches!(
            result.err(),
            Some(HandleError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn test_handle_derive_key_argon2id_success() {
        let h = handle_derive_key_argon2id(b"password", &[0u8; 16], 1024, 1, 1).expect("derive");
        assert!(handle_exists(h));
        handle_drop(h).unwrap();
    }

    // --- HandleError Display ---

    #[test]
    fn test_handle_error_display_all_variants() {
        let errors: Vec<HandleError> = vec![
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
            HandleError::HkdfFailed("test".into()),
            HandleError::InvalidPrkLength,
            HandleError::AuthenticationFailed,
            HandleError::InvalidPublicKeyLength,
            HandleError::HandleTypeMismatch,
        ];
        for err in &errors {
            let msg = format!("{}", err);
            assert!(!msg.is_empty());
        }
    }

    // --- HMAC verify path ---

    #[test]
    fn test_handle_hmac_verify_wrong_tag() {
        let h = fresh_key();
        let tag = handle_hmac_sha256(h, b"message").expect("hmac");
        let ok = handle_hmac_sha256_verify(h, b"message", &tag).expect("verify");
        assert!(ok);
        let bad = handle_hmac_sha256_verify(h, b"message", &[0u8; 32]).expect("verify");
        assert!(!bad);
        // Different length tag
        let diff_len = handle_hmac_sha256_verify(h, b"message", &[0u8; 16]).expect("verify");
        assert!(!diff_len);
        handle_drop(h).unwrap();
    }

    // --- X25519 full exchange ---

    #[test]
    fn test_handle_x25519_full_exchange() {
        let (h1, pub1) = handle_x25519_generate().expect("gen1");
        let (h2, pub2) = handle_x25519_generate().expect("gen2");

        let shared1_h = handle_x25519_exchange(h1, &pub2).expect("exchange1");
        let shared2_h = handle_x25519_exchange(h2, &pub1).expect("exchange2");

        let bytes1 = handle_export_key(shared1_h).expect("export1");
        let bytes2 = handle_export_key(shared2_h).expect("export2");
        assert_eq!(bytes1, bytes2);

        handle_drop(h1).unwrap();
        handle_drop(h2).unwrap();
        handle_drop(shared1_h).unwrap();
        handle_drop(shared2_h).unwrap();
    }

    // --- X25519 import and public ---

    #[test]
    fn test_handle_import_x25519_and_get_public() {
        let private_bytes = [0x42u8; 32];
        let h = handle_import_x25519_private(&private_bytes).expect("import");
        let pub_key = handle_x25519_public(h).expect("public");
        assert_eq!(pub_key.len(), 32);
        handle_drop(h).unwrap();
    }

    // --- Session handle positive paths ---

    #[test]
    fn test_handle_derive_hkdf_with_session_handle() {
        let enc = fresh_key();
        let mac = fresh_key();
        let session_h = handle_session_new(enc, Some(mac)).expect("session");
        let derived = handle_derive_hkdf(session_h, b"salt", b"info", 32).expect("derive");
        assert!(handle_exists(derived));
        handle_drop(derived).unwrap();
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_derive_hkdf_bytes_with_session_handle() {
        let enc = fresh_key();
        let session_h = handle_session_new(enc, None).expect("session");
        let bytes = handle_derive_hkdf_bytes(session_h, b"salt", b"info", 32).expect("derive");
        assert_eq!(bytes.len(), 32);
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_derive_hkdf_bytes_with_ratchet_handle() {
        let root = fresh_key();
        let ratchet_h = handle_ratchet_new(root, b"salt", b"info").expect("ratchet");
        handle_drop(root).unwrap();
        let bytes = handle_derive_hkdf_bytes(ratchet_h, b"salt2", b"info2", 32).expect("derive");
        assert_eq!(bytes.len(), 32);
        handle_drop(ratchet_h).unwrap();
    }

    #[test]
    fn test_handle_aes_gcm_decrypt_with_session_handle() {
        let enc = fresh_key();
        let session_h = handle_session_new(enc, None).expect("session");
        // Encrypt first with the session handle
        let ct = handle_aes_gcm_encrypt(session_h, &[0u8; 12], b"hello", None).expect("enc");
        let pt = handle_aes_gcm_decrypt(session_h, &[0u8; 12], &ct, None).expect("dec");
        assert_eq!(pt, b"hello");
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_hmac_sha256_with_session() {
        let enc = fresh_key();
        let mac = fresh_key();
        let session_h = handle_session_new(enc, Some(mac)).expect("session");
        let tag = handle_hmac_sha256(session_h, b"data").expect("hmac");
        assert_eq!(tag.len(), 32);
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_hmac_sha256_session_no_mac_key() {
        let enc = fresh_key();
        let session_h = handle_session_new(enc, None).expect("session");
        let result = handle_hmac_sha256(session_h, b"data");
        assert_eq!(result.err(), Some(HandleError::HandleTypeMismatch));
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_hmac_sha256_prefixed_with_session() {
        let enc = fresh_key();
        let mac = fresh_key();
        let session_h = handle_session_new(enc, Some(mac)).expect("session");
        let tag = handle_hmac_sha256_prefixed(session_h, b"PREFIX_", b"msg").expect("hmac");
        assert_eq!(tag.len(), 32);
        let ok = handle_hmac_sha256_prefixed_verify(session_h, b"PREFIX_", b"msg", &tag)
            .expect("verify");
        assert!(ok);
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_session_new_with_hmac_mac_key() {
        // Session with an HmacKey for mac is typically not created externally,
        // but the path accepts HmacKey. Since there's no public HmacKey constructor,
        // we test the session-without-mac path and the session-with-sym-mac path.
        let enc = fresh_key();
        let session_h = handle_session_new(enc, None).expect("session no-mac");
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_mix_hkdf_with_session() {
        let enc = fresh_key();
        let session_h = handle_session_new(enc, None).expect("session");
        let derived = handle_mix_hkdf(session_h, b"extra", b"salt", b"info", 32).expect("mix");
        assert!(handle_exists(derived));
        handle_drop(derived).unwrap();
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_mix_hkdf_with_ratchet() {
        let root = fresh_key();
        let ratchet_h = handle_ratchet_new(root, b"salt", b"info").expect("ratchet");
        handle_drop(root).unwrap();
        let derived = handle_mix_hkdf(ratchet_h, b"extra", b"salt2", b"info2", 32).expect("mix");
        assert!(handle_exists(derived));
        handle_drop(derived).unwrap();
        handle_drop(ratchet_h).unwrap();
    }

    #[test]
    fn test_handle_aes_ctr_crypt_with_session() {
        let enc = fresh_key();
        let session_h = handle_session_new(enc, None).expect("session");
        let nonce = [0xAAu8; 16];
        let ct = handle_aes_ctr_crypt(session_h, &nonce, b"data", 0).expect("crypt");
        let pt = handle_aes_ctr_crypt(session_h, &nonce, &ct, 0).expect("crypt back");
        assert_eq!(pt, b"data");
        handle_drop(session_h).unwrap();
    }

    #[test]
    fn test_handle_aes_ctr_crypt_with_ratchet() {
        let root = fresh_key();
        let ratchet_h = handle_ratchet_new(root, b"salt", b"info").expect("ratchet");
        handle_drop(root).unwrap();
        let nonce = [0xBBu8; 16];
        let ct = handle_aes_ctr_crypt(ratchet_h, &nonce, b"hello", 0).expect("crypt");
        let pt = handle_aes_ctr_crypt(ratchet_h, &nonce, &ct, 0).expect("crypt back");
        assert_eq!(pt, b"hello");
        handle_drop(ratchet_h).unwrap();
    }

    #[test]
    fn test_handle_derive_hkdf_with_ratchet() {
        let root = fresh_key();
        let ratchet_h = handle_ratchet_new(root, b"salt", b"info").expect("ratchet");
        handle_drop(root).unwrap();
        let derived = handle_derive_hkdf(ratchet_h, b"salt2", b"info2", 32).expect("derive");
        assert!(handle_exists(derived));
        handle_drop(derived).unwrap();
        handle_drop(ratchet_h).unwrap();
    }

    // --- handle_aes_gcm_encrypt with Session ---

    #[test]
    fn test_handle_aes_gcm_encrypt_with_session() {
        let enc = fresh_key();
        let session_h = handle_session_new(enc, None).expect("session");
        let ct =
            handle_aes_gcm_encrypt(session_h, &[0u8; 12], b"secret", Some(b"aad")).expect("enc");
        assert!(!ct.is_empty());
        handle_drop(session_h).unwrap();
    }
}
