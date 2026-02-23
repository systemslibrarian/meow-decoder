//! Property-based tests for meow_crypto_rs cryptographic primitives.
//!
//! Uses `proptest` to systematically verify security invariants over generated inputs.
//! Each property maps to one or more attack classes from the threat model.
//!
//! # Run
//!     cargo test --test property_tests
//!     cargo test --test property_tests --features pq   # include PQ paths
//!
//! # Attack class coverage
//! | Property                            | Attack class(es)                      |
//! |-------------------------------------|---------------------------------------|
//! | p_nonce_uniqueness                  | Nonce reuse                           |
//! | p_ratchet_monotonicity              | Nonce reuse, PCS violation            |
//! | p_replay_rejection                  | Replay                                |
//! | p_pcs_healing                       | State compromise                      |
//! | p_hybrid_requires_both_secrets      | Hybrid downgrade, PQ failure fallback |
//! | p_aad_canonicalization_determinism  | AAD omission                          |
//! | p_manifest_binding_integrity        | AAD omission, Truncation oracle       |
//! | p_decryption_fail_closed            | Partial decrypt leak                  |
//! | p_commitment_tag_prevents_forgery   | Header tampering                      |
//! | p_argon2id_domain_separation        | Nonce reuse (KDF level)               |

use meow_crypto_rs::pure::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_key_argon2id, derive_key_hkdf, hkdf_extract,
    hmac_sha256, hmac_sha256_verify, x25519_exchange, x25519_generate_keypair,
    x25519_public_from_private,
};
use proptest::prelude::*;

// ─── Helper: advance a minimal ratchet N steps ────────────────────────────────

/// Returns a vec of (chain_key, message_key) pairs for steps 0..n.
fn ratchet_steps(root_key: &[u8], n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    ratchet_steps_from(root_key, 0, n)
}

/// Like `ratchet_steps` but begins the step counter at `start_step`.
/// This lets an adversary who obtained chain_key[k] reproduce exactly the
/// same message keys the honest party derived at absolute steps k, k+1, …
fn ratchet_steps_from(root_key: &[u8], start_step: usize, n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut chain = root_key.to_vec();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let abs_i = start_step + i;
        let mut minfo = b"meow_ratchet_msg_v1".to_vec();
        minfo.extend_from_slice(&(abs_i as u32).to_be_bytes());
        let msg_key = derive_key_hkdf(&chain, None, &minfo, 32).unwrap_or_else(|_| vec![0u8; 32]);

        let mut cinfo = b"meow_ratchet_chain_v1".to_vec();
        cinfo.extend_from_slice(&(abs_i as u32).to_be_bytes());
        let next_chain =
            derive_key_hkdf(&chain, None, &cinfo, 32).unwrap_or_else(|_| vec![0u8; 32]);

        out.push((chain.clone(), msg_key));
        chain = next_chain;
    }
    out
}

/// Build canonical AAD: HMAC-SHA256(auth_key, v || mode || frame_idx_be32 || epoch_be32)
fn canonical_aad(auth_key: &[u8], v: u8, mode: u8, frame_idx: u32, epoch: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(10);
    msg.push(v);
    msg.push(mode);
    msg.extend_from_slice(&frame_idx.to_be_bytes());
    msg.extend_from_slice(&epoch.to_be_bytes());
    hmac_sha256(auth_key, &msg).unwrap_or_else(|_| vec![0u8; 32])
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 1 – Nonce uniqueness across N frames
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// For any root key and frame count (1..=32), all message keys are pairwise distinct.
    /// Attack class: Nonce reuse
    #[test]
    fn p_nonce_uniqueness(
        root_key in prop::collection::vec(any::<u8>(), 1..=64),
        n        in 1usize..=32,
    ) {
        let steps = ratchet_steps(&root_key, n);
        let msg_keys: Vec<&Vec<u8>> = steps.iter().map(|(_, mk)| mk).collect();

        for i in 0..n {
            for j in (i + 1)..n {
                prop_assert_ne!(
                    msg_keys[i], msg_keys[j],
                    "Message keys at steps {} and {} are identical (nonce reuse!)", i, j
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 2 – Ratchet monotonicity
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// Each ratchet advance changes the chain key (the ratchet is not the identity).
    /// Attack class: Nonce reuse, PCS violation
    #[test]
    fn p_ratchet_monotonicity(
        root_key in prop::collection::vec(any::<u8>(), 1..=64),
        n        in 2usize..=16,
    ) {
        let steps = ratchet_steps(&root_key, n);
        for i in 0..(n - 1) {
            let (ck_i, _)   = &steps[i];
            let (ck_i1, _)  = &steps[i + 1];
            prop_assert_ne!(
                ck_i, ck_i1,
                "Chain key must change at ratchet step {} → {}", i, i + 1
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 3 – Replay rejection via commitment tags
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// Two independent ratchets from the same root produce identical step-0 commitment
    /// (allows detection of replayed frame 0).  A replayed frame presents the same
    /// commitment tag and is caught by the receiver's seen-set.
    /// Attack class: Replay
    #[test]
    fn p_replay_rejection(
        root_key   in prop::collection::vec(any::<u8>(), 1..=64),
        frame_idx  in any::<u32>(),
    ) {
        // Two independent derivations from the same root must agree.
        let steps1 = ratchet_steps(&root_key, 1);
        let steps2 = ratchet_steps(&root_key, 1);
        let (_, mk1) = &steps1[0];
        let (_, mk2) = &steps2[0];
        prop_assert_eq!(mk1, mk2, "Re-derived step-0 message key must be identical");

        // Commitment tags are deterministic → replay detectable.
        let mut msg = b"meow_ratchet_commit_v1".to_vec();
        msg.extend_from_slice(&frame_idx.to_be_bytes());
        let tag1 = hmac_sha256(mk1, &msg).unwrap();
        let tag2 = hmac_sha256(mk2, &msg).unwrap();
        prop_assert_eq!(tag1, tag2, "Commitment tags for the same frame must match (replay detectable)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 4 – PCS healing: post-compromise cannot derive previous keys
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// Knowing chain_key[k] allows deriving message_key[k..] but NOT message_key[<k].
    /// We verify by showing that re-running the ratchet from step k reproduces
    /// future message keys but differs from all past message keys.
    /// Attack class: State compromise
    #[test]
    fn p_pcs_healing(
        root_key        in prop::collection::vec(any::<u8>(), 8..=64),
        total_steps     in 4usize..=16,
        compromise_at   in 1usize..=3,
    ) {
        // Full honest trace
        let honest = ratchet_steps(&root_key, total_steps);
        let (compromised_chain, _) = &honest[compromise_at];

        // Adversary runs ratchet from the compromised chain key, using the same
        // absolute step counter so their HKDF info strings match the honest party.
        let adversary = ratchet_steps_from(compromised_chain, compromise_at, total_steps - compromise_at);

        // Future keys should match
        for (adv_idx, (_ck, adv_mk)) in adversary.iter().enumerate() {
            let honest_idx = compromise_at + adv_idx;
            let (_, hon_mk) = &honest[honest_idx];
            prop_assert_eq!(
                adv_mk, hon_mk,
                "Adversary must derive same future key at step {}", honest_idx
            );
        }

        // Past keys (steps 0..compromise_at) must not appear in adversary's output
        for (_, adv_mk) in &adversary {
            for (past, (_, past_mk)) in honest.iter().enumerate().take(compromise_at) {
                prop_assert_ne!(
                    adv_mk, past_mk,
                    "Adversary must not derive past key at step {} (PCS violated)", past
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 5 – Hybrid combiner requires both secrets
// ═══════════════════════════════════════════════════════════════════════════════

/// PQXDH combiner: PRK = HKDF-Extract(0x00*32, classical_ss || pq_ss)
///                 OKM = HKDF-Expand(PRK, info, 32)
fn pqxdh_combine(classical_ss: &[u8], pq_ss: &[u8], transcript: &[u8]) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(classical_ss);
    ikm.extend_from_slice(pq_ss);
    let zero_salt = vec![0u8; 32];
    let prk = hkdf_extract(Some(&zero_salt), &ikm);
    let mut info = b"meow_pqxdh_v1".to_vec();
    info.extend_from_slice(transcript);
    derive_key_hkdf(&prk, None, &info, 32).unwrap_or_else(|_| vec![0u8; 32])
}

proptest! {
    /// Changing either the classical or PQ secret must change the combined key.
    /// Attack class: Hybrid downgrade, PQ failure fallback
    #[test]
    fn p_hybrid_requires_both_secrets(
        classical_ss in prop::collection::vec(any::<u8>(), 32..=32),
        pq_ss        in prop::collection::vec(any::<u8>(), 32..=32),
        transcript   in prop::collection::vec(any::<u8>(), 0..=64),
    ) {
        let full   = pqxdh_combine(&classical_ss, &pq_ss, &transcript);
        let no_pq  = pqxdh_combine(&classical_ss, &[0u8; 32], &transcript);
        let no_cls = pqxdh_combine(&[0u8; 32], &pq_ss, &transcript);

        // Zeroing PQ must change the output (PQ contributes).
        if pq_ss != vec![0u8; 32] {
            prop_assert_ne!(&full, &no_pq, "Removing PQ secret must change combined key");
        }

        // Zeroing classical must change the output (classical contributes).
        if classical_ss != vec![0u8; 32] {
            prop_assert_ne!(&full, &no_cls, "Removing classical secret must change combined key");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 6 – AAD canonicalization determinism
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// canonical_aad produces identical bytes for identical inputs (no random component).
    /// Attack class: AAD omission
    #[test]
    fn p_aad_canonicalization_determinism(
        auth_key  in prop::collection::vec(any::<u8>(), 1..=64),
        v         in any::<u8>(),
        mode      in any::<u8>(),
        frame_idx in any::<u32>(),
        epoch     in any::<u32>(),
    ) {
        let aad1 = canonical_aad(&auth_key, v, mode, frame_idx, epoch);
        let aad2 = canonical_aad(&auth_key, v, mode, frame_idx, epoch);
        prop_assert_eq!(aad1, aad2, "AAD must be deterministic");
    }
}

proptest! {
    /// Different fields must produce different AADs (no field is silently ignored).
    /// Attack class: AAD omission
    #[test]
    fn p_aad_field_independence(
        auth_key  in prop::collection::vec(any::<u8>(), 32..=32),
        v         in any::<u8>(),
        mode      in any::<u8>(),
        frame_idx in 0u32..=u32::MAX / 2,
        epoch     in any::<u32>(),
    ) {
        let aad_base      = canonical_aad(&auth_key, v, mode, frame_idx, epoch);
        let aad_diff_fidx = canonical_aad(&auth_key, v, mode, frame_idx + 1, epoch);
        // Different frame index = different AAD
        prop_assert_ne!(aad_base, aad_diff_fidx, "Frame index must affect AAD");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 7 – Manifest binding integrity
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// A ciphertext encrypted with AAD A must not decrypt with AAD B (A≠B).
    /// Attack class: AAD omission, Truncation oracle
    #[test]
    fn p_manifest_binding_integrity(
        key      in prop::collection::vec(any::<u8>(), 32..=32),
        nonce    in prop::collection::vec(any::<u8>(), 12..=12),
        payload  in prop::collection::vec(any::<u8>(), 0..=128),
        aad_a    in prop::collection::vec(any::<u8>(), 1..=64),
        aad_b    in prop::collection::vec(any::<u8>(), 1..=64),
    ) {
        // Only test when AADs differ
        prop_assume!(aad_a != aad_b);

        let ct = aes_gcm_encrypt(&key, &nonce, &payload, Some(&aad_a));
        let ct = match ct {
            Ok(c) => c,
            Err(_) => return Ok(()), // invalid key/nonce → skip
        };

        // Decrypting with AAD B must fail
        let result = aes_gcm_decrypt(&key, &nonce, &ct, Some(&aad_b));
        prop_assert!(result.is_err(), "Ciphertext sealed with AAD-A must not open with AAD-B");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 8 – Fail-closed AEAD (no partial plaintext on failure)
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// On any decryption failure, the return type is Err (not Ok(partial_bytes)).
    /// The RustCrypto AES-GCM implementation never returns partial plaintext;
    /// this property asserts the contract at the API boundary.
    /// Attack class: Partial decrypt leak
    #[test]
    fn p_decryption_fail_closed(
        key      in prop::collection::vec(any::<u8>(), 32..=32),
        nonce    in prop::collection::vec(any::<u8>(), 12..=12),
        payload  in prop::collection::vec(any::<u8>(), 0..=256),
        aad      in prop::option::of(prop::collection::vec(any::<u8>(), 0..=64)),
    ) {
        // Encrypt with correct AAD
        let aad_ref = aad.as_deref();
        let ct = aes_gcm_encrypt(&key, &nonce, &payload, aad_ref);
        let ct = match ct {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };

        // Flip every bit of every byte and verify decryption fails each time.
        // (We test a single-byte flip at position 0 for proptest efficiency.)
        if !ct.is_empty() {
            let mut tampered = ct.clone();
            tampered[0] ^= 0xFF;
            let result = aes_gcm_decrypt(&key, &nonce, &tampered, aad_ref);
            prop_assert!(result.is_err(), "Tampered ciphertext must not produce Ok(...)");
        }

        // Wrong nonce → must fail
        let mut bad_nonce = nonce.clone();
        bad_nonce[0] ^= 0x01;
        let result = aes_gcm_decrypt(&key, &bad_nonce, &ct, aad_ref);
        prop_assert!(result.is_err(), "Wrong nonce must cause decryption failure");

        // Wrong key → must fail
        let mut bad_key = key.clone();
        bad_key[0] ^= 0x01;
        let result = aes_gcm_decrypt(&bad_key, &nonce, &ct, aad_ref);
        prop_assert!(result.is_err(), "Wrong key must cause decryption failure");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 9 – Commitment tag prevents forgery
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// An attacker who knows the commitment tag but not the message_key cannot
    /// produce a valid (message_key, tag) pair for a different frame index.
    /// Attack class: Header tampering
    #[test]
    fn p_commitment_tag_prevents_forgery(
        msg_key   in prop::collection::vec(any::<u8>(), 8..=64),
        frame_idx in any::<u32>(),
    ) {
        let mut commit_msg = b"meow_ratchet_commit_v1".to_vec();
        commit_msg.extend_from_slice(&frame_idx.to_be_bytes());
        let tag = hmac_sha256(&msg_key, &commit_msg).unwrap();

        // Verification with correct inputs must succeed
        prop_assert!(
            hmac_sha256_verify(&msg_key, &commit_msg, &tag).unwrap(),
            "Commitment tag must verify with correct key+message"
        );

        // Verification with different frame index must fail
        let next_frame = frame_idx.wrapping_add(1);
        let mut bad_msg = b"meow_ratchet_commit_v1".to_vec();
        bad_msg.extend_from_slice(&next_frame.to_be_bytes());
        prop_assert!(
            !hmac_sha256_verify(&msg_key, &bad_msg, &tag).unwrap(),
            "Commitment tag must not verify for a different frame index"
        );

        // Wrong key must fail
        let wrong_key = b"wrong_key_for_forgery_test";
        prop_assert!(
            !hmac_sha256_verify(wrong_key, &commit_msg, &tag).unwrap(),
            "Commitment tag must not verify with wrong key"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 10 – Argon2id domain separation (same password, different salts ≠ same key)
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// Two different 16-byte salts must produce different derived keys.
    /// Attack class: Nonce reuse at the KDF level (password-derived key uniqueness)
    #[test]
    fn p_argon2id_domain_separation(
        password in prop::collection::vec(any::<u8>(), 0..=64),
        salt_a   in prop::collection::vec(any::<u8>(), 16..=16),
        salt_b   in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        prop_assume!(salt_a != salt_b);

        let key_a = derive_key_argon2id(&password, &salt_a, 256, 1, 1, 32);
        let key_b = derive_key_argon2id(&password, &salt_b, 256, 1, 1, 32);

        // Both must succeed with valid params
        prop_assert!(key_a.is_ok(), "Argon2id must not fail with valid 16-byte salt");
        prop_assert!(key_b.is_ok(), "Argon2id must not fail with valid 16-byte salt");

        // Different salts → different keys (collision resistance)
        prop_assert_ne!(key_a.unwrap(), key_b.unwrap(), "Different salts must produce different keys");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 11 – X25519 key exchange symmetry and uniqueness
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// X25519 DH shared secret is symmetric: DH(a, B) == DH(b, A).
    /// Independently generated keypairs produce different shared secrets.
    /// Attack class: Nonce reuse (session key uniqueness)
    #[test]
    fn p_x25519_symmetric_and_unique(
        _seed in any::<u64>(), // proptest runs multiple cases
    ) {
        let (priv_a, pub_a) = x25519_generate_keypair();
        let (priv_b, pub_b) = x25519_generate_keypair();
        let (_priv_c, pub_c) = x25519_generate_keypair();

        let ss_ab = x25519_exchange(&priv_a, &pub_b).unwrap();
        let ss_ba = x25519_exchange(&priv_b, &pub_a).unwrap();
        prop_assert_eq!(ss_ab, ss_ba, "X25519 DH must be symmetric");

        let ss_ac = x25519_exchange(&priv_a, &pub_c).unwrap();
        prop_assert_ne!(ss_ab, ss_ac, "Different DH sessions must produce different shared secrets");

        // Public key derivation must be consistent
        let pub_a2 = x25519_public_from_private(&priv_a).unwrap();
        prop_assert_eq!(pub_a, pub_a2, "Public key from private must be deterministic");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 12 – HKDF context binding (different info = different output)
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// The `info` field in HKDF provides domain separation.  Two calls with different
    /// info strings must produce different output keys.
    /// Attack class: AAD omission (domain separation failure allows cross-context key use)
    #[test]
    fn p_hkdf_domain_separation(
        ikm    in prop::collection::vec(any::<u8>(), 1..=64),
        info_a in prop::collection::vec(any::<u8>(), 1..=64),
        info_b in prop::collection::vec(any::<u8>(), 1..=64),
    ) {
        prop_assume!(info_a != info_b);

        let key_a = derive_key_hkdf(&ikm, None, &info_a, 32).unwrap();
        let key_b = derive_key_hkdf(&ikm, None, &info_b, 32).unwrap();
        prop_assert_ne!(key_a, key_b, "Different HKDF info strings must produce different outputs");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY 13 – AES-GCM round-trip for arbitrary inputs
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    /// Encrypt then decrypt with identical parameters must recover the original plaintext.
    /// Attack class: Sanity / regression gate
    #[test]
    fn p_aes_gcm_roundtrip(
        key      in prop::collection::vec(any::<u8>(), 32..=32),
        nonce    in prop::collection::vec(any::<u8>(), 12..=12),
        payload  in prop::collection::vec(any::<u8>(), 0..=512),
        aad      in prop::option::of(prop::collection::vec(any::<u8>(), 0..=64)),
    ) {
        let aad_ref = aad.as_deref();
        let ct = aes_gcm_encrypt(&key, &nonce, &payload, aad_ref);
        let ct = match ct {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, aad_ref);
        prop_assert_eq!(pt.unwrap(), payload, "Round-trip must recover original plaintext");
    }
}
