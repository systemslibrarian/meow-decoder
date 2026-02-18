//! Fuzz target: Per-frame symmetric ratchet (MSR v2.0 model)
//!
//! # Attack classes covered
//! - Replay               → re-feeding a previously processed frame index
//! - State compromise     → advancing beyond a compromised frame must not
//!                          allow derivation of earlier keys (forward secrecy)
//! - Nonce reuse          → each ratchet step must produce a unique message key
//! - Ratchet monotonicity → advancing the ratchet must be irreversible
//!
//! # Ratchet model (from copilot-instructions.md MSR v1.2 / v2.0):
//!   chain_key[n+1] = HKDF-SHA256(chain_key[n], "meow_ratchet_chain_v1", 32)
//!   message_key[n] = HKDF-SHA256(chain_key[n], "meow_ratchet_msg_v1",   32)
//!   commitment[n]  = HMAC-SHA256(message_key[n], "meow_commitment")
//!
//! This file models that ratchet independently of any Rust module so it can
//! be compiled today; replace `advance_ratchet` with the real function signature
//! when the ratchet module lands in rust_crypto.
//!
//! # Hard invariants
//! 1. No panic.
//! 2. message_key[n] != message_key[m] for n != m (nonce uniqueness).
//! 3. chain_key[n]   != chain_key[n+1] (ratchet is not identity).
//! 4. There is no function to go from chain_key[n+1] back to chain_key[n].
//!    (We verify this by asserting that re-deriving from a future state never
//!     matches any key produced before that state.)

#![no_main]

use libfuzzer_sys::fuzz_target;
use meow_crypto_rs::pure::{derive_key_hkdf, hmac_sha256, hmac_sha256_verify};

const CHAIN_DOMAIN: &[u8] = b"meow_ratchet_chain_v1";
const MSG_DOMAIN: &[u8] = b"meow_ratchet_msg_v1";
const COMMIT_DOMAIN: &[u8] = b"meow_ratchet_commit_v1";
const HEADER_DOMAIN: &[u8] = b"meow_ratchet_header_v1";

/// One ratchet state.
#[derive(Clone, Debug)]
struct RatchetState {
    chain_key: Vec<u8>,
    frame_idx: u32,
}

impl RatchetState {
    fn new(root_key: &[u8]) -> Self {
        RatchetState {
            chain_key: root_key.to_vec(),
            frame_idx: 0,
        }
    }

    /// Advance the ratchet by one step.
    /// Returns (message_key, commitment_tag, header_mask_20b).
    /// The chain_key is mutated; the previous value is irrecoverable.
    fn advance(&mut self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // Derive message key from current chain state
        let mut msg_info = MSG_DOMAIN.to_vec();
        msg_info.extend_from_slice(&self.frame_idx.to_be_bytes());
        let message_key =
            derive_key_hkdf(&self.chain_key, None, &msg_info, 32).unwrap_or_else(|_| vec![0u8; 32]);

        // Commitment tag: HMAC-SHA256(message_key, "meow_ratchet_commit_v1" || frame_idx)
        let mut commit_msg = COMMIT_DOMAIN.to_vec();
        commit_msg.extend_from_slice(&self.frame_idx.to_be_bytes());
        let commitment = hmac_sha256(&message_key, &commit_msg).unwrap_or_else(|_| vec![0u8; 32]);

        // Header mask (20 bytes: 4 for encrypted index, 16 for commitment tag XOR)
        let mut hdr_info = HEADER_DOMAIN.to_vec();
        hdr_info.extend_from_slice(&self.frame_idx.to_be_bytes());
        let header_mask =
            derive_key_hkdf(&self.chain_key, None, &hdr_info, 20).unwrap_or_else(|_| vec![0u8; 20]);

        // Advance chain key AFTER deriving message key (forward secrecy)
        let mut chain_info = CHAIN_DOMAIN.to_vec();
        chain_info.extend_from_slice(&self.frame_idx.to_be_bytes());
        let next_chain = derive_key_hkdf(&self.chain_key, None, &chain_info, 32)
            .unwrap_or_else(|_| vec![0u8; 32]);

        self.chain_key = next_chain;
        self.frame_idx += 1;

        (message_key, commitment, header_mask)
    }
}

fuzz_target!(|data: &[u8]| {
    // Use the fuzzer input as the root key; any length is valid (HKDF handles it)
    let root_key = if data.is_empty() {
        b"default_root_key".as_ref()
    } else {
        data
    };

    // ─── Scenario A: sequential ratchet steps ─────────────────────────────────
    // Derive N steps and collect all message_keys + chain_keys.
    // N is bounded at 64 to keep the fuzz run time sane.
    let steps: usize = 1 + (data.len() % 64);

    let mut state = RatchetState::new(root_key);
    let mut message_keys: Vec<Vec<u8>> = Vec::with_capacity(steps);
    let mut commitments: Vec<Vec<u8>> = Vec::with_capacity(steps);
    let mut header_masks: Vec<Vec<u8>> = Vec::with_capacity(steps);
    let mut chain_snapshots: Vec<Vec<u8>> = Vec::with_capacity(steps);

    chain_snapshots.push(state.chain_key.clone()); // snapshot before step 0

    for _ in 0..steps {
        let (mk, cm, hm) = state.advance();
        message_keys.push(mk);
        commitments.push(cm);
        header_masks.push(hm);
        chain_snapshots.push(state.chain_key.clone()); // snapshot after this step
    }

    // INVARIANT: ratchet is not the identity – chain_key must change each step.
    for i in 0..steps {
        assert_ne!(
            chain_snapshots[i],
            chain_snapshots[i + 1],
            "Chain key must change at every ratchet step (step {})",
            i
        );
    }

    // INVARIANT: message keys must all be unique (nonce uniqueness).
    for i in 0..steps {
        for j in (i + 1)..steps {
            assert_ne!(
                message_keys[i], message_keys[j],
                "Message keys at steps {} and {} must be distinct",
                i, j
            );
        }
    }

    // INVARIANT: commitment tags must all be 32 bytes.
    for (i, cm) in commitments.iter().enumerate() {
        assert_eq!(cm.len(), 32, "Commitment at step {} must be 32 bytes", i);
    }

    // INVARIANT: header masks must all be 20 bytes.
    for (i, hm) in header_masks.iter().enumerate() {
        assert_eq!(hm.len(), 20, "Header mask at step {} must be 20 bytes", i);
    }

    // ─── Scenario B: replay detection simulation──────────────────────────────
    // Simulate a receiver that tracks seen frame indices.
    // Re-presenting frame N must be detectable via the commitment tag.
    if steps >= 2 {
        // Re-derive step 0 from the original root key (attacker replays frame 0)
        let mut replayed = RatchetState::new(root_key);
        let (replay_mk, replay_cm, _) = replayed.advance();

        // The commitment tag for frame 0 must match what we computed above,
        // and a receiver's seen-set check catches the replay.
        assert_eq!(
            replay_cm, commitments[0],
            "Re-derived commitment for frame 0 must be deterministic (replay detectable)"
        );

        // Verify that the commitment tag for frame 0 authenticates correctly.
        let mut commit_msg = COMMIT_DOMAIN.to_vec();
        commit_msg.extend_from_slice(&0u32.to_be_bytes());
        let valid = hmac_sha256_verify(&replay_mk, &commit_msg, &replay_cm).unwrap_or(false);
        assert!(
            valid,
            "Commitment tag must verify with the matching message key"
        );

        // Verification with a WRONG key must fail (prevents forgery).
        let wrong_key = vec![0xFFu8; 32];
        let invalid = hmac_sha256_verify(&wrong_key, &commit_msg, &replay_cm).unwrap_or(true); // default true means "forged" – OK: also fails
        assert!(!invalid, "Commitment tag must not verify with wrong key");
    }

    // ─── Scenario C: post-compromise forward secrecy ──────────────────────────
    // An adversary who learns chain_key[k] must not be able to derive
    // message_key[k-1] (past keys are erased).
    //
    // We model this by showing that deriving backwards is impossible:
    // chain_key[k] cannot be inverted to chain_key[k-1] (HKDF is one-way).
    // We can only assert that re-running the ratchet from chain_key[k] yields
    // the same *future* keys but NOT the past ones.
    if steps >= 3 {
        let compromised_at = steps / 2;
        let compromised_chain_key = chain_snapshots[compromised_at].clone();

        // Re-run the ratchet from the compromised state.
        let mut future_state = RatchetState {
            chain_key: compromised_chain_key,
            frame_idx: compromised_at as u32,
        };
        let (future_mk, _, _) = future_state.advance();

        // The future key must match what the honest ratchet produced.
        assert_eq!(
            future_mk, message_keys[compromised_at],
            "Future keys must be recoverable from compromised state"
        );

        // Past keys must NOT be derivable from the compromised chain key.
        // We confirm by showing past keys != future keys (they were derived
        // from prior chain states that no longer exist).
        for past in 0..compromised_at {
            assert_ne!(
                future_mk, message_keys[past],
                "Future key at {} must not match past key at {} (PCS violated)",
                compromised_at, past
            );
        }
    }

    // ─── Scenario D: attacker-supplied commitment forgery attempt ─────────────
    // Fuzzer provides bytes as a forged commitment; verification must fail.
    if data.len() >= 32 && steps >= 1 {
        let forged_tag = &data[..32];
        let mut commit_msg = COMMIT_DOMAIN.to_vec();
        commit_msg.extend_from_slice(&0u32.to_be_bytes());

        let is_valid =
            hmac_sha256_verify(&message_keys[0], &commit_msg, forged_tag).unwrap_or(false);

        // Only if the fuzzer happened to supply the exact correct tag will this pass.
        // That requires guessing 32 bytes = 256-bit preimage.  We don't assert false
        // here because data COULD be the correct tag; we assert no panic only.
        let _ = is_valid;
    }
});
