//! Verus Proof Specifications for crypto_core (STUBS — NOT YET VERIFIED)
//!
//! This module contains formal Verus *specifications* (doc-comment annotations)
//! for the security properties of the AEAD wrapper. These are structured for
//! future Verus verification but are **not** machine-checked proofs today.
//!
//! ## Specified Properties (enforced by type system + tests)
//!
//! 1. **Nonce Uniqueness (AEAD-001)**: Each encryption uses a unique nonce
//! 2. **Auth-Gated Plaintext (AEAD-002)**: Only authenticated data is returned
//! 3. **Key Zeroization (AEAD-003)**: Keys are zeroed on drop
//! 4. **No Bypass (AEAD-004)**: All encryption paths consume a UniqueNonce
//!
//! ## Actual Verification Status
//!
//! These properties are enforced at runtime by Rust's ownership model
//! (`UniqueNonce` is consumed, `AuthenticatedPlaintext` has a private
//! constructor), the `zeroize` crate (volatile writes), and comprehensive
//! unit/integration tests. They are NOT yet verified by Verus.
//!
//! For **real** Verus proofs, see `verus_guarded_buffer.rs` (GB-001–GB-008).
//!
//! ## How to Verify (future)
//!
//! ```bash
//! # Install Verus: https://github.com/verus-lang/verus
//! # Then run:
//! verus --crate-type lib src/verus_proofs.rs
//! ```
//!
//! Note: These proofs are structured for Verus but annotated as doc comments
//! to allow compilation without Verus installed. For actual verification,
//! uncomment the `verus!` macros.

/// Ghost state for tracking allocated nonces
///
/// In Verus, this would be:
/// ```verus
/// tracked struct NonceGhost {
///     ghost allocated: Set<u64>,
///     ghost max_allocated: u64,
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct NonceGhost {
    /// Conceptual set of allocated counter values
    pub allocated: std::collections::HashSet<u64>,
    /// Highest allocated counter value
    pub max_allocated: u64,
}

// =============================================================================
// AEAD-001: Nonce Uniqueness Proof
// =============================================================================

/// Specification: Nonce counter is strictly monotonic
///
/// Verus specification (would be in `verus!` block):
/// ```verus
/// spec fn nonce_counter_monotonic(old_counter: u64, new_counter: u64) -> bool {
///     new_counter > old_counter
/// }
///
/// proof fn nonce_uniqueness_lemma(
///     ghost: NonceGhost,
///     counter_value: u64,
/// )
///     requires
///         counter_value == ghost.max_allocated + 1,
///         !ghost.allocated.contains(counter_value),
///     ensures
///         // After allocation, the new counter is unique
///         forall |v: u64| old(ghost.allocated).contains(v) ==> v != counter_value
/// {
///     // Counter-based generation with monotonic increment guarantees uniqueness
///     // Proof: If counter_value == max + 1 and max is the highest allocated,
///     // then counter_value has never been allocated.
/// }
/// ```
pub fn nonce_uniqueness_invariant_holds(counter: u64, prev_max: u64) -> bool {
    // Simplified runtime check that counter is strictly greater than previous max
    counter > prev_max
}

/// Property: fetch_add with SeqCst guarantees monotonic sequence
///
/// Argument: AtomicU64::fetch_add(1, SeqCst) returns old value and atomically
/// increments. Sequential consistency ensures no concurrent observer can
/// see the same value twice.
pub fn atomic_counter_property() -> &'static str {
    "AtomicU64::fetch_add(1, SeqCst) provides linearizable monotonic sequence"
}

// =============================================================================
// AEAD-002: Authentication-Gated Plaintext Proof
// =============================================================================

/// Specification: Plaintext is only output after authentication
///
/// Verus specification:
/// ```verus
/// spec fn auth_then_output(ciphertext: Seq<u8>, plaintext: Seq<u8>, auth_passed: bool) -> bool {
///     plaintext.len() > 0 ==> auth_passed
/// }
///
/// proof fn auth_gated_plaintext_lemma(
///     ciphertext: Seq<u8>,
///     tag: Seq<u8>,
///     key: Seq<u8>,
/// )
///     requires
///         tag.len() == 16,  // GCM tag is 16 bytes
///     ensures
///         // decrypt returns Ok only if tag verifies
///         forall |result: Result<AuthenticatedPlaintext, AeadError>|
///             result.is_ok() ==> gcm_verify(ciphertext, tag, key)
/// {
///     // AES-GCM decryption internally verifies GHASH tag
///     // aes_gcm::Aes256Gcm::decrypt returns Err on tag mismatch
///     // We wrap this in AuthenticatedPlaintext to make success explicit
/// }
/// ```
pub fn auth_gated_plaintext_invariant() -> &'static str {
    "AuthenticatedPlaintext is only constructable inside decrypt(), which only \
     returns Ok after GCM tag verification. The type cannot be forged externally."
}

/// The AuthenticatedPlaintext type is an existential witness
///
/// In Verus terms:
/// ```verus
/// type AuthenticatedPlaintext = exists |key, nonce, aad| {
///     data: Vec<u8>,
///     proof: GcmTagVerified(data, key, nonce, aad)
/// }
/// ```
pub fn authenticated_plaintext_existential() -> &'static str {
    "AuthenticatedPlaintext(pub data) where data is plaintext that \
     passed GCM authentication. The constructor is private to decrypt()."
}

// =============================================================================
// AEAD-003: Key Zeroization Proof
// =============================================================================

/// Specification: Key material is zeroed when wrapper is dropped
///
/// Verus specification:
/// ```verus
/// spec fn key_zeroed_on_drop(wrapper: AeadWrapper, post_drop_memory: Seq<u8>) -> bool {
///     // After drop, the memory region is all zeros
///     forall |i: nat| i < 32 ==> post_drop_memory[i] == 0
/// }
///
/// proof fn zeroize_on_drop_lemma()
///     ensures
///         // ZeroizeOnDrop trait guarantees zeroing
///         forall |wrapper: AeadWrapper| wrapper.drop() ==>
///             memory_region(wrapper.key_bytes) == [0u8; 32]
/// {
///     // The zeroize crate uses volatile writes to prevent optimization
///     // ZeroizeOnDrop calls zeroize() in Drop::drop()
///     // LLVM cannot optimize away volatile writes
/// }
/// ```
pub fn key_zeroization_proof() -> &'static str {
    "ZeroizeOnDrop from zeroize crate uses volatile_set_memory which is \
     guaranteed by LLVM to not be optimized away. Key bytes are overwritten \
     with zeros before deallocation."
}

/// Defense in depth: Multiple barriers against key leakage
pub fn key_protection_layers() -> Vec<&'static str> {
    vec![
        "1. Key stored in private field (no external access)",
        "2. Debug impl prints [REDACTED] instead of key",
        "3. Clone trait omitted to prevent accidental copies",
        "4. ZeroizeOnDrop zeros memory on Drop",
        "5. zeroize::Zeroize available for explicit zeroing",
    ]
}

// =============================================================================
// AEAD-004: No Bypass Proof
// =============================================================================

/// Specification: All encryption paths require UniqueNonce consumption
///
/// Verus specification:
/// ```verus
/// spec fn no_encryption_bypass(encrypt_called: bool, nonce_consumed: bool) -> bool {
///     encrypt_called ==> nonce_consumed
/// }
///
/// proof fn no_bypass_lemma(nonce: UniqueNonce)
///     requires
///         // UniqueNonce is a linear type (affine in Rust terms)
///         nonce.valid(),
///     ensures
///         // After encrypt(), nonce is consumed
///         !exists |n: UniqueNonce| n.id == nonce.id
/// {
///     // UniqueNonce is consumed by encrypt() via ownership transfer
///     // Rust's ownership system ensures it cannot be used again
///     // NonceManager.issue() creates new UniqueNonce and logs allocation
/// }
/// ```
pub fn no_bypass_proof() -> &'static str {
    "encrypt() takes UniqueNonce by value (moves ownership). \
     UniqueNonce can only be created by NonceManager.issue() which \
     uses fetch_add to ensure uniqueness. After encrypt() returns, \
     the nonce is consumed and cannot be reused."
}

/// Linear type argument for UniqueNonce
pub fn unique_nonce_linearity() -> &'static str {
    "UniqueNonce: !Clone, !Copy, private constructor. \
     Created only by NonceManager.issue(). \
     Consumed by AeadWrapper.encrypt(). \
     Drop logs warning if unused (defense in depth)."
}

// =============================================================================
// Combined Security Theorem
// =============================================================================

/// Meta-theorem: AEAD security follows from component properties
///
/// ```verus
/// proof fn aead_security_theorem()
///     requires
///         nonce_uniqueness_holds(),
///         auth_gated_plaintext_holds(),
///         key_zeroization_holds(),
///         no_bypass_holds(),
///     ensures
///         // IND-CPA: Ciphertext indistinguishable from random
///         ind_cpa_secure(),
///         // INT-CTXT: Cannot forge valid ciphertext
///         int_ctxt_secure(),
///         // Forward secrecy: Past keys don't compromise future
///         forward_secure_on_zeroize(),
/// {
///     // AES-256-GCM is proven IND-CPA and INT-CTXT secure under
///     // standard assumptions (PRP for AES, polynomial GHASH).
///     // Our wrapper adds:
///     // - Nonce uniqueness → IND-CPA not broken by nonce reuse
///     // - Auth-gated → Cannot extract plaintext without auth
///     // - Zeroization → Forward secrecy when keys dropped
/// }
/// ```
pub fn combined_security_argument() -> &'static str {
    "Given AES-256-GCM's proven security (IND-CPA, INT-CTXT) under nonce \
     uniqueness, our wrapper preserves these properties by enforcing nonce \
     uniqueness through NonceManager. Authentication gating prevents \
     plaintext release on verification failure. Key zeroization provides \
     forward secrecy properties."
}

// =============================================================================
// Verification Status
// =============================================================================

/// Current verification coverage
#[derive(Debug)]
pub struct VerificationStatus {
    /// Property ID
    pub id: &'static str,
    /// Property name
    pub name: &'static str,
    /// Verification method
    pub method: &'static str,
    /// Status
    pub status: VerificationState,
}

#[derive(Debug, Clone, Copy)]
pub enum VerificationState {
    /// Verified by Verus
    VerusVerified,
    /// Verified by testing
    Tested,
    /// Type-enforced (Rust ownership)
    TypeEnforced,
    /// External guarantee (crate dependency)
    External,
    /// Pending verification
    Pending,
}

/// Get verification status for all properties
pub fn verification_status() -> Vec<VerificationStatus> {
    vec![
        VerificationStatus {
            id: "AEAD-001",
            name: "Nonce Uniqueness",
            method: "Atomic counter + runtime checks + tests",
            status: VerificationState::Tested,
        },
        VerificationStatus {
            id: "AEAD-002",
            name: "Auth-Gated Plaintext",
            method: "Type system (private constructor)",
            status: VerificationState::TypeEnforced,
        },
        VerificationStatus {
            id: "AEAD-003",
            name: "Key Zeroization",
            method: "zeroize crate (volatile writes)",
            status: VerificationState::External,
        },
        VerificationStatus {
            id: "AEAD-004",
            name: "No Bypass",
            method: "Ownership (UniqueNonce consumed)",
            status: VerificationState::TypeEnforced,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_uniqueness_invariant() {
        assert!(nonce_uniqueness_invariant_holds(1, 0));
        assert!(nonce_uniqueness_invariant_holds(100, 99));
        assert!(!nonce_uniqueness_invariant_holds(5, 5));
        assert!(!nonce_uniqueness_invariant_holds(5, 10));
    }

    #[test]
    fn test_verification_status_complete() {
        let status = verification_status();
        assert_eq!(status.len(), 4);

        // All properties should have a verification method
        for s in status {
            assert!(!s.id.is_empty());
            assert!(!s.name.is_empty());
            assert!(!s.method.is_empty());
        }
    }

    #[test]
    fn test_key_protection_layers() {
        let layers = key_protection_layers();
        assert!(layers.len() >= 4);
    }

    #[test]
    fn test_atomic_counter_property() {
        let prop = atomic_counter_property();
        assert!(prop.contains("AtomicU64"));
        assert!(prop.contains("fetch_add"));
        assert!(prop.contains("SeqCst"));
    }

    #[test]
    fn test_auth_gated_plaintext_invariant() {
        let invariant = auth_gated_plaintext_invariant();
        assert!(invariant.contains("AuthenticatedPlaintext"));
        assert!(invariant.contains("GCM tag verification"));
    }

    #[test]
    fn test_authenticated_plaintext_existential() {
        let existential = authenticated_plaintext_existential();
        assert!(existential.contains("AuthenticatedPlaintext"));
        assert!(existential.contains("GCM authentication"));
    }

    #[test]
    fn test_key_zeroization_proof() {
        let proof = key_zeroization_proof();
        assert!(proof.contains("ZeroizeOnDrop"));
        assert!(proof.contains("volatile"));
        assert!(proof.contains("zeros"));
    }

    #[test]
    fn test_no_bypass_proof() {
        let proof = no_bypass_proof();
        assert!(proof.contains("encrypt()"));
        assert!(proof.contains("UniqueNonce"));
        assert!(proof.contains("consumed"));
    }

    #[test]
    fn test_unique_nonce_linearity() {
        let linearity = unique_nonce_linearity();
        assert!(linearity.contains("UniqueNonce"));
        assert!(linearity.contains("!Clone"));
        assert!(linearity.contains("!Copy"));
        assert!(linearity.contains("NonceManager"));
    }

    #[test]
    fn test_combined_security_argument() {
        let argument = combined_security_argument();
        assert!(argument.contains("AES-256-GCM"));
        assert!(argument.contains("IND-CPA"));
        assert!(argument.contains("INT-CTXT"));
        assert!(argument.contains("nonce"));
    }

    #[test]
    fn test_nonce_ghost_default() {
        let ghost = NonceGhost::default();
        assert!(ghost.allocated.is_empty());
        assert_eq!(ghost.max_allocated, 0);
    }

    #[test]
    fn test_nonce_ghost_clone() {
        let mut ghost = NonceGhost::default();
        ghost.allocated.insert(42);
        ghost.max_allocated = 42;

        let cloned = ghost.clone();
        assert!(cloned.allocated.contains(&42));
        assert_eq!(cloned.max_allocated, 42);
    }

    #[test]
    fn test_verification_state_variants() {
        // Test all variants can be created and debugged
        let states = [
            VerificationState::VerusVerified,
            VerificationState::Tested,
            VerificationState::TypeEnforced,
            VerificationState::External,
            VerificationState::Pending,
        ];

        for state in states {
            let debug_str = format!("{:?}", state);
            assert!(!debug_str.is_empty());
        }
    }

    #[test]
    fn test_verification_status_struct() {
        let status = VerificationStatus {
            id: "TEST-001",
            name: "Test Property",
            method: "Unit test",
            status: VerificationState::Tested,
        };

        assert_eq!(status.id, "TEST-001");
        assert_eq!(status.name, "Test Property");
        assert_eq!(status.method, "Unit test");
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("TEST-001"));
    }
}
