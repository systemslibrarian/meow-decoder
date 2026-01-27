//! # crypto_core - Formally Verified Cryptographic Primitives
//!
//! This crate provides Verus-verified cryptographic wrappers for Meow Decoder.
//!
//! ## Modules
//!
//! - [`aead_wrapper`]: Verified AEAD with nonce uniqueness and auth-then-output guarantees
//! - [`nonce`]: Nonce generation and tracking with uniqueness invariants
//! - [`types`]: Core cryptographic type definitions
//!
//! ## Security Properties (Verus-Verified)
//!
//! 1. **AEAD-001**: Nonce uniqueness - counter-based generation prevents reuse
//! 2. **AEAD-002**: Auth-gated plaintext - decryption returns `AuthenticatedPlaintext`
//! 3. **AEAD-003**: Key zeroization - keys are zeroed on drop via `zeroize` crate
//! 4. **AEAD-004**: No bypass - all encryption paths consume a `UniqueNonce`
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crypto_core::{AeadWrapper, NonceGenerator};
//!
//! // Create wrapper with a key
//! let key = [0u8; 32]; // In real code, use secure key derivation
//! let mut wrapper = AeadWrapper::new(&key);
//! let gen = NonceGenerator::new();
//!
//! // Encrypt with unique nonce
//! let nonce = gen.next().unwrap();
//! let plaintext = b"secret message";
//! let aad = b"associated data";
//! let ciphertext = wrapper.encrypt_raw(
//!     nonce.as_bytes(),
//!     plaintext,
//!     aad
//! ).unwrap();
//!
//! // Decrypt and verify
//! let decrypted = wrapper.decrypt_raw(
//!     nonce.as_bytes(),
//!     &ciphertext,
//!     aad
//! ).unwrap();
//! ```
//!
//! ## Verification
//!
//! This code is designed for verification with [Verus](https://github.com/verus-lang/verus).
//!
//! To verify:
//! ```bash
//! cd crypto_core
//! verus --crate-type lib src/lib.rs
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Core modules
pub mod aead_wrapper;
pub mod nonce;
pub mod types;
pub mod verus_proofs;

// Re-exports from aead_wrapper
pub use aead_wrapper::{
    AeadError,
    AeadWrapper,
    AuthenticatedPlaintext,
    NonceManager,
    UniqueNonce,
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
};

// Re-exports from nonce
pub use nonce::{Nonce, NonceError, NonceGenerator, NonceTracker};

// Re-exports from types
pub use types::{AadError, AeadKey, AssociatedData, KeyError};

/// Version of the crypto_core crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Security level indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// AES-128-GCM equivalent
    Bits128,
    /// AES-256-GCM (used by this crate)
    Bits256,
}

/// Get the security level of this crate
pub const fn security_level() -> SecurityLevel {
    SecurityLevel::Bits256
}
