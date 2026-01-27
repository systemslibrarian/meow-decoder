//! # crypto_core - Formally Verified Cryptographic Primitives
//!
//! This crate provides Verus-verified cryptographic wrappers for Meow-Encode.
//!
//! ## Modules
//!
//! - `aead_wrapper`: Verified AEAD with nonce uniqueness and auth-then-output guarantees
//!
//! ## Verification
//!
//! This code is designed for verification with [Verus](https://github.com/verus-lang/verus).
//!
//! To verify:
//! ```bash
//! verus src/lib.rs
//! ```

pub mod aead_wrapper;

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
