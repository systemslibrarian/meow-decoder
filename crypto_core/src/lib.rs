//! # crypto_core - Production Cryptographic Primitives
//!
//! This crate provides secure cryptographic operations for Meow Decoder.
//!
//! ## Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `std` | Standard library (default) |
//! | `hsm` | Hardware Security Module (PKCS#11) support |
//! | `yubikey` | YubiKey PIV/FIDO2 support |
//! | `tpm` | TPM 2.0 platform binding |
//! | `pure-crypto` | Pure Rust crypto (no Python) |
//! | `pq-crypto` | Post-quantum cryptography (ML-KEM, ML-DSA) |
//! | `wasm` | WebAssembly support |
//! | `hardware-full` | All hardware features |
//! | `full-software` | All software features |
//! | `full` | Everything |
//!
//! ## Modules
//!
//! ### Core (always available)
//! - [`aead_wrapper`]: Verified AEAD with nonce uniqueness
//! - [`nonce`]: Nonce generation and tracking
//! - [`types`]: Core cryptographic type definitions
//!
//! ### Hardware Security (feature-gated)
//! - [`hsm`]: PKCS#11 HSM integration (`hsm` feature)
//! - [`yubikey_piv`]: YubiKey PIV/FIDO2 (`yubikey` feature)
//! - [`tpm`]: TPM 2.0 binding (`tpm` feature)
//!
//! ### Pure Rust Crypto (feature-gated)
//! - [`pure_crypto`]: Complete crypto stack (`pure-crypto` feature)
//! - [`wasm`]: WASM bindings (`wasm` feature)
//!
//! ## Security Properties (Verus-Verified)
//!
//! 1. **AEAD-001**: Nonce uniqueness - counter-based generation prevents reuse
//! 2. **AEAD-002**: Auth-gated plaintext - decryption returns `AuthenticatedPlaintext`
//! 3. **AEAD-003**: Key zeroization - keys are zeroed on drop via `zeroize` crate
//! 4. **AEAD-004**: No bypass - all encryption paths consume a `UniqueNonce`
//!
//! ## Hardware Security Properties
//!
//! - **HSM-001**: Keys never leave hardware boundary
//! - **YK-001**: PIV operations require hardware touch
//! - **TPM-001**: PCR binding prevents key extraction on different boot state
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

// ============================================================================
// Core Modules (Always Available)
// ============================================================================

pub mod aead_wrapper;
pub mod nonce;
pub mod types;
pub mod verus_proofs;
pub mod verus_kdf_proofs;

// ============================================================================
// Hardware Security Modules (Feature-Gated)
// ============================================================================

/// HSM/PKCS#11 integration
///
/// Requires the `hsm` feature:
/// ```toml
/// [dependencies]
/// crypto_core = { version = "0.2", features = ["hsm"] }
/// ```
#[cfg(feature = "hsm")]
pub mod hsm;

/// YubiKey PIV/FIDO2 support
///
/// Requires the `yubikey` feature:
/// ```toml
/// [dependencies]
/// crypto_core = { version = "0.2", features = ["yubikey"] }
/// ```
#[cfg(feature = "yubikey")]
pub mod yubikey_piv;

/// TPM 2.0 platform binding
///
/// Requires the `tpm` feature:
/// ```toml
/// [dependencies]
/// crypto_core = { version = "0.2", features = ["tpm"] }
/// ```
#[cfg(feature = "tpm")]
pub mod tpm;

// ============================================================================
// Pure Rust Crypto Modules (Feature-Gated)
// ============================================================================

/// Pure Rust cryptographic operations
///
/// Provides complete crypto stack without Python dependencies.
///
/// Requires the `pure-crypto` feature:
/// ```toml
/// [dependencies]
/// crypto_core = { version = "0.2", features = ["pure-crypto"] }
/// ```
#[cfg(feature = "pure-crypto")]
pub mod pure_crypto;

/// WebAssembly bindings
///
/// Browser-compatible crypto operations.
///
/// Requires the `wasm` feature:
/// ```toml
/// [dependencies]
/// crypto_core = { version = "0.2", features = ["wasm", "pure-crypto"] }
/// ```
#[cfg(feature = "wasm")]
pub mod wasm;

// ============================================================================
// Re-exports (Core)
// ============================================================================

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

// ============================================================================
// Re-exports (Pure Crypto)
// ============================================================================

#[cfg(feature = "pure-crypto")]
pub use pure_crypto::{
    // Types
    SecretKey, Salt, CryptoError, Argon2Params,
    // AEAD
    aes_gcm_encrypt, aes_gcm_decrypt,
    // KDF
    argon2_derive, hkdf_derive, hkdf_derive_key,
    // Hash/MAC
    sha256, hmac_sha256, hmac_sha256_verify,
    // X25519
    X25519KeyPair,
    // Utilities
    random_bytes, random_key, constant_time_eq,
    // Constants
    constants,
};

#[cfg(feature = "pq-crypto")]
pub use pure_crypto::pq::{
    MlKemKeyPair, mlkem_encapsulate, hybrid_key_derive,
    MLKEM_PUBLIC_KEY_SIZE, MLKEM_SECRET_KEY_SIZE,
    MLKEM_CIPHERTEXT_SIZE, MLKEM_SHARED_SECRET_SIZE,
};

// ============================================================================
// Re-exports (Hardware Security)
// ============================================================================

#[cfg(feature = "hsm")]
pub use hsm::{
    HsmError, HsmUri, SecurePin, HsmKeyType, HsmKeyHandle,
    HsmProvider, HsmSession, derive_key_with_hsm,
};

#[cfg(feature = "yubikey")]
pub use yubikey_piv::{
    YubiKeyError, PivSlot, YubiKeyType, YubiKeyPin,
    YubiKeyInfo, YubiKeyProvider, Fido2Provider,
    derive_key_with_yubikey,
};

#[cfg(feature = "tpm")]
pub use tpm::{
    TpmError, PcrSelection, SealedBlob, TpmAuth,
    TpmProvider, TpmInfo, derive_key_with_tpm,
};

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
