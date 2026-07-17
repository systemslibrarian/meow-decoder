//! # Pure Rust Cryptography Module
//!
//! Consolidates all cryptographic operations in pure Rust.
//! This module provides the complete crypto stack without Python dependencies.
//!
//! ## Security Properties
//!
//! 1. **CRYPTO-001**: Constant-time operations via `subtle` crate
//! 2. **CRYPTO-002**: Secure memory zeroing via `zeroize`
//! 3. **CRYPTO-003**: CSPRNG from OS via `getrandom`
//! 4. **CRYPTO-004**: Hybrid PQ crypto (classical + post-quantum)
//!
//! ## Supported Algorithms
//!
//! | Category | Algorithm | Notes |
//! |----------|-----------|-------|
//! | AEAD | AES-256-GCM | Primary encryption |
//! | KDF | Argon2id | Password hashing |
//! | KDF | HKDF-SHA256 | Key derivation |
//! | Key Exchange | X25519 | Ephemeral DH |
//! | Signature | Ed25519 | Manifest auth |
//! | PQ KEM | ML-KEM-1024 | Quantum-resistant |
//! | PQ Signature | ML-DSA-65 | Quantum-resistant |

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "pure-crypto")]
use {
    aes::Aes256,
    aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce as GcmNonce,
    },
    argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version},
    ctr::cipher::{KeyIvInit, StreamCipher},
    ctr::Ctr128BE,
    hkdf::Hkdf,
    hmac::Hmac,
    rand_core::{OsRng, RngCore},
    sha2::{Digest, Sha256},
    subtle::ConstantTimeEq,
    x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret},
};

#[cfg(feature = "std")]
use std::{error::Error, fmt};

/// Cryptographic constants
pub mod constants {
    /// AES-256 key size in bytes
    pub const AES_KEY_SIZE: usize = 32;
    /// AES-GCM nonce size in bytes
    pub const AES_NONCE_SIZE: usize = 12;
    /// AES-GCM tag size in bytes
    pub const AES_TAG_SIZE: usize = 16;
    /// X25519 key size in bytes
    pub const X25519_KEY_SIZE: usize = 32;
    /// SHA-256 output size in bytes
    pub const SHA256_SIZE: usize = 32;
    /// HMAC-SHA256 output size in bytes
    pub const HMAC_SIZE: usize = 32;
    /// Argon2 salt size in bytes
    pub const ARGON2_SALT_SIZE: usize = 16;
    /// Default Argon2 memory cost (512 MiB)
    pub const ARGON2_MEMORY_KIB: u32 = 524288;
    /// Default Argon2 time cost (iterations)
    pub const ARGON2_TIME: u32 = 20;
    /// Default Argon2 parallelism
    pub const ARGON2_PARALLELISM: u32 = 4;
}

use constants::*;

/// Cryptographic error types
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// Key size invalid
    InvalidKeySize(usize, usize), // (got, expected)
    /// Nonce size invalid
    InvalidNonceSize(usize, usize),
    /// Encryption failed
    EncryptionFailed(String),
    /// Decryption failed (authentication error)
    DecryptionFailed,
    /// Key derivation failed
    KeyDerivationFailed(String),
    /// Signature verification failed
    SignatureInvalid,
    /// Random generation failed
    RandomFailed(String),
    /// Feature not compiled
    FeatureDisabled,
}

#[cfg(feature = "std")]
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeySize(got, expected) => {
                write!(f, "Invalid key size: got {}, expected {}", got, expected)
            }
            CryptoError::InvalidNonceSize(got, expected) => {
                write!(f, "Invalid nonce size: got {}, expected {}", got, expected)
            }
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed (authentication error)"),
            CryptoError::KeyDerivationFailed(msg) => write!(f, "Key derivation failed: {}", msg),
            CryptoError::SignatureInvalid => write!(f, "Signature verification failed"),
            CryptoError::RandomFailed(msg) => write!(f, "Random generation failed: {}", msg),
            CryptoError::FeatureDisabled => write!(f, "Crypto feature not compiled"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for CryptoError {}

/// Secure key container with automatic zeroing
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; AES_KEY_SIZE],
}

impl SecretKey {
    /// Create from bytes (copies and stores)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != AES_KEY_SIZE {
            return Err(CryptoError::InvalidKeySize(bytes.len(), AES_KEY_SIZE));
        }
        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Get key bytes (use with care)
    pub fn as_bytes(&self) -> &[u8; AES_KEY_SIZE] {
        &self.bytes
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Secure nonce container
#[derive(Clone, Copy, Zeroize)]
pub struct Nonce {
    bytes: [u8; AES_NONCE_SIZE],
}

impl Nonce {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != AES_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize(bytes.len(), AES_NONCE_SIZE));
        }
        let mut nonce = [0u8; AES_NONCE_SIZE];
        nonce.copy_from_slice(bytes);
        Ok(Self { bytes: nonce })
    }

    /// Generate random nonce
    #[cfg(feature = "pure-crypto")]
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; AES_NONCE_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Ok(Self { bytes })
    }

    /// Get nonce bytes
    pub fn as_bytes(&self) -> &[u8; AES_NONCE_SIZE] {
        &self.bytes
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Salt for key derivation
#[derive(Clone, Zeroize)]
pub struct Salt {
    bytes: [u8; ARGON2_SALT_SIZE],
}

impl Salt {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ARGON2_SALT_SIZE {
            return Err(CryptoError::InvalidKeySize(bytes.len(), ARGON2_SALT_SIZE));
        }
        let mut salt = [0u8; ARGON2_SALT_SIZE];
        salt.copy_from_slice(bytes);
        Ok(Self { bytes: salt })
    }

    /// Generate random salt
    #[cfg(feature = "pure-crypto")]
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; ARGON2_SALT_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Ok(Self { bytes })
    }

    /// Get salt bytes
    pub fn as_bytes(&self) -> &[u8; ARGON2_SALT_SIZE] {
        &self.bytes
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ============================================================================
// AES-256-GCM AEAD
// ============================================================================

/// Encrypt data with AES-256-GCM
///
/// # Security
///
/// - 256-bit key security
/// - 128-bit authentication tag
/// - Nonce must be unique per key/message pair
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte unique nonce
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (optional)
///
/// # Returns
///
/// Ciphertext || Tag (16 bytes appended)
#[cfg(feature = "pure-crypto")]
pub fn aes_gcm_encrypt(
    key: &SecretKey,
    nonce: &Nonce,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let gcm_nonce = GcmNonce::from(*nonce.as_bytes());

    let ciphertext = if let Some(aad_data) = aad {
        let payload = Payload {
            msg: plaintext,
            aad: aad_data,
        };
        cipher.encrypt(&gcm_nonce, payload)
    } else {
        cipher.encrypt(&gcm_nonce, plaintext)
    }
    .map_err(|_| CryptoError::EncryptionFailed("GCM encryption failed".into()))?;

    Ok(ciphertext)
}

/// Decrypt data with AES-256-GCM
///
/// # Security
///
/// - Constant-time tag verification
/// - Returns error if authentication fails
#[cfg(feature = "pure-crypto")]
pub fn aes_gcm_decrypt(
    key: &SecretKey,
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_e| CryptoError::DecryptionFailed)?;

    let gcm_nonce = GcmNonce::from(*nonce.as_bytes());

    let plaintext = if let Some(aad_data) = aad {
        let payload = Payload {
            msg: ciphertext,
            aad: aad_data,
        };
        cipher.decrypt(&gcm_nonce, payload)
    } else {
        cipher.decrypt(&gcm_nonce, ciphertext)
    }
    .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

// ============================================================================
// AES-256-CTR (Streaming Encryption)
// ============================================================================

/// AES-256-CTR encrypt/decrypt (symmetric — same operation for both)
///
/// # Security
///
/// - CTR mode provides NO authentication. Must be used with Encrypt-then-MAC.
/// - Nonce must NEVER be reused with the same key.
/// - This function XORs data with the AES-CTR keystream starting at the given
///   byte offset, enabling chunk-based streaming without buffering.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key
/// * `nonce` - 16-byte initial counter block (CTR IV)
/// * `data` - Plaintext (encrypt) or ciphertext (decrypt)
/// * `byte_offset` - Starting position in the stream (must be block-aligned, i.e. multiple of 16)
///
/// # Returns
///
/// Processed data (ciphertext or plaintext)
#[cfg(feature = "pure-crypto")]
pub fn aes_ctr_crypt(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    byte_offset: u64,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeySize(key.len(), 32));
    }
    if nonce.len() != 16 {
        return Err(CryptoError::InvalidNonceSize(nonce.len(), 16));
    }

    // Compute the counter block at the given byte offset.
    // The nonce is the initial 128-bit counter, incremented by block_offset.
    let block_offset = byte_offset / 16;

    // Parse the 16-byte nonce as a big-endian 128-bit integer, add block_offset
    let mut counter = [0u8; 16];
    counter.copy_from_slice(nonce);

    // Add block_offset to the 128-bit big-endian counter
    let mut carry = block_offset;
    for i in (0..16).rev() {
        let val = counter[i] as u64 + (carry & 0xFF);
        counter[i] = val as u8;
        carry = (carry >> 8) + (val >> 8);
    }

    // Create CTR cipher with adjusted counter
    let mut cipher = Ctr128BE::<Aes256>::new_from_slices(key, &counter)
        .map_err(|e| CryptoError::EncryptionFailed(format!("CTR init failed: {}", e)))?;

    // Handle partial block offset (if byte_offset is not block-aligned)
    let partial_offset = (byte_offset % 16) as usize;
    let mut output = data.to_vec();

    if partial_offset > 0 {
        // We need to skip `partial_offset` bytes of keystream.
        // Generate a dummy block and discard the first `partial_offset` bytes.
        let mut skip = vec![0u8; partial_offset];
        cipher.apply_keystream(&mut skip);
    }

    cipher.apply_keystream(&mut output);
    Ok(output)
}

// ============================================================================
// Argon2id KDF
// ============================================================================

/// Argon2id parameters
#[derive(Clone, Copy)]
pub struct Argon2Params {
    /// Memory cost in KiB
    pub memory_kib: u32,
    /// Time cost (iterations)
    pub time: u32,
    /// Parallelism (threads)
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            time: ARGON2_TIME,
            parallelism: ARGON2_PARALLELISM,
        }
    }
}

impl Argon2Params {
    /// OWASP minimum recommended settings
    pub fn owasp_minimum() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            time: 3,
            parallelism: 4,
        }
    }

    /// Ultra-hardened settings (1 GiB, 40 iterations)
    pub fn ultra() -> Self {
        Self {
            memory_kib: 1048576, // 1 GiB
            time: 40,
            parallelism: 4,
        }
    }
}

/// Derive key from password using Argon2id
///
/// # Security
///
/// - Memory-hard: Resistant to GPU/ASIC attacks
/// - Time-hard: Slow by design
/// - Default: 512 MiB, 20 iterations (~5-10 seconds)
#[cfg(feature = "pure-crypto")]
pub fn argon2_derive(
    password: &[u8],
    salt: &Salt,
    params: Option<Argon2Params>,
) -> Result<SecretKey, CryptoError> {
    let params = params.unwrap_or_default();

    let argon2_params = Params::new(
        params.memory_kib,
        params.time,
        params.parallelism,
        Some(AES_KEY_SIZE),
    )
    .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; AES_KEY_SIZE];
    argon2
        .hash_password_into(password, salt.as_bytes(), &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(SecretKey { bytes: output })
}

// ============================================================================
// HKDF
// ============================================================================

/// Derive key material using HKDF-SHA256
///
/// # Arguments
///
/// * `ikm` - Input key material
/// * `salt` - Optional salt (recommended)
/// * `info` - Context/application-specific info
/// * `length` - Output length (max 255 * 32 = 8160 bytes)
#[cfg(feature = "pure-crypto")]
pub fn hkdf_derive(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    Ok(okm)
}

/// Derive a 32-byte key using HKDF-SHA256
#[cfg(feature = "pure-crypto")]
pub fn hkdf_derive_key(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<SecretKey, CryptoError> {
    // SECURITY (L1): the plain HKDF `output` Vec holds raw key bytes. Copy it
    // into the ZeroizeOnDrop `SecretKey`, then wipe the intermediate before it
    // is dropped so key material does not linger in freed heap.
    let mut output = hkdf_derive(ikm, salt, info, AES_KEY_SIZE)?;
    let key = SecretKey::from_bytes(&output);
    output.zeroize();
    key
}

// ============================================================================
// X25519 Key Exchange
// ============================================================================

/// X25519 key pair
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519KeyPair {
    secret: [u8; X25519_KEY_SIZE],
    public: [u8; X25519_KEY_SIZE],
}

impl X25519KeyPair {
    /// Generate new random key pair
    #[cfg(feature = "pure-crypto")]
    pub fn generate() -> Result<Self, CryptoError> {
        // Use StaticSecret which exposes bytes (EphemeralSecret doesn't)
        let static_secret = StaticSecret::random();
        let public = PublicKey::from(&static_secret);

        Ok(Self {
            secret: static_secret.to_bytes(),
            public: public.to_bytes(),
        })
    }

    /// Get public key bytes
    pub fn public_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.public
    }

    /// Get secret key bytes (consuming — caller must zeroize after use)
    pub fn secret_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.secret
    }

    /// Perform Diffie-Hellman key exchange
    #[cfg(feature = "pure-crypto")]
    pub fn diffie_hellman(
        &self,
        their_public: &[u8; X25519_KEY_SIZE],
    ) -> Result<[u8; X25519_KEY_SIZE], CryptoError> {
        let secret = StaticSecret::from(self.secret);
        let their_pk = PublicKey::from(*their_public);
        let shared = secret.diffie_hellman(&their_pk);
        // SECURITY (M2): reject low-order points (RFC 7748 §6.1) that produce an
        // all-zero shared secret, mirroring rust_crypto/src/handles.rs. Without
        // this, an attacker-supplied low-order public key forces a predictable
        // key independent of our private key.
        if shared.as_bytes().iter().all(|&b| b == 0) {
            return Err(CryptoError::KeyDerivationFailed(
                "X25519 produced an all-zero shared secret (low-order point)".into(),
            ));
        }
        Ok(shared.to_bytes())
    }
}

// ============================================================================
// HMAC-SHA256
// ============================================================================

/// Compute HMAC-SHA256
///
/// # Safety Invariant
/// HMAC-SHA256 accepts any key length per RFC 2104 §2.
/// `new_from_slice` cannot fail for HMAC-SHA256.
#[cfg(feature = "pure-crypto")]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; HMAC_SIZE] {
    use hmac::{digest::KeyInit, Mac};
    type HmacSha256 = Hmac<Sha256>;
    // SAFETY: HMAC-SHA256 accepts any key length — InvalidLength is unreachable.
    // If somehow reached, abort rather than returning a forgeable all-zero MAC.
    let mut mac: HmacSha256 = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => {
            // Unreachable for HMAC-SHA256.  Abort to prevent an all-zero MAC
            // from being used as an authentication tag (forgery risk).
            unreachable!("HMAC-SHA256 new_from_slice cannot fail for any key length");
        }
    };
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Verify HMAC-SHA256 in constant time
#[cfg(feature = "pure-crypto")]
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8; HMAC_SIZE]) -> bool {
    let computed = hmac_sha256(key, data);
    computed.ct_eq(expected).into()
}

// ============================================================================
// SHA-256
// ============================================================================

/// Compute SHA-256 hash
#[cfg(feature = "pure-crypto")]
pub fn sha256(data: &[u8]) -> [u8; SHA256_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ============================================================================
// Constant-Time Operations
// ============================================================================

/// Constant-time byte comparison
#[cfg(feature = "pure-crypto")]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ============================================================================
// Random Number Generation
// ============================================================================

/// Generate cryptographically secure random bytes
#[cfg(feature = "pure-crypto")]
pub fn random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Generate random 32-byte key
#[cfg(feature = "pure-crypto")]
pub fn random_key() -> Result<SecretKey, CryptoError> {
    let mut bytes = [0u8; AES_KEY_SIZE];
    OsRng.fill_bytes(&mut bytes);
    Ok(SecretKey { bytes })
}

// ============================================================================
// Post-Quantum Cryptography - Dual Backend Support
// ============================================================================
//
// Two backends available:
// 1. `pq-crypto` feature: Pure Rust ml-kem/ml-dsa (RustCrypto)
// 2. `liboqs-native` feature: C library bindings (Open Quantum Safe)
//
// Both provide identical API via `crypto_core::pure_crypto::pq::*`
// Use `pq-crypto` for easy builds, `liboqs-native` for production audited code.

/// Check if any PQ backend is enabled
#[cfg(any(feature = "pq-crypto", feature = "liboqs-native"))]
pub mod pq {
    use super::*;

    // ========================================================================
    // Backend: RustCrypto ml-kem/ml-dsa (pure Rust)
    // ========================================================================
    #[cfg(all(feature = "pq-crypto", not(feature = "liboqs-native")))]
    mod backend {
        use super::*;
        // ML-KEM 0.3.0-rc.0 API with getrandom feature:
        // - Generate::generate() -> Self uses system RNG internally
        // - Encapsulate::encapsulate() -> (Ciphertext, SharedSecret) uses system RNG
        // - Decapsulate::decapsulate(&ct) -> SharedSecret [NOT Result]
        // - Serialization: .to_bytes(), ::new() for EncapsulationKey, ::from_expanded_bytes() for DecapsulationKey
        // The getrandom feature avoids rand_core version mismatches between crates.
        #[allow(deprecated)]
        // ExpandedKeyEncoding deprecated but needed for serialization roundtrip
        use ml_kem::{
            DecapsulationKey1024 as DecapsulationKey, EncapsulationKey1024 as EncapsulationKey,
            ExpandedKeyEncoding, KeyExport,
        };
        // External kem crate: Generate, Encapsulate, Decapsulate traits
        use kem::{Decapsulate, Encapsulate, Generate};
        use ml_dsa::{MlDsa65, SigningKey, VerifyingKey};

        pub const BACKEND_NAME: &str = "RustCrypto ml-kem/ml-dsa (pure Rust)";

        /// Generate new ML-KEM-1024 key pair
        /// Returns (secret_key_bytes, public_key_bytes)
        #[allow(deprecated)] // to_expanded_bytes deprecated but needed for serialization roundtrip
        pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            // Generate trait method: generate() uses system RNG via getrandom feature
            let dk = DecapsulationKey::generate();
            let ek = dk.encapsulation_key();
            // Use expanded bytes format to match from_expanded_bytes() in decapsulate.
            // SECURITY (L1): the expanded decapsulation-key bytes are the secret
            // key; copy them into the returned Vec, then wipe the intermediate.
            let mut expanded = dk.to_expanded_bytes();
            let secret_vec = expanded.to_vec();
            for b in expanded.iter_mut() {
                *b = 0;
            }
            Ok((secret_vec, ek.to_bytes().to_vec()))
        }

        /// Encapsulate to produce ciphertext and shared secret
        pub fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
            // Convert slice to Array using TryFrom
            let ek_array: ml_kem::array::Array<u8, _> =
                encapsulation_key.try_into().map_err(|_| {
                    CryptoError::KeyDerivationFailed("Invalid encapsulation key length".into())
                })?;
            // ml-kem 0.3.0-rc.0: use ::new() instead of from_encoded_bytes
            let ek = EncapsulationKey::new(&ek_array).map_err(|_| {
                CryptoError::KeyDerivationFailed("Invalid encapsulation key".into())
            })?;

            // Encapsulate trait: encapsulate() uses system RNG via getrandom feature
            // Returns (Ciphertext, SharedSecret) directly - NOT a Result
            let (ct, shared) = ek.encapsulate();

            let shared_arr: [u8; 32] = shared
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::EncryptionFailed("Invalid shared secret size".into()))?;
            Ok((ct.as_slice().to_vec(), shared_arr))
        }

        /// Decapsulate to recover shared secret
        #[allow(deprecated)] // from_expanded_bytes deprecated but needed for serialization roundtrip
        pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<[u8; 32], CryptoError> {
            // Convert slice to Array using TryFrom
            let mut dk_array: ml_kem::array::Array<u8, _> =
                secret_key.try_into().map_err(|_| {
                    CryptoError::KeyDerivationFailed("Invalid secret key length".into())
                })?;
            // ml-kem 0.3.0-rc.0: use from_expanded_bytes instead of from_encoded_bytes
            let dk = DecapsulationKey::from_expanded_bytes(&dk_array)
                .map_err(|_| CryptoError::KeyDerivationFailed("Invalid secret key".into()))?;
            // SECURITY (L1): wipe the stack copy of the secret-key bytes now that
            // the DecapsulationKey has been reconstructed from it.
            for b in dk_array.iter_mut() {
                *b = 0;
            }

            // Convert ciphertext to Array
            let ct_array: ml_kem::array::Array<u8, _> = ciphertext.try_into().map_err(|_| {
                CryptoError::KeyDerivationFailed("Invalid ciphertext length".into())
            })?;

            // Decapsulate trait: decapsulate returns SharedSecret directly
            // NOT a Result - no map_err needed
            let shared = dk.decapsulate(&ct_array);

            let shared_arr: [u8; 32] = shared
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::DecryptionFailed)?;
            Ok(shared_arr)
        }

        // ── ML-DSA-65 signing (FIPS 204) ──────────────────────────────────

        /// Generate ML-DSA-65 signing keypair.
        /// Returns (seed_bytes_32, verifying_key_bytes).
        /// The seed is the 32-byte secret that reconstructs the signing key.
        pub fn mldsa65_keygen() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            use ml_dsa::signature::Keypair;

            // Generate a random 32-byte seed using the system RNG
            let mut seed_bytes = [0u8; 32];
            getrandom::fill(&mut seed_bytes)
                .map_err(|_| CryptoError::KeyDerivationFailed("System RNG failed".into()))?;
            let seed = ml_dsa::Seed::try_from(&seed_bytes[..])
                .map_err(|_| CryptoError::KeyDerivationFailed("Invalid seed".into()))?;

            // Derive signing key from seed (deterministic). ml-dsa 0.1.0-rc.11
            // moved `from_seed` onto `SigningKey` (the `KeyGen` trait is gone).
            let sk = SigningKey::<MlDsa65>::from_seed(&seed);
            let vk = sk.verifying_key();
            let vk_encoded = vk.encode();
            // SECURITY (L1): copy the seed (secret) into the returned Vec, then
            // wipe the stack buffer so the 32-byte secret does not linger.
            let seed_vec = seed_bytes.to_vec();
            for b in seed_bytes.iter_mut() {
                *b = 0;
            }
            Ok((seed_vec, vk_encoded.to_vec()))
        }

        /// Sign a message with ML-DSA-65.
        /// `secret_key` must be a 32-byte seed.
        /// Returns the encoded signature bytes.
        pub fn mldsa65_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            use ml_dsa::signature::Signer;
            use ml_dsa::Seed;

            if secret_key.len() != 32 {
                return Err(CryptoError::KeyDerivationFailed(format!(
                    "Invalid ML-DSA-65 seed length: expected 32, got {}",
                    secret_key.len()
                )));
            }

            let seed = Seed::try_from(secret_key)
                .map_err(|_| CryptoError::KeyDerivationFailed("Invalid seed".into()))?;
            let sk = SigningKey::<MlDsa65>::from_seed(&seed);
            let sig = sk.sign(message);
            Ok(sig.encode().to_vec())
        }

        /// Verify a ML-DSA-65 signature.
        /// `public_key` is the encoded verifying key, `signature` is the encoded signature.
        pub fn mldsa65_verify(
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, CryptoError> {
            use ml_dsa::signature::Verifier;
            use ml_dsa::{EncodedVerifyingKey, Signature as MlDsaSignature};

            let vk_encoded: EncodedVerifyingKey<MlDsa65> = public_key.try_into().map_err(|_| {
                CryptoError::KeyDerivationFailed(format!(
                    "Invalid ML-DSA-65 public key length: got {}",
                    public_key.len()
                ))
            })?;
            let vk = VerifyingKey::<MlDsa65>::decode(&vk_encoded);

            let sig = MlDsaSignature::<MlDsa65>::try_from(signature).map_err(|_| {
                CryptoError::KeyDerivationFailed("Invalid ML-DSA-65 signature".into())
            })?;

            Ok(vk.verify(message, &sig).is_ok())
        }
    }

    // ========================================================================
    // Backend: liboqs (Open Quantum Safe C library)
    // ========================================================================
    #[cfg(feature = "liboqs-native")]
    mod backend {
        use super::*;

        pub const BACKEND_NAME: &str = "liboqs (Open Quantum Safe)";

        /// Generate new ML-KEM-1024 key pair using liboqs
        pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).map_err(|e| {
                CryptoError::KeyDerivationFailed(format!("liboqs init failed: {}", e))
            })?;

            let (public_key, secret_key) = kem.keypair().map_err(|e| {
                CryptoError::KeyDerivationFailed(format!("liboqs keygen failed: {}", e))
            })?;

            Ok((secret_key.into_vec(), public_key.into_vec()))
        }

        /// Encapsulate to produce ciphertext and shared secret using liboqs
        pub fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).map_err(|e| {
                CryptoError::KeyDerivationFailed(format!("liboqs init failed: {}", e))
            })?;

            let public_key = kem
                .public_key_from_bytes(encapsulation_key)
                .ok_or_else(|| CryptoError::KeyDerivationFailed("Invalid public key".into()))?;

            let (ciphertext, shared_secret) = kem.encapsulate(&public_key).map_err(|e| {
                CryptoError::KeyDerivationFailed(format!("liboqs encaps failed: {}", e))
            })?;

            let mut shared = [0u8; 32];
            shared.copy_from_slice(&shared_secret.into_vec()[..32]);
            Ok((ciphertext.into_vec(), shared))
        }

        /// Decapsulate to recover shared secret using liboqs
        pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<[u8; 32], CryptoError> {
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).map_err(|e| {
                CryptoError::KeyDerivationFailed(format!("liboqs init failed: {}", e))
            })?;

            let sk = kem
                .secret_key_from_bytes(secret_key)
                .ok_or_else(|| CryptoError::KeyDerivationFailed("Invalid secret key".into()))?;

            let ct = kem
                .ciphertext_from_bytes(ciphertext)
                .ok_or_else(|| CryptoError::KeyDerivationFailed("Invalid ciphertext".into()))?;

            let shared_secret = kem.decapsulate(&sk, &ct).map_err(|e| {
                CryptoError::KeyDerivationFailed(format!("liboqs decaps failed: {}", e))
            })?;

            let mut shared = [0u8; 32];
            shared.copy_from_slice(&shared_secret.into_vec()[..32]);
            Ok(shared)
        }
    }

    // ========================================================================
    // Unified Public API (works with either backend)
    // ========================================================================

    /// ML-KEM-1024 public key size
    pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1568;
    /// ML-KEM-1024 secret key size
    pub const MLKEM_SECRET_KEY_SIZE: usize = 3168;
    /// ML-KEM-1024 ciphertext size
    pub const MLKEM_CIPHERTEXT_SIZE: usize = 1568;
    /// ML-KEM-1024 shared secret size
    pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;

    /// Get the active PQ backend name
    pub fn backend_name() -> &'static str {
        backend::BACKEND_NAME
    }

    /// ML-KEM key pair
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct MlKemKeyPair {
        secret: Vec<u8>,
        public: Vec<u8>,
    }

    impl MlKemKeyPair {
        /// Generate new ML-KEM-1024 key pair
        ///
        /// Uses the active backend (RustCrypto or liboqs) based on feature flags.
        pub fn generate() -> Result<Self, CryptoError> {
            let (secret, public) = backend::generate_keypair()?;
            Ok(Self { secret, public })
        }

        /// Get encapsulation key (public)
        pub fn encapsulation_key(&self) -> &[u8] {
            &self.public
        }

        /// Decapsulate to recover shared secret
        pub fn decapsulate(
            &self,
            ciphertext: &[u8],
        ) -> Result<[u8; MLKEM_SHARED_SECRET_SIZE], CryptoError> {
            backend::decapsulate(&self.secret, ciphertext)
        }
    }

    /// Encapsulate to produce ciphertext and shared secret
    pub fn mlkem_encapsulate(
        encapsulation_key: &[u8],
    ) -> Result<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_SIZE]), CryptoError> {
        backend::encapsulate(encapsulation_key)
    }

    /// Hybrid key derivation: X25519 + ML-KEM-1024
    ///
    /// Secure if EITHER classical OR quantum crypto holds.
    /// This is the recommended usage pattern for post-quantum security.
    pub fn hybrid_key_derive(
        x25519_shared: &[u8; 32],
        mlkem_shared: &[u8; 32],
        info: &[u8],
    ) -> Result<SecretKey, CryptoError> {
        // Combine both shared secrets.
        // SECURITY (L1): the 64-byte combined IKM (x25519 || mlkem) fully
        // determines the returned key, so wrap it in `Zeroizing` to guarantee
        // it is wiped when it goes out of scope.
        let mut combined = zeroize::Zeroizing::new(Vec::with_capacity(64));
        combined.extend_from_slice(x25519_shared);
        combined.extend_from_slice(mlkem_shared);

        // Derive final key
        hkdf_derive_key(&combined, None, info)
    }

    /// Check which PQ backend is active (for diagnostics)
    pub fn pq_backend_info() -> String {
        format!(
            "🐱 Post-Quantum Backend: {}\n  ML-KEM-1024: {} byte public key, {} byte ciphertext",
            backend_name(),
            MLKEM_PUBLIC_KEY_SIZE,
            MLKEM_CIPHERTEXT_SIZE
        )
    }

    // ========================================================================
    // ML-DSA-65 Signing API (FIPS 204)
    // ========================================================================

    /// ML-DSA-65 public key size (1952 bytes)
    pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
    /// ML-DSA-65 signature size (3309 bytes)
    pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;

    /// Generate ML-DSA-65 keypair.
    /// Returns (secret_key_bytes, public_key_bytes).
    pub fn mldsa65_keygen() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        backend::mldsa65_keygen()
    }

    /// Sign a message with ML-DSA-65.
    /// Returns the detached signature bytes.
    pub fn mldsa65_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        backend::mldsa65_sign(secret_key, message)
    }

    /// Verify a ML-DSA-65 signature.
    pub fn mldsa65_verify(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        backend::mldsa65_verify(public_key, message, signature)
    }
}

// ============================================================================
// Stub implementations when feature is disabled
// ============================================================================

#[cfg(not(feature = "pure-crypto"))]
pub fn aes_gcm_encrypt(
    _key: &SecretKey,
    _nonce: &Nonce,
    _plaintext: &[u8],
    _aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::FeatureDisabled)
}

#[cfg(not(feature = "pure-crypto"))]
pub fn aes_gcm_decrypt(
    _key: &SecretKey,
    _nonce: &Nonce,
    _ciphertext: &[u8],
    _aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    Err(CryptoError::FeatureDisabled)
}

#[cfg(not(feature = "pure-crypto"))]
pub fn argon2_derive(
    _password: &[u8],
    _salt: &Salt,
    _params: Option<Argon2Params>,
) -> Result<SecretKey, CryptoError> {
    Err(CryptoError::FeatureDisabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_zeroize() {
        let key = SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
        assert_eq!(key.as_bytes()[0], 0x42);
    }

    #[test]
    fn test_nonce_from_bytes() {
        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();
        assert_eq!(nonce.as_bytes().len(), 12);
    }

    #[test]
    fn test_salt_from_bytes() {
        let salt = Salt::from_bytes(&[0u8; 16]).unwrap();
        assert_eq!(salt.as_bytes().len(), 16);
    }

    #[test]
    fn test_invalid_key_size() {
        let result = SecretKey::from_bytes(&[0u8; 16]);
        assert!(matches!(result, Err(CryptoError::InvalidKeySize(16, 32))));
    }

    #[cfg(feature = "pure-crypto")]
    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();
        let plaintext = b"Hello, Meow Decoder!";

        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext, None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[cfg(feature = "pure-crypto")]
    #[test]
    fn test_aes_gcm_with_aad() {
        let key = SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();
        let plaintext = b"Secret data";
        let aad = b"Additional authenticated data";

        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext, Some(aad)).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        // Wrong AAD should fail
        let wrong_aad = b"Wrong AAD";
        let result = aes_gcm_decrypt(&key, &nonce, &ciphertext, Some(wrong_aad));
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[cfg(feature = "pure-crypto")]
    #[test]
    fn test_hmac_sha256_verify() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let mac = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &mac));

        // Wrong mac should fail
        let mut wrong_mac = mac;
        wrong_mac[0] ^= 0x01;
        assert!(!hmac_sha256_verify(key, data, &wrong_mac));
    }

    #[cfg(feature = "pure-crypto")]
    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[cfg(feature = "pure-crypto")]
    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[cfg(feature = "pure-crypto")]
    #[test]
    fn test_random_bytes() {
        let r1 = random_bytes(32).unwrap();
        let r2 = random_bytes(32).unwrap();
        assert_eq!(r1.len(), 32);
        assert_ne!(r1, r2); // Probabilistically true
    }

    #[cfg(feature = "pure-crypto")]
    #[test]
    fn test_x25519_key_exchange() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared_alice = alice.diffie_hellman(bob.public_bytes()).unwrap();
        let shared_bob = bob.diffie_hellman(alice.public_bytes()).unwrap();

        assert_eq!(shared_alice, shared_bob);
    }

    #[cfg(feature = "pure-crypto")]
    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let salt = Some(b"salt".as_slice());
        let info = b"info";

        let okm = hkdf_derive(ikm, salt, info, 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_secret_key_as_ref() {
        let key = SecretKey::from_bytes(&[0x42u8; 32]).unwrap();
        let reference: &[u8] = key.as_ref();
        assert_eq!(reference.len(), 32);
    }

    #[test]
    fn test_nonce_as_ref() {
        let nonce = Nonce::from_bytes(&[0u8; 12]).unwrap();
        let reference: &[u8] = nonce.as_ref();
        assert_eq!(reference.len(), 12);
    }

    #[test]
    fn test_salt_as_ref() {
        let salt = Salt::from_bytes(&[0u8; 16]).unwrap();
        let reference: &[u8] = salt.as_ref();
        assert_eq!(reference.len(), 16);
    }

    #[test]
    fn test_invalid_nonce_size() {
        let result = Nonce::from_bytes(&[0u8; 8]);
        assert!(matches!(result, Err(CryptoError::InvalidNonceSize(8, 12))));
    }

    #[test]
    fn test_invalid_salt_size() {
        let result = Salt::from_bytes(&[0u8; 8]);
        // Salt uses InvalidKeySize since there's no InvalidSaltSize variant
        assert!(matches!(result, Err(CryptoError::InvalidKeySize(8, 16))));
    }

    #[test]
    fn test_crypto_error_display_all_variants() {
        // Cover all Display implementations
        let err1 = CryptoError::InvalidKeySize(16, 32);
        assert!(format!("{}", err1).contains("Invalid key size"));

        let err2 = CryptoError::InvalidNonceSize(8, 12);
        assert!(format!("{}", err2).contains("Invalid nonce size"));

        let err3 = CryptoError::EncryptionFailed("test".to_string());
        assert!(format!("{}", err3).contains("Encryption failed"));

        let err4 = CryptoError::DecryptionFailed;
        assert!(format!("{}", err4).contains("Decryption failed"));

        let err5 = CryptoError::KeyDerivationFailed("kdf".to_string());
        assert!(format!("{}", err5).contains("Key derivation failed"));

        let err6 = CryptoError::SignatureInvalid;
        assert!(format!("{}", err6).contains("Signature"));

        let err7 = CryptoError::RandomFailed("rng".to_string());
        assert!(format!("{}", err7).contains("Random"));

        let err8 = CryptoError::FeatureDisabled;
        assert!(format!("{}", err8).contains("feature"));
    }

    #[test]
    fn test_crypto_error_debug() {
        let err = CryptoError::DecryptionFailed;
        let dbg = format!("{:?}", err);
        assert!(dbg.contains("DecryptionFailed"));
    }

    #[test]
    fn test_argon2_params_variants() {
        let default = Argon2Params::default();
        assert_eq!(default.memory_kib, ARGON2_MEMORY_KIB);

        let owasp = Argon2Params::owasp_minimum();
        assert_eq!(owasp.memory_kib, 65536);
        assert_eq!(owasp.time, 3);

        let ultra = Argon2Params::ultra();
        assert_eq!(ultra.memory_kib, 1048576);
        assert_eq!(ultra.time, 40);
    }

    #[test]
    fn test_hkdf_derive_key() {
        let ikm = [1u8; 32];
        let info = b"test info";
        let result = hkdf_derive_key(&ikm, None, info);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_hkdf_derive_with_salt() {
        let ikm = [1u8; 32];
        let salt = [2u8; 32];
        let info = b"context";
        let result = hkdf_derive(&ikm, Some(&salt), info, 64);
        assert!(result.is_ok());
        let okm = result.unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_constant_time_eq_variants() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        let d = [1, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn test_random_bytes_generation() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        // Extremely unlikely to be equal
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_key_generation() {
        let key1 = random_key().unwrap();
        let key2 = random_key().unwrap();
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_nonce_random_generation() {
        let n1 = Nonce::random().unwrap();
        let n2 = Nonce::random().unwrap();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn test_salt_random_generation() {
        let s1 = Salt::random().unwrap();
        let s2 = Salt::random().unwrap();
        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn test_secret_key_as_ref_slice() {
        let key = SecretKey::from_bytes(&[0xAB; 32]).unwrap();
        let bytes: &[u8] = key.as_ref();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0xAB);
    }

    #[test]
    fn test_nonce_as_bytes() {
        let nonce = Nonce::from_bytes(&[0x42; 12]).unwrap();
        assert_eq!(nonce.as_bytes()[0], 0x42);
    }

    #[test]
    fn test_salt_as_bytes() {
        let salt = Salt::from_bytes(&[0x33; 16]).unwrap();
        assert_eq!(salt.as_bytes()[0], 0x33);
    }

    #[test]
    fn test_argon2_derive_basic() {
        let password = b"test_password";
        let salt = Salt::from_bytes(&[0xAA; 16]).unwrap();

        // Use minimal params for testing speed
        let params = Argon2Params {
            memory_kib: 1024, // 1 MiB for speed
            time: 1,
            parallelism: 1,
        };

        let result = argon2_derive(password, &salt, Some(params));
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.as_ref().len(), 32);
    }

    #[test]
    fn test_argon2_derive_deterministic() {
        let password = b"same_password";
        let salt = Salt::from_bytes(&[0xBB; 16]).unwrap();

        let params = Argon2Params {
            memory_kib: 1024,
            time: 1,
            parallelism: 1,
        };

        let key1 = argon2_derive(password, &salt, Some(params)).unwrap();
        let key2 = argon2_derive(password, &salt, Some(params)).unwrap();

        // Same password + salt = same key
        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_argon2_derive_different_passwords() {
        let salt = Salt::from_bytes(&[0xCC; 16]).unwrap();
        let params = Argon2Params {
            memory_kib: 1024,
            time: 1,
            parallelism: 1,
        };

        let key1 = argon2_derive(b"password1", &salt, Some(params)).unwrap();
        let key2 = argon2_derive(b"password2", &salt, Some(params)).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_argon2_derive_default_params() {
        let password = b"test";
        let salt = Salt::from_bytes(&[0xDD; 16]).unwrap();

        // Using default (None) will use production params - skip for speed
        // Just test that owasp_minimum works
        let owasp = Argon2Params::owasp_minimum();
        let result = argon2_derive(password, &salt, Some(owasp));
        assert!(result.is_ok());
    }
}
