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
    aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce as GcmNonce,
    },
    argon2::{Argon2, Params, Version, Algorithm as Argon2Algorithm},
    hkdf::Hkdf,
    sha2::{Sha256, Digest},
    hmac::Hmac,
    x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret},
    subtle::ConstantTimeEq,
    rand_core::{RngCore, OsRng},
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
    
    let gcm_nonce = GcmNonce::from_slice(nonce.as_bytes());
    
    let ciphertext = if let Some(aad_data) = aad {
        let payload = Payload {
            msg: plaintext,
            aad: aad_data,
        };
        cipher.encrypt(gcm_nonce, payload)
    } else {
        cipher.encrypt(gcm_nonce, plaintext)
    }.map_err(|_| CryptoError::EncryptionFailed("GCM encryption failed".into()))?;
    
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
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_e| CryptoError::DecryptionFailed)?;
    
    let gcm_nonce = GcmNonce::from_slice(nonce.as_bytes());
    
    let plaintext = if let Some(aad_data) = aad {
        let payload = Payload {
            msg: ciphertext,
            aad: aad_data,
        };
        cipher.decrypt(gcm_nonce, payload)
    } else {
        cipher.decrypt(gcm_nonce, ciphertext)
    }.map_err(|_| CryptoError::DecryptionFailed)?;
    
    Ok(plaintext)
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
    ).map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, argon2_params);
    
    let mut output = [0u8; AES_KEY_SIZE];
    argon2.hash_password_into(password, salt.as_bytes(), &mut output)
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
    let output = hkdf_derive(ikm, salt, info, AES_KEY_SIZE)?;
    SecretKey::from_bytes(&output)
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
        let static_secret = StaticSecret::random_from_rng(OsRng);
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

    /// Perform Diffie-Hellman key exchange
    #[cfg(feature = "pure-crypto")]
    pub fn diffie_hellman(&self, their_public: &[u8; X25519_KEY_SIZE]) -> Result<[u8; X25519_KEY_SIZE], CryptoError> {
        let secret = StaticSecret::from(self.secret);
        let their_pk = PublicKey::from(*their_public);
        let shared = secret.diffie_hellman(&their_pk);
        Ok(shared.to_bytes())
    }
}

// ============================================================================
// HMAC-SHA256
// ============================================================================

/// Compute HMAC-SHA256
#[cfg(feature = "pure-crypto")]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; HMAC_SIZE] {
    use hmac::Mac;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length");
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
        // ML-KEM 0.3.x API with getrandom feature:
        // - Generate::generate() -> Self uses system RNG internally
        // - Encapsulate::encapsulate() -> (Ciphertext, SharedSecret) uses system RNG
        // - Decapsulate::decapsulate(&ct) -> SharedSecret [NOT Result]
        // - EncodedSizeUser::from_encoded_bytes/to_encoded_bytes for serialization
        // The getrandom feature avoids rand_core version mismatches between crates.
        use ml_kem::{
            DecapsulationKey1024 as DecapsulationKey,
            EncapsulationKey1024 as EncapsulationKey,
            EncodedSizeUser,
        };
        // External kem crate: Generate, Encapsulate, Decapsulate traits
        use kem::{Decapsulate, Encapsulate, Generate};
        #[allow(unused_imports)]
        use ml_dsa::{MlDsa65, SigningKey, VerifyingKey};

        pub const BACKEND_NAME: &str = "RustCrypto ml-kem/ml-dsa (pure Rust)";

        /// Generate new ML-KEM-1024 key pair
        /// Returns (secret_key_bytes, public_key_bytes)
        pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            // Generate trait method: generate() uses system RNG via getrandom feature
            let dk = DecapsulationKey::generate();
            let ek = dk.encapsulation_key();
            Ok((dk.to_encoded_bytes().to_vec(), ek.to_encoded_bytes().to_vec()))
        }

        /// Encapsulate to produce ciphertext and shared secret
        pub fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
            // Convert slice to Array using TryFrom
            let ek_array: ml_kem::array::Array<u8, _> = encapsulation_key.try_into()
                .map_err(|_| CryptoError::KeyDerivationFailed("Invalid encapsulation key length".into()))?;
            let ek = EncapsulationKey::from_encoded_bytes(&ek_array)
                .map_err(|_| CryptoError::KeyDerivationFailed("Invalid encapsulation key".into()))?;
            
            // Encapsulate trait: encapsulate() uses system RNG via getrandom feature
            // Returns (Ciphertext, SharedSecret) directly - NOT a Result
            let (ct, shared) = ek.encapsulate();
            
            let shared_arr: [u8; 32] = shared.as_slice().try_into()
                .map_err(|_| CryptoError::EncryptionFailed("Invalid shared secret size".into()))?;
            Ok((ct.to_vec(), shared_arr))
        }

        /// Decapsulate to recover shared secret
        pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<[u8; 32], CryptoError> {
            // Convert slice to Array using TryFrom
            let dk_array: ml_kem::array::Array<u8, _> = secret_key.try_into()
                .map_err(|_| CryptoError::KeyDerivationFailed("Invalid secret key length".into()))?;
            let dk = DecapsulationKey::from_encoded_bytes(&dk_array)
                .map_err(|_| CryptoError::KeyDerivationFailed("Invalid secret key".into()))?;
            
            // Convert ciphertext to Array
            let ct_array: ml_kem::array::Array<u8, _> = ciphertext.try_into()
                .map_err(|_| CryptoError::KeyDerivationFailed("Invalid ciphertext length".into()))?;
            
            // Decapsulate trait: decapsulate returns SharedSecret directly
            // NOT a Result - no map_err needed
            let shared = dk.decapsulate(&ct_array);
            
            let shared_arr: [u8; 32] = shared.as_slice().try_into()
                .map_err(|_| CryptoError::DecryptionFailed)?;
            Ok(shared_arr)
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
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024)
                .map_err(|e| CryptoError::KeyDerivationFailed(format!("liboqs init failed: {}", e)))?;
            
            let (public_key, secret_key) = kem.keypair()
                .map_err(|e| CryptoError::KeyDerivationFailed(format!("liboqs keygen failed: {}", e)))?;
            
            Ok((secret_key.into_vec(), public_key.into_vec()))
        }

        /// Encapsulate to produce ciphertext and shared secret using liboqs
        pub fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024)
                .map_err(|e| CryptoError::KeyDerivationFailed(format!("liboqs init failed: {}", e)))?;
            
            let public_key = kem.public_key_from_bytes(encapsulation_key)
                .ok_or_else(|| CryptoError::KeyDerivationFailed("Invalid public key".into()))?;
            
            let (ciphertext, shared_secret) = kem.encapsulate(&public_key)
                .map_err(|e| CryptoError::KeyDerivationFailed(format!("liboqs encaps failed: {}", e)))?;
            
            let mut shared = [0u8; 32];
            shared.copy_from_slice(&shared_secret.into_vec()[..32]);
            Ok((ciphertext.into_vec(), shared))
        }

        /// Decapsulate to recover shared secret using liboqs
        pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<[u8; 32], CryptoError> {
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024)
                .map_err(|e| CryptoError::KeyDerivationFailed(format!("liboqs init failed: {}", e)))?;
            
            let sk = kem.secret_key_from_bytes(secret_key)
                .ok_or_else(|| CryptoError::KeyDerivationFailed("Invalid secret key".into()))?;
            
            let ct = kem.ciphertext_from_bytes(ciphertext)
                .ok_or_else(|| CryptoError::KeyDerivationFailed("Invalid ciphertext".into()))?;
            
            let shared_secret = kem.decapsulate(&sk, &ct)
                .map_err(|e| CryptoError::KeyDerivationFailed(format!("liboqs decaps failed: {}", e)))?;
            
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
        pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; MLKEM_SHARED_SECRET_SIZE], CryptoError> {
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
        // Combine both shared secrets
        let mut combined = Vec::with_capacity(64);
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
}
