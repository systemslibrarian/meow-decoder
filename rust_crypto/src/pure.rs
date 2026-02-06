//! Pure Rust crypto primitives without Python dependencies.
//!
//! This module provides testable crypto functions that can be covered by tarpaulin.
//! The PyO3 bindings in lib.rs delegate to these functions.

use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as HmacMac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};

type HmacSha256 = Hmac<Sha256>;

/// Error type for crypto operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid salt length
    InvalidSaltLength { expected: usize, got: usize },
    /// Invalid key length
    InvalidKeyLength { expected: usize, got: usize },
    /// Invalid nonce length
    InvalidNonceLength { expected: usize, got: usize },
    /// Ciphertext too short
    CiphertextTooShort,
    /// Invalid Argon2 parameters
    InvalidArgon2Params(String),
    /// Argon2 derivation failed
    Argon2Failed(String),
    /// HKDF failed
    HkdfFailed(String),
    /// Invalid PRK length
    InvalidPrkLength,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed (authentication error)
    DecryptionFailed,
    /// Invalid HMAC key
    InvalidHmacKey,
    /// Invalid ML-KEM public key
    InvalidMlKemPublicKey(String),
    /// Invalid ML-KEM private key
    InvalidMlKemPrivateKey(String),
    /// Invalid ML-KEM ciphertext
    InvalidMlKemCiphertext(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSaltLength { expected, got } => {
                write!(f, "Salt must be exactly {} bytes, got {}", expected, got)
            }
            Self::InvalidKeyLength { expected, got } => {
                write!(f, "Key must be {} bytes, got {}", expected, got)
            }
            Self::InvalidNonceLength { expected, got } => {
                write!(f, "Nonce must be {} bytes, got {}", expected, got)
            }
            Self::CiphertextTooShort => write!(f, "Ciphertext too short"),
            Self::InvalidArgon2Params(e) => write!(f, "Invalid Argon2 params: {}", e),
            Self::Argon2Failed(e) => write!(f, "Argon2id failed: {}", e),
            Self::HkdfFailed(e) => write!(f, "HKDF failed: {}", e),
            Self::InvalidPrkLength => write!(f, "Invalid PRK length"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed - authentication error"),
            Self::InvalidHmacKey => write!(f, "Invalid HMAC key length"),
            Self::InvalidMlKemPublicKey(e) => write!(f, "Invalid ML-KEM public key: {}", e),
            Self::InvalidMlKemPrivateKey(e) => write!(f, "Invalid ML-KEM private key: {}", e),
            Self::InvalidMlKemCiphertext(e) => write!(f, "Invalid ML-KEM ciphertext: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

// =============================================================================
// Argon2id Key Derivation
// =============================================================================

/// Derive a key using Argon2id.
pub fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    // Validate salt length - STRICT 16 BYTES
    if salt.len() != 16 {
        return Err(CryptoError::InvalidSaltLength {
            expected: 16,
            got: salt.len(),
        });
    }

    // Build Argon2id params
    let params = Params::new(memory_kib, iterations, parallelism, Some(output_len))
        .map_err(|e| CryptoError::InvalidArgon2Params(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive key
    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))?;

    Ok(output)
}

// =============================================================================
// HKDF (RFC 5869)
// =============================================================================

/// Derive key using HKDF with SHA-256.
pub fn derive_key_hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);

    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| CryptoError::HkdfFailed(format!("{:?}", e)))?;

    Ok(okm)
}

/// HKDF-Extract phase only.
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
    prk.to_vec()
}

/// HKDF-Expand phase only.
pub fn hkdf_expand(prk: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::InvalidPrkLength)?;

    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| CryptoError::HkdfFailed(format!("{:?}", e)))?;

    Ok(okm)
}

// =============================================================================
// AES-256-GCM
// =============================================================================

/// Encrypt data using AES-256-GCM.
pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    // Validate key length
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            got: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidNonceLength {
            expected: 12,
            got: nonce.len(),
        });
    }

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
        expected: 32,
        got: key.len(),
    })?;

    let nonce_arr = Nonce::from_slice(nonce);

    // Encrypt with AAD if provided
    let ciphertext = if let Some(aad_data) = aad {
        cipher.encrypt(
            nonce_arr,
            Payload {
                msg: plaintext,
                aad: aad_data,
            },
        )
    } else {
        cipher.encrypt(nonce_arr, plaintext)
    };

    ciphertext.map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt data using AES-256-GCM.
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    // Validate key length
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            got: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidNonceLength {
            expected: 12,
            got: nonce.len(),
        });
    }

    // Minimum ciphertext length (just auth tag)
    if ciphertext.len() < 16 {
        return Err(CryptoError::CiphertextTooShort);
    }

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
        expected: 32,
        got: key.len(),
    })?;

    let nonce_arr = Nonce::from_slice(nonce);

    // Decrypt with AAD if provided
    let plaintext = if let Some(aad_data) = aad {
        cipher.decrypt(
            nonce_arr,
            Payload {
                msg: ciphertext,
                aad: aad_data,
            },
        )
    } else {
        cipher.decrypt(nonce_arr, ciphertext)
    };

    plaintext.map_err(|_| CryptoError::DecryptionFailed)
}

// =============================================================================
// HMAC-SHA256
// =============================================================================

/// Compute HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut mac =
        <HmacSha256 as HmacMac>::new_from_slice(key).map_err(|_| CryptoError::InvalidHmacKey)?;
    mac.update(message);
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

/// Verify HMAC-SHA256 in constant time.
pub fn hmac_sha256_verify(key: &[u8], message: &[u8], expected_tag: &[u8]) -> Result<bool, CryptoError> {
    let mut mac =
        <HmacSha256 as HmacMac>::new_from_slice(key).map_err(|_| CryptoError::InvalidHmacKey)?;
    mac.update(message);
    let result = mac.finalize();

    // Constant-time comparison
    let computed = result.into_bytes();
    let is_valid = computed.as_slice().ct_eq(expected_tag);

    Ok(is_valid.into())
}

// =============================================================================
// SHA-256
// =============================================================================

/// Compute SHA-256 hash.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

/// Generate X25519 keypair.
/// Returns (private_key, public_key), both 32 bytes.
pub fn x25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    use rand::rngs::OsRng;

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    (*secret.as_bytes(), *public.as_bytes())
}

/// Perform X25519 key exchange.
pub fn x25519_exchange(
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<[u8; 32], CryptoError> {
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            got: private_key.len(),
        });
    }
    if peer_public_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            got: peer_public_key.len(),
        });
    }

    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(private_key);
    let secret = StaticSecret::from(priv_bytes);

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(peer_public_key);
    let public = PublicKey::from(pub_bytes);

    let shared = secret.diffie_hellman(&public);

    // Zeroize private key copy
    priv_bytes.zeroize();

    Ok(*shared.as_bytes())
}

/// Derive X25519 public key from private key.
pub fn x25519_public_from_private(private_key: &[u8]) -> Result<[u8; 32], CryptoError> {
    if private_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            got: private_key.len(),
        });
    }

    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(private_key);
    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);

    // Zeroize
    priv_bytes.zeroize();

    Ok(*public.as_bytes())
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Constant-time byte comparison.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Securely zero a mutable slice.
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Generate secure random bytes.
pub fn secure_random(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buffer = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut buffer);
    buffer
}

/// Get backend info.
pub fn backend_info() -> String {
    format!("meow_crypto_rs v{} (Rust)", env!("CARGO_PKG_VERSION"))
}

// =============================================================================
// ML-KEM-768 (Post-Quantum) - Kyber
// =============================================================================

/// Generate ML-KEM-768 keypair.
/// Returns (secret_key, public_key).
pub fn mlkem768_keygen() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mlkem768::keypair();
    (sk.as_bytes().to_vec(), pk.as_bytes().to_vec())
}

/// Encapsulate using ML-KEM-768.
/// Returns (shared_secret, ciphertext).
pub fn mlkem768_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Check key length
    if public_key.len() != mlkem768::public_key_bytes() {
        return Err(CryptoError::InvalidMlKemPublicKey(format!(
            "expected {}, got {}",
            mlkem768::public_key_bytes(),
            public_key.len()
        )));
    }

    let pk = mlkem768::PublicKey::from_bytes(public_key)
        .map_err(|e| CryptoError::InvalidMlKemPublicKey(format!("{:?}", e)))?;
    let (ss, ct) = mlkem768::encapsulate(&pk);
    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
}

/// Decapsulate using ML-KEM-768.
pub fn mlkem768_decapsulate(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Check lengths
    if private_key.len() != mlkem768::secret_key_bytes() {
        return Err(CryptoError::InvalidMlKemPrivateKey(format!(
            "expected {}, got {}",
            mlkem768::secret_key_bytes(),
            private_key.len()
        )));
    }
    if ciphertext.len() != mlkem768::ciphertext_bytes() {
        return Err(CryptoError::InvalidMlKemCiphertext(format!(
            "expected {}, got {}",
            mlkem768::ciphertext_bytes(),
            ciphertext.len()
        )));
    }

    let sk = mlkem768::SecretKey::from_bytes(private_key)
        .map_err(|e| CryptoError::InvalidMlKemPrivateKey(format!("{:?}", e)))?;
    let ct = mlkem768::Ciphertext::from_bytes(ciphertext)
        .map_err(|e| CryptoError::InvalidMlKemCiphertext(format!("{:?}", e)))?;
    let ss = mlkem768::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

// =============================================================================
// Unit Tests (for coverage)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Argon2id Tests
    // =========================================================================

    #[test]
    fn test_argon2id_basic() {
        let password = b"test_password";
        let salt = [0u8; 16];
        let key = derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_argon2id_deterministic() {
        let password = b"test_password";
        let salt = [0x42u8; 16];
        let key1 = derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
        let key2 = derive_key_argon2id(password, &salt, 1024, 1, 1, 32).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_argon2id_invalid_salt() {
        let password = b"test";
        let short_salt = [0u8; 15];
        let result = derive_key_argon2id(password, &short_salt, 1024, 1, 1, 32);
        assert!(matches!(result, Err(CryptoError::InvalidSaltLength { .. })));
    }

    #[test]
    fn test_argon2id_different_passwords() {
        let salt = [0u8; 16];
        let key1 = derive_key_argon2id(b"password1", &salt, 1024, 1, 1, 32).unwrap();
        let key2 = derive_key_argon2id(b"password2", &salt, 1024, 1, 1, 32).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_argon2id_different_salts() {
        let password = b"password";
        let key1 = derive_key_argon2id(password, &[0x11u8; 16], 1024, 1, 1, 32).unwrap();
        let key2 = derive_key_argon2id(password, &[0x22u8; 16], 1024, 1, 1, 32).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_argon2id_empty_password() {
        let salt = [0u8; 16];
        let key = derive_key_argon2id(b"", &salt, 1024, 1, 1, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2id_various_output_lengths() {
        let password = b"test";
        let salt = [0u8; 16];
        for len in [16, 32, 48, 64] {
            let key = derive_key_argon2id(password, &salt, 1024, 1, 1, len).unwrap();
            assert_eq!(key.len(), len);
        }
    }

    // =========================================================================
    // HKDF Tests
    // =========================================================================

    #[test]
    fn test_hkdf_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context info";
        let okm = derive_key_hkdf(ikm, Some(salt), info, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"input key material";
        let okm = derive_key_hkdf(ikm, None, b"info", 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_extract() {
        let prk = hkdf_extract(Some(b"salt"), b"ikm");
        assert_eq!(prk.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_hkdf_expand() {
        let prk = hkdf_extract(Some(b"salt"), b"ikm");
        let okm = hkdf_expand(&prk, b"info", 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_hkdf_expand_invalid_prk() {
        let result = hkdf_expand(&[0u8; 10], b"info", 32);
        assert!(matches!(result, Err(CryptoError::InvalidPrkLength)));
    }

    #[test]
    fn test_hkdf_deterministic() {
        let okm1 = derive_key_hkdf(b"ikm", Some(b"salt"), b"info", 32).unwrap();
        let okm2 = derive_key_hkdf(b"ikm", Some(b"salt"), b"info", 32).unwrap();
        assert_eq!(okm1, okm2);
    }

    // =========================================================================
    // AES-GCM Tests
    // =========================================================================

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Hello, world!";
        let aad = b"additional data";

        let ct = aes_gcm_encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, Some(aad)).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_gcm_no_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"Secret message";

        let ct = aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_gcm_invalid_key_length() {
        let short_key = [0u8; 31];
        let nonce = [0u8; 12];
        let result = aes_gcm_encrypt(&short_key, &nonce, b"test", None);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_aes_gcm_invalid_nonce_length() {
        let key = [0u8; 32];
        let short_nonce = [0u8; 11];
        let result = aes_gcm_encrypt(&key, &short_nonce, b"test", None);
        assert!(matches!(result, Err(CryptoError::InvalidNonceLength { .. })));
    }

    #[test]
    fn test_aes_gcm_ciphertext_too_short() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let short_ct = [0u8; 15]; // Less than tag size
        let result = aes_gcm_decrypt(&key, &nonce, &short_ct, None);
        assert!(matches!(result, Err(CryptoError::CiphertextTooShort)));
    }

    #[test]
    fn test_aes_gcm_wrong_key_fails() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret";

        let ct = aes_gcm_encrypt(&key1, &nonce, plaintext, None).unwrap();
        let result = aes_gcm_decrypt(&key2, &nonce, &ct, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_aes_gcm_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret";

        let ct = aes_gcm_encrypt(&key, &nonce, plaintext, Some(b"aad1")).unwrap();
        let result = aes_gcm_decrypt(&key, &nonce, &ct, Some(b"aad2"));
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret";

        let mut ct = aes_gcm_encrypt(&key, &nonce, plaintext, None).unwrap();
        ct[0] ^= 0xFF;
        let result = aes_gcm_decrypt(&key, &nonce, &ct, None);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];

        let ct = aes_gcm_encrypt(&key, &nonce, &[], None).unwrap();
        assert_eq!(ct.len(), 16); // Just the tag
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, None).unwrap();
        assert!(pt.is_empty());
    }

    // =========================================================================
    // HMAC Tests
    // =========================================================================

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let message = b"message";
        let tag = hmac_sha256(key, message).unwrap();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_verify() {
        let key = b"secret key";
        let message = b"message";
        let tag = hmac_sha256(key, message).unwrap();
        assert!(hmac_sha256_verify(key, message, &tag).unwrap());
    }

    #[test]
    fn test_hmac_sha256_verify_fails_wrong_tag() {
        let key = b"secret key";
        let message = b"message";
        let mut tag = hmac_sha256(key, message).unwrap();
        tag[0] ^= 0xFF;
        assert!(!hmac_sha256_verify(key, message, &tag).unwrap());
    }

    #[test]
    fn test_hmac_deterministic() {
        let key = b"key";
        let message = b"msg";
        let tag1 = hmac_sha256(key, message).unwrap();
        let tag2 = hmac_sha256(key, message).unwrap();
        assert_eq!(tag1, tag2);
    }

    // =========================================================================
    // SHA-256 Tests
    // =========================================================================

    #[test]
    fn test_sha256() {
        let hash = sha256(b"abc");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_deterministic() {
        let h1 = sha256(b"test");
        let h2 = sha256(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_different_inputs() {
        let h1 = sha256(b"test1");
        let h2 = sha256(b"test2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(hash.len(), 32);
    }

    // =========================================================================
    // X25519 Tests
    // =========================================================================

    #[test]
    fn test_x25519_keypair() {
        let (priv_key, pub_key) = x25519_generate_keypair();
        assert_eq!(priv_key.len(), 32);
        assert_eq!(pub_key.len(), 32);
    }

    #[test]
    fn test_x25519_exchange() {
        let (priv_a, pub_a) = x25519_generate_keypair();
        let (priv_b, pub_b) = x25519_generate_keypair();

        let shared_a = x25519_exchange(&priv_a, &pub_b).unwrap();
        let shared_b = x25519_exchange(&priv_b, &pub_a).unwrap();
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_x25519_public_from_private() {
        let (priv_key, pub_key) = x25519_generate_keypair();
        let derived_pub = x25519_public_from_private(&priv_key).unwrap();
        assert_eq!(derived_pub, pub_key);
    }

    #[test]
    fn test_x25519_invalid_key_length() {
        let short_key = [0u8; 31];
        let result = x25519_exchange(&short_key, &[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_x25519_public_invalid_key_length() {
        let short_key = [0u8; 31];
        let result = x25519_public_from_private(&short_key);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    // =========================================================================
    // Utility Tests
    // =========================================================================

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"abc", b"abc"));
        assert!(!constant_time_compare(b"abc", b"abd"));
        assert!(!constant_time_compare(b"abc", b"abcd"));
    }

    #[test]
    fn test_secure_zero() {
        let mut data = [0xFFu8; 32];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_random() {
        let r1 = secure_random(32);
        let r2 = secure_random(32);
        assert_eq!(r1.len(), 32);
        assert_eq!(r2.len(), 32);
        assert_ne!(r1, r2); // Extremely unlikely to be equal
    }

    #[test]
    fn test_backend_info() {
        let info = backend_info();
        assert!(info.contains("meow_crypto_rs"));
        assert!(info.contains("Rust"));
    }

    // =========================================================================
    // ML-KEM Tests
    // =========================================================================

    #[test]
    fn test_mlkem768_keygen() {
        let (sk, pk) = mlkem768_keygen();
        assert!(!sk.is_empty());
        assert!(!pk.is_empty());
    }

    #[test]
    fn test_mlkem768_roundtrip() {
        let (sk, pk) = mlkem768_keygen();
        let (ss1, ct) = mlkem768_encapsulate(&pk).unwrap();
        let ss2 = mlkem768_decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_mlkem768_invalid_public_key() {
        let result = mlkem768_encapsulate(&[0u8; 100]);
        assert!(matches!(result, Err(CryptoError::InvalidMlKemPublicKey(_))));
    }

    #[test]
    fn test_mlkem768_invalid_private_key() {
        let (_, pk) = mlkem768_keygen();
        let (_, ct) = mlkem768_encapsulate(&pk).unwrap();
        let result = mlkem768_decapsulate(&[0u8; 100], &ct);
        assert!(matches!(result, Err(CryptoError::InvalidMlKemPrivateKey(_))));
    }

    #[test]
    fn test_mlkem768_invalid_ciphertext() {
        let (sk, _) = mlkem768_keygen();
        let result = mlkem768_decapsulate(&sk, &[0u8; 100]);
        assert!(matches!(result, Err(CryptoError::InvalidMlKemCiphertext(_))));
    }

    // =========================================================================
    // CryptoError Display Tests
    // =========================================================================

    #[test]
    fn test_crypto_error_display() {
        let errors = vec![
            CryptoError::InvalidSaltLength { expected: 16, got: 10 },
            CryptoError::InvalidKeyLength { expected: 32, got: 16 },
            CryptoError::InvalidNonceLength { expected: 12, got: 8 },
            CryptoError::CiphertextTooShort,
            CryptoError::InvalidArgon2Params("bad param".into()),
            CryptoError::Argon2Failed("failed".into()),
            CryptoError::HkdfFailed("failed".into()),
            CryptoError::InvalidPrkLength,
            CryptoError::EncryptionFailed,
            CryptoError::DecryptionFailed,
            CryptoError::InvalidHmacKey,
            CryptoError::InvalidMlKemPublicKey("bad".into()),
            CryptoError::InvalidMlKemPrivateKey("bad".into()),
            CryptoError::InvalidMlKemCiphertext("bad".into()),
        ];

        for err in errors {
            let display = format!("{}", err);
            assert!(!display.is_empty());
            // Also test Debug
            let debug = format!("{:?}", err);
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_crypto_error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(CryptoError::EncryptionFailed);
        assert!(!err.to_string().is_empty());
    }
}
