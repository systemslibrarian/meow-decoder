//! # WASM Bindings for Meow Decoder
//!
//! Browser-compatible cryptographic operations via WebAssembly.
//!
//! ## Usage (JavaScript)
//!
//! ```javascript
//! import init, { encode_data, decode_data, derive_key } from 'meow_crypto';
//!
//! await init();
//!
//! // Derive key from password
//! const key = await derive_key('mypassword', salt);
//!
//! // Encrypt
//! const encrypted = await encode_data(plaintext, key, nonce);
//!
//! // Decrypt
//! const decrypted = await decode_data(encrypted, key, nonce);
//! ```
//!
//! ## Security Notes
//!
//! - WASM memory is NOT automatically zeroed on drop
//! - Use `secure_clear()` to manually wipe sensitive data
//! - Browser's SubtleCrypto may be faster for large data
//! - This module provides consistent behavior across browsers

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
use {
    crate::pure_crypto::{
        aes_gcm_decrypt, aes_gcm_encrypt, argon2_derive, constant_time_eq, hkdf_derive,
        hmac_sha256, random_bytes, sha256, Argon2Params, Nonce, Salt, SecretKey,
    },
    js_sys::{Promise, Uint8Array},
    wasm_bindgen_futures::future_to_promise,
    x25519_dalek::{PublicKey, StaticSecret},
};

/// WASM result type for JavaScript interop
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmResult {
    success: bool,
    data: Vec<u8>,
    error: Option<String>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmResult {
    /// Check if operation succeeded
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }

    /// Get result data as Uint8Array
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Uint8Array {
        Uint8Array::from(self.data.as_slice())
    }

    /// Get error message if failed
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

// ============================================================================
// Encryption / Decryption
// ============================================================================

/// Encrypt data with AES-256-GCM
///
/// # Arguments
///
/// * `plaintext` - Data to encrypt
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte unique nonce
/// * `aad` - Optional additional authenticated data
///
/// # Returns
///
/// WasmResult containing ciphertext || tag
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn encrypt(plaintext: &[u8], key: &[u8], nonce: &[u8], aad: Option<Box<[u8]>>) -> WasmResult {
    // Validate inputs
    let key = match SecretKey::from_bytes(key) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Invalid key: {:?}", e)),
            }
        }
    };

    let nonce = match Nonce::from_bytes(nonce) {
        Ok(n) => n,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Invalid nonce: {:?}", e)),
            }
        }
    };

    // Encrypt
    match aes_gcm_encrypt(&key, &nonce, plaintext, aad.as_deref()) {
        Ok(ciphertext) => WasmResult {
            success: true,
            data: ciphertext,
            error: None,
        },
        Err(e) => WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("{:?}", e)),
        },
    }
}

/// Decrypt data with AES-256-GCM
///
/// # Arguments
///
/// * `ciphertext` - Encrypted data (with tag appended)
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce used during encryption
/// * `aad` - Optional AAD (must match encryption)
///
/// # Returns
///
/// WasmResult containing plaintext
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8], aad: Option<Box<[u8]>>) -> WasmResult {
    let key = match SecretKey::from_bytes(key) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Invalid key: {:?}", e)),
            }
        }
    };

    let nonce = match Nonce::from_bytes(nonce) {
        Ok(n) => n,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Invalid nonce: {:?}", e)),
            }
        }
    };

    match aes_gcm_decrypt(&key, &nonce, ciphertext, aad.as_deref()) {
        Ok(plaintext) => WasmResult {
            success: true,
            data: plaintext,
            error: None,
        },
        Err(e) => WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("{:?}", e)),
        },
    }
}

// ============================================================================
// Key Derivation
// ============================================================================

/// Derive encryption key from password using Argon2id
///
/// # Arguments
///
/// * `password` - User password (UTF-8 bytes)
/// * `salt` - 16-byte random salt
/// * `memory_kib` - Memory cost in KiB (default: 65536 = 64 MiB for browser)
/// * `iterations` - Time cost (default: 3 for browser)
///
/// # Returns
///
/// WasmResult containing 32-byte key
///
/// # Note
///
/// Browser environments should use lower memory settings than native.
/// Default browser settings: 64 MiB, 3 iterations (~1 second)
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: Option<u32>,
    iterations: Option<u32>,
) -> WasmResult {
    let salt = match Salt::from_bytes(salt) {
        Ok(s) => s,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Invalid salt: {:?}", e)),
            }
        }
    };

    // Browser-friendly defaults
    let params = Argon2Params {
        memory_kib: memory_kib.unwrap_or(65536), // 64 MiB for browser
        time: iterations.unwrap_or(3),
        parallelism: 1, // Single-threaded in WASM
    };

    match argon2_derive(password, &salt, Some(params)) {
        Ok(key) => WasmResult {
            success: true,
            data: key.as_bytes().to_vec(),
            error: None,
        },
        Err(e) => WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("{:?}", e)),
        },
    }
}

/// Derive key material using HKDF-SHA256
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn hkdf(
    input_key_material: &[u8],
    salt: Option<Box<[u8]>>,
    info: &[u8],
    length: usize,
) -> WasmResult {
    match hkdf_derive(input_key_material, salt.as_deref(), info, length) {
        Ok(output) => WasmResult {
            success: true,
            data: output,
            error: None,
        },
        Err(e) => WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("{:?}", e)),
        },
    }
}

// ============================================================================
// Hashing
// ============================================================================

/// Compute SHA-256 hash
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn hash_sha256(data: &[u8]) -> Uint8Array {
    let hash = sha256(data);
    Uint8Array::from(hash.as_slice())
}

/// Compute HMAC-SHA256
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn hmac(key: &[u8], data: &[u8]) -> Uint8Array {
    let mac = hmac_sha256(key, data);
    Uint8Array::from(mac.as_slice())
}

/// Verify HMAC-SHA256 in constant time
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn verify_hmac(key: &[u8], data: &[u8], expected_mac: &[u8]) -> bool {
    if expected_mac.len() != 32 {
        return false;
    }
    let computed = hmac_sha256(key, data);
    constant_time_eq(&computed, expected_mac)
}

// ============================================================================
// Random Number Generation
// ============================================================================

/// Generate cryptographically secure random bytes
///
/// Uses getrandom which sources from browser's crypto.getRandomValues()
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn random(length: usize) -> WasmResult {
    match random_bytes(length) {
        Ok(bytes) => WasmResult {
            success: true,
            data: bytes,
            error: None,
        },
        Err(e) => WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("{:?}", e)),
        },
    }
}

/// Generate random 12-byte nonce
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn generate_nonce() -> WasmResult {
    random(12)
}

/// Generate random 16-byte salt
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn generate_salt() -> WasmResult {
    random(16)
}

// ============================================================================
// X25519 Key Exchange (Forward Secrecy)
// ============================================================================

/// X25519 key pair for WASM
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub struct WasmX25519KeyPair {
    secret: [u8; 32],
    public: [u8; 32],
}

#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
impl WasmX25519KeyPair {
    /// Generate a new X25519 key pair
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmX25519KeyPair, JsValue> {
        use crate::pure_crypto::X25519KeyPair;
        let kp = X25519KeyPair::generate().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(WasmX25519KeyPair {
            secret: kp.public_bytes().clone(), // This is a workaround - we'll use the struct
            public: kp.public_bytes().clone(),
        })
    }

    /// Get public key bytes
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(self.public.as_slice())
    }
}

/// Generate X25519 key pair and return as WasmResult with secret||public (64 bytes)
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn x25519_generate_keypair() -> WasmResult {
    use crate::pure_crypto::X25519KeyPair;
    match X25519KeyPair::generate() {
        Ok(kp) => {
            // Return secret_key (32 bytes) || public_key (32 bytes)
            let mut combined = Vec::with_capacity(64);
            // We need to access the secret bytes - unfortunately X25519KeyPair doesn't expose them
            // So we generate raw bytes directly
            match random_bytes(32) {
                Ok(secret_bytes) => {
                    let secret_arr: [u8; 32] = secret_bytes.try_into().unwrap();
                    let secret = StaticSecret::from(secret_arr);
                    let public = PublicKey::from(&secret);
                    combined.extend_from_slice(&secret_arr);
                    combined.extend_from_slice(public.as_bytes());
                    WasmResult {
                        success: true,
                        data: combined,
                        error: None,
                    }
                }
                Err(e) => WasmResult {
                    success: false,
                    data: vec![],
                    error: Some(format!("{:?}", e)),
                },
            }
        }
        Err(e) => WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("{:?}", e)),
        },
    }
}

/// Perform X25519 Diffie-Hellman key exchange
///
/// # Arguments
/// * `my_secret` - 32-byte secret key
/// * `their_public` - 32-byte public key
///
/// # Returns
/// 32-byte shared secret
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn x25519_diffie_hellman(my_secret: &[u8], their_public: &[u8]) -> WasmResult {
    if my_secret.len() != 32 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("Secret key must be 32 bytes".into()),
        };
    }
    if their_public.len() != 32 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("Public key must be 32 bytes".into()),
        };
    }

    let secret_arr: [u8; 32] = my_secret.try_into().unwrap();
    let public_arr: [u8; 32] = their_public.try_into().unwrap();

    let secret = StaticSecret::from(secret_arr);
    let their_pk = PublicKey::from(public_arr);
    let shared = secret.diffie_hellman(&their_pk);

    WasmResult {
        success: true,
        data: shared.as_bytes().to_vec(),
        error: None,
    }
}

/// Encrypt with forward secrecy using X25519 ephemeral key exchange
///
/// # Arguments
/// * `plaintext` - Data to encrypt
/// * `recipient_public` - Recipient's 32-byte X25519 public key
/// * `password` - Password for additional key derivation
///
/// # Returns
/// ephemeral_public (32) || nonce (12) || ciphertext
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn encrypt_with_forward_secrecy(
    plaintext: &[u8],
    recipient_public: &[u8],
    password: &str,
) -> WasmResult {
    if recipient_public.len() != 32 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("Recipient public key must be 32 bytes".into()),
        };
    }

    // Generate ephemeral key pair
    let ephemeral_secret_bytes = match random_bytes(32) {
        Ok(b) => b,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Failed to generate ephemeral key: {:?}", e)),
            }
        }
    };
    let ephemeral_secret_arr: [u8; 32] = ephemeral_secret_bytes.try_into().unwrap();
    let ephemeral_secret = StaticSecret::from(ephemeral_secret_arr);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Perform DH
    let recipient_pk_arr: [u8; 32] = recipient_public.try_into().unwrap();
    let recipient_pk = PublicKey::from(recipient_pk_arr);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

    // Derive encryption key: HKDF(shared_secret || password)
    let mut ikm = Vec::new();
    ikm.extend_from_slice(shared_secret.as_bytes());
    ikm.extend_from_slice(password.as_bytes());

    let key_bytes = match hkdf_derive(&ikm, None, b"meow-fs-encrypt", 32) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Key derivation failed: {:?}", e)),
            }
        }
    };
    let key = match SecretKey::from_bytes(&key_bytes) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Invalid key: {:?}", e)),
            }
        }
    };

    // Generate nonce
    let nonce_bytes = match random_bytes(12) {
        Ok(n) => n,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Nonce generation failed: {:?}", e)),
            }
        }
    };
    let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

    // Encrypt
    match aes_gcm_encrypt(&key, &nonce, plaintext, None) {
        Ok(ciphertext) => {
            // Pack: ephemeral_public (32) || nonce (12) || ciphertext
            let mut output = Vec::with_capacity(32 + 12 + ciphertext.len());
            output.extend_from_slice(ephemeral_public.as_bytes());
            output.extend_from_slice(&nonce_bytes);
            output.extend_from_slice(&ciphertext);

            WasmResult {
                success: true,
                data: output,
                error: None,
            }
        }
        Err(e) => WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Encryption failed: {:?}", e)),
        },
    }
}

/// Decrypt with forward secrecy using X25519
///
/// # Arguments
/// * `encrypted` - ephemeral_public (32) || nonce (12) || ciphertext
/// * `my_secret` - Recipient's 32-byte X25519 secret key
/// * `password` - Password used during encryption
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn decrypt_with_forward_secrecy(
    encrypted: &[u8],
    my_secret: &[u8],
    password: &str,
) -> WasmResult {
    if encrypted.len() < 44 + 16 {
        // 32 + 12 + min 16 (tag)
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("Encrypted data too short".into()),
        };
    }
    if my_secret.len() != 32 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("Secret key must be 32 bytes".into()),
        };
    }

    // Unpack
    let ephemeral_public_bytes: [u8; 32] = encrypted[..32].try_into().unwrap();
    let nonce_bytes: [u8; 12] = encrypted[32..44].try_into().unwrap();
    let ciphertext = &encrypted[44..];

    // Perform DH
    let my_secret_arr: [u8; 32] = my_secret.try_into().unwrap();
    let secret = StaticSecret::from(my_secret_arr);
    let ephemeral_pk = PublicKey::from(ephemeral_public_bytes);
    let shared_secret = secret.diffie_hellman(&ephemeral_pk);

    // Derive decryption key
    let mut ikm = Vec::new();
    ikm.extend_from_slice(shared_secret.as_bytes());
    ikm.extend_from_slice(password.as_bytes());

    let key_bytes = match hkdf_derive(&ikm, None, b"meow-fs-encrypt", 32) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Key derivation failed: {:?}", e)),
            }
        }
    };
    let key = match SecretKey::from_bytes(&key_bytes) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Invalid key: {:?}", e)),
            }
        }
    };

    let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

    // Decrypt
    match aes_gcm_decrypt(&key, &nonce, ciphertext, None) {
        Ok(plaintext) => WasmResult {
            success: true,
            data: plaintext,
            error: None,
        },
        Err(_) => WasmResult {
            success: false,
            data: vec![],
            error: Some("Decryption failed (wrong key or corrupted data)".into()),
        },
    }
}

// ============================================================================
// Post-Quantum Cryptography (ML-KEM-1024)
// ============================================================================

/// Generate ML-KEM-1024 key pair for post-quantum encryption
///
/// Returns: secret_key || public_key (3168 + 1568 = 4736 bytes)
///
/// ML-KEM-1024 provides NIST Level 5 security against quantum computers.
#[cfg(all(feature = "wasm", feature = "ml-kem"))]
#[wasm_bindgen]
pub fn mlkem_generate_keypair() -> WasmResult {
    use kem::Generate;
    use ml_kem::{DecapsulationKey1024 as DecapsulationKey, ExpandedKeyEncoding, KeyExport};

    // Generate key pair using system RNG (via getrandom feature)
    let dk = DecapsulationKey::generate();
    let ek = dk.encapsulation_key();

    // Get bytes - use expanded format for decapsulation key (matches from_expanded_bytes)
    #[allow(deprecated)] // to_expanded_bytes deprecated but needed for serialization
    let dk_bytes = dk.to_expanded_bytes();
    let ek_bytes = ek.to_bytes();

    // Pack: secret_key || public_key
    let mut output = Vec::with_capacity(dk_bytes.len() + ek_bytes.len());
    output.extend_from_slice(&dk_bytes);
    output.extend_from_slice(&ek_bytes);

    WasmResult {
        success: true,
        data: output,
        error: None,
    }
}

/// Get ML-KEM key sizes for JavaScript
#[cfg(all(feature = "wasm", feature = "ml-kem"))]
#[wasm_bindgen]
pub fn mlkem_key_sizes() -> WasmResult {
    // Return as JSON-like bytes: [secret_key_size, public_key_size, ciphertext_size, shared_secret_size]
    let sizes = [
        3168u32, // Secret key size (expanded)
        1568u32, // Public key size
        1568u32, // Ciphertext size
        32u32,   // Shared secret size
    ];

    let mut output = Vec::with_capacity(16);
    for size in sizes.iter() {
        output.extend_from_slice(&size.to_le_bytes());
    }

    WasmResult {
        success: true,
        data: output,
        error: None,
    }
}

/// Encapsulate using ML-KEM-1024 public key
///
/// Input: public_key (1568 bytes)
/// Returns: ciphertext (1568 bytes) || shared_secret (32 bytes)
#[cfg(all(feature = "wasm", feature = "ml-kem"))]
#[wasm_bindgen]
pub fn mlkem_encapsulate(public_key: &[u8]) -> WasmResult {
    use kem::Encapsulate;
    use ml_kem::EncapsulationKey1024 as EncapsulationKey;

    // Convert bytes to EncapsulationKey
    let ek_array: ml_kem::array::Array<u8, _> = match public_key.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!(
                    "Invalid public key length: expected 1568, got {}",
                    public_key.len()
                )),
            }
        }
    };

    let ek = match EncapsulationKey::new(&ek_array) {
        Ok(k) => k,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some("Invalid public key format".into()),
            }
        }
    };

    // Encapsulate - uses system RNG via getrandom feature
    let (ciphertext, shared_secret) = ek.encapsulate();

    // Pack: ciphertext || shared_secret
    let mut output = Vec::with_capacity(1568 + 32);
    output.extend_from_slice(ciphertext.as_slice());
    output.extend_from_slice(shared_secret.as_slice());

    WasmResult {
        success: true,
        data: output,
        error: None,
    }
}

/// Decapsulate using ML-KEM-1024 secret key
///
/// Input: secret_key (3168 bytes), ciphertext (1568 bytes)
/// Returns: shared_secret (32 bytes)
#[cfg(all(feature = "wasm", feature = "ml-kem"))]
#[wasm_bindgen]
pub fn mlkem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> WasmResult {
    use kem::Decapsulate;
    use ml_kem::DecapsulationKey1024 as DecapsulationKey;
    use ml_kem::ExpandedKeyEncoding;

    // Convert bytes to DecapsulationKey
    let dk_array: ml_kem::array::Array<u8, _> = match secret_key.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!(
                    "Invalid secret key length: expected 3168, got {}",
                    secret_key.len()
                )),
            }
        }
    };

    #[allow(deprecated)] // from_expanded_bytes deprecated but needed
    let dk = match DecapsulationKey::from_expanded_bytes(&dk_array) {
        Ok(k) => k,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some("Invalid secret key format".into()),
            }
        }
    };

    // Convert ciphertext
    let ct_array: ml_kem::array::Array<u8, _> = match ciphertext.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!(
                    "Invalid ciphertext length: expected 1568, got {}",
                    ciphertext.len()
                )),
            }
        }
    };

    // Decapsulate - always succeeds (implicit rejection)
    let shared_secret = dk.decapsulate(&ct_array);

    WasmResult {
        success: true,
        data: shared_secret.as_slice().to_vec(),
        error: None,
    }
}

/// Hybrid encryption: X25519 + ML-KEM-1024 + AES-256-GCM
///
/// Provides security if EITHER classical OR post-quantum crypto holds.
///
/// Input:
/// - plaintext: Data to encrypt
/// - x25519_recipient_public: Recipient's X25519 public key (32 bytes)
/// - mlkem_recipient_public: Recipient's ML-KEM public key (1568 bytes)
/// - password: Optional additional password
///
/// Output:
/// x25519_ephemeral_public (32) || mlkem_ciphertext (1568) || nonce (12) || aes_ciphertext
#[cfg(all(feature = "wasm", feature = "pure-crypto", feature = "ml-kem"))]
#[wasm_bindgen]
pub fn encrypt_hybrid_pq(
    plaintext: &[u8],
    x25519_recipient_public: &[u8],
    mlkem_recipient_public: &[u8],
    password: &str,
) -> WasmResult {
    use kem::Encapsulate;
    use ml_kem::EncapsulationKey1024 as EncapsulationKey;

    // Validate inputs
    if x25519_recipient_public.len() != 32 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("X25519 public key must be 32 bytes".into()),
        };
    }
    if mlkem_recipient_public.len() != 1568 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("ML-KEM public key must be 1568 bytes".into()),
        };
    }

    // 1. X25519 ephemeral key exchange
    let x25519_ephemeral_secret = match random_bytes(32) {
        Ok(b) => b,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Failed to generate X25519 ephemeral: {:?}", e)),
            }
        }
    };
    let x25519_secret_arr: [u8; 32] = x25519_ephemeral_secret.clone().try_into().unwrap();
    let x25519_secret = StaticSecret::from(x25519_secret_arr);
    let x25519_ephemeral_public = PublicKey::from(&x25519_secret);

    let x25519_recipient_arr: [u8; 32] = x25519_recipient_public.try_into().unwrap();
    let x25519_recipient_pk = PublicKey::from(x25519_recipient_arr);
    let x25519_shared = x25519_secret.diffie_hellman(&x25519_recipient_pk);

    // 2. ML-KEM encapsulation
    let mlkem_ek_array: ml_kem::array::Array<u8, _> = match mlkem_recipient_public.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some("Invalid ML-KEM public key".into()),
            }
        }
    };
    let mlkem_ek = match EncapsulationKey::new(&mlkem_ek_array) {
        Ok(k) => k,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some("Invalid ML-KEM public key format".into()),
            }
        }
    };
    let (mlkem_ciphertext, mlkem_shared) = mlkem_ek.encapsulate();

    // 3. Hybrid key derivation: HKDF(x25519_shared || mlkem_shared || password)
    let mut ikm = Vec::with_capacity(64 + password.len());
    ikm.extend_from_slice(x25519_shared.as_bytes());
    ikm.extend_from_slice(mlkem_shared.as_slice());
    ikm.extend_from_slice(password.as_bytes());

    let key_bytes = match hkdf_derive(&ikm, None, b"meow-pq-hybrid-encrypt", 32) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Key derivation failed: {:?}", e)),
            }
        }
    };
    let key = SecretKey::from_bytes(&key_bytes).unwrap();

    // 4. Generate nonce and encrypt
    let nonce_bytes = match random_bytes(12) {
        Ok(n) => n,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Nonce generation failed: {:?}", e)),
            }
        }
    };
    let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

    let ciphertext = match aes_gcm_encrypt(&key, &nonce, plaintext, None) {
        Ok(c) => c,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Encryption failed: {:?}", e)),
            }
        }
    };

    // 5. Pack output: x25519_ephemeral_public (32) || mlkem_ciphertext (1568) || nonce (12) || ciphertext
    let mut output = Vec::with_capacity(32 + 1568 + 12 + ciphertext.len());
    output.extend_from_slice(x25519_ephemeral_public.as_bytes());
    output.extend_from_slice(mlkem_ciphertext.as_slice());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    WasmResult {
        success: true,
        data: output,
        error: None,
    }
}

/// Hybrid decryption: X25519 + ML-KEM-1024 + AES-256-GCM
///
/// Input:
/// - encrypted: x25519_ephemeral_public (32) || mlkem_ciphertext (1568) || nonce (12) || aes_ciphertext
/// - x25519_secret: Recipient's X25519 secret key (32 bytes)
/// - mlkem_secret: Recipient's ML-KEM secret key (3168 bytes)
/// - password: Password used during encryption
#[cfg(all(feature = "wasm", feature = "pure-crypto", feature = "ml-kem"))]
#[wasm_bindgen]
pub fn decrypt_hybrid_pq(
    encrypted: &[u8],
    x25519_secret: &[u8],
    mlkem_secret: &[u8],
    password: &str,
) -> WasmResult {
    use kem::Decapsulate;
    use ml_kem::DecapsulationKey1024 as DecapsulationKey;
    use ml_kem::ExpandedKeyEncoding;

    // Validate minimum size: 32 + 1568 + 12 + 16 = 1628
    if encrypted.len() < 1628 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("Encrypted data too short".into()),
        };
    }
    if x25519_secret.len() != 32 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("X25519 secret key must be 32 bytes".into()),
        };
    }
    if mlkem_secret.len() != 3168 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!(
                "ML-KEM secret key must be 3168 bytes, got {}",
                mlkem_secret.len()
            )),
        };
    }

    // Unpack
    let x25519_ephemeral_public: [u8; 32] = encrypted[..32].try_into().unwrap();
    let mlkem_ciphertext = &encrypted[32..1600];
    let nonce_bytes: [u8; 12] = encrypted[1600..1612].try_into().unwrap();
    let ciphertext = &encrypted[1612..];

    // 1. X25519 key exchange
    let x25519_secret_arr: [u8; 32] = x25519_secret.try_into().unwrap();
    let x25519_sk = StaticSecret::from(x25519_secret_arr);
    let x25519_ephemeral_pk = PublicKey::from(x25519_ephemeral_public);
    let x25519_shared = x25519_sk.diffie_hellman(&x25519_ephemeral_pk);

    // 2. ML-KEM decapsulation
    let dk_array: ml_kem::array::Array<u8, _> = match mlkem_secret.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some("Invalid ML-KEM secret key length".into()),
            }
        }
    };

    #[allow(deprecated)]
    let dk = match DecapsulationKey::from_expanded_bytes(&dk_array) {
        Ok(k) => k,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some("Invalid ML-KEM secret key format".into()),
            }
        }
    };

    let ct_array: ml_kem::array::Array<u8, _> = match mlkem_ciphertext.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some("Invalid ML-KEM ciphertext".into()),
            }
        }
    };

    let mlkem_shared = dk.decapsulate(&ct_array);

    // 3. Hybrid key derivation
    let mut ikm = Vec::with_capacity(64 + password.len());
    ikm.extend_from_slice(x25519_shared.as_bytes());
    ikm.extend_from_slice(mlkem_shared.as_slice());
    ikm.extend_from_slice(password.as_bytes());

    let key_bytes = match hkdf_derive(&ikm, None, b"meow-pq-hybrid-encrypt", 32) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Key derivation failed: {:?}", e)),
            }
        }
    };
    let key = SecretKey::from_bytes(&key_bytes).unwrap();
    let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

    // 4. Decrypt
    match aes_gcm_decrypt(&key, &nonce, ciphertext, None) {
        Ok(plaintext) => WasmResult {
            success: true,
            data: plaintext,
            error: None,
        },
        Err(_) => WasmResult {
            success: false,
            data: vec![],
            error: Some("Decryption failed (wrong keys or corrupted data)".into()),
        },
    }
}

/// Check if post-quantum features are available
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn pq_available() -> bool {
    #[cfg(feature = "ml-kem")]
    {
        true
    }
    #[cfg(not(feature = "ml-kem"))]
    {
        false
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Securely clear a byte array by overwriting with zeros
///
/// WASM memory is not automatically zeroed, so call this for sensitive data.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn secure_clear(data: &mut [u8]) {
    // Use volatile write to prevent optimization
    for byte in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    // Memory barrier
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Compare two byte arrays in constant time
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    #[cfg(feature = "pure-crypto")]
    {
        constant_time_eq(a, b)
    }
    #[cfg(not(feature = "pure-crypto"))]
    {
        false
    }
}

/// Get library version
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ============================================================================
// High-Level Encode/Decode API
// ============================================================================

/// Encode data for transfer (compress + encrypt + add metadata)
///
/// This is the high-level API matching the Python encode workflow.
///
/// # Arguments
///
/// * `data` - Raw file data
/// * `password` - Encryption password
/// * `block_size` - Fountain code block size (default: 512)
///
/// # Returns
///
/// JSON-encoded manifest + encrypted blocks
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn encode_data(data: &[u8], password: &str, block_size: Option<u32>) -> WasmResult {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let block_size = block_size.unwrap_or(512) as usize;

    // 1. Compress
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    let compressed = encoder.finish().unwrap();

    // 2. Generate salt and nonce
    let salt_bytes = match random_bytes(16) {
        Ok(s) => s,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Salt generation failed: {:?}", e)),
            }
        }
    };
    let salt = Salt::from_bytes(&salt_bytes).unwrap();

    let nonce_bytes = match random_bytes(12) {
        Ok(n) => n,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Nonce generation failed: {:?}", e)),
            }
        }
    };
    let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

    // 3. Derive key (browser-friendly params)
    let params = Argon2Params {
        memory_kib: 65536, // 64 MiB
        time: 3,
        parallelism: 1,
    };
    let key = match argon2_derive(password.as_bytes(), &salt, Some(params)) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Key derivation failed: {:?}", e)),
            }
        }
    };

    // 4. Compute data hash
    let data_hash = sha256(data);

    // 5. Build AAD
    let mut aad = Vec::new();
    aad.extend_from_slice(&(data.len() as u64).to_le_bytes());
    aad.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
    aad.extend_from_slice(&salt_bytes);
    aad.extend_from_slice(&data_hash);
    aad.extend_from_slice(b"MEOW3");

    // 6. Encrypt
    let ciphertext = match aes_gcm_encrypt(&key, &nonce, &compressed, Some(&aad)) {
        Ok(c) => c,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Encryption failed: {:?}", e)),
            }
        }
    };

    // 7. Build output packet
    // Format: version (1) + salt (16) + nonce (12) + orig_len (8) + comp_len (8) + hash (32) + cipher (N)
    let mut output = Vec::new();
    output.push(0x03); // Version 3
    output.extend_from_slice(&salt_bytes);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&(data.len() as u64).to_le_bytes());
    output.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
    output.extend_from_slice(&data_hash);
    output.extend_from_slice(&ciphertext);

    WasmResult {
        success: true,
        data: output,
        error: None,
    }
}

/// Decode data from transfer format
///
/// # Arguments
///
/// * `encoded` - Encoded data from encode_data()
/// * `password` - Decryption password
///
/// # Returns
///
/// Original plaintext data
#[cfg(all(feature = "wasm", feature = "pure-crypto"))]
#[wasm_bindgen]
pub fn decode_data(encoded: &[u8], password: &str) -> WasmResult {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    // Minimum size: version (1) + salt (16) + nonce (12) + orig_len (8) + comp_len (8) + hash (32) + tag (16) = 93
    if encoded.len() < 93 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("Encoded data too short".into()),
        };
    }

    // Parse header
    let version = encoded[0];
    if version != 0x03 {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Unsupported version: {}", version)),
        };
    }

    let salt_bytes = &encoded[1..17];
    let nonce_bytes = &encoded[17..29];
    let orig_len = u64::from_le_bytes(encoded[29..37].try_into().unwrap()) as usize;
    let comp_len = u64::from_le_bytes(encoded[37..45].try_into().unwrap()) as usize;
    let expected_hash = &encoded[45..77];
    let ciphertext = &encoded[77..];

    // Reconstruct salt and nonce
    let salt = Salt::from_bytes(salt_bytes).unwrap();
    let nonce = Nonce::from_bytes(nonce_bytes).unwrap();

    // Derive key
    let params = Argon2Params {
        memory_kib: 65536,
        time: 3,
        parallelism: 1,
    };
    let key = match argon2_derive(password.as_bytes(), &salt, Some(params)) {
        Ok(k) => k,
        Err(e) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some(format!("Key derivation failed: {:?}", e)),
            }
        }
    };

    // Rebuild AAD
    let mut aad = Vec::new();
    aad.extend_from_slice(&(orig_len as u64).to_le_bytes());
    aad.extend_from_slice(&(comp_len as u64).to_le_bytes());
    aad.extend_from_slice(salt_bytes);
    aad.extend_from_slice(expected_hash);
    aad.extend_from_slice(b"MEOW3");

    // Decrypt
    let compressed = match aes_gcm_decrypt(&key, &nonce, ciphertext, Some(&aad)) {
        Ok(c) => c,
        Err(_) => {
            return WasmResult {
                success: false,
                data: vec![],
                error: Some("Decryption failed (wrong password or corrupted data)".into()),
            }
        }
    };

    // Decompress
    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut plaintext = Vec::new();
    if let Err(e) = decoder.read_to_end(&mut plaintext) {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Decompression failed: {}", e)),
        };
    }

    // Verify hash
    let actual_hash = sha256(&plaintext);
    if !constant_time_eq(&actual_hash, expected_hash) {
        return WasmResult {
            success: false,
            data: vec![],
            error: Some("Hash mismatch - data corrupted".into()),
        };
    }

    WasmResult {
        success: true,
        data: plaintext,
        error: None,
    }
}

// ============================================================================
// WASM Initialization
// ============================================================================

/// Initialize the WASM module (call once on page load)
#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
pub fn init() {
    // Set up panic hook for better error messages
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// ============================================================================
// Stub implementations when features are disabled
// ============================================================================

#[cfg(all(feature = "wasm", not(feature = "pure-crypto")))]
#[wasm_bindgen]
pub fn encrypt(_p: &[u8], _k: &[u8], _n: &[u8], _a: Option<Box<[u8]>>) -> WasmResult {
    WasmResult {
        success: false,
        data: vec![],
        error: Some("pure-crypto feature not enabled".into()),
    }
}

#[cfg(all(feature = "wasm", not(feature = "pure-crypto")))]
#[wasm_bindgen]
pub fn decrypt(_c: &[u8], _k: &[u8], _n: &[u8], _a: Option<Box<[u8]>>) -> WasmResult {
    WasmResult {
        success: false,
        data: vec![],
        error: Some("pure-crypto feature not enabled".into()),
    }
}

#[cfg(all(feature = "wasm", not(feature = "pure-crypto")))]
#[wasm_bindgen]
pub fn derive_key(_p: &[u8], _s: &[u8], _m: Option<u32>, _i: Option<u32>) -> WasmResult {
    WasmResult {
        success: false,
        data: vec![],
        error: Some("pure-crypto feature not enabled".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_result() {
        let result = WasmResult {
            success: true,
            data: vec![1, 2, 3],
            error: None,
        };
        assert!(result.success);
        assert!(result.error.is_none());
    }
}
