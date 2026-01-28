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
        aes_gcm_encrypt, aes_gcm_decrypt, argon2_derive, hkdf_derive,
        hmac_sha256, sha256, random_bytes, constant_time_eq,
        SecretKey, Nonce, Salt, Argon2Params,
    },
    js_sys::{Uint8Array, Promise},
    wasm_bindgen_futures::future_to_promise,
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
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: Option<Box<[u8]>>,
) -> WasmResult {
    // Validate inputs
    let key = match SecretKey::from_bytes(key) {
        Ok(k) => k,
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Invalid key: {:?}", e)),
        },
    };

    let nonce = match Nonce::from_bytes(nonce) {
        Ok(n) => n,
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Invalid nonce: {:?}", e)),
        },
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
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: Option<Box<[u8]>>,
) -> WasmResult {
    let key = match SecretKey::from_bytes(key) {
        Ok(k) => k,
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Invalid key: {:?}", e)),
        },
    };

    let nonce = match Nonce::from_bytes(nonce) {
        Ok(n) => n,
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Invalid nonce: {:?}", e)),
        },
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
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Invalid salt: {:?}", e)),
        },
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
pub fn encode_data(
    data: &[u8],
    password: &str,
    block_size: Option<u32>,
) -> WasmResult {
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
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Salt generation failed: {:?}", e)),
        },
    };
    let salt = Salt::from_bytes(&salt_bytes).unwrap();

    let nonce_bytes = match random_bytes(12) {
        Ok(n) => n,
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Nonce generation failed: {:?}", e)),
        },
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
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Key derivation failed: {:?}", e)),
        },
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
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Encryption failed: {:?}", e)),
        },
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
pub fn decode_data(
    encoded: &[u8],
    password: &str,
) -> WasmResult {
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
        Err(e) => return WasmResult {
            success: false,
            data: vec![],
            error: Some(format!("Key derivation failed: {:?}", e)),
        },
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
        Err(_) => return WasmResult {
            success: false,
            data: vec![],
            error: Some("Decryption failed (wrong password or corrupted data)".into()),
        },
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
