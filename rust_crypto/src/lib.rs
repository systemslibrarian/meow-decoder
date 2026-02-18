//! meow_crypto_rs - Rust Crypto Backend for Meow Decoder
//!
//! This module provides high-performance, constant-time cryptographic
//! primitives for the Meow Decoder project.
//!
//! Features:
//! - Argon2id key derivation
//! - AES-256-GCM authenticated encryption
//! - HKDF key derivation (RFC 5869)
//! - HMAC-SHA256 authentication
//! - X25519 key exchange
//! - Post-quantum ML-KEM-768 (Kyber) [optional]
//!
//! All implementations use audited crates and constant-time operations.
//!
//! # Architecture
//!
//! The crypto logic is implemented in the `pure` module without PyO3 dependencies,
//! enabling coverage measurement with cargo-tarpaulin. The PyO3 bindings in this
//! file are thin wrappers over the pure functions.

// Pure Rust crypto module (testable without Python)
pub mod pure;

// Opaque handle registry (all secrets Rust-owned)
pub mod handles;

// =============================================================================
// Python Bindings (only compiled with "python" feature)
// =============================================================================

#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::PyBytes;

#[cfg(feature = "python")]
use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit},
    Aes256Gcm, Nonce,
};
#[cfg(feature = "python")]
use argon2::{Algorithm, Argon2, Params, Version};
#[cfg(feature = "python")]
use hkdf::Hkdf;
#[cfg(feature = "python")]
use hmac::{Hmac, Mac as HmacMac};
#[cfg(feature = "python")]
use sha2::{Digest, Sha256};
#[cfg(feature = "python")]
use subtle::ConstantTimeEq;
#[cfg(feature = "python")]
use x25519_dalek::{PublicKey, StaticSecret};
#[cfg(feature = "python")]
use zeroize::Zeroize;

#[cfg(all(feature = "python", feature = "pq"))]
use pqcrypto_mlkem::mlkem768;
#[cfg(all(feature = "python", feature = "pq"))]
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};

#[cfg(all(feature = "python", feature = "yubikey"))]
use crypto_core::yubikey_piv::{derive_key_with_yubikey, PivSlot, YubiKeyPin, YubiKeyProvider};

// =============================================================================
// Argon2id Key Derivation
// =============================================================================

#[cfg(feature = "python")]
/// Derive a key using Argon2id.
///
/// Args:
///     password: Password bytes
///     salt: Salt (must be 16 bytes)
///     memory_kib: Memory usage in KiB
///     iterations: Number of iterations
///     parallelism: Degree of parallelism
///     output_len: Output key length in bytes
///
/// Returns:
///     Derived key bytes
#[pyfunction]
fn derive_key_argon2id<'py>(
    py: Python<'py>,
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    // Validate salt length - STRICT 16 BYTES
    if salt.len() != 16 {
        return Err(PyValueError::new_err(format!(
            "Salt must be exactly 16 bytes, got {}",
            salt.len()
        )));
    }

    // Build Argon2id params
    let params = Params::new(memory_kib, iterations, parallelism, Some(output_len))
        .map_err(|e| PyValueError::new_err(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive key
    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| PyValueError::new_err(format!("Argon2id failed: {}", e)))?;

    Ok(PyBytes::new(py, &output))
}

// =============================================================================
// HKDF (RFC 5869)
// =============================================================================

/// Derive key using HKDF with SHA-256.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (ikm, salt, info, output_len))]
fn derive_key_hkdf<'py>(
    py: Python<'py>,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);

    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| PyValueError::new_err(format!("HKDF expand failed: {:?}", e)))?;

    Ok(PyBytes::new(py, &okm))
}

/// HKDF-Extract phase only.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (salt, ikm))]
fn hkdf_extract<'py>(
    py: Python<'py>,
    salt: Option<&[u8]>,
    ikm: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
    Ok(PyBytes::new(py, prk.as_slice()))
}

/// HKDF-Expand phase only.
#[cfg(feature = "python")]
#[pyfunction]
fn hkdf_expand<'py>(
    py: Python<'py>,
    prk: &[u8],
    info: &[u8],
    output_len: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let hkdf =
        Hkdf::<Sha256>::from_prk(prk).map_err(|_| PyValueError::new_err("Invalid PRK length"))?;

    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| PyValueError::new_err(format!("HKDF expand failed: {:?}", e)))?;

    Ok(PyBytes::new(py, &okm))
}

// =============================================================================
// AES-256-GCM
// =============================================================================

/// Encrypt data using AES-256-GCM.
///
/// Args:
///     key: 32-byte encryption key
///     nonce: 12-byte nonce (must be unique per key)
///     plaintext: Data to encrypt
///     aad: Additional authenticated data (optional)
///
/// Returns:
///     Ciphertext with appended 16-byte auth tag
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (key, nonce, plaintext, aad=None))]
fn aes_gcm_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Validate key length
    if key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Key must be 32 bytes, got {}",
            key.len()
        )));
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(PyValueError::new_err(format!(
            "Nonce must be 12 bytes, got {}",
            nonce.len()
        )));
    }

    // Create cipher
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| PyValueError::new_err("Invalid key"))?;

    let nonce_arr = Nonce::from_slice(nonce);

    // Encrypt with AAD if provided
    let ciphertext = if let Some(aad_data) = aad {
        use aes_gcm::aead::Payload;
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

    let ciphertext = ciphertext.map_err(|_| PyValueError::new_err("Encryption failed"))?;

    Ok(PyBytes::new(py, &ciphertext))
}

/// Decrypt data using AES-256-GCM.
///
/// Args:
///     key: 32-byte encryption key
///     nonce: 12-byte nonce
///     ciphertext: Data to decrypt (includes auth tag)
///     aad: Additional authenticated data (optional)
///
/// Returns:
///     Decrypted plaintext
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (key, nonce, ciphertext, aad=None))]
fn aes_gcm_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Validate key length
    if key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Key must be 32 bytes, got {}",
            key.len()
        )));
    }

    // Validate nonce length
    if nonce.len() != 12 {
        return Err(PyValueError::new_err(format!(
            "Nonce must be 12 bytes, got {}",
            nonce.len()
        )));
    }

    // Minimum ciphertext length (just auth tag)
    if ciphertext.len() < 16 {
        return Err(PyValueError::new_err("Ciphertext too short"));
    }

    // Create cipher
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| PyValueError::new_err("Invalid key"))?;

    let nonce_arr = Nonce::from_slice(nonce);

    // Decrypt with AAD if provided
    let plaintext = if let Some(aad_data) = aad {
        use aes_gcm::aead::Payload;
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

    let plaintext =
        plaintext.map_err(|_| PyValueError::new_err("Decryption failed - authentication error"))?;

    Ok(PyBytes::new(py, &plaintext))
}

// =============================================================================
// AES-256-CTR (Streaming Encryption)
// =============================================================================

/// Encrypt or decrypt data using AES-256-CTR mode.
///
/// CTR mode is symmetric: the same function serves as both encrypt and decrypt.
///
/// Args:
///     key: 32-byte AES-256 key
///     nonce: 16-byte initial counter block (CTR IV)
///     data: Plaintext (encrypt) or ciphertext (decrypt)
///     byte_offset: Starting byte position in the stream (for chunked processing)
///
/// Returns:
///     Processed data (ciphertext or plaintext)
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (key, nonce, data, byte_offset=0))]
fn aes_ctr_crypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    byte_offset: u64,
) -> PyResult<Bound<'py, PyBytes>> {
    let result = crypto_core::pure_crypto::aes_ctr_crypt(key, nonce, data, byte_offset)
        .map_err(|e| PyValueError::new_err(format!("{}", e)))?;
    Ok(PyBytes::new(py, &result))
}

// =============================================================================
// HMAC-SHA256
// =============================================================================

#[cfg(feature = "python")]
type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256.
#[cfg(feature = "python")]
#[pyfunction]
fn hmac_sha256<'py>(py: Python<'py>, key: &[u8], message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("Invalid key length"))?;
    mac.update(message);
    let result = mac.finalize();
    Ok(PyBytes::new(py, result.into_bytes().as_slice()))
}

/// Verify HMAC-SHA256 in constant time.
#[cfg(feature = "python")]
#[pyfunction]
fn hmac_sha256_verify(key: &[u8], message: &[u8], expected_tag: &[u8]) -> PyResult<bool> {
    let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("Invalid key length"))?;
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
#[cfg(feature = "python")]
#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    Ok(PyBytes::new(py, result.as_slice()))
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

/// Generate X25519 keypair.
///
/// Returns:
///     Tuple of (private_key, public_key), both 32 bytes
#[cfg(feature = "python")]
#[pyfunction]
fn x25519_generate_keypair<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    use rand::rngs::OsRng;

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    Ok((
        PyBytes::new(py, secret.as_bytes()),
        PyBytes::new(py, public.as_bytes()),
    ))
}

/// Perform X25519 key exchange.
///
/// Args:
///     private_key: Our 32-byte private key
///     peer_public_key: Peer's 32-byte public key
///
/// Returns:
///     32-byte shared secret
#[cfg(feature = "python")]
#[pyfunction]
fn x25519_exchange<'py>(
    py: Python<'py>,
    private_key: &[u8],
    peer_public_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if private_key.len() != 32 {
        return Err(PyValueError::new_err("Private key must be 32 bytes"));
    }
    if peer_public_key.len() != 32 {
        return Err(PyValueError::new_err("Public key must be 32 bytes"));
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

    Ok(PyBytes::new(py, shared.as_bytes()))
}

/// Derive X25519 public key from private key.
#[cfg(feature = "python")]
#[pyfunction]
fn x25519_public_from_private<'py>(
    py: Python<'py>,
    private_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if private_key.len() != 32 {
        return Err(PyValueError::new_err("Private key must be 32 bytes"));
    }

    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(private_key);
    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);

    // Zeroize
    priv_bytes.zeroize();

    Ok(PyBytes::new(py, public.as_bytes()))
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Constant-time byte comparison.
#[cfg(feature = "python")]
#[pyfunction]
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Securely zero memory - writes zeros and forces volatile write.
///
/// Note: In Rust, we use zeroize crate which provides proper memory barriers.
/// This function is mostly for API completeness - Python bytearrays are mutable
/// and can be zeroed in place.
#[cfg(feature = "python")]
#[pyfunction]
fn secure_zero(_py: Python<'_>, data: &Bound<'_, pyo3::types::PyByteArray>) -> PyResult<()> {
    // Get mutable access to the bytearray
    unsafe {
        let slice = data.as_bytes_mut();
        // Use zeroize to securely zero the memory
        slice.zeroize();
    }
    Ok(())
}

/// Secure random bytes.
#[cfg(feature = "python")]
#[pyfunction]
fn secure_random<'py>(py: Python<'py>, size: usize) -> PyResult<Bound<'py, PyBytes>> {
    use rand::RngCore;
    let mut buffer = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut buffer);
    Ok(PyBytes::new(py, &buffer))
}

/// Get backend info.
#[cfg(feature = "python")]
#[pyfunction]
fn backend_info() -> String {
    format!("meow_crypto_rs v{} (Rust)", env!("CARGO_PKG_VERSION"))
}

// =============================================================================
// ML-KEM-768 (Post-Quantum) - Kyber
// =============================================================================

#[cfg(all(feature = "python", feature = "pq"))]
#[pyfunction]
fn mlkem768_keygen<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (pk, sk) = mlkem768::keypair();
    Ok((
        PyBytes::new(py, sk.as_bytes()),
        PyBytes::new(py, pk.as_bytes()),
    ))
}

#[cfg(all(feature = "python", feature = "pq"))]
#[pyfunction]
fn mlkem768_encapsulate<'py>(
    py: Python<'py>,
    public_key: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    // Check key length
    if public_key.len() != mlkem768::public_key_bytes() {
        return Err(PyValueError::new_err(format!(
            "Invalid public key length: expected {}, got {}",
            mlkem768::public_key_bytes(),
            public_key.len()
        )));
    }

    let pk = mlkem768::PublicKey::from_bytes(public_key)
        .map_err(|e| PyValueError::new_err(format!("Invalid public key: {:?}", e)))?;
    let (ss, ct) = mlkem768::encapsulate(&pk);
    Ok((
        PyBytes::new(py, ss.as_bytes()),
        PyBytes::new(py, ct.as_bytes()),
    ))
}

#[cfg(all(feature = "python", feature = "pq"))]
#[pyfunction]
fn mlkem768_decapsulate<'py>(
    py: Python<'py>,
    private_key: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    // Check lengths
    if private_key.len() != mlkem768::secret_key_bytes() {
        return Err(PyValueError::new_err(format!(
            "Invalid private key length: expected {}, got {}",
            mlkem768::secret_key_bytes(),
            private_key.len()
        )));
    }
    if ciphertext.len() != mlkem768::ciphertext_bytes() {
        return Err(PyValueError::new_err(format!(
            "Invalid ciphertext length: expected {}, got {}",
            mlkem768::ciphertext_bytes(),
            ciphertext.len()
        )));
    }

    let sk = mlkem768::SecretKey::from_bytes(private_key)
        .map_err(|e| PyValueError::new_err(format!("Invalid private key: {:?}", e)))?;
    let ct = mlkem768::Ciphertext::from_bytes(ciphertext)
        .map_err(|e| PyValueError::new_err(format!("Invalid ciphertext: {:?}", e)))?;
    let ss = mlkem768::decapsulate(&ct, &sk);
    Ok(PyBytes::new(py, ss.as_bytes()))
}

// =============================================================================
// YubiKey (optional)
// =============================================================================

#[cfg(all(feature = "python", feature = "yubikey"))]
fn parse_piv_slot(slot: &str) -> Result<PivSlot, PyErr> {
    match slot.to_ascii_lowercase().as_str() {
        "9a" | "auth" => Ok(PivSlot::Authentication),
        "9b" | "mgmt" => Ok(PivSlot::CardManagement),
        "9c" | "sign" => Ok(PivSlot::DigitalSignature),
        "9d" | "key" => Ok(PivSlot::KeyManagement),
        "9e" | "card" => Ok(PivSlot::CardAuthentication),
        other => Err(PyValueError::new_err(format!(
            "Unsupported PIV slot '{}'. Use 9a, 9b, 9c, 9d, or 9e.",
            other
        ))),
    }
}

#[cfg(all(feature = "python", feature = "yubikey"))]
#[pyfunction]
#[pyo3(signature = (password, salt, slot="9d", pin=None))]
fn yubikey_derive_key<'py>(
    py: Python<'py>,
    password: &[u8],
    salt: &[u8],
    slot: &str,
    pin: Option<String>,
) -> PyResult<Bound<'py, PyBytes>> {
    if salt.len() != 16 {
        return Err(PyValueError::new_err(format!(
            "Salt must be exactly 16 bytes, got {}",
            salt.len()
        )));
    }

    let piv_slot = parse_piv_slot(slot)?;
    let mut yubikey = YubiKeyProvider::connect()
        .map_err(|e| PyValueError::new_err(format!("YubiKey connection failed: {e:?}")))?;

    let pin_obj = pin.as_ref().map(|p| YubiKeyPin::new(p.clone()));
    let pin_ref = pin_obj.as_ref();

    if let Some(pin) = pin_ref {
        yubikey.verify_pin(pin).map_err(|e| {
            PyValueError::new_err(format!("YubiKey PIN verification failed: {e:?}"))
        })?;
    }

    let key = derive_key_with_yubikey(password, salt, &mut yubikey, piv_slot, pin_ref)
        .map_err(|e| PyValueError::new_err(format!("YubiKey derivation failed: {e:?}")))?;

    Ok(PyBytes::new(py, &key))
}

#[cfg(all(feature = "python", not(feature = "yubikey")))]
#[pyfunction]
#[pyo3(signature = (password, salt, slot="9d", pin=None))]
#[allow(unused_variables)]
fn yubikey_derive_key<'py>(
    py: Python<'py>,
    password: &[u8],
    salt: &[u8],
    slot: &str,
    pin: Option<String>,
) -> PyResult<Bound<'py, PyBytes>> {
    Err(PyValueError::new_err(
        "YubiKey support not enabled in Rust backend. Rebuild with: \
         maturin develop --release --features yubikey",
    ))
}

// =============================================================================
// Python Module
// =============================================================================

// =============================================================================
// Opaque Handle API (FFI-safe, no secret bytes cross into Python)
// =============================================================================

#[cfg(feature = "python")]
fn handle_err_to_py(e: handles::HandleError) -> PyErr {
    PyValueError::new_err(format!("{}", e))
}

/// Import raw key bytes into an opaque Rust handle. The Python caller
/// MUST zeroize their copy immediately after this call.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_import_key(key_bytes: &[u8]) -> PyResult<u64> {
    handles::handle_import_key(key_bytes).map_err(handle_err_to_py)
}

/// Derive key via Argon2id, store as opaque handle. Returns handle ID.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> PyResult<u64> {
    handles::handle_derive_key_argon2id(password, salt, memory_kib, iterations, parallelism)
        .map_err(handle_err_to_py)
}

/// Derive key via HKDF from a handle. Returns new handle ID.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_derive_hkdf(
    ikm_handle: u64,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> PyResult<u64> {
    handles::handle_derive_hkdf(ikm_handle, salt, info, output_len).map_err(handle_err_to_py)
}

/// Derive key via HKDF from raw IKM bytes. Returns handle ID.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_derive_hkdf_raw(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> PyResult<u64> {
    handles::handle_derive_hkdf_raw(ikm, salt, info, output_len).map_err(handle_err_to_py)
}

/// Derive HKDF from key handle, return raw bytes (for non-secret values like nonces).
#[cfg(feature = "python")]
#[pyfunction]
fn handle_derive_hkdf_bytes<'py>(
    py: Python<'py>,
    ikm_handle: u64,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let derived = handles::handle_derive_hkdf_bytes(ikm_handle, salt, info, output_len)
        .map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &derived))
}

/// Encrypt via AES-256-GCM using a key handle. Returns ciphertext bytes.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (key_handle, nonce, plaintext, aad=None))]
fn handle_aes_gcm_encrypt<'py>(
    py: Python<'py>,
    key_handle: u64,
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let ct = handles::handle_aes_gcm_encrypt(key_handle, nonce, plaintext, aad)
        .map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &ct))
}

/// Decrypt via AES-256-GCM using a key handle. Returns plaintext ONLY if auth passes.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (key_handle, nonce, ciphertext, aad=None))]
fn handle_aes_gcm_decrypt<'py>(
    py: Python<'py>,
    key_handle: u64,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let pt = handles::handle_aes_gcm_decrypt(key_handle, nonce, ciphertext, aad)
        .map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &pt))
}

/// Compute HMAC-SHA256 using a key handle. Returns tag bytes.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_hmac_sha256<'py>(
    py: Python<'py>,
    key_handle: u64,
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let tag = handles::handle_hmac_sha256(key_handle, message).map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &tag))
}

/// Verify HMAC-SHA256 in constant time using a key handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_hmac_sha256_verify(
    key_handle: u64,
    message: &[u8],
    expected_tag: &[u8],
) -> PyResult<bool> {
    handles::handle_hmac_sha256_verify(key_handle, message, expected_tag).map_err(handle_err_to_py)
}

/// Compute HMAC-SHA256 with prefixed key: effective key = prefix || handle_key.
/// Enables domain-separated HMAC (e.g. manifest auth) without exporting the secret.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_hmac_sha256_prefixed<'py>(
    py: Python<'py>,
    key_handle: u64,
    prefix: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let tag = handles::handle_hmac_sha256_prefixed(key_handle, prefix, message)
        .map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &tag))
}

/// Verify HMAC-SHA256 with prefixed key in constant time.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_hmac_sha256_prefixed_verify(
    key_handle: u64,
    prefix: &[u8],
    message: &[u8],
    expected_tag: &[u8],
) -> PyResult<bool> {
    handles::handle_hmac_sha256_prefixed_verify(key_handle, prefix, message, expected_tag)
        .map_err(handle_err_to_py)
}

/// Generate X25519 keypair. Private key stays in Rust.
/// Returns (handle_id, public_key_bytes).
#[cfg(feature = "python")]
#[pyfunction]
fn handle_x25519_generate<'py>(py: Python<'py>) -> PyResult<(u64, Bound<'py, PyBytes>)> {
    let (id, pub_bytes) = handles::handle_x25519_generate().map_err(handle_err_to_py)?;
    Ok((id, PyBytes::new(py, &pub_bytes)))
}

/// X25519 key exchange. Returns handle to shared secret.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_x25519_exchange(private_handle: u64, peer_public: &[u8]) -> PyResult<u64> {
    handles::handle_x25519_exchange(private_handle, peer_public).map_err(handle_err_to_py)
}

/// Get public key from X25519 private key handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_x25519_public<'py>(py: Python<'py>, handle: u64) -> PyResult<Bound<'py, PyBytes>> {
    let pub_bytes = handles::handle_x25519_public(handle).map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &pub_bytes))
}

/// Import raw X25519 private key bytes into an opaque handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_import_x25519_private(private_bytes: &[u8]) -> PyResult<u64> {
    handles::handle_import_x25519_private(private_bytes).map_err(handle_err_to_py)
}

/// Create a session from enc_key handle + optional mac_key handle.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (enc_key_handle, mac_key_handle=None))]
fn handle_session_new(enc_key_handle: u64, mac_key_handle: Option<u64>) -> PyResult<u64> {
    handles::handle_session_new(enc_key_handle, mac_key_handle).map_err(handle_err_to_py)
}

/// Create stream state for streaming encrypt/decrypt.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_stream_new(enc_key_handle: u64, nonce: &[u8], mac_domain: &[u8]) -> PyResult<u64> {
    handles::handle_stream_new(enc_key_handle, nonce, mac_domain).map_err(handle_err_to_py)
}

/// Stream encrypt. Returns (ciphertext, mac_tag).
#[cfg(feature = "python")]
#[pyfunction]
fn handle_stream_encrypt<'py>(
    py: Python<'py>,
    stream_handle: u64,
    plaintext: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (ct, tag) =
        handles::handle_stream_encrypt(stream_handle, plaintext).map_err(handle_err_to_py)?;
    Ok((PyBytes::new(py, &ct), PyBytes::new(py, &tag)))
}

/// Stream decrypt. Verifies MAC first (fail-closed), then returns plaintext.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_stream_decrypt<'py>(
    py: Python<'py>,
    stream_handle: u64,
    ciphertext: &[u8],
    expected_mac: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let pt = handles::handle_stream_decrypt(stream_handle, ciphertext, expected_mac)
        .map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &pt))
}

/// Create ratchet state from root key handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_ratchet_new(root_key_handle: u64, salt: &[u8], root_info: &[u8]) -> PyResult<u64> {
    handles::handle_ratchet_new(root_key_handle, salt, root_info).map_err(handle_err_to_py)
}

/// Ratchet step: advance chain key, return message key handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_ratchet_step(ratchet_handle: u64, step_info: &[u8], msg_info: &[u8]) -> PyResult<u64> {
    handles::handle_ratchet_step(ratchet_handle, step_info, msg_info).map_err(handle_err_to_py)
}

/// Stream chunk AES-CTR crypt using stream handle (key stays in Rust).
#[cfg(feature = "python")]
#[pyfunction]
fn handle_stream_ctr_crypt<'py>(
    py: Python<'py>,
    stream_handle: u64,
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = handles::handle_stream_ctr_crypt(stream_handle, data).map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &result))
}

/// Compute HMAC-SHA256 using stream handle's internal MAC key.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_stream_hmac<'py>(
    py: Python<'py>,
    stream_handle: u64,
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let tag = handles::handle_stream_hmac(stream_handle, message).map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &tag))
}

/// Verify HMAC-SHA256 using stream handle's MAC key (constant-time).
#[cfg(feature = "python")]
#[pyfunction]
fn handle_stream_hmac_verify(
    stream_handle: u64,
    message: &[u8],
    expected_tag: &[u8],
) -> PyResult<bool> {
    handles::handle_stream_hmac_verify(stream_handle, message, expected_tag)
        .map_err(handle_err_to_py)
}

/// Get nonce from stream handle (non-secret).
#[cfg(feature = "python")]
#[pyfunction]
fn handle_stream_nonce<'py>(py: Python<'py>, stream_handle: u64) -> PyResult<Bound<'py, PyBytes>> {
    let nonce = handles::handle_stream_nonce(stream_handle).map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &nonce))
}

/// Reset stream byte offset.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_stream_reset_offset(stream_handle: u64) -> PyResult<()> {
    handles::handle_stream_reset_offset(stream_handle).map_err(handle_err_to_py)
}

/// Generic AES-CTR crypt using any key handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_aes_ctr_crypt<'py>(
    py: Python<'py>,
    key_handle: u64,
    nonce: &[u8],
    data: &[u8],
    byte_offset: u64,
) -> PyResult<Bound<'py, PyBytes>> {
    let result = handles::handle_aes_ctr_crypt(key_handle, nonce, data, byte_offset)
        .map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &result))
}

/// HKDF with handle key concatenated with extra IKM. Returns handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_mix_hkdf(
    ikm_handle: u64,
    extra_ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> PyResult<u64> {
    handles::handle_mix_hkdf(ikm_handle, extra_ikm, salt, info, output_len)
        .map_err(handle_err_to_py)
}

/// HKDF with handle as salt and raw IKM bytes. Returns handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_hkdf_with_handle_salt(
    ikm: &[u8],
    salt_handle: u64,
    info: &[u8],
    output_len: usize,
) -> PyResult<u64> {
    handles::handle_hkdf_with_handle_salt(ikm, salt_handle, info, output_len)
        .map_err(handle_err_to_py)
}

/// HKDF-Expand only (no Extract). Treats handle key as PRK.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_hkdf_expand(prk_handle: u64, info: &[u8], output_len: usize) -> PyResult<u64> {
    handles::handle_hkdf_expand(prk_handle, info, output_len).map_err(handle_err_to_py)
}

/// Full HKDF where both IKM and salt come from handles.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_hkdf_two_handles(
    ikm_handle: u64,
    salt_handle: u64,
    info: &[u8],
    output_len: usize,
) -> PyResult<u64> {
    handles::handle_hkdf_two_handles(ikm_handle, salt_handle, info, output_len)
        .map_err(handle_err_to_py)
}

/// Drop (zeroize) a handle.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_drop(id: u64) -> PyResult<()> {
    handles::handle_drop(id).map_err(handle_err_to_py)
}

/// Export raw key bytes from handle. DANGEROUS: only for encrypted-at-rest serialization.
#[cfg(feature = "python")]
#[pyfunction]
fn handle_export_key<'py>(py: Python<'py>, id: u64) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = handles::handle_export_key(id).map_err(handle_err_to_py)?;
    Ok(PyBytes::new(py, &bytes))
}

/// Check if a handle exists (for testing only).
#[cfg(feature = "python")]
#[pyfunction]
fn handle_exists(id: u64) -> bool {
    handles::handle_exists(id)
}

/// Get current handle count (for testing / monitoring).
#[cfg(feature = "python")]
#[pyfunction]
fn handle_count() -> usize {
    handles::handle_count()
}

#[cfg(feature = "python")]
#[pymodule]
fn meow_crypto_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Argon2id
    m.add_function(wrap_pyfunction!(derive_key_argon2id, m)?)?;

    // HKDF
    m.add_function(wrap_pyfunction!(derive_key_hkdf, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_extract, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_expand, m)?)?;

    // AES-GCM
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;

    // AES-CTR (streaming)
    m.add_function(wrap_pyfunction!(aes_ctr_crypt, m)?)?;

    // HMAC
    m.add_function(wrap_pyfunction!(hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256_verify, m)?)?;

    // SHA-256
    m.add_function(wrap_pyfunction!(sha256, m)?)?;

    // X25519
    m.add_function(wrap_pyfunction!(x25519_generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_exchange, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_public_from_private, m)?)?;

    // Utilities
    m.add_function(wrap_pyfunction!(constant_time_compare, m)?)?;
    m.add_function(wrap_pyfunction!(secure_zero, m)?)?;
    m.add_function(wrap_pyfunction!(secure_random, m)?)?;
    m.add_function(wrap_pyfunction!(backend_info, m)?)?;

    // Post-quantum (optional - requires pq feature)
    #[cfg(feature = "pq")]
    {
        m.add_function(wrap_pyfunction!(mlkem768_keygen, m)?)?;
        m.add_function(wrap_pyfunction!(mlkem768_encapsulate, m)?)?;
        m.add_function(wrap_pyfunction!(mlkem768_decapsulate, m)?)?;
    }

    // YubiKey (optional)
    m.add_function(wrap_pyfunction!(yubikey_derive_key, m)?)?;

    // Opaque Handle API (no secret bytes cross FFI)
    m.add_function(wrap_pyfunction!(handle_import_key, m)?)?;
    m.add_function(wrap_pyfunction!(handle_derive_key_argon2id, m)?)?;
    m.add_function(wrap_pyfunction!(handle_derive_hkdf, m)?)?;
    m.add_function(wrap_pyfunction!(handle_derive_hkdf_raw, m)?)?;
    m.add_function(wrap_pyfunction!(handle_derive_hkdf_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(handle_aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(handle_aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(handle_hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(handle_hmac_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(handle_hmac_sha256_prefixed, m)?)?;
    m.add_function(wrap_pyfunction!(handle_hmac_sha256_prefixed_verify, m)?)?;
    m.add_function(wrap_pyfunction!(handle_x25519_generate, m)?)?;
    m.add_function(wrap_pyfunction!(handle_x25519_exchange, m)?)?;
    m.add_function(wrap_pyfunction!(handle_x25519_public, m)?)?;
    m.add_function(wrap_pyfunction!(handle_import_x25519_private, m)?)?;
    m.add_function(wrap_pyfunction!(handle_session_new, m)?)?;
    m.add_function(wrap_pyfunction!(handle_stream_new, m)?)?;
    m.add_function(wrap_pyfunction!(handle_stream_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(handle_stream_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(handle_ratchet_new, m)?)?;
    m.add_function(wrap_pyfunction!(handle_ratchet_step, m)?)?;
    m.add_function(wrap_pyfunction!(handle_stream_ctr_crypt, m)?)?;
    m.add_function(wrap_pyfunction!(handle_stream_hmac, m)?)?;
    m.add_function(wrap_pyfunction!(handle_stream_hmac_verify, m)?)?;
    m.add_function(wrap_pyfunction!(handle_stream_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(handle_stream_reset_offset, m)?)?;
    m.add_function(wrap_pyfunction!(handle_aes_ctr_crypt, m)?)?;
    m.add_function(wrap_pyfunction!(handle_mix_hkdf, m)?)?;
    m.add_function(wrap_pyfunction!(handle_hkdf_with_handle_salt, m)?)?;
    m.add_function(wrap_pyfunction!(handle_hkdf_expand, m)?)?;
    m.add_function(wrap_pyfunction!(handle_hkdf_two_handles, m)?)?;
    m.add_function(wrap_pyfunction!(handle_drop, m)?)?;
    m.add_function(wrap_pyfunction!(handle_export_key, m)?)?;
    m.add_function(wrap_pyfunction!(handle_exists, m)?)?;
    m.add_function(wrap_pyfunction!(handle_count, m)?)?;

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

// NOTE: Integration tests with Python bindings are in tests/comprehensive_tests.rs
// The tests below require Python linking and are disabled by default.
// Run with: maturin develop && python -c "import meow_crypto_rs; ..."
// Or use: cargo test --test comprehensive_tests (76 pure Rust tests)

#[cfg(all(test, feature = "python-tests"))]
mod tests {
    use super::*;
    use pyo3::types::PyByteArray;
    use pyo3::Python;

    #[test]
    fn test_argon2id_derive_and_invalid_salt() {
        Python::with_gil(|py| {
            let salt = [0u8; 16];
            let key = derive_key_argon2id(py, b"password", &salt, 1024, 1, 1, 32).unwrap();
            assert_eq!(key.as_bytes().len(), 32);

            let err = derive_key_argon2id(py, b"password", b"short", 1024, 1, 1, 32)
                .err()
                .expect("expected error for invalid salt");
            assert!(err.to_string().contains("Salt must be exactly 16 bytes"));
        });
    }

    #[test]
    fn test_hkdf_extract_expand() {
        Python::with_gil(|py| {
            let prk = hkdf_extract(py, Some(b"salt"), b"ikm").unwrap();
            let okm = hkdf_expand(py, prk.as_bytes(), b"info", 42).unwrap();
            assert_eq!(okm.as_bytes().len(), 42);

            let okm2 = derive_key_hkdf(py, b"ikm", Some(b"salt"), b"info", 42).unwrap();
            assert_eq!(okm.as_bytes(), okm2.as_bytes());
        });
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        Python::with_gil(|py| {
            let key = [0x11u8; 32];
            let nonce = [0x22u8; 12];
            let plaintext = b"meow secret";
            let aad = b"aad";

            let cipher = aes_gcm_encrypt(py, &key, &nonce, plaintext, Some(aad)).unwrap();
            let decrypted =
                aes_gcm_decrypt(py, &key, &nonce, cipher.as_bytes(), Some(aad)).unwrap();
            assert_eq!(decrypted.as_bytes(), plaintext);

            let bad = aes_gcm_decrypt(py, &key, &nonce, cipher.as_bytes(), Some(b"bad"));
            assert!(bad.is_err());
        });
    }

    #[test]
    fn test_hmac_sha256_verify() {
        Python::with_gil(|py| {
            let key = b"key";
            let message = b"message";
            let tag = hmac_sha256(py, key, message).unwrap();
            assert!(hmac_sha256_verify(key, message, tag.as_bytes()).unwrap());

            let mut bad = tag.as_bytes().to_vec();
            bad[0] ^= 0xFF;
            assert!(!hmac_sha256_verify(key, message, &bad).unwrap());
        });
    }

    #[test]
    fn test_sha256_and_constant_time_compare() {
        Python::with_gil(|py| {
            let digest = sha256(py, b"abc").unwrap();
            assert_eq!(digest.as_bytes().len(), 32);
        });

        assert!(constant_time_compare(b"abc", b"abc"));
        assert!(!constant_time_compare(b"abc", b"abd"));
        assert!(!constant_time_compare(b"abc", b"abcd"));
    }

    #[test]
    fn test_x25519_key_exchange_and_public() {
        Python::with_gil(|py| {
            let (priv_a, pub_a) = x25519_generate_keypair(py).unwrap();
            let (priv_b, pub_b) = x25519_generate_keypair(py).unwrap();

            let shared_a = x25519_exchange(py, priv_a.as_bytes(), pub_b.as_bytes()).unwrap();
            let shared_b = x25519_exchange(py, priv_b.as_bytes(), pub_a.as_bytes()).unwrap();
            assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());

            let derived_pub = x25519_public_from_private(py, priv_a.as_bytes()).unwrap();
            assert_eq!(derived_pub.as_bytes(), pub_a.as_bytes());
        });
    }

    #[test]
    fn test_secure_zero_and_random() {
        Python::with_gil(|py| {
            let ba = PyByteArray::new(py, b"secret");
            secure_zero(py, &ba).unwrap();
            // SAFETY: We have exclusive access to ba and don't modify it during this check
            assert_eq!(unsafe { ba.as_bytes() }, b"\x00\x00\x00\x00\x00\x00");

            let rnd = secure_random(py, 24).unwrap();
            // SAFETY: We have exclusive access to rnd and don't modify it during this check
            assert_eq!(unsafe { rnd.as_bytes() }.len(), 24);
        });
    }

    #[test]
    fn test_backend_info_and_mlkem() {
        let info = backend_info();
        assert!(info.contains("meow_crypto_rs"));

        Python::with_gil(|py| {
            let (sk, pk) = mlkem768_keygen(py).unwrap();
            let (ss1, ct) = mlkem768_encapsulate(py, pk.as_bytes()).unwrap();
            let ss2 = mlkem768_decapsulate(py, sk.as_bytes(), ct.as_bytes()).unwrap();
            assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        });
    }
}
