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

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Algorithm, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as HmacMac};
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{SecretKey as KemSecretKey, PublicKey as KemPublicKey, Ciphertext as KemCiphertext, SharedSecret as KemSharedSecret};

// =============================================================================
// Argon2id Key Derivation
// =============================================================================

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
    argon2.hash_password_into(password, salt, &mut output)
        .map_err(|e| PyValueError::new_err(format!("Argon2id failed: {}", e)))?;

    Ok(PyBytes::new(py, &output))
}

// =============================================================================
// HKDF (RFC 5869)
// =============================================================================

/// Derive key using HKDF with SHA-256.
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
#[pyfunction]
fn hkdf_expand<'py>(
    py: Python<'py>,
    prk: &[u8],
    info: &[u8],
    output_len: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| PyValueError::new_err("Invalid PRK length"))?;
    
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
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("Invalid key"))?;

    let nonce_arr = Nonce::from_slice(nonce);

    // Encrypt with AAD if provided
    let ciphertext = if let Some(aad_data) = aad {
        use aes_gcm::aead::Payload;
        cipher.encrypt(nonce_arr, Payload { msg: plaintext, aad: aad_data })
    } else {
        cipher.encrypt(nonce_arr, plaintext)
    };

    let ciphertext = ciphertext
        .map_err(|_| PyValueError::new_err("Encryption failed"))?;

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
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("Invalid key"))?;

    let nonce_arr = Nonce::from_slice(nonce);

    // Decrypt with AAD if provided
    let plaintext = if let Some(aad_data) = aad {
        use aes_gcm::aead::Payload;
        cipher.decrypt(nonce_arr, Payload { msg: ciphertext, aad: aad_data })
    } else {
        cipher.decrypt(nonce_arr, ciphertext)
    };

    let plaintext = plaintext
        .map_err(|_| PyValueError::new_err("Decryption failed - authentication error"))?;

    Ok(PyBytes::new(py, &plaintext))
}

// =============================================================================
// HMAC-SHA256
// =============================================================================

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256.
#[pyfunction]
fn hmac_sha256<'py>(
    py: Python<'py>,
    key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key)
        .map_err(|_| PyValueError::new_err("Invalid key length"))?;
    mac.update(message);
    let result = mac.finalize();
    Ok(PyBytes::new(py, result.into_bytes().as_slice()))
}

/// Verify HMAC-SHA256 in constant time.
#[pyfunction]
fn hmac_sha256_verify(
    key: &[u8],
    message: &[u8],
    expected_tag: &[u8],
) -> PyResult<bool> {
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
#[pyfunction]
fn secure_zero(py: Python<'_>, data: &Bound<'_, pyo3::types::PyByteArray>) -> PyResult<()> {
    // Get mutable access to the bytearray
    unsafe {
        let slice = data.as_bytes_mut();
        // Use zeroize to securely zero the memory
        slice.zeroize();
    }
    Ok(())
}

/// Secure random bytes.
#[pyfunction]
fn secure_random<'py>(py: Python<'py>, size: usize) -> PyResult<Bound<'py, PyBytes>> {
    use rand::RngCore;
    let mut buffer = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut buffer);
    Ok(PyBytes::new(py, &buffer))
}

/// Get backend info.
#[pyfunction]
fn backend_info() -> String {
    format!(
        "meow_crypto_rs v{} (Rust)",
        env!("CARGO_PKG_VERSION")
    )
}

// =============================================================================
// ML-KEM-768 (Post-Quantum) - Kyber
// =============================================================================

#[pyfunction]
fn mlkem768_keygen<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (pk, sk) = mlkem768::keypair();
    Ok((
        PyBytes::new(py, sk.as_bytes()),
        PyBytes::new(py, pk.as_bytes()),
    ))
}

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
// Python Module
// =============================================================================

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

    // Post-quantum stubs
    m.add_function(wrap_pyfunction!(mlkem768_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem768_decapsulate, m)?)?;

    Ok(())
}
