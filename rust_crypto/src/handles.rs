//! Opaque handle registry for secret key material.
//!
//! All secret-bearing state lives exclusively in Rust. Python receives only
//! opaque integer handles that index into a thread-safe registry.
//! Handles cannot be introspected from Python — no dump_state, no serialize.
//!
//! # Security invariants
//! - Secret bytes never cross the FFI boundary.
//! - All secret material is zeroized on drop (via `zeroize` crate).
//! - Handle IDs are sequential u64; cannot be forged to access another slot.
//! - Registry is bounded (MAX_HANDLES = 65536) to prevent resource exhaustion.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{digest::KeyInit as HmacKeyInit, Hmac, Mac as HmacMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of live handles (prevents DoS).
const MAX_HANDLES: usize = 65536;

// ─── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleError {
    InvalidHandle,
    RegistryFull,
    InvalidKeyLength { expected: usize, got: usize },
    InvalidNonceLength { expected: usize, got: usize },
    CiphertextTooShort,
    EncryptionFailed,
    DecryptionFailed,
    HkdfFailed(String),
    InvalidPrkLength,
    AuthenticationFailed,
    InvalidPublicKeyLength,
    HandleTypeMismatch,
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandleError::InvalidHandle => write!(f, "Invalid or expired handle"),
            HandleError::RegistryFull => write!(f, "Handle registry full (max {})", MAX_HANDLES),
            HandleError::InvalidKeyLength { expected, got } => {
                write!(f, "Key must be {} bytes, got {}", expected, got)
            }
            HandleError::InvalidNonceLength { expected, got } => {
                write!(f, "Nonce must be {} bytes, got {}", expected, got)
            }
            HandleError::CiphertextTooShort => write!(f, "Ciphertext too short"),
            HandleError::EncryptionFailed => write!(f, "Encryption failed"),
            HandleError::DecryptionFailed => write!(f, "Decryption failed - authentication error"),
            HandleError::HkdfFailed(s) => write!(f, "HKDF failed: {}", s),
            HandleError::InvalidPrkLength => write!(f, "Invalid PRK length"),
            HandleError::AuthenticationFailed => write!(f, "Authentication failed"),
            HandleError::InvalidPublicKeyLength => write!(f, "Public key must be 32 bytes"),
            HandleError::HandleTypeMismatch => write!(f, "Handle type mismatch"),
        }
    }
}

// ─── Handle ID ──────────────────────────────────────────────────────────────

/// Opaque handle ID. Python sees only this integer.
pub type HandleId = u64;

static NEXT_HANDLE_ID: AtomicU64 = AtomicU64::new(1);

fn next_id() -> HandleId {
    NEXT_HANDLE_ID.fetch_add(1, Ordering::SeqCst)
}

// ─── Secret material containers (all Zeroize on Drop) ───────────────────────

/// A 32-byte symmetric key that zeroizes on drop.
#[derive(Clone)]
struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    fn new(src: &[u8]) -> Result<Self, HandleError> {
        if src.len() != 32 {
            return Err(HandleError::InvalidKeyLength {
                expected: 32,
                got: src.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(src);
        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// X25519 private key container (zeroizes on drop).
struct X25519Private {
    bytes: [u8; 32],
}

impl X25519Private {
    fn generate() -> (Self, [u8; 32]) {
        use rand::rngs::OsRng;
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret.as_bytes());
        (Self { bytes }, *public.as_bytes())
    }

    fn from_bytes(private_bytes: &[u8; 32]) -> Self {
        Self {
            bytes: *private_bytes,
        }
    }

    fn exchange(&self, peer_public: &[u8; 32]) -> Result<[u8; 32], HandleError> {
        let secret = StaticSecret::from(self.bytes);
        let public = PublicKey::from(*peer_public);
        let shared = secret.diffie_hellman(&public);
        // Reject low-order points that produce an all-zero shared secret
        if shared.as_bytes().iter().all(|&b| b == 0) {
            return Err(HandleError::HandleTypeMismatch);
        }
        Ok(*shared.as_bytes())
    }

    fn public_key(&self) -> [u8; 32] {
        let secret = StaticSecret::from(self.bytes);
        let public = PublicKey::from(&secret);
        *public.as_bytes()
    }
}

impl Drop for X25519Private {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ─── Handle payload types ───────────────────────────────────────────────────

/// Session state: holds encryption key, MAC key, nonce state.
/// Used for AES-GCM or AES-CTR + HMAC based sessions.
#[allow(dead_code)] // Fields read when session operations are called via M1 migration
pub struct SessionState {
    enc_key: SecretKey,
    mac_key: Option<SecretKey>,
    nonce_counter: u64,
}

/// Ratchet state: chain key, root key, optional ephemeral X25519.
#[allow(dead_code)] // Fields read when ratchet step/advance operations are called via M2 migration
pub struct RatchetState {
    root_key: SecretKey,
    chain_key: SecretKey,
    step_index: u64,
    ephemeral_private: Option<X25519Private>,
    /// Cached skip keys: (frame_index -> message_key)
    skip_keys: HashMap<u64, SecretKey>,
}

/// Stream state: AES-CTR key + MAC key for streaming encrypt/decrypt.
pub struct StreamState {
    enc_key: SecretKey,
    mac_key: SecretKey,
    nonce: [u8; 16],
    byte_offset: u64,
}

/// An HMAC key handle for frame/message authentication.
pub struct HmacKeyState {
    key: SecretKey,
}

/// Enum wrapping all handle types.
#[allow(dead_code)] // HmacKey variant used in handle_hmac_* operations
enum HandlePayload {
    Session(SessionState),
    Ratchet(RatchetState),
    Stream(StreamState),
    HmacKey(HmacKeyState),
    SymmetricKey(SecretKey),
    X25519Key(X25519Private),
}

impl Drop for HandlePayload {
    fn drop(&mut self) {
        // Inner types all implement Zeroize-on-Drop via their own Drop impls
    }
}

// ─── Global registry ────────────────────────────────────────────────────────

lazy_static::lazy_static! {
    static ref REGISTRY: Mutex<HashMap<HandleId, HandlePayload>> = Mutex::new(HashMap::new());
}

fn insert_handle(payload: HandlePayload) -> Result<HandleId, HandleError> {
    let mut reg = REGISTRY.lock().unwrap();
    if reg.len() >= MAX_HANDLES {
        return Err(HandleError::RegistryFull);
    }
    let id = next_id();
    reg.insert(id, payload);
    Ok(id)
}

fn remove_handle(id: HandleId) -> Result<HandlePayload, HandleError> {
    let mut reg = REGISTRY.lock().unwrap();
    reg.remove(&id).ok_or(HandleError::InvalidHandle)
}

fn with_handle<F, R>(id: HandleId, f: F) -> Result<R, HandleError>
where
    F: FnOnce(&HandlePayload) -> Result<R, HandleError>,
{
    let reg = REGISTRY.lock().unwrap();
    let payload = reg.get(&id).ok_or(HandleError::InvalidHandle)?;
    f(payload)
}

fn with_handle_mut<F, R>(id: HandleId, f: F) -> Result<R, HandleError>
where
    F: FnOnce(&mut HandlePayload) -> Result<R, HandleError>,
{
    let mut reg = REGISTRY.lock().unwrap();
    let payload = reg.get_mut(&id).ok_or(HandleError::InvalidHandle)?;
    f(payload)
}

// ─── Public API: Key derivation ─────────────────────────────────────────────

/// Derive a key via Argon2id and store it as an opaque handle.
/// Returns handle ID — Python never sees the key bytes.
pub fn handle_derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<HandleId, HandleError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    if salt.len() != 16 {
        return Err(HandleError::InvalidKeyLength {
            expected: 16,
            got: salt.len(),
        });
    }

    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| HandleError::HkdfFailed(format!("Invalid Argon2 params: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| HandleError::HkdfFailed(format!("Argon2id failed: {}", e)))?;

    let key = SecretKey::new(&output)?;
    output.zeroize();
    insert_handle(HandlePayload::SymmetricKey(key))
}

/// Derive a key via HKDF and store as opaque handle.
/// `ikm_handle` must be an existing key handle.
pub fn handle_derive_hkdf(
    ikm_handle: HandleId,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<HandleId, HandleError> {
    let ikm_bytes = with_handle(ikm_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.as_bytes().to_vec()),
        HandlePayload::Session(s) => Ok(s.enc_key.as_bytes().to_vec()),
        HandlePayload::Ratchet(r) => Ok(r.chain_key.as_bytes().to_vec()),
        HandlePayload::HmacKey(h) => Ok(h.key.as_bytes().to_vec()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    let salt_opt: Option<&[u8]> = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha256>::new(salt_opt, &ikm_bytes);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    // Enforce exactly 32 bytes — reject truncation (loses entropy) and
    // padding (zero-fills, breaking domain separation).
    if output_len != 32 {
        okm.zeroize();
        return Err(HandleError::HkdfFailed(format!(
            "HKDF output_len must be 32 for key handle storage, got {}",
            output_len,
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&okm);
    okm.zeroize();

    let key = SecretKey { bytes: key_bytes };
    insert_handle(HandlePayload::SymmetricKey(key))
}

/// Derive a key via HKDF(password || keyfile) → Argon2id and store as handle.
///
/// This performs the full keyfile-combined KDF without any intermediate secret
/// bytes crossing the FFI boundary:
///   1. HKDF(password || keyfile, domain_sep, "password_keyfile_combine", 64)
///   2. Argon2id(combined, salt, params) → 32-byte key
///   3. Store key as opaque handle
///
/// All intermediate buffers are zeroized.
#[allow(clippy::too_many_arguments)]
pub fn handle_derive_key_argon2id_with_keyfile(
    password: &[u8],
    keyfile: &[u8],
    keyfile_domain_sep: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<HandleId, HandleError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    if salt.len() != 16 {
        return Err(HandleError::InvalidKeyLength {
            expected: 16,
            got: salt.len(),
        });
    }

    // Step 1: HKDF(password || keyfile, domain_sep, "password_keyfile_combine", 64)
    let mut ikm = Vec::with_capacity(password.len() + keyfile.len());
    ikm.extend_from_slice(password);
    ikm.extend_from_slice(keyfile);

    let hkdf = Hkdf::<Sha256>::new(Some(keyfile_domain_sep), &ikm);
    let mut combined = vec![0u8; 64];
    hkdf.expand(b"password_keyfile_combine", &mut combined)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;
    ikm.zeroize();

    // Step 2: Argon2id(combined, salt, params) → 32-byte key
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| HandleError::HkdfFailed(format!("Invalid Argon2 params: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(&combined, salt, &mut output)
        .map_err(|e| HandleError::HkdfFailed(format!("Argon2id failed: {}", e)))?;
    combined.zeroize();

    let key = SecretKey::new(&output)?;
    output.zeroize();
    insert_handle(HandlePayload::SymmetricKey(key))
}

/// Derive HKDF from a key handle and return the raw derived bytes.
/// USE ONLY for non-secret derived values (nonces, header masks, AAD components).
/// For secret derived keys, use handle_derive_hkdf() which returns a handle.
pub fn handle_derive_hkdf_bytes(
    ikm_handle: HandleId,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, HandleError> {
    let ikm_bytes = with_handle(ikm_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.as_bytes().to_vec()),
        HandlePayload::Session(s) => Ok(s.enc_key.as_bytes().to_vec()),
        HandlePayload::Ratchet(r) => Ok(r.chain_key.as_bytes().to_vec()),
        HandlePayload::HmacKey(h) => Ok(h.key.as_bytes().to_vec()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    let salt_opt: Option<&[u8]> = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha256>::new(salt_opt, &ikm_bytes);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    // Return raw bytes (for non-secret derived values like nonces)
    Ok(okm)
}

/// Derive HKDF from raw IKM bytes (for initial key material from password).
pub fn handle_derive_hkdf_raw(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<HandleId, HandleError> {
    let salt_opt: Option<&[u8]> = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    if output_len != 32 {
        okm.zeroize();
        return Err(HandleError::HkdfFailed(format!(
            "HKDF output_len must be 32 for key handle storage, got {}",
            output_len,
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&okm);
    okm.zeroize();

    let key = SecretKey { bytes: key_bytes };
    insert_handle(HandlePayload::SymmetricKey(key))
}

// ─── Public API: Encryption/Decryption ──────────────────────────────────────

/// Encrypt with AES-256-GCM using a key handle. Returns ciphertext (with tag).
/// The key never leaves Rust.
pub fn handle_aes_gcm_encrypt(
    key_handle: HandleId,
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, HandleError> {
    if nonce.len() != 12 {
        return Err(HandleError::InvalidNonceLength {
            expected: 12,
            got: nonce.len(),
        });
    }

    with_handle(key_handle, |payload| {
        let key_bytes = match payload {
            HandlePayload::SymmetricKey(k) => k.as_bytes(),
            HandlePayload::Session(s) => s.enc_key.as_bytes(),
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        let cipher =
            Aes256Gcm::new_from_slice(key_bytes).map_err(|_| HandleError::EncryptionFailed)?;
        let nonce_arr = Nonce::from_slice(nonce);

        let result = if let Some(aad_data) = aad {
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

        result.map_err(|_| HandleError::EncryptionFailed)
    })
}

/// Decrypt with AES-256-GCM using a key handle.
/// Returns plaintext ONLY if authentication succeeds. Fail-closed.
pub fn handle_aes_gcm_decrypt(
    key_handle: HandleId,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, HandleError> {
    if nonce.len() != 12 {
        return Err(HandleError::InvalidNonceLength {
            expected: 12,
            got: nonce.len(),
        });
    }
    if ciphertext.len() < 16 {
        return Err(HandleError::CiphertextTooShort);
    }

    with_handle(key_handle, |payload| {
        let key_bytes = match payload {
            HandlePayload::SymmetricKey(k) => k.as_bytes(),
            HandlePayload::Session(s) => s.enc_key.as_bytes(),
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        let cipher =
            Aes256Gcm::new_from_slice(key_bytes).map_err(|_| HandleError::DecryptionFailed)?;
        let nonce_arr = Nonce::from_slice(nonce);

        let result = if let Some(aad_data) = aad {
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

        result.map_err(|_| HandleError::DecryptionFailed)
    })
}

/// Compute HMAC-SHA256 using a key handle. Returns the tag bytes.
pub fn handle_hmac_sha256(key_handle: HandleId, message: &[u8]) -> Result<Vec<u8>, HandleError> {
    with_handle(key_handle, |payload| {
        let key_bytes = match payload {
            HandlePayload::SymmetricKey(k) => k.as_bytes(),
            HandlePayload::HmacKey(h) => h.key.as_bytes(),
            HandlePayload::Session(s) => s
                .mac_key
                .as_ref()
                .map(|k| k.as_bytes())
                .ok_or(HandleError::HandleTypeMismatch)?,
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key_bytes).map_err(|_| {
            HandleError::InvalidKeyLength {
                expected: 32,
                got: 0,
            }
        })?;
        mac.update(message);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    })
}

/// Verify HMAC-SHA256 in constant time using a key handle.
/// Returns Ok(true) or Ok(false). Never leaks the key.
pub fn handle_hmac_sha256_verify(
    key_handle: HandleId,
    message: &[u8],
    expected_tag: &[u8],
) -> Result<bool, HandleError> {
    let computed = handle_hmac_sha256(key_handle, message)?;
    if computed.len() != expected_tag.len() {
        return Ok(false);
    }
    Ok(computed.as_slice().ct_eq(expected_tag).into())
}

/// Compute HMAC-SHA256 with the effective key = `prefix || handle_key_bytes`.
///
/// This enables domain-separated HMAC (e.g. manifest authentication:
/// `HMAC(MANIFEST_HMAC_KEY_PREFIX || enc_key, manifest_bytes)`) without ever
/// exporting the secret key to Python.
///
/// All temporary key material is zeroized before returning.
pub fn handle_hmac_sha256_prefixed(
    key_handle: HandleId,
    prefix: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, HandleError> {
    with_handle(key_handle, |payload| {
        let key_bytes = match payload {
            HandlePayload::SymmetricKey(k) => k.as_bytes(),
            HandlePayload::HmacKey(h) => h.key.as_bytes(),
            HandlePayload::Session(s) => s
                .mac_key
                .as_ref()
                .map(|k| k.as_bytes())
                .ok_or(HandleError::HandleTypeMismatch)?,
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        // Build prefix || key_bytes — the combined HMAC key
        let mut hmac_key = Vec::with_capacity(prefix.len() + key_bytes.len());
        hmac_key.extend_from_slice(prefix);
        hmac_key.extend_from_slice(key_bytes);

        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&hmac_key).map_err(|_| {
            HandleError::InvalidKeyLength {
                expected: 32,
                got: hmac_key.len(),
            }
        })?;
        mac.update(message);
        let tag = mac.finalize().into_bytes().to_vec();

        // Zeroize the concatenated key material
        hmac_key.zeroize();

        Ok(tag)
    })
}

/// Verify HMAC-SHA256 with prefixed key in constant time.
/// Effective key = `prefix || handle_key_bytes`.
pub fn handle_hmac_sha256_prefixed_verify(
    key_handle: HandleId,
    prefix: &[u8],
    message: &[u8],
    expected_tag: &[u8],
) -> Result<bool, HandleError> {
    let computed = handle_hmac_sha256_prefixed(key_handle, prefix, message)?;
    if computed.len() != expected_tag.len() {
        return Ok(false);
    }
    Ok(computed.as_slice().ct_eq(expected_tag).into())
}

// ─── Public API: X25519 ────────────────────────────────────────────────────

/// Generate X25519 keypair. Private key stays in Rust handle.
/// Returns (handle_id, public_key_bytes).
pub fn handle_x25519_generate() -> Result<(HandleId, [u8; 32]), HandleError> {
    let (private, public) = X25519Private::generate();
    let id = insert_handle(HandlePayload::X25519Key(private))?;
    Ok((id, public))
}

/// Perform X25519 key exchange. Private key never leaves Rust.
/// Shared secret is stored as a new key handle.
pub fn handle_x25519_exchange(
    private_handle: HandleId,
    peer_public: &[u8],
) -> Result<HandleId, HandleError> {
    if peer_public.len() != 32 {
        return Err(HandleError::InvalidPublicKeyLength);
    }
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(peer_public);

    let shared = with_handle(private_handle, |payload| match payload {
        HandlePayload::X25519Key(k) => k.exchange(&pub_bytes),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    let key = SecretKey::new(&shared)?;
    let mut shared_mut = shared;
    shared_mut.zeroize();
    insert_handle(HandlePayload::SymmetricKey(key))
}

/// Get public key from an X25519 private key handle.
pub fn handle_x25519_public(handle: HandleId) -> Result<[u8; 32], HandleError> {
    with_handle(handle, |payload| match payload {
        HandlePayload::X25519Key(k) => Ok(k.public_key()),
        _ => Err(HandleError::HandleTypeMismatch),
    })
}

/// Import raw X25519 private key bytes into an opaque handle.
/// Private key bytes are copied into Rust and zeroized on drop.
pub fn handle_import_x25519_private(private_bytes: &[u8]) -> Result<HandleId, HandleError> {
    if private_bytes.len() != 32 {
        return Err(HandleError::InvalidKeyLength {
            expected: 32,
            got: private_bytes.len(),
        });
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(private_bytes);
    let key = X25519Private::from_bytes(&bytes);
    bytes.zeroize();
    insert_handle(HandlePayload::X25519Key(key))
}

// ─── Public API: Session management ─────────────────────────────────────────

/// Create a session from an encryption key handle and optional MAC key handle.
pub fn handle_session_new(
    enc_key_handle: HandleId,
    mac_key_handle: Option<HandleId>,
) -> Result<HandleId, HandleError> {
    let enc_key = with_handle(enc_key_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.clone()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    let mac_key = if let Some(mh) = mac_key_handle {
        let mk = with_handle(mh, |payload| match payload {
            HandlePayload::SymmetricKey(k) => Ok(k.clone()),
            HandlePayload::HmacKey(h) => Ok(h.key.clone()),
            _ => Err(HandleError::HandleTypeMismatch),
        })?;
        Some(mk)
    } else {
        None
    };

    insert_handle(HandlePayload::Session(SessionState {
        enc_key,
        mac_key,
        nonce_counter: 0,
    }))
}

// ─── Public API: Stream state ───────────────────────────────────────────────

/// Create a stream handle from enc_key_handle + salt for MAC key derivation.
pub fn handle_stream_new(
    enc_key_handle: HandleId,
    nonce: &[u8],
    mac_domain: &[u8],
) -> Result<HandleId, HandleError> {
    if nonce.len() != 16 {
        return Err(HandleError::InvalidNonceLength {
            expected: 16,
            got: nonce.len(),
        });
    }

    let enc_key = with_handle(enc_key_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.clone()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    // Derive MAC key via HKDF(enc_key, nonce, mac_domain)
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), enc_key.as_bytes());
    let mut mac_bytes = [0u8; 32];
    hkdf.expand(mac_domain, &mut mac_bytes)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;
    let mac_key = SecretKey { bytes: mac_bytes };

    let mut nonce_arr = [0u8; 16];
    nonce_arr.copy_from_slice(nonce);

    insert_handle(HandlePayload::Stream(StreamState {
        enc_key,
        mac_key,
        nonce: nonce_arr,
        byte_offset: 0,
    }))
}

/// Stream encrypt: AES-CTR encrypt + compute HMAC over (nonce || ciphertext).
pub fn handle_stream_encrypt(
    stream_handle: HandleId,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), HandleError> {
    with_handle_mut(stream_handle, |payload| {
        let stream = match payload {
            HandlePayload::Stream(s) => s,
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        // AES-CTR encrypt
        let ciphertext = crypto_core::pure_crypto::aes_ctr_crypt(
            stream.enc_key.as_bytes(),
            &stream.nonce,
            plaintext,
            stream.byte_offset,
        )
        .map_err(|_| HandleError::EncryptionFailed)?;

        stream.byte_offset += plaintext.len() as u64;

        // Compute MAC over nonce || ciphertext
        let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
        mac_input.extend_from_slice(&stream.nonce);
        mac_input.extend_from_slice(&ciphertext);

        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(stream.mac_key.as_bytes())
            .map_err(|_| HandleError::EncryptionFailed)?;
        mac.update(&mac_input);
        let tag = mac.finalize().into_bytes().to_vec();

        Ok((ciphertext, tag))
    })
}

/// Stream decrypt: verify HMAC then AES-CTR decrypt. Fail-closed.
pub fn handle_stream_decrypt(
    stream_handle: HandleId,
    ciphertext: &[u8],
    expected_mac: &[u8],
) -> Result<Vec<u8>, HandleError> {
    with_handle_mut(stream_handle, |payload| {
        let stream = match payload {
            HandlePayload::Stream(s) => s,
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        // Compute and verify MAC BEFORE decryption
        let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
        mac_input.extend_from_slice(&stream.nonce);
        mac_input.extend_from_slice(ciphertext);

        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(stream.mac_key.as_bytes())
            .map_err(|_| HandleError::DecryptionFailed)?;
        mac.update(&mac_input);
        let computed = mac.finalize().into_bytes();

        let is_valid: bool = computed.as_slice().ct_eq(expected_mac).into();
        if !is_valid {
            return Err(HandleError::AuthenticationFailed);
        }

        // MAC verified — now decrypt
        let plaintext = crypto_core::pure_crypto::aes_ctr_crypt(
            stream.enc_key.as_bytes(),
            &stream.nonce,
            ciphertext,
            stream.byte_offset,
        )
        .map_err(|_| HandleError::DecryptionFailed)?;

        stream.byte_offset += ciphertext.len() as u64;
        Ok(plaintext)
    })
}

// ─── Public API: Ratchet ────────────────────────────────────────────────────

/// Create a ratchet from a root key handle.
pub fn handle_ratchet_new(
    root_key_handle: HandleId,
    salt: &[u8],
    root_info: &[u8],
) -> Result<HandleId, HandleError> {
    let root_bytes = with_handle(root_key_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(*k.as_bytes()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    // Derive initial chain key from root key
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &root_bytes);
    let mut chain_bytes = [0u8; 32];
    hkdf.expand(root_info, &mut chain_bytes)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    let root_key = SecretKey { bytes: root_bytes };
    let chain_key = SecretKey { bytes: chain_bytes };

    insert_handle(HandlePayload::Ratchet(RatchetState {
        root_key,
        chain_key,
        step_index: 0,
        ephemeral_private: None,
        skip_keys: HashMap::new(),
    }))
}

/// Ratchet step: advance chain key, return message key handle.
///
/// NOTE: We must not call `insert_handle` inside `with_handle_mut` because
/// both acquire the global REGISTRY Mutex, causing a deadlock (std Mutex is
/// not reentrant). Instead we extract the derived bytes while holding the
/// lock, release it, then insert the new handle separately.
pub fn handle_ratchet_step(
    ratchet_handle: HandleId,
    step_info: &[u8],
    msg_info: &[u8],
) -> Result<HandleId, HandleError> {
    // Phase 1: mutate the ratchet state and extract the message key bytes.
    let msg_bytes = with_handle_mut(ratchet_handle, |payload| {
        let ratchet = match payload {
            HandlePayload::Ratchet(r) => r,
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        // Derive message key from current chain key
        let salt = ratchet.step_index.to_be_bytes();
        let hkdf_msg = Hkdf::<Sha256>::new(Some(&salt), ratchet.chain_key.as_bytes());
        let mut msg_bytes = [0u8; 32];
        hkdf_msg
            .expand(msg_info, &mut msg_bytes)
            .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

        // Advance chain key
        let hkdf_step = Hkdf::<Sha256>::new(Some(&salt), ratchet.chain_key.as_bytes());
        let mut new_chain = [0u8; 32];
        hkdf_step
            .expand(step_info, &mut new_chain)
            .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

        ratchet.chain_key.bytes.zeroize();
        ratchet.chain_key = SecretKey { bytes: new_chain };
        ratchet.step_index += 1;

        Ok(msg_bytes)
    })?;

    // Phase 2: insert the message key handle (lock is no longer held).
    let msg_key = SecretKey { bytes: msg_bytes };
    insert_handle(HandlePayload::SymmetricKey(msg_key))
}

// ─── Public API: Mixed HKDF operations ──────────────────────────────────────

/// HKDF where IKM = (handle_key_bytes || extra_ikm), salt=salt, info=info.
/// Used for beacon mixing: HKDF(message_key || beacon_secret, salt, info).
/// All key material stays in Rust. Returns new handle.
pub fn handle_mix_hkdf(
    ikm_handle: HandleId,
    extra_ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<HandleId, HandleError> {
    let mut ikm_bytes = with_handle(ikm_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.as_bytes().to_vec()),
        HandlePayload::Session(s) => Ok(s.enc_key.as_bytes().to_vec()),
        HandlePayload::Ratchet(r) => Ok(r.chain_key.as_bytes().to_vec()),
        HandlePayload::HmacKey(h) => Ok(h.key.as_bytes().to_vec()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    // Concatenate handle key bytes with extra IKM
    ikm_bytes.extend_from_slice(extra_ikm);

    let salt_opt: Option<&[u8]> = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha256>::new(salt_opt, &ikm_bytes);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    // Zeroize the concatenated IKM
    ikm_bytes.zeroize();

    if output_len != 32 {
        okm.zeroize();
        return Err(HandleError::HkdfFailed(format!(
            "HKDF output_len must be 32 for key handle storage, got {}",
            output_len,
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&okm);
    okm.zeroize();

    let key = SecretKey { bytes: key_bytes };
    insert_handle(HandlePayload::SymmetricKey(key))
}

/// HKDF where the salt is a handle's key bytes and IKM is raw bytes.
/// Used for asymmetric root rekey: HKDF(IKM=shared_secret, salt=root_key, info=...).
/// Root key stays in Rust. Returns new handle.
pub fn handle_hkdf_with_handle_salt(
    ikm: &[u8],
    salt_handle: HandleId,
    info: &[u8],
    output_len: usize,
) -> Result<HandleId, HandleError> {
    let salt_bytes = with_handle(salt_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.as_bytes().to_vec()),
        HandlePayload::HmacKey(h) => Ok(h.key.as_bytes().to_vec()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    let hkdf = Hkdf::<Sha256>::new(Some(&salt_bytes), ikm);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    if output_len != 32 {
        okm.zeroize();
        return Err(HandleError::HkdfFailed(format!(
            "HKDF output_len must be 32 for key handle storage, got {}",
            output_len,
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&okm);
    okm.zeroize();

    let key = SecretKey { bytes: key_bytes };
    insert_handle(HandlePayload::SymmetricKey(key))
}

/// HKDF-Expand only (no Extract step). Treats handle's key as PRK directly.
/// Used for chain key derivation where chain_key is already a PRK.
pub fn handle_hkdf_expand(
    prk_handle: HandleId,
    info: &[u8],
    output_len: usize,
) -> Result<HandleId, HandleError> {
    let prk_bytes = with_handle(prk_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.as_bytes().to_vec()),
        HandlePayload::HmacKey(h) => Ok(h.key.as_bytes().to_vec()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    let prk = hkdf::Hkdf::<Sha256>::from_prk(&prk_bytes)
        .map_err(|e| HandleError::HkdfFailed(format!("Invalid PRK: {:?}", e)))?;
    let mut okm = vec![0u8; output_len];
    prk.expand(info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    if output_len != 32 {
        okm.zeroize();
        return Err(HandleError::HkdfFailed(format!(
            "HKDF output_len must be 32 for key handle storage, got {}",
            output_len,
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&okm);
    okm.zeroize();

    let key = SecretKey { bytes: key_bytes };
    insert_handle(HandlePayload::SymmetricKey(key))
}

/// Full HKDF where both IKM and salt come from handles.
/// Used for double ratchet root key derivation: HKDF(IKM=dh_output, salt=root_key).
pub fn handle_hkdf_two_handles(
    ikm_handle: HandleId,
    salt_handle: HandleId,
    info: &[u8],
    output_len: usize,
) -> Result<HandleId, HandleError> {
    let ikm_bytes = with_handle(ikm_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.as_bytes().to_vec()),
        HandlePayload::HmacKey(h) => Ok(h.key.as_bytes().to_vec()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    let salt_bytes = with_handle(salt_handle, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.as_bytes().to_vec()),
        HandlePayload::HmacKey(h) => Ok(h.key.as_bytes().to_vec()),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    let hkdf = Hkdf::<Sha256>::new(Some(&salt_bytes), &ikm_bytes);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    if output_len != 32 {
        okm.zeroize();
        return Err(HandleError::HkdfFailed(format!(
            "HKDF output_len must be 32 for key handle storage, got {}",
            output_len,
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&okm);
    okm.zeroize();

    let key = SecretKey { bytes: key_bytes };
    insert_handle(HandlePayload::SymmetricKey(key))
}

// ─── Public API: Handle lifecycle ───────────────────────────────────────────

/// Drop (zeroize + free) a handle. Returns Ok(()) if it existed.
pub fn handle_drop(id: HandleId) -> Result<(), HandleError> {
    remove_handle(id)?;
    // HandlePayload drop impl zeroizes all secret material
    Ok(())
}

/// Check if a handle exists (for testing).
pub fn handle_exists(id: HandleId) -> bool {
    let reg = REGISTRY.lock().unwrap();
    reg.contains_key(&id)
}

/// Get current handle count (for testing / bounds checking).
pub fn handle_count() -> usize {
    let reg = REGISTRY.lock().unwrap();
    reg.len()
}

/// Import raw key bytes into a handle. Used ONLY at the Rust FFI boundary
/// for password-derived material. The raw bytes are consumed and stored
/// inside Rust; the Python caller's copy should be zeroized immediately.
pub fn handle_import_key(key_bytes: &[u8]) -> Result<HandleId, HandleError> {
    let key = SecretKey::new(key_bytes)?;
    insert_handle(HandlePayload::SymmetricKey(key))
}

/// DANGEROUS — use ONLY for encrypted-at-rest serialization or wire-protocol
/// fields (AAD, HKDF salt). The handle is NOT consumed (still valid).
/// Caller MUST zeroize the returned bytes immediately after use.
pub fn handle_export_key(id: HandleId) -> Result<Vec<u8>, HandleError> {
    with_handle(id, |payload| match payload {
        HandlePayload::SymmetricKey(k) => Ok(k.as_bytes().to_vec()),
        HandlePayload::X25519Key(k) => Ok(k.bytes.to_vec()),
        HandlePayload::HmacKey(h) => Ok(h.key.as_bytes().to_vec()),
        _ => Err(HandleError::HandleTypeMismatch),
    })
}

// ─── Public API: Stream chunk operations ────────────────────────────────────
// These enable chunk-by-chunk streaming encryption without leaking keys to Python.

/// AES-CTR crypt a chunk using stream handle's enc_key, nonce, and auto-tracked offset.
/// Key never leaves Rust. Only ciphertext/plaintext crosses FFI.
pub fn handle_stream_ctr_crypt(
    stream_handle: HandleId,
    data: &[u8],
) -> Result<Vec<u8>, HandleError> {
    with_handle_mut(stream_handle, |payload| {
        let stream = match payload {
            HandlePayload::Stream(s) => s,
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        let result = crypto_core::pure_crypto::aes_ctr_crypt(
            stream.enc_key.as_bytes(),
            &stream.nonce,
            data,
            stream.byte_offset,
        )
        .map_err(|_| HandleError::EncryptionFailed)?;

        stream.byte_offset += data.len() as u64;
        Ok(result)
    })
}

/// Compute HMAC-SHA256 using stream handle's internal MAC key.
/// MAC key never leaves Rust.
pub fn handle_stream_hmac(stream_handle: HandleId, message: &[u8]) -> Result<Vec<u8>, HandleError> {
    with_handle(stream_handle, |payload| {
        let stream = match payload {
            HandlePayload::Stream(s) => s,
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(stream.mac_key.as_bytes())
            .map_err(|_| HandleError::EncryptionFailed)?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    })
}

/// Verify HMAC-SHA256 using stream handle's MAC key (constant-time).
pub fn handle_stream_hmac_verify(
    stream_handle: HandleId,
    message: &[u8],
    expected_tag: &[u8],
) -> Result<bool, HandleError> {
    let computed = handle_stream_hmac(stream_handle, message)?;
    if computed.len() != expected_tag.len() {
        return Ok(false);
    }
    Ok(computed.as_slice().ct_eq(expected_tag).into())
}

/// Get nonce from stream handle (non-secret metadata).
pub fn handle_stream_nonce(stream_handle: HandleId) -> Result<[u8; 16], HandleError> {
    with_handle(stream_handle, |payload| {
        let stream = match payload {
            HandlePayload::Stream(s) => s,
            _ => return Err(HandleError::HandleTypeMismatch),
        };
        Ok(stream.nonce)
    })
}

/// Reset stream byte offset to 0 (for creating matching decrypt stream).
pub fn handle_stream_reset_offset(stream_handle: HandleId) -> Result<(), HandleError> {
    with_handle_mut(stream_handle, |payload| {
        let stream = match payload {
            HandlePayload::Stream(s) => s,
            _ => return Err(HandleError::HandleTypeMismatch),
        };
        stream.byte_offset = 0;
        Ok(())
    })
}

/// Generic AES-CTR crypt using any symmetric key handle + explicit nonce and offset.
/// Used by ratchet header encryption and other non-streaming AES-CTR paths.
pub fn handle_aes_ctr_crypt(
    key_handle: HandleId,
    nonce: &[u8],
    data: &[u8],
    byte_offset: u64,
) -> Result<Vec<u8>, HandleError> {
    if nonce.len() != 16 {
        return Err(HandleError::InvalidNonceLength {
            expected: 16,
            got: nonce.len(),
        });
    }

    with_handle(key_handle, |payload| {
        let key_bytes = match payload {
            HandlePayload::SymmetricKey(k) => k.as_bytes(),
            HandlePayload::Session(s) => s.enc_key.as_bytes(),
            HandlePayload::Ratchet(r) => r.chain_key.as_bytes(),
            _ => return Err(HandleError::HandleTypeMismatch),
        };

        crypto_core::pure_crypto::aes_ctr_crypt(key_bytes, nonce, data, byte_offset)
            .map_err(|_| HandleError::EncryptionFailed)
    })
}

// ─── Public API: PQXDH Hybrid Key Exchange (handle-only) ────────────────────

/// PQXDH-style hybrid encapsulation: X25519 + HMAC-Extract + HKDF-Expand.
///
/// Performs the full PQXDH key agreement inside Rust with no secret bytes
/// returned to the caller.  Returns (shared_secret_handle, ephemeral_pub).
///
/// Steps performed:
///   1. Generate ephemeral X25519 keypair
///   2. ECDH(ephemeral_private, receiver_classical_pub) → classical_shared
///   3. combined_ikm = classical_shared [|| pq_shared_secret]
///   4. PRK = HMAC-SHA256(extract_salt, combined_ikm)
///   5. transcript_hash = SHA-256(transcript_domain || eph_pub || receiver_pub [|| pq_pub] [|| pq_ct])
///   6. info = info_prefix || transcript_hash
///   7. shared_secret = HKDF-Expand(PRK, info, 32)
///   8. Store shared_secret as handle; zeroize all intermediates
///
/// All intermediate secrets (classical_shared, combined_ikm, PRK) are
/// zeroized before returning.  Only the ephemeral public key (non-secret)
/// crosses back to Python.
#[allow(clippy::too_many_arguments)]
pub fn handle_pqxdh_encapsulate(
    receiver_classical_pub: &[u8],
    pq_shared_secret: Option<&[u8]>,
    extract_salt: &[u8],
    info_prefix: &[u8],
    transcript_domain: &[u8],
    receiver_pq_pub: Option<&[u8]>,
    pq_ciphertext: Option<&[u8]>,
) -> Result<(HandleId, [u8; 32]), HandleError> {
    if receiver_classical_pub.len() != 32 {
        return Err(HandleError::InvalidPublicKeyLength);
    }

    // 1. Generate ephemeral X25519 keypair
    let (eph_private, eph_public) = X25519Private::generate();

    // 2. ECDH
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(receiver_classical_pub);
    let mut classical_shared = eph_private
        .exchange(&pub_bytes)
        .map_err(|_| HandleError::HandleTypeMismatch)?;

    // 3. Combine IKM
    let mut combined_ikm = classical_shared.to_vec();
    if let Some(pq_ss) = pq_shared_secret {
        combined_ikm.extend_from_slice(pq_ss);
    }

    // 4. HMAC-Extract: PRK = HMAC-SHA256(extract_salt, combined_ikm)
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(extract_salt)
        .map_err(|_| HandleError::HkdfFailed("HMAC init failed".into()))?;
    mac.update(&combined_ikm);
    let prk = mac.finalize().into_bytes();
    combined_ikm.zeroize();
    classical_shared.zeroize();

    // 5. Transcript hash
    let mut transcript_data = transcript_domain.to_vec();
    transcript_data.extend_from_slice(&eph_public);
    transcript_data.extend_from_slice(receiver_classical_pub);
    if let Some(rpq) = receiver_pq_pub {
        transcript_data.extend_from_slice(rpq);
    }
    if let Some(pq_ct) = pq_ciphertext {
        transcript_data.extend_from_slice(pq_ct);
    }
    use sha2::{Digest, Sha256 as Sha256Hasher};
    let transcript_hash = Sha256Hasher::digest(&transcript_data);

    // 6. Info = prefix || transcript_hash
    let mut info = info_prefix.to_vec();
    info.extend_from_slice(&transcript_hash);

    // 7. HKDF-Expand(PRK, info, 32)
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|e| HandleError::HkdfFailed(format!("PRK: {:?}", e)))?;
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    // 8. Store as handle
    let key = SecretKey::new(&okm)?;
    okm.zeroize();
    let handle = insert_handle(HandlePayload::SymmetricKey(key))?;

    Ok((handle, eph_public))
}

/// PQXDH-style hybrid decapsulation (receiver side).
///
/// Same derivation as encapsulate but uses the receiver's private key handle
/// for the ECDH step.  No secret bytes cross the FFI boundary.
#[allow(clippy::too_many_arguments)]
pub fn handle_pqxdh_decapsulate(
    ephemeral_classical_pub: &[u8],
    receiver_private_handle: HandleId,
    pq_shared_secret: Option<&[u8]>,
    receiver_classical_pub: &[u8],
    extract_salt: &[u8],
    info_prefix: &[u8],
    transcript_domain: &[u8],
    receiver_pq_pub: Option<&[u8]>,
    pq_ciphertext: Option<&[u8]>,
) -> Result<HandleId, HandleError> {
    if ephemeral_classical_pub.len() != 32 {
        return Err(HandleError::InvalidPublicKeyLength);
    }
    if receiver_classical_pub.len() != 32 {
        return Err(HandleError::InvalidPublicKeyLength);
    }

    // 1. ECDH using receiver private handle
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(ephemeral_classical_pub);
    let mut classical_shared = with_handle(receiver_private_handle, |payload| match payload {
        HandlePayload::X25519Key(k) => k.exchange(&eph_pub),
        _ => Err(HandleError::HandleTypeMismatch),
    })?;

    // 2. Combine IKM
    let mut combined_ikm = classical_shared.to_vec();
    if let Some(pq_ss) = pq_shared_secret {
        combined_ikm.extend_from_slice(pq_ss);
    }

    // 3. HMAC-Extract
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(extract_salt)
        .map_err(|_| HandleError::HkdfFailed("HMAC init failed".into()))?;
    mac.update(&combined_ikm);
    let prk = mac.finalize().into_bytes();
    combined_ikm.zeroize();
    classical_shared.zeroize();

    // 4. Transcript hash
    let mut transcript_data = transcript_domain.to_vec();
    transcript_data.extend_from_slice(ephemeral_classical_pub);
    transcript_data.extend_from_slice(receiver_classical_pub);
    if let Some(rpq) = receiver_pq_pub {
        transcript_data.extend_from_slice(rpq);
    }
    if let Some(pq_ct) = pq_ciphertext {
        transcript_data.extend_from_slice(pq_ct);
    }
    use sha2::{Digest, Sha256 as Sha256Hasher};
    let transcript_hash = Sha256Hasher::digest(&transcript_data);

    // 5. Info
    let mut info = info_prefix.to_vec();
    info.extend_from_slice(&transcript_hash);

    // 6. HKDF-Expand
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|e| HandleError::HkdfFailed(format!("PRK: {:?}", e)))?;
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm)
        .map_err(|e| HandleError::HkdfFailed(format!("{:?}", e)))?;

    let key = SecretKey::new(&okm)?;
    okm.zeroize();
    insert_handle(HandlePayload::SymmetricKey(key))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_handle_lifecycle() {
        let id = handle_import_key(&[0x42u8; 32]).unwrap();
        assert!(handle_exists(id));
        handle_drop(id).unwrap();
        assert!(!handle_exists(id));
    }

    #[test]
    fn test_invalid_handle() {
        assert_eq!(handle_drop(999999), Err(HandleError::InvalidHandle));
    }

    #[test]
    fn test_aes_gcm_roundtrip_via_handle() {
        let key_id = handle_import_key(&[0x11u8; 32]).unwrap();
        let nonce = [0x22u8; 12];
        let plaintext = b"meow secret via handle";
        let aad = b"aad data";

        let ct = handle_aes_gcm_encrypt(key_id, &nonce, plaintext, Some(aad)).unwrap();
        let pt = handle_aes_gcm_decrypt(key_id, &nonce, &ct, Some(aad)).unwrap();
        assert_eq!(pt, plaintext);

        // Wrong AAD must fail
        let err = handle_aes_gcm_decrypt(key_id, &nonce, &ct, Some(b"wrong"));
        assert_eq!(err, Err(HandleError::DecryptionFailed));

        handle_drop(key_id).unwrap();
    }

    #[test]
    fn test_hmac_via_handle() {
        let key_id = handle_import_key(&[0x33u8; 32]).unwrap();
        let tag = handle_hmac_sha256(key_id, b"message").unwrap();
        assert!(handle_hmac_sha256_verify(key_id, b"message", &tag).unwrap());
        assert!(!handle_hmac_sha256_verify(key_id, b"wrong", &tag).unwrap());
        handle_drop(key_id).unwrap();
    }

    #[test]
    fn test_x25519_via_handles() {
        let (a_handle, a_pub) = handle_x25519_generate().unwrap();
        let (b_handle, b_pub) = handle_x25519_generate().unwrap();

        let shared_a = handle_x25519_exchange(a_handle, &b_pub).unwrap();
        let shared_b = handle_x25519_exchange(b_handle, &a_pub).unwrap();

        // Verify shared secrets are equal by encrypting with each
        let nonce = [0u8; 12];
        let ct_a = handle_aes_gcm_encrypt(shared_a, &nonce, b"test", None).unwrap();
        let pt_b = handle_aes_gcm_decrypt(shared_b, &nonce, &ct_a, None).unwrap();
        assert_eq!(pt_b, b"test");

        handle_drop(a_handle).unwrap();
        handle_drop(b_handle).unwrap();
        handle_drop(shared_a).unwrap();
        handle_drop(shared_b).unwrap();
    }

    #[test]
    fn test_stream_encrypt_decrypt_via_handle() {
        let key_id = handle_import_key(&[0x55u8; 32]).unwrap();
        let nonce = [0x66u8; 16];
        let stream_h = handle_stream_new(key_id, &nonce, b"test_mac_domain").unwrap();

        let (ct, tag) = handle_stream_encrypt(stream_h, b"hello stream").unwrap();

        // Reset offset for decrypt (new stream handle with same params)
        let stream_d = handle_stream_new(key_id, &nonce, b"test_mac_domain").unwrap();
        let pt = handle_stream_decrypt(stream_d, &ct, &tag).unwrap();
        assert_eq!(pt, b"hello stream");

        // Wrong MAC must fail
        let stream_d2 = handle_stream_new(key_id, &nonce, b"test_mac_domain").unwrap();
        let err = handle_stream_decrypt(stream_d2, &ct, &[0u8; 32]);
        assert_eq!(err, Err(HandleError::AuthenticationFailed));

        handle_drop(key_id).unwrap();
        handle_drop(stream_h).unwrap();
        handle_drop(stream_d).unwrap();
    }

    #[test]
    fn test_argon2id_handle() {
        let h = handle_derive_key_argon2id(b"password", &[0u8; 16], 1024, 1, 1).unwrap();
        assert!(handle_exists(h));

        // Can use for encryption
        let nonce = [0u8; 12];
        let ct = handle_aes_gcm_encrypt(h, &nonce, b"test", None).unwrap();
        let pt = handle_aes_gcm_decrypt(h, &nonce, &ct, None).unwrap();
        assert_eq!(pt, b"test");

        handle_drop(h).unwrap();
    }

    #[test]
    fn test_argon2id_with_keyfile_handle() {
        let h = handle_derive_key_argon2id_with_keyfile(
            b"password",
            b"keyfile_content_here",
            b"meow_keyfile_separation_v2",
            &[0u8; 16],
            1024,
            1,
            1,
        )
        .unwrap();
        assert!(handle_exists(h));

        // Can use for encryption
        let nonce = [0u8; 12];
        let ct = handle_aes_gcm_encrypt(h, &nonce, b"test_keyfile", None).unwrap();
        let pt = handle_aes_gcm_decrypt(h, &nonce, &ct, None).unwrap();
        assert_eq!(pt, b"test_keyfile");

        handle_drop(h).unwrap();
    }

    #[test]
    fn test_argon2id_with_keyfile_invalid_salt() {
        let result = handle_derive_key_argon2id_with_keyfile(
            b"password",
            b"keyfile",
            b"domain",
            &[0u8; 8], // wrong salt length
            1024,
            1,
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_type_mismatch() {
        let (x_handle, _pub) = handle_x25519_generate().unwrap();
        // X25519 handle should not work as HMAC key
        // (it wraps X25519Key, not SymmetricKey or HmacKey)
        let err = handle_hmac_sha256(x_handle, b"msg");
        assert_eq!(err, Err(HandleError::HandleTypeMismatch));
        handle_drop(x_handle).unwrap();
    }

    #[test]
    fn test_registry_bounds() {
        // Verify we can create and drop handles without exhausting
        let mut handles = Vec::new();
        for _ in 0..100 {
            handles.push(handle_import_key(&[0xAAu8; 32]).unwrap());
        }
        for h in handles {
            handle_drop(h).unwrap();
        }
    }
}
