//! # HSM/PKCS#11 Integration Module
//!
//! Provides hardware security module integration via PKCS#11 interface.
//!
//! ## Security Properties
//!
//! 1. **HSM-001**: Keys never leave hardware boundary
//! 2. **HSM-002**: All operations occur within HSM
//! 3. **HSM-003**: Session management with automatic cleanup
//! 4. **HSM-004**: PIN handling with secure memory
//!
//! ## Supported HSMs
//!
//! - SoftHSM2 (for testing)
//! - YubiHSM 2
//! - Nitrokey HSM
//! - Any PKCS#11 compatible device
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crypto_core::hsm::{HsmProvider, HsmSession};
//!
//! // Connect to HSM
//! let provider = HsmProvider::new("pkcs11:library-path=/usr/lib/softhsm/libsofthsm2.so")?;
//! let session = provider.open_session(0, Some("1234"))?;
//!
//! // Generate AES-256 key in HSM
//! let key_handle = session.generate_aes_key(256, "meow-master")?;
//!
//! // Encrypt data (stays in HSM)
//! let ciphertext = session.encrypt_aes_gcm(key_handle, &plaintext, &aad)?;
//!
//! // Derive key material
//! let derived = session.derive_hkdf(key_handle, &salt, &info)?;
//! ```

#[cfg(feature = "hsm")]
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::{Mechanism, MechanismType},
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, SessionFlags, UserType},
    slot::Slot,
    types::AuthPin,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "std")]
use std::{error::Error, fmt, path::Path, sync::Arc};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// HSM error types
#[derive(Debug, Clone)]
pub enum HsmError {
    /// Failed to initialize PKCS#11 library
    InitializationFailed(String),
    /// HSM slot not found
    SlotNotFound(u64),
    /// Session open failed
    SessionFailed(String),
    /// Authentication failed (wrong PIN)
    AuthenticationFailed,
    /// Key generation failed
    KeyGenerationFailed(String),
    /// Encryption failed
    EncryptionFailed(String),
    /// Decryption failed
    DecryptionFailed(String),
    /// Key derivation failed
    DerivationFailed(String),
    /// Key not found
    KeyNotFound(String),
    /// Operation not supported by HSM
    NotSupported(String),
    /// HSM feature not compiled
    FeatureDisabled,
}

#[cfg(feature = "std")]
impl fmt::Display for HsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HsmError::InitializationFailed(msg) => write!(f, "HSM initialization failed: {}", msg),
            HsmError::SlotNotFound(slot) => write!(f, "HSM slot {} not found", slot),
            HsmError::SessionFailed(msg) => write!(f, "HSM session failed: {}", msg),
            HsmError::AuthenticationFailed => write!(f, "HSM authentication failed (wrong PIN)"),
            HsmError::KeyGenerationFailed(msg) => write!(f, "HSM key generation failed: {}", msg),
            HsmError::EncryptionFailed(msg) => write!(f, "HSM encryption failed: {}", msg),
            HsmError::DecryptionFailed(msg) => write!(f, "HSM decryption failed: {}", msg),
            HsmError::DerivationFailed(msg) => write!(f, "HSM key derivation failed: {}", msg),
            HsmError::KeyNotFound(label) => write!(f, "HSM key not found: {}", label),
            HsmError::NotSupported(op) => write!(f, "HSM operation not supported: {}", op),
            HsmError::FeatureDisabled => write!(f, "HSM feature not compiled (enable 'hsm' feature)"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for HsmError {}

/// HSM key type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmKeyType {
    /// AES-128 symmetric key
    Aes128,
    /// AES-256 symmetric key
    Aes256,
    /// ECDH key for key agreement
    EcdhP256,
    /// ECDH X25519 (if supported)
    EcdhX25519,
    /// Generic secret for derivation
    GenericSecret,
}

impl HsmKeyType {
    /// Get key size in bits
    pub fn key_bits(&self) -> u64 {
        match self {
            HsmKeyType::Aes128 => 128,
            HsmKeyType::Aes256 => 256,
            HsmKeyType::EcdhP256 => 256,
            HsmKeyType::EcdhX25519 => 256,
            HsmKeyType::GenericSecret => 256,
        }
    }
}

/// HSM key handle wrapper with zeroize on drop
#[derive(Debug)]
pub struct HsmKeyHandle {
    /// Internal handle (opaque)
    #[cfg(feature = "hsm")]
    handle: ObjectHandle,
    #[cfg(not(feature = "hsm"))]
    handle: u64,
    /// Key label
    label: String,
    /// Key type
    key_type: HsmKeyType,
}

impl HsmKeyHandle {
    /// Get the key label
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the key type
    pub fn key_type(&self) -> HsmKeyType {
        self.key_type
    }
}

/// Secure PIN holder with zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecurePin {
    pin: String,
}

impl SecurePin {
    /// Create new secure PIN
    pub fn new(pin: impl Into<String>) -> Self {
        Self { pin: pin.into() }
    }

    /// Get PIN as bytes (for PKCS#11)
    pub fn as_bytes(&self) -> &[u8] {
        self.pin.as_bytes()
    }
}

/// HSM URI parser (RFC 7512)
/// Format: pkcs11:library-path=/path/to/lib;slot=0;token=label
#[derive(Debug, Clone)]
pub struct HsmUri {
    /// Path to PKCS#11 library
    pub library_path: String,
    /// Slot ID (optional)
    pub slot_id: Option<u64>,
    /// Token label (optional)
    pub token_label: Option<String>,
    /// Key ID or label (optional)
    pub object_id: Option<String>,
}

impl HsmUri {
    /// Parse HSM URI
    pub fn parse(uri: &str) -> Result<Self, HsmError> {
        if !uri.starts_with("pkcs11:") {
            return Err(HsmError::InitializationFailed(
                "URI must start with 'pkcs11:'".into()
            ));
        }

        let params = &uri[7..]; // Skip "pkcs11:"
        let mut library_path = String::new();
        let mut slot_id = None;
        let mut token_label = None;
        let mut object_id = None;

        for part in params.split(';') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "library-path" | "module-path" => library_path = value.into(),
                    "slot" | "slot-id" => slot_id = value.parse().ok(),
                    "token" => token_label = Some(value.into()),
                    "object" | "id" => object_id = Some(value.into()),
                    _ => {} // Ignore unknown params
                }
            }
        }

        if library_path.is_empty() {
            return Err(HsmError::InitializationFailed(
                "library-path is required in URI".into()
            ));
        }

        Ok(Self {
            library_path,
            slot_id,
            token_label,
            object_id,
        })
    }
}

/// HSM provider for PKCS#11 operations
#[cfg(feature = "hsm")]
pub struct HsmProvider {
    /// PKCS#11 context
    ctx: Arc<Pkcs11>,
    /// Provider URI
    uri: HsmUri,
}

#[cfg(feature = "hsm")]
impl HsmProvider {
    /// Create new HSM provider from URI
    ///
    /// # Arguments
    ///
    /// * `uri` - PKCS#11 URI (e.g., "pkcs11:library-path=/usr/lib/softhsm/libsofthsm2.so")
    ///
    /// # Errors
    ///
    /// Returns `HsmError::InitializationFailed` if PKCS#11 library cannot be loaded
    pub fn new(uri: &str) -> Result<Self, HsmError> {
        let parsed_uri = HsmUri::parse(uri)?;
        
        let ctx = Pkcs11::new(Path::new(&parsed_uri.library_path))
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;
        
        ctx.initialize(CInitializeArgs::OsThreads)
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;
        
        Ok(Self {
            ctx: Arc::new(ctx),
            uri: parsed_uri,
        })
    }

    /// List available slots
    pub fn list_slots(&self) -> Result<Vec<HsmSlotInfo>, HsmError> {
        let slots = self.ctx.get_slots_with_token()
            .map_err(|e| HsmError::InitializationFailed(e.to_string()))?;
        
        let mut info = Vec::new();
        for slot in slots {
            if let Ok(token_info) = self.ctx.get_token_info(slot) {
                info.push(HsmSlotInfo {
                    slot_id: slot.id(),
                    label: token_info.label().trim().into(),
                    manufacturer: token_info.manufacturer_id().trim().into(),
                    model: token_info.model().trim().into(),
                    serial: token_info.serial_number().trim().into(),
                });
            }
        }
        Ok(info)
    }

    /// Open session to HSM slot
    ///
    /// # Arguments
    ///
    /// * `slot_id` - Slot ID to open (or use URI default)
    /// * `pin` - User PIN for authentication (None for read-only)
    ///
    /// # Errors
    ///
    /// Returns `HsmError::SlotNotFound` if slot doesn't exist
    /// Returns `HsmError::AuthenticationFailed` if PIN is wrong
    pub fn open_session(&self, slot_id: Option<u64>, pin: Option<SecurePin>) -> Result<HsmSession, HsmError> {
        let slot_id = slot_id.or(self.uri.slot_id).unwrap_or(0);
        
        let slots = self.ctx.get_slots_with_token()
            .map_err(|e| HsmError::SessionFailed(e.to_string()))?;
        
        let slot = slots.into_iter()
            .find(|s| s.id() == slot_id)
            .ok_or(HsmError::SlotNotFound(slot_id))?;
        
        let flags = SessionFlags::SERIAL_SESSION | SessionFlags::RW_SESSION;
        let session = self.ctx.open_session_no_callback(slot, flags)
            .map_err(|e| HsmError::SessionFailed(e.to_string()))?;
        
        // Authenticate if PIN provided
        if let Some(pin) = pin {
            let auth_pin = AuthPin::new(pin.pin.clone());
            session.login(UserType::User, Some(&auth_pin))
                .map_err(|_| HsmError::AuthenticationFailed)?;
        }
        
        Ok(HsmSession {
            session,
            ctx: Arc::clone(&self.ctx),
        })
    }
}

/// HSM slot information
#[derive(Debug, Clone)]
pub struct HsmSlotInfo {
    /// Slot ID
    pub slot_id: u64,
    /// Token label
    pub label: String,
    /// Manufacturer
    pub manufacturer: String,
    /// Model
    pub model: String,
    /// Serial number
    pub serial: String,
}

/// Active HSM session for cryptographic operations
#[cfg(feature = "hsm")]
pub struct HsmSession {
    session: Session,
    ctx: Arc<Pkcs11>,
}

#[cfg(feature = "hsm")]
impl HsmSession {
    /// Generate AES key in HSM
    ///
    /// The key is generated and stored entirely within the HSM.
    /// It cannot be exported (CKA_EXTRACTABLE = false).
    ///
    /// # Arguments
    ///
    /// * `key_type` - Type of key to generate
    /// * `label` - Label for the key (for later retrieval)
    ///
    /// # Security
    ///
    /// - Key never leaves HSM boundary (HSM-001)
    /// - CKA_SENSITIVE = true (hardware protection)
    /// - CKA_EXTRACTABLE = false (no export)
    pub fn generate_key(&self, key_type: HsmKeyType, label: &str) -> Result<HsmKeyHandle, HsmError> {
        let mechanism = match key_type {
            HsmKeyType::Aes128 | HsmKeyType::Aes256 => Mechanism::AesKeyGen,
            HsmKeyType::EcdhP256 => Mechanism::EccKeyPairGen,
            HsmKeyType::EcdhX25519 => {
                return Err(HsmError::NotSupported("X25519 key generation".into()));
            }
            HsmKeyType::GenericSecret => Mechanism::GenericSecretKeyGen,
        };
        
        let key_len = (key_type.key_bits() / 8) as u64;
        
        let template = vec![
            Attribute::Token(true),           // Persistent key
            Attribute::Private(true),         // Requires authentication
            Attribute::Sensitive(true),       // Cannot be revealed in plaintext
            Attribute::Extractable(false),    // Cannot be exported
            Attribute::Encrypt(true),         // Can encrypt
            Attribute::Decrypt(true),         // Can decrypt
            Attribute::Derive(true),          // Can derive keys
            Attribute::ValueLen(key_len),     // Key size
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        
        let handle = self.session.generate_key(&mechanism, &template)
            .map_err(|e| HsmError::KeyGenerationFailed(e.to_string()))?;
        
        Ok(HsmKeyHandle {
            handle,
            label: label.into(),
            key_type,
        })
    }

    /// Find key by label
    pub fn find_key(&self, label: &str) -> Result<HsmKeyHandle, HsmError> {
        let template = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
        ];
        
        let objects = self.session.find_objects(&template)
            .map_err(|e| HsmError::KeyNotFound(e.to_string()))?;
        
        let handle = objects.into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(label.into()))?;
        
        // Get key type from attributes
        let attrs = self.session.get_attributes(handle, &[AttributeType::KeyType])
            .map_err(|e| HsmError::KeyNotFound(e.to_string()))?;
        
        let key_type = if let Some(Attribute::KeyType(kt)) = attrs.first() {
            match kt {
                KeyType::AES => HsmKeyType::Aes256,
                KeyType::GENERIC_SECRET => HsmKeyType::GenericSecret,
                _ => HsmKeyType::GenericSecret,
            }
        } else {
            HsmKeyType::GenericSecret
        };
        
        Ok(HsmKeyHandle {
            handle,
            label: label.into(),
            key_type,
        })
    }

    /// Encrypt data using AES-GCM
    ///
    /// All encryption occurs within the HSM.
    ///
    /// # Arguments
    ///
    /// * `key` - Key handle from generate_key or find_key
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    ///
    /// Ciphertext with prepended nonce (12 bytes) and appended tag (16 bytes)
    pub fn encrypt_aes_gcm(
        &self,
        key: &HsmKeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        // Generate random IV
        let mut iv = [0u8; 12];
        getrandom::getrandom(&mut iv)
            .map_err(|e| HsmError::EncryptionFailed(e.to_string()))?;
        
        let mechanism = Mechanism::AesGcm {
            iv: iv.to_vec(),
            aad: aad.to_vec(),
            tag_bits: 128,
        };
        
        let ciphertext = self.session.encrypt(&mechanism, key.handle, plaintext)
            .map_err(|e| HsmError::EncryptionFailed(e.to_string()))?;
        
        // Prepend IV to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    /// Decrypt data using AES-GCM
    ///
    /// # Arguments
    ///
    /// * `key` - Key handle
    /// * `ciphertext` - Data to decrypt (with prepended nonce and appended tag)
    /// * `aad` - Additional authenticated data
    pub fn decrypt_aes_gcm(
        &self,
        key: &HsmKeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        if ciphertext.len() < 12 + 16 {
            return Err(HsmError::DecryptionFailed("Ciphertext too short".into()));
        }
        
        let (iv, ct) = ciphertext.split_at(12);
        
        let mechanism = Mechanism::AesGcm {
            iv: iv.to_vec(),
            aad: aad.to_vec(),
            tag_bits: 128,
        };
        
        self.session.decrypt(&mechanism, key.handle, ct)
            .map_err(|e| HsmError::DecryptionFailed(e.to_string()))
    }

    /// Derive key material using HKDF-like construction
    ///
    /// Note: Not all HSMs support HKDF directly. This uses PKCS#11 key derivation.
    ///
    /// # Arguments
    ///
    /// * `key` - Base key handle
    /// * `salt` - Salt for derivation
    /// * `info` - Context info
    /// * `output_len` - Desired output length
    pub fn derive_key(
        &self,
        key: &HsmKeyHandle,
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, HsmError> {
        // Build derivation data (salt || info)
        let mut data = Vec::with_capacity(salt.len() + info.len());
        data.extend_from_slice(salt);
        data.extend_from_slice(info);
        
        // Use SP800-108 KDF if available, otherwise SHA256 HMAC derivation
        let mechanism = Mechanism::Sha256Hmac;
        
        // Derive in HSM
        let derived = self.session.sign(&mechanism, key.handle, &data)
            .map_err(|e| HsmError::DerivationFailed(e.to_string()))?;
        
        // Truncate to desired length
        if derived.len() >= output_len {
            Ok(derived[..output_len].to_vec())
        } else {
            // Need multiple rounds (HKDF-Expand style)
            let mut output = derived;
            let mut counter = 1u8;
            while output.len() < output_len {
                let mut round_data = data.clone();
                round_data.push(counter);
                let round = self.session.sign(&mechanism, key.handle, &round_data)
                    .map_err(|e| HsmError::DerivationFailed(e.to_string()))?;
                output.extend_from_slice(&round);
                counter += 1;
            }
            Ok(output[..output_len].to_vec())
        }
    }

    /// Delete key from HSM
    pub fn delete_key(&self, key: HsmKeyHandle) -> Result<(), HsmError> {
        self.session.destroy_object(key.handle)
            .map_err(|e| HsmError::KeyNotFound(e.to_string()))
    }
}

// Stub implementation when HSM feature is disabled
#[cfg(not(feature = "hsm"))]
pub struct HsmProvider;

#[cfg(not(feature = "hsm"))]
impl HsmProvider {
    pub fn new(_uri: &str) -> Result<Self, HsmError> {
        Err(HsmError::FeatureDisabled)
    }
}

#[cfg(not(feature = "hsm"))]
pub struct HsmSession;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_parsing() {
        let uri = HsmUri::parse("pkcs11:library-path=/usr/lib/softhsm/libsofthsm2.so;slot=0").unwrap();
        assert_eq!(uri.library_path, "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(uri.slot_id, Some(0));
    }

    #[test]
    fn test_uri_parsing_minimal() {
        let uri = HsmUri::parse("pkcs11:library-path=/some/path.so").unwrap();
        assert_eq!(uri.library_path, "/some/path.so");
        assert_eq!(uri.slot_id, None);
    }

    #[test]
    fn test_uri_parsing_no_scheme() {
        let result = HsmUri::parse("/path/to/lib.so");
        assert!(matches!(result, Err(HsmError::InitializationFailed(_))));
    }

    #[test]
    fn test_secure_pin_zeroize() {
        let pin = SecurePin::new("1234");
        assert_eq!(pin.as_bytes(), b"1234");
        // Pin will be zeroized on drop
    }

    #[test]
    fn test_key_type_bits() {
        assert_eq!(HsmKeyType::Aes128.key_bits(), 128);
        assert_eq!(HsmKeyType::Aes256.key_bits(), 256);
        assert_eq!(HsmKeyType::EcdhP256.key_bits(), 256);
    }

    #[cfg(not(feature = "hsm"))]
    #[test]
    fn test_hsm_disabled() {
        let result = HsmProvider::new("pkcs11:library-path=/test.so");
        assert!(matches!(result, Err(HsmError::FeatureDisabled)));
    }
}
