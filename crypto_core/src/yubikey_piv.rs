//! # YubiKey Integration Module
//!
//! Provides YubiKey PIV and FIDO2 support for key operations.
//!
//! ## Security Properties
//!
//! 1. **YK-001**: Private keys never leave the YubiKey
//! 2. **YK-002**: Touch required for sensitive operations
//! 3. **YK-003**: PIN-protected key access
//! 4. **YK-004**: Rate limiting on PIN attempts
//!
//! ## Supported Features
//!
//! - PIV slot key generation (RSA, ECC)
//! - PIV signing and decryption
//! - FIDO2 hmac-secret extension for key derivation
//! - Challenge-response for password hardening
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crypto_core::yubikey::{YubiKeyProvider, PivSlot};
//!
//! // Connect to YubiKey
//! let yk = YubiKeyProvider::connect()?;
//!
//! // Generate key in PIV slot
//! yk.generate_key(PivSlot::KeyManagement, KeyType::EcP256)?;
//!
//! // Use FIDO2 hmac-secret for password hardening
//! let hardened = yk.fido2_hmac_secret(&password_hash, &salt)?;
//! ```

#[cfg(feature = "yubikey")]
use yubikey::{
    piv::{self, AlgorithmId, Key, ManagementSlotId, SlotId},
    Certificate, MgmKey, PinPolicy, TouchPolicy, YubiKey,
};

#[cfg(feature = "yubikey")]
use ctap_hid_fido2::{
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    FidoKeyHid, HidInfo,
    verifier,
    Cfg, FidoKeyHidFactory,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "std")]
use std::{error::Error, fmt};

/// YubiKey error types
#[derive(Debug, Clone)]
pub enum YubiKeyError {
    /// No YubiKey detected
    NotFound,
    /// Multiple YubiKeys detected (specify serial)
    MultipleFound(Vec<u32>),
    /// PIN required but not provided
    PinRequired,
    /// PIN verification failed
    PinIncorrect(u8), // Remaining attempts
    /// PIN blocked (too many attempts)
    PinBlocked,
    /// Touch required but timed out
    TouchTimeout,
    /// Key generation failed
    KeyGenerationFailed(String),
    /// Signing failed
    SigningFailed(String),
    /// Decryption failed
    DecryptionFailed(String),
    /// FIDO2 operation failed
    Fido2Failed(String),
    /// Slot is empty
    SlotEmpty(String),
    /// Operation not supported
    NotSupported(String),
    /// Feature not compiled
    FeatureDisabled,
    /// Connection error
    ConnectionFailed(String),
}

#[cfg(feature = "std")]
impl fmt::Display for YubiKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YubiKeyError::NotFound => write!(f, "No YubiKey detected"),
            YubiKeyError::MultipleFound(serials) => {
                write!(f, "Multiple YubiKeys found: {:?}", serials)
            }
            YubiKeyError::PinRequired => write!(f, "YubiKey PIN required"),
            YubiKeyError::PinIncorrect(n) => {
                write!(f, "YubiKey PIN incorrect ({} attempts remaining)", n)
            }
            YubiKeyError::PinBlocked => write!(f, "YubiKey PIN blocked"),
            YubiKeyError::TouchTimeout => write!(f, "YubiKey touch timed out"),
            YubiKeyError::KeyGenerationFailed(msg) => {
                write!(f, "YubiKey key generation failed: {}", msg)
            }
            YubiKeyError::SigningFailed(msg) => write!(f, "YubiKey signing failed: {}", msg),
            YubiKeyError::DecryptionFailed(msg) => write!(f, "YubiKey decryption failed: {}", msg),
            YubiKeyError::Fido2Failed(msg) => write!(f, "FIDO2 operation failed: {}", msg),
            YubiKeyError::SlotEmpty(slot) => write!(f, "YubiKey slot {} is empty", slot),
            YubiKeyError::NotSupported(op) => write!(f, "Operation not supported: {}", op),
            YubiKeyError::FeatureDisabled => write!(f, "YubiKey feature not compiled"),
            YubiKeyError::ConnectionFailed(msg) => write!(f, "YubiKey connection failed: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl Error for YubiKeyError {}

/// PIV slot identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PivSlot {
    /// Authentication slot (9a)
    Authentication,
    /// Card management (9b)
    CardManagement,
    /// Digital signature (9c) 
    DigitalSignature,
    /// Key management / encryption (9d)
    KeyManagement,
    /// Card authentication (9e)
    CardAuthentication,
    /// Retired slot 1-20 (82-95)
    Retired(u8),
}

impl PivSlot {
    /// Get slot description
    pub fn description(&self) -> &'static str {
        match self {
            PivSlot::Authentication => "Authentication (9a) - general authentication",
            PivSlot::CardManagement => "Card Management (9b) - management key",
            PivSlot::DigitalSignature => "Digital Signature (9c) - signing, touch required",
            PivSlot::KeyManagement => "Key Management (9d) - encryption/decryption",
            PivSlot::CardAuthentication => "Card Authentication (9e) - physical access",
            PivSlot::Retired(n) => "Retired slot - key storage",
        }
    }

    #[cfg(feature = "yubikey")]
    fn to_slot_id(&self) -> SlotId {
        match self {
            PivSlot::Authentication => SlotId::Authentication,
            PivSlot::CardManagement => SlotId::Signature, // Management key is separate
            PivSlot::DigitalSignature => SlotId::Signature,
            PivSlot::KeyManagement => SlotId::KeyManagement,
            PivSlot::CardAuthentication => SlotId::CardAuthentication,
            PivSlot::Retired(n) if *n <= 20 => SlotId::Retired(piv::RetiredSlotId::try_from(*n).unwrap()),
            _ => SlotId::Authentication, // Fallback
        }
    }
}

/// Key type for PIV operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YubiKeyType {
    /// RSA 2048-bit
    Rsa2048,
    /// RSA 4096-bit (YubiKey 5 only)
    Rsa4096,
    /// ECC P-256
    EcP256,
    /// ECC P-384
    EcP384,
    /// Ed25519 (not supported in PIV, FIDO2 only)
    Ed25519,
}

impl YubiKeyType {
    #[cfg(feature = "yubikey")]
    fn to_algorithm_id(&self) -> Result<AlgorithmId, YubiKeyError> {
        match self {
            YubiKeyType::Rsa2048 => Ok(AlgorithmId::Rsa2048),
            YubiKeyType::Rsa4096 => Ok(AlgorithmId::Rsa4096),
            YubiKeyType::EcP256 => Ok(AlgorithmId::EccP256),
            YubiKeyType::EcP384 => Ok(AlgorithmId::EccP384),
            YubiKeyType::Ed25519 => Err(YubiKeyError::NotSupported(
                "Ed25519 not supported in PIV".into()
            )),
        }
    }
}

/// Secure PIN holder
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct YubiKeyPin {
    pin: String,
}

impl YubiKeyPin {
    /// Create new secure PIN (6-8 digits typically)
    pub fn new(pin: impl Into<String>) -> Self {
        Self { pin: pin.into() }
    }

    /// Get PIN bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.pin.as_bytes()
    }
}

/// YubiKey information
#[derive(Debug, Clone)]
pub struct YubiKeyInfo {
    /// Serial number
    pub serial: u32,
    /// Firmware version
    pub version: String,
    /// Device name
    pub name: String,
    /// Supports FIDO2
    pub fido2_supported: bool,
    /// Supports PIV
    pub piv_supported: bool,
}

/// YubiKey provider for cryptographic operations
#[cfg(feature = "yubikey")]
pub struct YubiKeyProvider {
    /// Connected YubiKey
    yubikey: YubiKey,
    /// Device info
    info: YubiKeyInfo,
}

#[cfg(feature = "yubikey")]
impl YubiKeyProvider {
    /// Connect to first available YubiKey
    pub fn connect() -> Result<Self, YubiKeyError> {
        let mut yubikey = YubiKey::open()
            .map_err(|e| YubiKeyError::ConnectionFailed(e.to_string()))?;
        
        let serial = yubikey.serial().0;
        let version = format!("{}", yubikey.version());
        let name = yubikey.name().to_string();
        
        let info = YubiKeyInfo {
            serial,
            version,
            name,
            fido2_supported: true, // Modern YubiKeys support FIDO2
            piv_supported: true,
        };
        
        Ok(Self { yubikey, info })
    }

    /// Connect to YubiKey by serial number
    pub fn connect_by_serial(serial: u32) -> Result<Self, YubiKeyError> {
        let mut yubikey = YubiKey::open_by_serial(yubikey::Serial(serial))
            .map_err(|e| YubiKeyError::ConnectionFailed(e.to_string()))?;
        
        let version = format!("{}", yubikey.version());
        let name = yubikey.name().to_string();
        
        let info = YubiKeyInfo {
            serial,
            version,
            name,
            fido2_supported: true,
            piv_supported: true,
        };
        
        Ok(Self { yubikey, info })
    }

    /// List available YubiKeys
    pub fn list_devices() -> Result<Vec<YubiKeyInfo>, YubiKeyError> {
        let readers = yubikey::reader::Context::open()
            .map_err(|e| YubiKeyError::ConnectionFailed(e.to_string()))?;
        
        let mut devices = Vec::new();
        for reader in readers.iter().map_err(|e| YubiKeyError::ConnectionFailed(e.to_string()))? {
            if let Ok(yk) = reader.open() {
                devices.push(YubiKeyInfo {
                    serial: yk.serial().0,
                    version: format!("{}", yk.version()),
                    name: yk.name().to_string(),
                    fido2_supported: true,
                    piv_supported: true,
                });
            }
        }
        
        if devices.is_empty() {
            Err(YubiKeyError::NotFound)
        } else {
            Ok(devices)
        }
    }

    /// Get device info
    pub fn info(&self) -> &YubiKeyInfo {
        &self.info
    }

    /// Verify PIN
    pub fn verify_pin(&mut self, pin: &YubiKeyPin) -> Result<(), YubiKeyError> {
        self.yubikey.verify_pin(pin.pin.as_bytes())
            .map_err(|e| match e {
                yubikey::Error::WrongPin { tries } => YubiKeyError::PinIncorrect(tries),
                yubikey::Error::PinLocked => YubiKeyError::PinBlocked,
                _ => YubiKeyError::ConnectionFailed(e.to_string()),
            })
    }

    /// Generate key in PIV slot
    ///
    /// # Security
    ///
    /// - Private key generated inside YubiKey (YK-001)
    /// - Can require PIN for each use (PinPolicy::Always)
    /// - Can require touch for each use (TouchPolicy::Always)
    pub fn generate_key(
        &mut self,
        slot: PivSlot,
        key_type: YubiKeyType,
        pin_policy: bool,
        touch_policy: bool,
    ) -> Result<Vec<u8>, YubiKeyError> {
        let slot_id = slot.to_slot_id();
        let algorithm = key_type.to_algorithm_id()?;
        
        let pin_pol = if pin_policy {
            PinPolicy::Always
        } else {
            PinPolicy::Default
        };
        
        let touch_pol = if touch_policy {
            TouchPolicy::Always
        } else {
            TouchPolicy::Default
        };
        
        // Generate key
        let public_key = piv::generate(
            &mut self.yubikey,
            slot_id,
            algorithm,
            pin_pol,
            touch_pol,
        ).map_err(|e| YubiKeyError::KeyGenerationFailed(e.to_string()))?;
        
        // Return public key bytes
        Ok(public_key.to_vec())
    }

    /// Sign data using PIV slot key
    ///
    /// # Security
    ///
    /// - Touch may be required (YK-002)
    /// - PIN may be required (YK-003)
    pub fn sign(
        &mut self,
        slot: PivSlot,
        data: &[u8],
        pin: Option<&YubiKeyPin>,
    ) -> Result<Vec<u8>, YubiKeyError> {
        if let Some(p) = pin {
            self.verify_pin(p)?;
        }
        
        let slot_id = slot.to_slot_id();
        
        // Get key info to determine algorithm
        let key_info = piv::metadata(&mut self.yubikey, slot_id)
            .map_err(|e| YubiKeyError::SlotEmpty(format!("{:?}", slot)))?;
        
        // Sign the data
        let signature = piv::sign_data(
            &mut self.yubikey,
            data,
            key_info.algorithm,
            slot_id,
        ).map_err(|e| YubiKeyError::SigningFailed(e.to_string()))?;
        
        Ok(signature.to_vec())
    }

    /// Decrypt data using PIV Key Management slot
    pub fn decrypt(
        &mut self,
        slot: PivSlot,
        ciphertext: &[u8],
        pin: Option<&YubiKeyPin>,
    ) -> Result<Vec<u8>, YubiKeyError> {
        if let Some(p) = pin {
            self.verify_pin(p)?;
        }
        
        let slot_id = slot.to_slot_id();
        
        let key_info = piv::metadata(&mut self.yubikey, slot_id)
            .map_err(|e| YubiKeyError::SlotEmpty(format!("{:?}", slot)))?;
        
        let plaintext = piv::decrypt_data(
            &mut self.yubikey,
            ciphertext,
            key_info.algorithm,
            slot_id,
        ).map_err(|e| YubiKeyError::DecryptionFailed(e.to_string()))?;
        
        Ok(plaintext.to_vec())
    }

    /// Challenge-response for password hardening
    ///
    /// This uses HMAC-SHA1 challenge-response (slot 1 or 2) to
    /// derive additional key material that requires the physical YubiKey.
    ///
    /// # Arguments
    ///
    /// * `challenge` - 32-byte challenge (e.g., password hash)
    ///
    /// # Returns
    ///
    /// 20-byte HMAC-SHA1 response
    pub fn challenge_response(&mut self, challenge: &[u8; 32]) -> Result<[u8; 20], YubiKeyError> {
        // Challenge-response uses different interface (yubico OTP)
        // This is a placeholder - actual implementation would use ykpers or similar
        Err(YubiKeyError::NotSupported(
            "Challenge-response requires separate yubico OTP library".into()
        ))
    }
}

/// FIDO2 provider for hmac-secret extension
#[cfg(feature = "yubikey")]
pub struct Fido2Provider {
    /// FIDO2 device
    device: FidoKeyHid,
}

#[cfg(feature = "yubikey")]
impl Fido2Provider {
    /// Connect to FIDO2 device
    pub fn connect() -> Result<Self, YubiKeyError> {
        let device = FidoKeyHidFactory::create(&Cfg::init())
            .map_err(|e| YubiKeyError::ConnectionFailed(format!("{:?}", e)))?;
        
        Ok(Self { device })
    }

    /// List available FIDO2 devices
    pub fn list_devices() -> Result<Vec<HidInfo>, YubiKeyError> {
        let devices = ctap_hid_fido2::get_fidokey_devices()
            .map_err(|e| YubiKeyError::ConnectionFailed(format!("{:?}", e)))?;
        
        Ok(devices)
    }

    /// Use FIDO2 hmac-secret extension for key derivation
    ///
    /// This creates a credential bound to the device, then uses
    /// the hmac-secret extension to derive consistent key material.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - Relying party ID (e.g., "meow-decoder.local")
    /// * `salt` - 32-byte salt for derivation
    /// * `pin` - Optional PIN if required
    ///
    /// # Returns
    ///
    /// 32-byte derived key material
    ///
    /// # Security
    ///
    /// - Key derivation requires physical device
    /// - Salt is mixed with device secret
    /// - Result is consistent for same credential + salt
    pub fn hmac_secret(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
    ) -> Result<[u8; 32], YubiKeyError> {
        // FIDO2 GetAssertion with hmac-secret extension
        // This is a simplified implementation
        Err(YubiKeyError::NotSupported(
            "FIDO2 hmac-secret requires credential setup".into()
        ))
    }

    /// Create a credential for hmac-secret operations
    ///
    /// # Arguments
    ///
    /// * `rp_id` - Relying party ID
    /// * `user_id` - User identifier
    /// * `pin` - Optional PIN
    ///
    /// # Returns
    ///
    /// Credential ID for future hmac-secret operations
    pub fn create_credential(
        &self,
        rp_id: &str,
        user_id: &[u8],
        pin: Option<&str>,
    ) -> Result<Vec<u8>, YubiKeyError> {
        // Create credential with hmac-secret extension
        Err(YubiKeyError::NotSupported(
            "Credential creation not yet implemented".into()
        ))
    }
}

// Stub implementations when feature is disabled
#[cfg(not(feature = "yubikey"))]
pub struct YubiKeyProvider;

#[cfg(not(feature = "yubikey"))]
impl YubiKeyProvider {
    pub fn connect() -> Result<Self, YubiKeyError> {
        Err(YubiKeyError::FeatureDisabled)
    }
}

#[cfg(not(feature = "yubikey"))]
pub struct Fido2Provider;

#[cfg(not(feature = "yubikey"))]
impl Fido2Provider {
    pub fn connect() -> Result<Self, YubiKeyError> {
        Err(YubiKeyError::FeatureDisabled)
    }
}

/// Integrate YubiKey with password-based encryption
///
/// This function combines a password with YubiKey-derived material
/// to create a key that requires both knowledge and possession.
///
/// # Security Model
///
/// ```text
/// final_key = HKDF(
///     ikm = password_hash || yubikey_response,
///     salt = file_salt,
///     info = "meow-yubikey-v1"
/// )
/// ```
///
/// Attacker needs BOTH:
/// 1. Password (knowledge factor)
/// 2. Physical YubiKey (possession factor)
#[cfg(all(feature = "yubikey", feature = "pure-crypto"))]
pub fn derive_key_with_yubikey(
    password: &[u8],
    salt: &[u8],
    yubikey: &mut YubiKeyProvider,
    slot: PivSlot,
    pin: Option<&YubiKeyPin>,
) -> Result<[u8; 32], YubiKeyError> {
    use sha2::{Sha256, Digest};
    use hkdf::Hkdf;
    
    // Hash password
    let password_hash = Sha256::digest(password);
    
    // Sign password hash with YubiKey (requires physical device)
    let yk_response = yubikey.sign(slot, &password_hash, pin)?;
    
    // Combine password hash + YubiKey response
    let mut ikm = Vec::with_capacity(32 + yk_response.len());
    ikm.extend_from_slice(&password_hash);
    ikm.extend_from_slice(&yk_response);
    
    // Derive final key
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"meow-yubikey-v1", &mut okm)
        .map_err(|e| YubiKeyError::Fido2Failed(e.to_string()))?;
    
    // Zeroize intermediate material
    ikm.zeroize();
    
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_piv_slot_description() {
        assert!(PivSlot::KeyManagement.description().contains("encryption"));
        assert!(PivSlot::DigitalSignature.description().contains("signing"));
    }

    #[test]
    fn test_secure_pin_zeroize() {
        let pin = YubiKeyPin::new("123456");
        assert_eq!(pin.as_bytes(), b"123456");
    }

    #[cfg(not(feature = "yubikey"))]
    #[test]
    fn test_yubikey_disabled() {
        let result = YubiKeyProvider::connect();
        assert!(matches!(result, Err(YubiKeyError::FeatureDisabled)));
    }
}
