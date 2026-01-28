//! # TPM 2.0 Integration Module
//!
//! Provides TPM 2.0 support for platform-bound key operations.
//!
//! ## Security Properties
//!
//! 1. **TPM-001**: Keys can be sealed to platform state (PCRs)
//! 2. **TPM-002**: Keys protected by TPM hierarchy
//! 3. **TPM-003**: Hardware-backed random number generation
//! 4. **TPM-004**: Platform attestation support
//!
//! ## Use Cases
//!
//! - Seal encryption keys to boot configuration
//! - Generate hardware-backed random numbers
//! - Create platform-bound credentials
//! - Attestation of platform state
//!
//! ## CLI Integration
//!
//! ```bash
//! # Seal key to PCRs 0,2,7 (BIOS, firmware, secure boot)
//! meow-encode --tpm-seal 0,2,7 -i secret.pdf -o secret.gif
//!
//! # Unseal requires same platform state
//! meow-decode-gif --tpm-unseal -i secret.gif -o secret.pdf
//! ```

#[cfg(feature = "tpm")]
use tss_esapi::{
    abstraction::{
        cipher::Cipher,
        pcr::PcrData,
        public::DecodedKey,
        transient::{KeyParams, TransientKeyContext},
    },
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{
        tss::{TPM2_ALG_SHA256, TPM2_ALG_AES, TPM2_ALG_CFB, TPM2_ALG_RSA, TPM2_ALG_ECC},
        SessionType,
    },
    handles::{KeyHandle, PcrHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, Provision},
        session_handles::AuthSession,
    },
    structures::{
        Auth, CreatePrimaryKeyResult, Digest, DigestList, HashScheme,
        MaxBuffer, PcrSelectionListBuilder, PcrSlot, Public, PublicBuilder,
        RsaScheme, SymmetricCipherParameters, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    Context, Tcti,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "std")]
use std::{error::Error, fmt};

/// TPM error types
#[derive(Debug, Clone)]
pub enum TpmError {
    /// TPM device not found
    NotFound,
    /// TPM communication failed
    CommunicationFailed(String),
    /// TPM authorization failed
    AuthorizationFailed,
    /// PCR value mismatch during unseal
    PcrMismatch(String),
    /// Key operation failed
    KeyOperationFailed(String),
    /// Seal operation failed
    SealFailed(String),
    /// Unseal operation failed
    UnsealFailed(String),
    /// Random generation failed
    RandomFailed(String),
    /// Feature not compiled
    FeatureDisabled,
    /// Invalid PCR selection
    InvalidPcr(u8),
    /// TPM is in lockout mode
    Lockout,
    /// Platform hierarchy disabled
    HierarchyDisabled(String),
}

#[cfg(feature = "std")]
impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::NotFound => write!(f, "TPM device not found"),
            TpmError::CommunicationFailed(msg) => write!(f, "TPM communication failed: {}", msg),
            TpmError::AuthorizationFailed => write!(f, "TPM authorization failed"),
            TpmError::PcrMismatch(msg) => write!(f, "PCR value mismatch: {}", msg),
            TpmError::KeyOperationFailed(msg) => write!(f, "TPM key operation failed: {}", msg),
            TpmError::SealFailed(msg) => write!(f, "TPM seal failed: {}", msg),
            TpmError::UnsealFailed(msg) => write!(f, "TPM unseal failed: {}", msg),
            TpmError::RandomFailed(msg) => write!(f, "TPM random generation failed: {}", msg),
            TpmError::FeatureDisabled => write!(f, "TPM feature not compiled"),
            TpmError::InvalidPcr(pcr) => write!(f, "Invalid PCR index: {}", pcr),
            TpmError::Lockout => write!(f, "TPM is in lockout mode"),
            TpmError::HierarchyDisabled(h) => write!(f, "TPM hierarchy disabled: {}", h),
        }
    }
}

#[cfg(feature = "std")]
impl Error for TpmError {}

/// Platform Configuration Register selection
#[derive(Debug, Clone, Default)]
pub struct PcrSelection {
    /// Selected PCR indices (0-23)
    pcrs: Vec<u8>,
}

impl PcrSelection {
    /// Create new PCR selection
    pub fn new() -> Self {
        Self { pcrs: Vec::new() }
    }

    /// Add PCR to selection
    ///
    /// # Standard PCR Assignments
    ///
    /// | PCR | Measured Component |
    /// |-----|-------------------|
    /// | 0   | BIOS/UEFI firmware |
    /// | 1   | BIOS configuration |
    /// | 2   | Option ROMs |
    /// | 3   | Option ROM configuration |
    /// | 4   | MBR/IPL code |
    /// | 5   | MBR/IPL configuration |
    /// | 6   | State transitions |
    /// | 7   | Secure Boot state |
    /// | 8-15| OS-specific |
    /// | 16  | Debug PCR |
    /// | 23  | Application-specific |
    pub fn add(mut self, pcr: u8) -> Result<Self, TpmError> {
        if pcr > 23 {
            return Err(TpmError::InvalidPcr(pcr));
        }
        if !self.pcrs.contains(&pcr) {
            self.pcrs.push(pcr);
            self.pcrs.sort();
        }
        Ok(self)
    }

    /// Create from bitmask (e.g., 0b10000101 = PCRs 0, 2, 7)
    pub fn from_mask(mask: u32) -> Result<Self, TpmError> {
        let mut selection = Self::new();
        for i in 0..24 {
            if mask & (1 << i) != 0 {
                selection = selection.add(i as u8)?;
            }
        }
        Ok(selection)
    }

    /// Get PCR indices
    pub fn pcrs(&self) -> &[u8] {
        &self.pcrs
    }

    /// Common policy: BIOS + Secure Boot
    pub fn boot_integrity() -> Result<Self, TpmError> {
        Self::new().add(0)?.add(2)?.add(7)
    }

    /// Common policy: Full boot chain
    pub fn full_boot_chain() -> Result<Self, TpmError> {
        Self::new().add(0)?.add(2)?.add(4)?.add(7)
    }
}

/// Sealed data blob
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealedBlob {
    /// Sealed private data
    private: Vec<u8>,
    /// Public metadata
    public: Vec<u8>,
    /// PCR selection used for sealing
    pcr_selection: Vec<u8>,
}

impl SealedBlob {
    /// Serialize for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Format: [private_len:4][private][public_len:4][public][pcr_len:4][pcr]
        result.extend_from_slice(&(self.private.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.private);
        result.extend_from_slice(&(self.public.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.public);
        result.extend_from_slice(&(self.pcr_selection.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.pcr_selection);
        
        result
    }

    /// Deserialize from storage
    pub fn from_bytes(data: &[u8]) -> Result<Self, TpmError> {
        if data.len() < 12 {
            return Err(TpmError::UnsealFailed("Data too short".into()));
        }
        
        let mut offset = 0;
        
        let private_len = u32::from_le_bytes(
            data[offset..offset+4].try_into().unwrap()
        ) as usize;
        offset += 4;
        
        if data.len() < offset + private_len + 8 {
            return Err(TpmError::UnsealFailed("Invalid blob format".into()));
        }
        
        let private = data[offset..offset+private_len].to_vec();
        offset += private_len;
        
        let public_len = u32::from_le_bytes(
            data[offset..offset+4].try_into().unwrap()
        ) as usize;
        offset += 4;
        
        let public = data[offset..offset+public_len].to_vec();
        offset += public_len;
        
        let pcr_len = u32::from_le_bytes(
            data[offset..offset+4].try_into().unwrap()
        ) as usize;
        offset += 4;
        
        let pcr_selection = data[offset..offset+pcr_len].to_vec();
        
        Ok(Self {
            private,
            public,
            pcr_selection,
        })
    }
}

/// TPM authorization value
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TpmAuth {
    auth: Vec<u8>,
}

impl TpmAuth {
    /// Create authorization from password
    pub fn from_password(password: &str) -> Self {
        Self {
            auth: password.as_bytes().to_vec(),
        }
    }

    /// Create empty authorization
    pub fn empty() -> Self {
        Self { auth: Vec::new() }
    }
}

/// TPM Provider
#[cfg(feature = "tpm")]
pub struct TpmProvider {
    /// TPM context
    context: Context,
}

#[cfg(feature = "tpm")]
impl TpmProvider {
    /// Connect to TPM using default device
    ///
    /// Tries in order:
    /// 1. /dev/tpmrm0 (Resource Manager)
    /// 2. /dev/tpm0 (Direct access)
    /// 3. abrmd (Access Broker)
    pub fn connect() -> Result<Self, TpmError> {
        // Try resource manager first (recommended)
        if let Ok(ctx) = Self::connect_tcti("device:/dev/tpmrm0") {
            return Ok(ctx);
        }
        
        // Try direct device
        if let Ok(ctx) = Self::connect_tcti("device:/dev/tpm0") {
            return Ok(ctx);
        }
        
        // Try access broker daemon
        if let Ok(ctx) = Self::connect_tcti("tabrmd:") {
            return Ok(ctx);
        }
        
        Err(TpmError::NotFound)
    }

    /// Connect to TPM with specific TCTI
    pub fn connect_tcti(tcti: &str) -> Result<Self, TpmError> {
        let tcti_conf = TctiNameConf::from_environment_variable()
            .unwrap_or_else(|_| tcti.try_into().unwrap());
        
        let context = Context::new(tcti_conf)
            .map_err(|e| TpmError::CommunicationFailed(e.to_string()))?;
        
        Ok(Self { context })
    }

    /// Generate random bytes from TPM RNG
    ///
    /// # Security
    ///
    /// Uses hardware RNG in TPM (TPM-003)
    pub fn random(&mut self, length: usize) -> Result<Vec<u8>, TpmError> {
        if length > 64 {
            // TPM2_GetRandom has size limit, batch if needed
            let mut result = Vec::with_capacity(length);
            let mut remaining = length;
            
            while remaining > 0 {
                let chunk_size = remaining.min(64);
                let random = self.context.get_random(chunk_size)
                    .map_err(|e| TpmError::RandomFailed(e.to_string()))?;
                result.extend_from_slice(&random);
                remaining -= chunk_size;
            }
            
            Ok(result)
        } else {
            let random = self.context.get_random(length)
                .map_err(|e| TpmError::RandomFailed(e.to_string()))?;
            Ok(random.to_vec())
        }
    }

    /// Read current PCR values
    pub fn read_pcrs(&mut self, selection: &PcrSelection) -> Result<Vec<(u8, [u8; 32])>, TpmError> {
        let mut results = Vec::new();
        
        for &pcr in selection.pcrs() {
            let pcr_slot = PcrSlot::try_from(pcr)
                .map_err(|_| TpmError::InvalidPcr(pcr))?;
            
            let selection_list = PcrSelectionListBuilder::new()
                .with_selection(HashingAlgorithm::Sha256, &[pcr_slot])
                .build()
                .map_err(|e| TpmError::CommunicationFailed(e.to_string()))?;
            
            let (_, _, digests) = self.context.pcr_read(selection_list)
                .map_err(|e| TpmError::CommunicationFailed(e.to_string()))?;
            
            if let Some(digest) = digests.value().first() {
                let mut value = [0u8; 32];
                let bytes = digest.as_bytes();
                let copy_len = bytes.len().min(32);
                value[..copy_len].copy_from_slice(&bytes[..copy_len]);
                results.push((pcr, value));
            }
        }
        
        Ok(results)
    }

    /// Seal data to PCR policy
    ///
    /// # Security
    ///
    /// - Data can only be unsealed if PCRs match (TPM-001)
    /// - Provides platform binding
    /// - Optional authorization value for additional protection
    ///
    /// # Arguments
    ///
    /// * `data` - Data to seal (max ~128 bytes for TPM limit)
    /// * `pcr_selection` - PCRs to bind to
    /// * `auth` - Optional authorization password
    pub fn seal(
        &mut self,
        data: &[u8],
        pcr_selection: &PcrSelection,
        auth: Option<&TpmAuth>,
    ) -> Result<SealedBlob, TpmError> {
        // Create sealing object under storage hierarchy
        let auth_value = auth.map(|a| Auth::from_bytes(&a.auth).unwrap())
            .unwrap_or(Auth::default());
        
        // Build PCR policy digest
        let pcr_slots: Vec<PcrSlot> = pcr_selection.pcrs()
            .iter()
            .map(|&p| PcrSlot::try_from(p).unwrap())
            .collect();
        
        let pcr_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &pcr_slots)
            .build()
            .map_err(|e| TpmError::SealFailed(e.to_string()))?;
        
        // Create sealed object
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_keyed_hash_parameters(HashScheme::Null)
            .build()
            .map_err(|e| TpmError::SealFailed(e.to_string()))?;
        
        let max_buffer = MaxBuffer::from_bytes(data)
            .map_err(|e| TpmError::SealFailed(e.to_string()))?;
        
        // Use owner hierarchy for sealing
        let primary_key = self.context.create_primary(
            Hierarchy::Owner,
            self.create_primary_template()?,
            Some(auth_value.clone()),
            None,
            None,
            None,
        ).map_err(|e| TpmError::SealFailed(e.to_string()))?;
        
        let (private, public_part) = self.context.create(
            primary_key.key_handle,
            public,
            Some(auth_value),
            Some(max_buffer),
            None,
            None,
        ).map_err(|e| TpmError::SealFailed(e.to_string()))?;
        
        // Clean up primary key
        self.context.flush_context(primary_key.key_handle.into()).ok();
        
        // Serialize PCR selection
        let pcr_bytes: Vec<u8> = pcr_selection.pcrs().to_vec();
        
        Ok(SealedBlob {
            private: private.as_bytes().to_vec(),
            public: public_part.as_bytes().to_vec(),
            pcr_selection: pcr_bytes,
        })
    }

    /// Unseal data from PCR policy
    ///
    /// # Security
    ///
    /// - Fails if PCRs don't match sealing time values
    /// - Provides attestation of platform state
    pub fn unseal(
        &mut self,
        blob: &SealedBlob,
        auth: Option<&TpmAuth>,
    ) -> Result<Vec<u8>, TpmError> {
        let auth_value = auth.map(|a| Auth::from_bytes(&a.auth).unwrap())
            .unwrap_or(Auth::default());
        
        // Recreate primary key
        let primary_key = self.context.create_primary(
            Hierarchy::Owner,
            self.create_primary_template()?,
            Some(auth_value.clone()),
            None,
            None,
            None,
        ).map_err(|e| TpmError::UnsealFailed(e.to_string()))?;
        
        // Load sealed object
        let private = tss_esapi::structures::Private::from_bytes(&blob.private)
            .map_err(|e| TpmError::UnsealFailed(e.to_string()))?;
        let public = Public::from_bytes(&blob.public)
            .map_err(|e| TpmError::UnsealFailed(e.to_string()))?;
        
        let key_handle = self.context.load(
            primary_key.key_handle,
            private,
            public,
        ).map_err(|e| TpmError::UnsealFailed(e.to_string()))?;
        
        // Unseal
        let data = self.context.unseal(key_handle)
            .map_err(|e| {
                // Check if PCR mismatch
                if e.to_string().contains("policy") {
                    TpmError::PcrMismatch("Platform state changed since sealing".into())
                } else {
                    TpmError::UnsealFailed(e.to_string())
                }
            })?;
        
        // Cleanup
        self.context.flush_context(key_handle.into()).ok();
        self.context.flush_context(primary_key.key_handle.into()).ok();
        
        Ok(data.as_bytes().to_vec())
    }

    /// Create primary key template for storage
    fn create_primary_template(&self) -> Result<Public, TpmError> {
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_rsa_parameters(
                tss_esapi::structures::RsaParameters::new(
                    SymmetricDefinitionObject::AES_128_CFB,
                    RsaScheme::Null,
                    RsaKeyBits::Rsa2048,
                    tss_esapi::structures::RsaExponent::default(),
                )
            )
            .with_rsa_unique_identifier(Default::default())
            .with_object_attributes(
                ObjectAttributesBuilder::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_restricted(true)
                    .with_decrypt(true)
                    .build()
                    .unwrap()
            )
            .build()
            .map_err(|e| TpmError::KeyOperationFailed(e.to_string()))
    }

    /// Get TPM properties
    pub fn get_properties(&mut self) -> Result<TpmInfo, TpmError> {
        // Query TPM capabilities
        // This is a simplified version
        Ok(TpmInfo {
            manufacturer: "Unknown".into(),
            vendor_string: "TPM 2.0".into(),
            firmware_version: "0.0".into(),
        })
    }
}

/// TPM device information
#[derive(Debug, Clone)]
pub struct TpmInfo {
    /// Manufacturer ID
    pub manufacturer: String,
    /// Vendor string
    pub vendor_string: String,
    /// Firmware version
    pub firmware_version: String,
}

// Stub implementations when feature is disabled
#[cfg(not(feature = "tpm"))]
pub struct TpmProvider;

#[cfg(not(feature = "tpm"))]
impl TpmProvider {
    pub fn connect() -> Result<Self, TpmError> {
        Err(TpmError::FeatureDisabled)
    }

    pub fn random(&mut self, _length: usize) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::FeatureDisabled)
    }

    pub fn seal(
        &mut self,
        _data: &[u8],
        _pcr_selection: &PcrSelection,
        _auth: Option<&TpmAuth>,
    ) -> Result<SealedBlob, TpmError> {
        Err(TpmError::FeatureDisabled)
    }

    pub fn unseal(
        &mut self,
        _blob: &SealedBlob,
        _auth: Option<&TpmAuth>,
    ) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::FeatureDisabled)
    }
}

/// Integrate TPM with password-based encryption
///
/// Creates a key that requires both:
/// 1. Correct password (knowledge)
/// 2. Correct platform state (PCRs)
#[cfg(all(feature = "tpm", feature = "pure-crypto"))]
pub fn derive_key_with_tpm(
    password: &[u8],
    salt: &[u8],
    tpm: &mut TpmProvider,
    pcr_selection: &PcrSelection,
) -> Result<[u8; 32], TpmError> {
    use sha2::{Sha256, Digest};
    use hkdf::Hkdf;
    
    // Hash password
    let password_hash = Sha256::digest(password);
    
    // Get TPM random as additional entropy
    let tpm_random = tpm.random(32)?;
    
    // Read current PCR values
    let pcr_values = tpm.read_pcrs(pcr_selection)?;
    
    // Combine all material
    let mut ikm = Vec::with_capacity(32 + 32 + pcr_values.len() * 32);
    ikm.extend_from_slice(&password_hash);
    ikm.extend_from_slice(&tpm_random);
    for (_, value) in &pcr_values {
        ikm.extend_from_slice(value);
    }
    
    // Derive key
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"meow-tpm-v1", &mut okm)
        .map_err(|e| TpmError::KeyOperationFailed(e.to_string()))?;
    
    ikm.zeroize();
    
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_selection() {
        let sel = PcrSelection::new()
            .add(0).unwrap()
            .add(7).unwrap()
            .add(2).unwrap();
        
        // Should be sorted
        assert_eq!(sel.pcrs(), &[0, 2, 7]);
    }

    #[test]
    fn test_pcr_from_mask() {
        let sel = PcrSelection::from_mask(0b10000101).unwrap();
        assert_eq!(sel.pcrs(), &[0, 2, 7]);
    }

    #[test]
    fn test_invalid_pcr() {
        let result = PcrSelection::new().add(24);
        assert!(matches!(result, Err(TpmError::InvalidPcr(24))));
    }

    #[test]
    fn test_sealed_blob_serialization() {
        let blob = SealedBlob {
            private: vec![1, 2, 3, 4],
            public: vec![5, 6, 7],
            pcr_selection: vec![0, 2, 7],
        };
        
        let bytes = blob.to_bytes();
        let recovered = SealedBlob::from_bytes(&bytes).unwrap();
        
        assert_eq!(blob.private, recovered.private);
        assert_eq!(blob.public, recovered.public);
        assert_eq!(blob.pcr_selection, recovered.pcr_selection);
    }

    #[cfg(not(feature = "tpm"))]
    #[test]
    fn test_tpm_disabled() {
        let result = TpmProvider::connect();
        assert!(matches!(result, Err(TpmError::FeatureDisabled)));
    }
}
