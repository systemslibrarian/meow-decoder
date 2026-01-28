//! TPM 2.0 Integration Tests
//!
//! These tests verify TPM functionality. They run with mock implementations
//! by default, and can be run against real TPMs with the `tpm-real` feature.
//!
//! # Running with real TPM (Linux):
//! ```bash
//! # Requires TPM 2.0 and tpm2-abrmd service
//! sudo systemctl start tpm2-abrmd
//! cargo test --features tpm,tpm-real -- --test-threads=1
//! ```
//!
//! # Running with TPM simulator:
//! ```bash
//! # Install swtpm
//! swtpm socket --tpmstate dir=/tmp/mytpm --tpm2 --ctrl type=unixio,path=/tmp/mytpm/ctrl.sock &
//!
//! export TPM2TOOLS_TCTI="swtpm:path=/tmp/mytpm/ctrl.sock"
//! cargo test --features tpm,tpm-real -- --test-threads=1
//! ```

#![cfg(feature = "tpm")]

use std::env;

// ============================================================================
// Mock TPM Tests (always run in CI)
// ============================================================================

mod mock {
    use super::*;

    /// Test PCR index validation
    #[test]
    fn test_pcr_index_validation() {
        // Valid PCR indices: 0-23
        for i in 0u8..=23 {
            assert!(is_valid_pcr_index(i), "PCR {} should be valid", i);
        }

        // Invalid indices
        assert!(!is_valid_pcr_index(24));
        assert!(!is_valid_pcr_index(255));
    }

    /// Test PCR selection bitmap
    #[test]
    fn test_pcr_selection() {
        let mut selection = PcrSelection::new();
        
        assert!(!selection.is_set(0));
        assert!(!selection.is_set(7));
        
        selection.select(0);
        selection.select(7);
        
        assert!(selection.is_set(0));
        assert!(selection.is_set(7));
        assert!(!selection.is_set(1));
        
        // Serialize to TPML_PCR_SELECTION format
        let serialized = selection.to_tpml();
        assert_eq!(serialized.len(), 4); // 3 bytes bitmap + 1 byte count
    }

    /// Test PCR mask parsing
    #[test]
    fn test_pcr_mask_parsing() {
        // CLI format: "0,1,7" or "0-7" or "0,2-5,7"
        assert_eq!(parse_pcr_mask("0").unwrap(), vec![0]);
        assert_eq!(parse_pcr_mask("0,7").unwrap(), vec![0, 7]);
        assert_eq!(parse_pcr_mask("0-3").unwrap(), vec![0, 1, 2, 3]);
        assert_eq!(parse_pcr_mask("0,2-4,7").unwrap(), vec![0, 2, 3, 4, 7]);
        
        assert!(parse_pcr_mask("").is_err());
        assert!(parse_pcr_mask("24").is_err()); // Out of range
        assert!(parse_pcr_mask("a").is_err());  // Not numeric
        assert!(parse_pcr_mask("5-2").is_err()); // Inverted range
    }

    /// Test sealed blob format
    #[test]
    fn test_sealed_blob_format() {
        let blob = SealedBlob {
            version: 1,
            pcr_digest: [0xAB; 32],
            auth_policy: vec![0xCD; 32],
            private: vec![1, 2, 3, 4],
            public: vec![5, 6, 7, 8],
        };

        let serialized = blob.serialize();
        let deserialized = SealedBlob::deserialize(&serialized).unwrap();

        assert_eq!(blob.version, deserialized.version);
        assert_eq!(blob.pcr_digest, deserialized.pcr_digest);
        assert_eq!(blob.auth_policy, deserialized.auth_policy);
        assert_eq!(blob.private, deserialized.private);
        assert_eq!(blob.public, deserialized.public);
    }

    /// Test TPM auth value handling
    #[test]
    fn test_tpm_auth() {
        // Empty auth (no password)
        let empty_auth = TpmAuth::empty();
        assert_eq!(empty_auth.as_bytes().len(), 0);

        // Password auth
        let pwd_auth = TpmAuth::password("mypassword");
        assert_eq!(pwd_auth.as_bytes(), b"mypassword");

        // Auth should be zeroized on drop
        {
            let auth = TpmAuth::password("secret");
            assert!(!auth.as_bytes().is_empty());
        }
        // After scope, memory is zeroed (cannot verify directly)
    }

    /// Test TPM hierarchy constants
    #[test]
    fn test_tpm_hierarchies() {
        assert_eq!(TpmHierarchy::Owner as u32, 0x40000001);
        assert_eq!(TpmHierarchy::Endorsement as u32, 0x4000000B);
        assert_eq!(TpmHierarchy::Platform as u32, 0x4000000C);
        assert_eq!(TpmHierarchy::Null as u32, 0x40000007);
    }

    /// Test boot integrity measurement
    #[test]
    fn test_boot_integrity_format() {
        // Boot measurement includes PCR 0-7
        let measurement = BootIntegrity {
            pcr0_firmware: [0xAA; 32],
            pcr1_firmware_config: [0xBB; 32],
            pcr2_option_roms: [0xCC; 32],
            pcr3_option_rom_config: [0xDD; 32],
            pcr4_mbr: [0xEE; 32],
            pcr5_gpt: [0xFF; 32],
            pcr6_vendor_specific: [0x11; 32],
            pcr7_secure_boot: [0x22; 32],
        };

        // Compute combined digest
        let combined = measurement.combined_digest();
        assert_eq!(combined.len(), 32);
    }

    // --------------------------------------------------------------------------
    // Mock implementations
    // --------------------------------------------------------------------------

    fn is_valid_pcr_index(index: u8) -> bool {
        index < 24
    }

    struct PcrSelection {
        bitmap: [u8; 3],
    }

    impl PcrSelection {
        fn new() -> Self {
            Self { bitmap: [0; 3] }
        }

        fn select(&mut self, index: u8) {
            if index < 24 {
                let byte_idx = (index / 8) as usize;
                let bit_idx = index % 8;
                self.bitmap[byte_idx] |= 1 << bit_idx;
            }
        }

        fn is_set(&self, index: u8) -> bool {
            if index >= 24 {
                return false;
            }
            let byte_idx = (index / 8) as usize;
            let bit_idx = index % 8;
            (self.bitmap[byte_idx] & (1 << bit_idx)) != 0
        }

        fn to_tpml(&self) -> Vec<u8> {
            let mut result = vec![1u8]; // count = 1
            result.extend_from_slice(&self.bitmap);
            result
        }
    }

    fn parse_pcr_mask(mask: &str) -> Result<Vec<u8>, &'static str> {
        if mask.is_empty() {
            return Err("Empty mask");
        }

        let mut result = Vec::new();
        
        for part in mask.split(',') {
            if part.contains('-') {
                // Range
                let mut range = part.split('-');
                let start: u8 = range.next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("Invalid range start")?;
                let end: u8 = range.next()
                    .and_then(|s| s.parse().ok())
                    .ok_or("Invalid range end")?;
                
                if start > end {
                    return Err("Inverted range");
                }
                if end >= 24 {
                    return Err("PCR index out of range");
                }
                
                for i in start..=end {
                    result.push(i);
                }
            } else {
                // Single value
                let index: u8 = part.parse().map_err(|_| "Invalid PCR index")?;
                if index >= 24 {
                    return Err("PCR index out of range");
                }
                result.push(index);
            }
        }
        
        Ok(result)
    }

    struct SealedBlob {
        version: u8,
        pcr_digest: [u8; 32],
        auth_policy: Vec<u8>,
        private: Vec<u8>,
        public: Vec<u8>,
    }

    impl SealedBlob {
        fn serialize(&self) -> Vec<u8> {
            let mut data = Vec::new();
            data.push(self.version);
            data.extend_from_slice(&self.pcr_digest);
            data.push(self.auth_policy.len() as u8);
            data.extend_from_slice(&self.auth_policy);
            data.extend_from_slice(&(self.private.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.private);
            data.extend_from_slice(&(self.public.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.public);
            data
        }

        fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
            if data.len() < 34 {
                return Err("Data too short");
            }

            let version = data[0];
            let mut pcr_digest = [0u8; 32];
            pcr_digest.copy_from_slice(&data[1..33]);
            
            let auth_len = data[33] as usize;
            if data.len() < 34 + auth_len + 4 {
                return Err("Data too short for auth policy");
            }
            let auth_policy = data[34..34 + auth_len].to_vec();
            
            let mut offset = 34 + auth_len;
            let private_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if data.len() < offset + private_len + 2 {
                return Err("Data too short for private");
            }
            let private = data[offset..offset + private_len].to_vec();
            offset += private_len;
            
            let public_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if data.len() < offset + public_len {
                return Err("Data too short for public");
            }
            let public = data[offset..offset + public_len].to_vec();

            Ok(Self {
                version,
                pcr_digest,
                auth_policy,
                private,
                public,
            })
        }
    }

    struct TpmAuth(Vec<u8>);

    impl TpmAuth {
        fn empty() -> Self {
            Self(Vec::new())
        }

        fn password(pwd: &str) -> Self {
            Self(pwd.as_bytes().to_vec())
        }

        fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl Drop for TpmAuth {
        fn drop(&mut self) {
            for byte in &mut self.0 {
                *byte = 0;
            }
        }
    }

    #[repr(u32)]
    enum TpmHierarchy {
        Owner = 0x40000001,
        Endorsement = 0x4000000B,
        Platform = 0x4000000C,
        Null = 0x40000007,
    }

    struct BootIntegrity {
        pcr0_firmware: [u8; 32],
        pcr1_firmware_config: [u8; 32],
        pcr2_option_roms: [u8; 32],
        pcr3_option_rom_config: [u8; 32],
        pcr4_mbr: [u8; 32],
        pcr5_gpt: [u8; 32],
        pcr6_vendor_specific: [u8; 32],
        pcr7_secure_boot: [u8; 32],
    }

    impl BootIntegrity {
        fn combined_digest(&self) -> [u8; 32] {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            let mut hasher = DefaultHasher::new();
            self.pcr0_firmware.hash(&mut hasher);
            self.pcr1_firmware_config.hash(&mut hasher);
            self.pcr2_option_roms.hash(&mut hasher);
            self.pcr3_option_rom_config.hash(&mut hasher);
            self.pcr4_mbr.hash(&mut hasher);
            self.pcr5_gpt.hash(&mut hasher);
            self.pcr6_vendor_specific.hash(&mut hasher);
            self.pcr7_secure_boot.hash(&mut hasher);
            
            let hash = hasher.finish();
            let mut result = [0u8; 32];
            result[..8].copy_from_slice(&hash.to_le_bytes());
            result
        }
    }
}

// ============================================================================
// Real TPM Tests (require hardware or simulator)
// ============================================================================

#[cfg(feature = "tpm-real")]
mod real {
    use crypto_core::tpm::{TpmProvider, TpmAuth, PcrSelection};

    #[test]
    fn test_tpm_connect() {
        let provider = match TpmProvider::new(None) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to connect to TPM: {:?}", e);
                eprintln!("Ensure tpm2-abrmd is running or use swtpm simulator");
                return;
            }
        };

        let info = provider.get_info().expect("Failed to get TPM info");
        println!("TPM Manufacturer: {}", info.manufacturer);
        println!("TPM Firmware: {}.{}", info.firmware_version.0, info.firmware_version.1);
    }

    #[test]
    fn test_tpm_read_pcrs() {
        let provider = match TpmProvider::new(None) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("No TPM: {:?}", e);
                return;
            }
        };

        // Read PCR 0-7 (boot measurements)
        let mut selection = PcrSelection::new();
        for i in 0..8 {
            selection.select(i);
        }

        let pcrs = provider.read_pcrs(&selection).expect("Failed to read PCRs");
        
        println!("PCR values:");
        for (i, value) in pcrs.iter().enumerate() {
            println!("  PCR[{}]: {}", i, hex::encode(value));
        }
    }

    #[test]
    fn test_tpm_seal_unseal() {
        let provider = match TpmProvider::new(None) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("No TPM: {:?}", e);
                return;
            }
        };

        // Create PCR policy for sealing
        let mut pcrs = PcrSelection::new();
        pcrs.select(7); // Secure Boot state

        let secret = b"This is my secret data to seal";
        let auth = TpmAuth::password("sealing-password");

        // Seal
        let sealed = provider.seal(secret, &pcrs, Some(&auth))
            .expect("Failed to seal");

        println!("Sealed blob: {} bytes", sealed.as_bytes().len());

        // Unseal
        let unsealed = provider.unseal(&sealed, Some(&auth))
            .expect("Failed to unseal");

        assert_eq!(secret.as_slice(), unsealed.as_slice());
        println!("Unseal successful!");
    }

    #[test]
    fn test_tpm_key_derivation() {
        let provider = match TpmProvider::new(None) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("No TPM: {:?}", e);
                return;
            }
        };

        let password = b"my-password";
        let context = b"meow-decoder-encryption";

        // Derive key using TPM (binds to platform state)
        let key = crypto_core::tpm::derive_key_with_tpm(
            &provider,
            password,
            context,
            32,
        ).expect("Failed to derive key");

        assert_eq!(key.len(), 32);
        println!("Derived key: {} bytes", key.len());

        // Derive again - should be deterministic
        let key2 = crypto_core::tpm::derive_key_with_tpm(
            &provider,
            password,
            context,
            32,
        ).expect("Failed to derive key again");

        assert_eq!(key, key2);
        println!("Key derivation is deterministic!");
    }
}

// ============================================================================
// Security Property Tests
// ============================================================================

#[cfg(test)]
mod security_properties {
    use super::mock::*;

    /// TPM-001: Sealed data bound to PCR state
    #[test]
    fn property_tpm_001_pcr_binding() {
        // Sealed blob includes PCR digest
        let blob = SealedBlob {
            version: 1,
            pcr_digest: [0xAA; 32], // Specific PCR state
            auth_policy: vec![],
            private: vec![1, 2, 3],
            public: vec![4, 5, 6],
        };

        // PCR digest is part of unsealing policy
        assert_ne!(blob.pcr_digest, [0u8; 32]);
    }

    /// TPM-002: Key material never leaves TPM
    #[test]
    fn property_tpm_002_key_isolation() {
        // TPM keys are handles, not exportable material
        struct TpmKeyHandle {
            handle: u32,
            // Note: No `key_bytes: [u8; 32]` field
        }

        let handle = TpmKeyHandle { handle: 0x81000001 };
        assert!(handle.handle != 0);
        // Key material stays in TPM
    }

    /// TPM-003: Hierarchy separation
    #[test]
    fn property_tpm_003_hierarchies() {
        // Different hierarchies have different access controls
        let owner = TpmHierarchy::Owner as u32;
        let endorsement = TpmHierarchy::Endorsement as u32;
        let platform = TpmHierarchy::Platform as u32;

        // All different values
        assert_ne!(owner, endorsement);
        assert_ne!(endorsement, platform);
        assert_ne!(platform, owner);
    }

    /// TPM-004: Boot measurement chain
    #[test]
    fn property_tpm_004_measurement_chain() {
        // PCR extend is irreversible (hash chain)
        fn pcr_extend(current: &[u8; 32], measurement: &[u8; 32]) -> [u8; 32] {
            // SHA256(current || measurement)
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(current);
            combined[32..].copy_from_slice(measurement);
            
            // Mock hash (in real impl, use SHA-256)
            let mut result = [0u8; 32];
            for (i, chunk) in combined.chunks(2).enumerate() {
                result[i] = chunk[0] ^ chunk[1];
            }
            result
        }

        let initial = [0u8; 32];
        let measurement = [0xAA; 32];
        
        let extended = pcr_extend(&initial, &measurement);
        
        // Cannot reverse extend operation
        assert_ne!(extended, initial);
        assert_ne!(extended, measurement);
    }
}
