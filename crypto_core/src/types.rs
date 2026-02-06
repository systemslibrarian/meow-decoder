//! Core types for the AEAD wrapper
//!
//! These types enforce invariants at the type level where possible.

use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// AeadKey - Opaque Key Type
// =============================================================================

/// Opaque AEAD key type.
///
/// # Security Properties
/// - Key material is never logged or debug-printed
/// - Key is zeroed on drop (ZeroizeOnDrop)
/// - Key length is validated on construction
///
/// # Verus Specification
/// ```verus
/// spec fn key_valid(key: AeadKey) -> bool {
///     key.bytes.len() == 32
/// }
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey {
    /// Internal key bytes (always 32 bytes for AES-256)
    bytes: [u8; 32],
}

impl AeadKey {
    /// Key length in bytes (AES-256 = 32 bytes)
    pub const LEN: usize = 32;

    /// Create key from raw bytes.
    ///
    /// # Errors
    /// Returns error if bytes length is not exactly 32.
    ///
    /// # Verus Postcondition
    /// ```verus
    /// ensures |result: Result<AeadKey, KeyError>|
    ///     result.is_ok() ==> key_valid(result.unwrap())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != Self::LEN {
            return Err(KeyError::InvalidLength {
                expected: Self::LEN,
                got: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// Get reference to key bytes for crypto operations.
    ///
    /// # Security
    /// This is internal-only; key bytes should never leave the module.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// Prevent debug printing of key material
impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Key construction errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Invalid key length
    InvalidLength {
        /// Expected length
        expected: usize,
        /// Actual length
        got: usize,
    },
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { expected, got } => {
                write!(f, "Invalid key length: expected {}, got {}", expected, got)
            }
        }
    }
}

impl std::error::Error for KeyError {}

// =============================================================================
// AssociatedData - AAD Type
// =============================================================================

/// Associated Authenticated Data (AAD) for AEAD.
///
/// AAD is authenticated but not encrypted. Used for binding metadata
/// to ciphertext (e.g., manifest fields, version bytes).
#[derive(Debug, Clone)]
pub struct AssociatedData {
    bytes: Vec<u8>,
}

impl AssociatedData {
    /// Maximum AAD length (16 KB should be plenty for headers)
    pub const MAX_LEN: usize = 16 * 1024;

    /// Create AAD from bytes.
    ///
    /// # Errors
    /// Returns error if AAD exceeds maximum length.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, AadError> {
        let bytes = bytes.into();
        if bytes.len() > Self::MAX_LEN {
            return Err(AadError::TooLong {
                max: Self::MAX_LEN,
                got: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    /// Get AAD bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Create empty AAD (no additional data).
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }
}

impl From<&[u8]> for AssociatedData {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec()).expect("AAD from slice should not exceed max")
    }
}

/// AAD construction errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AadError {
    /// AAD too long
    TooLong {
        /// Maximum allowed
        max: usize,
        /// Actual length
        got: usize,
    },
}

impl std::fmt::Display for AadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { max, got } => {
                write!(f, "AAD too long: max {}, got {}", max, got)
            }
        }
    }
}

impl std::error::Error for AadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_valid_length() {
        let bytes = [0u8; 32];
        assert!(AeadKey::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn test_key_invalid_length() {
        let bytes = [0u8; 31];
        assert!(matches!(
            AeadKey::from_bytes(&bytes),
            Err(KeyError::InvalidLength {
                expected: 32,
                got: 31
            })
        ));
    }

    #[test]
    fn test_key_debug_redacted() {
        let key = AeadKey::from_bytes(&[0u8; 32]).unwrap();
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("0, 0, 0"));
    }

    #[test]
    fn test_aad_valid() {
        let aad = AssociatedData::new(vec![1, 2, 3]).unwrap();
        assert_eq!(aad.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_aad_too_long() {
        let bytes = vec![0u8; AssociatedData::MAX_LEN + 1];
        assert!(matches!(
            AssociatedData::new(bytes),
            Err(AadError::TooLong { .. })
        ));
    }

    #[test]
    fn test_key_as_bytes() {
        let bytes = [0xAB; 32];
        let key = AeadKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_error_display() {
        let err = KeyError::InvalidLength {
            expected: 32,
            got: 16,
        };
        assert_eq!(
            format!("{}", err),
            "Invalid key length: expected 32, got 16"
        );
    }

    #[test]
    fn test_key_error_is_error_trait() {
        let err: &dyn std::error::Error = &KeyError::InvalidLength {
            expected: 32,
            got: 16,
        };
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn test_aad_error_display() {
        let err = AadError::TooLong {
            max: 16384,
            got: 20000,
        };
        assert_eq!(format!("{}", err), "AAD too long: max 16384, got 20000");
    }

    #[test]
    fn test_aad_error_is_error_trait() {
        let err: &dyn std::error::Error = &AadError::TooLong { max: 100, got: 200 };
        assert!(err.to_string().contains("AAD too long"));
    }

    #[test]
    fn test_aad_empty() {
        let aad = AssociatedData::new(vec![]).unwrap();
        assert_eq!(aad.as_bytes(), &[]);
    }

    #[test]
    fn test_aad_max_length() {
        let bytes = vec![0u8; AssociatedData::MAX_LEN];
        let aad = AssociatedData::new(bytes).unwrap();
        assert_eq!(aad.as_bytes().len(), AssociatedData::MAX_LEN);
    }

    #[test]
    fn test_aad_from_slice() {
        let bytes: &[u8] = &[1, 2, 3, 4, 5];
        let aad: AssociatedData = bytes.into();
        assert_eq!(aad.as_bytes(), bytes);
    }

    #[test]
    fn test_aad_empty_default_method() {
        let aad = AssociatedData::empty();
        assert!(aad.as_bytes().is_empty());
    }
}
