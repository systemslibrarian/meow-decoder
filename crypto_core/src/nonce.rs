//! Nonce management with verified uniqueness guarantees
//!
//! This module provides types for generating and tracking nonces
//! with formal verification support for uniqueness invariants.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

/// A 12-byte nonce for AES-GCM.
///
/// This type enforces the 96-bit nonce size required by AES-256-GCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub struct Nonce {
    bytes: [u8; 12],
}

impl Nonce {
    /// Nonce length in bytes (96 bits = 12 bytes for AES-GCM)
    pub const LEN: usize = 12;

    /// Create nonce from bytes.
    ///
    /// # Errors
    /// Returns error if bytes length is not exactly 12.
    ///
    /// # Verus Postcondition
    /// ```verus
    /// ensures |result: Result<Nonce, NonceError>|
    ///     result.is_ok() ==> result.unwrap().bytes.len() == 12
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NonceError> {
        if bytes.len() != Self::LEN {
            return Err(NonceError::InvalidLength {
                expected: Self::LEN,
                got: bytes.len(),
            });
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: nonce_bytes })
    }

    /// Create nonce from fixed-size array (infallible).
    pub fn from_array(bytes: [u8; 12]) -> Self {
        Self { bytes }
    }

    /// Get nonce bytes.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.bytes
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Nonce construction errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceError {
    /// Invalid nonce length
    InvalidLength {
        /// Expected length
        expected: usize,
        /// Actual length
        got: usize,
    },
    /// Nonce was already used
    AlreadyUsed,
    /// Nonce counter exhausted
    Exhausted,
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { expected, got } => {
                write!(f, "Invalid nonce length: expected {}, got {}", expected, got)
            }
            Self::AlreadyUsed => write!(f, "Nonce already used"),
            Self::Exhausted => write!(f, "Nonce counter exhausted"),
        }
    }
}

impl std::error::Error for NonceError {}

// =============================================================================
// NonceGenerator - Counter-Based Nonce Generation
// =============================================================================

/// Generates unique nonces using a monotonic counter.
///
/// # Security Model
///
/// Uses counter-mode nonce generation: `[8-byte counter || 4-byte random]`
///
/// - Counter is strictly monotonic (atomic increment)
/// - Random suffix provides additional entropy across sessions
/// - Exhaustion check prevents counter wrap
///
/// # Verus Invariant
/// ```verus
/// invariant self.next_value > self.prev_allocated_values
/// invariant forall n1, n2 in self.allocated: n1 != n2 ==> nonce(n1) != nonce(n2)
/// ```
pub struct NonceGenerator {
    /// Monotonic counter (8 bytes of the nonce)
    counter: AtomicU64,
    /// Random session prefix (4 bytes of the nonce)
    session_id: [u8; 4],
}

impl NonceGenerator {
    /// Maximum counter value before exhaustion (leave headroom)
    pub const MAX_COUNTER: u64 = u64::MAX - 1024;

    /// Create a new nonce generator with random session ID.
    ///
    /// # Panics
    /// Panics if system RNG fails (should never happen on modern systems).
    pub fn new() -> Self {
        let mut session_id = [0u8; 4];
        getrandom::getrandom(&mut session_id)
            .expect("System RNG failed - cannot generate secure nonces");
        
        Self {
            counter: AtomicU64::new(0),
            session_id,
        }
    }

    /// Create generator with explicit session ID (for testing).
    #[cfg(test)]
    pub fn with_session_id(session_id: [u8; 4]) -> Self {
        Self {
            counter: AtomicU64::new(0),
            session_id,
        }
    }

    /// Generate the next unique nonce.
    ///
    /// # Returns
    /// A fresh nonce guaranteed unique within this generator's lifetime.
    ///
    /// # Errors
    /// Returns `NonceError::Exhausted` if counter would overflow.
    ///
    /// # Verus Specification
    /// ```verus
    /// requires self.counter.load() < MAX_COUNTER
    /// ensures result.is_ok() ==> 
    ///     self.counter.load() == old(self.counter.load()) + 1
    /// ensures result.is_ok() ==>
    ///     forall prev_nonce in old(self.generated): result.unwrap() != prev_nonce
    /// ```
    pub fn next(&self) -> Result<Nonce, NonceError> {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        
        if count >= Self::MAX_COUNTER {
            return Err(NonceError::Exhausted);
        }

        // Build nonce: [8-byte counter (big-endian) || 4-byte session]
        let mut bytes = [0u8; 12];
        bytes[0..8].copy_from_slice(&count.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.session_id);

        Ok(Nonce { bytes })
    }

    /// Get current counter value (for monitoring).
    pub fn count(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Check if generator is near exhaustion (>90% used).
    pub fn is_near_exhaustion(&self) -> bool {
        // Reordered to avoid overflow: divide first, then multiply
        self.count() > Self::MAX_COUNTER / 10 * 9
    }
}

impl Default for NonceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// NonceTracker - Explicit Nonce Tracking (for decryption/verification)
// =============================================================================

/// Tracks used nonces to detect reuse attempts.
///
/// Used on the decryption side to reject replayed messages.
/// This is complementary to `NonceGenerator` which is used on the encryption side.
///
/// # Security Model
///
/// - Maintains set of all seen nonces
/// - Rejects any nonce seen before
/// - Provides replay attack protection
///
/// # Memory Considerations
///
/// Each tracked nonce uses 12 bytes + HashSet overhead.
/// For high-volume applications, consider a Bloom filter or sliding window.
pub struct NonceTracker {
    /// Set of all seen nonces
    seen: HashSet<[u8; 12]>,
    /// Maximum nonces to track before requiring reset
    max_size: usize,
}

impl NonceTracker {
    /// Default maximum tracked nonces (1 million)
    pub const DEFAULT_MAX: usize = 1_000_000;

    /// Create a new tracker with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_MAX)
    }

    /// Create tracker with specified maximum capacity.
    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(max_size.min(10_000)),
            max_size,
        }
    }

    /// Check and mark a nonce as used.
    ///
    /// # Returns
    /// - `Ok(())` if nonce is fresh (first time seen)
    /// - `Err(NonceError::AlreadyUsed)` if nonce was seen before
    ///
    /// # Verus Specification
    /// ```verus
    /// requires nonce.len() == 12
    /// ensures result.is_ok() ==> self.seen.contains(nonce)
    /// ensures result.is_err() ==> old(self.seen).contains(nonce)
    /// ```
    pub fn check_and_mark(&mut self, nonce: &Nonce) -> Result<(), NonceError> {
        if self.seen.len() >= self.max_size {
            // In production, might want to switch to sliding window
            // For now, reject to prevent memory exhaustion
            return Err(NonceError::Exhausted);
        }

        if self.seen.contains(&nonce.bytes) {
            return Err(NonceError::AlreadyUsed);
        }

        self.seen.insert(nonce.bytes);
        Ok(())
    }

    /// Check if a nonce has been seen (without marking).
    pub fn was_seen(&self, nonce: &Nonce) -> bool {
        self.seen.contains(&nonce.bytes)
    }

    /// Get number of tracked nonces.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Check if tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Clear all tracked nonces (use with caution - enables replay).
    ///
    /// # Security Warning
    /// Clearing the tracker allows previously-seen nonces to be accepted again.
    /// Only do this during a re-keying operation.
    pub fn clear(&mut self) {
        self.seen.clear();
    }
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_from_bytes() {
        let bytes = [1u8; 12];
        let nonce = Nonce::from_bytes(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn test_nonce_invalid_length() {
        let bytes = [1u8; 11];
        assert!(matches!(
            Nonce::from_bytes(&bytes),
            Err(NonceError::InvalidLength { expected: 12, got: 11 })
        ));
    }

    #[test]
    fn test_generator_uniqueness() {
        let gen = NonceGenerator::with_session_id([0xAA, 0xBB, 0xCC, 0xDD]);
        let mut seen = HashSet::new();

        for _ in 0..10_000 {
            let nonce = gen.next().unwrap();
            assert!(!seen.contains(&nonce.bytes), "Nonce collision detected!");
            seen.insert(nonce.bytes);
        }

        assert_eq!(gen.count(), 10_000);
    }

    #[test]
    fn test_generator_counter_format() {
        let gen = NonceGenerator::with_session_id([0xDE, 0xAD, 0xBE, 0xEF]);
        
        let n1 = gen.next().unwrap();
        let n2 = gen.next().unwrap();

        // First 8 bytes should be counter (big-endian)
        assert_eq!(&n1.bytes[0..8], &0u64.to_be_bytes());
        assert_eq!(&n2.bytes[0..8], &1u64.to_be_bytes());

        // Last 4 bytes should be session ID
        assert_eq!(&n1.bytes[8..12], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&n2.bytes[8..12], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_tracker_rejects_reuse() {
        let mut tracker = NonceTracker::new();
        let nonce = Nonce::from_array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        // First use should succeed
        assert!(tracker.check_and_mark(&nonce).is_ok());
        
        // Second use should fail
        assert!(matches!(
            tracker.check_and_mark(&nonce),
            Err(NonceError::AlreadyUsed)
        ));
    }

    #[test]
    fn test_tracker_capacity() {
        let mut tracker = NonceTracker::with_capacity(100);
        
        for i in 0..100 {
            let mut bytes = [0u8; 12];
            bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            let nonce = Nonce::from_array(bytes);
            assert!(tracker.check_and_mark(&nonce).is_ok());
        }

        // 101st should fail
        let nonce = Nonce::from_array([0xFF; 12]);
        assert!(matches!(
            tracker.check_and_mark(&nonce),
            Err(NonceError::Exhausted)
        ));
    }
}
