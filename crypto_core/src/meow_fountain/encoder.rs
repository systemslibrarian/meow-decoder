//! Luby Transform encoder — wires Phase 1b–1d primitives to produce
//! droplets that match `meow_decoder.fountain.FountainEncoder` byte-
//! for-byte.
//!
//! Target Python (`meow_decoder/fountain.py:159-200`):
//!
//! ```python
//! def droplet(self, seed=None):
//!     if seed is None:
//!         seed = self.droplet_count
//!     self.droplet_count += 1
//!
//!     if seed < (2 * self.k_blocks):
//!         block_idx = seed % self.k_blocks
//!         block_indices = [block_idx]
//!         xor_data = bytearray(self.blocks[block_idx])
//!     else:
//!         rng = random.Random(seed)
//!         degree = self.distribution.sample_degree(rng)
//!         block_indices = rng.sample(range(self.k_blocks),
//!                                    min(degree, self.k_blocks))
//!         block_indices.sort()
//!         xor_data = bytearray(self.block_size)
//!         for idx in block_indices:
//!             block_data = self.blocks[idx]
//!             for i in range(self.block_size):
//!                 xor_data[i] ^= block_data[i]
//!
//!     return Droplet(seed=seed, block_indices=block_indices,
//!                    data=bytes(xor_data))
//! ```
//!
//! Two paths — the systematic shortcut for `seed < 2*k` (the early
//! frames carry literal source blocks for fast decode) and the
//! Robust-Soliton path for everything else.

use super::cpython_random::CpRandom;
use super::distribution::RobustSoliton;
use super::wire::Droplet;

/// Maximum `k_blocks` × `block_size` we will allocate. Mirrors the
/// fountain.py "10 GiB sanity ceiling" check (audit-followup 9.1).
const MAX_TOTAL_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// Errors from constructing or driving the encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderError {
    /// `k_blocks` or `block_size` is non-positive — same check as the
    /// Python encoder.
    InvalidShape { k_blocks: usize, block_size: usize },
    /// `k_blocks * block_size` exceeds the 10 GiB sanity ceiling.
    TotalSizeExceeded { total: u64, ceiling: u64 },
    /// `k_blocks` does not fit in u16 (which is what the wire format
    /// allows). Practical limit: 65535 source blocks.
    KBlocksOverflowU16 { k_blocks: usize },
}

/// Luby Transform fountain encoder.
///
/// Construction zero-pads the input to `k_blocks * block_size` bytes
/// (matching Python's `self.data + b"\x00" * (total_size - len(data))`)
/// and slices it into `k_blocks` source blocks.
pub struct FountainEncoder {
    k_blocks: usize,
    block_size: usize,
    blocks: Vec<Vec<u8>>,
    distribution: RobustSoliton,
}

impl FountainEncoder {
    /// Build a fresh encoder over `data`. `data` is zero-padded up to
    /// `k_blocks * block_size`. Errors mirror `FountainEncoder.__init__`
    /// in fountain.py.
    pub fn new(data: &[u8], k_blocks: usize, block_size: usize) -> Result<Self, EncoderError> {
        if k_blocks == 0 || block_size == 0 {
            return Err(EncoderError::InvalidShape {
                k_blocks,
                block_size,
            });
        }
        if k_blocks > u16::MAX as usize {
            return Err(EncoderError::KBlocksOverflowU16 { k_blocks });
        }
        let total = (k_blocks as u64) * (block_size as u64);
        if total > MAX_TOTAL_SIZE {
            return Err(EncoderError::TotalSizeExceeded {
                total,
                ceiling: MAX_TOTAL_SIZE,
            });
        }
        // Pad with zeros up to total_size.
        let mut padded = Vec::with_capacity(total as usize);
        padded.extend_from_slice(data);
        if (data.len() as u64) < total {
            padded.resize(total as usize, 0);
        }

        let mut blocks = Vec::with_capacity(k_blocks);
        for i in 0..k_blocks {
            blocks.push(padded[i * block_size..(i + 1) * block_size].to_vec());
        }

        Ok(Self {
            k_blocks,
            block_size,
            blocks,
            distribution: RobustSoliton::new(k_blocks),
        })
    }

    /// `k_blocks` reported back to the caller.
    pub fn k_blocks(&self) -> usize {
        self.k_blocks
    }

    /// `block_size` reported back to the caller.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Generate the droplet with the supplied seed.
    ///
    /// For `seed < 2*k_blocks`, emits a systematic degree-1 droplet
    /// carrying the source block at index `seed % k_blocks`. For
    /// larger seeds, runs the Python flow:
    /// `Random(seed)` → `sample_degree` → `sample(range(k), degree)` →
    /// sort → XOR.
    pub fn droplet(&self, seed: u32) -> Droplet {
        let k = self.k_blocks;
        if (seed as u64) < (2 * k as u64) {
            // Systematic branch — degree 1, deterministic block index.
            let block_idx = (seed as usize) % k;
            return Droplet {
                seed,
                block_indices: vec![block_idx as u16],
                data: self.blocks[block_idx].clone(),
            };
        }

        // Robust-Soliton branch.
        let mut rng = CpRandom::new(seed);
        let degree = self.distribution.sample_degree(rng.random());
        let degree_clamped = degree.min(k);

        // Dispatch to pool or set path based on CPython's setsize heuristic.
        let mut indices = rng.sample_range(k as u32, degree_clamped as u32);
        indices.sort_unstable();
        // Convert u32 → u16 (k_blocks ≤ u16::MAX validated in `new`).
        let block_indices: Vec<u16> = indices.into_iter().map(|x| x as u16).collect();

        let mut xor_data = vec![0u8; self.block_size];
        for &idx in &block_indices {
            let block = &self.blocks[idx as usize];
            for i in 0..self.block_size {
                xor_data[i] ^= block[i];
            }
        }

        Droplet {
            seed,
            block_indices,
            data: xor_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_shape_rejected() {
        assert!(matches!(
            FountainEncoder::new(&[], 0, 100),
            Err(EncoderError::InvalidShape { .. })
        ));
        assert!(matches!(
            FountainEncoder::new(&[], 10, 0),
            Err(EncoderError::InvalidShape { .. })
        ));
    }

    #[test]
    fn total_size_ceiling_enforced() {
        // k_blocks must fit u16 (≤ 65535) — pick a value just under
        // the limit, with a block_size that pushes total over 10 GiB.
        // 50_000 × 300_000 = 1.5e10 ≈ 14 GiB > 10 GiB ceiling.
        assert!(matches!(
            FountainEncoder::new(&[], 50_000, 300_000),
            Err(EncoderError::TotalSizeExceeded { .. })
        ));
    }

    #[test]
    fn k_blocks_overflow_u16_rejected() {
        // 65536 > u16::MAX = 65535. Total size is fine, but k won't
        // fit in the wire format's u16 block_count field.
        let r = FountainEncoder::new(&[], 65_536, 1);
        assert!(matches!(r, Err(EncoderError::KBlocksOverflowU16 { .. })));
    }

    #[test]
    fn systematic_droplet_for_small_seeds() {
        // For seed < 2*k, droplet is degree-1 and block_idx = seed % k.
        let data: Vec<u8> = (0u8..40).collect();
        let enc = FountainEncoder::new(&data, 2, 20).unwrap();

        let d0 = enc.droplet(0);
        assert_eq!(d0.seed, 0);
        assert_eq!(d0.block_indices, vec![0]);
        assert_eq!(d0.data, data[..20]);

        let d1 = enc.droplet(1);
        assert_eq!(d1.seed, 1);
        assert_eq!(d1.block_indices, vec![1]);
        assert_eq!(d1.data, data[20..40]);

        // seed=2 wraps around: 2 % k=2 = 0
        let d2 = enc.droplet(2);
        assert_eq!(d2.block_indices, vec![0]);
    }

    #[test]
    fn zero_padding_to_total_size() {
        // 5 bytes of input but k=2, block_size=8 → total=16 → 11 bytes
        // of zero padding.
        let data = vec![1u8, 2, 3, 4, 5];
        let enc = FountainEncoder::new(&data, 2, 8).unwrap();

        let d0 = enc.droplet(0);
        // First block: bytes 0..8 = [1,2,3,4,5,0,0,0]
        assert_eq!(d0.data, vec![1, 2, 3, 4, 5, 0, 0, 0]);

        let d1 = enc.droplet(1);
        // Second block: bytes 8..16 = [0,0,0,0,0,0,0,0]
        assert_eq!(d1.data, vec![0; 8]);
    }
}
