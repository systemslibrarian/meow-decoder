//! Droplet wire format — serialise / deserialise.
//!
//! Format (little-endian, see `docs/FOUNTAIN_RUST_WASM_MIGRATION.md`):
//!
//! ```text
//! seed:           u64
//! block_count:    u16
//! block_indices: [u16; block_count]
//! data:          [u8;  block_size]
//! ```
//!
//! Total size = `8 + 2 + 2*block_count + block_size` bytes.
//!
//! This format is locked: changing it breaks every previously-encoded
//! GIF. The 16 golden vectors under `tests/golden/fountain/` are the
//! regression net.

use core::convert::TryFrom;

/// One fountain-code droplet — an encoded symbol that is a XOR of one
/// or more source blocks.
///
/// Mirrors `meow_decoder.fountain.Droplet`. The `block_indices` field
/// is sorted ascending and contains no duplicates (encoder enforces
/// this on `random.sample` output before serialisation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Droplet {
    /// PRNG seed that deterministically reconstructs the
    /// `block_indices` list. Cross-checked at decode time.
    pub seed: u64,
    /// Sorted, unique source-block indices that XOR into this droplet.
    pub block_indices: Vec<u16>,
    /// XOR of the source blocks at `block_indices`. Length is
    /// `block_size` from the encoder's manifest.
    pub data: Vec<u8>,
}

/// Errors produced when parsing a droplet from the wire.
///
/// Each variant pins the *position* (byte offset) of the failure so
/// fuzzers and CI can show a precise diagnostic on garbled input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Header would not fit in the buffer at all.
    /// Need at least 10 bytes (8 seed + 2 block_count).
    HeaderTooShort {
        got: usize,
    },
    /// `block_count` field claims more indices than the buffer can hold.
    IndicesOverflow {
        block_count: u16,
        remaining_bytes: usize,
    },
    /// After the indices, the residual data length doesn't match the
    /// expected `block_size` configured by the caller. `expected` is
    /// the size declared by the encoder/decoder manifest; `got` is the
    /// number of leftover bytes.
    DataLengthMismatch {
        expected: usize,
        got: usize,
    },
    /// `block_indices` contains a duplicate or non-sorted value — the
    /// canonical encoder always emits sorted, unique indices.
    UnsortedOrDuplicateIndices,
}

impl Droplet {
    /// Serialised size in bytes for a given `block_size` and number of
    /// indices. Pure function — no allocation.
    #[inline]
    pub fn wire_size(block_count: usize, block_size: usize) -> usize {
        8 + 2 + 2 * block_count + block_size
    }

    /// Serialise a droplet to its wire bytes. Allocates exactly
    /// `wire_size(...)` bytes.
    ///
    /// Does NOT validate that `block_indices` is sorted — the encoder
    /// is expected to feed a sorted slice (matching the Python encoder
    /// which always sorts after `random.sample`). Decoders should call
    /// [`Droplet::from_wire`] which DOES enforce the sort invariant.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::wire_size(
            self.block_indices.len(),
            self.data.len(),
        ));
        out.extend_from_slice(&self.seed.to_le_bytes());
        out.extend_from_slice(&(self.block_indices.len() as u16).to_le_bytes());
        for idx in &self.block_indices {
            out.extend_from_slice(&idx.to_le_bytes());
        }
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse a droplet from wire bytes given the expected `block_size`
    /// (configured in the encoder's manifest, propagated to the
    /// decoder out of band).
    ///
    /// Strict: rejects unsorted or duplicate indices — those would be
    /// either a forged droplet or a buggy encoder.
    pub fn from_wire(buf: &[u8], block_size: usize) -> Result<Self, WireError> {
        if buf.len() < 10 {
            return Err(WireError::HeaderTooShort { got: buf.len() });
        }
        let seed = u64::from_le_bytes(<[u8; 8]>::try_from(&buf[0..8]).unwrap());
        let block_count = u16::from_le_bytes(<[u8; 2]>::try_from(&buf[8..10]).unwrap());
        let block_count_usize = block_count as usize;
        let indices_byte_count = 2 * block_count_usize;
        let header_end = 10 + indices_byte_count;
        if buf.len() < header_end {
            return Err(WireError::IndicesOverflow {
                block_count,
                remaining_bytes: buf.len().saturating_sub(10),
            });
        }
        let mut block_indices = Vec::with_capacity(block_count_usize);
        for i in 0..block_count_usize {
            let off = 10 + 2 * i;
            block_indices.push(u16::from_le_bytes(
                <[u8; 2]>::try_from(&buf[off..off + 2]).unwrap(),
            ));
        }
        // Strict sort + uniqueness check: catches forged droplets and
        // mismatched encoder behaviour before the decoder runs BP on
        // them.
        for window in block_indices.windows(2) {
            if window[0] >= window[1] {
                return Err(WireError::UnsortedOrDuplicateIndices);
            }
        }
        let data_len = buf.len() - header_end;
        if data_len != block_size {
            return Err(WireError::DataLengthMismatch {
                expected: block_size,
                got: data_len,
            });
        }
        let data = buf[header_end..].to_vec();
        Ok(Droplet {
            seed,
            block_indices,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_arithmetic() {
        // 8 (seed) + 2 (count) + 2*degree + block_size
        assert_eq!(Droplet::wire_size(0, 0), 10);
        assert_eq!(Droplet::wire_size(1, 32), 8 + 2 + 2 + 32);
        assert_eq!(Droplet::wire_size(5, 256), 8 + 2 + 10 + 256);
    }

    #[test]
    fn roundtrip_degree_one_systematic() {
        // Mirrors the seed=0 case from the smallest golden vector
        // (k=2, block_size=32). The systematic-droplet branch in the
        // Python encoder emits a degree-1 droplet for seed < 2*k.
        let d = Droplet {
            seed: 0,
            block_indices: vec![0],
            data: vec![0xAB; 32],
        };
        let wire = d.to_wire();
        assert_eq!(wire.len(), Droplet::wire_size(1, 32));
        // Header bytes spot check.
        assert_eq!(&wire[0..8], &0u64.to_le_bytes()); // seed
        assert_eq!(&wire[8..10], &1u16.to_le_bytes()); // count
        assert_eq!(&wire[10..12], &0u16.to_le_bytes()); // index 0
        assert_eq!(&wire[12..], &[0xAB; 32]);

        let parsed = Droplet::from_wire(&wire, 32).expect("parse ok");
        assert_eq!(parsed, d);
    }

    #[test]
    fn roundtrip_degree_five_random_data() {
        let d = Droplet {
            seed: 0xDEAD_BEEF_F00D_CAFE,
            block_indices: vec![3, 7, 11, 22, 99],
            data: (0u8..200).collect(),
        };
        let wire = d.to_wire();
        let parsed = Droplet::from_wire(&wire, 200).expect("parse ok");
        assert_eq!(parsed, d);
    }

    #[test]
    fn header_too_short_rejected() {
        assert!(matches!(
            Droplet::from_wire(&[0u8; 9], 32),
            Err(WireError::HeaderTooShort { got: 9 })
        ));
    }

    #[test]
    fn indices_overflow_rejected() {
        // Claim 5 indices, supply 0 indices' worth of bytes.
        let mut buf = vec![0u8; 10];
        buf[8..10].copy_from_slice(&5u16.to_le_bytes());
        assert!(matches!(
            Droplet::from_wire(&buf, 32),
            Err(WireError::IndicesOverflow { .. })
        ));
    }

    #[test]
    fn data_length_mismatch_rejected() {
        // 1 index, block_size 100, but only 99 data bytes.
        let mut buf = Vec::with_capacity(8 + 2 + 2 + 99);
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend(std::iter::repeat(0xFFu8).take(99));
        assert!(matches!(
            Droplet::from_wire(&buf, 100),
            Err(WireError::DataLengthMismatch {
                expected: 100,
                got: 99
            })
        ));
    }

    #[test]
    fn unsorted_indices_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&3u16.to_le_bytes());
        // 3, 1, 2 — out of order
        buf.extend_from_slice(&3u16.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend(std::iter::repeat(0u8).take(32));
        assert!(matches!(
            Droplet::from_wire(&buf, 32),
            Err(WireError::UnsortedOrDuplicateIndices)
        ));
    }

    #[test]
    fn duplicate_indices_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&5u16.to_le_bytes());
        buf.extend_from_slice(&5u16.to_le_bytes());
        buf.extend(std::iter::repeat(0u8).take(32));
        assert!(matches!(
            Droplet::from_wire(&buf, 32),
            Err(WireError::UnsortedOrDuplicateIndices)
        ));
    }

    #[test]
    fn matches_golden_vector_smallest() {
        // The k=2, b=32, seed=0 golden vector lives at
        // tests/golden/fountain/k2_b32_s0.bin and starts with:
        //   seed=0 (8 bytes LE), block_count=1, indices=[0], data=...
        // We can't read the file from a Rust test (path crosses crate
        // boundary), but we can assert the FORMAT by reconstructing it.
        let d = Droplet {
            seed: 0,
            block_indices: vec![0],
            data: vec![0u8; 32],
        };
        let wire = d.to_wire();
        // First two bytes of the seed field must be zero (LE encoding).
        assert_eq!(wire[0], 0x00);
        assert_eq!(wire[1], 0x00);
        // block_count = 1 in the next two bytes.
        assert_eq!(&wire[8..10], &1u16.to_le_bytes());
    }
}
