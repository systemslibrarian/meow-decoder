//! Droplet wire format — serialise / deserialise.
//!
//! Format (BIG-endian — must match the existing production
//! `meow_decoder.fountain.pack_droplet`, which uses `struct.pack(">I", ...)`
//! for the seed and `>H` for the counts/indices):
//!
//! ```text
//! seed:           u32  big-endian
//! block_count:    u16  big-endian
//! block_indices: [u16; block_count] big-endian
//! data:          [u8;  block_size]
//! ```
//!
//! Total size = `4 + 2 + 2*block_count + block_size` bytes.
//!
//! This format is locked — every Schrödinger GIF and every air-gap
//! transfer in the wild uses these bytes. Changing the format breaks
//! every previously-encoded recipient.
//!
//! The 16 golden vectors under `tests/golden/fountain/` are generated
//! by `pack_droplet()` and are the cross-language regression net.
//!
//! **Note on the design doc:** an earlier version of
//! `docs/FOUNTAIN_RUST_WASM_MIGRATION.md` documented this as
//! little-endian with a u64 seed; that was a doc bug, corrected when
//! the binding work crossed reference with `pack_droplet()` in
//! fountain.py. The doc and golden vectors were updated to match.

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
    /// `block_indices` list. Cross-checked at decode time. The wire
    /// format pins this to a u32 (4 bytes big-endian); the in-memory
    /// type is u32 to match.
    pub seed: u32,
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
        // 4 (seed BE u32) + 2 (block_count BE u16) + 2*block_count + block_size
        4 + 2 + 2 * block_count + block_size
    }

    /// Serialise a droplet to its wire bytes (BIG-endian).
    /// Allocates exactly `wire_size(...)` bytes.
    ///
    /// Matches `meow_decoder.fountain.pack_droplet`. Does NOT validate
    /// that `block_indices` is sorted — the encoder feeds a sorted
    /// slice (matching the Python encoder which always sorts after
    /// `random.sample`). Decoders should call [`Droplet::from_wire`]
    /// which DOES enforce the sort invariant.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::wire_size(
            self.block_indices.len(),
            self.data.len(),
        ));
        out.extend_from_slice(&self.seed.to_be_bytes());
        out.extend_from_slice(&(self.block_indices.len() as u16).to_be_bytes());
        for idx in &self.block_indices {
            out.extend_from_slice(&idx.to_be_bytes());
        }
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse a droplet from wire bytes given the expected `block_size`.
    /// Mirrors `meow_decoder.fountain.unpack_droplet`.
    ///
    /// Strict: rejects unsorted or duplicate indices — those would be
    /// either a forged droplet or a buggy encoder.
    pub fn from_wire(buf: &[u8], block_size: usize) -> Result<Self, WireError> {
        if buf.len() < 6 {
            return Err(WireError::HeaderTooShort { got: buf.len() });
        }
        let seed = u32::from_be_bytes(<[u8; 4]>::try_from(&buf[0..4]).unwrap());
        let block_count = u16::from_be_bytes(<[u8; 2]>::try_from(&buf[4..6]).unwrap());
        let block_count_usize = block_count as usize;
        let indices_byte_count = 2 * block_count_usize;
        let header_end = 6 + indices_byte_count;
        if buf.len() < header_end {
            return Err(WireError::IndicesOverflow {
                block_count,
                remaining_bytes: buf.len().saturating_sub(6),
            });
        }
        let mut block_indices = Vec::with_capacity(block_count_usize);
        for i in 0..block_count_usize {
            let off = 6 + 2 * i;
            block_indices.push(u16::from_be_bytes(
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
        // 4 (seed) + 2 (count) + 2*degree + block_size
        assert_eq!(Droplet::wire_size(0, 0), 6);
        assert_eq!(Droplet::wire_size(1, 32), 4 + 2 + 2 + 32);
        assert_eq!(Droplet::wire_size(5, 256), 4 + 2 + 10 + 256);
    }

    #[test]
    fn roundtrip_degree_one_systematic() {
        let d = Droplet {
            seed: 0,
            block_indices: vec![0],
            data: vec![0xAB; 32],
        };
        let wire = d.to_wire();
        assert_eq!(wire.len(), Droplet::wire_size(1, 32));
        // Header bytes spot check (BIG-endian).
        assert_eq!(&wire[0..4], &0u32.to_be_bytes());
        assert_eq!(&wire[4..6], &1u16.to_be_bytes());
        assert_eq!(&wire[6..8], &0u16.to_be_bytes());
        assert_eq!(&wire[8..], &[0xAB; 32]);

        let parsed = Droplet::from_wire(&wire, 32).expect("parse ok");
        assert_eq!(parsed, d);
    }

    #[test]
    fn roundtrip_degree_five_random_data() {
        let d = Droplet {
            seed: 0xF00D_CAFE,
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
            Droplet::from_wire(&[0u8; 5], 32),
            Err(WireError::HeaderTooShort { got: 5 })
        ));
    }

    #[test]
    fn indices_overflow_rejected() {
        // 6-byte header claiming 5 indices, with 0 indices bytes after.
        let mut buf = vec![0u8; 6];
        buf[4..6].copy_from_slice(&5u16.to_be_bytes());
        assert!(matches!(
            Droplet::from_wire(&buf, 32),
            Err(WireError::IndicesOverflow { .. })
        ));
    }

    #[test]
    fn data_length_mismatch_rejected() {
        // 1 index, block_size 100, but only 99 data bytes.
        let mut buf = Vec::with_capacity(4 + 2 + 2 + 99);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
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
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&3u16.to_be_bytes());
        // 3, 1, 2 — out of order
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend(std::iter::repeat(0u8).take(32));
        assert!(matches!(
            Droplet::from_wire(&buf, 32),
            Err(WireError::UnsortedOrDuplicateIndices)
        ));
    }

    #[test]
    fn duplicate_indices_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&5u16.to_be_bytes());
        buf.extend_from_slice(&5u16.to_be_bytes());
        buf.extend(std::iter::repeat(0u8).take(32));
        assert!(matches!(
            Droplet::from_wire(&buf, 32),
            Err(WireError::UnsortedOrDuplicateIndices)
        ));
    }
}
