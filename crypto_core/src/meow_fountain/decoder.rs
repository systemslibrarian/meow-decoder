//! Luby Transform decoder — belief-propagation reconstruction of the
//! source blocks from a stream of droplets.
//!
//! Mirrors `meow_decoder.fountain.FountainDecoder`:
//!
//! ```python
//! def add_droplet(self, droplet: Droplet) -> bool:
//!     droplet = self._reduce_droplet(droplet)
//!     if len(droplet.block_indices) == 0:
//!         return self.is_complete()
//!     if len(droplet.block_indices) == 1:
//!         block_idx = droplet.block_indices[0]
//!         self._decode_block(block_idx, droplet.data)
//!         self._process_pending()
//!     else:
//!         self.pending_droplets.append(droplet)
//!     return self.is_complete()
//! ```
//!
//! The decoder is intentionally simple — drop-in compatible with the
//! Python reference. No fancy data-structure tricks, just BP. For
//! adversarial-input safety the upstream MAC layer in
//! `schrodinger_decode.py` filters droplets before they reach the
//! decoder, and the GIF parser caps the total frame count at
//! MAX_GIF_FRAMES (verified bounded by `tests/test_schrodinger_dos.py`).

use super::wire::Droplet;

/// SECURITY (H1): Maximum `k_blocks` × `block_size` we will allocate.
/// Mirrors the encoder's `MAX_TOTAL_SIZE` (encoder.rs) — the 10 GiB
/// "sanity ceiling". Without this, an attacker-controlled `k_blocks`
/// (e.g. an unauthenticated `block_count` field flowing from
/// `schrodinger_decode.py` / a scanned `FOUNTAIN:` QR string) drives an
/// unbounded `vec![None; k_blocks]` allocation → OOM DoS.
const MAX_TOTAL_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// SECURITY (H1): Errors from constructing the decoder. Mirrors the
/// encoder's `EncoderError` variants so the two halves reject the same
/// out-of-range shapes identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderError {
    /// `k_blocks` or `block_size` is zero — same check as the encoder.
    InvalidShape { k_blocks: usize, block_size: usize },
    /// `k_blocks` does not fit in u16 (the wire format's `block_count`
    /// field). Practical limit: 65535 source blocks.
    KBlocksOverflowU16 { k_blocks: usize },
    /// `k_blocks * block_size` exceeds the 10 GiB sanity ceiling.
    TotalSizeExceeded { total: u64, ceiling: u64 },
}

impl std::fmt::Display for DecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecoderError::InvalidShape {
                k_blocks,
                block_size,
            } => write!(
                f,
                "invalid decoder shape: k_blocks={k_blocks}, block_size={block_size} (both must be > 0)"
            ),
            DecoderError::KBlocksOverflowU16 { k_blocks } => {
                write!(f, "k_blocks={k_blocks} exceeds u16::MAX (65535)")
            }
            DecoderError::TotalSizeExceeded { total, ceiling } => {
                write!(f, "total size {total} exceeds ceiling {ceiling}")
            }
        }
    }
}

impl std::error::Error for DecoderError {}

/// LT decoder. Construct with `new(k_blocks, block_size)`, feed
/// droplets via `add_droplet` until `is_complete()` returns `true`,
/// then call `recovered_data()` for the reassembled bytes.
pub struct FountainDecoder {
    k_blocks: usize,
    block_size: usize,
    /// `Some(data)` if block at index has been decoded.
    blocks: Vec<Option<Vec<u8>>>,
    decoded_count: usize,
    /// Droplets we have not yet been able to decode; degree ≥ 2.
    pending: Vec<Droplet>,
}

impl FountainDecoder {
    /// SECURITY (H1): Fallible, bounds-checked constructor. Rejects
    /// `k_blocks == 0` / `block_size == 0`, `k_blocks > u16::MAX`, and
    /// `k_blocks * block_size > MAX_TOTAL_SIZE` *before* allocating
    /// `vec![None; k_blocks]`, mirroring `FountainEncoder::new`. This is
    /// the constructor callers should use for attacker-influenced
    /// `(k_blocks, block_size)`.
    pub fn try_new(k_blocks: usize, block_size: usize) -> Result<Self, DecoderError> {
        if k_blocks == 0 || block_size == 0 {
            return Err(DecoderError::InvalidShape {
                k_blocks,
                block_size,
            });
        }
        if k_blocks > u16::MAX as usize {
            return Err(DecoderError::KBlocksOverflowU16 { k_blocks });
        }
        let total = (k_blocks as u64) * (block_size as u64);
        if total > MAX_TOTAL_SIZE {
            return Err(DecoderError::TotalSizeExceeded {
                total,
                ceiling: MAX_TOTAL_SIZE,
            });
        }
        Ok(Self {
            k_blocks,
            block_size,
            blocks: vec![None; k_blocks],
            decoded_count: 0,
            pending: Vec::new(),
        })
    }

    /// SECURITY (H1): `new` now validates its inputs. It forwards to
    /// [`FountainDecoder::try_new`] and returns the same `Result`, so an
    /// out-of-range `k_blocks` can no longer drive an unbounded
    /// allocation. NOTE: this is a signature change from the old
    /// infallible `new(...) -> Self`; callers must handle the `Result`
    /// (e.g. `?` / `map_err`). Callers may equivalently call `try_new`.
    pub fn new(k_blocks: usize, block_size: usize) -> Result<Self, DecoderError> {
        Self::try_new(k_blocks, block_size)
    }

    pub fn k_blocks(&self) -> usize {
        self.k_blocks
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn decoded_count(&self) -> usize {
        self.decoded_count
    }

    pub fn is_complete(&self) -> bool {
        self.decoded_count == self.k_blocks
    }

    /// Number of pending droplets (degree ≥ 2 awaiting BP).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// True if a droplet is structurally compatible with this decoder:
    /// every block index is in range and the data is exactly one block
    /// wide. The XOR/index math below assumes both; a droplet parsed for
    /// a different `(k_blocks, block_size)` (or a corrupted one that still
    /// slipped past an upstream MAC) must be rejected here rather than
    /// panicking with an out-of-bounds index — in wasm (`panic=abort`)
    /// that panic is an unrecoverable crash / DoS.
    fn droplet_is_valid(&self, droplet: &Droplet) -> bool {
        droplet.data.len() == self.block_size
            && droplet
                .block_indices
                .iter()
                .all(|&idx| (idx as usize) < self.k_blocks)
    }

    /// Add a droplet. Returns true if the decoder is complete after
    /// this insertion. Mirrors `FountainDecoder.add_droplet`.
    pub fn add_droplet(&mut self, droplet: Droplet) -> bool {
        // Defense-in-depth: ignore droplets that don't match this
        // decoder's geometry instead of indexing out of bounds.
        if !self.droplet_is_valid(&droplet) {
            return self.is_complete();
        }
        let reduced = self.reduce_droplet(droplet);
        match reduced.block_indices.len() {
            0 => {} // redundant — drop
            1 => {
                let idx = reduced.block_indices[0] as usize;
                self.decode_block(idx, reduced.data);
                self.process_pending();
            }
            _ => {
                self.pending.push(reduced);
            }
        }
        self.is_complete()
    }

    /// XOR-out already-decoded blocks from a droplet's data and prune
    /// their indices. Mirror of `_reduce_droplet`.
    fn reduce_droplet(&self, droplet: Droplet) -> Droplet {
        let unknown: Vec<u16> = droplet
            .block_indices
            .iter()
            .copied()
            .filter(|&idx| self.blocks[idx as usize].is_none())
            .collect();

        if unknown.len() == droplet.block_indices.len() {
            return droplet;
        }

        let mut reduced_data = droplet.data.clone();
        for &idx in &droplet.block_indices {
            if let Some(decoded) = &self.blocks[idx as usize] {
                for i in 0..self.block_size {
                    reduced_data[i] ^= decoded[i];
                }
            }
        }

        Droplet {
            seed: droplet.seed,
            block_indices: unknown,
            data: reduced_data,
        }
    }

    fn decode_block(&mut self, idx: usize, data: Vec<u8>) {
        if self.blocks[idx].is_none() {
            self.blocks[idx] = Some(data);
            self.decoded_count += 1;
        }
    }

    /// Belief propagation over pending droplets — mirror of
    /// `_process_pending`. Iterates until no further progress.
    fn process_pending(&mut self) {
        let mut made_progress = true;
        while made_progress {
            made_progress = false;
            let drained: Vec<Droplet> = std::mem::take(&mut self.pending);
            for droplet in drained {
                let reduced = self.reduce_droplet(droplet);
                match reduced.block_indices.len() {
                    0 => {} // redundant — drop
                    1 => {
                        let idx = reduced.block_indices[0] as usize;
                        self.decode_block(idx, reduced.data);
                        made_progress = true;
                    }
                    _ => self.pending.push(reduced),
                }
            }
        }
    }

    /// Reassemble the source data — concatenation of all decoded
    /// blocks. Returns the raw `k * block_size` byte buffer; trim to
    /// the original length out-of-band (the encoder doesn't carry
    /// the un-padded length itself; the manifest does).
    pub fn recovered_data(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut out = Vec::with_capacity(self.k_blocks * self.block_size);
        for slot in &self.blocks {
            out.extend_from_slice(slot.as_ref().expect("complete decoder"));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meow_fountain::encoder::FountainEncoder;

    fn make_source(total_size: usize) -> Vec<u8> {
        (0..total_size)
            .map(|i| ((i.wrapping_mul(31).wrapping_add(17)) & 0xFF) as u8)
            .collect()
    }

    #[test]
    fn roundtrip_small_k() {
        let k = 5;
        let block_size = 32;
        let source = make_source(k * block_size);
        let enc = FountainEncoder::new(&source, k, block_size).unwrap();

        let mut dec = FountainDecoder::new(k, block_size).unwrap();
        // Systematic droplets (seed < 2*k = 10) cover all blocks
        // exactly once via degree-1 deliveries.
        for seed in 0..(2 * k as u32) {
            dec.add_droplet(enc.droplet(seed));
            if dec.is_complete() {
                break;
            }
        }
        assert!(
            dec.is_complete(),
            "decoder should complete from systematic droplets"
        );
        assert_eq!(dec.recovered_data().unwrap(), source);
    }

    #[test]
    fn roundtrip_with_random_droplets() {
        // Mix of systematic and random-degree droplets — exercises
        // the BP path through `pending_droplets`.
        let k = 10;
        let block_size = 64;
        let source = make_source(k * block_size);
        let enc = FountainEncoder::new(&source, k, block_size).unwrap();

        let mut dec = FountainDecoder::new(k, block_size).unwrap();
        // First 5 systematic, then 50 random — fountain redundancy.
        for seed in 0..(5 + 50) as u32 {
            if dec.add_droplet(enc.droplet(seed)) {
                break;
            }
        }
        assert!(dec.is_complete(), "decoder should complete with redundancy");
        assert_eq!(dec.recovered_data().unwrap(), source);
    }

    #[test]
    fn redundant_droplets_dropped() {
        // Feed the same systematic droplet twice; the second is
        // redundant and should not advance decoded_count.
        let enc = FountainEncoder::new(&[1, 2, 3, 4], 2, 2).unwrap();
        let mut dec = FountainDecoder::new(2, 2).unwrap();
        let d0 = enc.droplet(0);
        dec.add_droplet(d0.clone());
        let count_after_first = dec.decoded_count();
        dec.add_droplet(d0);
        assert_eq!(dec.decoded_count(), count_after_first);
    }

    #[test]
    fn incomplete_returns_none_from_recovered_data() {
        let dec = FountainDecoder::new(5, 32).unwrap();
        assert!(dec.recovered_data().is_none());
    }

    #[test]
    fn out_of_range_block_index_is_ignored_not_panic() {
        // A droplet whose index exceeds k_blocks (corrupted, or built for
        // a different stream) must be rejected, not panic with an
        // out-of-bounds index.
        let mut dec = FountainDecoder::new(2, 4).unwrap();
        let bad = Droplet {
            seed: 0,
            block_indices: vec![1000],
            data: vec![0u8; 4],
        };
        assert!(!dec.add_droplet(bad)); // ignored; not complete; no panic
        assert_eq!(dec.decoded_count(), 0);
    }

    #[test]
    fn new_rejects_out_of_range_shapes() {
        // SECURITY (H1): constructor rejects the same shapes the encoder
        // does, so an attacker-controlled k_blocks cannot force an
        // unbounded allocation.
        assert!(matches!(
            FountainDecoder::new(0, 32),
            Err(DecoderError::InvalidShape { .. })
        ));
        assert!(matches!(
            FountainDecoder::new(5, 0),
            Err(DecoderError::InvalidShape { .. })
        ));
        assert!(matches!(
            FountainDecoder::new(65_536, 1),
            Err(DecoderError::KBlocksOverflowU16 { .. })
        ));
        // 50_000 × 300_000 ≈ 14 GiB > 10 GiB ceiling (k still fits u16).
        assert!(matches!(
            FountainDecoder::new(50_000, 300_000),
            Err(DecoderError::TotalSizeExceeded { .. })
        ));
        // try_new is the same validated path.
        assert!(FountainDecoder::try_new(5, 32).is_ok());
    }

    #[test]
    fn wrong_data_length_is_ignored_not_panic() {
        // A droplet whose data is narrower than the decoder's block_size
        // must be rejected before the XOR-reduction loop indexes past its
        // end.
        let mut dec = FountainDecoder::new(2, 8).unwrap();
        // Decode block 0 first so reduction would run against it.
        let good = Droplet { seed: 0, block_indices: vec![0], data: vec![7u8; 8] };
        dec.add_droplet(good);
        let short = Droplet {
            seed: 1,
            block_indices: vec![0, 1],
            data: vec![0u8; 3], // shorter than block_size
        };
        assert!(!dec.add_droplet(short)); // ignored; no panic
    }
}
