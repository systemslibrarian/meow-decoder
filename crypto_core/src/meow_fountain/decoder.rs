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
    pub fn new(k_blocks: usize, block_size: usize) -> Self {
        Self {
            k_blocks,
            block_size,
            blocks: vec![None; k_blocks],
            decoded_count: 0,
            pending: Vec::new(),
        }
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

    /// Add a droplet. Returns true if the decoder is complete after
    /// this insertion. Mirrors `FountainDecoder.add_droplet`.
    pub fn add_droplet(&mut self, droplet: Droplet) -> bool {
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

        let mut dec = FountainDecoder::new(k, block_size);
        // Systematic droplets (seed < 2*k = 10) cover all blocks
        // exactly once via degree-1 deliveries.
        for seed in 0..(2 * k as u32) {
            dec.add_droplet(enc.droplet(seed));
            if dec.is_complete() {
                break;
            }
        }
        assert!(dec.is_complete(), "decoder should complete from systematic droplets");
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

        let mut dec = FountainDecoder::new(k, block_size);
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
        let mut dec = FountainDecoder::new(2, 2);
        let d0 = enc.droplet(0);
        dec.add_droplet(d0.clone());
        let count_after_first = dec.decoded_count();
        dec.add_droplet(d0);
        assert_eq!(dec.decoded_count(), count_after_first);
    }

    #[test]
    fn incomplete_returns_none_from_recovered_data() {
        let dec = FountainDecoder::new(5, 32);
        assert!(dec.recovered_data().is_none());
    }
}
