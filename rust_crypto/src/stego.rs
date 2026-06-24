//! Steganography primitives for multi-layer embedding.
//!
//! This module provides:
//! - Per-frame, per-channel seed derivation via HKDF
//! - Syndrome-Trellis Codes (STC) for minimal-distortion embedding
//! - Pseudorandom pixel walk generation (keyed permutation)
//! - Adaptive cost function for palette-index-aware embedding
//!
//! All operations are constant-time where crypto-sensitive.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Domain separation constants for multi-layer seed derivation.
/// Each channel gets a unique context to ensure key independence.
const DOMAIN_PRIMARY: &[u8] = b"meow_stego_primary_lsb_v1";
const DOMAIN_SECONDARY: &[u8] = b"meow_stego_secondary_timing_v1";
const DOMAIN_TERTIARY: &[u8] = b"meow_stego_tertiary_palette_v1";
const DOMAIN_WALK: &[u8] = b"meow_stego_walk_permutation_v1";
const DOMAIN_DISPOSAL: &[u8] = b"meow_stego_disposal_gce_v1";
const DOMAIN_COMMENT: &[u8] = b"meow_stego_comment_ext_v1";
const DOMAIN_TEMPORAL: &[u8] = b"meow_stego_temporal_delta_v1";

/// Channel identifiers.
pub const CHANNEL_PRIMARY: u8 = 0x01;
pub const CHANNEL_SECONDARY: u8 = 0x02;
pub const CHANNEL_TERTIARY: u8 = 0x03;
pub const CHANNEL_DISPOSAL: u8 = 0x04;
pub const CHANNEL_COMMENT: u8 = 0x05;
pub const CHANNEL_TEMPORAL: u8 = 0x06;

/// Error type for stego operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StegoError {
    /// Invalid key length
    InvalidKeyLength { expected: usize, got: usize },
    /// STC encoding failed
    StcEncodingFailed(String),
    /// STC decoding failed
    StcDecodingFailed(String),
    /// Capacity exceeded
    CapacityExceeded { available: usize, required: usize },
    /// Invalid parameters
    InvalidParams(String),
}

impl std::fmt::Display for StegoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, got } => {
                write!(f, "Key must be {} bytes, got {}", expected, got)
            }
            Self::StcEncodingFailed(e) => write!(f, "STC encoding failed: {}", e),
            Self::StcDecodingFailed(e) => write!(f, "STC decoding failed: {}", e),
            Self::CapacityExceeded {
                available,
                required,
            } => {
                write!(
                    f,
                    "Capacity exceeded: need {} bits but only {} available",
                    required, available
                )
            }
            Self::InvalidParams(e) => write!(f, "Invalid parameters: {}", e),
        }
    }
}

impl std::error::Error for StegoError {}

// =============================================================================
// Per-Frame, Per-Channel Seed Derivation
// =============================================================================

/// Derive a 32-byte seed for a specific frame and channel.
///
/// Uses HKDF-SHA256 with domain separation:
///   info = domain_prefix || frame_idx (4 bytes LE) || channel_id (1 byte)
///
/// This ensures:
/// - Each frame gets a unique seed
/// - Each channel (primary/secondary/tertiary) gets an independent seed
/// - Compromise of one channel's seed reveals nothing about others
pub fn derive_frame_seed(
    master_key: &[u8],
    frame_idx: u32,
    channel_id: u8,
) -> Result<[u8; 32], StegoError> {
    if master_key.len() < 16 {
        return Err(StegoError::InvalidKeyLength {
            expected: 16,
            got: master_key.len(),
        });
    }

    let domain = match channel_id {
        CHANNEL_PRIMARY => DOMAIN_PRIMARY,
        CHANNEL_SECONDARY => DOMAIN_SECONDARY,
        CHANNEL_TERTIARY => DOMAIN_TERTIARY,
        CHANNEL_DISPOSAL => DOMAIN_DISPOSAL,
        CHANNEL_COMMENT => DOMAIN_COMMENT,
        CHANNEL_TEMPORAL => DOMAIN_TEMPORAL,
        _ => DOMAIN_PRIMARY,
    };

    // Build info: domain || frame_idx (LE) || channel_id
    let mut info = Vec::with_capacity(domain.len() + 5);
    info.extend_from_slice(domain);
    info.extend_from_slice(&frame_idx.to_le_bytes());
    info.push(channel_id);

    // HKDF-SHA256 Extract + Expand
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|e| StegoError::InvalidParams(format!("HKDF expand failed: {}", e)))?;

    Ok(okm)
}

/// Derive a walk seed for pseudorandom pixel permutation.
///
/// Separate from the channel seed to prevent walk pattern leaking
/// information about payload bits.
pub fn derive_walk_seed(master_key: &[u8], frame_idx: u32) -> Result<[u8; 32], StegoError> {
    if master_key.len() < 16 {
        return Err(StegoError::InvalidKeyLength {
            expected: 16,
            got: master_key.len(),
        });
    }

    let mut info = Vec::with_capacity(DOMAIN_WALK.len() + 4);
    info.extend_from_slice(DOMAIN_WALK);
    info.extend_from_slice(&frame_idx.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|e| StegoError::InvalidParams(format!("HKDF walk expand failed: {}", e)))?;

    Ok(okm)
}

// =============================================================================
// Pseudorandom Pixel Walk (Fisher-Yates keyed permutation)
// =============================================================================

/// Simple PRNG seeded from a 32-byte key using a hash chain.
/// NOT cryptographically secure — used only for walk pattern generation
/// where the seed itself provides the security guarantee.
struct SeededPrng {
    state: [u8; 32],
    counter: u64,
}

impl SeededPrng {
    fn new(seed: &[u8; 32]) -> Self {
        Self {
            state: *seed,
            counter: 0,
        }
    }

    /// Generate a pseudo-random u64.
    fn next_u64(&mut self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(self.state);
        hasher.update(self.counter.to_le_bytes());
        self.counter += 1;
        let digest = hasher.finalize();
        // Take first 8 bytes as u64
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&digest[..8]);
        // Update state with rest of digest for forward secrecy of walk
        self.state.copy_from_slice(&digest);
        u64::from_le_bytes(buf)
    }

    /// Generate a pseudo-random number in [0, bound).
    fn next_bounded(&mut self, bound: u64) -> u64 {
        if bound <= 1 {
            return 0;
        }
        // Rejection sampling to avoid modulo bias
        let threshold = u64::MAX - (u64::MAX % bound);
        loop {
            let val = self.next_u64();
            if val < threshold {
                return val % bound;
            }
        }
    }
}

/// Generate a pseudorandom pixel walk order using Fisher-Yates shuffle.
///
/// Given a walk seed (from derive_walk_seed) and a pixel count,
/// returns a permutation of [0..num_pixels) that defines the
/// embedding/extraction order.
///
/// This makes the embedding pattern unpredictable without the key,
/// spreading modifications across the image to resist spatial analysis.
pub fn generate_pixel_walk(walk_seed: &[u8; 32], num_pixels: usize) -> Vec<u32> {
    let mut rng = SeededPrng::new(walk_seed);
    let mut walk: Vec<u32> = (0..num_pixels as u32).collect();

    // Fisher-Yates shuffle (inside-out variant for efficiency)
    for i in (1..walk.len()).rev() {
        let j = rng.next_bounded((i + 1) as u64) as usize;
        walk.swap(i, j);
    }

    walk
}

// =============================================================================
// Syndrome-Trellis Codes (STC) — Minimal-distortion embedding
// =============================================================================
//
// STC embeds k payload bits into n cover bits with fewer than k/2 changes
// on average (vs k/2 for naive LSB replacement). This is the gold standard
// for steganographic embedding efficiency.
//
// Implementation: Viterbi-like trellis with constraint_height h (default 10).
// The submatrix H is a banded binary matrix generated from the seed.
// Embedding: find stego bits s.t. H*s = payload (mod 2) minimizing Σcost[i].
// Extraction: simply compute H*stego_bits (mod 2) to recover payload.
//
// Reference: Filler, Judas, Fridrich, "Minimizing Additive Distortion
// in Steganography using Syndrome-Trellis Codes" (2011)

/// STC constraint height (trellis width). Higher = better efficiency but slower.
/// h=10 is standard in academic literature and StegExpose-resistant tools.
const STC_CONSTRAINT_HEIGHT: usize = 10;

/// Maximum reasonable cover length to prevent OOM.
const STC_MAX_COVER_LEN: usize = 16 * 1024 * 1024; // 16M bits

/// Generate the STC submatrix H (banded, n_payload × n_cover) from a seed.
///
/// H is represented as a list of columns, where each column is a bitmask
/// of height `h` representing which payload equations this cover bit participates in.
///
/// For column j, the non-zero rows span [shift..shift+h) where shift = j * payload_len / cover_len.
fn generate_stc_matrix(seed: &[u8; 32], n_cover: usize, n_payload: usize) -> Vec<u16> {
    let h = STC_CONSTRAINT_HEIGHT;
    let mut rng = SeededPrng::new(seed);

    // Each column is a h-bit pattern (fits in u16 since h ≤ 16)
    let mut columns = vec![0u16; n_cover];

    for col in columns.iter_mut() {
        // Random h-bit pattern for this column
        let pattern = (rng.next_u64() & ((1u64 << h) - 1)) as u16;
        // Ensure at least one bit is set (column contributes to at least one equation)
        *col = if pattern == 0 { 1 } else { pattern };
    }

    // Suppress unused variable warnings
    let _ = n_payload;

    columns
}

/// Adaptive cost function for cover bits.
///
/// Returns a cost for flipping each cover bit. Higher cost = more visible change.
/// The cost function is content-aware:
/// - Bits in textured regions (high local variance) get lower cost
/// - Bits near palette boundaries get higher cost
/// - Zero cost = "wet" element (never modify this bit)
///
/// `adaptation_seed`: seed for any randomized cost adjustments
/// `cover_bits`: the cover bit stream
/// `costs_out`: pre-allocated output buffer (same length as cover_bits)
pub fn compute_adaptive_costs(
    adaptation_seed: &[u8; 32],
    cover_bits: &[u8],
    pixel_values: &[u8],
    costs_out: &mut [f64],
) {
    assert_eq!(cover_bits.len(), costs_out.len());

    let mut rng = SeededPrng::new(adaptation_seed);

    // Base cost: 1.0 for all bits (uniform)
    for c in costs_out.iter_mut() {
        *c = 1.0;
    }

    // Texture-aware adaptation: estimate local variance in a sliding window
    // Group bits by pixel (3 channels × lsb_bits per pixel)
    // For each pixel region, compute variance of surrounding pixel values
    if !pixel_values.is_empty() {
        let window = 8; // 8-pixel neighborhood
        let len = pixel_values.len();

        for i in 0..len {
            // Compute local variance in window around pixel i
            let start = i.saturating_sub(window);
            let end = if i + window < len { i + window } else { len };
            let slice = &pixel_values[start..end];

            let mean: f64 = slice.iter().map(|&v| v as f64).sum::<f64>() / slice.len() as f64;
            let variance: f64 = slice
                .iter()
                .map(|&v| {
                    let d = v as f64 - mean;
                    d * d
                })
                .sum::<f64>()
                / slice.len() as f64;

            // High variance (texture) = low cost; low variance (flat) = high cost
            // Normalize: variance of [0..255] uniform ≈ 5400
            let texture_factor = if variance > 100.0 {
                0.5 // Textured: cheap to modify
            } else if variance > 20.0 {
                1.0 // Medium: normal cost
            } else {
                3.0 // Flat/smooth: expensive to modify
            };

            // Apply to corresponding cover bits
            // Each pixel value maps to multiple cover bits depending on LSB depth
            // Approximate: proportional indexing
            let bit_idx = i * cover_bits.len() / len;
            if bit_idx < costs_out.len() {
                costs_out[bit_idx] *= texture_factor;
            }
        }
    }

    // Add small random perturbation to break patterns (constant-time safe since
    // this is the walk pattern, not secret data)
    for c in costs_out.iter_mut() {
        let jitter = (rng.next_bounded(100) as f64) / 10000.0; // ±0.01
        *c += jitter;
        // Ensure cost is never exactly zero (would mean "wet"/forbidden)
        if *c < 0.001 {
            *c = 0.001;
        }
    }
}

/// Compute syndrome H*bits (mod 2) — shared between encode and decode.
fn compute_syndrome_internal(columns: &[u16], bits: &[u8], n: usize, m: usize) -> Vec<u8> {
    let h = STC_CONSTRAINT_HEIGHT;
    let mut syndrome = vec![0u8; m];

    for j in 0..n {
        if bits[j] & 1 == 1 {
            let col_mask = columns[j];
            let eq_start = j * m / n;

            for bit_pos in 0..h {
                if col_mask & (1 << bit_pos) != 0 {
                    let eq_idx = eq_start + bit_pos;
                    if eq_idx < m {
                        syndrome[eq_idx] ^= 1;
                    }
                }
            }
        }
    }

    syndrome
}

/// STC encode: embed payload bits into cover bits minimizing total cost.
///
/// Finds stego bits s.t. H*stego = payload (mod 2) with minimum Σcost[i]
/// for each flipped bit, where H is the STC matrix derived from seed.
///
/// Algorithm: Viterbi trellis (Filler, Judas, Fridrich 2011)
/// Exploits the banded structure of H for O(n × 2^h) complexity
/// instead of O(m²) Gaussian elimination.
///
/// Uses checkpoint-based backtracking for memory efficiency:
/// - Forward pass saves dp snapshots every CHUNK columns
/// - Backward pass reprocesses each chunk to reconstruct decisions
/// - Memory: O((n/CHUNK + CHUNK) × 2^h) ≈ a few MB
///
/// # Arguments
/// * `seed` - Seed for generating the STC matrix H
/// * `cover_bits` - Cover element bits (0 or 1), length n
/// * `payload_bits` - Payload bits to embed (0 or 1), length m (m < n)
/// * `costs` - Cost of flipping each cover bit (length n)
///
/// # Returns
/// Stego bits (same length as cover_bits) with H*stego = payload
pub fn stc_encode(
    seed: &[u8; 32],
    cover_bits: &[u8],
    payload_bits: &[u8],
    costs: &[f64],
) -> Result<Vec<u8>, StegoError> {
    let n = cover_bits.len();
    let m = payload_bits.len();

    if n == 0 || m == 0 {
        return Err(StegoError::InvalidParams("Empty input".into()));
    }
    if n > STC_MAX_COVER_LEN {
        return Err(StegoError::InvalidParams(format!(
            "Cover too large: {} > {}",
            n, STC_MAX_COVER_LEN
        )));
    }
    if m >= n {
        return Err(StegoError::CapacityExceeded {
            available: n,
            required: m,
        });
    }
    if costs.len() != n {
        return Err(StegoError::InvalidParams(format!(
            "Cost length {} != cover length {}",
            costs.len(),
            n
        )));
    }

    let h = STC_CONSTRAINT_HEIGHT;
    let num_states: usize = 1 << h;
    let state_mask: usize = num_states - 1;

    // Generate STC submatrix
    let columns = generate_stc_matrix(seed, n, m);

    // --- Viterbi forward pass with checkpoints ---
    // Adaptive chunk size for memory efficiency
    let chunk_size: usize = if n <= 100_000 {
        256
    } else if n <= 1_000_000 {
        1024
    } else {
        4096
    };
    let num_chunks = n.div_ceil(chunk_size);

    // Save dp at the START of each chunk (including position 0)
    let mut checkpoints: Vec<Vec<f64>> = Vec::with_capacity(num_chunks + 1);

    let mut dp = vec![f64::INFINITY; num_states];
    dp[0] = 0.0; // Initial state: zero partial syndrome
    checkpoints.push(dp.clone());

    for j in 0..n {
        let col_mask = columns[j] as usize;
        let eq_start = j * m / n;
        let eq_start_next = (j + 1) * m / n;
        let committed = eq_start_next - eq_start; // always 0 or 1 since m < n

        let mut dp_next = vec![f64::INFINITY; num_states];

        // state is both an index into dp[] and a trellis syndrome value used
        // in bitwise ops (XOR, shift, mask), so indexing by range is clearest.
        #[allow(clippy::needless_range_loop)]
        for state in 0..num_states {
            if dp[state].is_infinite() {
                continue;
            }

            for flip in 0u8..2 {
                let bit_val = (cover_bits[j] ^ flip) & 1;
                let updated = if bit_val == 1 {
                    state ^ col_mask
                } else {
                    state
                };

                // Check committed equations (0 or 1)
                let (ok, next_state) = if committed == 1 {
                    let eq_idx = eq_start;
                    if eq_idx < m && (updated & 1) != (payload_bits[eq_idx] as usize & 1) {
                        (false, 0)
                    } else {
                        (true, (updated >> 1) & state_mask)
                    }
                } else {
                    (true, updated & state_mask)
                };

                if ok {
                    let cost = dp[state] + if flip == 1 { costs[j] } else { 0.0 };
                    if cost < dp_next[next_state] {
                        dp_next[next_state] = cost;
                    }
                }
            }
        }

        dp = dp_next;

        // Save checkpoint at end of each chunk
        if (j + 1) % chunk_size == 0 {
            checkpoints.push(dp.clone());
        }
    }
    // Save final dp if chunk didn't end exactly at n
    if !n.is_multiple_of(chunk_size) {
        checkpoints.push(dp.clone());
    }

    // Find optimal end state
    // After processing all n columns, all m equations should be committed.
    // The final state should be 0 (no residual syndrome).
    if dp[0].is_infinite() {
        return Err(StegoError::StcEncodingFailed(
            "No valid encoding path found in trellis (try lower embedding rate)".into(),
        ));
    }

    // --- Backward pass: reconstruct flip decisions ---
    let mut stego = cover_bits.to_vec();
    let mut target_state: usize = 0;

    for chunk_idx in (0..num_chunks).rev() {
        let chunk_start = chunk_idx * chunk_size;
        let chunk_end = std::cmp::min(chunk_start + chunk_size, n);
        let chunk_len = chunk_end - chunk_start;

        // Recompute forward pass for this chunk from checkpoint
        let mut local_dp = checkpoints[chunk_idx].clone();

        // Backtracking info: (prev_state, flip) per (position_in_chunk, state)
        // Memory: chunk_len × num_states × 3 bytes ≈ 768 KB for chunk=256, states=1024
        let mut trace_prev: Vec<Vec<u16>> = vec![vec![0u16; num_states]; chunk_len];
        let mut trace_flip: Vec<Vec<bool>> = vec![vec![false; num_states]; chunk_len];

        for (idx, j) in (chunk_start..chunk_end).enumerate() {
            let col_mask = columns[j] as usize;
            let eq_start = j * m / n;
            let eq_start_next = (j + 1) * m / n;
            let committed = eq_start_next - eq_start;

            let mut dp_next = vec![f64::INFINITY; num_states];

            // state is both an index into local_dp[] and a trellis syndrome value
            // used in bitwise ops (XOR, shift, mask), so indexing by range is clearest.
            #[allow(clippy::needless_range_loop)]
            for state in 0..num_states {
                if local_dp[state].is_infinite() {
                    continue;
                }

                for flip in 0u8..2 {
                    let bit_val = (cover_bits[j] ^ flip) & 1;
                    let updated = if bit_val == 1 {
                        state ^ col_mask
                    } else {
                        state
                    };

                    let (ok, next_state) = if committed == 1 {
                        let eq_idx = eq_start;
                        if eq_idx < m && (updated & 1) != (payload_bits[eq_idx] as usize & 1) {
                            (false, 0)
                        } else {
                            (true, (updated >> 1) & state_mask)
                        }
                    } else {
                        (true, updated & state_mask)
                    };

                    if ok {
                        let cost = local_dp[state] + if flip == 1 { costs[j] } else { 0.0 };
                        if cost < dp_next[next_state] {
                            dp_next[next_state] = cost;
                            trace_prev[idx][next_state] = state as u16;
                            trace_flip[idx][next_state] = flip == 1;
                        }
                    }
                }
            }

            local_dp = dp_next;
        }

        // Backtrack through this chunk
        let mut state = target_state;
        for idx in (0..chunk_len).rev() {
            let flip = trace_flip[idx][state];
            let prev = trace_prev[idx][state] as usize;
            if flip {
                stego[chunk_start + idx] ^= 1;
            }
            state = prev;
        }
        target_state = state;
    }

    // Verify correctness
    let final_syn = compute_syndrome_internal(&columns, &stego, n, m);
    let mismatches: usize = (0..m).filter(|&i| final_syn[i] != payload_bits[i]).count();

    if mismatches > 0 {
        return Err(StegoError::StcEncodingFailed(format!(
            "STC encode verification failed: {} of {} syndrome bits mismatch",
            mismatches, m
        )));
    }

    Ok(stego)
}

/// STC decode: extract payload bits from stego bits.
///
/// Computes H * stego_bits (mod 2) using the same matrix H derived from seed.
///
/// # Arguments
/// * `seed` - Same seed used during encoding
/// * `stego_bits` - Stego bit stream (0 or 1), length n
/// * `payload_len` - Expected payload length in bits (m)
///
/// # Returns
/// Extracted payload bits (length m)
pub fn stc_decode(
    seed: &[u8; 32],
    stego_bits: &[u8],
    payload_len: usize,
) -> Result<Vec<u8>, StegoError> {
    let n = stego_bits.len();
    if n == 0 || payload_len == 0 {
        return Err(StegoError::InvalidParams("Empty input".into()));
    }
    if payload_len > n {
        return Err(StegoError::StcDecodingFailed(format!(
            "Payload length {} > stego length {}",
            payload_len, n
        )));
    }

    let columns = generate_stc_matrix(seed, n, payload_len);

    // Compute syndrome: H * stego (mod 2)
    let h = STC_CONSTRAINT_HEIGHT;
    let mut syndrome = vec![0u8; payload_len];

    for j in 0..n {
        if stego_bits[j] & 1 == 1 {
            let col_mask = columns[j];
            let eq_start = j * payload_len / n;

            for bit_pos in 0..h {
                if col_mask & (1 << bit_pos) != 0 {
                    let eq_idx = eq_start + bit_pos;
                    if eq_idx < payload_len {
                        syndrome[eq_idx] ^= 1;
                    }
                }
            }
        }
    }

    Ok(syndrome)
}

/// Compute the number of bit changes (Hamming weight of diff)
/// between cover and stego. Useful for measuring embedding efficiency.
pub fn count_changes(cover_bits: &[u8], stego_bits: &[u8]) -> usize {
    assert_eq!(cover_bits.len(), stego_bits.len());
    cover_bits
        .iter()
        .zip(stego_bits.iter())
        .filter(|(&a, &b)| (a & 1) != (b & 1))
        .count()
}

// =============================================================================
// Timing Channel Encoding/Decoding
// =============================================================================

/// Encode bits into GIF frame delay values.
///
/// Each frame delay is an integer in centiseconds. We encode bits
/// by jittering the delay around a base value using the seed:
///
/// For each bit group:
///   seed_byte = PRNG(seed, frame_idx)
///   delay = base_delay + offset_map[bit_value]
///
/// With 4 possible delay offsets (0, 1, 2, 3 cs), we get 2 bits per frame.
/// With modulation to avoid patterns, this is undetectable by visual inspection.
///
/// # Arguments
/// * `seed` - 32-byte seed for this channel
/// * `base_delay` - Base delay in centiseconds (e.g., 10 = 100ms)
/// * `payload_bits` - Bits to encode (length = num_frames * bits_per_frame)
/// * `bits_per_frame` - Bits encoded per frame (1-4, default 2)
///
/// # Returns
/// Vector of frame delays in centiseconds
pub fn timing_encode(
    seed: &[u8; 32],
    base_delay: u16,
    payload_bits: &[u8],
    bits_per_frame: u8,
) -> Result<Vec<u16>, StegoError> {
    if bits_per_frame == 0 || bits_per_frame > 4 {
        return Err(StegoError::InvalidParams(format!(
            "bits_per_frame must be 1-4, got {}",
            bits_per_frame
        )));
    }

    let bpf = bits_per_frame as usize;
    let num_frames = payload_bits.len().div_ceil(bpf);
    let mut rng = SeededPrng::new(seed);
    let mut delays = Vec::with_capacity(num_frames);

    let max_offset = (1u16 << bits_per_frame) - 1; // e.g., 3 for 2 bits

    for frame in 0..num_frames {
        // Collect bits for this frame
        let mut value = 0u8;
        for b in 0..bpf {
            let bit_idx = frame * bpf + b;
            if bit_idx < payload_bits.len() {
                value |= (payload_bits[bit_idx] & 1) << b;
            }
        }

        // Pseudorandom base jitter (adds unpredictability)
        let jitter = rng.next_bounded(2) as u16; // 0 or 1 cs random base

        // Delay = base + jitter + encoded value.
        // Saturating: a large caller-supplied base_delay must not overflow
        // u16 (debug panic / release wrap) before the clamp below runs.
        let delay = base_delay
            .saturating_add(jitter)
            .saturating_add(value as u16);

        // Clamp to reasonable range
        let delay = delay.min(base_delay.saturating_add(max_offset).saturating_add(2));
        delays.push(delay);
    }

    Ok(delays)
}

/// Decode bits from GIF frame delay values.
///
/// # Arguments
/// * `seed` - Same seed used during encoding
/// * `base_delay` - Same base delay used during encoding
/// * `delays` - Frame delays in centiseconds
/// * `bits_per_frame` - Same bits_per_frame used during encoding
///
/// # Returns
/// Decoded payload bits
pub fn timing_decode(
    seed: &[u8; 32],
    base_delay: u16,
    delays: &[u16],
    bits_per_frame: u8,
) -> Result<Vec<u8>, StegoError> {
    if bits_per_frame == 0 || bits_per_frame > 4 {
        return Err(StegoError::InvalidParams(format!(
            "bits_per_frame must be 1-4, got {}",
            bits_per_frame
        )));
    }

    let bpf = bits_per_frame as usize;
    let mut rng = SeededPrng::new(seed);
    let mut bits = Vec::with_capacity(delays.len() * bpf);

    for &delay in delays {
        let jitter = rng.next_bounded(2) as u16;
        let raw = delay.saturating_sub(base_delay).saturating_sub(jitter);
        let value = raw.min((1 << bits_per_frame) - 1) as u8;

        for b in 0..bpf {
            bits.push((value >> b) & 1);
        }
    }

    Ok(bits)
}

// =============================================================================
// Palette Permutation Encoding/Decoding
// =============================================================================

/// Encode bits into palette ordering of near-duplicate/unused entries.
///
/// Given a set of palette indices that are "permutable" (near-duplicates
/// or unused entries), encode bits by choosing a specific permutation.
///
/// Uses Lehmer code: the permutation of n items encodes floor(log2(n!)) bits.
///
/// # Arguments
/// * `seed` - 32-byte seed for deterministic base ordering
/// * `permutable_indices` - Indices of palette entries that can be reordered
/// * `payload_bits` - Bits to encode
///
/// # Returns
/// New ordering of the permutable indices (same elements, different order)
pub fn palette_encode(
    seed: &[u8; 32],
    permutable_indices: &[u8],
    payload_bits: &[u8],
) -> Result<Vec<u8>, StegoError> {
    let n = permutable_indices.len();
    if n < 2 {
        return Err(StegoError::InvalidParams(
            "Need at least 2 permutable indices".into(),
        ));
    }

    // Maximum bits encodable: floor(log2(n!))
    let max_bits = factorial_bits(n);
    if max_bits == 0 {
        return Err(StegoError::CapacityExceeded {
            available: 0,
            required: payload_bits.len(),
        });
    }

    // Build a number from payload bits (up to max_bits)
    let use_bits = payload_bits.len().min(max_bits);
    let mut perm_number: u64 = 0;
    for (i, &bit) in payload_bits.iter().enumerate().take(use_bits) {
        if bit & 1 == 1 {
            perm_number |= 1u64 << i;
        }
    }

    // Convert perm_number to Lehmer code → permutation
    let mut items: Vec<u8> = permutable_indices.to_vec();

    // First, establish a deterministic base ordering using seed
    let mut rng = SeededPrng::new(seed);
    for i in (1..items.len()).rev() {
        let j = rng.next_bounded((i + 1) as u64) as usize;
        items.swap(i, j);
    }

    // Now apply the Lehmer-code permutation encoding
    let mut result = Vec::with_capacity(n);
    let mut remaining = items;
    let mut number = perm_number;

    for k in (1..=n).rev() {
        if remaining.is_empty() {
            break;
        }
        let idx = (number % k as u64) as usize;
        number /= k as u64;
        result.push(remaining.remove(idx));
    }

    Ok(result)
}

/// Decode bits from palette permutation order.
///
/// # Arguments
/// * `seed` - Same seed used during encoding
/// * `permutable_indices` - Original set of permutable indices (unordered)
/// * `observed_order` - Observed order of those indices in stego palette
///
/// # Returns
/// Decoded payload bits
pub fn palette_decode(
    seed: &[u8; 32],
    permutable_indices: &[u8],
    observed_order: &[u8],
) -> Result<Vec<u8>, StegoError> {
    let n = permutable_indices.len();
    if n < 2 || observed_order.len() != n {
        return Err(StegoError::InvalidParams("Mismatched index lengths".into()));
    }

    let max_bits = factorial_bits(n);
    if max_bits == 0 {
        return Ok(vec![]);
    }

    // Establish base ordering using seed (same as encode)
    let mut base_order: Vec<u8> = permutable_indices.to_vec();
    let mut rng = SeededPrng::new(seed);
    for i in (1..base_order.len()).rev() {
        let j = rng.next_bounded((i + 1) as u64) as usize;
        base_order.swap(i, j);
    }

    // Convert observed_order back to Lehmer code → number
    let mut remaining = base_order;
    let mut number: u64 = 0;
    let mut multiplier: u64 = 1;

    for &item in observed_order {
        let pos = remaining.iter().position(|&x| x == item);
        match pos {
            Some(idx) => {
                number += idx as u64 * multiplier;
                multiplier *= remaining.len() as u64;
                remaining.remove(idx);
            }
            None => {
                return Err(StegoError::StcDecodingFailed(
                    "Palette entry not found in base ordering".into(),
                ));
            }
        }
    }

    // Convert number to bits
    let mut bits = Vec::with_capacity(max_bits);
    for i in 0..max_bits {
        bits.push(((number >> i) & 1) as u8);
    }

    Ok(bits)
}

/// Calculate floor(log2(n!)) — max bits encodable in a permutation of n items.
fn factorial_bits(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    // log2(n!) = Σ log2(k) for k=2..n
    let mut log2_factorial: f64 = 0.0;
    for k in 2..=n {
        log2_factorial += (k as f64).log2();
    }
    log2_factorial.floor() as usize
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_frame_seed_uniqueness() {
        let key = [0x42u8; 32];

        // Different frames → different seeds
        let s0 = derive_frame_seed(&key, 0, CHANNEL_PRIMARY).unwrap();
        let s1 = derive_frame_seed(&key, 1, CHANNEL_PRIMARY).unwrap();
        assert_ne!(s0, s1);

        // Different channels → different seeds
        let sp = derive_frame_seed(&key, 0, CHANNEL_PRIMARY).unwrap();
        let ss = derive_frame_seed(&key, 0, CHANNEL_SECONDARY).unwrap();
        let st = derive_frame_seed(&key, 0, CHANNEL_TERTIARY).unwrap();
        assert_ne!(sp, ss);
        assert_ne!(sp, st);
        assert_ne!(ss, st);
    }

    #[test]
    fn test_derive_frame_seed_deterministic() {
        let key = [0xABu8; 32];
        let s1 = derive_frame_seed(&key, 42, CHANNEL_SECONDARY).unwrap();
        let s2 = derive_frame_seed(&key, 42, CHANNEL_SECONDARY).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_derive_frame_seed_short_key() {
        let key = [0u8; 8];
        assert!(derive_frame_seed(&key, 0, CHANNEL_PRIMARY).is_err());
    }

    #[test]
    fn test_pixel_walk_permutation() {
        let seed = [0x11u8; 32];
        let walk = generate_pixel_walk(&seed, 100);

        // Correct length
        assert_eq!(walk.len(), 100);

        // Is a permutation (all elements present)
        let mut sorted = walk.clone();
        sorted.sort();
        let expected: Vec<u32> = (0..100).collect();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn test_pixel_walk_deterministic() {
        let seed = [0x22u8; 32];
        let w1 = generate_pixel_walk(&seed, 50);
        let w2 = generate_pixel_walk(&seed, 50);
        assert_eq!(w1, w2);
    }

    #[test]
    fn test_pixel_walk_different_seeds() {
        let s1 = [0x11u8; 32];
        let s2 = [0x22u8; 32];
        let w1 = generate_pixel_walk(&s1, 50);
        let w2 = generate_pixel_walk(&s2, 50);
        assert_ne!(w1, w2);
    }

    #[test]
    fn test_stc_roundtrip() {
        let seed = [0x33u8; 32];
        let n = 200; // cover bits
        let m = 50; // payload bits

        // Random cover
        let mut rng = SeededPrng::new(&[0x44u8; 32]);
        let cover: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 1) as u8).collect();
        let payload: Vec<u8> = (0..m).map(|_| (rng.next_u64() & 1) as u8).collect();
        let costs = vec![1.0f64; n];

        // Encode
        let stego = stc_encode(&seed, &cover, &payload, &costs).unwrap();
        assert_eq!(stego.len(), n);

        // Decode — MUST recover exact payload
        let recovered = stc_decode(&seed, &stego, m).unwrap();
        assert_eq!(recovered.len(), m);
        assert_eq!(
            recovered, payload,
            "STC decode must recover exact payload bits"
        );

        // Verify fewer changes than naive
        let changes = count_changes(&cover, &stego);
        // STC should make fewer changes than payload length
        assert!(
            changes <= m,
            "STC made {} changes for {} payload bits",
            changes,
            m
        );
    }

    #[test]
    fn test_stc_roundtrip_various_sizes() {
        // Test multiple payload/cover ratios
        for (n, m) in [(100, 20), (500, 100), (1000, 200), (200, 99)] {
            let seed = [0x55u8; 32];
            let mut rng = SeededPrng::new(&[(n & 0xFF) as u8; 32]);
            let cover: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 1) as u8).collect();
            let payload: Vec<u8> = (0..m).map(|_| (rng.next_u64() & 1) as u8).collect();
            let costs = vec![1.0f64; n];

            let stego = stc_encode(&seed, &cover, &payload, &costs).unwrap();
            let recovered = stc_decode(&seed, &stego, m).unwrap();
            assert_eq!(
                recovered, payload,
                "STC roundtrip failed for n={}, m={}",
                n, m
            );
        }
    }

    #[test]
    fn test_stc_all_zeros_payload() {
        let seed = [0x66u8; 32];
        let n = 100;
        let m = 25;
        let mut rng = SeededPrng::new(&[0x77u8; 32]);
        let cover: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 1) as u8).collect();
        let payload = vec![0u8; m];
        let costs = vec![1.0f64; n];

        let stego = stc_encode(&seed, &cover, &payload, &costs).unwrap();
        let recovered = stc_decode(&seed, &stego, m).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_stc_all_ones_payload() {
        let seed = [0x88u8; 32];
        let n = 100;
        let m = 25;
        let mut rng = SeededPrng::new(&[0x99u8; 32]);
        let cover: Vec<u8> = (0..n).map(|_| (rng.next_u64() & 1) as u8).collect();
        let payload = vec![1u8; m];
        let costs = vec![1.0f64; n];

        let stego = stc_encode(&seed, &cover, &payload, &costs).unwrap();
        let recovered = stc_decode(&seed, &stego, m).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_stc_empty_input() {
        let seed = [0u8; 32];
        assert!(stc_encode(&seed, &[], &[1], &[]).is_err());
        assert!(stc_encode(&seed, &[1], &[], &[1.0]).is_err());
    }

    #[test]
    fn test_timing_roundtrip() {
        let seed = [0x55u8; 32];
        let base_delay = 10u16;
        let bits_per_frame = 2u8;
        let payload: Vec<u8> = vec![1, 0, 1, 1, 0, 0, 1, 0]; // 8 bits = 4 frames

        let delays = timing_encode(&seed, base_delay, &payload, bits_per_frame).unwrap();
        assert_eq!(delays.len(), 4);

        // All delays should be near base
        for &d in &delays {
            assert!(d >= base_delay);
            assert!(d <= base_delay + 5); // base + max_offset + jitter
        }

        let recovered = timing_decode(&seed, base_delay, &delays, bits_per_frame).unwrap();
        assert_eq!(recovered.len(), payload.len());
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_palette_roundtrip() {
        let seed = [0x66u8; 32];
        let indices: Vec<u8> = vec![200, 201, 202, 203, 204, 205, 206, 207];
        let payload: Vec<u8> = vec![1, 0, 1, 1, 0]; // 5 bits (8! = 40320, fits 15 bits)

        let encoded = palette_encode(&seed, &indices, &payload).unwrap();
        assert_eq!(encoded.len(), indices.len());

        let decoded = palette_decode(&seed, &indices, &encoded).unwrap();
        // Check first 5 bits match
        assert_eq!(&decoded[..5], &payload[..]);
    }

    #[test]
    fn test_factorial_bits() {
        assert_eq!(factorial_bits(0), 0);
        assert_eq!(factorial_bits(1), 0);
        assert_eq!(factorial_bits(2), 1); // 2! = 2, log2(2) = 1
        assert_eq!(factorial_bits(3), 2); // 3! = 6, log2(6) = 2.58 → 2
        assert_eq!(factorial_bits(4), 4); // 4! = 24, log2(24) = 4.58 → 4
        assert_eq!(factorial_bits(8), 15); // 8! = 40320, log2 ≈ 15.3
    }

    #[test]
    fn test_adaptive_costs() {
        let seed = [0x77u8; 32];
        let cover = vec![0u8; 100];
        // Flat region (low variance)
        let flat_pixels = vec![128u8; 100];
        let mut flat_costs = vec![0.0f64; 100];
        compute_adaptive_costs(&seed, &cover, &flat_pixels, &mut flat_costs);

        // Textured region (high variance)
        let textured_pixels: Vec<u8> = (0..100).map(|i| ((i * 37) % 256) as u8).collect();
        let mut texture_costs = vec![0.0f64; 100];
        compute_adaptive_costs(&seed, &cover, &textured_pixels, &mut texture_costs);

        // Flat costs should be higher on average
        let flat_avg: f64 = flat_costs.iter().sum::<f64>() / flat_costs.len() as f64;
        let text_avg: f64 = texture_costs.iter().sum::<f64>() / texture_costs.len() as f64;
        assert!(
            flat_avg > text_avg,
            "Flat avg {} should > texture avg {}",
            flat_avg,
            text_avg
        );
    }
}
