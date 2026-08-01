/**
 * catBlinkV2.ts — Cat Blink v2 FRAME-layer decoder (pure logic).
 *
 * TypeScript port of the *frame* layer of web_demo/static/cat-blink-v2.js and
 * meow_decoder/cat_blink_v2.py, matching docs/CAT_BLINK_V2.md bit-for-bit. This
 * module deliberately ports ONLY the byte/bit/frame/CRC layer — it does NOT
 * reconstruct the fountain payload. The phone is an untrusted optical sensor
 * (see src/types/capture.ts): it collects unique droplet frames and hands them
 * to the desktop decoder, exactly like the QR fountain path.
 *
 * Wire format (per droplet frame):
 *   SYNC(3=0xB1,0x17,0x5E) | version(1=0x02) | k_blocks(2 BE) | block_size(2 BE)
 *     | original_length(4 BE) | droplet(var) | crc16(2 BE, CCITT-FALSE)
 *
 * droplet layout (shared with the QR path):
 *   seed(4 BE) | count(2 BE) | indices(count*2 BE) | data(block_size)
 *   droplet_len = 4 + 2 + count*2 + block_size
 *
 * Bits are serialized MSB-first (bit 7 of byte 0 first) and the whole stream is
 * XORed with the MEOW-LCG keystream (see catWhitening.ts) — self-inverse, so the
 * receiver runs the same transform to recover the frame bytes.
 */

import { whiten as whitenBits, dewhiten as dewhitenBits } from './catWhitening';

// ── Wire constants (mirror the JS/Python reference) ─────────────────────────

/** Frame-boundary marker: "BLInk SEed". */
export const SYNC: readonly number[] = [0xb1, 0x17, 0x5e];
/** Wire version for this spec (0x01 = legacy blink, never emitted by v2). */
export const VERSION = 0x02;
/** sync(3) + version(1) + k_blocks(2) + block_size(2) + original_length(4). */
export const HEADER_LEN = SYNC.length + 1 + 2 + 2 + 4; // 12
/** CRC-16 trailer length in bytes. */
export const CRC_LEN = 2;
/** Fixed droplet prefix before the variable indices/data: seed(4) + count(2). */
const DROPLET_PREFIX = 6;

// Re-export the whitening helpers under the reference module's names so callers
// (and tests) read against the v2 vocabulary. These ARE catWhitening's whiten/
// dewhiten — the LCG is identical (MEOW seed 0x4D454F57, Math.imul low-32-bit
// product, advance-before-mask). catWhitening.test.ts guards that bit-true match.
export { whitenBits, dewhitenBits };

// ── CRC-16/CCITT-FALSE ──────────────────────────────────────────────────────

/**
 * CRC-16/CCITT-FALSE over bytes[start, end): poly 0x1021, init 0xFFFF, no
 * reflection, no final XOR. Bit-identical to the JS/Python crc16.
 */
export function crc16(bytes: Uint8Array, start = 0, end = bytes.length): number {
  let crc = 0xffff;
  for (let i = start; i < end; i++) {
    crc ^= (bytes[i] as number) << 8;
    for (let b = 0; b < 8; b++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc & 0xffff;
}

// ── byte ⇄ MSB-first bit helpers ────────────────────────────────────────────

/** Serialize bytes to an MSB-first bitstring (bit 7 of byte 0 first). */
export function bytesToBits(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += (bytes[i] as number).toString(2).padStart(8, '0');
  }
  return s;
}

/** Pack an MSB-first bitstring back to bytes (trailing partial byte dropped). */
export function bitsToBytes(bitStr: string): Uint8Array {
  const n = bitStr.length >> 3;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = parseInt(bitStr.substr(i * 8, 8), 2);
  }
  return out;
}

// ── Frame parse ─────────────────────────────────────────────────────────────

/** A parsed, CRC-validated droplet frame. */
export interface DecodedFrame {
  version: number;
  kBlocks: number;
  blockSize: number;
  originalLength: number;
  /** Packed droplet bytes (seed|count|indices|data) for the desktop decoder. */
  dropletBytes: Uint8Array;
  /** Droplet degree (index count). */
  count: number;
  /** Droplet seed = first 4 bytes of dropletBytes, big-endian. Dedupe key. */
  seed: number;
}

/** Read a big-endian u16 at offset. */
function u16(bytes: Uint8Array, o: number): number {
  return ((bytes[o] as number) << 8) | (bytes[o + 1] as number);
}
/** Read a big-endian u32 at offset. */
function u32(bytes: Uint8Array, o: number): number {
  return (
    ((bytes[o] as number) * 0x1000000 +
      ((bytes[o + 1] as number) << 16) +
      ((bytes[o + 2] as number) << 8) +
      (bytes[o + 3] as number)) >>>
    0
  );
}

/**
 * Parse a single WHITENED frame bitstring back to its droplet + fountain params.
 * Returns null if SYNC/version/CRC fail. Length-agnostic: reads exactly the
 * droplet the header describes, ignoring any trailing garbage bits.
 *
 * Bit-for-bit port of decodeFrame() in cat-blink-v2.js / cat_blink_v2.py.
 */
export function decodeFrame(whitenedBits: string): DecodedFrame | null {
  if (whitenedBits.length < (HEADER_LEN + CRC_LEN) * 8) return null;
  const bytes = bitsToBytes(dewhitenBits(whitenedBits));
  if (bytes[0] !== SYNC[0] || bytes[1] !== SYNC[1] || bytes[2] !== SYNC[2]) return null;

  let o = SYNC.length;
  const version = bytes[o] as number;
  o += 1;
  if (version !== VERSION) return null;
  const kBlocks = u16(bytes, o);
  o += 2;
  const blockSize = u16(bytes, o);
  o += 2;
  const originalLength = u32(bytes, o);
  o += 4;

  const dropStart = o;
  if (bytes.length < dropStart + DROPLET_PREFIX) return null;
  const count = u16(bytes, dropStart + 4);
  const dropLen = 4 + 2 + count * 2 + blockSize;
  const crcStart = dropStart + dropLen;
  if (bytes.length < crcStart + CRC_LEN) return null;

  const got = u16(bytes, crcStart);
  const want = crc16(bytes, SYNC.length, crcStart);
  if (got !== want) return null;

  const dropletBytes = bytes.slice(dropStart, dropStart + dropLen);
  const seed = u32(dropletBytes, 0);
  return { version, kBlocks, blockSize, originalLength, dropletBytes, count, seed };
}

// ── Frame scan over a free-running bit stream ───────────────────────────────

/** A frame located inside a scanned bit stream. */
export interface ScannedFrame extends DecodedFrame {
  /** Bit offset of the frame's SYNC within the input (de-whitened) stream. */
  bitOffset: number;
  /** Total frame length in bits (header + droplet + CRC). */
  bitLength: number;
  /** The exact WHITENED slice that decodes this frame (what desktop re-runs). */
  whitenedFrame: string;
}

/**
 * Slide over a WHITENED bit stream, lock onto SYNC, and yield every valid frame.
 *
 * IMPORTANT — per-frame whitening: docs/CAT_BLINK_V2.md specifies that the
 * keystream is reseeded from a FRESH MEOW seed at the start of every frame, so a
 * lost frame never desyncs the whitening of later frames. A free-running blink
 * loop is therefore `whiten(frame0) || whiten(frame1) || …` where each `whiten`
 * restarts the LCG. We CANNOT de-whiten the whole stream with one continuous
 * keystream; instead the scanner tries each candidate BIT offset, de-whitens a
 * header-sized window starting there from a fresh seed (that is exactly what
 * {@link decodeFrame} does on a whitened slice), checks for SYNC, learns the
 * exact frame length, then de-whitens + CRC-validates the full frame.
 *
 * Tolerant to leading/trailing garbage and inter-frame guard bits: on a miss the
 * scan advances one bit; on a good frame it jumps past it. The recovered
 * `whitenedFrame` slice is the canonical thing to hand to the desktop decoder —
 * feeding it back through decodeFrame()/cat_blink_v2.decode() reproduces the
 * droplet exactly.
 */
export function scanFrames(whitenedStream: string): ScannedFrame[] {
  const frames: ScannedFrame[] = [];
  const headerBits = HEADER_LEN * 8;
  const minBits = (HEADER_LEN + CRC_LEN) * 8;
  const totalBits = whitenedStream.length;

  let bit = 0;
  while (bit + minBits <= totalBits) {
    // De-whiten just enough (header + droplet prefix) from a fresh seed at this
    // offset to read the header and learn the exact frame length.
    const prefixBits = whitenedStream.substr(bit, headerBits + DROPLET_PREFIX * 8);
    const prefixBytes = bitsToBytes(dewhitenBits(prefixBits));
    if (
      prefixBytes.length < HEADER_LEN + DROPLET_PREFIX ||
      prefixBytes[0] !== SYNC[0] ||
      prefixBytes[1] !== SYNC[1] ||
      prefixBytes[2] !== SYNC[2] ||
      prefixBytes[SYNC.length] !== VERSION
    ) {
      bit += 1;
      continue;
    }
    const blockSize = u16(prefixBytes, SYNC.length + 1 + 2);
    const count = u16(prefixBytes, HEADER_LEN + 4);
    const dropLen = 4 + 2 + count * 2 + blockSize;
    const frameBits = (HEADER_LEN + dropLen + CRC_LEN) * 8;
    if (bit + frameBits > totalBits) {
      bit += 1;
      continue;
    }
    // De-whiten + CRC-validate the exact frame slice.
    const whitenedFrame = whitenedStream.substr(bit, frameBits);
    const parsed = decodeFrame(whitenedFrame);
    if (parsed) {
      frames.push({ ...parsed, bitOffset: bit, bitLength: frameBits, whitenedFrame });
      bit += frameBits; // jump past the accepted frame
      continue;
    }
    bit += 1;
  }
  return frames;
}

// ── Droplet collection (phone = collecting receiver) ─────────────────────────

/**
 * QR-path parity: the phone does NOT reconstruct the fountain on-device. It
 * collects UNIQUE droplet frames — keyed by the droplet seed (first 4 bytes of
 * dropletBytes, big-endian) — until it has enough for the desktop decoder to
 * reconstruct, then reports complete. Completion target mirrors the QR path:
 * ceil(1.5 × k_blocks) unique droplets (docs/CAT_BLINK_V2.md §Completion).
 */
export const COLLECT_REDUNDANCY = 1.5;

/** Unique-droplet target for a k-block message, matching the QR collecting path. */
export function collectTarget(kBlocks: number): number {
  return Math.ceil(COLLECT_REDUNDANCY * kBlocks);
}

/** A collected, deduplicated droplet frame plus its fountain parameters. */
export interface CollectedDroplet {
  seed: number;
  kBlocks: number;
  blockSize: number;
  originalLength: number;
  dropletBytes: Uint8Array;
  /** The whitened frame bitstring — the canonical desktop-decodable form. */
  whitenedFrame: string;
}

export interface CatBlinkV2CollectResult {
  /** Distinct droplets gathered so far (by seed). */
  droplets: CollectedDroplet[];
  /** Fountain source-block count (from the first good frame), or null. */
  kBlocks: number | null;
  /** Fountain block size, or null until a frame is seen. */
  blockSize: number | null;
  /** Exact payload length before zero-padding, or null until a frame is seen. */
  originalLength: number | null;
  /** ceil(1.5 × kBlocks) target, or null until kBlocks is known. */
  target: number | null;
  /** True once `droplets.length >= target`. */
  complete: boolean;
}

/**
 * Stateful collector: feed it de-whitening-free WHITENED bit streams (whatever
 * the sampler recovered this tick); it scans them for frames, dedupes by seed,
 * and reports progress/completion. Idempotent under re-feeding the same stream —
 * a droplet already held (same seed) is ignored, so repeatedly decoding the
 * growing sample buffer never double-counts.
 */
export class CatBlinkV2Collector {
  private readonly bySeed = new Map<number, CollectedDroplet>();
  private kBlocks: number | null = null;
  private blockSize: number | null = null;
  private originalLength: number | null = null;

  /**
   * Scan a whitened bit stream and absorb any new unique droplets.
   * @returns the number of NEW droplets added by this call.
   */
  addStream(whitenedStream: string): number {
    let added = 0;
    for (const f of scanFrames(whitenedStream)) {
      if (this.bySeed.has(f.seed)) continue;
      // Lock fountain params to the first good frame (all frames of one message
      // agree; a frame that disagrees is from a different/garbled transmission).
      if (this.kBlocks === null) {
        this.kBlocks = f.kBlocks;
        this.blockSize = f.blockSize;
        this.originalLength = f.originalLength;
      } else if (
        f.kBlocks !== this.kBlocks ||
        f.blockSize !== this.blockSize ||
        f.originalLength !== this.originalLength
      ) {
        continue; // param mismatch — not part of this message
      }
      this.bySeed.set(f.seed, {
        seed: f.seed,
        kBlocks: f.kBlocks,
        blockSize: f.blockSize,
        originalLength: f.originalLength,
        dropletBytes: f.dropletBytes,
        whitenedFrame: f.whitenedFrame,
      });
      added += 1;
    }
    return added;
  }

  /** Current progress snapshot. */
  result(): CatBlinkV2CollectResult {
    const droplets = [...this.bySeed.values()];
    const target = this.kBlocks !== null ? collectTarget(this.kBlocks) : null;
    return {
      droplets,
      kBlocks: this.kBlocks,
      blockSize: this.blockSize,
      originalLength: this.originalLength,
      target,
      complete: target !== null && droplets.length >= target,
    };
  }

  /** Distinct droplets held so far. */
  get size(): number {
    return this.bySeed.size;
  }

  /** Drop all collected state for a fresh capture. */
  reset(): void {
    this.bySeed.clear();
    this.kBlocks = null;
    this.blockSize = null;
    this.originalLength = null;
  }
}
