/**
 * catBlinkV2.test.ts — proves the mobile Cat Blink v2 FRAME-layer decoder is
 * bit-true against the SAME committed vector the JS and Python codecs use.
 *
 * The vector (tests/data/cat_blink_v2_vector.json) is produced by the JS emitter
 * (web_demo/static/cat-blink-v2.js) and consumed by cat_blink_v2.py; reading the
 * real file here keeps the JS-emitter ↔ mobile-decoder round-trip proven, not
 * just self-consistent. Each entry in `frames` is one WHITENED frame bitstring.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  decodeFrame,
  scanFrames,
  crc16,
  bytesToBits,
  bitsToBytes,
  dewhitenBits,
  whitenBits,
  CatBlinkV2Collector,
  collectTarget,
  SYNC,
  VERSION,
} from '../src/services/catBlinkV2';

// ── Load the committed cross-language vector ────────────────────────────────

interface Vector {
  payload_bytes: number[];
  kBlocks: number;
  blockSize: number;
  originalLength: number;
  frames: string[];
}

const VECTOR_PATH = path.resolve(__dirname, '../../tests/data/cat_blink_v2_vector.json');
const vector = JSON.parse(fs.readFileSync(VECTOR_PATH, 'utf8')) as Vector;

// ── Frame-layer primitives ──────────────────────────────────────────────────

describe('catBlinkV2 primitives', () => {
  it('crc16 is CRC-16/CCITT-FALSE (known test vector "123456789" = 0x29B1)', () => {
    const bytes = new Uint8Array([...'123456789'].map((c) => c.charCodeAt(0)));
    expect(crc16(bytes)).toBe(0x29b1);
  });

  it('bytesToBits/bitsToBytes round-trip MSB-first', () => {
    const bytes = new Uint8Array([0xb1, 0x17, 0x5e, 0x02, 0x00, 0xff]);
    const bits = bytesToBits(bytes);
    expect(bits).toBe('101100010001011101011110000000100000000011111111');
    expect([...bitsToBytes(bits)]).toEqual([...bytes]);
  });

  it('dewhitenBits is self-inverse (matches catWhitening)', () => {
    const raw = bytesToBits(new Uint8Array([0x00, 0x00, 0x00, 0xff, 0xa5]));
    expect(dewhitenBits(whitenBits(raw))).toBe(raw);
  });
});

// ── decodeFrame against every committed frame ───────────────────────────────

describe('catBlinkV2 decodeFrame (committed vector)', () => {
  it('decodes every frame with the vector headers and a well-formed droplet', () => {
    expect(vector.frames.length).toBeGreaterThan(0);
    for (const wf of vector.frames) {
      const f = decodeFrame(wf);
      expect(f).not.toBeNull();
      expect(f!.version).toBe(VERSION);
      expect(f!.kBlocks).toBe(vector.kBlocks);
      expect(f!.blockSize).toBe(vector.blockSize);
      expect(f!.originalLength).toBe(vector.originalLength);
      // droplet_len = 4(seed)+2(count)+count*2(indices)+blockSize(data)
      expect(f!.dropletBytes.length).toBe(4 + 2 + f!.count * 2 + vector.blockSize);
      // seed = first 4 bytes of dropletBytes, big-endian
      const db = f!.dropletBytes;
      const expectedSeed =
        (db[0]! * 0x1000000 + (db[1]! << 16) + (db[2]! << 8) + db[3]!) >>> 0;
      expect(f!.seed).toBe(expectedSeed);
    }
  });

  it('recovers all kBlocks distinct source-block indices across the frames', () => {
    // The systematic droplets (degree-1) cover every source block; gathering the
    // frames must reference all k blocks at least once.
    const covered = new Set<number>();
    for (const wf of vector.frames) {
      const f = decodeFrame(wf);
      if (!f) continue;
      const db = f.dropletBytes;
      const count = (db[4]! << 8) | db[5]!;
      for (let i = 0; i < count; i++) {
        covered.add((db[6 + i * 2]! << 8) | db[7 + i * 2]!);
      }
    }
    for (let k = 0; k < vector.kBlocks; k++) {
      expect(covered.has(k)).toBe(true);
    }
  });

  it('rejects a frame whose CRC is corrupted (fail-closed)', () => {
    const wf = vector.frames[0]!;
    // Flip the last (whitened) bit → the recovered CRC no longer matches.
    const flipped = wf.slice(0, -1) + (wf[wf.length - 1] === '1' ? '0' : '1');
    expect(decodeFrame(flipped)).toBeNull();
  });

  it('rejects a too-short bitstring and a wrong-SYNC frame', () => {
    expect(decodeFrame('0101')).toBeNull();
    // Build a header-length whitened frame whose SYNC is wrong.
    const bogus = new Uint8Array(20); // all zero → SYNC mismatch
    expect(decodeFrame(whitenBits(bytesToBits(bogus)))).toBeNull();
  });
});

// ── scanFrames over a free-running loop (concatenation) ─────────────────────

describe('catBlinkV2 scanFrames', () => {
  /** Build a free-running loop: guard garbage + concatenated whitened frames. */
  function buildLoop(frames: string[], guard = '0110'): string {
    return guard + frames.join(guard) + guard;
  }

  it('locks onto SYNC and recovers every frame from a concatenated stream', () => {
    const stream = vector.frames.join(''); // back-to-back, no guard
    const found = scanFrames(stream);
    expect(found.length).toBe(vector.frames.length);
    for (const sf of found) {
      expect(sf.kBlocks).toBe(vector.kBlocks);
      expect(sf.blockSize).toBe(vector.blockSize);
    }
    // The recovered whitened slices must equal the emitted frames.
    expect(found.map((f) => f.whitenedFrame)).toEqual(vector.frames);
  });

  it('tolerates leading/trailing garbage and inter-frame guard bits', () => {
    const stream = buildLoop(vector.frames);
    const found = scanFrames(stream);
    // Every unique seed present in the vector must be recovered.
    const seeds = new Set(found.map((f) => f.seed));
    const expected = new Set(vector.frames.map((wf) => decodeFrame(wf)!.seed));
    expect(seeds).toEqual(expected);
  });
});

// ── Collector: dedupe + completion (drop/shuffle case) ──────────────────────

describe('CatBlinkV2Collector', () => {
  it('collectTarget mirrors the QR path: ceil(1.5 × k)', () => {
    expect(collectTarget(3)).toBe(5); // ceil(4.5)
    expect(collectTarget(1)).toBe(2);
    expect(collectTarget(10)).toBe(15);
  });

  it('collects unique droplets and completes at ceil(1.5×k)', () => {
    const c = new CatBlinkV2Collector();
    // Feed one frame at a time (as the growing sample buffer would).
    for (const wf of vector.frames) c.addStream(wf);
    const r = c.result();
    expect(r.kBlocks).toBe(vector.kBlocks);
    expect(r.blockSize).toBe(vector.blockSize);
    expect(r.originalLength).toBe(vector.originalLength);
    expect(r.target).toBe(collectTarget(vector.kBlocks));
    // The vector has >= target unique droplets, so collection completes.
    expect(r.droplets.length).toBeGreaterThanOrEqual(r.target!);
    expect(r.complete).toBe(true);
  });

  it('dedupes: re-feeding the same stream adds nothing', () => {
    const c = new CatBlinkV2Collector();
    const stream = vector.frames.join('');
    const first = c.addStream(stream);
    expect(first).toBe(vector.frames.length);
    expect(c.addStream(stream)).toBe(0); // idempotent
    expect(c.size).toBe(vector.frames.length);
  });

  it('drop/shuffle case: recovers all kBlocks from a lossy, reordered subset', () => {
    // Shuffle deterministically and drop a third of the frames.
    const shuffled = [...vector.frames]
      .map((wf, i) => ({ wf, key: (i * 7 + 3) % vector.frames.length }))
      .sort((a, b) => a.key - b.key)
      .map((x) => x.wf);
    const kept = shuffled.filter((_, i) => i % 3 !== 0); // drop every 3rd

    const c = new CatBlinkV2Collector();
    for (const wf of kept) c.addStream(wf);
    const r = c.result();

    expect(r.kBlocks).toBe(vector.kBlocks);
    // Every surviving droplet has a distinct seed → no false dedup.
    const distinct = new Set(kept.map((wf) => decodeFrame(wf)!.seed));
    expect(r.droplets.length).toBe(distinct.size);
    // The kept subset still covers all k source blocks (systematic droplets).
    const covered = new Set<number>();
    for (const d of r.droplets) {
      const db = d.dropletBytes;
      const count = (db[4]! << 8) | db[5]!;
      for (let i = 0; i < count; i++) {
        covered.add((db[6 + i * 2]! << 8) | db[7 + i * 2]!);
      }
    }
    for (let k = 0; k < vector.kBlocks; k++) expect(covered.has(k)).toBe(true);
  });

  it('reset clears all collected state', () => {
    const c = new CatBlinkV2Collector();
    c.addStream(vector.frames[0]!);
    expect(c.size).toBe(1);
    c.reset();
    expect(c.size).toBe(0);
    expect(c.result().kBlocks).toBeNull();
  });
});

// Sanity: the SYNC constant is exactly the documented marker.
it('SYNC marker is 0xB1 0x17 0x5E', () => {
  expect([...SYNC]).toEqual([0xb1, 0x17, 0x5e]);
});
