/**
 * webDemoIntegration.test.ts
 *
 * Integration tests that exercise the full mobile pipeline against every QR
 * format produced by the web demo (wasm_browser_example_FULL.html).
 *
 * Each section:
 *  1. Builds a structurally accurate payload matching the web demo's binary
 *     format (same version bytes, field layout, endianness).
 *  2. Verifies the parser (isMeowQRPayload / parseQRPayload) accepts it.
 *  3. Runs the frame through FrameCollector.add().
 *  4. Calls buildQRExportChunks() on a CaptureResponse and verifies the
 *     exported JSON structure is valid.
 *
 * SECURITY: No actual encryption / decryption is performed here.
 * All "ciphertexts" are placeholder bytes.  The mobile app is an optical
 * sensor — it never decrypts.
 *
 * Web-demo format reference:                              (version byte)
 *   MEOW:   v3  = 0x03 + memKib(4LE) + iter(1) + salt(16) + nonce(12) + ct
 *   MEOW:   v4  = 0x04 + memKib(4LE) + iter(1) + isFile(1) + fnLen(1)
 *                      + filename + salt(16) + nonce(12) + ct
 *   FS:         = opaque WASM output bytes
 *   QUANTUM:    = 0xFF + memKib(4LE) + iter(1) + lenA(4LE) + lenB(4LE)
 *                      + saltA(16) + nonceA(12) + saltB(16) + nonceB(12) + interleaved
 *   HYBRID-PQ:  = opaque WASM hybrid PQ bytes
 *   DURESS:     = 0x11 + memKib(4LE) + iter(1) + salt(16) + nonce(12)
 *                      + duressTag(32) + decoyLen(2BE) + decoyBytes + ct
 *   FOUNTAIN:k:bs:len:<b64 droplet>
 *   MEOW-N/total:<b64>   — legacy chunked
 *   DURESS-N/total:<b64> — legacy chunked duress (large payloads)
 *   {"index":N,"data":"<b64>"}  — JSON bridge / CLI
 */

import {
  parseQRPayload,
  isMeowQRPayload,
  parseFountainPayload,
  parseSingleFramePayload,
  parseLegacyChunkedPayload,
  parseJsonPayload,
} from '../src/services/qrDecoder';
import { FrameCollector } from '../src/services/frameCollector';
import { buildQRExportChunks } from '../src/services/jsonExporter';
import type { CapturedFrame, CaptureResponse } from '../src/types/capture';

// ── Binary helpers ────────────────────────────────────────────────────────────

/** Writes n into a 4-byte little-endian array */
function uint32LE(n: number): number[] {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}

/** Writes big-endian 16-bit */
function uint16BE(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}

/** Repeats a value count times */
function fill(value: number, count: number): number[] {
  return new Array(count).fill(value);
}

/** Node Buffer → base64 */
function toB64(bytes: number[]): string {
  return Buffer.from(new Uint8Array(bytes)).toString('base64');
}

// Fixed "Argon2id standard" params used by web demo at "standard" security level
const MEM_KIB = 131_072; // 128 MiB
const ITER = 8;

// ── Payload Builders ──────────────────────────────────────────────────────────

/**
 * MEOW: v3 — text message
 * Layout: 0x03 + memKib(4LE) + iterations(1) + salt(16) + nonce(12) + ciphertext
 */
function buildMeowV3Payload(): string {
  const salt = fill(0xaa, 16);
  const nonce = fill(0xbb, 12);
  const ciphertext = fill(0xcc, 48); // AES-256-GCM: plaintext + 16-byte auth tag
  const bytes = [0x03, ...uint32LE(MEM_KIB), ITER, ...salt, ...nonce, ...ciphertext];
  return 'MEOW:' + toB64(bytes);
}

/**
 * MEOW: v4 — file upload
 * Layout: 0x04 + memKib(4LE) + iterations(1) + isFile(1=0x01) + fnLen(1)
 *               + filename + salt(16) + nonce(12) + ciphertext
 */
function buildMeowV4FilePayload(filename = 'secret.pdf'): string {
  const fnBytes = [...Buffer.from(filename, 'utf8')];
  const salt = fill(0xaa, 16);
  const nonce = fill(0xbb, 12);
  const ciphertext = fill(0xcc, 64); // slightly longer for file mode
  const bytes = [
    0x04,
    ...uint32LE(MEM_KIB),
    ITER,
    0x01, // isFile flag
    fnBytes.length,
    ...fnBytes,
    ...salt,
    ...nonce,
    ...ciphertext,
  ];
  return 'MEOW:' + toB64(bytes);
}

/**
 * FS: — forward secrecy (opaque WASM output — X25519 ephemeral header + ciphertext)
 * Mobile only needs valid base64 after the prefix.
 */
function buildFsPayload(): string {
  // Simulate: ephemeral_pub(32) + salt(16) + nonce(12) + ciphertext(48)
  const bytes = [...fill(0x11, 32), ...fill(0x22, 16), ...fill(0x33, 12), ...fill(0x44, 48)];
  return 'FS:' + toB64(bytes);
}

/**
 * QUANTUM: — Schrödinger dual-secret
 * Layout: 0xFF + memKib(4LE) + iterations(1) + lenA(4LE) + lenB(4LE)
 *               + saltA(16) + nonceA(12) + saltB(16) + nonceB(12) + interleaved(ctA+ctB)
 */
function buildQuantumPayload(): string {
  const ctA = fill(0xaa, 40);
  const ctB = fill(0xbb, 40);
  // interleaved: ABABABAB...
  const interleaved = ctA.flatMap((a, i) => [a, ctB[i] ?? 0xbb]);
  const bytes = [
    0xff,
    ...uint32LE(MEM_KIB),
    ITER,
    ...uint32LE(ctA.length), // lenA
    ...uint32LE(ctB.length), // lenB
    ...fill(0xa0, 16), // saltA
    ...fill(0xa1, 12), // nonceA
    ...fill(0xb0, 16), // saltB
    ...fill(0xb1, 12), // nonceB
    ...interleaved,
  ];
  return 'QUANTUM:' + toB64(bytes);
}

/**
 * HYBRID-PQ: — post-quantum hybrid (opaque WASM encrypt_hybrid_pq output)
 * Mobile only needs valid base64.
 */
function buildHybridPqPayload(): string {
  // Simulate: ephemeral_x25519_pub(32) + pq_ciphertext(1568) + encrypted_payload(48)
  const bytes = [...fill(0x05, 32), ...fill(0x06, 1568), ...fill(0x07, 48)];
  return 'HYBRID-PQ:' + toB64(bytes);
}

/**
 * DURESS: — duress / panic-password mode
 * Layout: 0x11 + memKib(4LE) + iterations(1) + salt(16) + nonce(12)
 *               + duressTag(32) + decoyLen(2BE) + decoyBytes + ciphertext
 */
function buildDuressPayload(decoy = 'Nothing here.'): string {
  const decoyBytes = [...Buffer.from(decoy, 'utf8')];
  const salt = fill(0xaa, 16);
  const nonce = fill(0xbb, 12);
  const duressTag = fill(0xdd, 32); // HMAC-SHA256 duress tag
  const ciphertext = fill(0xcc, 48);
  const bytes = [
    0x11,
    ...uint32LE(MEM_KIB),
    ITER,
    ...salt,
    ...nonce,
    ...duressTag,
    ...uint16BE(decoyBytes.length),
    ...decoyBytes,
    ...ciphertext,
  ];
  return 'DURESS:' + toB64(bytes);
}

/**
 * FOUNTAIN: — fountain code droplet
 * Format: FOUNTAIN:<k>:<blockSize>:<originalLength>:<base64(droplet)>
 * Droplet binary: seed(4LE) + numIndices(4LE) + indices(4*n LE) + xor_data(blockSize)
 */
function buildFountainFrame(seed = 0, kBlocks = 5, blockSize = 600, originalLength = 2800): string {
  // Minimal fountain droplet structure (seed + degree-1 index + xor data)
  const dropletBytes = [
    ...uint32LE(seed), // seed
    ...uint32LE(1), // numIndices = 1 (degree-1 droplet, simplest form)
    ...uint32LE(seed % kBlocks), // index of source block
    ...fill(0xaf, blockSize), // xor data (fake but blockSize bytes)
  ];
  const dropletB64 = toB64(dropletBytes);
  return `FOUNTAIN:${kBlocks}:${blockSize}:${originalLength}:${dropletB64}`;
}

/**
 * MEOW-N/total: — legacy web demo chunked split
 * Format: MEOW-<N>/<total>:<base64_chunk>
 */
function buildLegacyChunk(n: number, total: number): string {
  const chunk = fill(0x77, 200 + n); // different lengths to test dedup
  return `MEOW-${n}/${total}:${toB64(chunk)}`;
}

/**
 * DURESS-N/total: — legacy multi-frame DURESS (large payloads in web demo)
 * Format: DURESS-<N>/<total>:<base64_chunk>
 * Produced when the DURESS: payload exceeds 2500 chars (web demo splits at 800-char chunks).
 * Handled by qrDecoder.ts via parseLegacyChunkedPayload() and by useQRScanner.ts
 * (isMeow check includes 'DURESS-' prefix).
 */
function buildDuressChunk(n: number, total: number): string {
  const chunk = fill(0xde, 200);
  return `DURESS-${n}/${total}:${toB64(chunk)}`;
}

/**
 * JSON bridge — CLI bridge mode
 * Format: {"index": N, "data": "<base64>", "session_id": "..."}
 */
function buildJsonFrame(index: number, sessionId?: string): string {
  const data = toB64(fill(0xab, 100 + index));
  const frame: Record<string, unknown> = { index, data };
  if (sessionId) frame['session_id'] = sessionId;
  return JSON.stringify(frame);
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/**
 * Wraps a QRFramePayload in a CapturedFrame for FrameCollector consumption.
 * This mirrors what useQRScanner.ts does (adds timestamp_ms).
 */
function toCapture(
  qr: string,
  timestamp = Date.now(),
  expectedSessionId?: string,
): CapturedFrame | null {
  const payload = parseQRPayload(qr, expectedSessionId);
  if (!payload) return null;
  return { index: payload.index, data: payload.data, timestamp_ms: timestamp };
}

/** Minimal CaptureResponse for export tests */
function makeCaptureResponse(frames: CapturedFrame[]): CaptureResponse {
  return {
    session_id: 'test-session-00000000',
    frames,
    capture_complete: true,
    frames_captured: frames.length,
    frames_missed: 0,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PARITY GUARD: useQRScanner worklet isMeow filter vs isMeowQRPayload()
//
// The worklet in useQRScanner.ts contains an inline prefix check (because
// worklets cannot call module functions from qrDecoder.ts).  This test suite
// documents every prefix the worklet accepts and asserts that isMeowQRPayload()
// agrees — catching any future drift between the two code paths.
// ─────────────────────────────────────────────────────────────────────────────
describe('useQRScanner worklet isMeow filter parity with isMeowQRPayload()', () => {
  /**
   * Mirrors the exact `isMeow` logic from useQRScanner.ts.
   * Update here whenever useQRScanner.ts is updated.
   */
  function workletIsMeow(qrData: string): boolean {
    return (
      qrData.startsWith('FOUNTAIN:') ||
      qrData.startsWith('MEOW:') ||
      qrData.startsWith('FS:') ||
      qrData.startsWith('QUANTUM:') ||
      qrData.startsWith('HYBRID-PQ:') ||
      qrData.startsWith('DURESS:') ||   // single-frame duress
      qrData.startsWith('DURESS-') ||   // legacy chunked large-duress (DURESS-N/total:)
      qrData.startsWith('MEOW-') ||     // legacy chunked large-MEOW (MEOW-N/total:)
      qrData.startsWith('{')            // JSON bridge / CLI session mode
    );
  }

  // Representative valid sample from every supported format
  const validSamples: [string, string][] = [
    ['FOUNTAIN:', buildFountainFrame(0, 5, 600, 2800)],
    ['MEOW: v3', buildMeowV3Payload()],
    ['MEOW: v4 file', buildMeowV4FilePayload()],
    ['FS:', buildFsPayload()],
    ['QUANTUM:', buildQuantumPayload()],
    ['HYBRID-PQ:', buildHybridPqPayload()],
    ['DURESS: single-frame', buildDuressPayload()],
    ['DURESS-N/total: chunk 1', buildDuressChunk(1, 3)],
    ['DURESS-N/total: chunk 2', buildDuressChunk(2, 3)],
    ['MEOW-N/total: chunk 1', buildLegacyChunk(1, 3)],
    ['MEOW-N/total: chunk 2', buildLegacyChunk(2, 3)],
    ['JSON bridge', buildJsonFrame(0, 'sess-abc')],
  ];

  for (const [label, qr] of validSamples) {
    it(`workletIsMeow and isMeowQRPayload agree on ${label}`, () => {
      expect(workletIsMeow(qr)).toBe(true);
      expect(isMeowQRPayload(qr)).toBe(true);
    });
  }

  // Non-meow QR codes: both filters must return false
  const nonMeow = [
    'https://example.com',
    'WIFI:S:Net;T:WPA;P:secret;;',
    'plain text',
    'DURESS', // no colon or dash
    'MEOW',   // no colon or dash
  ];

  for (const qr of nonMeow) {
    it(`both filters correctly reject "${qr.slice(0, 30)}"`, () => {
      expect(workletIsMeow(qr)).toBe(false);
      expect(isMeowQRPayload(qr)).toBe(false);
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 1: MEOW: (standard text, v3)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: MEOW: (standard AES-256-GCM v3)', () => {
  const qr = buildMeowV3Payload();

  it('is recognised by isMeowQRPayload()', () => {
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('parseQRPayload returns non-null with correct structure', () => {
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(typeof result?.index).toBe('number');
    expect(result?.data).toBe(qr);
  });

  it('parseSingleFramePayload matches the payload', () => {
    const r = parseSingleFramePayload(qr);
    expect(r).not.toBeNull();
    expect(r?.data).toBe(qr);
  });

  it('FrameCollector accepts and deduplicates MEOW: frame', () => {
    const collector = new FrameCollector();
    const frame = toCapture(qr);
    expect(frame).not.toBeNull();
    expect(collector.add(frame!)).toBe('accepted');
    // duplicate scan
    expect(collector.add(frame!)).toBe('duplicate');
    expect(collector.size).toBe(1);
  });

  it('buildQRExportChunks produces valid JSON with the frame', () => {
    const frame = toCapture(qr)!;
    const response = makeCaptureResponse([frame]);
    const chunks = buildQRExportChunks(response, 10_000);
    expect(chunks.length).toBeGreaterThanOrEqual(1);
    const parsed = JSON.parse(chunks[0]!);
    expect(parsed.meow_qr_chunk).toBe(true);
    expect(parsed.session_id).toBe('test-session-00000000');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 2: MEOW: (file upload, v4)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: MEOW: (file upload v4)', () => {
  const qr = buildMeowV4FilePayload('secret.pdf');

  it('is recognised by isMeowQRPayload()', () => {
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('parses correctly and different from v3 payload', () => {
    const v3 = parseQRPayload(buildMeowV3Payload());
    const v4 = parseQRPayload(qr);
    expect(v4).not.toBeNull();
    // Different payloads should have different indices (hash collision is
    // theoretically possible but negligible for these test vectors)
    expect(v4?.index).not.toBe(v3?.index);
  });

  it('FrameCollector accepts file MEOW: frame', () => {
    const collector = new FrameCollector();
    const frame = toCapture(qr);
    expect(frame).not.toBeNull();
    expect(collector.add(frame!)).toBe('accepted');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 3: FS: (forward secrecy)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: FS: (forward secrecy / X25519)', () => {
  const qr = buildFsPayload();

  it('is recognised by isMeowQRPayload()', () => {
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('parseQRPayload returns correct data field', () => {
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.data).toBe(qr);
  });

  it('FrameCollector accepts FS: frame', () => {
    const collector = new FrameCollector();
    const frame = toCapture(qr);
    expect(frame).not.toBeNull();
    expect(collector.add(frame!)).toBe('accepted');
  });

  it('single-char difference produces different index (dedup reliability)', () => {
    const qr2 = 'FS:' + toB64([...fill(0x11, 31), 0x99, ...fill(0x22, 16), ...fill(0x33, 12), ...fill(0x44, 48)]);
    const r1 = parseQRPayload(qr);
    const r2 = parseQRPayload(qr2);
    expect(r1?.index).not.toBe(r2?.index);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 4: QUANTUM: (Schrödinger dual-secret)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: QUANTUM: (Schrödinger dual-secret)', () => {
  const qr = buildQuantumPayload();

  it('is recognised by isMeowQRPayload()', () => {
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('parseQRPayload returns non-null', () => {
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.data).toBe(qr);
  });

  it('prefix is preserved in stored data field', () => {
    const result = parseQRPayload(qr);
    expect(result?.data.startsWith('QUANTUM:')).toBe(true);
  });

  it('FrameCollector accepts QUANTUM: frame', () => {
    const collector = new FrameCollector();
    const frame = toCapture(qr);
    expect(frame).not.toBeNull();
    expect(collector.add(frame!)).toBe('accepted');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 5: HYBRID-PQ: (post-quantum ML-KEM-1024 + X25519)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: HYBRID-PQ: (post-quantum hybrid)', () => {
  const qr = buildHybridPqPayload();

  it('is recognised by isMeowQRPayload()', () => {
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('parseQRPayload returns non-null', () => {
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.data).toBe(qr);
  });

  it('prefix HYBRID-PQ: is preserved in data', () => {
    const result = parseQRPayload(qr);
    expect(result?.data.startsWith('HYBRID-PQ:')).toBe(true);
  });

  it('FrameCollector accepts HYBRID-PQ: frame', () => {
    const collector = new FrameCollector();
    const frame = toCapture(qr);
    expect(frame).not.toBeNull();
    expect(collector.add(frame!)).toBe('accepted');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 6: DURESS: (duress / panic mode)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: DURESS: (panic-password mode)', () => {
  const qr = buildDuressPayload('Nothing important here.');

  it('is recognised by isMeowQRPayload()', () => {
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('parseQRPayload returns non-null', () => {
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.data).toBe(qr);
  });

  it('prefix DURESS: is preserved in data', () => {
    const result = parseQRPayload(qr);
    expect(result?.data.startsWith('DURESS:')).toBe(true);
  });

  it('FrameCollector accepts DURESS: frame', () => {
    const collector = new FrameCollector();
    const frame = toCapture(qr);
    expect(frame).not.toBeNull();
    expect(collector.add(frame!)).toBe('accepted');
  });

  it('two DURESS: payloads with different decoys get different indices', () => {
    const qr1 = buildDuressPayload('Nothing here.');
    const qr2 = buildDuressPayload('Also nothing here.');
    const r1 = parseQRPayload(qr1);
    const r2 = parseQRPayload(qr2);
    expect(r1?.index).not.toBe(r2?.index);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 7: FOUNTAIN: (animated multi-frame fountain coded)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: FOUNTAIN: (animated multi-frame)', () => {
  const K_BLOCKS = 5;
  const BLOCK_SIZE = 600;
  const ORIGINAL_LEN = 2800;

  it('single FOUNTAIN: frame parses correctly', () => {
    const qr = buildFountainFrame(0, K_BLOCKS, BLOCK_SIZE, ORIGINAL_LEN);
    const result = parseFountainPayload(qr);
    expect(result).not.toBeNull();
    expect(typeof result?.index).toBe('number');
    expect(result?.data).toBe(qr);
  });

  it('isMeowQRPayload returns true for FOUNTAIN: frames', () => {
    const qr = buildFountainFrame(1, K_BLOCKS, BLOCK_SIZE, ORIGINAL_LEN);
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('multiple FOUNTAIN: frames are deduplicated correctly', () => {
    const collector = new FrameCollector();
    const frames = [0, 1, 2, 3, 4, 5, 6].map(seed => {
      const qr = buildFountainFrame(seed, K_BLOCKS, BLOCK_SIZE, ORIGINAL_LEN);
      const f = toCapture(qr);
      return f;
    });

    let accepted = 0;
    for (const frame of frames) {
      if (frame && collector.add(frame) === 'accepted') accepted++;
    }
    expect(accepted).toBe(7);
    expect(collector.size).toBe(7);
  });

  it('same FOUNTAIN: frame scanned twice is deduplicated', () => {
    const collector = new FrameCollector();
    const qr = buildFountainFrame(42, K_BLOCKS, BLOCK_SIZE, ORIGINAL_LEN);
    const frame = toCapture(qr)!;
    expect(collector.add(frame)).toBe('accepted');
    expect(collector.add(frame)).toBe('duplicate');
    expect(collector.size).toBe(1);
  });

  it('FOUNTAIN: with > 1.5×k frames satisfies fountain code requirement', () => {
    const collector = new FrameCollector();
    const numDroplets = Math.ceil(K_BLOCKS * 1.5); // 8
    for (let i = 0; i < numDroplets; i++) {
      const qr = buildFountainFrame(i, K_BLOCKS, BLOCK_SIZE, ORIGINAL_LEN);
      const frame = toCapture(qr);
      if (frame) collector.add(frame);
    }
    expect(collector.size).toBe(numDroplets);
    expect(collector.size).toBeGreaterThanOrEqual(K_BLOCKS);
  });

  it('FOUNTAIN: frame with invalid base64 is rejected', () => {
    const qr = `FOUNTAIN:5:600:2800:!!!invalid!!!`;
    expect(parseFountainPayload(qr)).toBeNull();
    expect(isMeowQRPayload(qr)).toBe(false);
  });

  it('FOUNTAIN: with kBlocks=0 is rejected', () => {
    const qr = `FOUNTAIN:0:600:2800:${toB64(fill(0xaf, 4))}`;
    expect(parseFountainPayload(qr)).toBeNull();
  });

  it('FOUNTAIN: with too few colon-separated parts is rejected', () => {
    expect(parseFountainPayload('FOUNTAIN:5:600')).toBeNull();
    expect(parseFountainPayload('FOUNTAIN:5')).toBeNull();
  });

  it('buildQRExportChunks includes all fountain frames in export', () => {
    const numDroplets = 8;
    const capturedFrames: CapturedFrame[] = Array.from({ length: numDroplets }, (_, i) => {
      const qr = buildFountainFrame(i, K_BLOCKS, BLOCK_SIZE, ORIGINAL_LEN);
      return toCapture(qr, 1000 + i)!;
    });

    const response = makeCaptureResponse(capturedFrames);
    const chunks = buildQRExportChunks(response, 100_000);
    expect(chunks.length).toBeGreaterThanOrEqual(1);

    // All chunks should be valid JSON
    for (const chunk of chunks) {
      expect(() => JSON.parse(chunk)).not.toThrow();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 8: MEOW-N/total: (legacy chunked — web demo)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: MEOW-N/total: (legacy chunked)', () => {
  const TOTAL = 3;

  it('parses all three chunks with correct 0-based indices', () => {
    for (let n = 1; n <= TOTAL; n++) {
      const qr = buildLegacyChunk(n, TOTAL);
      const result = parseLegacyChunkedPayload(qr);
      expect(result).not.toBeNull();
      expect(result?.index).toBe(n - 1); // 1-based → 0-based
      expect(result?.data).toBe(qr);
    }
  });

  it('isMeowQRPayload returns true for all chunks', () => {
    for (let n = 1; n <= TOTAL; n++) {
      const qr = buildLegacyChunk(n, TOTAL);
      expect(isMeowQRPayload(qr)).toBe(true);
    }
  });

  it('parseQRPayload dispatches to parseLegacyChunkedPayload', () => {
    const qr = buildLegacyChunk(2, TOTAL);
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.index).toBe(1); // chunk 2 of 3 → index 1
  });

  it('FrameCollector collects all chunks without duplicates', () => {
    const collector = new FrameCollector();
    let accepted = 0;
    for (let n = 1; n <= TOTAL; n++) {
      const qr = buildLegacyChunk(n, TOTAL);
      const frame = toCapture(qr);
      if (frame && collector.add(frame) === 'accepted') accepted++;
    }
    expect(accepted).toBe(TOTAL);
    expect(collector.size).toBe(TOTAL);
  });

  it('re-scanning chunk 1 is deduplicated', () => {
    const collector = new FrameCollector();
    const qr = buildLegacyChunk(1, TOTAL);
    const frame = toCapture(qr)!;
    collector.add(frame);
    expect(collector.add(frame)).toBe('duplicate');
  });

  it('chunks are sorted by index in getSorted()', () => {
    const collector = new FrameCollector();
    // Add in reverse order to test sorting
    for (let n = TOTAL; n >= 1; n--) {
      const qr = buildLegacyChunk(n, TOTAL);
      const frame = toCapture(qr);
      if (frame) collector.add(frame);
    }
    const sorted = collector.getSorted();
    expect(sorted.map(f => f.index)).toEqual([0, 1, 2]);
  });

  it('MEOW-0/3: (chunk 0) is rejected by parseLegacyChunkedPayload', () => {
    // Chunk numbers must be >= 1 (1-based)
    const qr = `MEOW-0/3:${toB64(fill(0x77, 50))}`;
    expect(parseLegacyChunkedPayload(qr)).toBeNull();
  });

  it('MEOW-: without slash/colon is rejected', () => {
    expect(parseLegacyChunkedPayload('MEOW-')).toBeNull();
    expect(parseLegacyChunkedPayload(`MEOW-1:${toB64([0x01])}`)).toBeNull();
  });

  it('MEOW-N/total: with invalid base64 is rejected', () => {
    expect(parseLegacyChunkedPayload('MEOW-1/3:!!!invalid')).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 9: DURESS-N/total: (legacy multi-frame duress)
// Web demo generates this for DURESS: payloads > 2500 chars.
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: DURESS-N/total: (legacy multi-frame duress)', () => {
  const TOTAL = 3;

  /**
   * The web demo generates DURESS-N/total: frames for large DURESS: payloads
   * (> 2500 chars). qrDecoder.ts now handles this via the DURESS_CHUNKED
   * constant and the generalised parseLegacyChunkedPayload().
   */
  it('DURESS-1/3: is recognised and returns index 0', () => {
    const qr = buildDuressChunk(1, TOTAL);
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.index).toBe(0); // 1-based → 0-based
    expect(result?.data).toBe(qr);
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('DURESS-2/3: is recognised and returns index 1', () => {
    const qr = buildDuressChunk(2, TOTAL);
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.index).toBe(1);
  });

  it('DURESS-3/3: is recognised and returns index 2', () => {
    const qr = buildDuressChunk(3, TOTAL);
    const result = parseQRPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.index).toBe(2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FORMAT 10: JSON bridge (CLI / session mode)
// ─────────────────────────────────────────────────────────────────────────────
describe('Web demo format: JSON bridge (CLI session mode)', () => {
  const SESSION_ID = 'cli-session-abc123';

  it('JSON frame without session_id is accepted', () => {
    const qr = buildJsonFrame(0);
    const result = parseJsonPayload(qr);
    expect(result).not.toBeNull();
    expect(result?.index).toBe(0);
    expect(result?.data).toBeTruthy();
  });

  it('JSON frame with matching session_id is accepted', () => {
    const qr = buildJsonFrame(7, SESSION_ID);
    const result = parseJsonPayload(qr, SESSION_ID);
    expect(result).not.toBeNull();
    expect(result?.index).toBe(7);
    expect(result?.session_id).toBe(SESSION_ID);
  });

  it('JSON frame with wrong session_id is rejected', () => {
    const qr = buildJsonFrame(0, 'session-A');
    const result = parseJsonPayload(qr, 'session-B');
    expect(result).toBeNull();
  });

  it('JSON frame without session_id matches any expectedSessionId', () => {
    const qr = buildJsonFrame(0); // no session_id in payload
    const result = parseJsonPayload(qr, SESSION_ID);
    expect(result).not.toBeNull(); // no session_id = session-less frame, always accepted
  });

  it('parseQRPayload dispatches to parseJsonPayload', () => {
    const qr = buildJsonFrame(3, SESSION_ID);
    const result = parseQRPayload(qr, SESSION_ID);
    expect(result).not.toBeNull();
    expect(result?.index).toBe(3);
  });

  it('isMeowQRPayload returns true for valid JSON frames', () => {
    expect(isMeowQRPayload(buildJsonFrame(0))).toBe(true);
    expect(isMeowQRPayload(buildJsonFrame(42, SESSION_ID))).toBe(true);
  });

  it('JSON with invalid base64 data field is rejected', () => {
    const qr = JSON.stringify({ index: 0, data: '!!!not base64!!!' });
    expect(parseJsonPayload(qr)).toBeNull();
  });

  it('JSON with string index is rejected', () => {
    const qr = JSON.stringify({ index: '0', data: toB64([0x01]) });
    expect(parseJsonPayload(qr)).toBeNull();
  });

  it('JSON with NaN index is rejected', () => {
    const qr = JSON.stringify({ index: NaN, data: toB64([0x01]) }); // JSON.stringify NaN → null
    expect(parseJsonPayload(qr)).toBeNull();
  });

  it('non-JSON string is not parsed as JSON frame', () => {
    expect(parseJsonPayload('plain text')).toBeNull();
    expect(parseJsonPayload('MEOW:abc')).toBeNull();
  });

  it('multiple JSON frames collected in order', () => {
    const collector = new FrameCollector();
    for (let i = 0; i < 5; i++) {
      const frame = toCapture(buildJsonFrame(i, SESSION_ID), Date.now(), SESSION_ID);
      expect(frame).not.toBeNull();
      expect(collector.add(frame!)).toBe('accepted');
    }
    expect(collector.size).toBe(5);
    const sorted = collector.getSorted();
    expect(sorted.map(f => f.index)).toEqual([0, 1, 2, 3, 4]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// NEGATIVE TESTS: Non-meow QR codes are silently ignored
// ─────────────────────────────────────────────────────────────────────────────
describe('Non-meow QR codes: rejected at all stages', () => {
  const nonMeowCases = [
    'https://example.com/something',
    'WIFI:S:MyNetwork;T:WPA;P:password;;',
    'BEGIN:VCARD\nFN:John Doe\nEND:VCARD',
    'tel:+15551234567',
    'plain text with no prefix',
    '', // empty
    'MEOW', // prefix only, no colon
    'QUANTUM', // no colon
    'FS', // no colon
    'FOUNTAIN:not:enough', // too few parts
  ];

  for (const qr of nonMeowCases) {
    it(`isMeowQRPayload("${qr.slice(0, 30)}...") returns false`, () => {
      expect(isMeowQRPayload(qr)).toBe(false);
    });

    it(`parseQRPayload("${qr.slice(0, 30)}...") returns null`, () => {
      expect(parseQRPayload(qr)).toBeNull();
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PIPELINE: Full end-to-end parse → collect → export for a mixed session
// Simulates scanning a mix of MEOW:, FOUNTAIN:, and JSON frames
// ─────────────────────────────────────────────────────────────────────────────
describe('Full pipeline: mixed format session', () => {
  it('processes a realistic mixed capture session', () => {
    const collector = new FrameCollector();

    // Simulate scanning 5 fountain frames, then the MEOW manifest
    const sourceQRs = [
      buildFountainFrame(0, 5, 600, 2800),
      buildFountainFrame(1, 5, 600, 2800),
      buildFountainFrame(2, 5, 600, 2800),
      buildFountainFrame(3, 5, 600, 2800),
      buildFountainFrame(4, 5, 600, 2800),
      buildFountainFrame(5, 5, 600, 2800), // 1.5× redundancy
      buildFountainFrame(6, 5, 600, 2800),
      buildFountainFrame(7, 5, 600, 2800),
    ];

    // Simulate re-scanning frame 3 twice (common in video scanning)
    const duplicateQR = buildFountainFrame(3, 5, 600, 2800);
    sourceQRs.push(duplicateQR);
    sourceQRs.push(duplicateQR);

    for (const qr of sourceQRs) {
      const frame = toCapture(qr, Date.now());
      if (frame) collector.add(frame);
    }

    // Should have 8 unique frames (2 duplicates dropped)
    expect(collector.size).toBe(8);
    expect(collector.stats.totalDuplicated).toBe(2);

    // Frames should be sorted by index
    const sorted = collector.getSorted();
    const indices = sorted.map(f => f.index);
    expect(indices).toEqual([...indices].sort((a, b) => a - b));

    // Build export
    const response = makeCaptureResponse(sorted);
    const chunks = buildQRExportChunks(response, 100_000);
    expect(chunks.length).toBeGreaterThanOrEqual(1);

    // Verify export JSON structure
    for (const chunk of chunks) {
      const parsed: Record<string, unknown> = JSON.parse(chunk);
      expect(parsed['meow_qr_chunk']).toBe(true);
      expect(parsed['session_id']).toBe('test-session-00000000');
      expect(typeof parsed['chunk_index']).toBe('number');
      expect(typeof parsed['total_chunks']).toBe('number');
      expect(typeof parsed['data']).toBe('string');
    }
  });

  it('all single-frame formats can coexist in one session', () => {
    const collector = new FrameCollector();
    const singleFrameQRs = [
      buildMeowV3Payload(),
      buildMeowV4FilePayload('file.bin'),
      buildFsPayload(),
      buildQuantumPayload(),
      buildHybridPqPayload(),
      buildDuressPayload('decoy'),
    ];

    for (const qr of singleFrameQRs) {
      const frame = toCapture(qr, Date.now());
      expect(frame).not.toBeNull();
      collector.add(frame!);
    }

    expect(collector.size).toBe(6);
    const response = makeCaptureResponse(collector.getSorted());
    const chunks = buildQRExportChunks(response, 100_000);
    expect(chunks.length).toBeGreaterThanOrEqual(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// EDGE CASES: Minimum length, padding variants, URL-safe base64
// ─────────────────────────────────────────────────────────────────────────────
describe('Edge cases: base64 variants and minimum payloads', () => {
  it('MEOW: with exactly 10 chars is accepted (min length)', () => {
    // 'MEOW:' (5) + 5 chars = 10
    const qr = 'MEOW:xxxxx';
    // parseSingleFramePayload checks length >= 10 only, no base64 validation
    expect(isMeowQRPayload(qr)).toBe(true);
  });

  it('MEOW: with 9 chars is rejected (too short)', () => {
    expect(isMeowQRPayload('MEOW:xxxx')).toBe(false); // length 9
  });

  it('FOUNTAIN: with URL-safe base64 (no = padding) is accepted', () => {
    // URL-safe base64: uses - and _ instead of + and /
    const urlSafeB64 = toB64(fill(0xaf, 608)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const qr = `FOUNTAIN:5:600:2800:${urlSafeB64}`;
    expect(parseFountainPayload(qr)).not.toBeNull();
  });

  it('JSON frame with Infinity index is rejected', () => {
    // JSON.stringify(Infinity) → null — should be ignored
    const qr = JSON.stringify({ index: null, data: toB64([0x01]) });
    expect(parseJsonPayload(qr)).toBeNull();
  });

  it('empty FOUNTAIN: data field is rejected', () => {
    expect(parseFountainPayload('FOUNTAIN:5:600:2800:')).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// STATS: FrameCollector statistics accuracy
// ─────────────────────────────────────────────────────────────────────────────
describe('FrameCollector stats across web demo formats', () => {
  it('stats correctly tracks accepted / duplicated across all formats', () => {
    const collector = new FrameCollector();
    const formats = [
      buildMeowV3Payload(),
      buildFsPayload(),
      buildQuantumPayload(),
      buildHybridPqPayload(),
      buildDuressPayload(),
      buildFountainFrame(0),
    ];

    // Add each once → all accepted
    for (const qr of formats) {
      const frame = toCapture(qr, Date.now());
      if (frame) collector.add(frame);
    }
    expect(collector.stats.totalAccepted).toBe(formats.length);
    expect(collector.stats.totalDuplicated).toBe(0);

    // Add each again → all duplicated
    for (const qr of formats) {
      const frame = toCapture(qr, Date.now());
      if (frame) collector.add(frame);
    }
    expect(collector.stats.totalDuplicated).toBe(formats.length);
    expect(collector.stats.totalAccepted).toBe(formats.length); // unchanged

    // Clear resets everything
    collector.clear();
    expect(collector.size).toBe(0);
    expect(collector.stats.totalAccepted).toBe(0);
    expect(collector.stats.totalDuplicated).toBe(0);
  });
});
