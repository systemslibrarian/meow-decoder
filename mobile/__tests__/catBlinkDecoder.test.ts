/**
 * catBlinkDecoder.test.ts — golden-vector tests for the Cat Mode blink decoder.
 *
 * The "oracle" here reproduces the real transmitter framing from
 * web_demo/cat_mode.html (preamble → 2-bits-per-frame dual-eye → postamble,
 * over the whitened payload) and synthesizes a realistic camera brightness
 * stream (camera fps >> blink rate, with optional noise / dropped samples).
 * Each test asserts decodeCatBlink() recovers the exact un-whitened payload
 * bit-pattern — the same "binary pattern" the web demo saves.
 */

import { decodeCatBlink, type BrightnessSample } from '../src/services/catBlinkDecoder';
import { whiten } from '../src/services/catWhitening';

// ── Transmitter oracle (mirrors web_demo/cat_mode.html getFrameState) ────────

const PREAMBLE_ON = 8;
const PREAMBLE_OFF = 8;
const PREAMBLE_ALT = 4;
const POSTAMBLE = 8;

type Frame = readonly [0 | 1, 0 | 1]; // [leftEye, rightEye]

/** Deterministic LCG → byte, so vectors are reproducible across runs. */
function makeRng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s >>> 24; // a byte 0–255
  };
}

/** Build a structurally-valid payload: orig_len|comp_len BE headers + body. */
function buildPayloadBytes(origLen: number, compLen: number, seed: number): Uint8Array {
  const total = 68 + compLen + 16; // header(68) + ciphertext(comp + GCM tag)
  const b = new Uint8Array(total);
  const rng = makeRng(seed);
  for (let i = 0; i < total; i++) b[i] = rng();
  // Big-endian orig_len / comp_len in the first 8 bytes.
  b[0] = (origLen >>> 24) & 0xff;
  b[1] = (origLen >>> 16) & 0xff;
  b[2] = (origLen >>> 8) & 0xff;
  b[3] = origLen & 0xff;
  b[4] = (compLen >>> 24) & 0xff;
  b[5] = (compLen >>> 16) & 0xff;
  b[6] = (compLen >>> 8) & 0xff;
  b[7] = compLen & 0xff;
  return b;
}

function bytesToBinary(bytes: Uint8Array): string {
  let s = '';
  for (const byte of bytes) s += byte.toString(2).padStart(8, '0');
  return s;
}

/** Whitened payload → frame list with preamble + postamble (the wire format). */
function buildFrames(rawBinary: string): Frame[] {
  const whitened = whiten(rawBinary);
  const frames: Frame[] = [];
  for (let i = 0; i < PREAMBLE_ON; i++) frames.push([1, 1]);
  for (let i = 0; i < PREAMBLE_OFF; i++) frames.push([0, 0]);
  for (let i = 0; i < PREAMBLE_ALT; i++) frames.push(i % 2 === 0 ? [1, 0] : [0, 1]);
  for (let bit = 0; bit < whitened.length; bit += 2) {
    const left = whitened[bit] === '1' ? 1 : 0;
    const right = whitened[bit + 1] === '1' ? 1 : 0;
    frames.push([left, right]);
  }
  for (let i = 0; i < POSTAMBLE; i++) frames.push([1, 1]);
  return frames;
}

/**
 * Continuous-loop wire format — mirrors web_demo/cat_mode.html's loop mode:
 * [GUARD_OFF off][preamble 8 ON, 8 OFF, 4 alt][data], repeated, NO postamble.
 */
const LOOP_GUARD_OFF = 6;
function buildLoopingFrames(rawBinary: string, cycles: number): Frame[] {
  const whitened = whiten(rawBinary);
  const cycle: Frame[] = [];
  for (let i = 0; i < LOOP_GUARD_OFF; i++) cycle.push([0, 0]);
  for (let i = 0; i < PREAMBLE_ON; i++) cycle.push([1, 1]);
  for (let i = 0; i < PREAMBLE_OFF; i++) cycle.push([0, 0]);
  for (let i = 0; i < PREAMBLE_ALT; i++) cycle.push(i % 2 === 0 ? [1, 0] : [0, 1]);
  for (let bit = 0; bit < whitened.length; bit += 2) {
    const left = whitened[bit] === '1' ? 1 : 0;
    const right = whitened[bit + 1] === '1' ? 1 : 0;
    cycle.push([left, right]);
  }
  const frames: Frame[] = [];
  for (let c = 0; c < cycles; c++) frames.push(...cycle);
  return frames;
}

interface SynthOptions {
  blinkPeriodMs: number;
  cameraFps: number;
  onLevel: number;
  offLevel: number;
  noiseStd: number;
  dropEvery: number; // drop 1-in-N samples (0 = none) to model frame loss
  seed: number;
}

/** Synthesize a camera brightness stream from the transmitted frames. */
function synthesize(frames: Frame[], opts: SynthOptions): BrightnessSample[] {
  const dt = 1000 / opts.cameraFps;
  const totalMs = frames.length * opts.blinkPeriodMs;
  const rng = makeRng(opts.seed ^ 0x5a5a5a5a);
  const noise = () => (opts.noiseStd === 0 ? 0 : (rng() / 255 - 0.5) * 2 * opts.noiseStd);
  const samples: BrightnessSample[] = [];
  let n = 0;
  for (let t = 0; t < totalMs; t += dt, n++) {
    if (opts.dropEvery > 0 && n % opts.dropEvery === 0) continue; // dropped frame
    const f = frames[Math.floor(t / opts.blinkPeriodMs)];
    if (!f) break;
    const lvl = (on: 0 | 1) => (on ? opts.onLevel : opts.offLevel) + noise();
    samples.push({ t_ms: t, left: lvl(f[0]), right: lvl(f[1]) });
  }
  return samples;
}

// ── Tests ────────────────────────────────────────────────────────────────────

const baseSynth: Omit<SynthOptions, 'seed'> = {
  blinkPeriodMs: 200,
  cameraFps: 30,
  onLevel: 200,
  offLevel: 40,
  noiseStd: 0,
  dropEvery: 0,
};

describe('decodeCatBlink', () => {
  it('recovers the exact payload from a clean stream', () => {
    const raw = bytesToBinary(buildPayloadBytes(42, 40, 1));
    const frames = buildFrames(raw);
    const samples = synthesize(frames, { ...baseSynth, seed: 1 });

    const result = decodeCatBlink(samples);
    expect(result.locked).toBe(true);
    expect(result.diagnostics.reason).toBeNull();
    expect(result.binary).toBe(raw);
    expect(result.bits).toBe(raw.length);
    expect(result.diagnostics.origLen).toBe(42);
    expect(result.diagnostics.compLen).toBe(40);
  });

  it('estimates a blink period close to the true value (no drift)', () => {
    const raw = bytesToBinary(buildPayloadBytes(80, 96, 7));
    const samples = synthesize(buildFrames(raw), { ...baseSynth, seed: 7 });
    const result = decodeCatBlink(samples);
    expect(result.locked).toBe(true);
    expect(result.binary).toBe(raw);
    expect(Math.abs(result.blinkPeriodMs - 200)).toBeLessThan(10);
  });

  it('recovers under brightness noise', () => {
    const raw = bytesToBinary(buildPayloadBytes(50, 64, 3));
    const samples = synthesize(buildFrames(raw), {
      ...baseSynth,
      noiseStd: 18,
      seed: 3,
    });
    const result = decodeCatBlink(samples);
    expect(result.locked).toBe(true);
    expect(result.binary).toBe(raw);
  });

  it('recovers with dropped camera frames', () => {
    const raw = bytesToBinary(buildPayloadBytes(33, 48, 5));
    const samples = synthesize(buildFrames(raw), {
      ...baseSynth,
      dropEvery: 7, // lose ~1 in 7 samples
      seed: 5,
    });
    const result = decodeCatBlink(samples);
    expect(result.locked).toBe(true);
    expect(result.binary).toBe(raw);
  });

  it('recovers at a faster blink rate (100 ms) and 60 fps', () => {
    const raw = bytesToBinary(buildPayloadBytes(20, 24, 9));
    const samples = synthesize(buildFrames(raw), {
      ...baseSynth,
      blinkPeriodMs: 100,
      cameraFps: 60,
      noiseStd: 10,
      seed: 9,
    });
    const result = decodeCatBlink(samples);
    expect(result.locked).toBe(true);
    expect(result.binary).toBe(raw);
  });

  it('recovers from a LOOPING transmitter when the receiver starts mid-stream', () => {
    // This is the real phone scenario: the web sender loops continuously and the
    // phone starts scanning at an arbitrary point. The decoder must find a later
    // cycle's preamble and recover that cycle's full payload.
    const raw = bytesToBinary(buildPayloadBytes(20, 16, 11));
    const cycleFrames = LOOP_GUARD_OFF + PREAMBLE_ON + PREAMBLE_OFF + PREAMBLE_ALT
      + Math.ceil(whiten(raw).length / 2);
    const frames = buildLoopingFrames(raw, 3);
    const all = synthesize(frames, { ...baseSynth, noiseStd: 12, seed: 11 });
    // Drop the first ~0.6 cycle so the buffer begins partway through cycle 1.
    const dropMs = 0.6 * cycleFrames * baseSynth.blinkPeriodMs;
    const midStream = all.filter((s) => s.t_ms >= dropMs);

    const result = decodeCatBlink(midStream);
    expect(result.locked).toBe(true);
    expect(result.binary).toBe(raw);
  });

  it('reports progress (expectedBits) once the header locks on a partial capture', () => {
    // Only ~70% of one cycle is present → not complete, but the header should be
    // readable so progress/ETA can be shown.
    const raw = bytesToBinary(buildPayloadBytes(24, 40, 13));
    const frames = buildLoopingFrames(raw, 1);
    const full = synthesize(frames, { ...baseSynth, seed: 13 });
    const partial = full.slice(0, Math.floor(full.length * 0.7));
    const result = decodeCatBlink(partial);
    // Header read → expectedBits known even though capture is incomplete.
    expect(result.diagnostics.expectedBits).toBe((68 + 40 + 16) * 8);
    expect(result.bits).toBeGreaterThan(0);
    expect(result.bits).toBeLessThan(result.diagnostics.expectedBits as number);
  });

  it('does not lock on a stream with no preamble', () => {
    // Pure noise around the threshold, no structured preamble.
    const rng = makeRng(99);
    const samples: BrightnessSample[] = [];
    for (let i = 0; i < 400; i++) {
      samples.push({ t_ms: i * 33, left: rng(), right: rng() });
    }
    const result = decodeCatBlink(samples);
    expect(result.locked).toBe(false);
    expect(result.binary).toBe('');
  });

  it('returns too_few_samples for a tiny input', () => {
    const result = decodeCatBlink([{ t_ms: 0, left: 10, right: 10 }]);
    expect(result.locked).toBe(false);
    expect(result.diagnostics.reason).toBe('too_few_samples');
  });

  it('does not mutate the caller’s sample array', () => {
    const raw = bytesToBinary(buildPayloadBytes(16, 16, 2));
    const samples = synthesize(buildFrames(raw), { ...baseSynth, seed: 2 });
    const copy = samples.map((s) => ({ ...s }));
    decodeCatBlink(samples);
    expect(samples).toEqual(copy);
  });
});
