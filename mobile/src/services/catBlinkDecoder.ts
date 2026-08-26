/**
 * catBlinkDecoder.ts — Cat Mode blinking-eye optical decoder (pure logic).
 *
 * Converts a time-series of per-eye brightness samples (produced by the camera
 * frame processor pointed at a blinking-eye animation) into the original
 * payload bit-pattern — the same "binary pattern" the web demo saves and feeds
 * to its decrypt step. This module performs NO decryption: the mobile app is an
 * untrusted optical sensor (see src/types/capture.ts) and only recovers bits.
 *
 * Channel (must match web_demo/cat_mode.html transmitter exactly):
 *   • Each blink frame carries 2 bits: left eye = bit, right eye = bit
 *     (green/ON = 1, dark = 0).
 *   • Preamble = 8× both-ON, 8× both-OFF, 4× alternating  (20 frames).
 *     Used to find sync, learn ON/OFF brightness, and estimate the blink period.
 *   • Postamble = 8× both-ON.
 *   • Transmitted bits are whitened (catWhitening); we de-whiten to recover the
 *     raw payload pattern.
 *   • Payload begins with orig_len(4B BE) | comp_len(4B BE); we read those to
 *     compute the exact payload length and stop precisely (matching the web
 *     decoder's check_header), so the postamble never bleeds into the data.
 *
 * The camera samples far faster than the blink rate (e.g. 30 fps camera vs a
 * 5 Hz / 200 ms blink), so the pipeline works in TIME: classify each sample,
 * then NRZ-sample the per-eye state at the midpoint of each blink window.
 */

import { dewhiten } from './catWhitening';

// ── Public types ────────────────────────────────────────────────────────────

/** One camera sample: mean brightness of each eye ROI at a point in time. */
export interface BrightnessSample {
  /** Capture time in milliseconds (monotonic; need not start at 0). */
  t_ms: number;
  /** Mean brightness of the left-eye region (any consistent scale, e.g. 0–255). */
  left: number;
  /** Mean brightness of the right-eye region. */
  right: number;
}

export interface CatDecodeDiagnostics {
  /** Why the decode failed, when locked === false. */
  reason: string | null;
  /** Estimated time (ms) where the data region begins. */
  dataStartMs: number | null;
  /** Recovered header lengths, when the header parsed. */
  origLen: number | null;
  compLen: number | null;
  /** Total payload bits expected (from the header), once the header is read. */
  expectedBits: number | null;
  /** Whitened bits sampled before de-whitening (for debugging). */
  whitenedBits: number;
  /** Per-eye learned thresholds. */
  leftThreshold: number | null;
  rightThreshold: number | null;
}

export interface CatDecodeResult {
  /** True once the preamble was located and a plausible payload recovered. */
  locked: boolean;
  /** Recovered raw (de-whitened) payload bit-pattern, or '' if not locked. */
  binary: string;
  /** Length of `binary` in bits. */
  bits: number;
  /** Estimated blink period in milliseconds. */
  blinkPeriodMs: number;
  /** Number of data frames decoded (each frame = 2 bits). */
  frames: number;
  diagnostics: CatDecodeDiagnostics;
}

export interface CatDecodeOptions {
  /**
   * Hysteresis deadband as a fraction of the ON/OFF range (default 0.10).
   * Samples within ±band of the threshold hold the previous state.
   */
  hysteresis?: number;
  /**
   * Hard cap on payload bytes accepted from the header length (default 65536).
   * Guards against a corrupt header demanding a runaway-length decode.
   */
  maxPayloadBytes?: number;
}

// ── Protocol constants (mirror the transmitter) ─────────────────────────────

const PREAMBLE_ON = 8;
const PREAMBLE_OFF = 8;
const PREAMBLE_ALT = 4;
/** Fixed payload header size in bytes: orig_len(4)|comp_len(4)|sha(32)|salt(16)|nonce(12). */
const HEADER_BYTES = 68;
/** AES-256-GCM authentication tag appended to the ciphertext. */
const GCM_TAG_BYTES = 16;
const DEFAULT_HYSTERESIS = 0.1;
const DEFAULT_MAX_PAYLOAD_BYTES = 65536;

// ── Small numeric helpers ───────────────────────────────────────────────────

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.round(p * (sorted.length - 1))));
  return sorted[idx] as number;
}

/**
 * Robust ON/OFF separation for one eye. Uses the 10th/90th percentiles as the
 * OFF/ON anchors (resistant to a few outlier frames) and the midpoint as the
 * decision threshold.
 */
function learnLevels(values: number[]): { threshold: number; offLevel: number; onLevel: number } {
  const sorted = [...values].sort((a, b) => a - b);
  const offLevel = percentile(sorted, 0.1);
  const onLevel = percentile(sorted, 0.9);
  return { threshold: (offLevel + onLevel) / 2, offLevel, onLevel };
}

// ── Per-eye state classification (threshold + hysteresis) ───────────────────

type EyeState = 0 | 1;

interface ClassifiedSample {
  t_ms: number;
  left: EyeState;
  right: EyeState;
}

function classifyEye(
  values: number[],
  threshold: number,
  band: number,
): EyeState[] {
  const low = threshold - band;
  const high = threshold + band;
  const out: EyeState[] = [];
  let prev: EyeState = 0;
  for (let i = 0; i < values.length; i++) {
    const v = values[i] as number;
    let s: EyeState;
    if (v > high) s = 1;
    else if (v < low) s = 0;
    else s = prev; // hysteresis deadband: hold previous state
    out.push(s);
    prev = s;
  }
  return out;
}

// ── Preamble / sync detection ───────────────────────────────────────────────

interface SyncInfo {
  /** Time of the last sample in the preamble's both-OFF block. */
  offRunEndMs: number;
  /** Coarse blink period from the preamble blocks (bootstrap for refinement). */
  roughPeriodMs: number;
}

type Combined = 'ON' | 'OFF' | 'MIX';

interface Run {
  state: Combined;
  startMs: number;
  endMs: number; // time of the last sample in the run
  count: number;
}

function buildCombinedRuns(samples: ClassifiedSample[]): Run[] {
  const runs: Run[] = [];
  for (const s of samples) {
    const c: Combined = s.left === 1 && s.right === 1 ? 'ON' : s.left === 0 && s.right === 0 ? 'OFF' : 'MIX';
    const last = runs[runs.length - 1];
    if (last && last.state === c) {
      last.endMs = s.t_ms;
      last.count += 1;
    } else {
      runs.push({ state: c, startMs: s.t_ms, endMs: s.t_ms, count: 1 });
    }
  }
  return runs;
}

/**
 * Locate the preamble's long both-ON run followed by its long both-OFF run, and
 * from their durations derive the blink period and the data-start time.
 *
 * The ON and OFF preamble blocks are each PREAMBLE_ON / PREAMBLE_OFF blinks
 * long, so each block's duration ÷ block-count estimates the blink period. Data
 * begins PREAMBLE_ALT blinks after the OFF block ends.
 */
function detectSync(samples: ClassifiedSample[]): SyncInfo | null {
  if (samples.length < 4) return null;
  const runs = buildCombinedRuns(samples);

  // Candidate ON run: the longest both-ON run within the first ~60% of runs
  // (the preamble lives near the start; later both-ON noise is ignored).
  const searchLimit = Math.max(1, Math.floor(runs.length * 0.6));
  let onIdx = -1;
  let onBestCount = 0;
  for (let i = 0; i < searchLimit; i++) {
    const r = runs[i] as Run;
    if (r.state === 'ON' && r.count > onBestCount) {
      onBestCount = r.count;
      onIdx = i;
    }
  }
  if (onIdx < 0) return null;

  // First both-OFF run after the ON run.
  let offIdx = -1;
  for (let i = onIdx + 1; i < runs.length; i++) {
    if ((runs[i] as Run).state === 'OFF') {
      offIdx = i;
      break;
    }
  }
  if (offIdx < 0) return null;

  const onRun = runs[onIdx] as Run;
  const offRun = runs[offIdx] as Run;

  // Run duration spans (count-1) sample intervals; period = span / blocks.
  const onSpan = onRun.endMs - onRun.startMs;
  const offSpan = offRun.endMs - offRun.startMs;
  const onPeriod = onSpan / PREAMBLE_ON;
  const offPeriod = offSpan / PREAMBLE_OFF;
  // Average the two estimates; ignore a degenerate (too-short) span.
  const estimates = [onPeriod, offPeriod].filter((p) => p > 0);
  if (estimates.length === 0) return null;
  const roughPeriodMs = estimates.reduce((a, b) => a + b, 0) / estimates.length;
  if (!(roughPeriodMs > 0)) return null;

  return { offRunEndMs: offRun.endMs, roughPeriodMs };
}

/**
 * Refine the blink period from single-blink transition intervals across the
 * whole signal. The preamble span gives only a coarse estimate (biased low by
 * up to half a sample interval), which would compound into multi-frame drift
 * over a long payload. Each length-1 run between two transitions lasts exactly
 * one blink period, so the median of those intervals is an unbiased, drift-free
 * estimate (mirrors refine_blink_period in meow_decoder/cat_video.py).
 *
 * Transition times are taken at the midpoint between the two straddling samples
 * to remove half-sample bias. Falls back to the rough period if too few
 * single-blink intervals are observed.
 */
function refinePeriod(samples: ClassifiedSample[], roughPeriodMs: number): number {
  const intervals: number[] = [];
  for (const eye of ['left', 'right'] as const) {
    let lastTransMs: number | null = null;
    for (let i = 1; i < samples.length; i++) {
      const cur = samples[i] as ClassifiedSample;
      const prev = samples[i - 1] as ClassifiedSample;
      if (cur[eye] !== prev[eye]) {
        const tMs = (cur.t_ms + prev.t_ms) / 2;
        if (lastTransMs !== null) {
          const iv = tMs - lastTransMs;
          if (iv > 0 && Math.round(iv / roughPeriodMs) === 1) intervals.push(iv);
        }
        lastTransMs = tMs;
      }
    }
  }
  if (intervals.length < 3) return roughPeriodMs;
  intervals.sort((a, b) => a - b);
  return intervals[Math.floor(intervals.length / 2)] as number;
}

// ── NRZ time-sampling (windowed majority vote) ──────────────────────────────

/**
 * Fraction of the blink period on each side of the frame midpoint that
 * contributes to the majority vote. ±0.30 keeps the vote inside the steady
 * centre of the blink, away from the transition edges where the camera may
 * straddle two states.
 */
const VOTE_HALF_WINDOW = 0.3;

/**
 * Read `frameCount` frames (2 bits each) starting at `fromFrame`, majority-
 * voting each eye over the samples inside the centre of the blink window. This
 * tolerates per-sample brightness noise far better than reading a single
 * nearest sample. Ties and empty windows fall back to the sample nearest the
 * midpoint. Stops early if the window runs past the end of the stream.
 */
function sampleFrames(
  samples: ClassifiedSample[],
  dataStartMs: number,
  blinkPeriodMs: number,
  fromFrame: number,
  frameCount: number,
): string {
  if (samples.length === 0) return '';
  const half = blinkPeriodMs * VOTE_HALF_WINDOW;
  let lo = 0; // moving window-start cursor (target times are monotonic)
  let bits = '';

  for (let f = 0; f < frameCount; f++) {
    const frameIdx = fromFrame + f;
    const midMs = dataStartMs + (frameIdx + 0.5) * blinkPeriodMs;
    const startMs = midMs - half;
    const endMs = midMs + half;

    while (lo < samples.length && (samples[lo] as ClassifiedSample).t_ms < startMs) lo++;
    if (lo >= samples.length) break; // window past end of stream

    let leftOnes = 0;
    let votes = 0;
    let rightOnes = 0;
    let nearest: ClassifiedSample | null = null;
    let nearestDist = Infinity;
    for (let i = lo; i < samples.length; i++) {
      const s = samples[i] as ClassifiedSample;
      if (s.t_ms > endMs) break;
      leftOnes += s.left;
      rightOnes += s.right;
      votes++;
      const d = Math.abs(s.t_ms - midMs);
      if (d < nearestDist) {
        nearestDist = d;
        nearest = s;
      }
    }

    let leftBit: EyeState;
    let rightBit: EyeState;
    if (votes === 0) {
      // No samples landed in the window — fall back to the nearest overall.
      const s = samples[Math.min(lo, samples.length - 1)] as ClassifiedSample;
      leftBit = s.left;
      rightBit = s.right;
    } else {
      const fallback = nearest as ClassifiedSample;
      leftBit = leftOnes * 2 === votes ? fallback.left : ((leftOnes * 2 > votes ? 1 : 0) as EyeState);
      rightBit = rightOnes * 2 === votes ? fallback.right : ((rightOnes * 2 > votes ? 1 : 0) as EyeState);
    }
    bits += leftBit === 1 ? '1' : '0';
    bits += rightBit === 1 ? '1' : '0';
  }
  return bits;
}

// ── v2 raw-bit sampling (frame layer parses downstream) ─────────────────────

export interface CatSampleBitsResult {
  /** True once the preamble was located and a blink period estimated. */
  locked: boolean;
  /**
   * The WHITENED bit stream recovered from every blink frame after the preamble,
   * in transmit order. NOT de-whitened and NOT length-limited: the v2 frame
   * scanner (catBlinkV2.scanFrames) de-whitens per-frame and finds the frame
   * boundaries itself, so this stage only does clock recovery + NRZ sampling.
   */
  whitenedBits: string;
  /** Estimated blink period in milliseconds (0 until locked). */
  blinkPeriodMs: number;
  /** Time (ms) where the data region begins, or null when not locked. */
  dataStartMs: number | null;
}

/**
 * Cat Blink v2 sampling stage: recover the raw whitened bit stream from the eye
 * brightness samples. Shares the exact preamble-sync + drift-free period-refine
 * + NRZ majority-vote machinery used by {@link decodeCatBlink}; ONLY the parse
 * stage differs — v1 reads a fixed 68-byte header and stops at the payload
 * length, whereas v2 defers all framing to the fountain frame scanner and simply
 * samples every blink from data-start to the end of the stream.
 *
 * The whitened bits are returned as-is (self-inverse whitening is undone per
 * frame downstream), so a lossy or partial capture still yields whatever frames
 * were transmitted for the scanner to sift.
 */
export function sampleCatBlinkV2Bits(
  samples: BrightnessSample[],
  options: CatDecodeOptions = {},
): CatSampleBitsResult {
  const hysteresisFrac = options.hysteresis ?? DEFAULT_HYSTERESIS;

  const empty: CatSampleBitsResult = {
    locked: false,
    whitenedBits: '',
    blinkPeriodMs: 0,
    dataStartMs: null,
  };
  if (samples.length < PREAMBLE_ON + PREAMBLE_OFF) return empty;

  const ordered = [...samples].sort((a, b) => a.t_ms - b.t_ms);

  const leftLevels = learnLevels(ordered.map((s) => s.left));
  const rightLevels = learnLevels(ordered.map((s) => s.right));
  const leftBand = ((leftLevels.onLevel - leftLevels.offLevel) / 2) * hysteresisFrac;
  const rightBand = ((rightLevels.onLevel - rightLevels.offLevel) / 2) * hysteresisFrac;
  const leftStates = classifyEye(ordered.map((s) => s.left), leftLevels.threshold, leftBand);
  const rightStates = classifyEye(ordered.map((s) => s.right), rightLevels.threshold, rightBand);

  const classified: ClassifiedSample[] = ordered.map((s, i) => ({
    t_ms: s.t_ms,
    left: leftStates[i] as EyeState,
    right: rightStates[i] as EyeState,
  }));

  const sync = detectSync(classified);
  if (sync === null) return empty;
  const blinkPeriodMs = refinePeriod(classified, sync.roughPeriodMs);
  if (!(blinkPeriodMs > 0)) return empty;
  const dataStartMs = sync.offRunEndMs + PREAMBLE_ALT * blinkPeriodMs;

  // Sample every blink from data-start to the end of the stream (2 bits/frame).
  const lastMs = (classified[classified.length - 1] as ClassifiedSample).t_ms;
  const availableFrames = Math.max(0, Math.floor((lastMs - dataStartMs) / blinkPeriodMs));
  const whitenedBits = sampleFrames(classified, dataStartMs, blinkPeriodMs, 0, availableFrames);

  return { locked: true, whitenedBits, blinkPeriodMs, dataStartMs };
}

// ── Public API ──────────────────────────────────────────────────────────────

function emptyResult(reason: string): CatDecodeResult {
  return {
    locked: false,
    binary: '',
    bits: 0,
    blinkPeriodMs: 0,
    frames: 0,
    diagnostics: {
      reason,
      dataStartMs: null,
      origLen: null,
      compLen: null,
      expectedBits: null,
      whitenedBits: 0,
      leftThreshold: null,
      rightThreshold: null,
    },
  };
}

/**
 * Decode a Cat Mode blink stream into the raw payload bit-pattern.
 *
 * @param samples  Per-eye brightness samples in capture-time order.
 * @param options  Optional tuning (hysteresis band, payload-size cap).
 * @returns        The recovered binary pattern plus sync/diagnostics. When the
 *                 preamble can't be found or the header is implausible,
 *                 `locked` is false and `binary` is ''.
 */
export function decodeCatBlink(
  samples: BrightnessSample[],
  options: CatDecodeOptions = {},
): CatDecodeResult {
  const hysteresisFrac = options.hysteresis ?? DEFAULT_HYSTERESIS;
  const maxPayloadBytes = options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES;

  if (samples.length < PREAMBLE_ON + PREAMBLE_OFF) {
    return emptyResult('too_few_samples');
  }

  // Ensure monotonic time order without mutating the caller's array.
  const ordered = [...samples].sort((a, b) => a.t_ms - b.t_ms);

  // 1. Learn per-eye ON/OFF levels and classify every sample with hysteresis.
  const leftLevels = learnLevels(ordered.map((s) => s.left));
  const rightLevels = learnLevels(ordered.map((s) => s.right));
  const leftBand = ((leftLevels.onLevel - leftLevels.offLevel) / 2) * hysteresisFrac;
  const rightBand = ((rightLevels.onLevel - rightLevels.offLevel) / 2) * hysteresisFrac;
  const leftStates = classifyEye(ordered.map((s) => s.left), leftLevels.threshold, leftBand);
  const rightStates = classifyEye(ordered.map((s) => s.right), rightLevels.threshold, rightBand);

  const classified: ClassifiedSample[] = ordered.map((s, i) => ({
    t_ms: s.t_ms,
    left: leftStates[i] as EyeState,
    right: rightStates[i] as EyeState,
  }));

  // 2. Find the preamble → coarse period + OFF-block anchor, then refine the
  //    period (drift-free) and place the data-start one alt-block later.
  const sync = detectSync(classified);
  if (sync === null) {
    const r = emptyResult('no_preamble');
    r.diagnostics.leftThreshold = leftLevels.threshold;
    r.diagnostics.rightThreshold = rightLevels.threshold;
    return r;
  }
  const blinkPeriodMs = refinePeriod(classified, sync.roughPeriodMs);
  const dataStartMs = sync.offRunEndMs + PREAMBLE_ALT * blinkPeriodMs;

  // 3. Read the 64-bit header (32 frames) → orig_len, comp_len → payload length.
  const headerBits = sampleFrames(classified, dataStartMs, blinkPeriodMs, 0, 32);
  const dewhitenedHeader = dewhiten(headerBits);
  if (dewhitenedHeader.length < 64) {
    const r = emptyResult('header_truncated');
    r.diagnostics.dataStartMs = dataStartMs;
    r.diagnostics.leftThreshold = leftLevels.threshold;
    r.diagnostics.rightThreshold = rightLevels.threshold;
    return r;
  }
  const origLen = parseInt(dewhitenedHeader.slice(0, 32), 2);
  const compLen = parseInt(dewhitenedHeader.slice(32, 64), 2);

  // Payload = header(68) + ciphertext(comp_len + GCM tag 16).
  const payloadBytes = HEADER_BYTES + compLen + GCM_TAG_BYTES;
  if (
    !Number.isFinite(compLen) ||
    compLen <= 0 ||
    payloadBytes > maxPayloadBytes ||
    !Number.isFinite(origLen) ||
    origLen <= 0
  ) {
    const r = emptyResult('bad_header');
    r.diagnostics.dataStartMs = dataStartMs;
    r.diagnostics.origLen = origLen;
    r.diagnostics.compLen = compLen;
    r.diagnostics.leftThreshold = leftLevels.threshold;
    r.diagnostics.rightThreshold = rightLevels.threshold;
    return r;
  }

  const totalBits = payloadBytes * 8;
  const totalFrames = Math.ceil(totalBits / 2);

  // 4. Read the full payload (header frames included) and de-whiten.
  const whitened = sampleFrames(classified, dataStartMs, blinkPeriodMs, 0, totalFrames);
  const binary = dewhiten(whitened).slice(0, totalBits);

  return {
    locked: binary.length === totalBits,
    binary,
    bits: binary.length,
    blinkPeriodMs,
    frames: Math.min(totalFrames, Math.ceil(whitened.length / 2)),
    diagnostics: {
      reason: binary.length === totalBits ? null : 'incomplete_payload',
      dataStartMs,
      origLen,
      compLen,
      expectedBits: totalBits,
      whitenedBits: whitened.length,
      leftThreshold: leftLevels.threshold,
      rightThreshold: rightLevels.threshold,
    },
  };
}
