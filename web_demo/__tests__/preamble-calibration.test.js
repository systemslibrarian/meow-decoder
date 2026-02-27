/**
 * preamble-calibration.test.js — Unit tests for preamble detection,
 * auto-calibration, and video duration pre-check.
 */

const {
  checkVideoDuration,
  detectPreamble,
  learnFromPreamble,
  detectPreambleWithFallback,
  median,
  mean,
  standardDeviation,
} = require('../preamble-calibration');

// ── checkVideoDuration ────────────────────────────────────────────────────────

describe('checkVideoDuration', () => {
  it('rejects video shorter than minimum overhead', () => {
    const r = checkVideoDuration(2.0, 100);
    expect(r.ok).toBe(false);
    expect(r.maxPayloadBits).toBe(0);
    expect(r.message).toMatch(/at least/i);
  });

  it('accepts short video with shortVideoMode', () => {
    const r = checkVideoDuration(5.0, 100);
    expect(r.ok).toBe(true);
    expect(r.shortVideoMode).toBe(true);
    expect(r.message).toMatch(/short video/i);
  });

  it('accepts normal-length video without short mode', () => {
    const r = checkVideoDuration(15.0, 100);
    expect(r.ok).toBe(true);
    expect(r.shortVideoMode).toBe(false);
    expect(r.message).toBeNull();
  });

  it('calculates maxPayloadBits correctly for normal video', () => {
    // 15s video, 100ms/bit, full overhead = 56 bits = 5.6s
    // payload = floor((15 - 5.6) / 0.1) = 93 (rounding)
    const r = checkVideoDuration(15.0, 100);
    expect(r.maxPayloadBits).toBe(93);
  });

  it('uses custom bit period', () => {
    const r = checkVideoDuration(15.0, 200);
    expect(r.ok).toBe(true);
    expect(r.maxPayloadBits).toBeGreaterThan(0);
  });

  it('handles edge case: exactly minimum duration', () => {
    // minOverheadSec = 32 * 0.1 = 3.2s, needs + 1 bit = 3.3s
    // 3.3s is below fullOverheadSec(5.6) + 8bits(0.8) = 6.4s, so shortVideoMode
    const r = checkVideoDuration(3.4, 100);
    expect(r.ok).toBe(true);
    expect(r.shortVideoMode).toBe(true);
  });
});

// ── detectPreamble ────────────────────────────────────────────────────────────

describe('detectPreamble', () => {
  /** Generate alternating on/off frames. */
  function makeAlternating(count, bitPeriod) {
    return Array.from({ length: count }, (_, i) => ({
      time: i * bitPeriod,
      state: i % 2 === 0 ? 'on' : 'off',
      greenScore: i % 2 === 0 ? 0.8 : 0.2,
    }));
  }

  it('returns null for fewer than 10 frames', () => {
    expect(detectPreamble([])).toBeNull();
    expect(detectPreamble([{ time: 0, state: 'on' }])).toBeNull();
  });

  it('detects alternating pattern (early termination)', () => {
    const frames = makeAlternating(40, 0.1);
    const result = detectPreamble(frames, 0.7, 0.8, { earlyTermination: true, minAlternations: 16 });
    expect(result).not.toBeNull();
    expect(result.start).toBeDefined();
    expect(result.end).toBeDefined();
    expect(result.transitionRate).toBeGreaterThan(0.7);
  });

  it('detects alternating pattern without early termination', () => {
    const frames = makeAlternating(40, 0.1);
    const result = detectPreamble(frames, 0.7, 0.8, { earlyTermination: false });
    expect(result).not.toBeNull();
    expect(result.earlyTerminated).toBe(false);
  });

  it('returns null for non-alternating (all same state)', () => {
    const frames = Array.from({ length: 40 }, (_, i) => ({
      time: i * 0.1,
      state: 'on',
      greenScore: 0.8,
    }));
    expect(detectPreamble(frames, 0.7, 0.8)).toBeNull();
  });

  it('reports confidence level', () => {
    const frames = makeAlternating(60, 0.05);
    const result = detectPreamble(frames, 0.7, 0.5);
    expect(result).not.toBeNull();
    expect(['high', 'medium', 'low']).toContain(result.confidence);
  });
});

// ── learnFromPreamble ─────────────────────────────────────────────────────────

describe('learnFromPreamble', () => {
  function makeFrames() {
    const frames = [];
    for (let i = 0; i < 40; i++) {
      frames.push({
        time: i * 0.1,
        state: i % 2 === 0 ? 'on' : 'off',
        greenScore: i % 2 === 0 ? 0.75 : 0.25,
      });
    }
    return frames;
  }

  it('returns null with insufficient on/off samples', () => {
    const frames = Array.from({ length: 10 }, (_, i) => ({
      time: i * 0.1,
      state: 'on',
      greenScore: 0.8,
    }));
    expect(learnFromPreamble(frames, { start: 0, end: 10 })).toBeNull();
  });

  it('learns on/off means and threshold from good preamble', () => {
    const frames = makeFrames();
    const result = learnFromPreamble(frames, { start: 0, end: 40 });
    expect(result).not.toBeNull();
    expect(result.onMean).toBeCloseTo(0.75, 1);
    expect(result.offMean).toBeCloseTo(0.25, 1);
    expect(result.threshold).toBeCloseTo(0.5, 1);
    expect(result.range).toBeCloseTo(0.5, 1);
  });

  it('estimates bit rate from transition intervals', () => {
    const frames = makeFrames();
    const result = learnFromPreamble(frames, { start: 0, end: 40 });
    expect(result).not.toBeNull();
    // bitRate = median transition interval; transitions are every 0.1s
    // so bitRate ≈ 0.1s (one bit period)
    expect(result.bitRate).toBeCloseTo(0.1, 1);
  });

  it('reports sample count', () => {
    const frames = makeFrames();
    const result = learnFromPreamble(frames, { start: 0, end: 40 });
    expect(result.sampleCount).toBe(40);
  });
});

// ── detectPreambleWithFallback ────────────────────────────────────────────────

describe('detectPreambleWithFallback', () => {
  it('falls back to UI speed when no preamble detected', () => {
    // All same state = no preamble
    const frames = Array.from({ length: 40 }, (_, i) => ({
      time: i * 0.1,
      state: 'on',
      greenScore: 0.8,
    }));
    const allScores = frames.map((f) => f.greenScore);
    const result = detectPreambleWithFallback(frames, 100, allScores);
    expect(result.found).toBe(false);
    expect(result.learned.fallback).toBe(true);
    expect(result.learned.bitRate).toBe(0.1); // 100ms → 0.1s
  });

  it('returns preamble-learned data when found', () => {
    const frames = [];
    for (let i = 0; i < 60; i++) {
      frames.push({
        time: i * 0.05,
        state: i % 2 === 0 ? 'on' : 'off',
        greenScore: i % 2 === 0 ? 0.8 : 0.2,
      });
    }
    const allScores = frames.map((f) => f.greenScore);
    const result = detectPreambleWithFallback(frames, 100, allScores);
    expect(result.found).toBe(true);
    expect(result.learned.onMean).toBeGreaterThan(0.5);
    expect(result.learned.offMean).toBeLessThan(0.5);
  });
});

// ── Multi-frame-per-bit detection (real video scenario) ───────────────────────

describe('detectPreamble (multi-frame-per-bit)', () => {
  /**
   * Generate frames simulating real video: multiple frames per bit period.
   * At 100ms/bit with 50fps sampling, each bit has ~5 frames.
   * Preamble 1010... → OOOOO FFFFF OOOOO FFFFF ...
   */
  function makeMultiFrameAlternating(numBits, framesPerBit, bitPeriodSec) {
    const frames = [];
    const frameInterval = bitPeriodSec / framesPerBit;
    let frameIdx = 0;
    for (let bit = 0; bit < numBits; bit++) {
      const state = bit % 2 === 0 ? 'on' : 'off';
      const greenScore = state === 'on' ? 0.8 : 0.2;
      for (let f = 0; f < framesPerBit; f++) {
        frames.push({
          time: frameIdx * frameInterval,
          state,
          greenScore,
        });
        frameIdx++;
      }
    }
    return frames;
  }

  it('detects preamble with 5 frames per bit (100ms bits at 50fps)', () => {
    // 32 alternating bits * 5 frames/bit = 160 frames, ~3.2s
    const frames = makeMultiFrameAlternating(32, 5, 0.1);
    const result = detectPreamble(frames, 0.7, 0.8);
    expect(result).not.toBeNull();
    expect(result.duration).toBeGreaterThan(0.8);
    expect(result.transitionRate).toBeGreaterThan(0.7);
  });

  it('detects preamble with 3 frames per bit (100ms bits at 30fps)', () => {
    const frames = makeMultiFrameAlternating(32, 3, 0.1);
    const result = detectPreamble(frames, 0.7, 0.8);
    expect(result).not.toBeNull();
  });

  it('detects preamble with 10 frames per bit (100ms bits at 100fps)', () => {
    const frames = makeMultiFrameAlternating(32, 10, 0.1);
    const result = detectPreamble(frames, 0.7, 0.8);
    expect(result).not.toBeNull();
    // Early termination at 16 alternations gives ~1.6-1.7s
    expect(result.duration).toBeGreaterThan(1.5);
  });

  it('early-terminates with multi-frame-per-bit data', () => {
    const frames = makeMultiFrameAlternating(40, 5, 0.1);
    const result = detectPreamble(frames, 0.7, 0.8, { earlyTermination: true, minAlternations: 16 });
    expect(result).not.toBeNull();
    expect(result.earlyTerminated).toBe(true);
  });

  it('learns correct bitRate from multi-frame preamble', () => {
    const frames = makeMultiFrameAlternating(32, 5, 0.1);
    const preamble = detectPreamble(frames, 0.7, 0.8);
    expect(preamble).not.toBeNull();
    const learned = learnFromPreamble(frames, preamble);
    expect(learned).not.toBeNull();
    // Bit period is 0.1s; bitRate should be ~0.1, NOT 0.2
    expect(learned.bitRate).toBeCloseTo(0.1, 1);
    expect(learned.threshold).toBeCloseTo(0.5, 1);
  });

  it('handles lead-in zeros followed by alternation (real encoding format)', () => {
    // Simulate: 8 zeros lead-in (40 frames at 5 frames/bit) + 32 alternating bits
    const leadInFrames = 8 * 5; // 40 frames of state='off'
    const frames = [];
    for (let i = 0; i < leadInFrames; i++) {
      frames.push({ time: i * 0.02, state: 'off', greenScore: 0.2 });
    }
    const altFrames = makeMultiFrameAlternating(32, 5, 0.1);
    for (const f of altFrames) {
      frames.push({ ...f, time: f.time + leadInFrames * 0.02 });
    }
    const result = detectPreamble(frames, 0.7, 0.5);
    expect(result).not.toBeNull();
    // The lead-in 'off' run + first 'on' preamble run forms an alternation.
    // The preamble region may start at/near the lead-in boundary.
    // What matters is that the alternation is detected and downstream
    // code (catVideoAnalyze) correctly finds the alternation END.
    expect(result.duration).toBeGreaterThan(0.5);
    // The transition rate should be high (all runs alternate)
    expect(result.transitionRate).toBeGreaterThan(0.7);
  });
});

// ── learnFromPreamble with greenLevel (video pipeline compat) ─────────────────

describe('learnFromPreamble (greenLevel field)', () => {
  it('works with greenLevel instead of greenScore', () => {
    const frames = [];
    for (let i = 0; i < 40; i++) {
      frames.push({
        time: i * 0.1,
        state: i % 2 === 0 ? 'on' : 'off',
        greenLevel: i % 2 === 0 ? 75.0 : 25.0,
      });
    }
    const result = learnFromPreamble(frames, { start: 0, end: 40 });
    expect(result).not.toBeNull();
    expect(result.onMean).toBeCloseTo(75.0, 0);
    expect(result.offMean).toBeCloseTo(25.0, 0);
    expect(result.threshold).toBeCloseTo(50.0, 0);
  });
});

// ── Utility functions ─────────────────────────────────────────────────────────

describe('utility: median', () => {
  it('returns 0 for empty', () => expect(median([])).toBe(0));
  it('returns middle for odd', () => expect(median([3, 1, 2])).toBe(2));
  it('returns average for even', () => expect(median([1, 3])).toBe(2));
});

describe('utility: mean', () => {
  it('returns 0 for empty', () => expect(mean([])).toBe(0));
  it('computes mean', () => expect(mean([2, 4])).toBe(3));
});

describe('utility: standardDeviation', () => {
  it('returns 0 for empty', () => expect(standardDeviation([])).toBe(0));
  it('returns 0 for identical', () => expect(standardDeviation([7, 7, 7], 7)).toBe(0));
  it('computes stddev', () => {
    const sd = standardDeviation([2, 4, 4, 4, 5, 5, 7, 9], 5);
    expect(sd).toBeCloseTo(2.0, 1);
  });
});
