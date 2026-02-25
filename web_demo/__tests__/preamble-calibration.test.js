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
    // bitRate = 2 × median transition interval; transitions are every 0.1s
    // so bitRate ≈ 0.2s
    expect(result.bitRate).toBeCloseTo(0.2, 1);
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
