/**
 * quality-metrics.test.js — Unit tests for quality gating and metrics tracking.
 */

const {
  QualityMetrics,
  classifyFrame,
  classifyFrameWithPercentiles,
  getStableState,
  learnDistributionsFromPreamble,
  detectPreamble,
  mean,
  median,
  standardDeviation,
} = require('../quality-metrics');

// ── Helper stats ──────────────────────────────────────────────────────────────

describe('mean', () => {
  it('returns 0 for empty array', () => expect(mean([])).toBe(0));
  it('calculates arithmetic mean', () => expect(mean([2, 4, 6])).toBe(4));
});

describe('median', () => {
  it('returns 0 for empty array', () => expect(median([])).toBe(0));
  it('returns middle value (odd)', () => expect(median([5, 1, 3])).toBe(3));
  it('returns average of middles (even)', () => expect(median([1, 2, 3, 4])).toBe(2.5));
});

describe('standardDeviation', () => {
  it('returns 0 for empty array', () => expect(standardDeviation([])).toBe(0));
  it('returns 0 for identical values', () => expect(standardDeviation([5, 5, 5])).toBe(0));
  it('computes population stddev', () => {
    // stddev of [2, 4, 4, 4, 5, 5, 7, 9] = 2.0
    expect(standardDeviation([2, 4, 4, 4, 5, 5, 7, 9])).toBeCloseTo(2.0, 1);
  });
});

// ── classifyFrame ─────────────────────────────────────────────────────────────

describe('classifyFrame', () => {
  const threshold = 0.5;
  const onMean = 0.8;
  const offMean = 0.2;

  it('classifies value well above threshold as ON', () => {
    const r = classifyFrame(0.75, threshold, onMean, offMean);
    expect(r.state).toBe('on');
    expect(r.confidence).toBeGreaterThan(0.15);
  });

  it('classifies value well below threshold as OFF', () => {
    const r = classifyFrame(0.25, threshold, onMean, offMean);
    expect(r.state).toBe('off');
    expect(r.confidence).toBeGreaterThan(0.15);
  });

  it('classifies value near threshold as UNKNOWN (low confidence)', () => {
    const r = classifyFrame(0.51, threshold, onMean, offMean, 0.15);
    expect(r.state).toBe('unknown');
    expect(r.confidence).toBeLessThan(0.15);
  });

  it('confidence scales with distance from threshold', () => {
    const far = classifyFrame(0.9, threshold, onMean, offMean);
    const near = classifyFrame(0.55, threshold, onMean, offMean);
    expect(far.confidence).toBeGreaterThan(near.confidence);
  });

  it('handles zero on/off range gracefully (uses eps)', () => {
    const r = classifyFrame(0.6, 0.5, 0.5, 0.5);
    expect(r.state).toBeDefined();
    // Should not throw
  });
});

// ── classifyFrameWithPercentiles ──────────────────────────────────────────────

describe('classifyFrameWithPercentiles', () => {
  it('returns unknown for empty allScores', () => {
    const r = classifyFrameWithPercentiles(0.5, 0.5, []);
    expect(r.state).toBe('unknown');
    expect(r.confidence).toBe(0);
  });

  it('classifies using percentile-based range', () => {
    const allScores = [];
    for (let i = 0; i < 100; i++) allScores.push(i / 100);
    const r = classifyFrameWithPercentiles(0.9, 0.5, allScores);
    expect(r.state).toBe('on');
    expect(r.range).toBeGreaterThan(0);
  });

  it('marks ambiguous values as unknown', () => {
    const allScores = [];
    for (let i = 0; i < 100; i++) allScores.push(0.5 + (Math.random() - 0.5) * 0.001);
    const r = classifyFrameWithPercentiles(0.5, 0.5, allScores, 0.15);
    // With very tight range, value at threshold is unknown
    expect(r.state).toBe('unknown');
  });
});

// ── getStableState ────────────────────────────────────────────────────────────

describe('getStableState', () => {
  it('returns null until buffer fills', () => {
    const buf = [];
    expect(getStableState('on', buf, 3)).toBeNull();
    expect(getStableState('on', buf, 3)).toBeNull();
  });

  it('returns state when N consecutive agree', () => {
    const buf = [];
    getStableState('on', buf, 3);
    getStableState('on', buf, 3);
    const result = getStableState('on', buf, 3);
    expect(result).toBe('on');
  });

  it('returns null when samples disagree', () => {
    const buf = [];
    getStableState('on', buf, 3);
    getStableState('off', buf, 3);
    const result = getStableState('on', buf, 3);
    expect(result).toBeNull();
  });

  it('returns null when buffer is all unknown', () => {
    const buf = [];
    getStableState('unknown', buf, 3);
    getStableState('unknown', buf, 3);
    const result = getStableState('unknown', buf, 3);
    expect(result).toBeNull();
  });

  it('uses default requiredConsecutive=3', () => {
    const buf = [];
    getStableState('off', buf);
    getStableState('off', buf);
    const result = getStableState('off', buf);
    expect(result).toBe('off');
  });
});

// ── QualityMetrics ────────────────────────────────────────────────────────────

describe('QualityMetrics', () => {
  it('starts with zero counters', () => {
    const m = new QualityMetrics();
    const s = m.getSummary();
    expect(s.frames_total).toBe(0);
    expect(s.quality_score).toBe(0);
  });

  it('tracks confident and uncertain frames', () => {
    const m = new QualityMetrics();
    m.recordFrame({ state: 'on', confidence: 0.5 });
    m.recordFrame({ state: 'off', confidence: 0.6 });
    m.recordFrame({ state: 'unknown', confidence: 0.05 });
    expect(m.getSummary().frames_confident).toBe(2);
    expect(m.getSummary().frames_uncertain).toBe(1);
  });

  it('counts transitions', () => {
    const m = new QualityMetrics();
    m.recordFrame({ state: 'on' });
    m.recordFrame({ state: 'off' }); // transition
    m.recordFrame({ state: 'off' }); // no transition
    m.recordFrame({ state: 'on' }); // transition
    expect(m.getSummary().transitions_detected).toBe(2);
  });

  it('records CRC passes and fails', () => {
    const m = new QualityMetrics();
    m.recordCRC(true);
    m.recordCRC(true);
    m.recordCRC(false);
    const s = m.getSummary();
    expect(s.crc_passes).toBe(2);
    expect(s.crc_fails).toBe(1);
    expect(parseFloat(s.crc_pass_rate)).toBeCloseTo(66.7, 0);
  });

  it('computes quality score (70% confidence + 30% CRC)', () => {
    const m = new QualityMetrics();
    // All frames confident, all CRCs pass
    for (let i = 0; i < 10; i++) {
      m.recordFrame({ state: 'on' });
      m.recordCRC(true);
    }
    expect(m.getQualityScore()).toBe(100);
  });

  it('reset clears everything', () => {
    const m = new QualityMetrics();
    m.recordFrame({ state: 'on' });
    m.recordCRC(true);
    m.reset();
    expect(m.getSummary().frames_total).toBe(0);
    expect(m.getSummary().crc_passes).toBe(0);
  });
});

// ── learnDistributionsFromPreamble ────────────────────────────────────────────

describe('learnDistributionsFromPreamble', () => {
  it('returns null when no on or off samples', () => {
    const frames = [{ state: 'unknown', greenScore: 0.5 }];
    expect(learnDistributionsFromPreamble(frames, { start: 0, end: 1 })).toBeNull();
  });

  it('learns on/off distributions from alternating frames', () => {
    const frames = [];
    for (let i = 0; i < 20; i++) {
      frames.push({
        state: i % 2 === 0 ? 'on' : 'off',
        greenScore: i % 2 === 0 ? 0.8 : 0.2,
      });
    }
    const result = learnDistributionsFromPreamble(frames, { start: 0, end: 20 });
    expect(result).not.toBeNull();
    expect(result.onMean).toBeCloseTo(0.8, 1);
    expect(result.offMean).toBeCloseTo(0.2, 1);
    expect(result.threshold).toBeCloseTo(0.5, 1);
    expect(result.range).toBeCloseTo(0.6, 1);
  });
});

// ── detectPreamble (from quality-metrics.js) ──────────────────────────────────

describe('detectPreamble (quality-metrics)', () => {
  it('returns null for too few frames', () => {
    const frames = Array.from({ length: 10 }, (_, i) => ({
      state: i % 2 === 0 ? 'on' : 'off',
      time: i * 0.1,
    }));
    expect(detectPreamble(frames, 0.8, 50)).toBeNull();
  });

  it('detects high-rate alternating region', () => {
    const frames = [];
    for (let i = 0; i < 60; i++) {
      frames.push({ state: i % 2 === 0 ? 'on' : 'off', time: i * 0.1 });
    }
    const result = detectPreamble(frames, 0.8, 50);
    expect(result).not.toBeNull();
    expect(result.start).toBeDefined();
    expect(result.end).toBeDefined();
  });
});
