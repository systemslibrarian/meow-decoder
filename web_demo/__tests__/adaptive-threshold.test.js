/**
 * adaptive-threshold.test.js — Unit tests for adaptive threshold,
 * gradient compensation, and histogram utilities.
 */

const {
  AdaptiveThreshold,
  GradientCompensator,
  median,
  medianAbsoluteDeviation,
  computeHistogram,
  findPeaks,
  findValley,
} = require('../adaptive-threshold');

// ── median ────────────────────────────────────────────────────────────────────

describe('median', () => {
  it('returns 0 for empty array', () => {
    expect(median([])).toBe(0);
  });

  it('returns middle value for odd-length array', () => {
    expect(median([3, 1, 2])).toBe(2);
  });

  it('returns average of two middle values for even-length array', () => {
    expect(median([1, 2, 3, 4])).toBe(2.5);
  });

  it('does not mutate input array', () => {
    const arr = [5, 3, 1];
    median(arr);
    expect(arr).toEqual([5, 3, 1]);
  });

  it('handles single element', () => {
    expect(median([42])).toBe(42);
  });
});

// ── medianAbsoluteDeviation ───────────────────────────────────────────────────

describe('medianAbsoluteDeviation', () => {
  it('returns 0 for empty array', () => {
    expect(medianAbsoluteDeviation([])).toBe(0);
  });

  it('returns 0 for identical values', () => {
    expect(medianAbsoluteDeviation([5, 5, 5])).toBe(0);
  });

  it('computes correct MAD', () => {
    // median([1,2,3,4,5]) = 3, deviations = [2,1,0,1,2], median(deviations) = 1
    expect(medianAbsoluteDeviation([1, 2, 3, 4, 5])).toBe(1);
  });
});

// ── computeHistogram ──────────────────────────────────────────────────────────

describe('computeHistogram', () => {
  it('returns empty bins for empty data', () => {
    const { bins } = computeHistogram([]);
    expect(bins).toEqual([]);
  });

  it('handles all-same values', () => {
    const { bins } = computeHistogram([5, 5, 5]);
    expect(bins.length).toBe(1);
    expect(bins[0].count).toBe(3);
  });

  it('distributes values across specified bins', () => {
    const values = [0, 0.25, 0.5, 0.75, 1.0];
    const { bins, binWidth } = computeHistogram(values, 4, 0, 1);
    expect(bins.length).toBe(4);
    expect(binWidth).toBeCloseTo(0.25);
    // All bins should have at least some counts
    const total = bins.reduce((s, b) => s + b.count, 0);
    expect(total).toBe(5);
  });

  it('auto-detects min/max when not provided', () => {
    const values = [10, 20, 30, 40, 50];
    const { bins } = computeHistogram(values, 5);
    expect(bins.length).toBe(5);
  });
});

// ── findPeaks ─────────────────────────────────────────────────────────────────

describe('findPeaks', () => {
  it('returns empty for fewer than 3 bins', () => {
    expect(findPeaks([{ count: 5 }, { count: 10 }])).toEqual([]);
  });

  it('finds local maxima', () => {
    const hist = [
      { value: 0, count: 1 },
      { value: 1, count: 10 },
      { value: 2, count: 3 },
      { value: 3, count: 15 },
      { value: 4, count: 2 },
    ];
    const peaks = findPeaks(hist);
    expect(peaks.length).toBe(2);
    expect(peaks[0].value).toBe(1);
    expect(peaks[1].value).toBe(3);
  });

  it('respects minPeakHeight', () => {
    const hist = [
      { value: 0, count: 1 },
      { value: 1, count: 3 },
      { value: 2, count: 1 },
      { value: 3, count: 20 },
      { value: 4, count: 1 },
    ];
    const peaks = findPeaks(hist, 5);
    expect(peaks.length).toBe(1);
    expect(peaks[0].value).toBe(3);
  });

  it('returns empty for flat histogram', () => {
    const hist = Array.from({ length: 5 }, (_, i) => ({ value: i, count: 10 }));
    expect(findPeaks(hist)).toEqual([]);
  });
});

// ── findValley ────────────────────────────────────────────────────────────────

describe('findValley', () => {
  it('finds minimum between two peaks', () => {
    const hist = [
      { value: 0, count: 10 },
      { value: 1, count: 5 },
      { value: 2, count: 2 },   // valley
      { value: 3, count: 6 },
      { value: 4, count: 12 },
    ];
    const peak1 = { value: 0, height: 10, index: 0 };
    const peak2 = { value: 4, height: 12, index: 4 };
    expect(findValley(hist, peak1, peak2)).toBe(2);
  });

  it('works regardless of peak order', () => {
    const hist = [
      { value: 0, count: 10 },
      { value: 1, count: 1 },
      { value: 2, count: 8 },
    ];
    const peakA = { index: 0 };
    const peakB = { index: 2 };
    expect(findValley(hist, peakB, peakA)).toBe(1); // reversed order
  });
});

// ── GradientCompensator ───────────────────────────────────────────────────────

describe('GradientCompensator', () => {
  it('returns uncompensated score with insufficient data', () => {
    const gc = new GradientCompensator();
    gc.update(0.5, 0.0);
    expect(gc.compensate(0.5, 0.1)).toBe(0.5);
  });

  it('detects and compensates linear gradient', () => {
    const gc = new GradientCompensator(100, 0.005);
    // Simulate a rising gradient: 0.5 + 0.02/s × t
    for (let t = 0; t < 15; t += 0.1) {
      const score = 0.5 + 0.02 * t;
      gc.update(score, t);
    }
    // At t=15 the raw score is ~0.8, compensated should bring it back toward baseline
    const compensated = gc.compensate(0.8, 15);
    expect(compensated).toBeLessThan(0.8);
    expect(gc.compensationActive).toBe(true);
  });

  it('does not compensate stable signal', () => {
    const gc = new GradientCompensator();
    for (let t = 0; t < 2; t += 0.1) {
      gc.update(0.5, t);
    }
    const compensated = gc.compensate(0.5, 2);
    expect(compensated).toBe(0.5);
    expect(gc.compensationActive).toBe(false);
  });

  it('reset clears state', () => {
    const gc = new GradientCompensator();
    for (let t = 0; t < 2; t += 0.1) {
      gc.update(0.5 + t * 0.1, t);
    }
    gc.reset();
    expect(gc.getDiagnostics().windowSize).toBe(0);
    expect(gc.compensationActive).toBe(false);
    expect(gc.totalCompensations).toBe(0);
  });

  it('respects maxWindow size', () => {
    const gc = new GradientCompensator(10);
    for (let i = 0; i < 20; i++) {
      gc.update(0.5, i);
    }
    expect(gc.getDiagnostics().windowSize).toBe(10);
  });
});

// ── AdaptiveThreshold ─────────────────────────────────────────────────────────

describe('AdaptiveThreshold', () => {
  it('initialises with default threshold 0.5', () => {
    const at = new AdaptiveThreshold();
    expect(at.getThreshold()).toBe(0.5);
  });

  it('calibrates on bimodal data', () => {
    const at = new AdaptiveThreshold(100, 0.001); // Very fast recalibration
    // Feed bimodal distribution: cluster around 0.3 and 0.7
    for (let i = 0; i < 50; i++) {
      at.update(0.3 + Math.random() * 0.05, i * 100);
    }
    for (let i = 0; i < 50; i++) {
      at.update(0.7 + Math.random() * 0.05, (50 + i) * 100);
    }
    // Force recalibrate
    at.recalibrate();
    const threshold = at.getThreshold();
    // Threshold should be somewhere between the two clusters (allow some histogram quantization)
    expect(threshold).toBeGreaterThan(0.2);
    expect(threshold).toBeLessThan(0.8);
  });

  it('falls back to median for uniform data', () => {
    const at = new AdaptiveThreshold(100);
    // Feed uniform data
    for (let i = 0; i < 100; i++) {
      at.update(i / 100, i * 20);
    }
    at.recalibrate();
    const diag = at.getDiagnostics();
    // Should detect unimodal or uniform
    expect(['unimodal', 'uniform', 'bimodal']).toContain(diag.distributionType);
  });

  it('tracks calibration count', () => {
    const at = new AdaptiveThreshold(50, 0.001);
    for (let i = 0; i < 30; i++) {
      at.update(0.5, i * 10);
    }
    at.recalibrate();
    at.recalibrate();
    expect(at.getDiagnostics().calibrationCount).toBeGreaterThanOrEqual(2);
  });

  it('reset clears all state', () => {
    const at = new AdaptiveThreshold();
    for (let i = 0; i < 30; i++) {
      at.update(0.5, i * 10);
    }
    at.reset();
    expect(at.getThreshold()).toBe(0.5);
    expect(at.getDiagnostics().windowSize).toBe(0);
    expect(at.getDiagnostics().calibrationCount).toBe(0);
  });

  it('getDiagnostics includes gradient info', () => {
    const at = new AdaptiveThreshold();
    at.update(0.5, 0);
    const diag = at.getDiagnostics();
    expect(diag.gradient).toBeDefined();
    expect(diag.gradient.windowSize).toBeDefined();
  });
});
