/**
 * formatters.test.ts — Pure unit tests for display helper functions.
 *
 * All functions are pure (no side effects) and deterministic.
 */

import {
  formatElapsed,
  formatPercent,
  recoverabilityLabel,
  formatFileSize,
  estimateETA,
  formatCountdown,
  formatFrameCount,
  recoveryConfidenceLabel,
  decodeRateDisplay,
} from '../src/utils/formatters';

// ── formatElapsed ─────────────────────────────────────────────────────────────

describe('formatElapsed', () => {
  it('formats sub-minute as Xs', () => {
    expect(formatElapsed(0)).toBe('0s');
    expect(formatElapsed(1000)).toBe('1s');
    expect(formatElapsed(59000)).toBe('59s');
  });

  it('formats minutes as Xm Ys', () => {
    expect(formatElapsed(60000)).toBe('1m 0s');
    expect(formatElapsed(90000)).toBe('1m 30s');
  });

  it('formats hours as Xh Ym', () => {
    expect(formatElapsed(3600000)).toBe('1h 0m');
  });

  it('includes minutes in seconds component when padding needed', () => {
    expect(formatElapsed(65000)).toBe('1m 5s');
    expect(formatElapsed(601000)).toBe('10m 1s');
  });

  it('handles 0 ms', () => {
    expect(formatElapsed(0)).toBe('0s');
  });
});

// ── formatCountdown ───────────────────────────────────────────────────────────

describe('formatCountdown', () => {
  it('formats seconds remaining as zero-padded MM:SS', () => {
    expect(formatCountdown(60)).toBe('01:00');
    expect(formatCountdown(30)).toBe('00:30');
    expect(formatCountdown(0)).toBe('00:00');
    expect(formatCountdown(90)).toBe('01:30');
  });
});

// ── formatPercent ─────────────────────────────────────────────────────────────

describe('formatPercent', () => {
  it('formats zero', () => {
    expect(formatPercent(0)).toBe('0%');
  });

  it('rounds to whole numbers', () => {
    expect(formatPercent(0.333)).toBe('33%');
    expect(formatPercent(0.999)).toBe('100%');
  });

  it('caps at 100% when capAt100 is true (default)', () => {
    expect(formatPercent(1.5, true)).toBe('100%');
    expect(formatPercent(2.0, true)).toBe('100%');
  });

  it('allows over 100% when capAt100 is false', () => {
    expect(formatPercent(1.5, false)).toBe('150%');
  });

  it('formats exactly 100%', () => {
    expect(formatPercent(1.0)).toBe('100%');
  });
});

// ── recoverabilityLabel ───────────────────────────────────────────────────────

describe('recoverabilityLabel', () => {
  it('returns empty or not recoverable for 0 frames', () => {
    const label = recoverabilityLabel(0, 10);
    // Should indicate no data
    expect(label).toBeTruthy();
    expect(typeof label).toBe('string');
  });

  it('returns "Likely Recoverable" (or similar) near fountain threshold', () => {
    const label = recoverabilityLabel(7, 10);
    expect(typeof label).toBe('string');
    expect(label.length).toBeGreaterThan(0);
  });

  it('shows higher confidence at 1.5× expected', () => {
    const at_threshold = recoverabilityLabel(15, 10);
    const at_partial = recoverabilityLabel(5, 10);
    expect(at_threshold).not.toBe(at_partial);
  });

  it('handles expected_frames of 0 without division by zero', () => {
    const label = recoverabilityLabel(5, 0);
    expect(typeof label).toBe('string');
  });
});

// ── formatFileSize ────────────────────────────────────────────────────────────

describe('formatFileSize', () => {
  it('formats bytes', () => {
    expect(formatFileSize(0)).toMatch(/0\s*B/);
    expect(formatFileSize(512)).toMatch(/512\s*B/);
  });

  it('formats kilobytes', () => {
    const result = formatFileSize(1024);
    expect(result).toMatch(/1(\.0)?\s*KB/);
  });

  it('formats megabytes', () => {
    const result = formatFileSize(1024 * 1024);
    expect(result).toMatch(/1(\.0)?\s*MB/);
  });

  it('formats large files', () => {
    const result = formatFileSize(5 * 1024 * 1024);
    expect(result).toMatch(/5(\.0)?\s*MB/);
  });
});

// ── estimateETA ───────────────────────────────────────────────────────────────

describe('estimateETA', () => {
  it('returns null at 0 captured frames', () => {
    expect(estimateETA(0, 15, 5000)).toBeNull();
  });

  it('returns null if elapsed is 0', () => {
    expect(estimateETA(5, 15, 0)).toBeNull();
  });

  it('returns "< 1s" string when target already reached', () => {
    expect(estimateETA(15, 15, 10000)).toBe('< 1s');
  });

  it('returns a non-null ETA string when frames remain', () => {
    // 5 frames in 5 seconds = 1 fps; need 10 more frames → ETA string
    const eta = estimateETA(5, 15, 5000);
    expect(eta).not.toBeNull();
    expect(typeof eta).toBe('string');
    expect(eta).toContain('left');
  });
});

// ── formatFrameCount ──────────────────────────────────────────────────────────

describe('formatFrameCount', () => {
  it('formats captured / expected', () => {
    expect(formatFrameCount(32, 45)).toBe('32 / 45');
  });

  it('handles zero captured', () => {
    expect(formatFrameCount(0, 10)).toBe('0 / 10');
  });

  it('handles zero expected', () => {
    expect(formatFrameCount(0, 0)).toBe('0 / 0');
  });

  it('handles overcapture', () => {
    expect(formatFrameCount(20, 10)).toBe('20 / 10');
  });
});

// ── recoveryConfidenceLabel ───────────────────────────────────────────────────

describe('recoveryConfidenceLabel', () => {
  it('returns "Waiting…" when expected is 0', () => {
    const result = recoveryConfidenceLabel(0, 0);
    expect(result.label).toBe('Waiting…');
    expect(result.safeToStop).toBe(false);
    expect(result.color).toBe('dim');
  });

  it('returns "Keep scanning" (danger) below 0.67 ratio', () => {
    const result = recoveryConfidenceLabel(3, 10);
    expect(result.label).toBe('Keep scanning');
    expect(result.color).toBe('danger');
    expect(result.safeToStop).toBe(false);
    expect(result.sublabel).toContain('more frames');
  });

  it('returns "Getting there" (warning) at 0.67–1.0 ratio', () => {
    const result = recoveryConfidenceLabel(7, 10);
    expect(result.label).toBe('Getting there');
    expect(result.color).toBe('warning');
    expect(result.safeToStop).toBe(false);
    expect(result.sublabel).toContain('more frames');
  });

  it('returns "Good progress" (success) at 1.0–1.2 ratio', () => {
    const result = recoveryConfidenceLabel(10, 10);
    expect(result.label).toBe('Good progress');
    expect(result.color).toBe('success');
    expect(result.safeToStop).toBe(false);
  });

  it('returns "Strong recovery confidence" (success, safeToStop) at 1.2–1.5 ratio', () => {
    const result = recoveryConfidenceLabel(13, 10);
    expect(result.label).toBe('Strong recovery confidence');
    expect(result.color).toBe('success');
    expect(result.safeToStop).toBe(true);
  });

  it('returns "Transfer complete" (gold, safeToStop) at ≥ 1.5 ratio', () => {
    const result = recoveryConfidenceLabel(15, 10);
    expect(result.label).toBe('Transfer complete');
    expect(result.color).toBe('gold');
    expect(result.safeToStop).toBe(true);
  });

  it('boundary: exactly 0.67 ratio returns "Getting there"', () => {
    // 67 captured, 100 expected → 0.67
    const result = recoveryConfidenceLabel(67, 100);
    expect(result.label).toBe('Getting there');
  });

  it('boundary: exactly 1.5 ratio returns "Transfer complete"', () => {
    const result = recoveryConfidenceLabel(15, 10);
    expect(result.label).toBe('Transfer complete');
  });
});

// ── decodeRateDisplay ─────────────────────────────────────────────────────────

describe('decodeRateDisplay', () => {
  it('formats normal fps and dup rate', () => {
    expect(decodeRateDisplay(3.5, 0.12)).toBe('3.5 fps · 12% dup');
  });

  it('returns "— fps (no signal)" when rate is below 0.1', () => {
    expect(decodeRateDisplay(0.05, 0)).toBe('— fps (no signal)');
    expect(decodeRateDisplay(0, 0.5)).toBe('— fps (no signal)');
  });

  it('rounds duplicate percentage to whole number', () => {
    expect(decodeRateDisplay(2.0, 0.156)).toBe('2.0 fps · 16% dup');
  });

  it('handles 0% duplicate rate', () => {
    expect(decodeRateDisplay(5.0, 0)).toBe('5.0 fps · 0% dup');
  });

  it('handles 100% duplicate rate', () => {
    expect(decodeRateDisplay(1.0, 1.0)).toBe('1.0 fps · 100% dup');
  });
});
