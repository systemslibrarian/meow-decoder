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
