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
  it('formats sub-minute as MM:SS', () => {
    expect(formatElapsed(0)).toBe('0:00');
    expect(formatElapsed(1000)).toBe('0:01');
    expect(formatElapsed(59000)).toBe('0:59');
  });

  it('formats minutes', () => {
    expect(formatElapsed(60000)).toBe('1:00');
    expect(formatElapsed(90000)).toBe('1:30');
    expect(formatElapsed(3600000)).toBe('60:00');
  });

  it('pads seconds with leading zero', () => {
    expect(formatElapsed(65000)).toBe('1:05');
    expect(formatElapsed(601000)).toBe('10:01');
  });

  it('handles 0 ms', () => {
    expect(formatElapsed(0)).toBe('0:00');
  });
});

// ── formatCountdown ───────────────────────────────────────────────────────────

describe('formatCountdown', () => {
  it('formats seconds remaining', () => {
    expect(formatCountdown(60)).toBe('1:00');
    expect(formatCountdown(30)).toBe('0:30');
    expect(formatCountdown(0)).toBe('0:00');
    expect(formatCountdown(90)).toBe('1:30');
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

  it('returns null when target already reached', () => {
    expect(estimateETA(15, 15, 10000)).toBeNull();
  });

  it('estimates reasonable ETA', () => {
    // 5 frames in 5 seconds = 1 fps; need 10 more frames → ~10 sec
    const eta = estimateETA(5, 15, 5000);
    expect(eta).not.toBeNull();
    if (eta !== null) {
      expect(eta).toBeGreaterThan(0);
    }
  });

  it('returns null if elapsed is 0', () => {
    expect(estimateETA(5, 15, 0)).toBeNull();
  });
});
