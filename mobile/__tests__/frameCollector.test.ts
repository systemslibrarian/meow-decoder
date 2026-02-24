/**
 * frameCollector.test.ts — Unit tests for the FrameCollector service.
 *
 * Tests O(1) dedup, capacity limit, sorted retrieval, and stat tracking.
 */

import { FrameCollector } from '../src/services/frameCollector';
import type { CapturedFrame } from '../src/types/capture';

const makeFrame = (index: number, data = 'AAAA'): CapturedFrame => ({
  index,
  data,
  timestamp_ms: 1000 + index,
});

describe('FrameCollector — basic add', () => {
  it('starts empty', () => {
    const c = new FrameCollector();
    expect(c.size).toBe(0);
    expect(c.stats.accepted).toBe(0);
  });

  it('accepts a new frame and returns "accepted"', () => {
    const c = new FrameCollector();
    const result = c.add(makeFrame(0));
    expect(result).toBe('accepted');
    expect(c.size).toBe(1);
    expect(c.stats.accepted).toBe(1);
  });

  it('returns "duplicate" for same index', () => {
    const c = new FrameCollector();
    c.add(makeFrame(5));
    const result = c.add(makeFrame(5, 'DIFFERENT_DATA'));
    expect(result).toBe('duplicate');
    expect(c.size).toBe(1);
    expect(c.stats.duplicates).toBe(1);
    // First data wins
    expect(c.getSorted()[0]?.data).toBe('AAAA');
  });

  it('accepts many unique frames', () => {
    const c = new FrameCollector();
    for (let i = 0; i < 100; i++) {
      const result = c.add(makeFrame(i));
      expect(result).toBe('accepted');
    }
    expect(c.size).toBe(100);
  });
});

describe('FrameCollector — capacity limit', () => {
  it('rejects frames beyond 10,000 limit', () => {
    const c = new FrameCollector();
    for (let i = 0; i < 10_000; i++) {
      c.add(makeFrame(i));
    }
    expect(c.size).toBe(10_000);
    const result = c.add(makeFrame(10_000));
    expect(result).toBe('rejected');
    expect(c.size).toBe(10_000);
    expect(c.stats.rejected).toBe(1);
  });
});

describe('FrameCollector — getSorted', () => {
  it('returns frames sorted by index ascending', () => {
    const c = new FrameCollector();
    c.add(makeFrame(7));
    c.add(makeFrame(2));
    c.add(makeFrame(14));
    c.add(makeFrame(0));
    const sorted = c.getSorted();
    expect(sorted.map(f => f.index)).toEqual([0, 2, 7, 14]);
  });

  it('returns empty array when no frames', () => {
    const c = new FrameCollector();
    expect(c.getSorted()).toEqual([]);
  });
});

describe('FrameCollector — clear', () => {
  it('clears all frames and resets stats', () => {
    const c = new FrameCollector();
    c.add(makeFrame(0));
    c.add(makeFrame(1));
    c.add(makeFrame(1)); // duplicate
    c.clear();
    expect(c.size).toBe(0);
    expect(c.stats.accepted).toBe(0);
    expect(c.stats.duplicates).toBe(0);
    expect(c.stats.rejected).toBe(0);
    expect(c.getSorted()).toEqual([]);
  });
});

describe('FrameCollector — stats', () => {
  it('tracks all categories independently', () => {
    const c = new FrameCollector();
    c.add(makeFrame(0));        // accepted
    c.add(makeFrame(1));        // accepted
    c.add(makeFrame(0));        // duplicate

    expect(c.stats.accepted).toBe(2);
    expect(c.stats.duplicates).toBe(1);
    expect(c.stats.rejected).toBe(0);
  });
});

describe('FrameCollector — hasIndex', () => {
  it('returns true for existing index', () => {
    const c = new FrameCollector();
    c.add(makeFrame(42));
    expect(c.hasIndex(42)).toBe(true);
  });

  it('returns false for missing index', () => {
    const c = new FrameCollector();
    expect(c.hasIndex(99)).toBe(false);
  });
});
