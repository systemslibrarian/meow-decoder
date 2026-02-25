/**
 * nrz-decoder.test.js — Unit tests for NRZ timing decoder.
 */

const {
  sampleBits,
  findNearestFrame,
  voteWithinBitWindow,
  resolveUnknownBits,
  findSyncWord,
} = require('../nrz-decoder');

// ── Test fixtures ─────────────────────────────────────────────────────────────

/** Build a simple frame sequence with known on/off pattern. */
function makeFrames(bitPattern, bitPeriod, startTime = 0) {
  const frames = [];
  for (let b = 0; b < bitPattern.length; b++) {
    // 3 frames per bit window for decent resolution
    for (let sub = 0; sub < 3; sub++) {
      const t = startTime + b * bitPeriod + sub * (bitPeriod / 3);
      frames.push({
        time: t,
        state: bitPattern[b] === 1 ? 'on' : 'off',
        confidence: 0.9,
        greenScore: bitPattern[b] === 1 ? 0.8 : 0.2,
      });
    }
  }
  return frames;
}

// ── sampleBits ────────────────────────────────────────────────────────────────

describe('sampleBits', () => {
  it('samples known alternating pattern', () => {
    const pattern = [1, 0, 1, 0, 1, 0];
    const frames = makeFrames(pattern, 0.1);
    const bits = sampleBits(frames, 0, 0.1, 6);
    expect(bits).toEqual([1, 0, 1, 0, 1, 0]);
  });

  it('samples all-ones', () => {
    const pattern = [1, 1, 1, 1];
    const frames = makeFrames(pattern, 0.1);
    const bits = sampleBits(frames, 0, 0.1, 4);
    expect(bits).toEqual([1, 1, 1, 1]);
  });

  it('samples all-zeros', () => {
    const pattern = [0, 0, 0, 0];
    const frames = makeFrames(pattern, 0.1);
    const bits = sampleBits(frames, 0, 0.1, 4);
    expect(bits).toEqual([0, 0, 0, 0]);
  });

  it('marks low-confidence frames as uncertain', () => {
    const frames = [
      { time: 0.05, state: 'on', confidence: 0.01 },
      { time: 0.15, state: 'off', confidence: 0.9 },
    ];
    const bits = sampleBits(frames, 0, 0.1, 2, 0.15);
    expect(bits[0]).toBe('?');
    expect(bits[1]).toBe(0);
  });

  it('handles empty frame array gracefully', () => {
    // sampleBits accesses frames[0] unconditionally — this is expected to throw
    // on empty input. Verify it does not silently return wrong data.
    expect(() => sampleBits([], 0, 0.1, 3)).toThrow();
  });
});

// ── findNearestFrame ──────────────────────────────────────────────────────────

describe('findNearestFrame', () => {
  const frames = [
    { time: 0.0 },
    { time: 0.1 },
    { time: 0.2 },
    { time: 0.3 },
    { time: 0.4 },
  ];

  it('returns null for empty array', () => {
    expect(findNearestFrame([], 0.1)).toBeNull();
  });

  it('returns the only frame for single-element array', () => {
    expect(findNearestFrame([{ time: 0.5 }], 0.0)).toEqual({ time: 0.5 });
  });

  it('finds exact match', () => {
    expect(findNearestFrame(frames, 0.2).time).toBe(0.2);
  });

  it('finds nearest before', () => {
    expect(findNearestFrame(frames, 0.14).time).toBe(0.1);
  });

  it('finds nearest after', () => {
    expect(findNearestFrame(frames, 0.16).time).toBe(0.2);
  });

  it('handles target before all frames', () => {
    expect(findNearestFrame(frames, -1.0).time).toBe(0.0);
  });

  it('handles target after all frames', () => {
    expect(findNearestFrame(frames, 10.0).time).toBe(0.4);
  });
});

// ── voteWithinBitWindow ───────────────────────────────────────────────────────

describe('voteWithinBitWindow', () => {
  it('returns 1 when majority of samples are ON', () => {
    const frames = makeFrames([1], 0.1, 0);
    const result = voteWithinBitWindow(frames, 0, 0.1, 0, 5);
    expect(result).toBe(1);
  });

  it('returns 0 when majority of samples are OFF', () => {
    const frames = makeFrames([0], 0.1, 0);
    const result = voteWithinBitWindow(frames, 0, 0.1, 0, 5);
    expect(result).toBe(0);
  });

  it('returns ? when no confident frames exist', () => {
    const frames = [
      { time: 0.025, state: 'on', confidence: 0.01 },
      { time: 0.05, state: 'off', confidence: 0.02 },
      { time: 0.075, state: 'on', confidence: 0.03 },
    ];
    const result = voteWithinBitWindow(frames, 0, 0.1, 0, 3, 0.15);
    expect(result).toBe('?');
  });
});

// ── resolveUnknownBits ────────────────────────────────────────────────────────

describe('resolveUnknownBits', () => {
  it('passes through known bits unchanged', () => {
    const bits = [1, 0, 1, 1, 0];
    const frames = makeFrames(bits, 0.1);
    const resolved = resolveUnknownBits(bits, frames, 0, 0.1, 'vote');
    expect(resolved).toEqual([1, 0, 1, 1, 0]);
  });

  it('repeat policy copies last known bit for unknowns', () => {
    const bits = [1, '?', '?', 0, '?'];
    const resolved = resolveUnknownBits(bits, [], 0, 0.1, 'repeat');
    expect(resolved).toEqual([1, 1, 1, 0, 0]);
  });

  it('uses default 0 when first bit is unknown (repeat)', () => {
    const bits = ['?', 1, 0];
    const resolved = resolveUnknownBits(bits, [], 0, 0.1, 'repeat');
    expect(resolved[0]).toBe(0);
  });

  it('vote policy resolves unknowns via majority', () => {
    // Build frames with clear ON at bit 1
    const pattern = [0, 1, 0];
    const frames = makeFrames(pattern, 0.1);
    const bits = [0, '?', 0];
    const resolved = resolveUnknownBits(bits, frames, 0, 0.1, 'vote');
    expect(resolved[1]).toBe(1);
  });
});

// ── findSyncWord ──────────────────────────────────────────────────────────────

describe('findSyncWord', () => {
  it('finds 8-bit sync pattern', () => {
    // Build 0xAA = 10101010
    const syncBits = [1, 0, 1, 0, 1, 0, 1, 0];
    const payload = [1, 1, 0, 0];
    const frames = makeFrames([...syncBits, ...payload], 0.1);

    const result = findSyncWord(frames, 0.1, 0, 5.0, { shortVideoMode: true });
    expect(result).not.toBeNull();
    expect(result.syncBits).toBe(8);
    expect(result.confidence).toBeGreaterThanOrEqual(0.75);
  });

  it('returns null when no sync pattern present', () => {
    const frames = makeFrames([1, 1, 1, 1, 1, 1, 1, 1], 0.1);
    const result = findSyncWord(frames, 0.1, 0, 2.0, { allowShortSync: true });
    expect(result).toBeNull();
  });

  it('finds 16-bit sync pattern when present', () => {
    // 0xAA55 = 16 alternating bits
    const syncBits = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0];
    const payload = [1, 1, 0, 0];
    const frames = makeFrames([...syncBits, ...payload], 0.1);

    const result = findSyncWord(frames, 0.1, 0, 5.0, { shortVideoMode: false });
    expect(result).not.toBeNull();
    expect(result.syncBits).toBe(16);
    expect(result.confidence).toBeGreaterThanOrEqual(0.75);
  });
});
