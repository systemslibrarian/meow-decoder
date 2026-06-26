/**
 * catWhitening.test.ts — verifies the Cat Mode whitening port is bit-true.
 *
 * Two guarantees are tested:
 *   1. Self-inverse: dewhiten(whiten(x)) === x for arbitrary binary.
 *   2. Bit-for-bit agreement with the transmitter's `whitenBinary()`
 *      (copied verbatim from web_demo/cat_mode.html as an independent oracle).
 * If the port ever drifts from the transmitter, (2) fails loudly.
 */

import { whiten, dewhiten } from '../src/services/catWhitening';

/**
 * Independent reference — copied verbatim from web_demo/cat_mode.html's
 * whitenBinary(). Do NOT refactor to share code with the implementation under
 * test; its value is being a second, independent witness.
 */
function referenceWhitenBinary(binaryStr: string): string {
  let seed = 0x4d454f57; // "MEOW" in hex
  let result = '';
  for (let i = 0; i < binaryStr.length; i++) {
    const lo = Math.imul(seed, 1103515245);
    seed = ((lo >>> 0) + 12345) & 0x7fffffff;
    const mask = (seed >>> 16) & 1;
    result += String(parseInt(binaryStr[i] as string, 10) ^ mask);
  }
  return result;
}

function randomBinary(len: number, seed: number): string {
  // Deterministic pseudo-random binary so the test is reproducible.
  let s = seed >>> 0;
  let out = '';
  for (let i = 0; i < len; i++) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    out += (s >>> 31) & 1 ? '1' : '0';
  }
  return out;
}

describe('catWhitening', () => {
  it('is self-inverse (dewhiten(whiten(x)) === x)', () => {
    for (let len = 0; len <= 200; len += 37) {
      const x = randomBinary(len, len + 1);
      expect(dewhiten(whiten(x))).toBe(x);
    }
  });

  it('matches the transmitter whitenBinary() bit-for-bit', () => {
    const cases = [
      '',
      '0',
      '1',
      '0000000000000000', // long zero run — the case whitening exists to fix
      '1111111111111111',
      '0101010101010101',
      randomBinary(256, 12345),
      randomBinary(1024, 99),
    ];
    for (const c of cases) {
      expect(whiten(c)).toBe(referenceWhitenBinary(c));
    }
  });

  it('preserves length', () => {
    const x = randomBinary(513, 7);
    expect(whiten(x)).toHaveLength(513);
  });
});
