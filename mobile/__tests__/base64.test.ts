/**
 * base64.test.ts — Unit tests for base64 validation utilities.
 *
 * Validates WITHOUT decoding per the project security model.
 * Mobile app never decodes base64 — that's the desktop server's job.
 */

import {
  isValidBase64,
  estimateDecodedBytes,
  isValidDropletBase64,
} from '../src/utils/base64';

describe('isValidBase64', () => {
  describe('standard base64', () => {
    it('accepts empty string', () => {
      expect(isValidBase64('')).toBe(true);
    });

    it('accepts basic base64 without padding', () => {
      expect(isValidBase64('AAAA')).toBe(true);
    });

    it('accepts base64 with one padding char', () => {
      expect(isValidBase64('AA==')).toBe(true);
    });

    it('accepts base64 with two padding chars', () => {
      expect(isValidBase64('AAA=')).toBe(true);
    });

    it('accepts long real-world base64 string', () => {
      // 48 bytes of zero → 64 characters
      const b64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      expect(isValidBase64(b64)).toBe(true);
    });

    it('accepts + and / characters (standard base64 alphabet)', () => {
      // Padding must be at the end — 'ab+/AA==' is valid; '='-in-middle is not
      expect(isValidBase64('ab+/AA==')).toBe(true);
      expect(isValidBase64('aGVsbG8=')).toBe(true); // "hello"
    });
  });

  describe('URL-safe base64', () => {
    it('accepts - and _ as base64url variants', () => {
      expect(isValidBase64('abc-_AA')).toBe(true);
    });
  });

  describe('invalid base64', () => {
    it('rejects strings with spaces', () => {
      expect(isValidBase64('AA BB')).toBe(false);
    });

    it('rejects strings with invalid characters', () => {
      expect(isValidBase64('AA!!')).toBe(false);
    });

    it('rejects strings with null bytes', () => {
      expect(isValidBase64('AA\x00BB')).toBe(false);
    });
  });
});

describe('estimateDecodedBytes', () => {
  it('estimates 0 bytes for empty string', () => {
    expect(estimateDecodedBytes('')).toBe(0);
  });

  it('estimates 3 bytes from 4-char base64', () => {
    expect(estimateDecodedBytes('AAAA')).toBe(3);
  });

  it('estimates 6 bytes from 8-char base64', () => {
    expect(estimateDecodedBytes('AAAAAAAA')).toBe(6);
  });

  it('handles base64 with padding', () => {
    // AA== → 1 byte
    const result = estimateDecodedBytes('AA==');
    expect(result).toBeGreaterThan(0);
    expect(result).toBeLessThanOrEqual(3);
  });

  it('estimates correctly for 12 chars', () => {
    expect(estimateDecodedBytes('AAAAAAAAAAAA')).toBe(9);
  });

  it('scales linearly', () => {
    const a = estimateDecodedBytes('AAAA');     // 3
    const b = estimateDecodedBytes('AAAAAAAA'); // 6
    expect(b).toBe(a * 2);
  });
});

describe('isValidDropletBase64', () => {
  it('accepts a valid base64 string with minimum length', () => {
    // Need at least enough bytes for a fountain droplet header (seed + metadata)
    const valid = 'AAAAAAAAAAAAAAAAAAAAAA=='; // 16 bytes
    expect(isValidDropletBase64(valid)).toBe(true);
  });

  it('rejects empty string', () => {
    expect(isValidDropletBase64('')).toBe(false);
  });

  it('rejects single character', () => {
    expect(isValidDropletBase64('A')).toBe(false);
  });

  it('rejects invalid base64', () => {
    expect(isValidDropletBase64('!!!invalid!!!')).toBe(false);
  });
});
