/**
 * deriveExpectedFrames.test.ts — verifies the frame-count derivation used to
 * start capture straight from a looping transfer QR (no setup QR needed).
 *
 * The frame strings here mirror the real web-demo / CLI formats documented in
 * webDemoIntegration.test.ts and parsed by qrDecoder.ts.
 */

import { deriveExpectedFramesFromFrame } from '../src/services/qrDecoder';

describe('deriveExpectedFramesFromFrame', () => {
  it('reads k (source block count) from a real FOUNTAIN frame', () => {
    // FOUNTAIN:<k>:<blockSize>:<originalLength>:<base64(droplet)>
    expect(deriveExpectedFramesFromFrame('FOUNTAIN:44:600:4523:AABBCCDD==')).toBe(44);
    expect(deriveExpectedFramesFromFrame('FOUNTAIN:66:512:9001:Zm9vYmFy')).toBe(66);
  });

  it('reads total from legacy chunked frames', () => {
    expect(deriveExpectedFramesFromFrame('MEOW-1/12:Zm9v')).toBe(12);
    expect(deriveExpectedFramesFromFrame('DURESS-3/8:YmFy')).toBe(8);
  });

  it('treats single-frame payloads as one frame', () => {
    expect(deriveExpectedFramesFromFrame('MEOW:Zm9vYmFy')).toBe(1);
    expect(deriveExpectedFramesFromFrame('FS:Zm9v')).toBe(1);
    expect(deriveExpectedFramesFromFrame('QUANTUM:Zm9v')).toBe(1);
    expect(deriveExpectedFramesFromFrame('HYBRID-PQ:Zm9v')).toBe(1);
    expect(deriveExpectedFramesFromFrame('DURESS:Zm9v')).toBe(1);
  });

  it('returns null for non-meow QR and malformed FOUNTAIN counts', () => {
    expect(deriveExpectedFramesFromFrame('https://example.com')).toBeNull();
    expect(deriveExpectedFramesFromFrame('{"some":"json"}')).toBeNull();
    expect(deriveExpectedFramesFromFrame('FOUNTAIN:notanumber:1:2:zz')).toBeNull();
    expect(deriveExpectedFramesFromFrame('')).toBeNull();
  });

  it('clamps absurd counts to the 10,000 schema bound', () => {
    expect(deriveExpectedFramesFromFrame('FOUNTAIN:999999:1:2:zz')).toBe(10_000);
  });
});
