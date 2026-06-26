/**
 * polyfills.test.ts — verifies the Hermes TextEncoder/TextDecoder shims install
 * and round-trip UTF-8 correctly (incl. multi-byte). The qrcode lib used on the
 * export screen relies on `new TextEncoder().encode()` returning real UTF-8.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

describe('polyfills', () => {
  it('installs a working TextEncoder/TextDecoder when missing (Hermes)', () => {
    const g = globalThis as any;
    const origEnc = g.TextEncoder;
    const origDec = g.TextDecoder;
    try {
      // Simulate Hermes: neither API present.
      g.TextEncoder = undefined;
      g.TextDecoder = undefined;
      jest.resetModules();
      require('../src/polyfills');

      const enc = new g.TextEncoder();
      expect(Array.from(enc.encode('AB'))).toEqual([65, 66]); // ASCII
      expect(Array.from(enc.encode('é'))).toEqual([0xc3, 0xa9]); // UTF-8 multi-byte
      expect(Array.from(enc.encode('🐱'))).toEqual([0xf0, 0x9f, 0x90, 0xb1]); // emoji

      const dec = new g.TextDecoder();
      expect(dec.decode(enc.encode('Hello 🐱 é'))).toBe('Hello 🐱 é');
    } finally {
      g.TextEncoder = origEnc;
      g.TextDecoder = origDec;
    }
  });
});
