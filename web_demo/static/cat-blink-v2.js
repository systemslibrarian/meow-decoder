/**
 * Cat Blink v2 — fountain-coded optical blink transport codec.
 *
 * Shared reference implementation for the wire format specified in
 * docs/CAT_BLINK_V2.md. Reuses the existing fountain droplet layout
 * (fountain-codes.js) so the blink path and QR path share one FEC layer.
 *
 * Pure functions over payload bytes ⇄ whitened bitstring. The physical blink
 * packing (eye states, preamble, loop timing) lives in the emitter/sampler;
 * this module is the byte/bit/frame/FEC layer and is unit-testable without a
 * camera.
 *
 * Works in the browser (loaded after fountain-codes.js) and in Node
 * (require('./fountain-codes.js')).
 */
(function (root, factory) {
  let Fountain;
  if (typeof module !== 'undefined' && module.exports) {
    Fountain = require('./fountain-codes.js');
    module.exports = factory(Fountain);
  } else {
    // Browser: fountain-codes.js defines these globals.
    Fountain = {
      FountainEncoder: root.FountainEncoder,
      FountainDecoder: root.FountainDecoder,
      Droplet: root.Droplet,
    };
    root.CatBlinkV2 = factory(Fountain);
  }
})(typeof self !== 'undefined' ? self : this, function (Fountain) {
  'use strict';

  const { FountainEncoder, FountainDecoder, Droplet } = Fountain;

  const SYNC = [0xb1, 0x17, 0x5e];
  const VERSION = 0x02;
  const HEADER_LEN = SYNC.length + 1 + 2 + 2 + 4; // sync+ver+k+bs+origlen = 12
  const CRC_LEN = 2;
  const WHITEN_SEED = 0x4d454f57; // "MEOW"

  // ── CRC-16/CCITT-FALSE ──────────────────────────────────────────────────
  function crc16(bytes, start, end) {
    let crc = 0xffff;
    for (let i = start; i < end; i++) {
      crc ^= bytes[i] << 8;
      for (let b = 0; b < 8; b++) {
        crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
      }
    }
    return crc & 0xffff;
  }

  // ── MEOW-LCG whitening (self-inverse), reseeded per call ─────────────────
  // Math.imul for the correct low-32-bit product: `seed * 1103515245`
  // overflows Number's 53-bit safe range, so a plain multiply desyncs from
  // the Python/mobile references. Matches catWhitening.ts and cat_video.py.
  function whitenBits(bitStr) {
    let seed = WHITEN_SEED;
    let out = '';
    for (let i = 0; i < bitStr.length; i++) {
      const lo = Math.imul(seed, 1103515245) >>> 0;
      seed = (lo + 12345) & 0x7fffffff;
      const mask = (seed >> 16) & 1;
      out += String((bitStr.charCodeAt(i) - 48) ^ mask);
    }
    return out;
  }
  const dewhitenBits = whitenBits; // self-inverse

  // ── byte ⇄ MSB-first bit helpers ─────────────────────────────────────────
  function bytesToBits(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += bytes[i].toString(2).padStart(8, '0');
    }
    return s;
  }
  function bitsToBytes(bitStr) {
    const n = bitStr.length >> 3;
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      out[i] = parseInt(bitStr.substr(i * 8, 8), 2);
    }
    return out;
  }

  // ── Frame one droplet ────────────────────────────────────────────────────
  function frameDroplet(dropletBytes, kBlocks, blockSize, originalLength) {
    const body = new Uint8Array(HEADER_LEN - SYNC.length + dropletBytes.length);
    const dv = new DataView(body.buffer);
    let o = 0;
    body[o++] = VERSION;
    dv.setUint16(o, kBlocks, false); o += 2;
    dv.setUint16(o, blockSize, false); o += 2;
    dv.setUint32(o, originalLength, false); o += 4;
    body.set(dropletBytes, o);

    const frame = new Uint8Array(SYNC.length + body.length + CRC_LEN);
    frame.set(SYNC, 0);
    frame.set(body, SYNC.length);
    const crc = crc16(frame, SYNC.length, SYNC.length + body.length);
    frame[frame.length - 2] = (crc >> 8) & 0xff;
    frame[frame.length - 1] = crc & 0xff;
    return frame;
  }

  /**
   * Encode a payload into `frameCount` whitened blink frames (bitstrings).
   * Returns { frames: string[], kBlocks, blockSize, originalLength }.
   */
  function encode(payloadBytes, opts = {}) {
    const blockSize = opts.blockSize || 32;
    const redundancy = opts.redundancy || 3.0;
    const minFrames = opts.minFrames || 8;
    const kBlocks = Math.max(1, Math.ceil(payloadBytes.length / blockSize));
    const frameCount = Math.max(minFrames, Math.ceil(kBlocks * redundancy));

    const enc = new FountainEncoder(payloadBytes, kBlocks, blockSize);
    const frames = [];
    for (let i = 0; i < frameCount; i++) {
      const droplet = enc.generateDroplet(i);
      const frameBytes = frameDroplet(droplet.pack(), kBlocks, blockSize, payloadBytes.length);
      frames.push(whitenBits(bytesToBits(frameBytes)));
    }
    return { frames, kBlocks, blockSize, originalLength: payloadBytes.length, frameCount };
  }

  /**
   * Parse a single whitened frame bitstring back to its droplet + params.
   * Returns null if SYNC/version/CRC fail. Length-agnostic: reads exactly the
   * droplet the header describes.
   */
  function decodeFrame(whitenedBits) {
    if (whitenedBits.length < (HEADER_LEN + CRC_LEN) * 8) return null;
    const bits = dewhitenBits(whitenedBits);
    const bytes = bitsToBytes(bits);
    if (bytes[0] !== SYNC[0] || bytes[1] !== SYNC[1] || bytes[2] !== SYNC[2]) return null;
    const dv = new DataView(bytes.buffer);
    let o = SYNC.length;
    const version = bytes[o]; o += 1;
    if (version !== VERSION) return null;
    const kBlocks = dv.getUint16(o, false); o += 2;
    const blockSize = dv.getUint16(o, false); o += 2;
    const originalLength = dv.getUint32(o, false); o += 4;
    // droplet: seed(4)+count(2)+indices(count*2)+data(blockSize)
    const dropStart = o;
    if (bytes.length < dropStart + 6) return null;
    const count = dv.getUint16(dropStart + 4, false);
    const dropLen = 4 + 2 + count * 2 + blockSize;
    const crcStart = dropStart + dropLen;
    if (bytes.length < crcStart + CRC_LEN) return null;
    const got = (bytes[crcStart] << 8) | bytes[crcStart + 1];
    const want = crc16(bytes, SYNC.length, crcStart);
    if (got !== want) return null;
    const dropletBytes = bytes.subarray(dropStart, dropStart + dropLen);
    return { version, kBlocks, blockSize, originalLength, dropletBytes, count };
  }

  /**
   * Decode a set of whitened frame bitstrings into the original payload.
   * Frames may be in any order and a lossy subset — the fountain layer
   * reconstructs from any sufficient set. Returns Uint8Array or null.
   */
  function decode(whitenedFrames) {
    let decoder = null;
    let originalLength = null;
    for (const wf of whitenedFrames) {
      const f = decodeFrame(wf);
      if (!f) continue; // dropped/corrupt frame — fountain tolerates it
      if (!decoder) {
        decoder = new FountainDecoder(f.kBlocks, f.blockSize, f.originalLength);
        originalLength = f.originalLength;
      }
      const droplet = Droplet.unpack(f.dropletBytes, f.blockSize);
      decoder.addDroplet(droplet);
      if (decoder.isComplete()) break;
    }
    if (!decoder || !decoder.isComplete()) return null;
    return decoder.getData(originalLength);
  }

  return {
    SYNC, VERSION, HEADER_LEN, CRC_LEN,
    crc16, whitenBits, dewhitenBits, bytesToBits, bitsToBytes,
    frameDroplet, encode, decodeFrame, decode,
  };
});
