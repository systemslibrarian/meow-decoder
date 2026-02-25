/**
 * cat-mode-protocol.test.js — Unit tests for the Cat Mode packet protocol.
 *
 * Tests CRC32, constant-time comparison, packet encode/decode,
 * message encode/decode, and the stateful CatProtocolDecoder.
 */

// Polyfill crypto.getRandomValues for Node.js
const nodeCrypto = require('crypto');
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = { getRandomValues: (buf) => nodeCrypto.randomFillSync(buf) };
}

const CatProtocol = require('../cat-mode-protocol');

const {
  crc32,
  verifyCrc32,
  encodePacket,
  decodePacket,
  encodeMessage,
  Decoder: CatProtocolDecoder,
  MAGIC_NUMBER,
  PROTOCOL_VERSION,
  HEADER_SIZE,
  MAX_PAYLOAD_SIZE,
  bytesToHex,
} = CatProtocol;

// ── CRC32 ─────────────────────────────────────────────────────────────────────

describe('crc32', () => {
  it('returns 0 CRC for empty data', () => {
    const result = crc32(new Uint8Array(0));
    expect(typeof result).toBe('number');
    expect(result).toBe(0x00000000);
  });

  it('produces consistent output for same input', () => {
    const data = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    const a = crc32(data);
    const b = crc32(data);
    expect(a).toBe(b);
  });

  it('produces different output for different input', () => {
    const a = crc32(new Uint8Array([1, 2, 3]));
    const b = crc32(new Uint8Array([3, 2, 1]));
    expect(a).not.toBe(b);
  });

  it('produces unsigned 32-bit integer', () => {
    const data = new Uint8Array([0xFF, 0xFE, 0xFD, 0xFC]);
    const result = crc32(data);
    expect(result).toBeGreaterThanOrEqual(0);
    expect(result).toBeLessThanOrEqual(0xFFFFFFFF);
  });

  it('computes known IEEE CRC32 for "123456789" (sanity check)', () => {
    // IEEE 802.3 CRC32 of ASCII "123456789" = 0xCBF43926
    const data = new TextEncoder().encode('123456789');
    const result = crc32(data);
    expect(result).toBe(0xCBF43926);
  });
});

describe('verifyCrc32', () => {
  it('returns true for matching CRC', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const expected = crc32(data);
    expect(verifyCrc32(data, expected)).toBe(true);
  });

  it('returns false for mismatched CRC', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    expect(verifyCrc32(data, 0xDEADBEEF)).toBe(false);
  });
});

// ── constantTimeEqual32 (tested indirectly via verifyCrc32) ───────────────────

describe('constant-time comparison', () => {
  it('equal values return true', () => {
    // Tested through verifyCrc32 to ensure constant-time path is exercised
    const data = new Uint8Array([42]);
    const expected = crc32(data);
    expect(verifyCrc32(data, expected)).toBe(true);
  });

  it('off-by-one returns false', () => {
    const data = new Uint8Array([42]);
    const expected = crc32(data);
    expect(verifyCrc32(data, expected + 1)).toBe(false);
    expect(verifyCrc32(data, expected - 1)).toBe(false);
  });
});

// ── Packet Encode/Decode ──────────────────────────────────────────────────────

describe('encodePacket', () => {
  it('produces packet of correct length', () => {
    const payload = new Uint8Array([0x41, 0x42, 0x43]); // "ABC"
    const packet = encodePacket(payload, 0x12345678, 0);
    expect(packet.length).toBe(HEADER_SIZE + payload.length);
  });

  it('throws on payload exceeding MAX_PAYLOAD_SIZE', () => {
    const oversized = new Uint8Array(MAX_PAYLOAD_SIZE + 1);
    expect(() => encodePacket(oversized, 1, 0)).toThrow(/too large/i);
  });

  it('accepts empty payload', () => {
    const packet = encodePacket(new Uint8Array(0), 1, 0);
    expect(packet.length).toBe(HEADER_SIZE);
  });

  it('accepts max-size payload', () => {
    const packet = encodePacket(new Uint8Array(MAX_PAYLOAD_SIZE), 1, 0);
    expect(packet.length).toBe(HEADER_SIZE + MAX_PAYLOAD_SIZE);
  });
});

describe('decodePacket', () => {
  it('round-trips a packet (encode → decode)', () => {
    const payload = new TextEncoder().encode('Hello, Cat!');
    const sessionId = 0xCAFEBABE;
    const seq = 42;
    const packet = encodePacket(payload, sessionId, seq);
    const decoded = decodePacket(packet);

    expect(decoded.valid).toBe(true);
    expect(decoded.sessionId).toBe(sessionId);
    expect(decoded.sequenceNum).toBe(seq);
    expect(decoded.version).toBe(PROTOCOL_VERSION);
    expect(new TextDecoder().decode(decoded.payload)).toBe('Hello, Cat!');
  });

  it('rejects packet shorter than header', () => {
    const result = decodePacket(new Uint8Array(HEADER_SIZE - 1));
    expect(result.valid).toBe(false);
    expect(result.error).toBe('packet_invalid');
  });

  it('rejects packet with wrong magic number', () => {
    const payload = new Uint8Array([1, 2, 3]);
    const packet = encodePacket(payload, 1, 0);
    // Corrupt magic
    packet[0] = 0xFF;
    packet[1] = 0xFF;
    const result = decodePacket(packet);
    expect(result.valid).toBe(false);
  });

  it('rejects packet with tampered payload (CRC mismatch)', () => {
    const payload = new TextEncoder().encode('Secret');
    const packet = encodePacket(payload, 1, 0);
    // Flip a payload byte
    packet[HEADER_SIZE] ^= 0xFF;
    const result = decodePacket(packet);
    expect(result.valid).toBe(false);
  });

  it('rejects packet with wrong version', () => {
    const payload = new Uint8Array([1]);
    const packet = encodePacket(payload, 1, 0);
    // Corrupt version byte (byte index 2)
    packet[2] = 0xFF;
    const result = decodePacket(packet);
    expect(result.valid).toBe(false);
  });

  it('rejects packet with truncated payload', () => {
    const payload = new Uint8Array(100).fill(0x42);
    const packet = encodePacket(payload, 1, 0);
    // Truncate: remove last 10 bytes
    const truncated = packet.slice(0, packet.length - 10);
    const result = decodePacket(truncated);
    expect(result.valid).toBe(false);
  });

  it('uses generic error message (no information leakage)', () => {
    // Wrong magic
    const badMagic = new Uint8Array(HEADER_SIZE + 1);
    expect(decodePacket(badMagic).error).toBe('packet_invalid');

    // Wrong CRC
    const payload = new Uint8Array([1]);
    const packet = encodePacket(payload, 1, 0);
    packet[HEADER_SIZE] ^= 0xFF;
    expect(decodePacket(packet).error).toBe('packet_invalid');
  });
});

// ── Message Encode/Decode ─────────────────────────────────────────────────────

describe('encodeMessage', () => {
  it('encodes a short string into one packet', () => {
    const packets = encodeMessage('Hi', 0x12345678);
    expect(packets.length).toBe(1);
  });

  it('splits long message across multiple packets', () => {
    const longMsg = 'A'.repeat(1000);
    const packets = encodeMessage(longMsg, 0x12345678, 256);
    expect(packets.length).toBe(Math.ceil(1000 / 256));
  });

  it('accepts Uint8Array input', () => {
    const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
    const packets = encodeMessage(data, 1);
    expect(packets.length).toBe(1);
  });

  it('generates session ID when null', () => {
    const packets = encodeMessage('test', null);
    expect(packets.length).toBe(1);
    const decoded = decodePacket(packets[0]);
    expect(decoded.valid).toBe(true);
    expect(typeof decoded.sessionId).toBe('number');
  });
});

// ── CatProtocolDecoder (Stateful Multi-Packet) ───────────────────────────────

describe('CatProtocolDecoder', () => {
  it('decodes a single-packet message', () => {
    const sessionId = 0xAABBCCDD;
    const packets = encodeMessage('Hello!', sessionId);
    const decoder = new CatProtocolDecoder();
    const result = decoder.processPacket(packets[0]);

    expect(result.accepted).toBe(true);
    expect(result.complete).toBe(true);
    expect(new TextDecoder().decode(result.message)).toBe('Hello!');
  });

  it('decodes a multi-packet message', () => {
    const sessionId = 0x11223344;
    const original = 'The quick brown fox jumps over the lazy cat! 🐱';
    const packets = encodeMessage(original, sessionId, 16); // Small chunks
    expect(packets.length).toBeGreaterThan(1);

    const decoder = new CatProtocolDecoder();
    let finalResult = null;

    // The decoder considers contiguous 0..max as complete, so feed all packets
    for (const pkt of packets) {
      finalResult = decoder.processPacket(pkt);
    }

    expect(finalResult.accepted).toBe(true);
    expect(finalResult.complete).toBe(true);
    expect(new TextDecoder().decode(finalResult.message)).toBe(original);
    expect(finalResult.totalPackets).toBe(packets.length);
  });

  it('rejects invalid packets', () => {
    const decoder = new CatProtocolDecoder();
    const garbage = new Uint8Array(20).fill(0xFF);
    const result = decoder.processPacket(garbage);
    expect(result.accepted).toBe(false);
    expect(result.error).toBe('packet_rejected');
  });

  it('rejects packets from wrong session', () => {
    const decoder = new CatProtocolDecoder();
    // Lock to session A
    const packetsA = encodeMessage('From A', 0xAAAAAAAA);
    decoder.processPacket(packetsA[0]);

    // Try session B
    const packetsB = encodeMessage('From B', 0xBBBBBBBB);
    const result = decoder.processPacket(packetsB[0]);
    expect(result.accepted).toBe(false);
  });

  it('rejects duplicate sequence numbers', () => {
    const sessionId = 0x12345678;
    const original = 'ABCDEFGHIJKLMNOP';
    const packets = encodeMessage(original, sessionId, 4);

    const decoder = new CatProtocolDecoder();
    // Process first packet
    decoder.processPacket(packets[0]);
    // Process same packet again
    const result = decoder.processPacket(packets[0]);
    expect(result.accepted).toBe(false);
  });

  it('tracks stats correctly', () => {
    const decoder = new CatProtocolDecoder();
    const packets = encodeMessage('test', 0x12345678);
    decoder.processPacket(packets[0]);
    // Process an invalid packet
    decoder.processPacket(new Uint8Array(5));

    const stats = decoder.getStats();
    expect(stats.packets_received).toBe(2);
    expect(stats.packets_accepted).toBe(1);
    expect(stats.packets_rejected).toBe(1);
  });

  it('reset() clears all state', () => {
    const decoder = new CatProtocolDecoder();
    const packets = encodeMessage('hello', 0xAABBCCDD);
    decoder.processPacket(packets[0]);
    expect(decoder.getSessionId()).toBe(0xAABBCCDD);

    decoder.reset();
    expect(decoder.getSessionId()).toBeNull();
    expect(decoder.getStats().packets_received).toBe(0);
  });

  it('reports progress for incomplete multi-packet messages (out-of-order)', () => {
    const packets = encodeMessage('A'.repeat(100), 0x12345678, 16);
    expect(packets.length).toBeGreaterThan(2);

    const decoder = new CatProtocolDecoder();
    // Send last packet first — creates a gap, so decoder sees incomplete
    const result = decoder.processPacket(packets[packets.length - 1]);
    expect(result.accepted).toBe(true);
    expect(result.complete).toBe(false);
    expect(result.progress).toBeDefined();
    expect(result.progress.received).toBe(1);
  });
});

// ── bytesToHex ────────────────────────────────────────────────────────────────

describe('bytesToHex', () => {
  it('converts bytes to hex string', () => {
    expect(bytesToHex(new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]))).toBe('deadbeef');
  });

  it('zero-pads single-digit hex values', () => {
    expect(bytesToHex(new Uint8Array([0x01, 0x0A]))).toBe('010a');
  });

  it('handles empty array', () => {
    expect(bytesToHex(new Uint8Array(0))).toBe('');
  });
});
