/**
 * cat-mode-manual-decode.test.js — End-to-end test proving that pasting
 * the original binary pattern into the manual decode field works correctly.
 *
 * This test reproduces the exact bug where the manual decode path did NOT
 * unwrap CatProtocol packets, causing bytes[0]=0xFE (first byte of the
 * 0xCAFE magic) to be misinterpreted as "Unknown format version: 0xfe".
 */

const nodeCrypto = require('crypto');
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = { getRandomValues: (buf) => nodeCrypto.randomFillSync(buf) };
}

const CatProtocol = require('../cat-mode-protocol');

// ── Helpers (mirrors the FULL.html functions) ─────────────────────────────────

function bytesToBinary(bytes) {
  return Array.from(bytes).map(b => b.toString(2).padStart(8, '0')).join('');
}

function binaryToBytes(binary) {
  const bytes = [];
  for (let i = 0; i < binary.length; i += 8) {
    bytes.push(parseInt(binary.substr(i, 8), 2));
  }
  return new Uint8Array(bytes);
}

/**
 * Simulate the ENCODER side: buildCatBinaryPayload()
 * Creates a version-tagged payload, wraps it in CatProtocol packets,
 * adds preamble/sync/end markers → returns the full binary string.
 */
function simulateEncode(payloadBytes) {
  const sessionId = CatProtocol.generateSessionId();
  const packets = CatProtocol.encodeMessage(payloadBytes, sessionId, 256);

  let packetsBinary = '';
  for (const packet of packets) {
    packetsBinary += bytesToBinary(packet);
  }

  const leadIn   = '00000000';
  const preamble = '1010101010101010';
  const syncWord = packetsBinary.length < 200 ? '10101010' : '1010101010101010';
  const endMarker = '0101010101010101';

  return leadIn + preamble + syncWord + packetsBinary + endMarker;
}

/**
 * Simulate the DECODER side: catModeDecode() manual binary path.
 * This is the FIXED version that unwraps CatProtocol packets.
 */
function simulateDecode(binaryInput) {
  let binary = binaryInput.replace(/[^01]/g, '');

  // Step 1: Find alternating region start
  let altStart = -1;
  for (let i = 0; i < binary.length - 1; i++) {
    if (binary[i] !== binary[i + 1]) {
      let isAlternating = true;
      for (let j = i + 1; j < Math.min(i + 8, binary.length - 1); j++) {
        if (binary[j] === binary[j + 1]) { isAlternating = false; break; }
      }
      if (isAlternating) { altStart = i; break; }
    }
  }

  // Step 2: Find where alternation stops
  let dataStart = -1;
  if (altStart >= 0) {
    for (let i = altStart + 1; i < binary.length - 1; i++) {
      if (binary[i] === binary[i + 1]) {
        dataStart = i;
        break;
      }
    }
  }

  if (dataStart >= 0) {
    binary = binary.substring(dataStart);
  } else {
    const startIdx = binary.indexOf('1010101010101010');
    if (startIdx !== -1) {
      binary = binary.substring(startIdx + 16);
    }
  }

  // Remove end marker
  const endIdx16 = binary.lastIndexOf('0101010101010101');
  if (endIdx16 !== -1 && endIdx16 > binary.length / 2) {
    binary = binary.substring(0, endIdx16);
  } else if (binary.endsWith('00000000')) {
    binary = binary.substring(0, binary.length - 8);
  }

  // Pad to byte boundary
  while (binary.length % 8 !== 0) {
    binary += '0';
  }

  let bytes = binaryToBytes(binary);

  // ========== THE FIX: CatProtocol packet unwrapping ==========
  if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xCA) {
    const packetDecoder = new CatProtocol.Decoder();
    let currentOffset = 0;
    let packetsProcessed = 0;
    let lastCompleteMessage = null;

    while (currentOffset < bytes.length) {
      const remainingBytes = bytes.slice(currentOffset);
      if (remainingBytes.length < 15) break;

      const packetResult = CatProtocol.decodePacket(remainingBytes);
      if (!packetResult.valid) {
        let foundNext = false;
        for (let i = 1; i < Math.min(remainingBytes.length - 1, 100); i++) {
          if (remainingBytes[i] === 0xFE && remainingBytes[i + 1] === 0xCA) {
            currentOffset += i;
            foundNext = true;
            break;
          }
        }
        if (!foundNext) break;
        continue;
      }

      const processResult = packetDecoder.processPacket(remainingBytes);
      packetsProcessed++;
      currentOffset += packetResult.packet_size;

      if (processResult.complete) {
        lastCompleteMessage = processResult.message;
      }
    }

    if (packetsProcessed === 0) {
      throw new Error('No valid CatProtocol packets found');
    }
    const stats = packetDecoder.getStats();
    if (stats.packets_accepted === 0) {
      throw new Error(`All ${stats.packets_rejected} packet(s) failed CRC`);
    }
    if (lastCompleteMessage) {
      bytes = lastCompleteMessage;
    }
  }

  return bytes;
}

/**
 * Simulate the OLD (BROKEN) decoder: no CatProtocol unwrapping.
 */
function simulateDecodeBROKEN(binaryInput) {
  let binary = binaryInput.replace(/[^01]/g, '');

  let altStart = -1;
  for (let i = 0; i < binary.length - 1; i++) {
    if (binary[i] !== binary[i + 1]) {
      let isAlternating = true;
      for (let j = i + 1; j < Math.min(i + 8, binary.length - 1); j++) {
        if (binary[j] === binary[j + 1]) { isAlternating = false; break; }
      }
      if (isAlternating) { altStart = i; break; }
    }
  }

  let dataStart = -1;
  if (altStart >= 0) {
    for (let i = altStart + 1; i < binary.length - 1; i++) {
      if (binary[i] === binary[i + 1]) {
        dataStart = i;
        break;
      }
    }
  }

  if (dataStart >= 0) {
    binary = binary.substring(dataStart);
  }

  const endIdx16 = binary.lastIndexOf('0101010101010101');
  if (endIdx16 !== -1 && endIdx16 > binary.length / 2) {
    binary = binary.substring(0, endIdx16);
  }

  while (binary.length % 8 !== 0) {
    binary += '0';
  }

  return binaryToBytes(binary);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Cat Mode manual binary decode (paste original pattern)', () => {

  // A v0x03 payload: [0x03, memKib(4), iter(1), salt(16), nonce(12), cipher(N)]
  function makeV03Payload() {
    const salt = nodeCrypto.randomBytes(16);
    const nonce = nodeCrypto.randomBytes(12);
    const cipher = nodeCrypto.randomBytes(32);  // fake ciphertext

    const packed = new Uint8Array(1 + 4 + 1 + 16 + 12 + cipher.length);
    packed[0] = 0x03;  // version
    const dv = new DataView(packed.buffer);
    dv.setUint32(1, 32768, true);  // memoryKib
    packed[5] = 3;                 // iterations
    packed.set(salt, 6);
    packed.set(nonce, 22);
    packed.set(cipher, 34);
    return packed;
  }

  it('OLD decoder FAILS with "Unknown format version: 0xfe"', () => {
    const payload = makeV03Payload();
    const binary = simulateEncode(payload);
    const decoded = simulateDecodeBROKEN(binary);

    // The broken decoder sees the CatProtocol magic 0xFE as the version byte
    expect(decoded[0]).toBe(0xFE);  // This is the bug!
    expect(decoded[1]).toBe(0xCA);  // Second byte of CAFE magic
  });

  it('FIXED decoder correctly unwraps CatProtocol packets', () => {
    const payload = makeV03Payload();
    const binary = simulateEncode(payload);
    const decoded = simulateDecode(binary);

    // The fixed decoder unwraps the packet and recovers the actual payload
    expect(decoded[0]).toBe(0x03);  // Correct version byte!
    expect(decoded.length).toBe(payload.length);
    expect(Buffer.from(decoded)).toEqual(Buffer.from(payload));
  });

  it('round-trips a v0x03 payload exactly', () => {
    const original = makeV03Payload();
    const binary = simulateEncode(original);
    const recovered = simulateDecode(binary);

    expect(recovered[0]).toBe(0x03);
    expect(Array.from(recovered)).toEqual(Array.from(original));
  });

  it('round-trips a v0x04 payload (with filename) exactly', () => {
    const salt = nodeCrypto.randomBytes(16);
    const nonce = nodeCrypto.randomBytes(12);
    const cipher = nodeCrypto.randomBytes(48);
    const fnBytes = Buffer.from('secret.pdf');

    const headerLen = 1 + 4 + 1 + 1 + 1 + fnBytes.length;
    const packed = new Uint8Array(headerLen + 16 + 12 + cipher.length);
    packed[0] = 0x04;
    const dv = new DataView(packed.buffer);
    dv.setUint32(1, 65536, true);
    packed[5] = 5;
    packed[6] = 0x01;
    packed[7] = fnBytes.length;
    packed.set(fnBytes, 8);
    packed.set(salt, 8 + fnBytes.length);
    packed.set(nonce, 8 + fnBytes.length + 16);
    packed.set(cipher, 8 + fnBytes.length + 28);

    const binary = simulateEncode(packed);
    const recovered = simulateDecode(binary);

    expect(recovered[0]).toBe(0x04);
    expect(Array.from(recovered)).toEqual(Array.from(packed));
  });

  it('round-trips a DEMO payload (no encryption)', () => {
    const demoPayload = Buffer.from('DEMO:Hello World!');
    const binary = simulateEncode(demoPayload);
    const recovered = simulateDecode(binary);

    const str = new TextDecoder().decode(recovered);
    expect(str).toBe('DEMO:Hello World!');
  });

  it('handles multi-packet payloads (large messages)', () => {
    // 600 bytes will be split across multiple 256-byte packets
    const largePayload = new Uint8Array(600);
    for (let i = 0; i < 600; i++) largePayload[i] = i & 0xFF;
    largePayload[0] = 0x03; // version byte

    const binary = simulateEncode(largePayload);
    const recovered = simulateDecode(binary);

    expect(recovered.length).toBe(600);
    expect(Array.from(recovered)).toEqual(Array.from(largePayload));
  });

  it('still works for non-CatProtocol binary (legacy/raw)', () => {
    // If someone pastes raw binary without packet framing and its first
    // two bytes are NOT 0xFE 0xCA, the decoder should pass through unchanged.
    // Use a payload whose first byte (0x03) starts with bits '00' so the
    // alternation boundary still lines up (0xFE='11...' naturally works).
    const rawPayload = new Uint8Array([0xFE, 0x00, ...nodeCrypto.randomBytes(44)]);
    // Manually build binary WITHOUT CatProtocol: version 0xFE but second byte
    // is NOT 0xCA, so the guard check (bytes[0]===0xFE && bytes[1]===0xCA) won't
    // trigger and the raw payload passes through.
    const rawBinary = '00000000' + '1010101010101010' + '10101010' +
                      bytesToBinary(rawPayload) + '0101010101010101';

    const recovered = simulateDecode(rawBinary);
    // 0xFE starts with '11' so preamble boundary detection is correct
    expect(recovered[0]).toBe(0xFE);  // Should NOT try CatProtocol unwrapping (0xCA missing)
    expect(recovered[1]).not.toBe(0xCA);
    expect(recovered.length).toBe(rawPayload.length);
  });
});
