/**
 * Full E2E pipeline trace: encode → copy binary → paste binary → decode
 * Proves every layer of the cat mode pipeline works correctly.
 * Uses real CatProtocol but simulated crypto payloads.
 */

const nodeCrypto = require('crypto');
globalThis.crypto = { getRandomValues: (buf) => nodeCrypto.randomFillSync(buf) };
const CatProtocol = require('./cat-mode-protocol');

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

let failures = 0;
function check(label, condition) {
  if (condition) {
    console.log(`  ✅ ${label}`);
  } else {
    console.log(`  ❌ FAIL: ${label}`);
    failures++;
  }
}

function runTest(testName, testFn) {
  console.log(`\n━━━ ${testName} ━━━`);
  testFn();
}

// ═════════════════════════════════════════════════════════════════════════════
// Simulate buildCatBinaryPayload() and catModeDecode() from the HTML
// ═════════════════════════════════════════════════════════════════════════════

function simulateEncode(payload) {
  const sessionId = CatProtocol.generateSessionId();
  const packets = CatProtocol.encodeMessage(payload, sessionId, 256);

  let packetsBinary = '';
  for (const packet of packets) {
    packetsBinary += bytesToBinary(packet);
  }

  const leadIn = '00000000';
  const preamble = '1010101010101010';
  const shortMessage = packetsBinary.length < 200;
  const syncWord = shortMessage ? '10101010' : '1010101010101010';
  const endMarker = '0101010101010101';
  const totalBinary = leadIn + preamble + syncWord + packetsBinary + endMarker;

  return { binary: totalBinary, packets: packets.length, sessionId };
}

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
    // Fallback: try old method
    let startIdx = binary.indexOf('1010101010101010');
    if (startIdx !== -1) {
      binary = binary.substring(startIdx + 16);
    } else {
      startIdx = binary.indexOf('11111111');
      if (startIdx !== -1) binary = binary.substring(startIdx + 8);
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
  while (binary.length % 8 !== 0) binary += '0';

  let bytes = binaryToBytes(binary);

  // CatProtocol packet unwrapping (THE FIX)
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
      if (processResult.complete) lastCompleteMessage = processResult.message;
    }

    if (lastCompleteMessage) {
      bytes = lastCompleteMessage;
    }
  }

  return bytes;
}

// ═══════════════════════════════════════
// Test: v0x03 text payload (most common)
// ═══════════════════════════════════════
runTest('v0x03 text payload (standard security)', () => {
  const salt = nodeCrypto.randomBytes(16);
  const nonce = nodeCrypto.randomBytes(12);
  const fakeCipher = nodeCrypto.randomBytes(48);

  const packed = new Uint8Array(1 + 4 + 1 + 16 + 12 + fakeCipher.length);
  packed[0] = 0x03;
  const dv = new DataView(packed.buffer);
  dv.setUint32(1, 131072, true);
  packed[5] = 8;
  packed.set(salt, 6);
  packed.set(nonce, 22);
  packed.set(fakeCipher, 34);

  const encoded = simulateEncode(packed);
  console.log(`  Encoded: ${encoded.binary.length} bits, ${encoded.packets} packet(s)`);

  const decoded = simulateDecode(encoded.binary);
  check('Version byte is 0x03', decoded[0] === 0x03);
  check('Payload length matches', decoded.length === packed.length);
  check('Full payload matches byte-for-byte', Buffer.from(decoded).equals(Buffer.from(packed)));

  // Verify field extraction
  const dv2 = new DataView(decoded.buffer, decoded.byteOffset);
  check('memoryKib = 131072', dv2.getUint32(1, true) === 131072);
  check('iterations = 8', decoded[5] === 8);
  check('salt matches', Buffer.from(decoded.slice(6, 22)).equals(salt));
  check('nonce matches', Buffer.from(decoded.slice(22, 34)).equals(nonce));
  check('ciphertext matches', Buffer.from(decoded.slice(34)).equals(fakeCipher));
});

// ═══════════════════════════════════════
// Test: v0x04 file payload (with filename)
// ═══════════════════════════════════════
runTest('v0x04 file payload (with filename)', () => {
  const salt = nodeCrypto.randomBytes(16);
  const nonce = nodeCrypto.randomBytes(12);
  const fakeCipher = nodeCrypto.randomBytes(100);
  const fnBytes = Buffer.from('secret.pdf');

  const headerLen = 1 + 4 + 1 + 1 + 1 + fnBytes.length;
  const packed = new Uint8Array(headerLen + 16 + 12 + fakeCipher.length);
  packed[0] = 0x04;
  const dv = new DataView(packed.buffer);
  dv.setUint32(1, 65536, true);
  packed[5] = 3;
  packed[6] = 0x01;
  packed[7] = fnBytes.length;
  packed.set(fnBytes, 8);
  packed.set(salt, 8 + fnBytes.length);
  packed.set(nonce, 8 + fnBytes.length + 16);
  packed.set(fakeCipher, 8 + fnBytes.length + 28);

  const encoded = simulateEncode(packed);
  const decoded = simulateDecode(encoded.binary);
  check('Version byte is 0x04', decoded[0] === 0x04);
  check('Payload matches byte-for-byte', Buffer.from(decoded).equals(Buffer.from(packed)));

  const fnLen = decoded[7];
  const decodedFn = Buffer.from(decoded.slice(8, 8 + fnLen)).toString();
  check(`Filename = "${decodedFn}"`, decodedFn === 'secret.pdf');
});

// ═══════════════════════════════════════
// Test: DEMO mode (no WASM, no encryption)
// ═══════════════════════════════════════
runTest('DEMO mode (no encryption)', () => {
  const demoPayload = Buffer.from('DEMO:Hello from cat mode!');
  const encoded = simulateEncode(demoPayload);
  const decoded = simulateDecode(encoded.binary);
  const str = Buffer.from(decoded).toString();
  check('Decoded text starts with DEMO:', str.startsWith('DEMO:'));
  check(`Message = "${str.substring(5)}"`, str === 'DEMO:Hello from cat mode!');
});

// ═══════════════════════════════════════
// Test: Large payload (multi-packet)
// ═══════════════════════════════════════
runTest('Large payload (multi-packet, 600 bytes)', () => {
  const largePayload = new Uint8Array(600);
  for (let i = 0; i < 600; i++) largePayload[i] = i & 0xFF;
  largePayload[0] = 0x03;

  const encoded = simulateEncode(largePayload);
  console.log(`  Encoded: ${encoded.binary.length} bits, ${encoded.packets} packet(s)`);
  check('Multiple packets created', encoded.packets > 1);

  const decoded = simulateDecode(encoded.binary);
  check('Version byte is 0x03', decoded[0] === 0x03);
  check('Full payload matches', Buffer.from(decoded).equals(Buffer.from(largePayload)));
});

// ═══════════════════════════════════════
// Test: Very short message
// ═══════════════════════════════════════
runTest('Very short message (10 bytes)', () => {
  const shortPayload = new Uint8Array([0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  const encoded = simulateEncode(shortPayload);
  check('Short message mode used', encoded.binary.length < 500);

  const decoded = simulateDecode(encoded.binary);
  check('Payload matches', Buffer.from(decoded).equals(Buffer.from(shortPayload)));
});

// ═══════════════════════════════════════
// Test: Binary with whitespace/newlines (user might copy from textarea)
// ═══════════════════════════════════════
runTest('Binary with whitespace (copy-paste artifact)', () => {
  const payload = Buffer.from('DEMO:test whitespace');
  const encoded = simulateEncode(payload);

  // Add typical copy-paste artifacts
  const messy = encoded.binary.match(/.{1,40}/g).join('\n');
  const decoded = simulateDecode(messy);
  const str = Buffer.from(decoded).toString();
  check('Decoded despite whitespace', str === 'DEMO:test whitespace');
});

// ═══════════════════════════════════════
// Test: Realistic encrypted message sizes
// ═══════════════════════════════════════
runTest('Realistic encrypted "Hello World" (~82 bytes with v0x03 header)', () => {
  // A real "Hello World" encrypted: 11 bytes plaintext → ~27 bytes ciphertext (AES-GCM adds 16 tag)
  const salt = nodeCrypto.randomBytes(16);
  const nonce = nodeCrypto.randomBytes(12);
  const fakeCipher = nodeCrypto.randomBytes(27); // 11 + 16 GCM tag

  const packed = new Uint8Array(1 + 4 + 1 + 16 + 12 + fakeCipher.length);
  packed[0] = 0x03;
  const dv = new DataView(packed.buffer);
  dv.setUint32(1, 65536, true); // fast mode
  packed[5] = 3;
  packed.set(salt, 6);
  packed.set(nonce, 22);
  packed.set(fakeCipher, 34);

  const encoded = simulateEncode(packed);
  console.log(`  Payload: ${packed.length} bytes → ${encoded.binary.length} bits (${encoded.packets} packet)`);

  const decoded = simulateDecode(encoded.binary);
  check('Version byte is 0x03', decoded[0] === 0x03);
  check('Full round-trip matches', Buffer.from(decoded).equals(Buffer.from(packed)));
});

// ═══════════════════════════════════════
// Test: What happens WITHOUT the fix (regression guard)
// ═══════════════════════════════════════
runTest('Regression: without packet unwrapping, version = 0xFE (BROKEN)', () => {
  const packed = new Uint8Array([0x03, ...nodeCrypto.randomBytes(60)]);
  const encoded = simulateEncode(packed);

  // Simulate old decoder (no CatProtocol unwrapping)
  let binary = encoded.binary;
  let altStart = -1;
  for (let i = 0; i < binary.length - 1; i++) {
    if (binary[i] !== binary[i + 1]) {
      let isAlt = true;
      for (let j = i + 1; j < Math.min(i + 8, binary.length - 1); j++) {
        if (binary[j] === binary[j + 1]) { isAlt = false; break; }
      }
      if (isAlt) { altStart = i; break; }
    }
  }
  let dataStart = -1;
  if (altStart >= 0) {
    for (let i = altStart + 1; i < binary.length - 1; i++) {
      if (binary[i] === binary[i + 1]) { dataStart = i; break; }
    }
  }
  if (dataStart >= 0) binary = binary.substring(dataStart);
  const endIdx = binary.lastIndexOf('0101010101010101');
  if (endIdx > binary.length / 2) binary = binary.substring(0, endIdx);
  while (binary.length % 8 !== 0) binary += '0';
  const rawBytes = binaryToBytes(binary);

  check('OLD decoder sees 0xFE (BROKEN)', rawBytes[0] === 0xFE);
  check('OLD decoder sees 0xCA (packet magic)', rawBytes[1] === 0xCA);

  // Now with the fix
  const fixedBytes = simulateDecode(encoded.binary);
  check('FIXED decoder sees 0x03 (correct)', fixedBytes[0] === 0x03);
});

// ═══════════════════════════════════════
// Test: End marker collision check
// ═══════════════════════════════════════
runTest('End marker inside encrypted data (false positive check)', () => {
  // Create a payload that contains the end marker pattern inside it
  const tricky = new Uint8Array(40);
  tricky[0] = 0x03;
  // Insert 0101010101010101 pattern at byte 10 = bits 80-95
  tricky[10] = 0x55; // 01010101
  tricky[11] = 0x55; // 01010101
  for (let i = 12; i < 40; i++) tricky[i] = 0xFF; // fill rest with non-zero

  const encoded = simulateEncode(tricky);
  const decoded = simulateDecode(encoded.binary);

  // The end marker should be the LAST occurrence, not the one inside data
  check('Full payload preserved despite internal end marker pattern',
    Buffer.from(decoded).equals(Buffer.from(tricky)));
});

// ═══════════════════════════════════════
// Summary
// ═══════════════════════════════════════
console.log('\n' + '═'.repeat(50));
if (failures === 0) {
  console.log('🎉 ALL TESTS PASSED! Cat mode pipeline is working.');
} else {
  console.log(`💥 ${failures} TEST(S) FAILED!`);
  process.exit(1);
}
