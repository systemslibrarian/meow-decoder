/**
 * Test: Verify the binary decode fix works with the user's real encoded data.
 */
const CatProtocol = require('./web_demo/cat-mode-protocol.js');

const raw = '000000001010101010101010101010101010101011111110110010100000000100101111111000110011001110101110000000000000000001000001000000001011110011000001001100111100110000000011000000000000000000000010000000000000100010100100110111111110110001010001001011010001000000010110000101000010010001010101111110010101001010100011110000010010110010110010011111001101001100011110111010010101100101001011001011000101010001010010110000111010001111000000111011000111111101001101000010010011110000011100101110101111011011100000101100001110101000100111000000111101001110100111101011111000100100011101101000100100111010100100010011010000001101101001111100010011110010010101000100101100101111000010101001000101010101010101';

function binaryToBytes(bin) {
    const bytes = new Uint8Array(Math.ceil(bin.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bin.substring(i * 8, i * 8 + 8), 2);
    }
    return bytes;
}

// ============ NEW METHOD: find where alternation ends ============
let binary = raw;
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
        if (binary[i] === binary[i + 1]) { dataStart = i; break; }
    }
}
if (dataStart >= 0) binary = binary.substring(dataStart);

// Remove end marker
let endIdx = binary.lastIndexOf('0101010101010101');
if (endIdx !== -1 && endIdx > binary.length / 2) binary = binary.substring(0, endIdx);

// Pad to byte boundary
while (binary.length % 8 !== 0) binary += '0';

const bytes = binaryToBytes(binary);

console.log('Alt region: bits', altStart, '-', dataStart);
console.log('First byte: 0x' + bytes[0].toString(16).padStart(2, '0'));
console.log('Magic number: 0x' + ((bytes[0] | (bytes[1] << 8)) >>> 0).toString(16).padStart(4, '0'));
console.log('Payload bytes:', bytes.length);

// Process through CatProtocolDecoder
const decoder = new CatProtocol.Decoder();
let offset = 0;
let messageComplete = false;

while (offset < bytes.length) {
    const remaining = bytes.slice(offset);
    if (remaining.length < 15) break;

    const packetResult = CatProtocol.decodePacket(remaining);
    if (!packetResult.valid) {
        let found = false;
        for (let i = 1; i < Math.min(remaining.length - 1, 100); i++) {
            if (remaining[i] === 0xFE && remaining[i + 1] === 0xCA) {
                offset += i;
                found = true;
                break;
            }
        }
        if (!found) break;
        continue;
    }

    const processResult = decoder.processPacket(remaining);
    offset += CatProtocol.HEADER_SIZE + packetResult.payload.length;

    if (processResult.complete) {
        messageComplete = true;
        const msg = processResult.message;
        console.log('\n✅ Message complete!');
        console.log('Packets:', processResult.totalPackets);
        console.log('Message bytes:', msg.length);

        const ver = msg[0];
        console.log('Format version: 0x' + ver.toString(16).padStart(2, '0'));

        if (ver === 0x03) {
            const dv = new DataView(msg.buffer, msg.byteOffset);
            const memKib = dv.getUint32(1, true);
            const iterations = msg[5];
            console.log('Argon2: memKib=' + memKib + ', iterations=' + iterations);
            console.log('(Version 0x03 = encrypted with Argon2 - needs WASM to decrypt)');
        }
        break;
    }
}

if (!messageComplete) {
    console.log('⚠️ Message not complete');
}

const stats = decoder.getStats();
console.log('\nDecoder stats:', JSON.stringify(stats));

// ============ VERIFY OLD METHOD WOULD FAIL ============
let binary_old = raw;
let si = binary_old.indexOf('1010101010101010');
if (si !== -1) binary_old = binary_old.substring(si + 16);
let ei = binary_old.lastIndexOf('0101010101010101');
if (ei !== -1) binary_old = binary_old.substring(0, ei);
while (binary_old.length % 8 !== 0) binary_old += '0';
const bytes_old = binaryToBytes(binary_old);
const oldMagic = (bytes_old[0] | (bytes_old[1] << 8)) >>> 0;
const oldPacket = CatProtocol.decodePacket(bytes_old);

console.log('\n=== OLD METHOD (should fail) ===');
console.log('First byte: 0x' + bytes_old[0].toString(16).padStart(2, '0'), '(expected 0xFE)');
console.log('Magic: 0x' + oldMagic.toString(16).padStart(4, '0'), '(expected 0xCAFE)');
console.log('Packet valid:', oldPacket.valid, '(expected: false)');
