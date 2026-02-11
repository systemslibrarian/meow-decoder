#!/usr/bin/env node
// Test: Simulate the cat mode encode → video binary → decode pipeline
// This verifies the binary framing, start marker detection, and byte recovery.

// ── helpers (match the browser code exactly) ───────────────────────
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

// ── encoder side (catModeEncode) ──────────────────────────────────
function encode(payloadBytes) {
    const preamble    = '0000000000000000'; // 16 dark bits
    const startMarker = '11111111';         // 8 ones
    const lengthBits  = payloadBytes.length.toString(2).padStart(16, '0'); // 16-bit length
    return preamble + startMarker + lengthBits + bytesToBinary(payloadBytes);
}

// ── decoder side (catVideoAnalyze) ────────────────────────────────
function decode(binary) {
    // Forward search for preamble (8+ zeros) → start marker (8 ones).
    // This avoids matching 0xFF payload bytes that look like 11111111.
    let startIdx = -1;
    const match = binary.match(/0{8,}1{8}/);
    if (match) {
        startIdx = match.index + match[0].length - 8;
    }
    if (startIdx === -1) startIdx = binary.indexOf('11111111');
    if (startIdx === -1) throw new Error('No start marker');

    let afterStart = binary.substring(startIdx + 8); // skip start marker

    // Read 16-bit length header
    if (afterStart.length < 16) throw new Error('No length header');
    const payloadByteCount = parseInt(afterStart.substring(0, 16), 2);
    const payloadBitCount  = payloadByteCount * 8;
    let payload = afterStart.substring(16, 16 + payloadBitCount);

    while (payload.length % 8 !== 0) payload += '0';

    return binaryToBytes(payload);
}

// ── test scenarios ────────────────────────────────────────────────
let pass = 0, fail = 0;

function assert(label, condition, detail) {
    if (condition) { pass++; console.log(`  ✅ ${label}`); }
    else { fail++; console.log(`  ❌ ${label}: ${detail}`); }
}

// Test 1: Clean round-trip (no noise)
console.log('\n── Test 1: Clean round-trip ──');
{
    // Simulate a WASM-encrypted payload: version(1) + salt(16) + nonce(12) + cipher(N)
    const fakePayload = new Uint8Array(1 + 16 + 12 + 10);
    fakePayload[0] = 0x01; // version
    for (let i = 1; i < fakePayload.length; i++) fakePayload[i] = i & 0xff;

    const binary = encode(fakePayload);
    const recovered = decode(binary);

    assert('Same length', recovered.length === fakePayload.length,
        `${recovered.length} vs ${fakePayload.length}`);
    assert('Version byte is 0x01', recovered[0] === 0x01,
        `got 0x${recovered[0].toString(16)}`);
    assert('All bytes match', JSON.stringify([...recovered]) === JSON.stringify([...fakePayload]),
        `first 10: ${[...recovered.slice(0,10)]}`);
}

// Test 2: Video starts with static green (long leading 1s from camera delay)
console.log('\n── Test 2: Leading 1s (static green before blink) ──');
{
    const fakePayload = new Uint8Array([0x01, 0xAA, 0xBB, 0xCC]);
    const realBinary = encode(fakePayload);
    
    // Simulate 50 bits of static green at the start of the video
    const noisy = '1'.repeat(50) + realBinary;
    
    const recovered = decode(noisy);
    assert('Recovers despite leading 1s', recovered[0] === 0x01,
        `got 0x${recovered[0].toString(16)}`);
    assert('Payload intact', 
        recovered[1] === 0xAA && recovered[2] === 0xBB && recovered[3] === 0xCC,
        `got ${[...recovered]}`);
}

// Test 3: Video has trailing junk after end marker
console.log('\n── Test 3: Trailing junk after end marker ──');
{
    const fakePayload = new Uint8Array([0x01, 0xDE, 0xAD]);
    const binary = encode(fakePayload) + '1010101010101010';
    
    const recovered = decode(binary);
    assert('Ignores trailing junk', recovered.length === fakePayload.length,
        `${recovered.length} vs ${fakePayload.length}`);
    assert('Payload intact', recovered[0] === 0x01 && recovered[1] === 0xDE && recovered[2] === 0xAD,
        `got ${[...recovered]}`);
}

// Test 4: Payload with internal 0x00 byte (was a bug before length header fix)
console.log('\n── Test 4: Payload with internal 0x00 byte ──');
{
    // version=0x01, then a byte 0x00, then more data
    const fakePayload = new Uint8Array([0x01, 0x00, 0xFF, 0x42]);
    const binary = encode(fakePayload);
    
    const recovered = decode(binary);
    assert('Length matches', recovered.length === fakePayload.length,
        `${recovered.length} vs ${fakePayload.length}`);
    assert('Payload intact (0x00 preserved)', 
        recovered[0] === 0x01 && recovered[1] === 0x00 && recovered[2] === 0xFF && recovered[3] === 0x42,
        `got ${[...recovered]}`);
}

// Test 5: Realistic encrypted payload with many 0x00 bytes
console.log('\n── Test 5: Payload with multiple 0x00 bytes ──');
{
    const payload = new Uint8Array(39); // 1 + 16 + 12 + 10
    payload[0] = 0x01;
    for (let i = 1; i < payload.length; i++) payload[i] = 0x42 + (i % 200);
    // Sprinkle 0x00 bytes throughout
    payload[5] = 0x00;
    payload[20] = 0x00;
    payload[35] = 0x00;
    
    const binary = encode(payload);
    const recovered = decode(binary);
    
    assert('Full length recovered', recovered.length === payload.length,
        `${recovered.length} vs ${payload.length}`);
    assert('All bytes match including 0x00s',
        JSON.stringify([...recovered]) === JSON.stringify([...payload]),
        `mismatch at first diff`);
}

// Test 6: Large payload (simulate real encryption output)
console.log('\n── Test 6: Large payload (500 bytes) ──');
{
    const payload = new Uint8Array(500);
    payload[0] = 0x01;
    for (let i = 1; i < payload.length; i++) payload[i] = Math.floor(Math.random() * 256);
    
    const binary = encode(payload);
    // Simulate 100 leading 1s from camera capturing green eyes during key derivation
    const noisy = '1'.repeat(100) + binary;
    
    const recovered = decode(noisy);
    assert('500-byte payload recovered', recovered.length === payload.length,
        `${recovered.length} vs ${payload.length}`);
    assert('All bytes match', 
        JSON.stringify([...recovered]) === JSON.stringify([...payload]),
        'data mismatch');
}

// ── summary ──────────────────────────────────────────────────────
console.log(`\n═══ Results: ${pass} passed, ${fail} failed ═══`);
if (fail > 0) {
    console.log('\n🐛 Some tests failed — needs investigation.');
} else {
    console.log('\n✅ All tests passed! The binary pipeline is reliable.');
}
