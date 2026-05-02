#!/usr/bin/env node
// Comprehensive smoke tests for cat-mode-protocol.js after audit fixes.
// Runs in pure Node, no browser/Playwright deps required.

global.crypto = {
    getRandomValues: (a) => {
        for (let i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256);
        return a;
    }
};

const CP = require('/workspaces/meow-decoder/web_demo/cat-mode-protocol.js');
const { encodeMessage, encodePacket, decodePacket, generateSessionId, Decoder, crc32, MAX_PACKETS } = CP;

let pass = 0, fail = 0;
const td = new TextDecoder();

function t(name, fn) {
    try {
        fn();
        console.log(`  \x1b[32m✓\x1b[0m ${name}`);
        pass++;
    } catch (e) {
        console.log(`  \x1b[31m✗\x1b[0m ${name}: ${e.message}`);
        fail++;
    }
}

function assertEq(a, b, msg) {
    if (a !== b) throw new Error(`${msg}: expected ${b}, got ${a}`);
}
function assertTrue(v, msg) {
    if (!v) throw new Error(msg);
}
function assertBytesEq(a, b, msg) {
    if (a.length !== b.length) throw new Error(`${msg}: length ${a.length} != ${b.length}`);
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) throw new Error(`${msg}: byte[${i}] ${a[i]} != ${b[i]}`);
    }
}

console.log('\n=== CRC32 ===');
t('CRC32 of empty data is 0', () => assertEq(crc32(new Uint8Array(0)), 0, 'crc'));
t('CRC32 deterministic', () => {
    const d = new TextEncoder().encode('test data');
    assertEq(crc32(d), crc32(d), 'crc');
});
t('CRC32 detects single bit flip', () => {
    const d1 = new TextEncoder().encode('Hello, World!');
    const d2 = new Uint8Array(d1); d2[5] ^= 1;
    assertTrue(crc32(d1) !== crc32(d2), 'should differ');
});

console.log('\n=== Round-trip ===');
t('UTF-8 round-trip', () => {
    const msg = 'Hello cat mode! 🐱😻 with emoji';
    const sid = generateSessionId();
    const packets = encodeMessage(msg, sid, 32);
    const dec = new Decoder();
    let r;
    for (const p of packets) r = dec.processPacket(p);
    assertTrue(r.complete, 'not complete');
    assertEq(td.decode(r.message), msg, 'msg');
});

t('Empty payload', () => {
    const packet = encodePacket(new Uint8Array(0), 0xCAFEBABE, 0);
    const dec = new Decoder();
    const r = dec.processPacket(packet);
    assertTrue(r.complete, 'not complete');
    assertEq(r.message.length, 0, 'len');
});

t('Single-byte payload', () => {
    const sid = 0xDEADBEEF;
    const dec = new Decoder();
    const r = dec.processPacket(encodePacket(new Uint8Array([0x42]), sid, 0));
    assertTrue(r.complete, 'not complete');
    assertEq(r.message[0], 0x42, 'byte');
});

t('Maximum-size single packet (1024 B)', () => {
    const payload = new Uint8Array(1024);
    for (let i = 0; i < 1024; i++) payload[i] = i & 0xFF;
    const dec = new Decoder();
    const r = dec.processPacket(encodePacket(payload, 0x11111111, 0));
    assertTrue(r.complete, 'not complete');
    assertBytesEq(r.message, payload, 'payload');
});

console.log('\n=== Multi-packet ===');
t('Multi-packet (3 packets)', () => {
    const big = new Uint8Array(800);
    for (let i = 0; i < big.length; i++) big[i] = (i * 7) & 0xFF;
    const sid = 0x77777777;
    const packets = encodeMessage(big, sid, 256);
    assertEq(packets.length, 4, 'pkt count');
    const dec = new Decoder();
    let r;
    for (const p of packets) r = dec.processPacket(p);
    assertTrue(r.complete, 'not complete');
    assertBytesEq(r.message, big, 'reassembly');
});

t('Out-of-order delivery', () => {
    const big = new Uint8Array(700);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xFF;
    const sid = 0x88888888;
    const packets = encodeMessage(big, sid, 256);
    // Reverse order
    const dec = new Decoder();
    let r;
    for (let i = packets.length - 1; i >= 0; i--) r = dec.processPacket(packets[i]);
    assertTrue(r.complete, 'not complete');
    assertBytesEq(r.message, big, 'reassembly');
});

t('Duplicate packets are harmless', () => {
    const sid = 0x99999999;
    const packets = encodeMessage('test message that fits in one', sid, 256);
    const dec = new Decoder();
    dec.processPacket(packets[0]);
    const r = dec.processPacket(packets[0]); // duplicate
    assertTrue(r.duplicate, 'should be duplicate');
    assertTrue(r.complete || r.complete === undefined, 'no crash');
});

console.log('\n=== Audit fixes ===');
t('Large message (60 KB / 235 packets) — used to crash', () => {
    const big = new Uint8Array(60000);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xFF;
    const dec = new Decoder();
    const packets = encodeMessage(big, 0xCAFEBABE, 256);
    assertEq(packets.length, 235, 'pkt count');
    let r;
    for (const p of packets) r = dec.processPacket(p);
    assertTrue(r.complete, 'not complete');
    assertEq(r.message.length, 60000, 'msg len');
});

t('seq=65535 single packet does not OOM', () => {
    const dec = new Decoder();
    const r = dec.processPacket(encodePacket(new Uint8Array([1]), 0xDEAD, 65535));
    assertTrue(r.accepted, 'should accept seq=65535 (within MAX_PACKETS)');
    // Map has 1 entry, maxSeq=65535, isComplete=false → no big array allocated
    assertTrue(!r.complete, 'should not be complete');
});

t('Session lock recovery after threshold mismatches', () => {
    const dec = new Decoder();
    // Attacker locks
    dec.processPacket(encodePacket(new Uint8Array([1]), 0x11111111, 0));
    // 5 mismatches from real sender
    for (let i = 0; i < 4; i++) {
        const r = dec.processPacket(encodePacket(new Uint8Array([2]), 0x22222222, i));
        assertTrue(!r.accepted, `mismatch ${i} should be rejected`);
    }
    // 5th mismatch triggers unlock; new session takes over
    const r5 = dec.processPacket(encodePacket(new Uint8Array([2]), 0x22222222, 0));
    assertTrue(r5.accepted, '5th packet should be accepted (recovered)');
});

t('Wrong session always rejected (without recovery, single mismatch)', () => {
    const dec = new Decoder();
    dec.processPacket(encodePacket(new Uint8Array([1]), 0xAAAAAAAA, 0));
    const r = dec.processPacket(encodePacket(new Uint8Array([2]), 0xBBBBBBBB, 0));
    assertTrue(!r.accepted, 'should reject');
});

t('Truncated packet rejected', () => {
    const packet = encodePacket(new Uint8Array([1, 2, 3]), 0xCAFE, 0);
    const truncated = packet.slice(0, packet.length - 5);
    const dec = new Decoder();
    const r = dec.processPacket(truncated);
    assertTrue(!r.accepted, 'truncated should be rejected');
});

t('Bit-flip in CRC region detected', () => {
    const packet = encodePacket(new Uint8Array([1, 2, 3, 4, 5]), 0xCAFE, 0);
    packet[2] ^= 0x01;  // flip a bit in version
    const dec = new Decoder();
    const r = dec.processPacket(packet);
    assertTrue(!r.accepted, 'CRC violation should be rejected');
});

t('Bit-flip in payload detected', () => {
    const packet = encodePacket(new Uint8Array([1, 2, 3, 4, 5]), 0xCAFE, 0);
    packet[packet.length - 1] ^= 0x01;  // flip last payload byte
    const dec = new Decoder();
    const r = dec.processPacket(packet);
    assertTrue(!r.accepted, 'payload bit-flip should be rejected');
});

t('Reset clears all state', () => {
    const dec = new Decoder();
    dec.processPacket(encodePacket(new Uint8Array([1]), 0xCAFE, 0));
    dec.reset();
    // Now a new session should lock cleanly
    const r = dec.processPacket(encodePacket(new Uint8Array([2]), 0xBABE, 0));
    assertTrue(r.accepted, 'fresh session after reset should lock');
});

console.log('\n=== Summary ===');
console.log(`\x1b[32m${pass} passed\x1b[0m, \x1b[${fail ? 31 : 32}m${fail} failed\x1b[0m`);
process.exit(fail ? 1 : 0);
