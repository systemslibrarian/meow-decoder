#!/usr/bin/env node
// Smoke tests for the WebM → MP4 transcode pipeline (gemini #5).
//
// Runs under pure Node, no browser. Covers the parts that don't need
// WebCodecs: module loading, identity branch, Branch 3 fallback message,
// and end-to-end demux of a hand-crafted WebM fixture.
//
// The actual WebCodecs decode → encode → mux pipeline (Branch 2) is
// browser-only and is exercised by `tests/test_cross_browser.spec.js`.

let pass = 0, fail = 0;

function t(name, fn) {
    try {
        const result = fn();
        if (result && typeof result.then === 'function') {
            // Caller passed an async fn — handle separately.
            return result.then(
                () => { console.log(`  \x1b[32m✓\x1b[0m ${name}`); pass++; },
                (e) => { console.log(`  \x1b[31m✗\x1b[0m ${name}: ${e.message}`); fail++; },
            );
        }
        console.log(`  \x1b[32m✓\x1b[0m ${name}`);
        pass++;
    } catch (e) {
        console.log(`  \x1b[31m✗\x1b[0m ${name}: ${e.message}`);
        fail++;
    }
}

function assertEq(a, b, msg) {
    if (a !== b) throw new Error(`${msg}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}
function assert(cond, msg) {
    if (!cond) throw new Error(msg);
}

// ─── Test fixture builders ──────────────────────────────────────────────

function vintFromLen(value, len) {
    const marker = 1 << (8 - len);
    const buf = new Uint8Array(len);
    buf[0] = marker | ((value >> ((len - 1) * 8)) & 0xFF);
    for (let i = 1; i < len; i++) buf[i] = (value >> ((len - 1 - i) * 8)) & 0xFF;
    return buf;
}
function vintAuto(value) {
    for (let len = 1; len <= 8; len++) {
        const max = (1 << (7 * len)) - 2;
        if (value <= max) return vintFromLen(value, len);
    }
    throw new Error('value too large');
}
function idBytes(id) {
    const b = []; let n = id;
    while (n > 0) { b.unshift(n & 0xFF); n = Math.floor(n / 256); }
    return new Uint8Array(b);
}
function concat(arrs) {
    const total = arrs.reduce((s, a) => s + a.length, 0);
    const out = new Uint8Array(total);
    let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
}
function elem(id, body) { return concat([idBytes(id), vintAuto(body.length), body]); }
function uintBytes(value, len) {
    const buf = new Uint8Array(len);
    for (let i = 0; i < len; i++) buf[len - 1 - i] = (value >> (i * 8)) & 0xFF;
    return buf;
}

function buildSyntheticWebM({ codec = 'V_VP9', width = 320, height = 240, frames = [] } = {}) {
    // Default: one keyframe at t=0, one delta at t=33ms.
    if (frames.length === 0) {
        frames = [
            { t: 0, key: true, data: new Uint8Array([0xDE, 0xAD]) },
            { t: 33, key: false, data: new Uint8Array([0xBE, 0xEF, 0x42]) },
        ];
    }
    const ebmlHeader = elem(0x1A45DFA3, new Uint8Array(0));
    const info = elem(0x1549A966, elem(0x2AD7B1, uintBytes(1_000_000, 4)));
    const trackEntry = concat([
        elem(0xD7, uintBytes(1, 1)),
        elem(0x83, uintBytes(1, 1)),
        elem(0x86, new TextEncoder().encode(codec)),
        elem(0xE0, concat([
            elem(0xB0, uintBytes(width, 2)),
            elem(0xBA, uintBytes(height, 2)),
        ])),
    ]);
    const tracks = elem(0x1654AE6B, elem(0xAE, trackEntry));
    function blk(t, key, frame) {
        const tc = new Uint8Array(2);
        new DataView(tc.buffer).setInt16(0, t, false);
        return elem(0xA3, concat([vintFromLen(1, 1), tc, new Uint8Array([key ? 0x80 : 0x00]), frame]));
    }
    const blocks = frames.map((f) => blk(f.t, f.key, f.data));
    const cluster = elem(0x1F43B675, concat([elem(0xE7, uintBytes(0, 1)), ...blocks]));
    const segment = elem(0x18538067, concat([info, tracks, cluster]));
    return concat([ebmlHeader, segment]);
}

// ─── Tests ─────────────────────────────────────────────────────────────

console.log('\nWebM → MP4 smoke tests (gemini #5)\n');

(async () => {

await t('convert-webm-to-mp4.js loads in Node', () => {
    const m = require('/workspaces/meow-decoder/web_demo/static/convert-webm-to-mp4.js');
    assert(typeof m.convertWebMToMp4 === 'function', 'convertWebMToMp4 missing');
    assert(typeof m.isMp4Blob === 'function', 'isMp4Blob missing');
    assert(typeof m.canTranscodeViaWebCodecs === 'function', 'canTranscodeViaWebCodecs missing');
    assert(typeof m.transcodeWebMToMp4ViaWebCodecs === 'function', 'transcodeWebMToMp4ViaWebCodecs missing');
});

await t('mp4-muxer ESM is loadable', async () => {
    const mod = await import('/workspaces/meow-decoder/web_demo/static/vendor/mp4-muxer-5.2.2.mjs');
    assert(typeof mod.Muxer === 'function', 'Muxer export missing');
    assert(typeof mod.ArrayBufferTarget === 'function', 'ArrayBufferTarget export missing');
});

await t('webm-demuxer ESM is loadable', async () => {
    const mod = await import('/workspaces/meow-decoder/web_demo/static/vendor/webm-demuxer.mjs');
    assert(typeof mod.demuxWebMToVideoPackets === 'function', 'demuxWebMToVideoPackets missing');
});

await t('Branch 1 (identity): MP4 in → MP4 out', async () => {
    const m = require('/workspaces/meow-decoder/web_demo/static/convert-webm-to-mp4.js');
    const inBlob = new Blob([new Uint8Array([0x00, 0x00, 0x00, 0x18])], { type: 'video/mp4' });
    const out = await m.convertWebMToMp4(inBlob);
    assert(out instanceof Blob, 'output not a Blob');
    assertEq(out.type, 'video/mp4', 'output type');
});

await t('Branch 1 (identity): video/mp4;codecs=avc1 → video/mp4', async () => {
    const m = require('/workspaces/meow-decoder/web_demo/static/convert-webm-to-mp4.js');
    const inBlob = new Blob([new Uint8Array([0x00])], { type: 'video/mp4;codecs=avc1.42E01E' });
    const out = await m.convertWebMToMp4(inBlob);
    assertEq(out.type, 'video/mp4', 'normalized output type');
});

await t('Branch 3 fallback: WebM input + no WebCodecs → actionable error', async () => {
    const m = require('/workspaces/meow-decoder/web_demo/static/convert-webm-to-mp4.js');
    const fakeWebm = new Blob([new Uint8Array([0x1A, 0x45, 0xDF, 0xA3])], { type: 'video/webm' });
    let threw = false;
    try {
        await m.convertWebMToMp4(fakeWebm);
    } catch (e) {
        threw = true;
        assert(/ffmpeg|HandBrake|VLC|WebCodecs/.test(e.message),
            `error message should suggest offline tools, got: ${e.message}`);
    }
    assert(threw, 'expected rejection');
});

await t('non-Blob input → TypeError', async () => {
    const m = require('/workspaces/meow-decoder/web_demo/static/convert-webm-to-mp4.js');
    let threw = false;
    try { await m.convertWebMToMp4('not-a-blob'); }
    catch (e) { threw = e instanceof TypeError; }
    assert(threw, 'expected TypeError');
});

await t('demux: synthetic V_VP9 320x240 with 2 packets', async () => {
    const mod = await import('/workspaces/meow-decoder/web_demo/static/vendor/webm-demuxer.mjs');
    const buf = buildSyntheticWebM().buffer;
    const r = mod.demuxWebMToVideoPackets(buf);
    assertEq(r.codec, 'V_VP9', 'codec');
    assertEq(r.width, 320, 'width');
    assertEq(r.height, 240, 'height');
    assertEq(r.packets.length, 2, 'packet count');
    assertEq(r.packets[0].timestampUs, 0, 'p0 ts');
    assertEq(r.packets[1].timestampUs, 33000, 'p1 ts');
    assertEq(r.packets[0].isKeyframe, true, 'p0 keyframe');
    assertEq(r.packets[1].isKeyframe, false, 'p1 keyframe');
});

await t('demux: V_VP8 codec accepted', async () => {
    const mod = await import('/workspaces/meow-decoder/web_demo/static/vendor/webm-demuxer.mjs');
    const buf = buildSyntheticWebM({ codec: 'V_VP8' }).buffer;
    const r = mod.demuxWebMToVideoPackets(buf);
    assertEq(r.codec, 'V_VP8', 'codec');
});

await t('demux: V_AV1 codec rejected with helpful message', async () => {
    const mod = await import('/workspaces/meow-decoder/web_demo/static/vendor/webm-demuxer.mjs');
    const buf = buildSyntheticWebM({ codec: 'V_AV1' }).buffer;
    let threw = false;
    try { mod.demuxWebMToVideoPackets(buf); }
    catch (e) { threw = /unsupported.*codec/i.test(e.message); }
    assert(threw, 'expected unsupported-codec error');
});

await t('demux: empty / non-WebM input throws', async () => {
    const mod = await import('/workspaces/meow-decoder/web_demo/static/vendor/webm-demuxer.mjs');
    let threw = false;
    try { mod.demuxWebMToVideoPackets(new ArrayBuffer(0)); }
    catch (e) { threw = true; }
    assert(threw, 'expected error on empty buffer');
});

await t('demux: VINT decoders correct on edge values', async () => {
    const mod = await import('/workspaces/meow-decoder/web_demo/static/vendor/webm-demuxer.mjs');
    const t = mod.__test;
    // 1-byte VINT: 0x80 → value=0, length=1
    const r1 = t.readVint(new DataView(new Uint8Array([0x80]).buffer), 0);
    assertEq(r1.length, 1, '0x80 length');
    assertEq(r1.valueWithoutMarker, 0, '0x80 value');
    // 4-byte VINT: 0x1A45DFA3 → length=4, value=0x1A45DFA3 (with marker)
    const r4 = t.readVint(new DataView(new Uint8Array([0x1A, 0x45, 0xDF, 0xA3]).buffer), 0);
    assertEq(r4.length, 4, '0x1A.. length');
    assertEq(r4.value, 0x1A45DFA3, '0x1A.. value');
});

await t('mp4-muxer + Muxer instance constructible (sanity)', async () => {
    const { Muxer, ArrayBufferTarget } = await import('/workspaces/meow-decoder/web_demo/static/vendor/mp4-muxer-5.2.2.mjs');
    const m = new Muxer({
        target: new ArrayBufferTarget(),
        video: { codec: 'avc', width: 320, height: 240 },
        fastStart: 'in-memory',
    });
    assert(typeof m.addVideoChunk === 'function', 'addVideoChunk');
    assert(typeof m.finalize === 'function', 'finalize');
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);

})();
