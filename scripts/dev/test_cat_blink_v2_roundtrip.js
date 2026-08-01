/**
 * Dev harness: prove the wasm_browser_example_FULL.html v2 transmit path calls
 * CatBlinkV2.encode/decode the way the codec expects.
 *
 * This does NOT re-test the codec (it has its own unit tests); it only exercises
 * the exact call shape the HTML transmit path uses:
 *   CatBlinkV2.encode(payloadBytes, {blockSize:32, redundancy:4.0})
 *   -> { frames, kBlocks, blockSize, originalLength, frameCount }
 *   CatBlinkV2.decode(frames) -> Uint8Array == payloadBytes
 *
 * Run: node scripts/dev/test_cat_blink_v2_roundtrip.js
 */
'use strict';
const path = require('path');
const CatBlinkV2 = require(path.join(__dirname, '..', '..', 'web_demo', 'static', 'cat-blink-v2.js'));

function assert(cond, msg) {
  if (!cond) { console.error('FAIL: ' + msg); process.exit(1); }
}

// A "MEOW:"-shaped encrypted payload stand-in (the HTML feeds these exact bytes).
const sample = new TextEncoder().encode(
  'MEOW:' + Buffer.from('the quick brown cat blinks over the lazy dog '.repeat(4)).toString('base64')
);

const { frames, kBlocks, blockSize, originalLength, frameCount } =
  CatBlinkV2.encode(sample, { blockSize: 32, redundancy: 4.0 });

console.log(`payloadBytes=${sample.length} kBlocks=${kBlocks} blockSize=${blockSize} ` +
  `frameCount=${frameCount} frameBits=${frames[0].length}`);

assert(frames.length === frameCount, 'frames.length === frameCount');
assert(blockSize === 32, 'blockSize honoured');
assert(originalLength === sample.length, 'originalLength === payload length');
assert(frames.every(f => /^[01]+$/.test(f)), 'frames are pure bitstrings');
// Frame bit length VARIES per droplet: droplet len = 4+2+count*2+blockSize and
// `count` (fountain degree) differs per droplet. The sampler therefore cannot
// assume a fixed frame width — it must resync on SYNC each frame. This is why
// the transmit path inserts a per-frame guard run between frames.
const lens = frames.map(f => f.length);
console.log(`frame bit lengths: min=${Math.min(...lens)} max=${Math.max(...lens)} ` +
  `distinct=${new Set(lens).size}`);

// Full round-trip.
const out = CatBlinkV2.decode(frames);
assert(out, 'decode returned a payload');
assert(out.length === sample.length, `decoded length ${out ? out.length : 'null'} === ${sample.length}`);
for (let i = 0; i < sample.length; i++) assert(out[i] === sample[i], `byte ${i} matches`);

// Lossy subset round-trip (drop 30% of frames) — mirrors camera blink loss.
const kept = frames.filter((_, i) => i % 10 >= 3);
const out2 = CatBlinkV2.decode(kept);
assert(out2 && out2.length === sample.length, 'lossy-subset decode still round-trips');
for (let i = 0; i < sample.length; i++) assert(out2[i] === sample[i], `lossy byte ${i} matches`);

// decodeFrame on a single good frame recovers the fountain params (used by the
// sampler to learn k/blockSize from any one frame).
const one = CatBlinkV2.decodeFrame(frames[0]);
assert(one && one.kBlocks === kBlocks && one.blockSize === blockSize, 'decodeFrame recovers params');

console.log('PASS: CatBlinkV2 encode/decode round-trip (full + 30% loss) OK');
