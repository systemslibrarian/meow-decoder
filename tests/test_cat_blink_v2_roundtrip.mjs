/**
 * Cat Blink v2 round-trip + erasure-tolerance test (no device needed).
 *
 * Proves the core value of the v2 wire format: a fountain-coded blink stream
 * reconstructs the payload even when the phone misses a fraction of frames.
 *
 * Run: node tests/test_cat_blink_v2_roundtrip.mjs
 */
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const require = createRequire(import.meta.url);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CatBlinkV2 = require(resolve(ROOT, 'web_demo/static/cat-blink-v2.js'));

let pass = 0;
let fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Deterministic PRNG so CI is reproducible (no Math.random).
function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function makePayload(n, seed) {
  const rng = mulberry32(seed);
  const p = new Uint8Array(n);
  for (let i = 0; i < n; i++) p[i] = Math.floor(rng() * 256);
  return p;
}

console.log('Cat Blink v2 round-trip:');

// 1. Clean round-trip across a range of payload sizes.
for (const size of [1, 16, 40, 100, 250]) {
  const payload = makePayload(size, size * 7 + 1);
  const { frames } = CatBlinkV2.encode(payload, { blockSize: 32, redundancy: 3.0 });
  const recovered = CatBlinkV2.decode(frames);
  check(`clean round-trip, ${size} bytes`, recovered && bytesEqual(recovered, payload));
}

// 2. Frame CRC rejects a single flipped blink (corrupt frame → dropped, not accepted).
{
  const payload = makePayload(64, 99);
  const { frames } = CatBlinkV2.encode(payload, { blockSize: 32 });
  const bad = frames[2].split('');
  bad[50] = bad[50] === '1' ? '0' : '1'; // flip one bit (one misread blink)
  check('CRC rejects a corrupted frame', CatBlinkV2.decodeFrame(bad.join('')) === null);
}

// 3. Erasure tolerance: drop a fraction of frames (glare/motion/slow frames),
//    shuffle the rest (loop wrap / out-of-order), still recover.
function dropAndShuffle(frames, dropFrac, rng) {
  const kept = frames.filter(() => rng() >= dropFrac);
  for (let i = kept.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [kept[i], kept[j]] = [kept[j], kept[i]];
  }
  return kept;
}
for (const drop of [0.1, 0.25, 0.4]) {
  const payload = makePayload(120, Math.round(drop * 1000));
  // Higher redundancy for the lossy channel, mirroring the QR path's 4.0x.
  const { frames } = CatBlinkV2.encode(payload, { blockSize: 32, redundancy: 4.0 });
  const rng = mulberry32(1234 + Math.round(drop * 100));
  const lossy = dropAndShuffle(frames, drop, rng);
  const recovered = CatBlinkV2.decode(lossy);
  check(`recover through ${Math.round(drop * 100)}% frame loss (${lossy.length}/${frames.length} frames)`,
    recovered && bytesEqual(recovered, payload));
}

// 4. A MEOW: text payload (what the real encrypted blob looks like) survives loss.
{
  const text = 'MEOW:' + 'A'.repeat(180);
  const payload = new TextEncoder().encode(text);
  const { frames } = CatBlinkV2.encode(payload, { blockSize: 32, redundancy: 4.0 });
  const rng = mulberry32(777);
  const lossy = dropAndShuffle(frames, 0.3, rng);
  const recovered = CatBlinkV2.decode(lossy);
  const ok = recovered && new TextDecoder().decode(recovered) === text;
  check('MEOW: payload recovers through 30% loss', ok);
}

// 5. Too much loss must fail cleanly (null), never wrong bytes.
{
  const payload = makePayload(120, 5);
  const { frames } = CatBlinkV2.encode(payload, { blockSize: 32, redundancy: 4.0 });
  const rng = mulberry32(42);
  const shredded = dropAndShuffle(frames, 0.85, rng);
  const recovered = CatBlinkV2.decode(shredded);
  check('excessive loss fails cleanly (null, not wrong data)',
    recovered === null || bytesEqual(recovered, payload));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
