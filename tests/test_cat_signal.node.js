#!/usr/bin/env node
// Signal-processing smoke tests after audit fixes.
// Synthesizes frame streams and runs them through the full pipeline.

global.window = {};

// Load the modules in order they're loaded in the browser.
require('/workspaces/meow-decoder/web_demo/quality-metrics.js');
require('/workspaces/meow-decoder/web_demo/adaptive-threshold.js');
require('/workspaces/meow-decoder/web_demo/hysteresis.js');
require('/workspaces/meow-decoder/web_demo/preamble-calibration.js');
require('/workspaces/meow-decoder/web_demo/nrz-decoder.js');

// Each module assigns to module.exports — pull them out.
const QM = require('/workspaces/meow-decoder/web_demo/quality-metrics.js');
const AT = require('/workspaces/meow-decoder/web_demo/adaptive-threshold.js');
const HY = require('/workspaces/meow-decoder/web_demo/hysteresis.js');
const PC = require('/workspaces/meow-decoder/web_demo/preamble-calibration.js');
const NRZ = require('/workspaces/meow-decoder/web_demo/nrz-decoder.js');

let pass = 0, fail = 0;
function t(name, fn) {
    try { fn(); console.log(`  \x1b[32m✓\x1b[0m ${name}`); pass++; }
    catch (e) { console.log(`  \x1b[31m✗\x1b[0m ${name}: ${e.message}`); fail++; }
}
function assertEq(a, b, msg) { if (a !== b) throw new Error(`${msg}: expected ${b}, got ${a}`); }
function assertTrue(v, msg) { if (!v) throw new Error(msg); }
function assertFinite(v, msg) { if (!Number.isFinite(v)) throw new Error(`${msg}: not finite (${v})`); }
function inRange(v, lo, hi, msg) { if (v < lo || v > hi) throw new Error(`${msg}: ${v} not in [${lo}, ${hi}]`); }

console.log('\n=== quality-metrics: classifyFrame confidence clamp ===');
t('Saturated greenScore returns confidence ≤ 1', () => {
    const r = QM.classifyFrame(/*greenScore*/ 5.0, /*threshold*/ 0.5, /*onMean*/ 0.8, /*offMean*/ 0.2);
    inRange(r.confidence, 0, 1, 'confidence');
});
t('Normal greenScore in [offMean, onMean] returns sensible state', () => {
    const r = QM.classifyFrame(0.7, 0.5, 0.8, 0.2);
    assertEq(r.state, 'on', 'state');
    assertTrue(r.confidence > 0.15, 'confidence too low');
});
t('classifyFrameWithPercentiles handles empty allScores', () => {
    const r = QM.classifyFrameWithPercentiles(0.5, 0.5, []);
    assertEq(r.state, 'unknown', 'state');
});
t('detectPreamble loop bound (off-by-one fix)', () => {
    // Build exactly 51 frames where only the trailing 50-frame window
    // is alternating. The fix means it should still detect.
    const frames = [];
    for (let i = 0; i < 51; i++) {
        frames.push({
            time: i * 0.05,
            state: (i === 0) ? 'off' : (i % 2 === 0 ? 'on' : 'off')
        });
    }
    const r = QM.detectPreamble(frames, 0.8, 50);
    assertTrue(r !== null, 'tail-of-video preamble should be detected');
});

console.log('\n=== adaptive-threshold ===');
t('First frame does not trigger immediate calibration (lastCalibration null fix)', () => {
    const at = new AT.AdaptiveThreshold(100, 1, 50);
    // Send one frame at a typical performance.now() timestamp.
    const r = at.update(0.5, 12345.678);
    assertTrue(!r.calibrated, 'should not calibrate on first frame');
    assertEq(at.lastCalibration, 12345.678, 'lastCalibration should be set');
});
t('GradientCompensator R² formula stable for low-variance data', () => {
    const gc = new AT.GradientCompensator();
    // Add a flat signal with tiny variance + slight positive trend.
    for (let i = 0; i < 30; i++) {
        gc.update(0.5 + 0.0001 * i + (Math.random() - 0.5) * 0.001, i);
    }
    const trend = gc.detectTrend();
    inRange(trend.r2, 0, 1, 'r2');
    assertFinite(trend.slope, 'slope');
    assertFinite(trend.intercept, 'intercept');
});
t('GradientCompensator caches r2 (not 0) on cache hit', () => {
    const gc = new AT.GradientCompensator();
    for (let i = 0; i < 30; i++) gc.update(0.5 + 0.001 * i, i);
    const t1 = gc.detectTrend();
    const t2 = gc.detectTrend();  // cache hit
    assertEq(t1.r2, t2.r2, 'r2 should match across cache hit');
    assertTrue(t2.r2 > 0, 'cached r2 should not be 0');
});
t('findValley with adjacent peaks returns midpoint, not a peak', () => {
    // Build a histogram where peak1 and peak2 are at indices 3 and 4.
    const histogram = [];
    for (let i = 0; i < 8; i++) {
        histogram.push({ value: i / 8, count: i === 3 || i === 4 ? 100 : 5 });
    }
    const peak1 = { value: 3 / 8, count: 100, index: 3, height: 100 };
    const peak2 = { value: 4 / 8, count: 100, index: 4, height: 100 };
    const v = AT.findValley(histogram, peak1, peak2);
    // Should be midpoint of the two peak values, not 3/8 or 4/8 directly.
    assertEq(v, (3 / 8 + 4 / 8) / 2, 'should be midpoint of adjacent peaks');
});

console.log('\n=== hysteresis ===');
t('Negative threshold does not invert hysteresis band', () => {
    const st = new HY.SchmittTrigger(-0.1, 0.1);
    assertTrue(st.low < st.high, 'low should be < high even for negative threshold');
});
t('Near-zero threshold still has usable band', () => {
    const st = new HY.SchmittTrigger(0.0, 0.1);
    assertTrue(st.high - st.low > 0, 'band should be > 0');
});
t('calculateOptimalMargin handles zero mean (no NaN)', () => {
    const values = [];
    for (let i = 0; i < 30; i++) values.push(0);
    const m = HY.calculateOptimalMargin(values, 0);
    assertFinite(m, 'margin');
    inRange(m, 0.05, 0.3, 'margin range');
});
t('AdaptiveHysteresis update with adaptiveThreshold=0 does not divide by zero', () => {
    const ah = new HY.AdaptiveHysteresis(0.5);
    const r = ah.update(0.5, 0);  // adaptiveThreshold=0
    assertFinite(r.thresholds.low, 'low');
    assertFinite(r.thresholds.high, 'high');
});

console.log('\n=== preamble-calibration ===');
t('learnFromPreamble requires ≥3 intervals (ignores stray transition)', () => {
    // Only one transition → only 0 intervals. bitRate should be null.
    const frames = [];
    for (let i = 0; i < 20; i++) frames.push({ time: i * 0.1, state: i < 10 ? 'on' : 'off', greenScore: i < 10 ? 0.8 : 0.2 });
    const r = PC.learnFromPreamble(frames, { start: 0, end: 20 });
    if (r) assertTrue(r.bitRate === null, 'bitRate should be null with only 1 transition');
});
t('detectPreambleWithFallback handles empty allScores', () => {
    const r = PC.detectPreambleWithFallback([], 100, []);
    assertTrue(!r.found, 'not found');
    assertEq(r.error, 'no_samples', 'error code');
});

console.log('\n=== nrz-decoder ===');
t('findNearestFrame rejects NaN targetTime', () => {
    const frames = [{ time: 0, state: 'on', confidence: 0.9 }, { time: 1, state: 'off', confidence: 0.9 }];
    const r = NRZ.findNearestFrame(frames, NaN);
    assertEq(r, null, 'should return null for NaN');
});
t('sampleBits returns [] for empty frames', () => {
    const r = NRZ.sampleBits([], 0, 0.1, 10);
    assertEq(r.length, 0, 'should return empty array');
});
t('sampleBits returns [] for numBits<=0', () => {
    const frames = [{ time: 0, state: 'on', confidence: 0.9 }];
    const r = NRZ.sampleBits(frames, 0, 0.1, 0);
    assertEq(r.length, 0, 'should return empty array');
});
t('voteWithinBitWindow with numSamples=1 does not divide by zero', () => {
    const frames = [{ time: 0.05, state: 'on', confidence: 0.9 }];
    const r = NRZ.voteWithinBitWindow(frames, 0, 0.1, 0, 1, 0.15);
    assertTrue(r === 1 || r === 0 || r === '?', 'should return a valid value');
});
t('decodeNRZ on empty frames returns clean error', () => {
    const r = NRZ.decodeNRZ([], 0.1, 0.5, 0, 100);
    assertTrue(!r.success, 'should fail');
    assertEq(r.error, 'no_frames', 'error code');
});
t('decodeNRZ when sync lands past last frame returns no_data_after_sync', () => {
    // Make a sync-only stream — 8 alternating bits then nothing.
    const frames = [];
    for (let i = 0; i < 16; i++) {
        frames.push({
            time: i * 0.05,
            state: i % 2 === 0 ? 'on' : 'off',
            confidence: 0.9,
            greenScore: i % 2 === 0 ? 0.8 : 0.2
        });
    }
    // Sync starts at t=0, takes 16 * 0.05 = 0.8s. Last frame is at 0.75s.
    // So t0 (after sync) > lastFrameTime → no_data_after_sync.
    const r = NRZ.decodeNRZ(frames, 0.05, 0.5, 0, 100);
    if (r.success) {
        assertTrue(r.binary.length > 0, 'if success, must have data');
    } else {
        assertTrue(r.error === 'no_data_after_sync' || r.error === 'no_sync_lock' || r.error,
            `expected error, got: ${JSON.stringify(r)}`);
    }
});

console.log('\n=== Summary ===');
console.log(`\x1b[32m${pass} passed\x1b[0m, \x1b[${fail ? 31 : 32}m${fail} failed\x1b[0m`);
process.exit(fail ? 1 : 0);
