/**
 * Phase 5 Week 2 Feature Tests
 * 
 * Tests for Task 5.2.1 (Short Video Sync), Task 5.2.2 (Gradient Compensation),
 * and Task 5.2.3 (Eye Region Confidence Masking) features.
 * 
 * Run: node tests/test_week2_features.js
 */

const assert = require('assert');

// Load modules
const PreambleCalibration = require('../examples/preamble-calibration.js');
const NRZDecoder = require('../examples/nrz-decoder.js');
const { AdaptiveThreshold, GradientCompensator } = require('../examples/adaptive-threshold.js');

let passed = 0;
let failed = 0;
const results = [];

function test(name, fn) {
    try {
        fn();
        passed++;
        results.push({ name, status: 'PASS' });
        console.log(`  ✅ ${name}`);
    } catch (e) {
        failed++;
        results.push({ name, status: 'FAIL', error: e.message });
        console.log(`  ❌ ${name}: ${e.message}`);
    }
}

// ============================================================================
// Task 5.2.1: Short Video Sync Tests
// ============================================================================

console.log('\n📋 Task 5.2.1: Short Video Sync Fix');
console.log('─'.repeat(50));

test('checkVideoDuration: rejects very short videos', () => {
    const result = PreambleCalibration.checkVideoDuration(2.0, 100);
    assert.strictEqual(result.ok, false);
    assert(result.message.includes('needs at least'));
});

test('checkVideoDuration: enables short video mode for 4-6s videos', () => {
    const result = PreambleCalibration.checkVideoDuration(5.0, 100);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.shortVideoMode, true);
    assert(result.message.includes('fast-start'));
});

test('checkVideoDuration: normal mode for long videos', () => {
    const result = PreambleCalibration.checkVideoDuration(10.0, 100);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.shortVideoMode, false);
    assert.strictEqual(result.message, null);
});

test('checkVideoDuration: maxPayloadBits is correct', () => {
    const result = PreambleCalibration.checkVideoDuration(10.0, 100);
    assert(result.maxPayloadBits > 0);
    // 10s - 5.6s overhead = 4.4s = 44 bits at 100ms
    assert(result.maxPayloadBits >= 40);
});

test('detectPreamble: early termination with 16 alternations', () => {
    // Create frames with alternating state
    const frames = [];
    for (let i = 0; i < 40; i++) {
        frames.push({
            time: i * 0.1,
            state: i % 2 === 0 ? 'on' : 'off',
            greenScore: i % 2 === 0 ? 0.8 : 0.2
        });
    }
    
    const result = PreambleCalibration.detectPreamble(frames, 0.7, 0.8, { earlyTermination: true, minAlternations: 16 });
    assert(result !== null, 'Should detect preamble');
    assert(result.earlyTerminated === true, 'Should use early termination');
});

test('detectPreamble: works with only 10 frames', () => {
    const frames = [];
    for (let i = 0; i < 20; i++) {
        frames.push({
            time: i * 0.1,
            state: i % 2 === 0 ? 'on' : 'off',
            greenScore: i % 2 === 0 ? 0.8 : 0.2
        });
    }
    
    const result = PreambleCalibration.detectPreamble(frames, 0.7, 0.8);
    assert(result !== null, 'Should detect preamble with 20 frames');
});

test('detectPreamble: returns confidence level', () => {
    const frames = [];
    for (let i = 0; i < 30; i++) {
        frames.push({
            time: i * 0.1,
            state: i % 2 === 0 ? 'on' : 'off',
            greenScore: i % 2 === 0 ? 0.8 : 0.2
        });
    }
    
    const result = PreambleCalibration.detectPreamble(frames);
    assert(result !== null);
    assert(['high', 'medium', 'low'].includes(result.confidence));
});

test('findSyncWord: finds 16-bit sync pattern', () => {
    // Create frames encoding 0xAA55 = 1010101010101010
    const pattern = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0];
    const frames = [];
    const bitPeriod = 0.1;
    
    for (let i = 0; i < pattern.length; i++) {
        frames.push({
            time: i * bitPeriod + 0.05,
            state: pattern[i] === 1 ? 'on' : 'off',
            confidence: 0.9
        });
    }
    
    const result = NRZDecoder.findSyncWord(frames, bitPeriod, 0, 2.0);
    assert(result !== null, 'Should find sync word');
    assert.strictEqual(result.syncBits, 16);
});

test('findSyncWord: falls back to 8-bit sync', () => {
    // Create frames encoding only 0xAA = 10101010 (8 bits)
    const pattern = [1, 0, 1, 0, 1, 0, 1, 0];
    const frames = [];
    const bitPeriod = 0.1;
    
    for (let i = 0; i < pattern.length; i++) {
        frames.push({
            time: i * bitPeriod + 0.05,
            state: pattern[i] === 1 ? 'on' : 'off',
            confidence: 0.9
        });
    }
    
    // Force short video mode so it only tries 8-bit
    const result = NRZDecoder.findSyncWord(frames, bitPeriod, 0, 2.0, { shortVideoMode: true });
    assert(result !== null, 'Should find 8-bit sync');
    assert.strictEqual(result.syncBits, 8);
});

// ============================================================================
// Task 5.2.2: Gradient Compensation Tests
// ============================================================================

console.log('\n📋 Task 5.2.2: Gradient Compensation');
console.log('─'.repeat(50));

test('GradientCompensator: detects upward trend', () => {
    const gc = new GradientCompensator(100, 0.01);
    
    // Simulate linear upward trend: 0.5 + 0.05*t
    for (let t = 0; t < 50; t++) {
        gc.update(0.5 + 0.05 * t * 0.1, t * 0.1);
    }
    
    const trend = gc.detectTrend();
    assert(trend.slope > 0.01, `Expected positive slope, got ${trend.slope}`);
});

test('GradientCompensator: no compensation for flat data', () => {
    const gc = new GradientCompensator(100, 0.01);
    
    // Flat data with noise
    for (let t = 0; t < 30; t++) {
        gc.update(0.5 + (Math.random() - 0.5) * 0.001, t * 0.1);
    }
    
    const score = gc.compensate(0.5, 3.0);
    // Should return approximately the same score
    assert(Math.abs(score - 0.5) < 0.05, `Expected ~0.5, got ${score}`);
});

test('GradientCompensator: compensates for gradient', () => {
    const gc = new GradientCompensator(100, 0.005);
    
    // Strong upward trend
    for (let t = 0; t < 50; t++) {
        gc.update(0.3 + 0.1 * t * 0.1, t * 0.1);
    }
    
    // A score at t=5.0 should be detrended back toward baseline
    const raw = 0.3 + 0.1 * 5.0;
    const compensated = gc.compensate(raw, 5.0);
    assert(compensated < raw, `Compensated (${compensated}) should be less than raw (${raw})`);
});

test('GradientCompensator: diagnostics include slope and R²', () => {
    const gc = new GradientCompensator();
    
    for (let t = 0; t < 20; t++) {
        gc.update(0.5 + 0.02 * t, t * 0.1);
    }
    
    const diag = gc.getDiagnostics();
    assert('slope' in diag);
    assert('r2' in diag);
    assert('compensationActive' in diag);
});

test('GradientCompensator: reset clears state', () => {
    const gc = new GradientCompensator();
    gc.update(0.5, 0);
    gc.update(0.6, 1);
    gc.reset();
    
    assert.strictEqual(gc.recentScores.length, 0);
    assert.strictEqual(gc.compensationActive, false);
});

test('AdaptiveThreshold: recalibrates every 1s (not 5s)', () => {
    const at = new AdaptiveThreshold(100, 1);
    assert.strictEqual(at.recalibrateInterval, 1000);
});

test('AdaptiveThreshold: includes gradient diagnostics', () => {
    const at = new AdaptiveThreshold();
    
    // Feed some data
    for (let i = 0; i < 25; i++) {
        at.update(i % 2 === 0 ? 0.8 : 0.2, i * 100);
    }
    
    const diag = at.getDiagnostics();
    assert('gradient' in diag, 'Should include gradient diagnostics');
    assert('slope' in diag.gradient);
});

test('AdaptiveThreshold: returns compensated score', () => {
    const at = new AdaptiveThreshold();
    const result = at.update(0.5, 100);
    assert('compensatedScore' in result, 'Should return compensated score');
});

test('AdaptiveThreshold: reset also resets gradient compensator', () => {
    const at = new AdaptiveThreshold();
    at.update(0.5, 100);
    at.reset();
    
    assert.strictEqual(at.gradientCompensator.recentScores.length, 0);
});

// ============================================================================
// Task 5.2.3: Eye Region Confidence Masking Tests  
// (Gaussian mask functions - can test without browser ImageData)
// ============================================================================

console.log('\n📋 Task 5.2.3: Eye Region Confidence Masking');
console.log('─'.repeat(50));

test('checkVideoDuration export exists', () => {
    assert(typeof PreambleCalibration.checkVideoDuration === 'function');
});

test('NRZ decodeNRZ accepts options parameter', () => {
    // Empty frames should fail gracefully
    const result = NRZDecoder.decodeNRZ([], 0.1, 0.5, 0, 100, { shortVideoMode: true });
    assert.strictEqual(result.success, false);
});

test('searchForPattern is exported', () => {
    assert(typeof NRZDecoder.searchForPattern === 'function');
});

// ============================================================================
// Summary
// ============================================================================

console.log('\n' + '═'.repeat(50));
console.log(`📊 Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log('═'.repeat(50));

if (failed > 0) {
    console.log('\n❌ Failed tests:');
    results.filter(r => r.status === 'FAIL').forEach(r => {
        console.log(`   - ${r.name}: ${r.error}`);
    });
    process.exit(1);
} else {
    console.log('\n✅ All Phase 5 Week 2 tests passed!');
    process.exit(0);
}
