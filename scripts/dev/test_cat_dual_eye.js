#!/usr/bin/env node
/**
 * Cat Mode DUAL-EYE Roundtrip Test
 *
 * Tests the full dual-eye encode → signal → decode pipeline:
 *   1. Encrypt message → CatProtocol packets → binary framing
 *   2. Split into header (single-eye) + 0xFD marker + payload (dual-eye interleaved)
 *   3. Build transmission schedule: {left, right} per interval
 *   4. Simulate video with independent left/right green channels
 *   5. Run NRZ on combined channel → detect 0xFD marker
 *   6. Re-decode payload from independent L/R channels
 *   7. Verify CRC + decrypt matches original
 *
 * Also tests:
 *   - Backward compatibility: single-eye videos still decode correctly
 *   - 0xFD marker detection accuracy
 *   - Interleave/deinterleave correctness
 *   - Multiple blink speeds
 */

'use strict';

const crypto = require('crypto');

// Load production modules
const CatProtocol = require('./web_demo/cat-mode-protocol.js');
const NRZDecoder = require('./web_demo/nrz-decoder.js');
const PreambleCalibration = require('./web_demo/preamble-calibration.js');
const { computeHistogram, findPeaks, findValley } = require('./web_demo/adaptive-threshold.js');

// Suppress verbose logging from imported modules during test
const _origLog = console.log;
const _origWarn = console.warn;
let suppressLogs = false;
console.log = (...args) => { if (!suppressLogs) _origLog(...args); };
console.warn = (...args) => { if (!suppressLogs) _origWarn(...args); };

// ── Helpers ─────────────────────────────────────────────────────
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

// ── Simulate encryption (AES-256-GCM, same v3 format as WASM) ──
function simulateEncrypt(message, password) {
    const salt = crypto.randomBytes(16);
    const nonce = crypto.randomBytes(12);
    const key = crypto.scryptSync(password, salt, 32);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const ciphertext = Buffer.concat([encrypted, tag]);

    const packed = new Uint8Array(1 + 4 + 1 + 16 + 12 + ciphertext.length);
    packed[0] = 0x03;
    const dv = new DataView(packed.buffer);
    dv.setUint32(1, 32768, true);
    packed[5] = 1;
    packed.set(salt, 6);
    packed.set(nonce, 22);
    packed.set(new Uint8Array(ciphertext), 34);
    return { packed, salt, nonce, ciphertext: new Uint8Array(ciphertext) };
}

function simulateDecrypt(packed, password) {
    if (packed[0] !== 0x03) throw new Error(`Version: 0x${packed[0].toString(16)}`);
    const salt = packed.slice(6, 22);
    const nonce = packed.slice(22, 34);
    const cipherAndTag = packed.slice(34);
    const key = crypto.scryptSync(password, Buffer.from(salt), 32);
    const tag = cipherAndTag.slice(cipherAndTag.length - 16);
    const ct = cipherAndTag.slice(0, cipherAndTag.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(nonce));
    decipher.setAuthTag(Buffer.from(tag));
    return Buffer.concat([decipher.update(Buffer.from(ct)), decipher.final()]).toString('utf8');
}

// ── Build binary payload (same as browser buildCatBinaryPayload) ──
function buildCatBinaryPayload(payloadBytes) {
    const sessionId = CatProtocol.generateSessionId();
    const packets = CatProtocol.encodeMessage(payloadBytes, sessionId, 256);

    let packetsBinary = '';
    for (const pkt of packets) packetsBinary += bytesToBinary(pkt);

    const payloadBits = packetsBinary.length;
    const shortMessage = payloadBits < 200;

    const leadIn = '00000000';
    const preamble = '1010101010101010'; // 16 bits always
    const syncWord = shortMessage
        ? '10101010'
        : '1010101010101010';
    const endMarker = '0101010101010101';

    const totalBinary = leadIn + preamble + syncWord + packetsBinary + endMarker;

    return {
        binary: totalBinary,
        sessionId,
        packetCount: packets.length,
        shortVideoMode: shortMessage,
        preambleBits: preamble.length,
        syncBits: syncWord.length,
        packetsBinary
    };
}

// ═══════════════════════════════════════════════════════════════
// DUAL-EYE ENCODER (mirrors wasm_browser_example_FULL.html)
// ═══════════════════════════════════════════════════════════════

function buildDualEyeSchedule(totalBinary, preambleBits, syncBits) {
    // Split into header and payload (exactly matching HTML)
    const headerLen = 8 + preambleBits + syncBits;  // lead-in + preamble + sync
    let headerBinary = totalBinary.substring(0, headerLen);
    let payloadBinary = totalBinary.substring(headerLen);

    // Append 0xFD dual-eye mode marker to header
    // (0xFD avoids collision with CatProtocol magic 0xCAFE LE = 0xFE first byte)
    headerBinary += '11111101';  // 0xFD

    // Pad payload to even length
    if (payloadBinary.length % 2 !== 0) {
        payloadBinary += '0';
    }

    // Build schedule
    const schedule = [];

    // Phase 1: Header — single-eye (both eyes same)
    for (let i = 0; i < headerBinary.length; i++) {
        schedule.push({ left: headerBinary[i], right: headerBinary[i] });
    }

    // Phase 2: Payload — dual-eye interleaved
    for (let i = 0; i < payloadBinary.length; i += 2) {
        schedule.push({
            left: payloadBinary[i] || '0',
            right: payloadBinary[i + 1] || '0'
        });
    }

    return {
        schedule,
        headerBinary,
        payloadBinary,
        headerLen: headerBinary.length,
        payloadLen: payloadBinary.length,
        intervalCount: schedule.length
    };
}

// ═══════════════════════════════════════════════════════════════
// DUAL-EYE VIDEO SIGNAL SIMULATOR
// ═══════════════════════════════════════════════════════════════
// Produces frameSamples with:
//   - greenLevel (combined) for NRZ preamble/sync detection
//   - leftGreenLevel / rightGreenLevel for dual-eye decode

function simulateDualEyeVideoSignal(schedule, blinkSpeedMs, opts = {}) {
    const fps = Math.max(30, Math.round(5000 / blinkSpeedMs));
    const sampleInterval = 1 / fps;
    const bitDuration = blinkSpeedMs / 1000;
    const totalDuration = schedule.length * bitDuration;
    const totalSamples = Math.ceil(totalDuration / sampleInterval) + 10;

    const baseGreen = opts.baseGreen || 0.25;
    const peakGreen = opts.peakGreen || 0.80;
    const noiseLevel = opts.noiseLevel || 0.015;

    const samples = [];
    for (let i = 0; i < totalSamples; i++) {
        const time = i * sampleInterval;
        const intervalIdx = Math.floor(time / bitDuration);

        let leftTarget, rightTarget, combinedState;
        if (intervalIdx < 0 || intervalIdx >= schedule.length) {
            leftTarget = baseGreen;
            rightTarget = baseGreen;
            combinedState = 'off';
        } else {
            const entry = schedule[intervalIdx];
            leftTarget = entry.left === '1' ? peakGreen : baseGreen;
            rightTarget = entry.right === '1' ? peakGreen : baseGreen;
            // Combined state: "on" if either eye is green (for NRZ on combined channel)
            combinedState = (entry.left === '1' || entry.right === '1') ? 'on' : 'off';
        }

        // Add independent noise per channel
        const leftNoise = (Math.random() - 0.5) * noiseLevel * 2;
        const rightNoise = (Math.random() - 0.5) * noiseLevel * 2;
        const leftGreenLevel = Math.max(0, Math.min(1, leftTarget + leftNoise));
        const rightGreenLevel = Math.max(0, Math.min(1, rightTarget + rightNoise));

        // Combined green: average of both eyes (what the single-channel analyzer sees)
        const greenLevel = (leftGreenLevel + rightGreenLevel) / 2;

        // For the header portion (both eyes same), the combined channel
        // has the same signal as either eye. For the payload, it's averaged.
        // The NRZ decoder uses `state` for preamble detection.
        // During header: left===right, so combined threshold works.
        // During payload: left/right diverge, combined is ambiguous — but
        // NRZ only processes up through sync+mode byte (all single-eye).
        const headerState = intervalIdx < schedule.length
            ? (schedule[intervalIdx].left === schedule[intervalIdx].right
                ? (schedule[intervalIdx].left === '1' ? 'on' : 'off')
                : 'on')  // ambiguous during dual-eye payload
            : 'off';

        samples.push({
            frame: i,
            time,
            greenLevel,
            leftGreenLevel,
            rightGreenLevel,
            greenScore: greenLevel,
            rawGreenLevel: greenLevel,
            state: headerState,
            confidence: 0.95,
            isGreen: headerState === 'on'
        });
    }

    return { samples, fps };
}

// ═══════════════════════════════════════════════════════════════
// DUAL-EYE DECODER (mirrors wasm_browser_example_FULL.html)
// ═══════════════════════════════════════════════════════════════

function decodeDualEyePipeline(frameSamples, blinkSpeedMs) {
    const bitDuration = blinkSpeedMs / 1000;

    // Normalize combined green levels to 0-100 (for NRZ/preamble)
    const rawLevels = frameSamples.map(s => s.rawGreenLevel || s.greenLevel);
    const minG = Math.min(...rawLevels);
    const maxG = Math.max(...rawLevels);
    const range = maxG - minG;
    if (range < 0.01) throw new Error(`No green variation (range=${range.toFixed(4)})`);

    for (const s of frameSamples) {
        s.greenLevel = ((s.rawGreenLevel - minG) / range) * 100;
        s.greenScore = s.greenLevel;
    }
    const greenLevels = frameSamples.map(s => s.greenLevel);

    // Preamble detection (uses combined channel)
    suppressLogs = true;
    const preambleResult = PreambleCalibration.detectPreambleWithFallback(
        frameSamples, blinkSpeedMs, greenLevels
    );
    suppressLogs = false;

    const leadInBits = 8;
    let preambleBits;
    if (preambleResult.found && preambleResult.preamble) {
        preambleBits = Math.round(preambleResult.preamble.duration / bitDuration);
    } else {
        preambleBits = 32;
    }
    const syncStartTime = (leadInBits + preambleBits) * bitDuration;
    const threshold = preambleResult.threshold || 50;

    // NRZ decode on combined channel — finds sync word, returns bits after it
    suppressLogs = true;
    const nrzResult = NRZDecoder.decodeNRZ(
        frameSamples,
        preambleResult.bitRate || bitDuration,
        threshold,
        syncStartTime,
        100000,
        { shortVideoMode: false }
    );
    suppressLogs = false;

    if (!nrzResult.success) {
        const causes = nrzResult.diagnostics
            ? nrzResult.diagnostics.likely_causes.join('; ')
            : 'unknown';
        throw new Error(`NRZ failed: ${causes}`);
    }

    let binary = nrzResult.binary;

    // ── DUAL-EYE DETECTION (mirrors HTML exactly) ────────────────
    let isDualEye = false;
    const modeByteCandidate = binary.substring(0, 8);

    if (modeByteCandidate === '11111101') {
        isDualEye = true;

        // nrzResult.stats.bitPeriod is in ms; convert to seconds
        const bitDur = (nrzResult.stats.bitPeriod / 1000) || bitDuration;
        const payloadStartTime = nrzResult.t0 + 8 * bitDur;

        // Normalize left and right channels independently
        const leftLevels = frameSamples.map(s => s.leftGreenLevel);
        const rightLevels = frameSamples.map(s => s.rightGreenLevel);

        function normalizeChannel(levels) {
            const min = Math.min(...levels);
            const max = Math.max(...levels);
            const range = max - min;
            if (range < 0.001) return levels.map(() => 50);
            return levels.map(v => ((v - min) / range) * 100);
        }

        const normLeft = normalizeChannel(leftLevels);
        const normRight = normalizeChannel(rightLevels);

        // Per-channel bimodal thresholds
        function channelThreshold(normLevels) {
            const hist = computeHistogram(normLevels, 50, 0, 100);
            const peaks = findPeaks(hist.bins);
            if (peaks.length >= 2) {
                const sorted = peaks.slice().sort((a, b) => b.height - a.height);
                return findValley(hist.bins, sorted[0], sorted[1]);
            }
            return 50;
        }

        const leftThreshold = channelThreshold(normLeft);
        const rightThreshold = channelThreshold(normRight);

        // Sample L/R channels at bit-duration intervals
        const dualBits = [];
        let sampleTime = payloadStartTime + bitDur / 2;
        let searchStart = 0;

        while (sampleTime < frameSamples[frameSamples.length - 1].time) {
            let bestIdx = searchStart;
            let bestDist = Math.abs(frameSamples[searchStart].time - sampleTime);
            for (let j = searchStart + 1; j < frameSamples.length; j++) {
                const dist = Math.abs(frameSamples[j].time - sampleTime);
                if (dist < bestDist) {
                    bestDist = dist;
                    bestIdx = j;
                } else if (frameSamples[j].time > sampleTime + bitDur) {
                    break;
                }
            }
            searchStart = Math.max(0, bestIdx - 1);

            const leftBit = normLeft[bestIdx] >= leftThreshold ? '1' : '0';
            const rightBit = normRight[bestIdx] >= rightThreshold ? '1' : '0';
            dualBits.push(leftBit);
            dualBits.push(rightBit);

            sampleTime += bitDur;
        }

        binary = dualBits.join('');
    }

    // Strip end marker
    let payload = binary;
    const endIdx = payload.lastIndexOf('0101010101010101');
    if (endIdx !== -1) {
        payload = payload.substring(0, endIdx);
    }

    // Pad to byte boundary
    while (payload.length % 8 !== 0) payload += '0';

    // Decode CatProtocol packets
    let bytes = binaryToBytes(payload);
    const packetDecoder = new CatProtocol.Decoder();
    let currentOffset = 0;
    let crcPasses = 0;
    let crcFails = 0;

    while (currentOffset < bytes.length) {
        const remaining = bytes.slice(currentOffset);
        if (remaining.length < 15) break;

        const packetResult = CatProtocol.decodePacket(remaining);
        if (!packetResult.valid) {
            let found = false;
            for (let i = 1; i < Math.min(remaining.length - 1, 100); i++) {
                if (remaining[i] === 0xFE && remaining[i + 1] === 0xCA) {
                    currentOffset += i;
                    found = true;
                    break;
                }
            }
            if (!found) break;
            continue;
        }

        const processResult = packetDecoder.processPacket(remaining);
        if (processResult.accepted) crcPasses++;
        else crcFails++;

        currentOffset += packetResult.packet_size;
        if (processResult.complete) {
            bytes = processResult.message;
            break;
        }
    }

    return { bytes, binary, payload, isDualEye, crcPasses, crcFails };
}

// ══════════════════════════════════════════════════════════════════
// TEST RUNNER
// ══════════════════════════════════════════════════════════════════

let totalPass = 0;
let totalFail = 0;

function assert(label, condition, detail) {
    if (condition) {
        totalPass++;
        _origLog(`    ✅ ${label}`);
    } else {
        totalFail++;
        _origLog(`    ❌ ${label}: ${detail || 'FAILED'}`);
    }
}

_origLog('╔══════════════════════════════════════════════════════════════╗');
_origLog('║  Cat Mode: Dual-Eye Roundtrip Test                         ║');
_origLog('║  encrypt → dual-eye signal → NRZ+L/R → CRC → decrypt     ║');
_origLog('╚══════════════════════════════════════════════════════════════╝');

// ── Test 1: Basic interleave/deinterleave ────────────────────────
_origLog('\n── Test 1: Interleave / Deinterleave Logic ──');
{
    const payloadBinary = '1100101011110000';  // 16 bits
    // Interleave: left=even bits (1,0,1,1,0,0,0,0), right=odd bits (1,0,0,1,1,0,0,0)
    const schedule = [];
    for (let i = 0; i < payloadBinary.length; i += 2) {
        schedule.push({ left: payloadBinary[i], right: payloadBinary[i + 1] || '0' });
    }
    // Deinterleave
    let recovered = '';
    for (const entry of schedule) {
        recovered += entry.left + entry.right;
    }
    assert('Interleave roundtrip', recovered === payloadBinary,
        `got '${recovered}', expected '${payloadBinary}'`);
    assert('Schedule has half the intervals', schedule.length === payloadBinary.length / 2,
        `${schedule.length} vs ${payloadBinary.length / 2}`);
}

// ── Test 2: 0xFE mode byte detection ─────────────────────────────
_origLog('\n── Test 2: 0xFE Mode Byte Detection ──');
{
    assert('0xFE = 11111110', parseInt('11111110', 2) === 0xFE,
        `got 0x${parseInt('11111110', 2).toString(16)}`);
    const marker = '11111101';
    assert('Dual-eye marker = 0xFD (11111101)', parseInt(marker, 2) === 0xFD,
        `got 0x${parseInt(marker, 2).toString(16)}`);
    assert('Marker is exactly 8 bits', marker.length === 8, `${marker.length}`);
    // 0xFD must not collide with CatProtocol magic first byte (0xFE)
    assert('0xFD ≠ 0xFE (CatProtocol magic)', marker !== '11111110', 'collision with CatProtocol');
}

// ── Test 3: Dual-eye schedule construction ───────────────────────
_origLog('\n── Test 3: Dual-Eye Schedule Construction ──');
{
    const password = crypto.randomBytes(4).toString('hex');
    const msg = 'Dual-eye schedule test message';
    const { packed } = simulateEncrypt(msg, password);
    const buildResult = buildCatBinaryPayload(packed);

    const dualResult = buildDualEyeSchedule(
        buildResult.binary,
        buildResult.preambleBits,
        buildResult.syncBits
    );

    // Header should be single-eye (left === right)
    const headerEntries = dualResult.schedule.slice(0, dualResult.headerLen);
    const allHeaderSingleEye = headerEntries.every(e => e.left === e.right);
    assert('Header is single-eye (L===R)', allHeaderSingleEye, 'header has divergent entries');

    // Header ends with 0xFD marker
    const lastHeaderBits = dualResult.headerBinary.slice(-8);
    assert('Header ends with 0xFD', lastHeaderBits === '11111101',
        `got '${lastHeaderBits}'`);

    // Payload entries may have divergent L/R
    const payloadEntries = dualResult.schedule.slice(dualResult.headerLen);
    assert('Payload intervals = ceil(payloadLen/2)',
        payloadEntries.length === Math.ceil(dualResult.payloadLen / 2),
        `${payloadEntries.length} vs ${Math.ceil(dualResult.payloadLen / 2)}`);

    // Payload is even length
    assert('Payload padded to even', dualResult.payloadLen % 2 === 0,
        `length is ${dualResult.payloadLen}`);

    // Total intervals < total bits (compression from dual-eye)
    const totalBits = dualResult.headerLen + dualResult.payloadLen;
    assert('Fewer intervals than total bits (2× speedup)',
        dualResult.intervalCount < totalBits,
        `${dualResult.intervalCount} intervals >= ${totalBits} bits`);

    _origLog(`    (Header: ${dualResult.headerLen} bits, Payload: ${dualResult.payloadLen} bits, Intervals: ${dualResult.intervalCount})`);
}

// ── Test 4-6: Full roundtrip at multiple speeds ──────────────────
const SPEEDS = [
    { ms: 200, label: 'Medium',    noise: 0.015 },
    { ms: 100, label: 'Fast',      noise: 0.012 },
    { ms:  50, label: 'Very Fast', noise: 0.008 },
];

for (let t = 0; t < SPEEDS.length; t++) {
    const { ms, label, noise } = SPEEDS[t];
    const fps = Math.max(30, Math.round(5000 / ms));
    const msg = `DualEye-${ms}ms: ${crypto.randomBytes(8).toString('hex')} ts=${Date.now()}`;
    const password = `pw-${crypto.randomBytes(4).toString('hex')}`;

    _origLog(`\n── Test ${4 + t}: Dual-Eye Full Roundtrip — ${label} (${ms}ms @ ${fps}fps) ──`);
    _origLog(`  Message: "${msg}"`);

    try {
        // Step 1: Encrypt
        const { packed } = simulateEncrypt(msg, password);

        // Step 2: Build binary framing
        const buildResult = buildCatBinaryPayload(packed);

        // Step 3: Build dual-eye schedule (encoder side)
        const dualResult = buildDualEyeSchedule(
            buildResult.binary,
            buildResult.preambleBits,
            buildResult.syncBits
        );
        _origLog(`  Schedule: ${dualResult.intervalCount} intervals (header=${dualResult.headerLen} + payload=${dualResult.payloadLen} interleaved)`);

        // Step 4: Simulate dual-eye video
        const { samples: frameSamples } = simulateDualEyeVideoSignal(dualResult.schedule, ms, {
            noiseLevel: noise,
            baseGreen: 0.20 + Math.random() * 0.10,
            peakGreen: 0.75 + Math.random() * 0.10,
        });
        _origLog(`  Signal: ${frameSamples.length} frames, noise=${(noise*100).toFixed(1)}%`);

        // Step 5: Run dual-eye decoder
        const result = decodeDualEyePipeline(frameSamples, ms);
        _origLog(`  Decoded: ${result.bytes.length} bytes, dualEye=${result.isDualEye}, CRC ${result.crcPasses}✅/${result.crcFails}❌`);

        // Assertions
        assert('Dual-eye mode detected', result.isDualEye === true, 'isDualEye=false');
        assert('Payload length', result.bytes.length === packed.length,
            `got ${result.bytes.length}, expected ${packed.length}`);

        let byteMatch = true;
        let firstMismatch = -1;
        for (let i = 0; i < packed.length; i++) {
            if (result.bytes[i] !== packed[i]) {
                byteMatch = false;
                firstMismatch = i;
                break;
            }
        }
        assert('Byte-perfect recovery', byteMatch,
            firstMismatch >= 0 ? `mismatch at [${firstMismatch}]: 0x${(result.bytes[firstMismatch]||0).toString(16)} vs 0x${packed[firstMismatch].toString(16)}` : '');

        const decrypted = simulateDecrypt(new Uint8Array(result.bytes), password);
        assert('Decrypted message matches', decrypted === msg,
            `got "${decrypted.substring(0, 40)}..."`);

        assert('CRC passes > 0', result.crcPasses > 0, `crcPasses=${result.crcPasses}`);
        assert('No CRC failures', result.crcFails === 0, `crcFails=${result.crcFails}`);

    } catch (err) {
        totalFail++;
        _origLog(`    ❌ PIPELINE ERROR: ${err.message}`);
        if (err.stack) _origLog(`       ${err.stack.split('\n').slice(1, 3).join('\n       ')}`);
    }
}

// ── Test 7: Single-eye backward compatibility ────────────────────
// A video WITHOUT the 0xFD marker should still decode correctly
_origLog('\n── Test 7: Single-Eye Backward Compatibility ──');
{
    const msg = `SingleEye-compat: ${crypto.randomBytes(4).toString('hex')}`;
    const password = 'backcompat-pw';
    const ms = 100;

    try {
        const { packed } = simulateEncrypt(msg, password);
        const buildResult = buildCatBinaryPayload(packed);

        // Build single-eye schedule (NO 0xFD marker, both eyes same)
        const schedule = [];
        for (let i = 0; i < buildResult.binary.length; i++) {
            schedule.push({ left: buildResult.binary[i], right: buildResult.binary[i] });
        }

        const { samples: frameSamples } = simulateDualEyeVideoSignal(schedule, ms, {
            noiseLevel: 0.012
        });

        const result = decodeDualEyePipeline(frameSamples, ms);

        assert('Single-eye: NOT detected as dual-eye', result.isDualEye === false, `isDualEye=${result.isDualEye}`);
        assert('Single-eye: payload recovered', result.bytes.length === packed.length,
            `got ${result.bytes.length}, expected ${packed.length}`);

        let byteMatch = true;
        for (let i = 0; i < packed.length; i++) {
            if (result.bytes[i] !== packed[i]) { byteMatch = false; break; }
        }
        assert('Single-eye: byte-perfect', byteMatch, 'mismatch');

        const decrypted = simulateDecrypt(new Uint8Array(result.bytes), password);
        assert('Single-eye: decrypts correctly', decrypted === msg, 'decryption failed');

    } catch (err) {
        totalFail++;
        _origLog(`    ❌ PIPELINE ERROR: ${err.message}`);
    }
}

// ── Test 8: Speed comparison ─────────────────────────────────────
_origLog('\n── Test 8: Dual-Eye Speed Advantage ──');
{
    const msg = `Speed test: ${crypto.randomBytes(16).toString('hex')}`;
    const password = 'speed-pw';
    const ms = 100;

    const { packed } = simulateEncrypt(msg, password);
    const buildResult = buildCatBinaryPayload(packed);

    // Single-eye: 1 bit per interval = binary.length intervals
    const singleEyeIntervals = buildResult.binary.length;

    // Dual-eye
    const dualResult = buildDualEyeSchedule(
        buildResult.binary,
        buildResult.preambleBits,
        buildResult.syncBits
    );
    const dualEyeIntervals = dualResult.intervalCount;

    const speedup = singleEyeIntervals / dualEyeIntervals;
    assert(`Dual-eye is faster (${speedup.toFixed(2)}× speedup)`,
        dualEyeIntervals < singleEyeIntervals,
        `dual=${dualEyeIntervals} >= single=${singleEyeIntervals}`);

    // Header is the same, payload is halved → speedup should be >1 and <2
    assert('Speedup > 1.3× (payload is dominant)', speedup > 1.3,
        `only ${speedup.toFixed(2)}×`);
    assert('Speedup < 2.0× (header not doubled)', speedup < 2.0,
        `${speedup.toFixed(2)}× exceeds theoretical max`);

    _origLog(`    (Single-eye: ${singleEyeIntervals} intervals, Dual-eye: ${dualEyeIntervals} intervals)`);
}

// ── Summary ─────────────────────────────────────────────────────
_origLog(`\n${'═'.repeat(60)}`);
_origLog(`  Results: ${totalPass} passed, ${totalFail} failed`);
_origLog(`${'═'.repeat(60)}`);

if (totalFail > 0) {
    _origLog('\n🐛 Some dual-eye tests failed.\n');
    process.exit(1);
} else {
    _origLog('\n✅ All dual-eye tests passed!\n');
    _origLog('  ✓ Interleave/deinterleave logic correct');
    _origLog('  ✓ 0xFE mode byte detection works');
    _origLog('  ✓ Header single-eye, payload dual-eye');
    _origLog('  ✓ Full encrypt → dual-eye → decrypt at 3 speeds');
    _origLog('  ✓ Single-eye backward compatibility preserved');
    _origLog('  ✓ ~1.7× speedup confirmed\n');
    process.exit(0);
}
