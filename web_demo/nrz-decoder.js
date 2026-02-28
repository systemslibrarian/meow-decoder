/**
 * @fileoverview NRZ Timing Decoder (Task 1.2 - Part 2)
 *
 * Implements Non-Return-to-Zero (NRZ) decoding for cat mode video:
 * - Sync word detection (0xAA55 = 1010101010101010) for bit boundary alignment
 * - 8-bit sync fallback (0xAA) for short videos (Task 5.2.1)
 * - Bit sampling at fixed time intervals (midpoint of each bit window)
 * - Low-confidence bit voting (sample 3-5 times, majority wins)
 * - Fail-fast diagnostics when sync not found
 *
 * CRITICAL: Cat mode uses FIXED time windows (not duration coding).
 * Each bit is held for exactly `speed` ms using requestAnimationFrame timestamps.
 * We decode by sampling at t₀ + (n + 0.5) × bitPeriod, NOT by clustering durations.
 *
 * @author Meow Decoder Production Team
 * @version 1.1.0
 */

// Set to true for verbose sync/decode logging
// Using var (not const) to allow safe redeclaration across multiple script files
var NRZ_DEBUG = (typeof window !== 'undefined' && window.MEOW_DEBUG) || false;

/**
 * Find sync word in bit stream, with 8-bit fallback for short videos (Task 5.2.1)
 *
 * Tries 16-bit sync (0xAA55) first, then falls back to 8-bit sync (0xAA)
 * if the video is too short for a full sync word to be present.
 *
 * @param {object[]} frames - Array of frames with {time, state, confidence, greenScore}
 * @param {number} bitPeriod - Bit duration in seconds
 * @param {number} startSearchTime - Time to start searching (after preamble)
 * @param {number} maxSearchDuration - Maximum time to search in seconds (default 5.0s)
 * @param {object} options - {shortVideoMode: bool, allowShortSync: bool}
 * @returns {object|null} {t0, confidence, syncBits, samples} or null
 */
function findSyncWord(frames, bitPeriod, startSearchTime = 0, maxSearchDuration = 5.0, options = {}) {
    const { shortVideoMode = false, allowShortSync = true } = options;
    const syncPattern16 = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0]; // 0xAA55
    const syncPattern8 = [1, 0, 1, 0, 1, 0, 1, 0]; // 0xAA (8-bit)
    const searchEndTime = startSearchTime + maxSearchDuration;

    // Try 16-bit sync first (unless in explicit short video mode)
    if (!shortVideoMode) {
        const result16 = searchForPattern(frames, syncPattern16, bitPeriod, startSearchTime, searchEndTime);
        if (result16 && result16.confidence >= 0.75) {
            NRZ_DEBUG && console.log(`🔍 [Sync] Found 16-bit sync at t=${(result16.t0 * 1000).toFixed(1)}ms (${(result16.confidence * 100).toFixed(1)}% match)`);
            return { ...result16, syncBits: 16 };
        }
    }

    // Fallback to 8-bit sync (Task 5.2.1)
    if (allowShortSync || shortVideoMode) {
        const result8 = searchForPattern(frames, syncPattern8, bitPeriod, startSearchTime, searchEndTime);
        if (result8 && result8.confidence >= 0.75) {
            NRZ_DEBUG && console.log(`🔍 [Sync] Found 8-bit sync (fallback) at t=${(result8.t0 * 1000).toFixed(1)}ms (${(result8.confidence * 100).toFixed(1)}% match)`);
            return { ...result8, syncBits: 8 };
        }
    }

    return null;
}

/**
 * Search for a specific bit pattern in frames
 * @private
 */
function searchForPattern(frames, pattern, bitPeriod, startTime, endTime) {
    const phaseStep = bitPeriod / 10;
    let bestMatch = null;
    let bestScore = 0;

    for (let t0 = startTime; t0 < endTime; t0 += phaseStep) {
        const samples = sampleBits(frames, t0, bitPeriod, pattern.length);

        let matches = 0;
        for (let i = 0; i < pattern.length; i++) {
            if (samples[i] === pattern[i]) {
                matches++;
            }
        }

        const score = matches / pattern.length;

        if (score > bestScore) {
            bestScore = score;
            bestMatch = { t0, confidence: score, samples };
        }

        if (score === 1.0) break;
    }

    return bestMatch;
}

/**
 * Find sync word with fail-fast diagnostics and 8-bit fallback (Task 5.2.1)
 *
 * Wraps findSyncWord with helpful error messages when sync not found.
 * Provides actionable suggestions for the user.
 *
 * @param {object[]} frames - Array of frames
 * @param {number} bitPeriod - Bit duration in seconds
 * @param {number} threshold - Current threshold value
 * @param {number} startSearchTime - Time to start searching
 * @param {object} options - {shortVideoMode: bool}
 * @returns {object} {found, t0, confidence, syncBits, error, diagnostics}
 */
function findSyncWordWithFallback(frames, bitPeriod, threshold, startSearchTime = 0, options = {}) {
    const { shortVideoMode = false } = options;
    NRZ_DEBUG && console.log(`🔍 [Sync] Searching for sync word starting at t=${(startSearchTime * 1000).toFixed(1)}ms${shortVideoMode ? ' (short video mode)' : ''}...`);

    const result = findSyncWord(frames, bitPeriod, startSearchTime, 5.0, { shortVideoMode, allowShortSync: true });

    if (result) {
        NRZ_DEBUG && console.log(`✅ [Sync] ${result.syncBits}-bit sync word found at t=${(result.t0 * 1000).toFixed(1)}ms`);
        return {
            found: true,
            t0: result.t0,
            confidence: result.confidence,
            syncBits: result.syncBits,
            error: null,
            diagnostics: null
        };
    }

    // FAIL FAST with diagnostics
    const diagnostics = {
        likely_causes: [
            'Wrong ROI (not targeting cat eyes)',
            'Lighting too uniform (no clear on/off distinction)',
            'Timing drift (video frame drops or variable frame rate)',
            'Bit rate mismatch (UI speed ≠ actual transmission speed)',
            'Threshold too aggressive (filtering out real data)'
        ],
        suggestions: [
            'Try "Auto" sensitivity to auto-detect threshold',
            'Verify bit rate matches transmission (check original)',
            'Check video quality - re-record at higher resolution if blurry',
            'Ensure cat eyes are visible and in focus',
            'Check live counters - confident frames should be >70%'
        ],
        current_state: {
            threshold: threshold.toFixed(3),
            bitPeriod: (bitPeriod * 1000).toFixed(1) + 'ms',
            searchedFrames: frames.filter(f => f.time >= startSearchTime && f.time < startSearchTime + 5.0).length
        }
    };

    NRZ_DEBUG && console.log('❌ [Sync] Sync word not found - decode cannot proceed');
    NRZ_DEBUG && console.log('📋 [Sync] Diagnostics:', JSON.stringify(diagnostics, null, 2));

    return {
        found: false,
        t0: null,
        confidence: 0,
        error: 'no_sync_lock',
        diagnostics
    };
}

/**
 * Sample bits at fixed time intervals (NRZ decoding)
 *
 * Samples the video frames at regular intervals to extract bits.
 * Uses two-pointer advance for O(numBits) performance (not O(numBits × numFrames)).
 *
 * @param {object[]} frames - Array of frames sorted by time
 * @param {number} t0 - Start time in seconds
 * @param {number} bitPeriod - Bit duration in seconds
 * @param {number} numBits - Number of bits to sample
 * @param {number} confidenceThreshold - Minimum confidence (default 0.15)
 * @returns {Array<number|string>} Array of bits (0, 1, or '?' for uncertain)
 */
function sampleBits(frames, t0, bitPeriod, numBits, confidenceThreshold = 0.15) {
    const bits = [];
    let frameIdx = 0; // Two-pointer: advance through sorted frames

    for (let i = 0; i < numBits; i++) {
        // Sample at midpoint of bit window
        const sampleTime = t0 + (i + 0.5) * bitPeriod;

        // Advance frameIdx until frames[frameIdx].time >= sampleTime
        while (frameIdx < frames.length - 1 && frames[frameIdx + 1].time < sampleTime) {
            frameIdx++;
        }

        // Choose nearest frame: current or next
        let nearestFrame = frames[frameIdx];
        if (frameIdx < frames.length - 1) {
            const distCurrent = Math.abs(frames[frameIdx].time - sampleTime);
            const distNext = Math.abs(frames[frameIdx + 1].time - sampleTime);
            if (distNext < distCurrent) {
                nearestFrame = frames[frameIdx + 1];
                frameIdx++; // Advance for next iteration
            }
        }

        // Check if frame is confident
        if (nearestFrame.confidence !== undefined && nearestFrame.confidence < confidenceThreshold) {
            bits.push('?'); // Uncertain
        } else if (nearestFrame.state === 'on') {
            bits.push(1);
        } else if (nearestFrame.state === 'off') {
            bits.push(0);
        } else {
            bits.push('?'); // Unknown state
        }
    }

    return bits;
}

/**
 * Binary search for nearest frame (alternative for random access)
 *
 * More efficient than linear scan when accessing frames non-sequentially.
 *
 * @param {object[]} frames - Sorted array of frames
 * @param {number} targetTime - Target time in seconds
 * @returns {object} Nearest frame
 */
function findNearestFrame(frames, targetTime) {
    if (frames.length === 0) return null;
    if (frames.length === 1) return frames[0];

    let left = 0;
    let right = frames.length - 1;

    // Binary search for closest time
    while (left < right - 1) {
        const mid = Math.floor((left + right) / 2);
        if (frames[mid].time < targetTime) {
            left = mid;
        } else {
            right = mid;
        }
    }

    // Compare left and right
    const distLeft = Math.abs(frames[left].time - targetTime);
    const distRight = Math.abs(frames[right].time - targetTime);

    return distLeft < distRight ? frames[left] : frames[right];
}

/**
 * Vote within bit window to resolve uncertain bits
 *
 * When a bit is uncertain ('?'), sample multiple times within the bit window
 * and take the majority vote. Much more robust than single-sample.
 *
 * @param {object[]} frames - Array of frames
 * @param {number} t0 - Start time of payload in seconds
 * @param {number} bitPeriod - Bit duration in seconds
 * @param {number} bitIndex - Index of the bit to vote on
 * @param {number} numSamples - Number of samples to take (default 5)
 * @param {number} confidenceThreshold - Minimum confidence (default 0.15)
 * @returns {number|string} 0, 1, or '?' if no consensus
 */
function voteWithinBitWindow(frames, t0, bitPeriod, bitIndex, numSamples = 5, confidenceThreshold = 0.15) {
    const votes = [];
    const bitStart = t0 + bitIndex * bitPeriod;
    const bitEnd = bitStart + bitPeriod;

    // Sample evenly across bit window
    for (let i = 0; i < numSamples; i++) {
        const sampleTime = bitStart + (i / (numSamples - 1)) * bitPeriod;
        const frame = findNearestFrame(frames, sampleTime);

        if (frame && frame.confidence >= confidenceThreshold) {
            if (frame.state === 'on') {
                votes.push(1);
            } else if (frame.state === 'off') {
                votes.push(0);
            }
        }
    }

    // Majority vote
    if (votes.length === 0) return '?';

    const ones = votes.filter(v => v === 1).length;
    const zeros = votes.filter(v => v === 0).length;

    // Require clear majority (>60%)
    if (ones > votes.length * 0.6) return 1;
    if (zeros > votes.length * 0.6) return 0;

    return '?'; // No clear consensus
}

/**
 * Resolve unknown bits using voting strategy
 *
 * Post-processes bit array to resolve '?' bits by voting within their windows.
 *
 * @param {Array} bits - Array of bits (may contain '?')
 * @param {object[]} frames - Array of frames
 * @param {number} t0 - Start time in seconds
 * @param {number} bitPeriod - Bit duration in seconds
 * @param {string} policy - 'vote' or 'repeat' (default 'vote')
 * @returns {Array<number>} Array of resolved bits (0 or 1 only)
 */
function resolveUnknownBits(bits, frames, t0, bitPeriod, policy = 'vote') {
    if (policy === 'repeat') {
        // Option A: Repeat last known bit (simple but less accurate)
        let lastKnown = 0;
        return bits.map(b => {
            if (b === '?') return lastKnown;
            lastKnown = b;
            return b;
        });
    } else {
        // Option B: Vote within bit window (better - recommended)
        return bits.map((b, i) => {
            if (b === '?') {
                const voted = voteWithinBitWindow(frames, t0, bitPeriod, i, 5, 0.15);
                return voted === '?' ? 0 : voted; // Default to 0 if still uncertain
            }
            return b;
        });
    }
}

/**
 * Decode payload from frames using NRZ timing with adaptive sync (Task 5.2.1)
 *
 * Enhanced NRZ decoding that:
 * 1. Checks video duration and warns if too short
 * 2. Finds sync word (16-bit or 8-bit fallback)
 * 3. Samples bits at fixed intervals
 * 4. Resolves uncertain bits
 * 5. Converts to binary string
 *
 * @param {object[]} frames - Array of frames
 * @param {number} bitPeriod - Bit duration in seconds
 * @param {number} threshold - Current threshold
 * @param {number} startSearchTime - Time to start sync search
 * @param {number} maxBits - Maximum bits to decode (safety limit)
 * @param {object} options - {shortVideoMode: bool}
 * @returns {object} {success, binary, t0, stats, shortVideoMode, syncBits}
 */
function decodeNRZ(frames, bitPeriod, threshold, startSearchTime = 0, maxBits = 100000, options = {}) {
    const { shortVideoMode = false } = options;

    // Find sync word (with 8-bit fallback for short videos)
    const syncResult = findSyncWordWithFallback(frames, bitPeriod, threshold, startSearchTime, { shortVideoMode });

    if (!syncResult.found) {
        return {
            success: false,
            binary: '',
            t0: null,
            error: syncResult.error,
            diagnostics: syncResult.diagnostics
        };
    }

    const syncBits = syncResult.syncBits || 16;
    let t0 = syncResult.t0 + (syncBits * bitPeriod); // Skip sync word itself

    // ================================================================
    // ALTERNATION STRIPPING (defense-in-depth)
    //
    // The preamble and sync word use the SAME alternating pattern
    // (1010...). When the sync search matches within the preamble,
    // t0 lands in the middle of the alternating region instead of at
    // data start. Detect and skip any remaining alternating bits.
    //
    // When we find two consecutive same-value bits at position (i-1,i),
    // the alternation region ends at i-2. Position i-1 is the first
    // data bit (which happens to match the next alternation value),
    // confirmed non-alternating by position i having the same value.
    // ================================================================
    const probeCount = Math.min(40, Math.floor((frames[frames.length - 1].time - t0) / bitPeriod));
    if (probeCount > 4) {
        const probeBits = sampleBits(frames, t0, bitPeriod, probeCount, 0.15);
        const resolvedProbe = resolveUnknownBits(probeBits, frames, t0, bitPeriod, 'vote');
        // Find where alternation stops: two consecutive same-value bits
        let altEnd = 0;
        for (let i = 1; i < resolvedProbe.length; i++) {
            if (resolvedProbe[i] === resolvedProbe[i - 1]) {
                // First same-value pair at (i-1, i). The alternation
                // region is bits 0 to i-2. Bit i-1 is likely the first
                // data bit (it coincidentally continues the alternation
                // from i-2, but i confirms it's not alternation).
                altEnd = Math.max(0, i - 1);
                break;
            }
        }
        if (altEnd > 0) {
            NRZ_DEBUG && console.log(`📡 [NRZ] Stripping ${altEnd} leading alternating bits after sync word`);
            t0 += altEnd * bitPeriod;
        }
    }

    // Calculate maximum bits to decode based on available video duration
    const lastFrameTime = frames[frames.length - 1].time;
    const availableDuration = lastFrameTime - t0;
    const maxAvailableBits = Math.floor(availableDuration / bitPeriod);
    const numBits = Math.min(maxBits, maxAvailableBits);

    NRZ_DEBUG && console.log(`📡 [NRZ] Decoding ${numBits} bits starting at t=${(t0 * 1000).toFixed(1)}ms (${syncBits}-bit sync)`);

    // Sample bits
    const bits = sampleBits(frames, t0, bitPeriod, numBits, 0.15);

    // Count uncertain bits
    const uncertainCount = bits.filter(b => b === '?').length;
    const uncertainPercent = (uncertainCount / numBits * 100).toFixed(1);

    NRZ_DEBUG && console.log(`📡 [NRZ] Sampled ${numBits} bits, ${uncertainCount} uncertain (${uncertainPercent}%)`);

    // Resolve uncertain bits using voting
    const resolvedBits = resolveUnknownBits(bits, frames, t0, bitPeriod, 'vote');

    // Convert to binary string
    const binary = resolvedBits.join('');

    return {
        success: true,
        binary,
        t0,
        syncConfidence: syncResult.confidence,
        syncBits,
        shortVideoMode: shortVideoMode || syncBits === 8,
        stats: {
            totalBits: numBits,
            uncertainBits: uncertainCount,
            uncertainPercent: parseFloat(uncertainPercent),
            bitPeriod: bitPeriod * 1000, // Convert to ms for display
            syncBits
        }
    };
}

// Export for browser use
if (typeof window !== 'undefined') {
    window.NRZDecoder = {
        findSyncWord,
        findSyncWordWithFallback,
        searchForPattern,
        sampleBits,
        findNearestFrame,
        voteWithinBitWindow,
        resolveUnknownBits,
        decodeNRZ
    };
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        findSyncWord,
        findSyncWordWithFallback,
        searchForPattern,
        sampleBits,
        findNearestFrame,
        voteWithinBitWindow,
        resolveUnknownBits,
        decodeNRZ
    };
}
