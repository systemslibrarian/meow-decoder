/**
 * @fileoverview Preamble Detection & Auto-Calibration (Task 1.2 - Part 1)
 * 
 * Detects the alternating 1010... preamble pattern and uses it to:
 * - Learn on/off green score distributions
 * - Calculate optimal threshold (midpoint between peaks)
 * - Estimate bit rate from zero-crossings
 * 
 * This auto-calibration eliminates the need for manual threshold tuning
 * and makes cat mode robust to different lighting conditions.
 * 
 * Task 5.2.1: Added adaptive early preamble termination and video duration
 * pre-check for short video (<5s) robustness.
 * 
 * @author Meow Decoder Production Team
 * @version 1.1.0
 */

/**
 * Pre-check video duration before attempting decode (Task 5.2.1)
 * 
 * Short videos (<5s) have limited payload capacity because the preamble
 * and sync word consume ~4.8s of overhead at 100ms/bit. This function
 * warns the user before wasting time on a doomed decode attempt.
 * 
 * @param {number} durationSec - Video duration in seconds
 * @param {number} bitPeriodMs - Bit period in milliseconds (default 100)
 * @returns {object} {ok: boolean, message: string|null, maxPayloadBits: number}
 */
function checkVideoDuration(durationSec, bitPeriodMs = 100) {
    const bitPeriodSec = bitPeriodMs / 1000;
    // Minimum overhead: lead-in(8) + preamble(16 adaptive) + sync(8 short) = 32 bits
    const minOverheadBits = 32;
    const minOverheadSec = minOverheadBits * bitPeriodSec;
    
    // Full overhead: lead-in(8) + preamble(32) + sync(16) = 56 bits 
    const fullOverheadBits = 56;
    const fullOverheadSec = fullOverheadBits * bitPeriodSec;
    
    const maxPayloadBits = Math.floor((durationSec - minOverheadSec) / bitPeriodSec);
    
    if (durationSec < minOverheadSec + bitPeriodSec) {
        return {
            ok: false,
            maxPayloadBits: 0,
            message: `⚠️ Video is ${durationSec.toFixed(1)}s but needs at least ${(minOverheadSec + bitPeriodSec).toFixed(1)}s. Record for longer!`,
            suggestion: 'Add 2-3 seconds before and after the message',
            shortVideoMode: false
        };
    }
    
    if (durationSec < fullOverheadSec + bitPeriodSec * 8) {
        // Short video: will use adaptive preamble + 8-bit sync
        return {
            ok: true,
            maxPayloadBits,
            message: `📹 Short video (${durationSec.toFixed(1)}s) - using fast-start mode (reduced preamble + 8-bit sync)`,
            suggestion: null,
            shortVideoMode: true
        };
    }
    
    return {
        ok: true,
        maxPayloadBits: Math.floor((durationSec - fullOverheadSec) / bitPeriodSec),
        message: null,
        suggestion: null,
        shortVideoMode: false
    };
}

/**
 * Detect preamble region in frame sequence with adaptive early termination
 * 
 * Searches for sustained alternating pattern (1010...) at the start of transmission.
 * Supports early termination: if 16+ consecutive alternations are stable, stops early
 * instead of requiring the full 32-bit preamble. This reduces overhead from 3.2s to
 * as little as 1.6s, critical for short (<5s) videos.
 * 
 * @param {object[]} frames - Array of frames with {time, state, greenScore}
 * @param {number} minTransitionRate - Minimum transition rate (default 0.7 = 70%)
 * @param {number} minDuration - Minimum preamble duration in seconds (default 0.8s for adaptive)
 * @param {object} options - {earlyTermination: bool, minAlternations: number}
 * @returns {object|null} {start, end, transitionRate, duration, earlyTerminated, confidence}
 */
function detectPreamble(frames, minTransitionRate = 0.7, minDuration = 0.8, options = {}) {
    const { earlyTermination = true, minAlternations = 16 } = options;
    
    if (frames.length < 10) {
        return null;
    }
    
    // Search for alternating pattern in early frames (first 40% of video for short videos)
    const searchRange = Math.min(frames.length, Math.floor(frames.length * 0.4));
    
    for (let start = 0; start < searchRange - 10; start++) {
        // Count consecutive alternations from this starting point
        let alternations = 0;
        let endIdx = start;
        let consecutiveAlts = 0;
        let maxConsecutiveAlts = 0;
        
        for (let i = start + 1; i < Math.min(start + 100, searchRange); i++) {
            if (frames[i].state !== frames[i - 1].state &&
                frames[i].state !== 'unknown' &&
                frames[i - 1].state !== 'unknown') {
                alternations++;
                consecutiveAlts++;
                endIdx = i;
            } else {
                maxConsecutiveAlts = Math.max(maxConsecutiveAlts, consecutiveAlts);
                consecutiveAlts = 0;
            }
            
            // Early termination: if we have enough stable alternations, stop early
            if (earlyTermination && consecutiveAlts >= minAlternations) {
                const duration = frames[endIdx].time - frames[start].time;
                if (duration >= minDuration) {
                    const transitionRate = alternations / (endIdx - start);
                    console.log(`📡 [Preamble] Early termination at frames ${start}-${endIdx} (${consecutiveAlts} alternations, ${(transitionRate * 100).toFixed(1)}% rate, ${duration.toFixed(2)}s)`);
                    return {
                        start,
                        end: endIdx + 1,
                        transitionRate,
                        duration,
                        earlyTerminated: true,
                        confidence: consecutiveAlts >= 24 ? 'high' : 'medium'
                    };
                }
            }
        }
        
        // Full window check (original behavior)
        maxConsecutiveAlts = Math.max(maxConsecutiveAlts, consecutiveAlts);
        if (alternations > 0) {
            const duration = frames[endIdx].time - frames[start].time;
            const transitionRate = alternations / (endIdx - start);
            
            if (transitionRate >= minTransitionRate && duration >= minDuration) {
                console.log(`📡 [Preamble] Detected at frames ${start}-${endIdx} (${(transitionRate * 100).toFixed(1)}% transitions, ${duration.toFixed(2)}s)`);
                return {
                    start,
                    end: endIdx + 1,
                    transitionRate,
                    duration,
                    earlyTerminated: false,
                    confidence: maxConsecutiveAlts >= 24 ? 'high' : (maxConsecutiveAlts >= 16 ? 'medium' : 'low')
                };
            }
        }
    }
    
    return null;
}

/**
 * Learn distributions from preamble with robust statistics
 * 
 * Analyzes the alternating preamble to extract:
 * - On/off means and standard deviations
 * - Optimal threshold (midpoint)
 * - Estimated bit rate from transition intervals
 * 
 * @param {object[]} frames - Array of all frames
 * @param {object} preambleRegion - {start, end} frame indices
 * @returns {object} {onMean, offMean, threshold, bitRate, onStd, offStd, sampleCount}
 */
function learnFromPreamble(frames, preambleRegion) {
    const preambleFrames = frames.slice(preambleRegion.start, preambleRegion.end);
    
    // Separate into on/off based on current state classification
    const onScores = [];
    const offScores = [];
    
    for (const frame of preambleFrames) {
        if (frame.state === 'on') {
            onScores.push(frame.greenScore);
        } else if (frame.state === 'off') {
            offScores.push(frame.greenScore);
        }
    }
    
    if (onScores.length < 5 || offScores.length < 5) {
        console.warn('⚠️ [Preamble] Insufficient samples for learning');
        return null;
    }
    
    // Calculate robust statistics (use median instead of mean for outlier resistance)
    const onMean = median(onScores);
    const offMean = median(offScores);
    const onStd = standardDeviation(onScores, onMean);
    const offStd = standardDeviation(offScores, offMean);
    const threshold = (onMean + offMean) / 2;
    
    // Estimate bit rate from transition intervals
    const transitions = [];
    for (let i = 1; i < preambleFrames.length; i++) {
        if (preambleFrames[i].state !== preambleFrames[i - 1].state &&
            preambleFrames[i].state !== 'unknown' &&
            preambleFrames[i - 1].state !== 'unknown') {
            transitions.push(preambleFrames[i].time);
        }
    }
    
    const intervals = [];
    for (let i = 1; i < transitions.length; i++) {
        intervals.push(transitions[i] - transitions[i - 1]);
    }
    
    // Bit rate = 2 × median transition interval (alternating pattern)
    const medianInterval = median(intervals);
    const bitRate = medianInterval > 0 ? 2 * medianInterval : null;
    
    console.log(`📊 [Preamble] Learned: on=${onMean.toFixed(3)}±${onStd.toFixed(3)}, off=${offMean.toFixed(3)}±${offStd.toFixed(3)}, threshold=${threshold.toFixed(3)}, bitRate=${bitRate ? (bitRate * 1000).toFixed(1) + 'ms' : 'N/A'}`);
    
    return {
        onMean,
        offMean,
        threshold,
        bitRate,
        onStd,
        offStd,
        range: Math.abs(onMean - offMean),
        sampleCount: onScores.length + offScores.length
    };
}

/**
 * Detect preamble with fallback to UI settings
 * 
 * Tries to detect and learn from preamble. If not found, falls back to:
 * - Using UI-specified bit rate
 * - Percentile-based threshold estimation
 * 
 * @param {object[]} frames - Array of frames
 * @param {number} uiSpeedMs - UI-specified blink speed in milliseconds
 * @param {number[]} allScores - All green scores for percentile calculation
 * @returns {object} {found, preamble, threshold, bitRate, learned}
 */
function detectPreambleWithFallback(frames, uiSpeedMs, allScores) {
    const preamble = detectPreamble(frames);
    
    if (preamble) {
        const learned = learnFromPreamble(frames, preamble);
        
        if (learned && learned.bitRate) {
            console.log('✅ [Preamble] Auto-calibration successful');
            return {
                found: true,
                preamble,
                threshold: learned.threshold,
                bitRate: learned.bitRate,
                learned
            };
        }
    }
    
    // FALLBACK: Use UI speed + percentile threshold
    console.log('⚠️ [Preamble] Not detected - using fallback (UI speed + percentile threshold)');
    
    const sorted = allScores.slice().sort((a, b) => a - b);
    const p5 = sorted[Math.floor(sorted.length * 0.05)];
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    const p50 = sorted[Math.floor(sorted.length * 0.50)];
    
    return {
        found: false,
        preamble: null,
        threshold: p50,  // Median as threshold
        bitRate: uiSpeedMs / 1000,  // Convert to seconds
        learned: {
            onMean: p95,
            offMean: p5,
            threshold: p50,
            bitRate: uiSpeedMs / 1000,
            range: p95 - p5,
            fallback: true
        }
    };
}

/**
 * Calculate median of array
 * @param {number[]} arr - Input array
 * @returns {number} Median value
 */
function median(arr) {
    if (arr.length === 0) return 0;
    const sorted = arr.slice().sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    
    if (sorted.length % 2 === 0) {
        return (sorted[mid - 1] + sorted[mid]) / 2;
    } else {
        return sorted[mid];
    }
}

/**
 * Calculate mean of array
 * @param {number[]} arr - Input array
 * @returns {number} Mean value
 */
function mean(arr) {
    if (arr.length === 0) return 0;
    return arr.reduce((sum, x) => sum + x, 0) / arr.length;
}

/**
 * Calculate standard deviation
 * @param {number[]} arr - Input array
 * @param {number} meanOrMedian - Pre-computed mean/median
 * @returns {number} Standard deviation
 */
function standardDeviation(arr, meanOrMedian) {
    if (arr.length === 0) return 0;
    const squaredDiffs = arr.map(x => Math.pow(x - meanOrMedian, 2));
    const variance = mean(squaredDiffs);
    return Math.sqrt(variance);
}

// Export for browser use
if (typeof window !== 'undefined') {
    window.PreambleCalibration = {
        detectPreamble,
        learnFromPreamble,
        detectPreambleWithFallback,
        checkVideoDuration,
        median,
        mean,
        standardDeviation
    };
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        detectPreamble,
        learnFromPreamble,
        detectPreambleWithFallback,
        checkVideoDuration,
        median,
        mean,
        standardDeviation
    };
}
