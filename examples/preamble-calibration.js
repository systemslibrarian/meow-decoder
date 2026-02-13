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
 * @author Meow Decoder Production Team
 * @version 1.0.0
 */

/**
 * Detect preamble region in frame sequence
 * 
 * Searches for sustained alternating pattern (1010...) at the start of transmission.
 * The preamble is 32 bits = 3.2 seconds at 100ms/bit, providing robust calibration data.
 * 
 * @param {object[]} frames - Array of frames with {time, state, greenScore}
 * @param {number} minTransitionRate - Minimum transition rate (default 0.7 = 70%)
 * @param {number} minDuration - Minimum preamble duration in seconds (default 2.0s)
 * @returns {object|null} {start: frameIndex, end: frameIndex, transitionRate, duration} or null
 */
function detectPreamble(frames, minTransitionRate = 0.7, minDuration = 2.0) {
    if (frames.length < 20) {
        return null;
    }
    
    // Search for alternating pattern in early frames (first 30% of video)
    const searchRange = Math.min(frames.length, Math.floor(frames.length * 0.3));
    
    for (let start = 0; start < searchRange - 20; start++) {
        // Try different window sizes
        for (let windowSize = 20; windowSize <= Math.min(100, searchRange - start); windowSize += 10) {
            const windowFrames = frames.slice(start, start + windowSize);
            const duration = windowFrames[windowFrames.length - 1].time - windowFrames[0].time;
            
            if (duration < minDuration) {
                continue; // Too short
            }
            
            // Count transitions
            let transitions = 0;
            for (let i = 1; i < windowFrames.length; i++) {
                if (windowFrames[i].state !== windowFrames[i - 1].state && 
                    windowFrames[i].state !== 'unknown' && 
                    windowFrames[i - 1].state !== 'unknown') {
                    transitions++;
                }
            }
            
            const transitionRate = transitions / (windowFrames.length - 1);
            
            if (transitionRate >= minTransitionRate) {
                console.log(`📡 [Preamble] Detected at frames ${start}-${start + windowSize} (${(transitionRate * 100).toFixed(1)}% transitions, ${duration.toFixed(2)}s)`);
                return { 
                    start, 
                    end: start + windowSize,
                    transitionRate,
                    duration
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
        median,
        mean,
        standardDeviation
    };
}
