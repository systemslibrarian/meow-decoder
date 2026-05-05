/**
 * @fileoverview Cat Mode Quality Metrics & Confidence Gating (Task 1.3)
 * 
 * Provides per-frame confidence scoring to filter out noisy/uncertain detections
 * before they pollute the transition list. Key innovation: confidence is measured
 * as distance from threshold RELATIVE TO on/off separation (not threshold value).
 * 
 * Critical for Phase 1 reliability - must be done BEFORE timing detection to
 * prevent garbage data from entering the clustering pipeline.
 * 
 * @author Meow Decoder Production Team
 * @version 1.0.0
 */

/**
 * Quality metrics tracker for decode session
 * Tracks overall statistics about frame confidence and state stability
 */
class QualityMetrics {
    constructor() {
        this.frames_total = 0;
        this.frames_confident = 0;
        this.frames_uncertain = 0;
        this.transitions_detected = 0;
        this.crc_passes = 0;
        this.crc_fails = 0;
        this.lastState = null;
    }
    
    /**
     * Record a frame's classification result
     * @param {object} result - Classification result from classifyFrame()
     */
    recordFrame(result) {
        this.frames_total++;
        
        if (result.state === 'unknown') {
            this.frames_uncertain++;
        } else {
            this.frames_confident++;
            
            // Track transitions (state changes)
            if (this.lastState !== null && this.lastState !== result.state) {
                this.transitions_detected++;
            }
            this.lastState = result.state;
        }
    }
    
    /**
     * Record CRC validation result
     * @param {boolean} passed - Whether CRC validation passed
     */
    recordCRC(passed) {
        if (passed) {
            this.crc_passes++;
        } else {
            this.crc_fails++;
        }
    }
    
    /**
     * Get overall quality score (0-100)
     * @returns {number} Quality score
     */
    getQualityScore() {
        if (this.frames_total === 0) return 0;
        
        const confidenceRatio = this.frames_confident / this.frames_total;
        const crcTotal = this.crc_passes + this.crc_fails;
        const crcRatio = crcTotal > 0 ? this.crc_passes / crcTotal : 1.0;
        
        // Weight: 70% confidence, 30% CRC pass rate
        return Math.round((confidenceRatio * 0.7 + crcRatio * 0.3) * 100);
    }
    
    /**
     * Get summary statistics
     * @returns {object} Statistics object
     */
    getSummary() {
        return {
            frames_total: this.frames_total,
            frames_confident: this.frames_confident,
            frames_uncertain: this.frames_uncertain,
            confidence_percent: this.frames_total > 0 
                ? ((this.frames_confident / this.frames_total) * 100).toFixed(1)
                : '0.0',
            transitions_detected: this.transitions_detected,
            crc_passes: this.crc_passes,
            crc_fails: this.crc_fails,
            crc_pass_rate: (this.crc_passes + this.crc_fails) > 0
                ? ((this.crc_passes / (this.crc_passes + this.crc_fails)) * 100).toFixed(1)
                : '0.0',
            quality_score: this.getQualityScore()
        };
    }
    
    /**
     * Reset all metrics
     */
    reset() {
        this.frames_total = 0;
        this.frames_confident = 0;
        this.frames_uncertain = 0;
        this.transitions_detected = 0;
        this.crc_passes = 0;
        this.crc_fails = 0;
        this.lastState = null;
    }
}

/**
 * Per-frame quality gate with learned on/off separation
 * 
 * CRITICAL FIX (from ChatGPT review): Confidence is measured as distance
 * from threshold RELATIVE TO the on/off range (not relative to threshold value).
 * This makes it robust to threshold scale and small threshold values.
 * 
 * @param {number} greenScore - Frame's green intensity score
 * @param {number} threshold - Decision threshold
 * @param {number} onMean - Mean score for "on" state (from preamble)
 * @param {number} offMean - Mean score for "off" state (from preamble)
 * @param {number} confidenceMargin - Minimum confidence required (default 0.15 = 15%)
 * @returns {object} {state: 'on'|'off'|'unknown', confidence: number, distance: number}
 */
function classifyFrame(greenScore, threshold, onMean, offMean, confidenceMargin = 0.15) {
    const distance = Math.abs(greenScore - threshold);
    const range = Math.abs(onMean - offMean); // Learned from preamble
    const eps = 0.01; // Prevent division by zero
    // Clamp confidence to [0, 1]. Saturated pixels can put greenScore
    // outside [offMean, onMean], producing values like 3.7 that pollute
    // any downstream code treating this as a probability.
    const confidence = Math.min(distance / (range + eps), 1);
    
    if (confidence < confidenceMargin) {
        return { 
            state: 'unknown', 
            confidence: confidence,
            distance: distance,
            greenScore: greenScore
        };
    }
    
    return { 
        state: greenScore > threshold ? 'on' : 'off',
        confidence: confidence,
        distance: distance,
        greenScore: greenScore
    };
}

/**
 * Per-frame quality gate using percentile-based range (fallback)
 * 
 * When preamble is not available, estimate on/off separation using
 * percentiles (5th and 95th) of all observed scores.
 * 
 * @param {number} greenScore - Frame's green intensity score
 * @param {number} threshold - Decision threshold
 * @param {number[]} allScores - Array of all green scores for percentile calculation
 * @param {number} confidenceMargin - Minimum confidence required (default 0.15 = 15%)
 * @returns {object} {state: 'on'|'off'|'unknown', confidence: number, distance: number}
 */
function classifyFrameWithPercentiles(greenScore, threshold, allScores, confidenceMargin = 0.15) {
    if (allScores.length === 0) {
        return { state: 'unknown', confidence: 0, distance: 0, greenScore: greenScore };
    }
    
    const sorted = allScores.slice().sort((a, b) => a - b);
    const p5Index = Math.floor(sorted.length * 0.05);
    const p95Index = Math.floor(sorted.length * 0.95);
    const p5 = sorted[p5Index];
    const p95 = sorted[p95Index];
    const range = p95 - p5;
    const eps = 0.01;
    
    const distance = Math.abs(greenScore - threshold);
    // Same clamp as classifyFrame — keep confidence in [0, 1].
    const confidence = Math.min(distance / (range + eps), 1);
    
    if (confidence < confidenceMargin) {
        return { 
            state: 'unknown', 
            confidence: confidence,
            distance: distance,
            greenScore: greenScore,
            range: range
        };
    }
    
    return { 
        state: greenScore > threshold ? 'on' : 'off',
        confidence: confidence,
        distance: distance,
        greenScore: greenScore,
        range: range
    };
}

/**
 * Consecutive sample gating (Schmitt trigger for state changes)
 * 
 * Requires N consecutive frames to agree before accepting a state transition.
 * Prevents single-frame glitches from causing false transitions.
 * 
 * @param {string} newState - New state ('on', 'off', or 'unknown')
 * @param {string[]} stateBuffer - Circular buffer of recent states (modified in place)
 * @param {number} requiredConsecutive - Number of consecutive samples required (default 3)
 * @returns {string|null} Stable state if N samples agree, null otherwise
 */
function getStableState(newState, stateBuffer, requiredConsecutive = 3) {
    // Add new state to buffer
    stateBuffer.push(newState);
    
    // Keep buffer size at requiredConsecutive
    while (stateBuffer.length > requiredConsecutive) {
        stateBuffer.shift();
    }
    
    // Check if buffer is full and all samples agree
    if (stateBuffer.length === requiredConsecutive) {
        const allAgree = stateBuffer.every(s => s === stateBuffer[0]);
        
        if (allAgree && stateBuffer[0] !== 'unknown') {
            return stateBuffer[0]; // Stable state confirmed
        }
    }
    
    return null; // Still uncertain
}

/**
 * Learn on/off distributions from preamble
 * 
 * Analyzes the alternating 1010... preamble pattern to determine:
 * - Mean green score for "on" state
 * - Mean green score for "off" state
 * - Optimal threshold (midpoint)
 * - Standard deviations for confidence estimation
 * 
 * @param {object[]} frames - Array of frame results with {time, greenScore, state}
 * @param {object} preambleRegion - {start: frameIndex, end: frameIndex}
 * @returns {object} {onMean, offMean, threshold, onStd, offStd, sampleCount}
 */
function learnDistributionsFromPreamble(frames, preambleRegion) {
    const preambleFrames = frames.slice(preambleRegion.start, preambleRegion.end);
    
    // Separate into on/off based on preliminary state
    const onScores = preambleFrames
        .filter(f => f.state === 'on')
        .map(f => f.greenScore);
    const offScores = preambleFrames
        .filter(f => f.state === 'off')
        .map(f => f.greenScore);
    
    if (onScores.length === 0 || offScores.length === 0) {
        console.warn('⚠️ [Quality] Preamble learning failed: insufficient on/off samples');
        return null;
    }
    
    const onMean = mean(onScores);
    const offMean = mean(offScores);
    const onStd = standardDeviation(onScores, onMean);
    const offStd = standardDeviation(offScores, offMean);
    const threshold = (onMean + offMean) / 2;
    
    console.log(`📊 [Quality] Learned from preamble: on=${onMean.toFixed(3)}±${onStd.toFixed(3)}, off=${offMean.toFixed(3)}±${offStd.toFixed(3)}, threshold=${threshold.toFixed(3)}`);
    
    return {
        onMean,
        offMean,
        threshold,
        onStd,
        offStd,
        range: Math.abs(onMean - offMean),
        sampleCount: onScores.length + offScores.length
    };
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
 * @param {number} meanVal - Pre-computed mean (optional)
 * @returns {number} Standard deviation
 */
function standardDeviation(arr, meanVal = null) {
    if (arr.length === 0) return 0;
    const m = meanVal !== null ? meanVal : mean(arr);
    const squaredDiffs = arr.map(x => Math.pow(x - m, 2));
    const variance = mean(squaredDiffs);
    return Math.sqrt(variance);
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
 * Detect preamble region in frame sequence
 * 
 * Searches for sustained alternating 1010... pattern indicating preamble.
 * The preamble is used for auto-calibration before data transmission.
 * 
 * @param {object[]} frames - Array of frames with {time, state}
 * @param {number} minTransitionRate - Minimum transition rate (default 0.8 = 80%)
 * @param {number} windowSize - Search window size in frames (default 50)
 * @returns {object|null} {start: frameIndex, end: frameIndex} or null if not found
 */
function detectPreamble(frames, minTransitionRate = 0.8, windowSize = 50) {
    if (frames.length < windowSize) {
        return null;
    }
    
    // Count transitions in sliding window. Use `<=` so the trailing window
    // starting at frames.length - windowSize is also considered — `<`
    // skipped any preamble that landed at the very end of the capture.
    for (let i = 0; i <= frames.length - windowSize; i++) {
        const windowFrames = frames.slice(i, i + windowSize);
        let transitions = 0;
        
        for (let j = 1; j < windowFrames.length; j++) {
            if (windowFrames[j].state !== windowFrames[j - 1].state) {
                transitions++;
            }
        }
        
        const transitionRate = transitions / (windowSize - 1);
        
        if (transitionRate >= minTransitionRate) {
            // Found preamble!
            console.log(`📡 [Quality] Preamble detected at frames ${i}-${i + windowSize} (${(transitionRate * 100).toFixed(1)}% transitions)`);
            return { start: i, end: i + windowSize };
        }
    }
    
    return null;
}

// Export for use in browser (attach to window object)
if (typeof window !== 'undefined') {
    window.QualityMetrics = QualityMetrics;
    window.CatQuality = {
        classifyFrame,
        classifyFrameWithPercentiles,
        getStableState,
        learnDistributionsFromPreamble,
        detectPreamble,
        mean,
        median,
        standardDeviation
    };
}

// Export for Node.js (if running in test environment)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        QualityMetrics,
        classifyFrame,
        classifyFrameWithPercentiles,
        getStableState,
        learnDistributionsFromPreamble,
        detectPreamble,
        mean,
        median,
        standardDeviation
    };
}
