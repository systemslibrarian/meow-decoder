/**
 * 🎯 Adaptive Threshold for Cat Mode Detection
 * 
 * Implements sliding-window threshold adaptation using bimodal distribution analysis.
 * Addresses lighting changes during video capture by continuously recalibrating.
 * 
 * Key Features:
 * - Sliding window (default 100 frames) for recent history
 * - Histogram-based bimodal peak detection
 * - Automatic re-calibration every N seconds
 * - Median Absolute Deviation (MAD) for robust statistics
 * - Fallback to median if distribution is unimodal
 * - Task 5.2.2: Gradient compensation (linear detrending)
 * 
 * Algorithm:
 * 1. Maintain circular buffer of recent green scores
 * 2. Every 1 second (reduced from 5s), compute histogram of window
 * 3. Find two highest peaks (on/off states)
 * 4. Set threshold to midpoint between peaks
 * 5. If gradient detected, apply linear detrending
 * 6. If only one peak found, warn and use median
 * 
 * @author Meow Decoder Team
 * @date 2026-02-13
 */

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Compute median of array (non-destructive).
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
 * Compute Median Absolute Deviation (MAD) for robust statistics.
 * MAD = median(|x_i - median(x)|)
 */
function medianAbsoluteDeviation(arr) {
    if (arr.length === 0) return 0;
    const med = median(arr);
    const deviations = arr.map(x => Math.abs(x - med));
    return median(deviations);
}

/**
 * Compute histogram of values.
 * @param {number[]} values - Input data
 * @param {number} bins - Number of bins
 * @param {number} min - Minimum value (default: auto-detect)
 * @param {number} max - Maximum value (default: auto-detect)
 * @returns {object} { bins: [{value, count}], binWidth }
 */
function computeHistogram(values, bins = 50, min = null, max = null) {
    if (values.length === 0) {
        return { bins: [], binWidth: 0 };
    }
    
    // Auto-detect range if not provided
    if (min === null) min = Math.min(...values);
    if (max === null) max = Math.max(...values);
    
    // Handle case where all values are the same
    if (min === max) {
        return {
            bins: [{ value: min, count: values.length }],
            binWidth: 0
        };
    }
    
    const binWidth = (max - min) / bins;
    const histogram = Array(bins).fill(0).map((_, i) => ({
        value: min + (i + 0.5) * binWidth,  // Center of bin
        count: 0
    }));
    
    // Fill histogram
    for (const val of values) {
        const binIndex = Math.min(Math.floor((val - min) / binWidth), bins - 1);
        histogram[binIndex].count++;
    }
    
    return { bins: histogram, binWidth };
}

/**
 * Find peaks in histogram using simple local maxima detection.
 * A peak is a bin with count higher than both neighbors.
 * @param {object[]} histogram - Array of {value, count}
 * @param {number} minPeakHeight - Minimum count to be considered a peak (default: 5% of max)
 * @returns {object[]} Array of {value, height, index}
 */
function findPeaks(histogram, minPeakHeight = null) {
    if (histogram.length < 3) return [];

    // Auto-set minimum peak height if not provided
    const maxCount = Math.max(...histogram.map(b => b.count));
    if (minPeakHeight === null) {
        minPeakHeight = maxCount * 0.05;  // 5% of max count
    }

    const peaks = [];

    // FIX (2026-05-04, Gate 2): also consider boundary bins.
    // computeHistogram bins values from min..max, so a bimodal
    // distribution clustered at the EXTREMES (e.g. cat-mode green
    // scores: 8.x off, 43.x on) puts both peaks in bin 0 and bin N-1.
    // The interior-only loop missed both, returning peaks=[] →
    // "No peaks detected" → median fallback → bad threshold → no sync.
    // A boundary bin is a peak iff it's greater than its one neighbor
    // and meets the height threshold.
    if (histogram.length >= 2 && histogram[0].count > histogram[1].count
        && histogram[0].count >= minPeakHeight) {
        peaks.push({ value: histogram[0].value, height: histogram[0].count, index: 0 });
    }

    // Find interior local maxima (higher than both neighbors)
    for (let i = 1; i < histogram.length - 1; i++) {
        const current = histogram[i].count;
        const left = histogram[i - 1].count;
        const right = histogram[i + 1].count;

        if (current > left && current > right && current >= minPeakHeight) {
            peaks.push({
                value: histogram[i].value,
                height: current,
                index: i
            });
        }
    }

    const lastIdx = histogram.length - 1;
    if (histogram.length >= 2 && histogram[lastIdx].count > histogram[lastIdx - 1].count
        && histogram[lastIdx].count >= minPeakHeight) {
        peaks.push({
            value: histogram[lastIdx].value,
            height: histogram[lastIdx].count,
            index: lastIdx,
        });
    }

    return peaks;
}

/**
 * Find valley (minimum) between two peaks.
 * This is a more robust threshold than simple midpoint.
 * @param {object[]} histogram
 * @param {object} peak1 - First peak {value, height, index}
 * @param {object} peak2 - Second peak
 * @returns {number} Value at valley minimum
 */
function findValley(histogram, peak1, peak2) {
    const leftIdx = Math.min(peak1.index, peak2.index);
    const rightIdx = Math.max(peak1.index, peak2.index);

    // Look strictly between the two peaks. The previous version seeded
    // minIdx at leftIdx (the peak itself), so adjacent or near-adjacent
    // peaks could return a peak as the threshold and misclassify ~half the
    // samples in that bin.
    if (rightIdx - leftIdx < 2) {
        return (histogram[leftIdx].value + histogram[rightIdx].value) / 2;
    }

    // FIX (2026-05-04, Gate 2): scan ALL interior bins for the minimum
    // count first, then return the CENTRE of the contiguous run of bins
    // at that minimum. The previous version returned the FIRST min-count
    // bin encountered, which — for cat-mode green scores where the peaks
    // sit at the histogram extremes (8.x off, 43.x on) and almost every
    // intermediate bin is empty (count=0) — meant the returned value was
    // bin (leftIdx+1), i.e. immediately adjacent to the lower peak.
    // Sampling noise of one bin width then crossed the threshold the
    // wrong way and corrupted bit decoding (sync word mismatch).
    let minCount = Infinity;
    for (let i = leftIdx + 1; i < rightIdx; i++) {
        if (histogram[i].count < minCount) minCount = histogram[i].count;
    }
    // Collect all interior bins at the minimum count.
    const minIndices = [];
    for (let i = leftIdx + 1; i < rightIdx; i++) {
        if (histogram[i].count === minCount) minIndices.push(i);
    }
    // Return the CENTRE of that valley region.
    const centerIdx = minIndices[Math.floor(minIndices.length / 2)];
    return histogram[centerIdx].value;
}

// ============================================================================
// AdaptiveThreshold Class
// ============================================================================
// GradientCompensator Class (Task 5.2.2)
// ============================================================================

/**
 * Detects and compensates for gradual lighting gradients during video capture.
 * 
 * Uses linear regression on recent green scores to detect trends and
 * apply detrending when the slope exceeds a threshold. This prevents
 * the adaptive threshold from drifting slowly and losing calibration.
 * 
 * @example
 * const compensator = new GradientCompensator();
 * compensator.update(0.65, 1.0);
 * compensator.update(0.68, 1.5);
 * const adjusted = compensator.compensate(0.72, 2.0);
 * // adjusted ≈ 0.65 if linear trend detected
 */
class GradientCompensator {
    /**
     * @param {number} maxWindow - Maximum number of frames in regression window
     * @param {number} slopeThreshold - Minimum slope to trigger compensation (default 0.01 = 1%/s)
     */
    constructor(maxWindow = 100, slopeThreshold = 0.01) {
        this.recentScores = [];
        this.recentTimes = [];
        this.maxWindow = maxWindow;
        this.slopeThreshold = slopeThreshold;
        
        // Cached regression
        this._cachedSlope = 0;
        this._cachedIntercept = 0;
        this._cacheValid = false;
        this._lastCacheSize = 0;
        
        // Diagnostics
        this.compensationActive = false;
        this.totalCompensations = 0;
    }
    
    /**
     * Add a new score/time observation.
     * @param {number} score - Green score (0-1 range)
     * @param {number} time - Timestamp in seconds
     */
    update(score, time) {
        this.recentScores.push(score);
        this.recentTimes.push(time);
        
        if (this.recentScores.length > this.maxWindow) {
            this.recentScores.shift();
            this.recentTimes.shift();
        }
        
        // Invalidate cache when data changes
        if (this.recentScores.length !== this._lastCacheSize) {
            this._cacheValid = false;
        }
    }
    
    /**
     * Compute linear regression (least-squares fit).
     * Returns slope (m) and intercept (b) for y = mx + b.
     * @returns {object} {slope, intercept, r2}
     */
    detectTrend() {
        const n = this.recentScores.length;
        if (n < 10) return { slope: 0, intercept: 0, r2: 0 };

        // Cache returns the actual r2 — the previous code returned 0 on a
        // cache hit, which made compensate() flip off whenever it was
        // called twice without intervening data.
        if (this._cacheValid && this._lastCacheSize === n) {
            return { slope: this._cachedSlope, intercept: this._cachedIntercept, r2: this._cachedR2 };
        }

        let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;

        for (let i = 0; i < n; i++) {
            const x = this.recentTimes[i];
            const y = this.recentScores[i];
            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
        }

        const denom = n * sumX2 - sumX * sumX;
        if (Math.abs(denom) < 1e-10) {
            return { slope: 0, intercept: sumY / n, r2: 0 };
        }

        const slope = (n * sumXY - sumX * sumY) / denom;
        const intercept = (sumY - slope * sumX) / n;

        // R² (coefficient of determination). Compute ssTotal and
        // ssResidual directly from residuals rather than from the
        // algebraic-expansion form (sumY2 - n*meanY*meanY etc.), which
        // catastrophically cancels when y has small variance — green
        // scores cluster tightly so this case is the norm, not the
        // exception. The clamp at the end was hiding wrong values.
        const meanY = sumY / n;
        let ssTotal = 0;
        let ssResidual = 0;
        for (let i = 0; i < n; i++) {
            const y = this.recentScores[i];
            const x = this.recentTimes[i];
            const dy = y - meanY;
            ssTotal += dy * dy;
            const r = y - (slope * x + intercept);
            ssResidual += r * r;
        }
        const r2 = ssTotal > 0 ? Math.max(0, Math.min(1, 1 - ssResidual / ssTotal)) : 0;

        // Cache result
        this._cachedSlope = slope;
        this._cachedIntercept = intercept;
        this._cachedR2 = r2;
        this._cacheValid = true;
        this._lastCacheSize = n;

        return { slope, intercept, r2 };
    }
    
    /**
     * Compensate a score for detected gradient.
     * Removes the linear trend if slope exceeds threshold.
     * @param {number} score - Raw green score
     * @param {number} time - Timestamp in seconds
     * @returns {number} Compensated score
     */
    compensate(score, time) {
        const { slope, intercept, r2 } = this.detectTrend();
        
        // Only compensate if:
        // 1. Significant slope (above threshold)
        // 2. Good fit (R² > 0.3) to avoid compensating noise
        if (Math.abs(slope) > this.slopeThreshold && r2 > 0.3) {
            const baseline = intercept + slope * this.recentTimes[0]; // Value at start
            const expectedDrift = slope * (time - this.recentTimes[0]);
            const compensated = score - expectedDrift;
            
            if (!this.compensationActive) {
                console.log(`🌈 [Gradient] Compensation activated: slope=${slope.toFixed(4)}/s, R²=${r2.toFixed(2)}`);
            }
            this.compensationActive = true;
            this.totalCompensations++;
            
            return compensated;
        }
        
        if (this.compensationActive && Math.abs(slope) <= this.slopeThreshold) {
            console.log(`🌈 [Gradient] Compensation deactivated: slope=${slope.toFixed(4)}/s (below threshold)`);
            this.compensationActive = false;
        }
        
        return score; // No compensation needed
    }
    
    /**
     * Get diagnostics for debugging/UI display.
     */
    getDiagnostics() {
        const { slope, intercept, r2 } = this.detectTrend();
        return {
            windowSize: this.recentScores.length,
            slope: slope.toFixed(5),
            intercept: intercept.toFixed(3),
            r2: r2.toFixed(3),
            compensationActive: this.compensationActive,
            totalCompensations: this.totalCompensations,
            slopeThreshold: this.slopeThreshold
        };
    }
    
    /**
     * Reset state.
     */
    reset() {
        this.recentScores = [];
        this.recentTimes = [];
        this._cacheValid = false;
        this.compensationActive = false;
        this.totalCompensations = 0;
    }
}

// ============================================================================
// AdaptiveThreshold Class
// ============================================================================

class AdaptiveThreshold {
    /**
     * @param {number} windowSize - Number of frames to keep in sliding window
     * @param {number} recalibrateSec - Seconds between re-calibrations (default 1s, reduced from 5s per Task 5.2.2)
     * @param {number} histogramBins - Number of histogram bins
     */
    constructor(windowSize = 100, recalibrateSec = 1, histogramBins = 50) {
        this.window = [];
        this.windowSize = windowSize;
        this.recalibrateInterval = recalibrateSec * 1000; // Convert to ms
        // Use null sentinel so the first frame doesn't immediately trigger
        // calibration (timestamp - 0 always exceeds recalibrateInterval).
        // Set on the first update() call.
        this.lastCalibration = null;
        this.threshold = 0.5; // Initial guess (will be updated)
        this.histogramBins = histogramBins;
        
        // Task 5.2.2: Gradient compensator
        this.gradientCompensator = new GradientCompensator();
        
        // Diagnostics
        this.calibrationCount = 0;
        this.lastHistogram = null;
        this.lastPeaks = null;
        this.distributionType = 'unknown'; // 'bimodal', 'unimodal', 'uniform'
        this.confidence = 0; // 0-1, how confident we are in threshold
    }
    
    /**
     * Update window with new green score and potentially recalibrate.
     * Task 5.2.2: Also applies gradient compensation.
     * @param {number} greenScore - Current frame's green score
     * @param {number} timestamp - Timestamp in milliseconds
     * @returns {object} { threshold, calibrated, compensatedScore, diagnostics }
     */
    update(greenScore, timestamp) {
        // Task 5.2.2: Update gradient compensator and apply detrending
        const timeSec = timestamp / 1000;
        this.gradientCompensator.update(greenScore, timeSec);
        const compensatedScore = this.gradientCompensator.compensate(greenScore, timeSec);
        
        // Add compensated score to sliding window
        this.window.push(compensatedScore);
        if (this.window.length > this.windowSize) {
            this.window.shift();
        }
        
        // Check if need to recalibrate (every 1s per Task 5.2.2, was 5s).
        // Initialize lastCalibration on the first update so the elapsed-time
        // check measures from real first-frame time, not from epoch zero.
        if (this.lastCalibration === null) {
            this.lastCalibration = timestamp;
        }
        let calibrated = false;
        if (timestamp - this.lastCalibration >= this.recalibrateInterval && this.window.length >= 20) {
            this.recalibrate();
            this.lastCalibration = timestamp;
            calibrated = true;
        }
        
        return {
            threshold: this.threshold,
            calibrated: calibrated,
            compensatedScore,
            diagnostics: this.getDiagnostics()
        };
    }
    
    /**
     * Force immediate recalibration.
     */
    recalibrate() {
        if (this.window.length < 10) {
            console.warn('⚠️ [Adaptive Threshold] Not enough data for calibration');
            return;
        }
        
        // Compute histogram
        const histogramData = computeHistogram(this.window, this.histogramBins);
        this.lastHistogram = histogramData.bins;
        
        // Find peaks
        const peaks = findPeaks(this.lastHistogram);
        this.lastPeaks = peaks;
        
        if (peaks.length >= 2) {
            // BIMODAL: Two or more peaks detected
            this.distributionType = 'bimodal';
            
            // Sort peaks by height (highest first)
            const sortedPeaks = peaks.slice().sort((a, b) => b.height - a.height);
            const peak1 = sortedPeaks[0];
            const peak2 = sortedPeaks[1];
            
            // Use valley between two highest peaks as threshold
            this.threshold = findValley(this.lastHistogram, peak1, peak2);
            
            // Confidence: ratio of peak separation to total range
            const separation = Math.abs(peak1.value - peak2.value);
            const range = Math.max(...this.window) - Math.min(...this.window);
            this.confidence = range > 0 ? Math.min(separation / range, 1.0) : 0;
            
            console.log(`✅ [Adaptive Threshold] Bimodal calibration: threshold=${this.threshold.toFixed(3)}, peaks=[${peak1.value.toFixed(3)}, ${peak2.value.toFixed(3)}], confidence=${this.confidence.toFixed(2)}`);
            
        } else if (peaks.length === 1) {
            // UNIMODAL: Only one peak (e.g., all on or all off)
            this.distributionType = 'unimodal';
            this.confidence = 0.3; // Low confidence
            
            // Use MAD-based threshold: median ± 1.5*MAD
            const med = median(this.window);
            const mad = medianAbsoluteDeviation(this.window);
            
            // If peak is above median, threshold below it; vice versa
            const peak = peaks[0];
            if (peak.value > med) {
                this.threshold = med - 1.5 * mad;
            } else {
                this.threshold = med + 1.5 * mad;
            }
            
            // Clamp to data range
            this.threshold = Math.max(Math.min(...this.window), Math.min(this.threshold, Math.max(...this.window)));
            
            console.warn(`⚠️ [Adaptive Threshold] Unimodal distribution (no clear on/off) - using median ± MAD: threshold=${this.threshold.toFixed(3)}`);
            
        } else {
            // UNIFORM or NOISY: No clear peaks
            this.distributionType = 'uniform';
            this.confidence = 0.1; // Very low confidence
            
            // Fall back to median
            this.threshold = median(this.window);
            
            console.warn(`⚠️ [Adaptive Threshold] No peaks detected - using median: threshold=${this.threshold.toFixed(3)}`);
        }
        
        this.calibrationCount++;
    }
    
    /**
     * Get current threshold value.
     */
    getThreshold() {
        return this.threshold;
    }
    
    /**
     * Get diagnostics for debugging/UI display.
     * Task 5.2.2: Includes gradient compensation metrics.
     */
    getDiagnostics() {
        return {
            threshold: this.threshold,
            windowSize: this.window.length,
            windowCapacity: this.windowSize,
            distributionType: this.distributionType,
            confidence: this.confidence,
            calibrationCount: this.calibrationCount,
            peakCount: this.lastPeaks ? this.lastPeaks.length : 0,
            lastPeaks: this.lastPeaks ? this.lastPeaks.map(p => ({
                value: p.value.toFixed(3),
                height: p.height
            })) : [],
            // Statistics
            median: this.window.length > 0 ? median(this.window).toFixed(3) : 'N/A',
            mad: this.window.length > 0 ? medianAbsoluteDeviation(this.window).toFixed(3) : 'N/A',
            min: this.window.length > 0 ? Math.min(...this.window).toFixed(3) : 'N/A',
            max: this.window.length > 0 ? Math.max(...this.window).toFixed(3) : 'N/A',
            // Task 5.2.2: Gradient metrics
            gradient: this.gradientCompensator.getDiagnostics()
        };
    }
    
    /**
     * Reset state (e.g., when starting new video analysis).
     */
    reset() {
        this.window = [];
        this.lastCalibration = null;
        this.threshold = 0.5;
        this.calibrationCount = 0;
        this.lastHistogram = null;
        this.lastPeaks = null;
        this.distributionType = 'unknown';
        this.confidence = 0;
        this.gradientCompensator.reset();
    }
}

// ============================================================================
// Export
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        AdaptiveThreshold,
        GradientCompensator,
        median,
        medianAbsoluteDeviation,
        computeHistogram,
        findPeaks,
        findValley
    };
}

if (typeof window !== 'undefined') {
    window.AdaptiveThreshold = AdaptiveThreshold;
    window.GradientCompensator = GradientCompensator;
    window.AdaptiveThresholdUtils = {
        median,
        medianAbsoluteDeviation,
        computeHistogram,
        findPeaks,
        findValley
    };
}
