/**
 * 🔄 Hysteresis (Schmitt Trigger) for Cat Mode Detection
 * 
 * Implements noise-resistant state detection using dual thresholds.
 * Prevents flickering when signal hovers near threshold boundary.
 * 
 * How It Works:
 * - Two thresholds: LOW and HIGH
 * - State only changes on definitive crossing:
 *   * value > HIGH → state = ON
 *   * value < LOW → state = OFF
 *   * LOW < value < HIGH → keep previous state (hysteresis zone)
 * 
 * Example:
 *   threshold = 50, margin = 10%
 *   → LOW = 45, HIGH = 55
 *   
 *   Signal path: 40 → 48 → 52 → 49 → 58 → 43
 *   States:      OFF  OFF   OFF  OFF  ON   OFF
 *                ↑    ↑     ↑    ↑    ↑    ↑
 *              < 45  45-55 45-55 45-55 >55  <45
 *              new   stay  stay  stay  new  new
 * 
 * Benefits:
 * - Eliminates rapid on/off oscillation near threshold
 * - More stable state detection in noisy environments
 * - Configurable margin (default 10%)
 * 
 * @author Meow Decoder Team
 * @date 2026-02-13
 */

// ============================================================================
// SchmittTrigger Class
// ============================================================================

class SchmittTrigger {
    /**
     * @param {number} threshold - Center threshold value
     * @param {number} margin - Hysteresis margin (0-1, default 0.1 = 10%)
     * @param {string} initialState - Initial state ('off' or 'on')
     */
    constructor(threshold, margin = 0.1, initialState = 'off') {
        this.setThresholds(threshold, margin);
        this.state = initialState;
        this.transitionCount = 0;
        this.lastTransitionValue = null;
    }
    
    /**
     * Update thresholds (useful when adaptive threshold changes).
     * @param {number} threshold - Center threshold
     * @param {number} margin - Hysteresis margin (0-1)
     */
    setThresholds(threshold, margin = 0.1) {
        this.centerThreshold = threshold;
        this.margin = margin;
        // Use a half-band based on |threshold| so:
        //  - negative thresholds (possible after gradient compensation
        //    detrends a signal) don't invert low/high and silently break
        //    the hysteresis logic, and
        //  - thresholds near zero still get a usable band rather than
        //    collapsing to ~0 width.
        // Falls back to a small absolute floor so the band is never zero.
        const halfBand = Math.max(Math.abs(threshold) * margin, 1e-6);
        this.low = threshold - halfBand;
        this.high = threshold + halfBand;
    }
    
    /**
     * Update state based on input value.
     * @param {number} value - Current sensor value
     * @returns {object} { state, changed, inHysteresisZone }
     */
    update(value) {
        const previousState = this.state;
        let inHysteresisZone = false;
        
        if (value > this.high) {
            // Definitive ON
            this.state = 'on';
        } else if (value < this.low) {
            // Definitive OFF
            this.state = 'off';
        } else {
            // In hysteresis zone - keep previous state
            inHysteresisZone = true;
            // this.state unchanged
        }
        
        const changed = (this.state !== previousState);
        
        if (changed) {
            this.transitionCount++;
            this.lastTransitionValue = value;
        }
        
        return {
            state: this.state,
            changed: changed,
            inHysteresisZone: inHysteresisZone,
            thresholds: {
                low: this.low,
                high: this.high,
                center: this.centerThreshold
            }
        };
    }
    
    /**
     * Get current state without updating.
     */
    getState() {
        return this.state;
    }
    
    /**
     * Reset state.
     * @param {string} newState - New state ('off' or 'on')
     */
    reset(newState = 'off') {
        this.state = newState;
        this.transitionCount = 0;
        this.lastTransitionValue = null;
    }
    
    /**
     * Get diagnostics.
     */
    getDiagnostics() {
        return {
            state: this.state,
            low: this.low.toFixed(3),
            high: this.high.toFixed(3),
            center: this.centerThreshold.toFixed(3),
            margin: (this.margin * 100).toFixed(1) + '%',
            hysteresisZone: `${this.low.toFixed(3)} - ${this.high.toFixed(3)}`,
            transitionCount: this.transitionCount,
            lastTransition: this.lastTransitionValue ? this.lastTransitionValue.toFixed(3) : 'N/A'
        };
    }
}

// ============================================================================
// Adaptive Hysteresis (Integrates with Adaptive Threshold)
// ============================================================================

class AdaptiveHysteresis {
    /**
     * Combines Schmitt trigger with adaptive threshold.
     * Automatically updates hysteresis thresholds when adaptive threshold changes.
     * 
     * @param {number} initialThreshold - Starting threshold
     * @param {number} margin - Hysteresis margin (default 0.1 = 10%)
     * @param {string} initialState - Initial state
     */
    constructor(initialThreshold, margin = 0.1, initialState = 'off') {
        this.schmitt = new SchmittTrigger(initialThreshold, margin, initialState);
        this.margin = margin;
        this.thresholdHistory = [initialThreshold];
        this.maxHistorySize = 10;
    }
    
    /**
     * Update with new value and potentially new threshold.
     * @param {number} value - Current sensor value
     * @param {number} adaptiveThreshold - Current adaptive threshold (may change over time)
     * @returns {object} Update result
     */
    update(value, adaptiveThreshold) {
        // Check if threshold changed significantly (> 1%). Use absolute
        // threshold magnitude as the basis so a small / negative
        // adaptiveThreshold doesn't make the comparator effectively
        // detect every tiny noise wiggle as a change (which then thrashes
        // thresholdHistory and forces a setThresholds() recompute every
        // frame).
        const refScale = Math.max(Math.abs(adaptiveThreshold), 1e-6);
        const thresholdChanged = Math.abs(this.schmitt.centerThreshold - adaptiveThreshold) > refScale * 0.01;


        if (thresholdChanged) {
            this.schmitt.setThresholds(adaptiveThreshold, this.margin);
            this.thresholdHistory.push(adaptiveThreshold);
            if (this.thresholdHistory.length > this.maxHistorySize) {
                this.thresholdHistory.shift();
            }
        }
        
        const result = this.schmitt.update(value);
        result.thresholdChanged = thresholdChanged;
        
        return result;
    }
    
    /**
     * Get current state.
     */
    getState() {
        return this.schmitt.getState();
    }
    
    /**
     * Set hysteresis margin.
     * @param {number} margin - New margin (0-1)
     */
    setMargin(margin) {
        this.margin = margin;
        this.schmitt.setThresholds(this.schmitt.centerThreshold, margin);
    }
    
    /**
     * Reset state.
     */
    reset(newState = 'off') {
        this.schmitt.reset(newState);
        this.thresholdHistory = [this.schmitt.centerThreshold];
    }
    
    /**
     * Get diagnostics.
     */
    getDiagnostics() {
        const diag = this.schmitt.getDiagnostics();
        diag.thresholdUpdates = this.thresholdHistory.length - 1;
        return diag;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Calculate optimal hysteresis margin based on signal characteristics.
 * @param {number[]} values - Array of signal values
 * @param {number} threshold - Current threshold
 * @returns {number} Recommended margin (0-1)
 */
function calculateOptimalMargin(values, threshold) {
    if (values.length < 10) return 0.1; // Default 10%

    // Find values near threshold (within ±20% of |threshold|, with a small
    // absolute floor for thresholds near zero — division by `threshold`
    // would produce NaN otherwise on dark / silent video).
    const refScale = Math.max(Math.abs(threshold), 1e-6);
    const nearThreshold = values.filter(v => {
        const dist = Math.abs(v - threshold) / refScale;
        return dist < 0.2;
    });

    if (nearThreshold.length === 0) {
        // No values near threshold - can use smaller margin
        return 0.05; // 5%
    }

    // Calculate variance of near-threshold values
    const mean = nearThreshold.reduce((a, b) => a + b, 0) / nearThreshold.length;
    const variance = nearThreshold.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / nearThreshold.length;
    const stdDev = Math.sqrt(variance);

    // Margin = 2 * coefficient of variation (CV).
    // Guard mean → 0 (all near-threshold values clustered at zero) so the
    // CV doesn't go to Infinity and the final clamp doesn't return NaN.
    const cv = Math.abs(mean) > 1e-6 ? stdDev / Math.abs(mean) : 0.1;
    if (!Number.isFinite(cv)) return 0.1;
    const margin = Math.min(Math.max(cv * 2, 0.05), 0.3); // Clamp to 5-30%

    return margin;
}

// ============================================================================
// Export
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SchmittTrigger,
        AdaptiveHysteresis,
        calculateOptimalMargin
    };
}

if (typeof window !== 'undefined') {
    window.SchmittTrigger = SchmittTrigger;
    window.AdaptiveHysteresis = AdaptiveHysteresis;
    window.HysteresisUtils = {
        calculateOptimalMargin
    };
}
