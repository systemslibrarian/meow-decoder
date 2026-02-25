/**
 * hysteresis.test.js — Unit tests for Schmitt trigger & adaptive hysteresis.
 */

const { SchmittTrigger, AdaptiveHysteresis, calculateOptimalMargin } = require('../hysteresis');

// ── SchmittTrigger ────────────────────────────────────────────────────────────

describe('SchmittTrigger', () => {
  it('starts in the specified initial state', () => {
    expect(new SchmittTrigger(100, 0.1, 'off').getState()).toBe('off');
    expect(new SchmittTrigger(100, 0.1, 'on').getState()).toBe('on');
  });

  it('transitions OFF → ON when value exceeds high threshold', () => {
    const s = new SchmittTrigger(100, 0.1, 'off');
    // high = 110
    const r = s.update(115);
    expect(r.state).toBe('on');
    expect(r.changed).toBe(true);
    expect(r.inHysteresisZone).toBe(false);
  });

  it('transitions ON → OFF when value drops below low threshold', () => {
    const s = new SchmittTrigger(100, 0.1, 'on');
    // low = 90
    const r = s.update(85);
    expect(r.state).toBe('off');
    expect(r.changed).toBe(true);
  });

  it('holds state inside hysteresis zone', () => {
    const s = new SchmittTrigger(100, 0.1, 'off');
    // zone: 90–110
    const r = s.update(100);
    expect(r.state).toBe('off');
    expect(r.changed).toBe(false);
    expect(r.inHysteresisZone).toBe(true);
  });

  it('holds ON state inside hysteresis zone', () => {
    const s = new SchmittTrigger(100, 0.1, 'on');
    const r = s.update(100);
    expect(r.state).toBe('on');
    expect(r.changed).toBe(false);
    expect(r.inHysteresisZone).toBe(true);
  });

  it('follows the documented signal path example', () => {
    // From docstring: threshold=50, margin=10%  → LOW=45, HIGH=55
    const s = new SchmittTrigger(50, 0.1, 'off');
    const signals = [40, 48, 52, 49, 58, 43];
    const expected = ['off', 'off', 'off', 'off', 'on', 'off'];

    for (let i = 0; i < signals.length; i++) {
      s.update(signals[i]);
      expect(s.getState()).toBe(expected[i]);
    }
  });

  it('counts transitions correctly', () => {
    const s = new SchmittTrigger(50, 0.1, 'off');
    s.update(60); // → on (transition)
    s.update(50); // hysteresis zone, stays on
    s.update(40); // → off (transition)
    expect(s.getDiagnostics().transitionCount).toBe(2);
  });

  it('setThresholds updates low/high', () => {
    const s = new SchmittTrigger(100, 0.1);
    s.setThresholds(200, 0.2);
    expect(s.getDiagnostics().center).toBe('200.000');
    // low = 160, high = 240
    s.update(250);
    expect(s.getState()).toBe('on');
    s.update(180);
    expect(s.getState()).toBe('on'); // still in zone
    s.update(150);
    expect(s.getState()).toBe('off');
  });

  it('reset clears transition count and state', () => {
    const s = new SchmittTrigger(50, 0.1, 'off');
    s.update(60);
    expect(s.getState()).toBe('on');
    s.reset('off');
    expect(s.getState()).toBe('off');
    expect(s.getDiagnostics().transitionCount).toBe(0);
  });

  it('returns correct threshold info in update result', () => {
    const s = new SchmittTrigger(100, 0.1);
    const r = s.update(120);
    expect(r.thresholds.low).toBeCloseTo(90);
    expect(r.thresholds.high).toBeCloseTo(110);
    expect(r.thresholds.center).toBe(100);
  });
});

// ── AdaptiveHysteresis ────────────────────────────────────────────────────────

describe('AdaptiveHysteresis', () => {
  it('tracks adaptive threshold changes', () => {
    const ah = new AdaptiveHysteresis(100, 0.1, 'off');
    // Threshold jumps to 200 (>1% change)
    const r = ah.update(250, 200);
    expect(r.thresholdChanged).toBe(true);
    expect(r.state).toBe('on');
  });

  it('ignores small threshold changes (<1%)', () => {
    const ah = new AdaptiveHysteresis(100, 0.1, 'off');
    const r = ah.update(50, 100.5); // 0.5% change, below 1%
    expect(r.thresholdChanged).toBe(false);
  });

  it('records threshold history', () => {
    const ah = new AdaptiveHysteresis(100, 0.1, 'off');
    ah.update(50, 150);
    ah.update(50, 200);
    const diag = ah.getDiagnostics();
    expect(diag.thresholdUpdates).toBe(2);
  });

  it('caps threshold history at maxHistorySize', () => {
    const ah = new AdaptiveHysteresis(10, 0.1, 'off');
    for (let i = 0; i < 20; i++) {
      ah.update(0, 100 + i * 10);
    }
    // maxHistorySize = 10, first entry + 10 updates → capped at 10
    expect(ah.getDiagnostics().thresholdUpdates).toBeLessThanOrEqual(10);
  });

  it('setMargin updates margin and thresholds', () => {
    const ah = new AdaptiveHysteresis(100, 0.1, 'off');
    ah.setMargin(0.2);
    // Now zone is 80–120
    ah.update(115, 100);
    expect(ah.getState()).toBe('off'); // still in zone
    ah.update(125, 100);
    expect(ah.getState()).toBe('on');
  });

  it('reset clears history', () => {
    const ah = new AdaptiveHysteresis(100, 0.1, 'off');
    // Threshold adapts to 200 → high = 220.  value 250 > 220 → on
    ah.update(250, 200);
    expect(ah.getState()).toBe('on');
    ah.reset();
    expect(ah.getState()).toBe('off');
    expect(ah.getDiagnostics().thresholdUpdates).toBe(0);
  });
});

// ── calculateOptimalMargin ────────────────────────────────────────────────────

describe('calculateOptimalMargin', () => {
  it('returns default 0.1 for fewer than 10 values', () => {
    expect(calculateOptimalMargin([1, 2, 3], 50)).toBe(0.1);
  });

  it('returns small margin when no values are near threshold', () => {
    const values = Array.from({ length: 20 }, () => 10); // all far from threshold=100
    expect(calculateOptimalMargin(values, 100)).toBe(0.05);
  });

  it('returns larger margin for noisy near-threshold values', () => {
    // High variance near threshold
    const values = [];
    for (let i = 0; i < 50; i++) {
      values.push(50 + (Math.random() - 0.5) * 20);
    }
    const margin = calculateOptimalMargin(values, 50);
    expect(margin).toBeGreaterThanOrEqual(0.05);
    expect(margin).toBeLessThanOrEqual(0.3);
  });

  it('clamps margin to 5–30% range', () => {
    // Very tight cluster (low variance)
    const values = Array.from({ length: 20 }, (_, i) => 100 + i * 0.001);
    const margin = calculateOptimalMargin(values, 100);
    expect(margin).toBeGreaterThanOrEqual(0.05);
    expect(margin).toBeLessThanOrEqual(0.3);
  });
});
