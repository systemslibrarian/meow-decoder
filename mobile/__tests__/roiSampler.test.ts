/**
 * roiSampler.test.ts — unit tests for the Cat Mode ROI luminance helper.
 *
 * roiMeanLuminance is the pure, testable spec the frame-processor worklet's
 * inlined loop mirrors. These tests pin its behaviour: region mapping, row
 * stride (bytesPerRow) handling, clamping, and subsampling.
 */

import {
  roiMeanLuminance,
  DEFAULT_LEFT_EYE_ROI,
  DEFAULT_RIGHT_EYE_ROI,
  type NormalizedRoi,
} from '../src/services/roiSampler';

/** Build a width×height Y-plane with optional row padding, filled by fn(x,y). */
function makePlane(
  width: number,
  height: number,
  bytesPerRow: number,
  fn: (x: number, y: number) => number,
): Uint8Array {
  const plane = new Uint8Array(bytesPerRow * height);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      plane[y * bytesPerRow + x] = fn(x, y) & 0xff;
    }
  }
  return plane;
}

describe('roiMeanLuminance', () => {
  it('returns the constant value of a uniform region', () => {
    const plane = makePlane(100, 100, 100, () => 137);
    const roi: NormalizedRoi = { x: 0.25, y: 0.25, w: 0.5, h: 0.5 };
    expect(roiMeanLuminance(plane, 100, 100, 100, roi)).toBe(137);
  });

  it('reads only the requested region (left half dark, right half bright)', () => {
    const plane = makePlane(100, 100, 100, (x) => (x < 50 ? 20 : 220));
    const left: NormalizedRoi = { x: 0.0, y: 0.0, w: 0.4, h: 1.0 };
    const right: NormalizedRoi = { x: 0.6, y: 0.0, w: 0.4, h: 1.0 };
    expect(roiMeanLuminance(plane, 100, 100, 100, left)).toBe(20);
    expect(roiMeanLuminance(plane, 100, 100, 100, right)).toBe(220);
  });

  it('honours bytesPerRow padding (stride > width)', () => {
    // 8 px wide rows but 16-byte stride; padding bytes are 255 and must be
    // ignored. A correct reader keys off x within [0,width), never the padding.
    const width = 8;
    const height = 8;
    const stride = 16;
    const plane = new Uint8Array(stride * height).fill(255);
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) plane[y * stride + x] = 50;
    }
    const roi: NormalizedRoi = { x: 0, y: 0, w: 1, h: 1 };
    expect(roiMeanLuminance(plane, width, height, stride, roi)).toBe(50);
  });

  it('clamps out-of-range ROIs to the frame', () => {
    const plane = makePlane(40, 40, 40, () => 90);
    const roi: NormalizedRoi = { x: -0.5, y: -0.5, w: 5, h: 5 };
    expect(roiMeanLuminance(plane, 40, 40, 40, roi)).toBe(90);
  });

  it('returns 0 for a degenerate (zero-area) region', () => {
    const plane = makePlane(40, 40, 40, () => 90);
    expect(roiMeanLuminance(plane, 40, 40, 40, { x: 0.5, y: 0.5, w: 0, h: 0 })).toBe(0);
  });

  it('returns 0 for invalid frame geometry', () => {
    const plane = new Uint8Array(10);
    expect(roiMeanLuminance(plane, 0, 10, 10, { x: 0, y: 0, w: 1, h: 1 })).toBe(0);
    expect(roiMeanLuminance(plane, 10, 10, 5, { x: 0, y: 0, w: 1, h: 1 })).toBe(0);
  });

  it('approximates the mean when subsampling a large region', () => {
    // Smooth horizontal gradient; subsampled mean should be near the true mean.
    const w = 400;
    const h = 400;
    const plane = makePlane(w, h, w, (x) => Math.round((x / (w - 1)) * 255));
    const roi: NormalizedRoi = { x: 0, y: 0, w: 1, h: 1 };
    const mean = roiMeanLuminance(plane, w, h, w, roi, 256); // force heavy subsampling
    expect(Math.abs(mean - 127.5)).toBeLessThan(8);
  });

  it('default eye ROIs are disjoint and within the frame', () => {
    for (const roi of [DEFAULT_LEFT_EYE_ROI, DEFAULT_RIGHT_EYE_ROI]) {
      expect(roi.x).toBeGreaterThanOrEqual(0);
      expect(roi.y).toBeGreaterThanOrEqual(0);
      expect(roi.x + roi.w).toBeLessThanOrEqual(1);
      expect(roi.y + roi.h).toBeLessThanOrEqual(1);
    }
    // Left ends before right begins → non-overlapping.
    expect(DEFAULT_LEFT_EYE_ROI.x + DEFAULT_LEFT_EYE_ROI.w).toBeLessThanOrEqual(
      DEFAULT_RIGHT_EYE_ROI.x,
    );
  });
});
