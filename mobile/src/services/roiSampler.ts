/**
 * roiSampler.ts — mean luminance over a rectangular region of a camera frame.
 *
 * This is the pure, testable core of the Cat Mode brightness sampler. The
 * VisionCamera frame processor (useCatBlinkSampler) hands us the frame's
 * luminance plane and the two eye regions; this computes the mean brightness of
 * each so the decoder can tell an ON (bright) eye from an OFF (dark) one.
 *
 * The luminance (Y) plane of a YUV 4:2:0 frame is a width×height array of 8-bit
 * brightness samples, one per pixel, stored row-major with a row stride
 * (`bytesPerRow`) that may be larger than `width` due to hardware alignment.
 * Working on the Y plane directly is both cheap and exactly what we want: a
 * green-lit eye reads as high luminance, a dark eye as low.
 */

/** A region of interest expressed in normalized [0,1] frame coordinates. */
export interface NormalizedRoi {
  /** Left edge, 0 (frame left) … 1 (frame right). */
  x: number;
  /** Top edge, 0 (frame top) … 1 (frame bottom). */
  y: number;
  /** Width as a fraction of frame width. */
  w: number;
  /** Height as a fraction of frame height. */
  h: number;
}

function clamp01(v: number): number {
  if (v < 0) return 0;
  if (v > 1) return 1;
  return v;
}

/**
 * Mean luminance (0–255) of `roi` within a YUV Y-plane.
 *
 * To keep the cost bounded on every frame, at most ~`maxSamples` pixels are
 * read: the region is subsampled with an integer stride when it is large. The
 * result is the average of the sampled pixels, which is a faithful estimate of
 * the region mean for the smooth, near-uniform eye patches we measure.
 *
 * @param yPlane      Luminance bytes (length ≥ bytesPerRow × height).
 * @param width       Frame width in pixels.
 * @param height      Frame height in pixels.
 * @param bytesPerRow Row stride in bytes (≥ width).
 * @param roi         Region of interest in normalized [0,1] coordinates.
 * @param maxSamples  Soft cap on pixels read (default 1024).
 * @returns           Mean luminance 0–255, or 0 if the region is empty.
 */
export function roiMeanLuminance(
  yPlane: Uint8Array,
  width: number,
  height: number,
  bytesPerRow: number,
  roi: NormalizedRoi,
  maxSamples = 1024,
): number {
  if (width <= 0 || height <= 0 || bytesPerRow < width) return 0;

  const x0 = Math.floor(clamp01(roi.x) * width);
  const y0 = Math.floor(clamp01(roi.y) * height);
  const x1 = Math.min(width, Math.ceil(clamp01(roi.x + roi.w) * width));
  const y1 = Math.min(height, Math.ceil(clamp01(roi.y + roi.h) * height));

  const roiW = x1 - x0;
  const roiH = y1 - y0;
  if (roiW <= 0 || roiH <= 0) return 0;

  // Choose an integer stride so the number of sampled pixels stays ~≤ maxSamples.
  const totalPixels = roiW * roiH;
  const stride = totalPixels > maxSamples ? Math.ceil(Math.sqrt(totalPixels / maxSamples)) : 1;

  let sum = 0;
  let count = 0;
  for (let y = y0; y < y1; y += stride) {
    const rowOffset = y * bytesPerRow;
    for (let x = x0; x < x1; x += stride) {
      const idx = rowOffset + x;
      if (idx < yPlane.length) {
        sum += yPlane[idx] as number;
        count++;
      }
    }
  }
  return count === 0 ? 0 : sum / count;
}

/**
 * Default eye regions for the on-screen reticle: two boxes in the upper-middle
 * band of the frame, matching how a cat's eyes sit when the animation fills the
 * scan area. The user aligns the reticle to the eyes; these are the starting
 * positions and the regions the sampler reads.
 */
export const DEFAULT_LEFT_EYE_ROI: NormalizedRoi = { x: 0.24, y: 0.2, w: 0.2, h: 0.18 };
export const DEFAULT_RIGHT_EYE_ROI: NormalizedRoi = { x: 0.56, y: 0.2, w: 0.2, h: 0.18 };
