/**
 * useCatBlinkSampler.ts — VisionCamera frame processor that samples the two
 * eye regions' brightness each frame and streams them to JS for decoding.
 *
 * This is the camera-facing half of Cat Mode live capture. It runs a worklet on
 * the frame-processor thread (throttled with runAtTargetFps), reads the mean
 * luminance of the left and right eye ROIs from the YUV Y-plane, and dispatches
 * a { t_ms, left, right } BrightnessSample to the JS thread via
 * react-native-worklets-core. The decoder (catBlinkDecoder) consumes that
 * stream.
 *
 * NOTE: the per-pixel mean loop below is inlined deliberately. A frame-processor
 * worklet cannot call an ordinary imported function across the thread boundary,
 * so the loop mirrors services/roiSampler.ts (roiMeanLuminance), which is the
 * unit-tested reference for this exact computation. Keep the two in sync.
 *
 * Requires a physical device + native build (react-native-worklets-core linked).
 * It is mocked in tests; the testable luminance math lives in roiSampler.ts.
 */

import { useEffect, useMemo, useRef } from 'react';
import { useFrameProcessor, runAtTargetFps, type Frame } from 'react-native-vision-camera';
import { Worklets } from 'react-native-worklets-core';
import type { BrightnessSample } from '../services/catBlinkDecoder';
import {
  DEFAULT_LEFT_EYE_ROI,
  DEFAULT_RIGHT_EYE_ROI,
  type NormalizedRoi,
} from '../services/roiSampler';

export interface UseCatBlinkSamplerOptions {
  /** Called on the JS thread with each throttled brightness sample. */
  onSample: (sample: BrightnessSample) => void;
  /** When false the frame processor is not attached (camera does no sampling). */
  enabled: boolean;
  /** Throttle rate for sampling, in samples/second (default 30). */
  sampleFps?: number;
  /**
   * Left/right eye ROIs in normalized [0,1] coords. Plain objects (NOT reanimated
   * shared values): VisionCamera frame processors run on the worklets-core
   * runtime, which cannot read reanimated shared values. The object is captured
   * into the worklet, so the frame processor re-creates when the ROI changes
   * (i.e. when the user commits a drag) — cheap and correct.
   */
  leftRoi?: NormalizedRoi;
  rightRoi?: NormalizedRoi;
  /** Soft cap on pixels read per ROI per frame (default 1024). */
  maxSamples?: number;
}

/**
 * Build a VisionCamera frame processor that emits eye-brightness samples.
 *
 * @returns A frame processor to pass to `<Camera frameProcessor={...} />`, or
 *          `undefined` when `enabled` is false.
 */
export function useCatBlinkSampler(
  options: UseCatBlinkSamplerOptions,
): ReturnType<typeof useFrameProcessor> | undefined {
  const {
    onSample,
    enabled,
    sampleFps = 30,
    leftRoi = DEFAULT_LEFT_EYE_ROI,
    rightRoi = DEFAULT_RIGHT_EYE_ROI,
    maxSamples = 1024,
  } = options;

  // Keep the latest onSample in a ref so the JS-bridge function stays stable.
  const onSampleRef = useRef(onSample);
  useEffect(() => {
    onSampleRef.current = onSample;
  }, [onSample]);

  // A worklet-callable function that hops back to the JS thread. Time-stamping
  // happens here (JS side) — sufficient for the decoder, whose period estimate
  // is robust to small per-sample jitter.
  const dispatch = useMemo(
    () =>
      Worklets.createRunOnJS((left: number, right: number) => {
        onSampleRef.current({ t_ms: Date.now(), left, right });
      }),
    [],
  );

  const frameProcessor = useFrameProcessor(
    (frame: Frame) => {
      'worklet';
      runAtTargetFps(sampleFps, () => {
        'worklet';
        // A throw inside a frame processor is otherwise fatal (it bubbles up as a
        // JS exception and crashes the app). Guard the whole body so an
        // unsupported pixel format / buffer access degrades to "no sample this
        // frame" instead of taking the app down.
        try {
        if (frame.pixelFormat !== 'yuv') return;
        const width = frame.width;
        const height = frame.height;
        const bytesPerRow = frame.bytesPerRow;
        if (width <= 0 || height <= 0 || bytesPerRow < width) return;
        const y = new Uint8Array(frame.toArrayBuffer());

        // Inlined mirror of services/roiSampler.ts → roiMeanLuminance.
        const meanLuminance = (roi: NormalizedRoi): number => {
          'worklet';
          const cx0 = Math.min(1, Math.max(0, roi.x));
          const cy0 = Math.min(1, Math.max(0, roi.y));
          const cx1 = Math.min(1, Math.max(0, roi.x + roi.w));
          const cy1 = Math.min(1, Math.max(0, roi.y + roi.h));
          const x0 = Math.floor(cx0 * width);
          const yy0 = Math.floor(cy0 * height);
          const x1 = Math.min(width, Math.ceil(cx1 * width));
          const yy1 = Math.min(height, Math.ceil(cy1 * height));
          const roiW = x1 - x0;
          const roiH = yy1 - yy0;
          if (roiW <= 0 || roiH <= 0) return 0;
          const totalPixels = roiW * roiH;
          const stride =
            totalPixels > maxSamples ? Math.ceil(Math.sqrt(totalPixels / maxSamples)) : 1;
          let sum = 0;
          let count = 0;
          for (let yi = yy0; yi < yy1; yi += stride) {
            const rowOffset = yi * bytesPerRow;
            for (let xi = x0; xi < x1; xi += stride) {
              const idx = rowOffset + xi;
              if (idx < y.length) {
                sum += y[idx] as number;
                count++;
              }
            }
          }
          return count === 0 ? 0 : sum / count;
        };

        const left = meanLuminance(leftRoi);
        const right = meanLuminance(rightRoi);
        dispatch(left, right);
        } catch {
          // Swallow per-frame errors — never crash the app from a worklet.
        }
      });
    },
    [dispatch, sampleFps, leftRoi, rightRoi, maxSamples],
  );

  return enabled ? frameProcessor : undefined;
}
