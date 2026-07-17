/** Low-cost camera frame count and luminance metrics for capture guidance. */

import { useEffect, useMemo, useState } from 'react';
import {
  runAtTargetFps,
  useFrameProcessor,
  type Frame,
  type ReadonlyFrameProcessor,
} from 'react-native-vision-camera';
import { Worklets } from 'react-native-worklets-core';

export interface CaptureFrameMetrics {
  frameProcessor: ReadonlyFrameProcessor | undefined;
  /** Camera frames sampled by this diagnostics processor. */
  framesSeen: number;
  /** Mean Y-plane luminance, 0-255. */
  luminance: number;
}

interface UseCaptureFrameMetricsOptions {
  enabled: boolean;
  sampleFps?: number;
  maxSamples?: number;
}

export function useCaptureFrameMetrics({
  enabled,
  sampleFps = 5,
  maxSamples = 512,
}: UseCaptureFrameMetricsOptions): CaptureFrameMetrics {
  const [framesSeen, setFramesSeen] = useState(0);
  const [luminance, setLuminance] = useState(0);

  useEffect(() => {
    if (!enabled) {
      setFramesSeen(0);
      setLuminance(0);
    }
  }, [enabled]);

  const dispatch = useMemo(
    () =>
      Worklets.createRunOnJS((meanLuminance: number) => {
        setFramesSeen((count) => count + 1);
        setLuminance(meanLuminance);
      }),
    [],
  );

  const frameProcessor = useFrameProcessor(
    (frame: Frame) => {
      'worklet';
      runAtTargetFps(sampleFps, () => {
        'worklet';
        try {
          if (frame.pixelFormat !== 'yuv') return;
          const width = frame.width;
          const height = frame.height;
          const bytesPerRow = frame.bytesPerRow;
          if (width <= 0 || height <= 0 || bytesPerRow < width) return;

          const yPlane = new Uint8Array(frame.toArrayBuffer());
          const stride = Math.max(1, Math.ceil(Math.sqrt((width * height) / maxSamples)));
          let sum = 0;
          let count = 0;
          for (let y = 0; y < height; y += stride) {
            const rowOffset = y * bytesPerRow;
            for (let x = 0; x < width; x += stride) {
              const index = rowOffset + x;
              if (index < yPlane.length) {
                sum += yPlane[index] as number;
                count += 1;
              }
            }
          }
          if (count > 0) dispatch(sum / count);
        } catch {
          // Camera diagnostics must never interrupt QR capture.
        }
      });
    },
    [dispatch, sampleFps, maxSamples],
  );

  return {
    frameProcessor: enabled ? frameProcessor : undefined,
    framesSeen,
    luminance,
  };
}
