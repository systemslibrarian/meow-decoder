/**
 * useQRScanner.ts — Vision Camera frame processor for QR detection.
 *
 * Processes camera frames on the worklet thread (never the JS thread),
 * extracts QR payloads, validates them as meow-decoder frames, and
 * dispatches to the capture state machine.
 *
 * Includes a GIF auto-detection heuristic: when 3+ distinct QR codes
 * are detected within a 500ms window, we infer the source is an animated
 * GIF and call onGifDetected().
 *
 * SECURITY: The worklet never stores frame image data. Only the decoded
 * string value is passed to the JS thread, and only after validation.
 */

import { useCallback, useRef } from 'react';
import { useFrameProcessor } from 'react-native-vision-camera';
import { Worklets } from 'react-native-worklets-core';
import type { CapturedFrame } from '../types/capture';
import { parseQRPayload } from '../services/qrDecoder';
import {
  QR_DEDUP_INTERVAL_MS,
  GIF_DETECT_WINDOW_MS,
  GIF_DETECT_MIN_UNIQUE,
} from '../constants/config';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface UseQRScannerOptions {
  /** Session ID used to validate frame ownership (optional — skip check if absent) */
  sessionId?: string;
  /** Called with each newly discovered frame (not duplicates) */
  onFrame: (frame: CapturedFrame) => void;
  /** Called when animated GIF pattern detected */
  onGifDetected: () => void;
  /** Pause/resume scanning without unmounting the frame processor */
  enabled: boolean;
}

export interface UseQRScannerReturn {
  /** Attach to Camera component's frameProcessor prop */
  frameProcessor: ReturnType<typeof useFrameProcessor>;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useQRScanner({
  sessionId,
  onFrame,
  onGifDetected,
  enabled,
}: UseQRScannerOptions): UseQRScannerReturn {
  // Refs are accessible in worklets via .value pattern
  const lastScannedRef = useRef<string>('');
  const lastTimestampRef = useRef<number>(0);
  const recentCodesRef = useRef<Array<{ value: string; time: number }>>([]);
  const gifDetectedRef = useRef<boolean>(false);

  // Worklet-safe callbacks (bridge JS thread ↔ worklet thread)
  const handleFrameJS = Worklets.createRunInJsFn(
    useCallback(
      (qrValue: string, timestamp: number) => {
        const payload = parseQRPayload(qrValue, sessionId);
        if (!payload) return;

        onFrame({
          index: payload.index,
          data: payload.data,
          timestamp_ms: timestamp,
        });
      },
      [sessionId, onFrame],
    ),
  );

  const handleGifDetectedJS = Worklets.createRunInJsFn(
    useCallback(() => {
      if (!gifDetectedRef.current) {
        gifDetectedRef.current = true;
        onGifDetected();
      }
    }, [onGifDetected]),
  );

  const frameProcessor = useFrameProcessor(
    (frame) => {
      'worklet';
      if (!enabled) return;

      // Import scanCodes inline — worklets can't use module-level imports
      // from non-worklet packages. The camera barcode scanner plugin wraps
      // this for us when using vision-camera-code-scanner or @mgcrea variant.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { scanCodes } = require('vision-camera-code-scanner') as any;
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call
      const codes: Array<{ value?: string }> = scanCodes(frame, { types: ['qr'] });
      if (!codes || codes.length === 0) return;

      const now = Date.now();
      const qrData = codes[0]?.value;
      if (!qrData || qrData.length === 0) return;

      // Skip rapid-fire identical content within dedup interval
      if (
        qrData === lastScannedRef.current &&
        now - lastTimestampRef.current < QR_DEDUP_INTERVAL_MS
      ) {
        return;
      }

      lastScannedRef.current = qrData;
      lastTimestampRef.current = now;

      // ── GIF auto-detection heuristic ─────────────────────────────────────
      if (!gifDetectedRef.current) {
        const recent = recentCodesRef.current;
        recent.push({ value: qrData, time: now });
        // Evict entries older than the detection window
        const cutoff = now - GIF_DETECT_WINDOW_MS;
        recentCodesRef.current = recent.filter((e) => e.time >= cutoff);

        const uniqueCount = new Set(recentCodesRef.current.map((e) => e.value))
          .size;
        if (uniqueCount >= GIF_DETECT_MIN_UNIQUE) {
          handleGifDetectedJS();
        }
      }

      // ── Dispatch to JS thread ─────────────────────────────────────────────
      handleFrameJS(qrData, now);
    },
    [enabled, handleFrameJS, handleGifDetectedJS],
  );

  return { frameProcessor };
}
