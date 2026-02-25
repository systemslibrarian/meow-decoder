/**
 * useQRScanner.ts — Vision Camera v4 native code scanner.
 *
 * Uses VisionCamera v4's first-class `useCodeScanner` hook which drives
 * native MLKit (Android) / AVFoundation (iOS) directly. The callback fires
 * on the JS thread — no worklet bridge required.
 *
 * This replaces the abandoned `vision-camera-code-scanner` v0.2 worklet
 * approach, which used an inline require() inside a worklet — fragile,
 * unmaintained, and silently broken on Android 14+ / iOS 17+ targets.
 *
 * SECURITY: Only decoded string values are processed — no image data ever
 * leaves the camera frame. Non-meow-protocol QR codes are dropped immediately.
 */

import { useCallback, useRef, useState, useEffect } from 'react';
import { useCodeScanner, type CodeScanner } from 'react-native-vision-camera';
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
  /** Called when animated GIF pattern is detected */
  onGifDetected: () => void;
  /** Pause scanning without unmounting the component */
  enabled: boolean;
}

export interface UseQRScannerReturn {
  /** Pass directly to <Camera codeScanner={...} /> */
  codeScanner: CodeScanner;
  /** Fresh unique droplets decoded per second (rolling 3-second window) */
  decodeRate: number;
  /** Fraction of all QR scans that were duplicates in the rolling window (0–1) */
  duplicateRate: number;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useQRScanner({
  sessionId,
  onFrame,
  onGifDetected,
  enabled,
}: UseQRScannerOptions): UseQRScannerReturn {
  const lastScannedRef = useRef<string>('');
  const lastTimestampRef = useRef<number>(0);
  const recentCodesRef = useRef<Array<{ value: string; time: number }>>([]);
  const gifDetectedRef = useRef<boolean>(false);

  // ── Decode-rate tracking ─────────────────────────────────────────────────
  // Ring buffers: timestamps of all QR callbacks vs fresh (non-dup) frames.
  // Updated inside the hot scan callback; rates computed in a 1 Hz interval.
  const freshTimestampsRef = useRef<number[]>([]);
  const allScanTimestampsRef = useRef<number[]>([]);
  const [decodeRate, setDecodeRate] = useState(0);
  const [duplicateRate, setDuplicateRate] = useState(0);

  const RATE_WINDOW_MS = 3000; // rolling window for rate calculation

  useEffect(() => {
    if (!enabled) {
      setDecodeRate(0);
      setDuplicateRate(0);
      return;
    }
    const interval = setInterval(() => {
      const now = Date.now();
      const cutoff = now - RATE_WINDOW_MS;
      const fresh = freshTimestampsRef.current.filter((t) => t >= cutoff);
      const all = allScanTimestampsRef.current.filter((t) => t >= cutoff);
      // Prune
      freshTimestampsRef.current = fresh;
      allScanTimestampsRef.current = all;
      setDecodeRate(fresh.length / (RATE_WINDOW_MS / 1000));
      setDuplicateRate(all.length > 0 ? 1 - fresh.length / all.length : 0);
    }, 1000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  const codeScanner = useCodeScanner({
    codeTypes: ['qr'],

    onCodeScanned: useCallback(
      (codes) => {
        if (!enabled) return;

        const qrData = codes[0]?.value;
        if (!qrData || qrData.length === 0) return;

        const now = Date.now();
        // ── Dedup: skip identical payload within the dedup window ───────────
        if (
          qrData === lastScannedRef.current &&
          now - lastTimestampRef.current < QR_DEDUP_INTERVAL_MS
        ) {
          // Still counts as a scan for duplicate-rate — same frame seen again
          allScanTimestampsRef.current.push(now);
          return;
        }

        lastScannedRef.current = qrData;
        lastTimestampRef.current = now;

        // ── Fast prefix filter — discard non-meow QR codes immediately ──────
        // IMPORTANT: keep in sync with QR_PREFIXES in qrDecoder.ts and
        // isMeowQRPayload(). Any new prefix added there must be added here too.
        const isMeow =
          qrData.startsWith('FOUNTAIN:') ||
          qrData.startsWith('MEOW:') ||
          qrData.startsWith('FS:') ||
          qrData.startsWith('QUANTUM:') ||
          qrData.startsWith('HYBRID-PQ:') ||
          qrData.startsWith('DURESS:') ||    // single-frame duress
          qrData.startsWith('DURESS-') ||    // legacy chunked large-duress
          qrData.startsWith('MEOW-') ||      // legacy chunked large-MEOW
          qrData.startsWith('{');            // JSON bridge / CLI session mode

        if (!isMeow) return;

        // Only count meow QR events toward duplicate-rate tracking so that
        // accidentally-scanned non-meow codes don't inflate the metric.
        allScanTimestampsRef.current.push(now);

        // ── GIF auto-detection heuristic ─────────────────────────────────────
        if (!gifDetectedRef.current) {
          const isSingleFrame =
            qrData.startsWith('MEOW:') ||
            qrData.startsWith('FS:') ||
            qrData.startsWith('QUANTUM:') ||
            qrData.startsWith('HYBRID-PQ:') ||
            qrData.startsWith('DURESS:');

          if (isSingleFrame) {
            gifDetectedRef.current = true;
            onGifDetected();
          } else {
            const recent = recentCodesRef.current;
            const cutoff = now - GIF_DETECT_WINDOW_MS;
            const fresh = recent.filter((r) => r.time >= cutoff);
            if (!fresh.some((r) => r.value === qrData)) {
              fresh.push({ value: qrData, time: now });
            }
            recentCodesRef.current = fresh;

            const uniqueCount = new Set(fresh.map((e) => e.value)).size;
            if (uniqueCount >= GIF_DETECT_MIN_UNIQUE) {
              gifDetectedRef.current = true;
              recentCodesRef.current = [];
              onGifDetected();
            }
          }
        }

        // ── Parse + dispatch frame to capture state machine ──────────────────
        const payload = parseQRPayload(qrData, sessionId);
        if (!payload) return;

        // Count this as a fresh decoded frame for rate tracking
        freshTimestampsRef.current.push(now);

        onFrame({
          index: payload.index,
          data: payload.data,
          timestamp_ms: now,
        });
      },
      // eslint-disable-next-line react-hooks/exhaustive-deps
      [enabled, sessionId, onFrame, onGifDetected],
    ),
  });

  return { codeScanner, decodeRate, duplicateRate };
}
