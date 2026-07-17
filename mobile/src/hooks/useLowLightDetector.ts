/** Measured zero-decode coaching for the QR capture screen. */

import { useEffect, useRef, useState } from 'react';
import { AccessibilityInfo } from 'react-native';
import {
  diagnoseZeroDecode,
  type ZeroDecodeDiagnosis,
} from '../services/captureDiagnostics';

export interface UseLowLightDetectorOptions {
  /** Current QR decode rate (frames/s). 0 when no codes are being scanned. */
  decodeRate: number;
  /** Mean sampled Y-plane luminance, 0-255, or null when no sample exists. */
  luminance: number | null;
  /** Accelerometer movement magnitude in m/s^2. */
  shakeMagnitude: number;
  /** Latest QR-to-scanner-frame size ratio, or null before a QR is decoded. */
  qrCoverage: number | null;
  /** Whether the detector should be active (e.g. only during CAPTURING). */
  active: boolean;
  /** Callback to display a CatToast hint. */
  showHint: (message: string) => void;
}

export function useLowLightDetector({
  decodeRate,
  luminance,
  shakeMagnitude,
  qrCoverage,
  active,
  showHint,
}: UseLowLightDetectorOptions): ZeroDecodeDiagnosis | null {
  const [diagnosis, setDiagnosis] = useState<ZeroDecodeDiagnosis | null>(null);
  const lowSinceRef = useRef<number | null>(null);
  const announcedReasonRef = useRef<ZeroDecodeDiagnosis['reason'] | null>(null);

  // Independent 1 s clock: with decodeRate pinned at 0 and static sensor
  // inputs, no dependency changes and the evaluation effect would otherwise
  // never re-run — the diagnosis could simply never fire.
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!active) return undefined;
    const interval = setInterval(() => setTick((t) => t + 1), 1_000);
    return () => clearInterval(interval);
  }, [active]);

  useEffect(() => {
    if (!active || decodeRate >= 0.1) {
      lowSinceRef.current = null;
      announcedReasonRef.current = null;
      setDiagnosis(null);
      return;
    }

    const now = Date.now();
    if (lowSinceRef.current === null) {
      lowSinceRef.current = now;
      return;
    }

    const nextDiagnosis = diagnoseZeroDecode({
      decodeRate,
      zeroDecodeMs: now - lowSinceRef.current,
      luminance,
      shakeMagnitude,
      qrCoverage,
    });
    // Keep the previous object when the reason is unchanged so memoized
    // consumers don't re-render at sensor rate.
    setDiagnosis((prev) =>
      prev?.reason === nextDiagnosis?.reason ? prev : nextDiagnosis,
    );
    if (nextDiagnosis && announcedReasonRef.current !== nextDiagnosis.reason) {
      announcedReasonRef.current = nextDiagnosis.reason;
      showHint(nextDiagnosis.message);
      AccessibilityInfo.announceForAccessibility(nextDiagnosis.message);
    }
  }, [decodeRate, luminance, shakeMagnitude, qrCoverage, active, showHint, tick]);

  return diagnosis;
}
