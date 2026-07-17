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
  /** Mean sampled Y-plane luminance, 0-255. */
  luminance: number;
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
    setDiagnosis(nextDiagnosis);
    if (nextDiagnosis && announcedReasonRef.current !== nextDiagnosis.reason) {
      announcedReasonRef.current = nextDiagnosis.reason;
      showHint(nextDiagnosis.message);
      AccessibilityInfo.announceForAccessibility(nextDiagnosis.message);
    }
  }, [decodeRate, luminance, shakeMagnitude, qrCoverage, active, showHint]);

  return diagnosis;
}
