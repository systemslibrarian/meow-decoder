/**
 * useCameraHealthCheck.ts — Startup self-test for camera readiness.
 *
 * After the camera becomes active, this hook starts a countdown timer.
 * If no QR code is scanned within the timeout (default 3 s for AWAITING_GIF,
 * 8 s for CAPTURING), it surfaces a diagnostic hint to the user.
 *
 * Common causes of failure:
 *   - Camera permission revoked mid-session
 *   - Lens obstructed or device case covering camera
 *   - VisionCamera native module crash (rare but possible on older Android)
 *   - Phone camera hardware failure
 *
 * SECURITY: Read-only — no storage, no network. Only fires toasts.
 */

import { useEffect, useRef } from 'react';
import { AccessibilityInfo } from 'react-native';
import type { CaptureState } from '../types/capture';

export interface UseCameraHealthCheckOptions {
  /** Current capture status */
  status: CaptureState;
  /** Number of QR codes scanned so far */
  capturedCount: number;
  /** Callback to display a warning hint */
  showHint: (message: string) => void;
  /** Timeout in ms before firing the check (default: 3000) */
  timeoutMs?: number;
}

export function useCameraHealthCheck({
  status,
  capturedCount,
  showHint,
  timeoutMs = 3_000,
}: UseCameraHealthCheckOptions): void {
  const firedRef = useRef(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    // Only run during the initial AWAITING_GIF phase
    if (status !== 'AWAITING_GIF') {
      // Reset when leaving the check-relevant status
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      return;
    }

    // Don't fire again if already warned or if frames have been captured
    if (firedRef.current || capturedCount > 0) {
      return;
    }

    timerRef.current = setTimeout(() => {
      // Re-check: if frames arrived during the timeout, skip
      if (firedRef.current || capturedCount > 0) return;

      firedRef.current = true;
      showHint(
        '📷 Camera not detecting QR codes — check that:\n' +
        '• Camera lens is unobstructed\n' +
        '• Phone is pointed at the QR code\n' +
        '• Screen brightness is turned up'
      );
      AccessibilityInfo.announceForAccessibility(
        'Camera health check: no QR codes detected. Ensure the camera is pointed at the QR code and the lens is not covered.'
      );
    }, timeoutMs);

    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [status, capturedCount, showHint, timeoutMs]);

  // Reset the fired flag when a new session starts
  useEffect(() => {
    if (status === 'IDLE') {
      firedRef.current = false;
    }
  }, [status]);
}
