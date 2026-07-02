/**
 * useLowLightDetector.ts — Proactive "not decoding" coaching.
 *
 * NOTE: this hook has no light sensor. It infers trouble purely from a sustained
 * low DECODE RATE — the camera is not recovering QR frames. That can be glare,
 * over-exposure, blur/focus, or framing just as easily as genuine dimness, so
 * the hints must not assume "too dark."
 *
 * IMPORTANT (decode regression fixed 2026-06): an earlier version auto-RAISED
 * exposure +0.5 EV and suggested the torch whenever decode rate hit 0. When
 * scanning a bright emissive screen the failure is almost always glare/over-
 * exposure, so brightening (and torch reflections) washed the QR out further and
 * kept decode rate pinned at 0 — a self-reinforcing stall. We no longer change
 * exposure automatically; the hints now point the user at the likely real cause
 * (framing/focus/glare) and let them adjust ☀±/torch manually.
 *
 * Monitors decode rate, exposure bias, and torch state and surfaces graduated
 * coaching hints through CatToast:
 *
 *   Stage 1 (2 s):  "Not decoding — fill the frame with the QR, hold in focus"
 *   Stage 2 (4 s):  "Too bright? ☀− to cut glare. Too dim? ☀+"
 *   Stage 3 (6 s):  "Avoid screen reflections / glare hotspots"
 *   Stage 4 (10 s): "Move 10 cm closer" final fallback
 *
 * Resets whenever decode rate recovers above threshold.
 *
 * SECURITY: Read-only hook — no side effects beyond toast display. No automatic
 * camera changes, no network, no storage.
 */

import { useEffect, useRef } from 'react';
import { AccessibilityInfo } from 'react-native';
import {
  LOW_LIGHT_RATE_THRESHOLD,
  LOW_LIGHT_DETECT_DELAY_MS,
} from '../constants/config';

export interface UseLowLightDetectorOptions {
  /** Current QR decode rate (frames/s). 0 when no codes are being scanned. */
  decodeRate: number;
  /** Current exposure bias from CameraPreview (EV). Typically -1..+1. */
  exposureBias: number;
  /** Whether the torch is currently active. */
  torchOn: boolean;
  /** Whether the detector should be active (e.g. only during CAPTURING). */
  active: boolean;
  /** Callback to display a CatToast hint. */
  showHint: (message: string) => void;
}

/**
 * Coaching stages. Each fires at most once per continuous low-decode period;
 * recovering above the rate threshold resets all stages. (HINT_EXPOSURE is the
 * old AUTO_NUDGE stage — it now only shows a bidirectional exposure hint and
 * never changes the camera.)
 */
const enum LowLightStage {
  OK = 0,
  HINT_FRAMING = 1,
  HINT_EXPOSURE = 2,
  HINT_GLARE = 3,
  HINT_CLOSER = 4,
}

export function useLowLightDetector({
  decodeRate,
  exposureBias,
  torchOn,
  active,
  showHint,
}: UseLowLightDetectorOptions): void {
  const stageRef = useRef<LowLightStage>(LowLightStage.OK);
  const lowSinceRef = useRef<number | null>(null);

  useEffect(() => {
    if (!active) {
      // Reset when not actively capturing
      stageRef.current = LowLightStage.OK;
      lowSinceRef.current = null;
      return;
    }

    // Decode rate recovered — reset everything
    if (decodeRate >= LOW_LIGHT_RATE_THRESHOLD) {
      stageRef.current = LowLightStage.OK;
      lowSinceRef.current = null;
      return;
    }

    // Start counting low-light time
    const now = Date.now();
    if (lowSinceRef.current === null) {
      lowSinceRef.current = now;
      return;
    }

    const elapsed = now - lowSinceRef.current;

    // Stage 1: after initial delay — the camera isn't recovering frames. Most
    // common fixes are framing and focus, not lighting.
    if (stageRef.current < LowLightStage.HINT_FRAMING && elapsed >= LOW_LIGHT_DETECT_DELAY_MS) {
      stageRef.current = LowLightStage.HINT_FRAMING;
      showHint('🔍 Not decoding — fill the frame with the QR and hold it in focus');
      AccessibilityInfo.announceForAccessibility('Not decoding. Fill the frame with the QR code and hold the phone steady so it can focus.');
    }

    // Stage 2: exposure is bidirectional — for a bright screen, glare/over-
    // exposure is the usual culprit, so suggest BOTH directions rather than
    // blindly brightening (and never change exposure automatically).
    if (stageRef.current < LowLightStage.HINT_EXPOSURE && elapsed >= LOW_LIGHT_DETECT_DELAY_MS * 2) {
      stageRef.current = LowLightStage.HINT_EXPOSURE;
      showHint('☀ Too bright? tap ☀− to cut glare. Too dim? tap ☀+');
      AccessibilityInfo.announceForAccessibility('Adjust exposure. If the screen looks washed out, decrease exposure to reduce glare. If it looks dim, increase exposure.');
    }

    // Stage 3: glare on an emissive screen — torch makes screen reflections
    // worse, so steer toward removing reflections instead of adding light.
    if (stageRef.current < LowLightStage.HINT_GLARE && elapsed >= LOW_LIGHT_DETECT_DELAY_MS * 3 && !torchOn) {
      stageRef.current = LowLightStage.HINT_GLARE;
      showHint('✨ Tilt slightly to clear screen glare / reflections');
      AccessibilityInfo.announceForAccessibility('Tilt the phone slightly to move reflections off the QR code.');
    }

    // Stage 4: move closer
    if (stageRef.current < LowLightStage.HINT_CLOSER && elapsed >= LOW_LIGHT_DETECT_DELAY_MS * 5) {
      stageRef.current = LowLightStage.HINT_CLOSER;
      showHint('📐 Move 10 cm closer to the screen');
      AccessibilityInfo.announceForAccessibility('Move the phone closer to the screen.');
    }
  }, [decodeRate, exposureBias, torchOn, active, showHint]);
}
