/**
 * useLowLightDetector.ts — Proactive low-light / glare auto-nudge.
 *
 * Monitors decode rate, exposure bias, and torch state. When the decode rate
 * drops below a threshold for a sustained period, surfaces graduated coaching
 * hints through CatToast:
 *
 *   Stage 1 (2 s):  "Low light — try increasing exposure (☀️+)"
 *   Stage 2 (4 s):  Auto-nudge exposure +0.5 EV
 *   Stage 3 (6 s):  "Turn on torch 🔦" suggestion
 *   Stage 4 (10 s): "Move 10 cm closer" final fallback
 *
 * Resets whenever decode rate recovers above threshold.
 *
 * SECURITY: Read-only hook — no side effects beyond toast display and optional
 * exposure nudge callback. No network, no storage.
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
  /** Optional callback to imperatively nudge exposure by ΔEV. */
  nudgeExposure?: (delta: number) => void;
}

/**
 * Stages of low-light auto-nudge. Each stage fires at most once per
 * continuous low-light period. Recovering resets all stages.
 */
const enum LowLightStage {
  OK = 0,
  HINT_EXPOSURE = 1,
  AUTO_NUDGE = 2,
  HINT_TORCH = 3,
  HINT_CLOSER = 4,
}

export function useLowLightDetector({
  decodeRate,
  exposureBias,
  torchOn,
  active,
  showHint,
  nudgeExposure,
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

    // Stage 1: after initial delay — hint to increase exposure
    if (stageRef.current < LowLightStage.HINT_EXPOSURE && elapsed >= LOW_LIGHT_DETECT_DELAY_MS) {
      stageRef.current = LowLightStage.HINT_EXPOSURE;
      showHint('🌙 Low decode rate — try ☀️+ to brighten');
      AccessibilityInfo.announceForAccessibility('Low decode rate detected. Try increasing exposure.');
    }

    // Stage 2: auto-nudge exposure up half a stop
    if (stageRef.current < LowLightStage.AUTO_NUDGE && elapsed >= LOW_LIGHT_DETECT_DELAY_MS * 2) {
      stageRef.current = LowLightStage.AUTO_NUDGE;
      nudgeExposure?.(0.5);
      showHint('✨ Auto-brightened +0.5 EV');
      AccessibilityInfo.announceForAccessibility('Exposure automatically increased.');
    }

    // Stage 3: suggest torch
    if (stageRef.current < LowLightStage.HINT_TORCH && elapsed >= LOW_LIGHT_DETECT_DELAY_MS * 3 && !torchOn) {
      stageRef.current = LowLightStage.HINT_TORCH;
      showHint('🔦 Try turning on the torch');
      AccessibilityInfo.announceForAccessibility('Try turning on the torch for better visibility.');
    }

    // Stage 4: move closer
    if (stageRef.current < LowLightStage.HINT_CLOSER && elapsed >= LOW_LIGHT_DETECT_DELAY_MS * 5) {
      stageRef.current = LowLightStage.HINT_CLOSER;
      showHint('📐 Move 10 cm closer to the screen');
      AccessibilityInfo.announceForAccessibility('Move the phone closer to the screen.');
    }
  }, [decodeRate, exposureBias, torchOn, active, showHint, nudgeExposure]);
}
