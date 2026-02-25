/**
 * useStallDetector.ts — Detects when a CAPTURING session stops receiving frames.
 *
 * If `frameCount` does not increase for STALL_DETECT_MS milliseconds during
 * an active capture, the `isStalled` flag becomes true and the optional
 * `onStall` callback fires once per stall event (not on every tick).
 *
 * The stall is cleared the moment a new frame arrives.
 *
 * Usage:
 *   const { isStalled } = useStallDetector({
 *     frameCount: progress?.captured ?? 0,
 *     active: status === 'CAPTURING',
 *     onStall: () => showToast({ message: 'No new frames — move camera' }),
 *   });
 */

import { useState, useEffect, useRef } from 'react';
import { STALL_DETECT_MS } from '../constants/config';

// ── Types ─────────────────────────────────────────────────────────────────────

interface UseStallDetectorOptions {
  /** Current frame count. Stall triggers when this stops increasing. */
  frameCount: number;
  /** Whether the session is actively capturing (hook is a no-op when false). */
  active: boolean;
  /** Called once when a stall is first detected. */
  onStall?: () => void;
  /** Custom threshold in ms — defaults to STALL_DETECT_MS (5 000 ms). */
  stallMs?: number;
}

interface UseStallDetectorReturn {
  /** True when no new frame has arrived for stallMs during an active session. */
  isStalled: boolean;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useStallDetector({
  frameCount,
  active,
  onStall,
  stallMs = STALL_DETECT_MS,
}: UseStallDetectorOptions): UseStallDetectorReturn {
  const [isStalled, setIsStalled] = useState(false);
  const lastFrameCountRef = useRef(frameCount);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Track whether we've already fired onStall for the current stall event
  const stalledFiredRef = useRef(false);

  useEffect(() => {
    // Clear stall if no longer actively capturing
    if (!active) {
      setIsStalled(false);
      stalledFiredRef.current = false;
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      return;
    }

    if (frameCount !== lastFrameCountRef.current) {
      // New frame arrived — reset stall state
      lastFrameCountRef.current = frameCount;
      setIsStalled(false);
      stalledFiredRef.current = false;
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    }

    // Arm the stall timer if not already running
    if (timerRef.current === null) {
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        setIsStalled(true);
        if (!stalledFiredRef.current) {
          stalledFiredRef.current = true;
          onStall?.();
        }
      }, stallMs);
    }

    return () => {
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [frameCount, active, onStall, stallMs]);

  return { isStalled };
}
