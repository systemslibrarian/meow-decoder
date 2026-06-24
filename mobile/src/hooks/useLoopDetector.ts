/**
 * useLoopDetector.ts — Detects when a looping QR animation has completed a
 * full pass, and whether the loop is still yielding new frames.
 *
 * The desktop sender shows an animated QR (a "yarn ball") that plays its
 * frames in a repeating loop. The receiver has no out-of-band signal for when
 * one full cycle has elapsed — it only sees a stream of decoded frame indices.
 *
 * This hook reconstructs that signal from the index stream alone:
 *
 *   • Within a single pass of the animation, each frame index appears at most
 *     once. The first time we re-observe an index we have already seen this
 *     pass, the loop must have wrapped around → one loop completed.
 *
 *   • Dropped frames (camera blur, glare) simply never enter the pass set, so
 *     wrap detection is robust to loss — it keys off repeats, not gaps.
 *
 *   • We track how many *new* distinct indices each pass discovered. Once a
 *     full pass completes having discovered nothing new, the animation has
 *     nothing left to give: `exhausted` flips true. That is the honest signal
 *     for "you have seen the whole loop — more scanning will not help."
 *
 * This works identically for standard QR and cat-*carrier* QR (both emit real
 * QR codes); only the brightness-coded blinking-eye variant needs a separate
 * decoder.
 *
 * SECURITY: only integer frame indices are observed here — never payload data.
 */

import { useCallback, useRef, useState } from 'react';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface LoopDetectorState {
  /** Number of full animation loops observed since the last reset. */
  loopsCompleted: number;
  /** Distinct frame indices discovered during the most recently completed loop. */
  lastLoopNewFrames: number;
  /**
   * True once a full loop has completed without discovering any new frame
   * index — i.e. the animation has been seen in its entirety and further
   * scanning yields only repeats. If the capture is not yet recoverable at
   * this point, frames are being physically missed (focus/glare/too fast).
   */
  exhausted: boolean;
}

export interface UseLoopDetectorReturn extends LoopDetectorState {
  /** Feed every parsed frame index here — including repeats. */
  observe: (index: number) => void;
  /** Clear all loop state for a fresh session. */
  reset: () => void;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

const INITIAL: LoopDetectorState = {
  loopsCompleted: 0,
  lastLoopNewFrames: 0,
  exhausted: false,
};

export function useLoopDetector(): UseLoopDetectorReturn {
  // Distinct indices ever seen (across all passes).
  const allSeenRef = useRef<Set<number>>(new Set());
  // Distinct indices seen in the current (in-progress) pass.
  const passSeenRef = useRef<Set<number>>(new Set());
  // Count of indices in the current pass that were never seen in a prior pass.
  const passNewRef = useRef<number>(0);

  const [state, setState] = useState<LoopDetectorState>(INITIAL);

  const observe = useCallback((index: number) => {
    if (!Number.isFinite(index)) return;

    const pass = passSeenRef.current;

    if (pass.has(index)) {
      // ── Wrap detected: the animation looped back to a frame seen this pass.
      const newThisLoop = passNewRef.current;
      // Seed the next pass with the wrapping index (already in allSeen, so it
      // contributes zero new frames to the fresh pass).
      passSeenRef.current = new Set<number>([index]);
      passNewRef.current = 0;
      setState((prev) => ({
        loopsCompleted: prev.loopsCompleted + 1,
        lastLoopNewFrames: newThisLoop,
        // Once exhausted, stay exhausted — a later stray new frame is noise.
        exhausted: prev.exhausted || newThisLoop === 0,
      }));
      return;
    }

    pass.add(index);
    if (!allSeenRef.current.has(index)) {
      allSeenRef.current.add(index);
      passNewRef.current += 1;
    }
  }, []);

  const reset = useCallback(() => {
    allSeenRef.current = new Set();
    passSeenRef.current = new Set();
    passNewRef.current = 0;
    setState(INITIAL);
  }, []);

  return { ...state, observe, reset };
}
