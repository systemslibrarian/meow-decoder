/**
 * useSessionManager.ts — High-level session orchestration.
 *
 * Wraps useCapture, useQRScanner, and useStabilityMonitor into a single
 * convenience hook for the CaptureScreen. Manages milestone notifications,
 * memory pressure warnings, and elapsed time tracking.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import type { CaptureRequest, CaptureResponse, CaptureProgress } from '../types/capture';
import { useCapture } from './useCapture';
import { useQRScanner } from './useQRScanner';
import { useStabilityMonitor } from './useStabilityMonitor';
import { MILESTONE_THRESHOLDS, FOUNTAIN_OVERHEAD, MEMORY_WARN_FRAME_COUNT } from '../constants/config';
import type { MilestoneThreshold } from '../constants/config';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface SessionManagerReturn {
  // State
  status: ReturnType<typeof useCapture>['state']['status'];
  progress: CaptureProgress | null;
  error: string | null;
  elapsedMs: number;
  remainingMs: number | null;
  /** Raw count of captured frames (for stall detection) */
  capturedCount: number;
  /** Fresh decoded droplets per second (rolling 3 s window) */
  decodeRate: number;
  /** Fraction of all QR scans that were duplicates (0–1) */
  duplicateRate: number;
  // Stability
  isStable: boolean;
  shakeMagnitude: number;
  // Memory
  isNearMemoryLimit: boolean;
  // Milestones
  lastMilestone: MilestoneThreshold | null;
  // Actions
  loadRequest: (req: CaptureRequest) => void;
  stop: () => void;
  cancel: () => void;
  pause: () => void;
  resume: () => void;
  markExporting: () => void;
  buildResponse: () => CaptureResponse | null;
  // Code scanner for Camera component (VisionCamera v4 native API)
  codeScanner: ReturnType<typeof useQRScanner>['codeScanner'];
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useSessionManager(): SessionManagerReturn {
  const {
    state,
    progress,
    loadRequest,
    onFrameScanned,
    onGifDetected,
    stop,
    cancel,
    pause,
    resume,
    markExporting,
    buildResponse,
  } = useCapture();

  const { isStable, shakeMagnitude } = useStabilityMonitor();

  const { codeScanner, decodeRate, duplicateRate } = useQRScanner({
    // exactOptionalPropertyTypes: only pass sessionId when it is a string,
    // never pass the property as `undefined` (that would fail the strict check).
    ...(state.request?.session_id !== undefined
      ? { sessionId: state.request.session_id }
      : {}),
    onFrame: onFrameScanned,
    onGifDetected,
    // Disable scanner when paused so the UI thread isn't processing frames.
    enabled: state.status === 'AWAITING_GIF' || state.status === 'CAPTURING',
  });

  // ── Elapsed time ticker ───────────────────────────────────────────────────
  const [elapsedMs, setElapsedMs] = useState(0);
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // Timestamp of the most recent CAPTURING period start (null when not capturing).
  // Resets on every transition TO CAPTURING so remainingMs mirrors the timeout
  // timer in useCapture, which also resets to the full timeout on each resume.
  const [captureRestartedAt, setCaptureRestartedAt] = useState<number | null>(null);

  useEffect(() => {
    if (state.status === 'CAPTURING' && state.startedAt !== null) {
      // Record when this CAPTURING burst began (fresh on every resume).
      setCaptureRestartedAt(Date.now());
      tickRef.current = setInterval(() => {
        setElapsedMs(Date.now() - (state.startedAt ?? Date.now()));
      }, 1_000);
    } else {
      if (tickRef.current !== null) {
        clearInterval(tickRef.current);
        tickRef.current = null;
      }
      // Always reset the restart anchor when not CAPTURING so the next
      // CAPTURING entry (first start or resume) gets a fresh timestamp.
      // This mirrors the setTimeout reset in useCapture on every CAPTURING entry.
      setCaptureRestartedAt(null);
      if (state.status === 'IDLE' || state.status === 'AWAITING_GIF') {
        setElapsedMs(0);
      }
    }
    return () => {
      if (tickRef.current !== null) clearInterval(tickRef.current);
    };
  }, [state.status, state.startedAt]);

  // ── Remaining time ─────────────────────────────────────────────────────────
  // Use captureRestartedAt (not startedAt) as the countdown reference so that
  // a pause + resume correctly resets the countdown to the full timeout_seconds,
  // matching the setTimeout reset in useCapture on every CAPTURING entry.
  const remainingMs =
    state.request?.timeout_seconds != null && captureRestartedAt !== null
      ? Math.max(0, state.request.timeout_seconds * 1_000 - (Date.now() - captureRestartedAt))
      : state.request?.timeout_seconds != null
        ? Math.max(0, state.request.timeout_seconds * 1_000 - elapsedMs)
        : null;

  // ── Memory pressure detection ──────────────────────────────────────────────
  const isNearMemoryLimit = state.frames.size >= MEMORY_WARN_FRAME_COUNT;

  // ── Milestone tracking ─────────────────────────────────────────────────────
  const [lastMilestone, setLastMilestone] = useState<MilestoneThreshold | null>(null);
  const firedMilestonesRef = useRef<Set<MilestoneThreshold>>(new Set());

  useEffect(() => {
    if (
      !progress ||
      state.status !== 'CAPTURING'
    ) return;

    const fraction =
      progress.captured /
      Math.ceil((state.request?.expected_frames ?? 1) * FOUNTAIN_OVERHEAD);

    for (const threshold of MILESTONE_THRESHOLDS) {
      if (
        fraction >= threshold &&
        !firedMilestonesRef.current.has(threshold)
      ) {
        firedMilestonesRef.current.add(threshold);
        setLastMilestone(threshold);
      }
    }
  }, [progress, state.status, state.request]);

  // Reset milestones on new session
  useEffect(() => {
    if (state.status === 'IDLE' || state.status === 'AWAITING_GIF') {
      firedMilestonesRef.current.clear();
      setLastMilestone(null);
    }
  }, [state.status]);

  const buildResponseWrapper = useCallback(
    () => buildResponse(),
    [buildResponse],
  );

  return {
    status: state.status,
    progress,
    error: state.error,
    elapsedMs,
    remainingMs,
    capturedCount: state.frames.size,
    decodeRate,
    duplicateRate,
    isStable,
    shakeMagnitude,
    isNearMemoryLimit,
    lastMilestone,
    loadRequest,
    stop,
    cancel,
    pause,
    resume,
    markExporting,
    buildResponse: buildResponseWrapper,
    codeScanner,
  };
}
