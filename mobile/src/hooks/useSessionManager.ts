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
import { MILESTONE_THRESHOLDS, FOUNTAIN_OVERHEAD } from '../constants/config';
import type { MilestoneThreshold } from '../constants/config';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface SessionManagerReturn {
  // State
  status: ReturnType<typeof useCapture>['state']['status'];
  progress: CaptureProgress | null;
  error: string | null;
  elapsedMs: number;
  remainingMs: number | null;
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
  markExporting: () => void;
  buildResponse: () => CaptureResponse | null;
  // Frame processor for Camera component
  frameProcessor: ReturnType<typeof useQRScanner>['frameProcessor'];
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
    markExporting,
    buildResponse,
  } = useCapture();

  const { isStable, shakeMagnitude } = useStabilityMonitor();

  const { frameProcessor } = useQRScanner({
    sessionId: state.request?.session_id,
    onFrame: onFrameScanned,
    onGifDetected,
    enabled: state.status === 'AWAITING_GIF' || state.status === 'CAPTURING',
  });

  // ── Elapsed time ticker ───────────────────────────────────────────────────
  const [elapsedMs, setElapsedMs] = useState(0);
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (state.status === 'CAPTURING' && state.startedAt !== null) {
      tickRef.current = setInterval(() => {
        setElapsedMs(Date.now() - (state.startedAt ?? Date.now()));
      }, 1_000);
    } else {
      if (tickRef.current !== null) {
        clearInterval(tickRef.current);
        tickRef.current = null;
      }
      if (state.status === 'IDLE' || state.status === 'AWAITING_GIF') {
        setElapsedMs(0);
      }
    }
    return () => {
      if (tickRef.current !== null) clearInterval(tickRef.current);
    };
  }, [state.status, state.startedAt]);

  // ── Remaining time ─────────────────────────────────────────────────────────
  const remainingMs = state.request?.timeout_seconds
    ? Math.max(0, state.request.timeout_seconds * 1_000 - elapsedMs)
    : null;

  // ── Memory pressure detection ──────────────────────────────────────────────
  const isNearMemoryLimit = state.frames.size >= 800;

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
    isStable,
    shakeMagnitude,
    isNearMemoryLimit,
    lastMilestone,
    loadRequest,
    stop,
    cancel,
    markExporting,
    buildResponse: buildResponseWrapper,
    frameProcessor,
  };
}
