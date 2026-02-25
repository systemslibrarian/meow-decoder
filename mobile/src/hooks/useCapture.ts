/**
 * useCapture.ts — Core capture session state machine.
 *
 * Implements the full lifecycle:
 *   IDLE → AWAITING_GIF → CAPTURING → COMPLETE → EXPORTING
 *                                   ↓
 *                               TIMED_OUT
 *
 * All frame data lives exclusively in this reducer state (React memory).
 * It is never written to disk except by the explicit export action.
 * On AppState background/inactive, RESET is dispatched immediately.
 *
 * SECURITY:
 *  - useEffect cleanup dispatches RESET on unmount
 *  - AppState handler clears all frames when app backgrounds
 *  - No frame data escapes this hook except via buildResponse()
 */

import {
  useReducer,
  useCallback,
  useRef,
  useEffect,
} from 'react';
import { AppState, type AppStateStatus } from 'react-native';
import type {
  CaptureRequest,
  CapturedFrame,
  CaptureResponse,
  CaptureState,
  CaptureProgress,
} from '../types/capture';
import { FOUNTAIN_OVERHEAD, MIN_RECOVERABLE_RATIO } from '../constants/config';

// ── State & Actions ───────────────────────────────────────────────────────────

type State = {
  status: CaptureState;
  request: CaptureRequest | null;
  /** Keyed by frame index for O(1) dedup lookups */
  frames: Map<number, CapturedFrame>;
  startedAt: number | null;
  error: string | null;
};

type Action =
  | { type: 'LOAD_REQUEST'; payload: CaptureRequest }
  | { type: 'GIF_DETECTED' }
  | { type: 'FRAME_CAPTURED'; payload: CapturedFrame }
  | { type: 'CAPTURE_COMPLETE' }
  | { type: 'PAUSE' }
  | { type: 'RESUME' }
  | { type: 'START_EXPORT' }
  | { type: 'TIMEOUT' }
  | { type: 'CANCEL' }
  | { type: 'ERROR'; payload: string }
  | { type: 'RESET' };

const initialState: State = {
  status: 'IDLE',
  request: null,
  frames: new Map(),
  startedAt: null,
  error: null,
};

// ── Reducer ───────────────────────────────────────────────────────────────────

function captureReducer(state: State, action: Action): State {
  switch (action.type) {
    case 'LOAD_REQUEST':
      return {
        ...state,
        status: 'AWAITING_GIF',
        request: action.payload,
        frames: new Map(),
        error: null,
      };

    case 'GIF_DETECTED':
      // Only transition if we're actually waiting
      if (state.status !== 'AWAITING_GIF') return state;
      return { ...state, status: 'CAPTURING', startedAt: Date.now() };

    case 'FRAME_CAPTURED': {
      // Only collect frames during active capture (not when paused)
      if (state.status !== 'CAPTURING' && state.status !== 'AWAITING_GIF') return state;
      const next = new Map(state.frames);
      // Dedup: only store first occurrence of each index
      if (!next.has(action.payload.index)) {
        next.set(action.payload.index, action.payload);
      }
      // Auto-transition to CAPTURING on first frame if still AWAITING_GIF
      const status =
        state.status === 'AWAITING_GIF' ? 'CAPTURING' : state.status;
      const startedAt =
        state.status === 'AWAITING_GIF' ? Date.now() : state.startedAt;
      return { ...state, status, startedAt, frames: next };
    }

    case 'CAPTURE_COMPLETE':
      if (
        state.status !== 'CAPTURING' &&
        state.status !== 'TIMED_OUT' &&
        state.status !== 'PAUSED'
      ) return state;
      return { ...state, status: 'COMPLETE' };

    case 'PAUSE':
      if (state.status !== 'CAPTURING') return state;
      return { ...state, status: 'PAUSED' };

    case 'RESUME':
      if (state.status !== 'PAUSED') return state;
      return { ...state, status: 'CAPTURING' };

    case 'START_EXPORT':
      return { ...state, status: 'EXPORTING' };

    case 'TIMEOUT':
      if (state.status !== 'CAPTURING') return state;
      return { ...state, status: 'TIMED_OUT' };

    case 'CANCEL':
      return {
        ...initialState,
        status: 'IDLE',
      };

    case 'ERROR':
      return { ...state, status: 'ERROR', error: action.payload };

    case 'RESET':
      // Full reset — clears all frame data from memory
      return { ...initialState };

    default:
      return state;
  }
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export interface UseCaptureReturn {
  state: State;
  progress: CaptureProgress | null;
  loadRequest: (req: CaptureRequest) => void;
  onFrameScanned: (frame: CapturedFrame) => void;
  onGifDetected: () => void;
  stop: () => void;
  cancel: () => void;
  pause: () => void;
  resume: () => void;
  markExporting: () => void;
  buildResponse: (reason?: 'complete' | 'timeout' | 'manual') => CaptureResponse | null;
}

export function useCapture(): UseCaptureReturn {
  const [state, dispatch] = useReducer(captureReducer, initialState);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Auto-complete when fountain overhead threshold is met ──────────────────
  useEffect(() => {
    if (state.status === 'CAPTURING' && state.request) {
      const threshold = Math.ceil(
        state.request.expected_frames * FOUNTAIN_OVERHEAD,
      );
      if (state.frames.size >= threshold) {
        dispatch({ type: 'CAPTURE_COMPLETE' });
      }
    }
  }, [state.frames.size, state.status, state.request]);

  // ── Session timeout management ────────────────────────────────────────────
  useEffect(() => {
    if (state.status === 'CAPTURING' && state.request?.timeout_seconds) {
      timeoutRef.current = setTimeout(() => {
        dispatch({ type: 'TIMEOUT' });
      }, state.request.timeout_seconds * 1_000);
    }
    return () => {
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };
  }, [state.status, state.request]);

  // ── Security: clear frames when app goes to background ───────────────────
  useEffect(() => {
    const handleAppStateChange = (nextState: AppStateStatus) => {
      if (nextState === 'background' || nextState === 'inactive') {
        dispatch({ type: 'RESET' });
      }
    };
    const subscription = AppState.addEventListener('change', handleAppStateChange);
    return () => subscription.remove();
  }, []);

  // ── Security: clear frame data on unmount ─────────────────────────────────
  useEffect(() => {
    return () => {
      dispatch({ type: 'RESET' });
    };
  }, []);

  // ── Actions ───────────────────────────────────────────────────────────────

  const loadRequest = useCallback((req: CaptureRequest) => {
    dispatch({ type: 'LOAD_REQUEST', payload: req });
  }, []);

  const onFrameScanned = useCallback((frame: CapturedFrame) => {
    dispatch({ type: 'FRAME_CAPTURED', payload: frame });
  }, []);

  const onGifDetected = useCallback(() => {
    dispatch({ type: 'GIF_DETECTED' });
  }, []);

  const stop = useCallback(() => {
    dispatch({ type: 'CAPTURE_COMPLETE' });
  }, []);

  const cancel = useCallback(() => {
    dispatch({ type: 'CANCEL' });
  }, []);

  const pause = useCallback(() => {
    dispatch({ type: 'PAUSE' });
  }, []);

  const resume = useCallback(() => {
    dispatch({ type: 'RESUME' });
  }, []);

  const markExporting = useCallback(() => {
    dispatch({ type: 'START_EXPORT' });
  }, []);

  const buildResponse = useCallback(
    (_reason?: 'complete' | 'timeout' | 'manual'): CaptureResponse | null => {
      if (!state.request) return null;
      const framesArray = Array.from(state.frames.values()).sort(
        (a, b) => a.index - b.index,
      );
      return {
        session_id: state.request.session_id,
        frames: framesArray,
        capture_complete:
          state.status === 'COMPLETE' || state.status === 'EXPORTING',
        frames_captured: framesArray.length,
        frames_missed: Math.max(
          0,
          state.request.expected_frames - framesArray.length,
        ),
      };
    },
    [state],
  );

  // ── Progress metrics ──────────────────────────────────────────────────────
  const progress: CaptureProgress | null = state.request
    ? (() => {
        const captured = state.frames.size;
        const expected = state.request.expected_frames;
        const fountainThreshold = Math.ceil(expected * FOUNTAIN_OVERHEAD);
        return {
          captured,
          expected,
          percentRaw: expected > 0 ? (captured / expected) * 100 : 0,
          percentRecoverable:
            fountainThreshold > 0 ? (captured / fountainThreshold) * 100 : 0,
          isRecoverable: captured >= Math.ceil(expected * MIN_RECOVERABLE_RATIO),
          isFountainComplete: captured >= fountainThreshold,
        };
      })()
    : null;

  return {
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
  };
}
