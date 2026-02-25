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
import { MMKV } from 'react-native-mmkv';
import type {
  CaptureRequest,
  CapturedFrame,
  CaptureResponse,
  CaptureState,
  CaptureProgress,
} from '../types/capture';
import { FOUNTAIN_OVERHEAD, MIN_RECOVERABLE_RATIO } from '../constants/config';

// ── MMKV Checkpoint Storage ─────────────────────────────────────────────────────────
// SECURITY NOTE: Only frame INDICES are persisted — never QR payload strings.
// This allows HomeScreen to surface a "resume" hint after an unexpected kill
// without writing any sensitive capture data to device storage.
const checkpointStorage = new MMKV({ id: 'meow_capture_checkpoint' });
const CHECKPOINT_KEY = 'active_session';

export type SessionCheckpoint = {
  session_id: string;
  frame_indices: number[];
  saved_at: number;  // Unix ms for staleness check
};

/** Read the last persisted checkpoint (indices only) — safe to call from any screen. */
export function readCaptureCheckpoint(): SessionCheckpoint | null {
  const raw = checkpointStorage.getString(CHECKPOINT_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SessionCheckpoint;
  } catch {
    return null;
  }
}

/** Clear the checkpoint — call when the user explicitly dismisses the resume hint. */
export function clearCaptureCheckpoint(): void {
  checkpointStorage.delete(CHECKPOINT_KEY);
}

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
      // SECURITY NOTE: JS `String` values are immutable and GC-managed.
      // Frame payload strings held in `state.frames` cannot be zero-filled
      // in-process (no raw heap access in Hermes/V8). Security relies on:
      //   • GC releasing all Map references on the next collection cycle
      //   • No persistence — frame data was never written to disk
      //   • OS-level memory reclaim (Hermes does not mmap frame strings)
      //   • FLAG_SECURE / privacy overlay blocking exfiltration via UI
      // This is architecturally equivalent to Signal's in-process string model.
      return {
        ...initialState,
        status: 'IDLE',
      };

    case 'ERROR':
      return { ...state, status: 'ERROR', error: action.payload };

    case 'RESET':
      // Full reset — clears all frame data from memory.
      // See CANCEL case for zeroization constraints and security rationale.
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
  /** Read the last persisted checkpoint (indices only, never payload data) */
  getCheckpoint: () => SessionCheckpoint | null;
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

  // ── MMKV checkpoint ───────────────────────────────────────────────────────
  // Debounced write every ~5 frames — persists only frame indices, never
  // QR payload strings. Allows HomeScreen to surface a resume hint after kill.
  const checkpointDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (state.status !== 'CAPTURING' || !state.request) return;
    if (checkpointDebounceRef.current) clearTimeout(checkpointDebounceRef.current);
    checkpointDebounceRef.current = setTimeout(() => {
      checkpointDebounceRef.current = null;
      const checkpoint: SessionCheckpoint = {
        session_id: state.request!.session_id,
        frame_indices: Array.from(state.frames.keys()),
        saved_at: Date.now(),
      };
      checkpointStorage.set(CHECKPOINT_KEY, JSON.stringify(checkpoint));
    }, 200);
    return () => {
      if (checkpointDebounceRef.current) {
        clearTimeout(checkpointDebounceRef.current);
        checkpointDebounceRef.current = null;
      }
    };
  }, [state.frames.size, state.status, state.request]);

  // Clear checkpoint when session reaches a terminal/idle state
  useEffect(() => {
    if (
      state.status === 'COMPLETE' ||
      state.status === 'TIMED_OUT' ||
      state.status === 'IDLE'
    ) {
      checkpointStorage.delete(CHECKPOINT_KEY);
    }
  }, [state.status]);

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

  const getCheckpoint = useCallback((): SessionCheckpoint | null => {
    const raw = checkpointStorage.getString(CHECKPOINT_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as SessionCheckpoint;
    } catch {
      return null;
    }
  }, []);

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
    getCheckpoint,
  };
}
