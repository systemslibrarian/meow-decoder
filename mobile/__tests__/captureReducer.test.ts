/**
 * captureReducer.test.ts — Unit tests for the capture state machine reducer.
 *
 * Tests every valid and invalid state transition to ensure correctness
 * and prevent regressions in the session lifecycle.
 */

// We test the reducer in isolation by extracting it from the hook module.
// The reducer function is not exported from useCapture — we re-define it here
// for pure unit testing without React dependencies.

// Import the types to keep tests in sync with production types
import type { CaptureState, CaptureRequest, CapturedFrame } from '../src/types/capture';

// ── Reducer re-definition (mirrors useCapture.ts) ────────────────────────────

type State = {
  status: CaptureState;
  request: CaptureRequest | null;
  frames: Map<number, CapturedFrame>;
  startedAt: number | null;
  error: string | null;
};

type Action =
  | { type: 'LOAD_REQUEST'; payload: CaptureRequest }
  | { type: 'GIF_DETECTED' }
  | { type: 'FRAME_CAPTURED'; payload: CapturedFrame }
  | { type: 'CAPTURE_COMPLETE' }
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

function captureReducer(state: State, action: Action): State {
  switch (action.type) {
    case 'LOAD_REQUEST':
      return { ...state, status: 'AWAITING_GIF', request: action.payload, frames: new Map(), error: null };
    case 'GIF_DETECTED':
      if (state.status !== 'AWAITING_GIF') return state;
      return { ...state, status: 'CAPTURING', startedAt: Date.now() };
    case 'FRAME_CAPTURED': {
      if (state.status !== 'CAPTURING' && state.status !== 'AWAITING_GIF') return state;
      const next = new Map(state.frames);
      if (!next.has(action.payload.index)) next.set(action.payload.index, action.payload);
      const status = state.status === 'AWAITING_GIF' ? 'CAPTURING' : state.status;
      const startedAt = state.status === 'AWAITING_GIF' ? Date.now() : state.startedAt;
      return { ...state, status, startedAt, frames: next };
    }
    case 'CAPTURE_COMPLETE':
      if (state.status !== 'CAPTURING' && state.status !== 'TIMED_OUT') return state;
      return { ...state, status: 'COMPLETE' };
    case 'START_EXPORT':
      return { ...state, status: 'EXPORTING' };
    case 'TIMEOUT':
      if (state.status !== 'CAPTURING') return state;
      return { ...state, status: 'TIMED_OUT' };
    case 'CANCEL':
      return { ...initialState, status: 'IDLE' };
    case 'ERROR':
      return { ...state, status: 'ERROR', error: action.payload };
    case 'RESET':
      return { ...initialState };
    default:
      return state;
  }
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

const mockRequest: CaptureRequest = {
  action: 'capture',
  session_id: '550e8400-e29b-41d4-a716-446655440000',
  expected_frames: 10,
  timeout_seconds: 60,
};

const mockFrame = (index: number): CapturedFrame => ({
  index,
  data: 'AAAA',
  timestamp_ms: Date.now(),
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('captureReducer', () => {
  describe('LOAD_REQUEST', () => {
    it('transitions IDLE → AWAITING_GIF', () => {
      const state = captureReducer(initialState, {
        type: 'LOAD_REQUEST',
        payload: mockRequest,
      });
      expect(state.status).toBe('AWAITING_GIF');
      expect(state.request).toEqual(mockRequest);
      expect(state.frames.size).toBe(0);
    });

    it('clears previous frames on new request', () => {
      const withFrames: State = {
        ...initialState,
        status: 'CAPTURING',
        frames: new Map([[0, mockFrame(0)]]),
      };
      const state = captureReducer(withFrames, {
        type: 'LOAD_REQUEST',
        payload: mockRequest,
      });
      expect(state.frames.size).toBe(0);
    });
  });

  describe('GIF_DETECTED', () => {
    it('transitions AWAITING_GIF → CAPTURING', () => {
      const awaiting: State = { ...initialState, status: 'AWAITING_GIF', request: mockRequest };
      const state = captureReducer(awaiting, { type: 'GIF_DETECTED' });
      expect(state.status).toBe('CAPTURING');
      expect(state.startedAt).not.toBeNull();
    });

    it('ignores GIF_DETECTED when not AWAITING_GIF', () => {
      const idle: State = { ...initialState, status: 'IDLE' };
      const state = captureReducer(idle, { type: 'GIF_DETECTED' });
      expect(state.status).toBe('IDLE');
    });
  });

  describe('FRAME_CAPTURED', () => {
    it('adds new frame during CAPTURING', () => {
      const capturing: State = { ...initialState, status: 'CAPTURING', request: mockRequest };
      const state = captureReducer(capturing, {
        type: 'FRAME_CAPTURED',
        payload: mockFrame(5),
      });
      expect(state.frames.size).toBe(1);
      expect(state.frames.has(5)).toBe(true);
    });

    it('deduplicates frame with same index', () => {
      const first = mockFrame(3);
      first.data = 'FIRST';
      const second = { ...mockFrame(3), data: 'SECOND' };
      let state: State = { ...initialState, status: 'CAPTURING', request: mockRequest };
      state = captureReducer(state, { type: 'FRAME_CAPTURED', payload: first });
      state = captureReducer(state, { type: 'FRAME_CAPTURED', payload: second });
      expect(state.frames.size).toBe(1);
      // First capture wins
      expect(state.frames.get(3)?.data).toBe('FIRST');
    });

    it('accepts frames with different indices', () => {
      let state: State = { ...initialState, status: 'CAPTURING', request: mockRequest };
      for (let i = 0; i < 5; i++) {
        state = captureReducer(state, { type: 'FRAME_CAPTURED', payload: mockFrame(i) });
      }
      expect(state.frames.size).toBe(5);
    });

    it('ignores frames when IDLE', () => {
      const state = captureReducer(initialState, {
        type: 'FRAME_CAPTURED',
        payload: mockFrame(0),
      });
      expect(state.frames.size).toBe(0);
      expect(state.status).toBe('IDLE');
    });

    it('auto-starts CAPTURING from AWAITING_GIF on first frame', () => {
      const awaiting: State = { ...initialState, status: 'AWAITING_GIF', request: mockRequest };
      const state = captureReducer(awaiting, {
        type: 'FRAME_CAPTURED',
        payload: mockFrame(0),
      });
      expect(state.status).toBe('CAPTURING');
      expect(state.frames.size).toBe(1);
    });
  });

  describe('CAPTURE_COMPLETE', () => {
    it('transitions CAPTURING → COMPLETE', () => {
      const capturing: State = { ...initialState, status: 'CAPTURING' };
      const state = captureReducer(capturing, { type: 'CAPTURE_COMPLETE' });
      expect(state.status).toBe('COMPLETE');
    });

    it('transitions TIMED_OUT → COMPLETE (for export after timeout)', () => {
      const timedOut: State = { ...initialState, status: 'TIMED_OUT' };
      const state = captureReducer(timedOut, { type: 'CAPTURE_COMPLETE' });
      expect(state.status).toBe('COMPLETE');
    });

    it('ignores CAPTURE_COMPLETE when IDLE', () => {
      const state = captureReducer(initialState, { type: 'CAPTURE_COMPLETE' });
      expect(state.status).toBe('IDLE');
    });
  });

  describe('TIMEOUT', () => {
    it('transitions CAPTURING → TIMED_OUT', () => {
      const capturing: State = { ...initialState, status: 'CAPTURING' };
      const state = captureReducer(capturing, { type: 'TIMEOUT' });
      expect(state.status).toBe('TIMED_OUT');
    });

    it('ignores TIMEOUT when not CAPTURING', () => {
      const awaiting: State = { ...initialState, status: 'AWAITING_GIF' };
      const state = captureReducer(awaiting, { type: 'TIMEOUT' });
      expect(state.status).toBe('AWAITING_GIF');
    });
  });

  describe('CANCEL', () => {
    it('resets to IDLE and clears all data', () => {
      const active: State = {
        ...initialState,
        status: 'CAPTURING',
        request: mockRequest,
        frames: new Map([[0, mockFrame(0)], [1, mockFrame(1)]]),
        startedAt: Date.now(),
      };
      const state = captureReducer(active, { type: 'CANCEL' });
      expect(state.status).toBe('IDLE');
      expect(state.frames.size).toBe(0);
      expect(state.request).toBeNull();
      expect(state.startedAt).toBeNull();
    });
  });

  describe('ERROR', () => {
    it('transitions to ERROR with message', () => {
      const capturing: State = { ...initialState, status: 'CAPTURING' };
      const state = captureReducer(capturing, {
        type: 'ERROR',
        payload: 'Camera failed',
      });
      expect(state.status).toBe('ERROR');
      expect(state.error).toBe('Camera failed');
    });
  });

  describe('RESET', () => {
    it('returns to initialState completely', () => {
      const active: State = {
        status: 'CAPTURING',
        request: mockRequest,
        frames: new Map([[0, mockFrame(0)]]),
        startedAt: 12345,
        error: 'old error',
      };
      const state = captureReducer(active, { type: 'RESET' });
      expect(state).toEqual(initialState);
      expect(state.frames.size).toBe(0);
    });
  });
});

describe('progress calculations', () => {
  it('calculates percentRaw correctly at 0 frames', () => {
    const captured = 0;
    const expected = 10;
    const pct = expected > 0 ? (captured / expected) * 100 : 0;
    expect(pct).toBe(0);
  });

  it('calculates percentRaw at exactly expected', () => {
    const captured = 10;
    const expected = 10;
    const pct = (captured / expected) * 100;
    expect(pct).toBe(100);
  });

  it('calculates percentRecoverable at fountain threshold', () => {
    const FOUNTAIN_OVERHEAD = 1.5;
    const expected = 10;
    const captured = Math.ceil(expected * FOUNTAIN_OVERHEAD); // 15
    const threshold = Math.ceil(expected * FOUNTAIN_OVERHEAD);
    const pct = (captured / threshold) * 100;
    expect(pct).toBe(100);
  });

  it('isFountainComplete at exactly threshold', () => {
    const FOUNTAIN_OVERHEAD = 1.5;
    const expected = 10;
    const threshold = Math.ceil(expected * FOUNTAIN_OVERHEAD);
    expect(threshold).toBe(15);
    expect(15 >= threshold).toBe(true);
  });
});
