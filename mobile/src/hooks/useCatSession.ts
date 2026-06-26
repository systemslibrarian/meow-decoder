/**
 * useCatSession.ts — orchestrates a live Cat Mode capture.
 *
 * Buffers the brightness samples produced by useCatBlinkSampler, periodically
 * runs the decoder (catBlinkDecoder) over the buffer, and surfaces live UI
 * state: a smoothed left/right signal for the on-screen meters, whether the
 * preamble has been locked, and the recovered binary pattern once complete.
 *
 * Two independent gates:
 *   • `active`   — the screen is up: keep the live left/right signal flowing so
 *                  the user can align the eye boxes (meters move) even before
 *                  capture begins.
 *   • `scanning` — the user has tapped Start: accumulate the buffer, run the
 *                  decoder, and enforce the timeout. The timeout clock starts
 *                  only when scanning begins, so aligning never burns the budget.
 *
 * The decode runs on a timer (not per frame) to keep the JS thread free.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  decodeCatBlink,
  type BrightnessSample,
  type CatDecodeResult,
} from '../services/catBlinkDecoder';
import { CAT_CAPTURE_TIMEOUT_MS } from '../constants/config';

/** Capture lifecycle for a Cat Mode session. */
export type CatSessionStatus = 'idle' | 'sampling' | 'locked' | 'complete' | 'timeout';

export interface UseCatSessionReturn {
  status: CatSessionStatus;
  /** Number of brightness samples buffered so far. */
  sampleCount: number;
  /** Latest left/right brightness (raw, ~0–255) for live meters. */
  signalLeft: number;
  signalRight: number;
  /** True once the preamble locked and a blink period was estimated. */
  locked: boolean;
  /** True if the preamble was EVER locked this session (for timeout diagnosis). */
  everLocked: boolean;
  /** Recovered raw binary pattern (empty until complete). */
  binary: string;
  /** Bits recovered (0 until complete). */
  bits: number;
  /** Estimated blink period in ms (0 until locked). */
  blinkPeriodMs: number;
  /** Fraction of the payload captured so far (0–1; 0 until the header is read). */
  progress: number;
  /** Bits captured so far. */
  capturedBits: number;
  /** Total payload bits expected (0 until the header is read). */
  expectedBits: number;
  /** Pass this to useCatBlinkSampler's onSample. */
  onSample: (sample: BrightnessSample) => void;
  /** Clear all buffered samples and results for a fresh capture. */
  reset: () => void;
}

/** Largest number of samples retained (~11 min at 30 fps). Guards memory. */
const MAX_SAMPLES = 20_000;
/** How often (ms) to re-run the decoder over the buffer. */
const DECODE_INTERVAL_MS = 400;
/** How often (ms) to push the live signal to React state (throttled). */
const SIGNAL_INTERVAL_MS = 100;

export interface UseCatSessionOptions {
  /** Screen is up: keep the live signal flowing for alignment. */
  active: boolean;
  /** User tapped Start: accumulate buffer, decode, and enforce the timeout. */
  scanning: boolean;
  /**
   * Give up and emit status 'timeout' after this many ms of *scanning* without a
   * complete decode. Defaults to CAT_CAPTURE_TIMEOUT_MS so capture can never run
   * indefinitely on an undecodable signal.
   */
  timeoutMs?: number;
}

export function useCatSession({
  active,
  scanning,
  timeoutMs = CAT_CAPTURE_TIMEOUT_MS,
}: UseCatSessionOptions): UseCatSessionReturn {
  const bufferRef = useRef<BrightnessSample[]>([]);
  const latestRef = useRef<{ left: number; right: number }>({ left: 0, right: 0 });
  // Wall-clock start of scanning (first sample after Start), for the timeout guard.
  const startMsRef = useRef<number | null>(null);
  const [sampleCount, setSampleCount] = useState(0);
  const [signal, setSignal] = useState<{ left: number; right: number }>({ left: 0, right: 0 });
  const [result, setResult] = useState<CatDecodeResult | null>(null);
  const [status, setStatus] = useState<CatSessionStatus>('idle');
  const [everLocked, setEverLocked] = useState(false);
  // Latch completion so a later partial decode can't regress a finished capture.
  const completedRef = useRef(false);

  const onSample = useCallback(
    (sample: BrightnessSample) => {
      if (!active) return;
      // Always update the live signal so the eye meters move during alignment.
      latestRef.current = { left: sample.left, right: sample.right };
      // Only accumulate toward a decode once the user has started scanning.
      if (!scanning || completedRef.current) return;
      if (startMsRef.current === null) startMsRef.current = Date.now();
      const buf = bufferRef.current;
      buf.push(sample);
      if (buf.length > MAX_SAMPLES) buf.shift();
    },
    [active, scanning],
  );

  const reset = useCallback(() => {
    bufferRef.current = [];
    latestRef.current = { left: 0, right: 0 };
    startMsRef.current = null;
    completedRef.current = false;
    setSampleCount(0);
    setSignal({ left: 0, right: 0 });
    setResult(null);
    setEverLocked(false);
    setStatus('idle');
  }, []);

  // Live signal + sample-count ticker (throttled, independent of decode cost).
  useEffect(() => {
    if (!active) return undefined;
    const id = setInterval(() => {
      setSignal(latestRef.current);
      setSampleCount(bufferRef.current.length);
    }, SIGNAL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [active]);

  // Periodic decode attempt over the whole buffer — only while scanning.
  useEffect(() => {
    if (!scanning) return undefined;
    const id = setInterval(() => {
      if (completedRef.current) return;
      // Timeout guard: give up if no complete decode within the budget.
      if (startMsRef.current !== null && Date.now() - startMsRef.current > timeoutMs) {
        completedRef.current = true;
        setStatus('timeout');
        return;
      }
      const buf = bufferRef.current;
      if (buf.length < 64) {
        setStatus((s) => (s === 'idle' ? 'sampling' : s));
        return;
      }
      const decoded = decodeCatBlink(buf);
      setResult(decoded);
      if (decoded.blinkPeriodMs > 0) setEverLocked(true);
      if (decoded.locked && decoded.diagnostics.reason === null) {
        completedRef.current = true;
        setStatus('complete');
      } else if (decoded.blinkPeriodMs > 0) {
        setStatus('locked');
      } else {
        setStatus('sampling');
      }
    }, DECODE_INTERVAL_MS);
    return () => clearInterval(id);
  }, [scanning, timeoutMs]);

  const expectedBits = result?.diagnostics.expectedBits ?? 0;
  const capturedBits = result?.bits ?? 0;
  const progress = expectedBits > 0 ? Math.min(1, capturedBits / expectedBits) : 0;

  return {
    status,
    sampleCount,
    signalLeft: signal.left,
    signalRight: signal.right,
    locked: status === 'locked' || status === 'complete',
    everLocked,
    binary: status === 'complete' ? (result?.binary ?? '') : '',
    bits: status === 'complete' ? (result?.bits ?? 0) : 0,
    blinkPeriodMs: result?.blinkPeriodMs ?? 0,
    progress,
    capturedBits,
    expectedBits,
    onSample,
    reset,
  };
}

