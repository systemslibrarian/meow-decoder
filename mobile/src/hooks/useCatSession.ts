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
  sampleCatBlinkV2Bits,
  type BrightnessSample,
  type CatDecodeResult,
} from '../services/catBlinkDecoder';
import { CatBlinkV2Collector, type CollectedDroplet } from '../services/catBlinkV2';
import { CAT_CAPTURE_TIMEOUT_MS } from '../constants/config';

/** Capture lifecycle for a Cat Mode session. */
export type CatSessionStatus = 'idle' | 'sampling' | 'locked' | 'complete' | 'timeout';

/**
 * Decoder mode. v1 = legacy contiguous 68-byte-header blink stream (no FEC);
 * v2 = fountain droplet frames collected for the desktop decoder (see
 * services/catBlinkV2.ts and docs/CAT_BLINK_V2.md).
 */
export type CatDecoderMode = 'v1' | 'v2';

/** Progress snapshot for a v2 (fountain droplet) collecting session. */
export interface CatV2Progress {
  /** Distinct droplets gathered so far (deduped by seed). */
  droplets: CollectedDroplet[];
  /** Fountain source-block count, or null until a frame is seen. */
  kBlocks: number | null;
  /** Fountain block size, or null until a frame is seen. */
  blockSize: number | null;
  /** Exact payload length before zero-padding, or null until a frame is seen. */
  originalLength: number | null;
  /** ceil(1.5 × kBlocks) unique-droplet target, or null until kBlocks is known. */
  target: number | null;
}

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
  /** True when capture was ended by the user's manual Finish (not auto-detect). */
  stoppedEarly: boolean;
  /** Active decoder mode ('v1' legacy header, 'v2' fountain droplets). */
  mode: CatDecoderMode;
  /**
   * v2 collecting-session progress (droplets, fountain params, target). Null in
   * v1 mode. Present as soon as scanning begins in v2, populated once the first
   * good frame is CRC-validated.
   */
  v2: CatV2Progress | null;
  /** Pass this to useCatBlinkSampler's onSample. */
  onSample: (sample: BrightnessSample) => void;
  /**
   * Manually end capture and finalize with whatever is buffered. Runs one last
   * decode: if a usable pattern was recovered it lands on 'complete' (Copy/Save
   * available, possibly partial); if nothing locked it lands on 'timeout'. Lets
   * the user acknowledge "the transmission is done" when auto-detect never fires.
   */
  finish: () => void;
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
  /** Decoder mode. Defaults to 'v1' so existing callers are unchanged. */
  mode?: CatDecoderMode;
}

export function useCatSession({
  active,
  scanning,
  timeoutMs = CAT_CAPTURE_TIMEOUT_MS,
  mode = 'v1',
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
  const [stoppedEarly, setStoppedEarly] = useState(false);
  // Latch completion so a later partial decode can't regress a finished capture.
  const completedRef = useRef(false);

  // ── v2 collecting state ────────────────────────────────────────────────────
  // A persistent collector so unique droplets accumulate across decode ticks
  // (the growing sample buffer is re-scanned each tick; dedup-by-seed makes that
  // idempotent). Snapshot to React state for the UI.
  const v2CollectorRef = useRef<CatBlinkV2Collector>(new CatBlinkV2Collector());
  const blinkPeriodMsV2Ref = useRef(0);
  const [v2, setV2] = useState<CatV2Progress | null>(null);

  const snapshotV2 = useCallback((): boolean => {
    const r = v2CollectorRef.current.result();
    setV2({
      droplets: r.droplets,
      kBlocks: r.kBlocks,
      blockSize: r.blockSize,
      originalLength: r.originalLength,
      target: r.target,
    });
    return r.complete;
  }, []);

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
    v2CollectorRef.current.reset();
    blinkPeriodMsV2Ref.current = 0;
    setV2(null);
    setSampleCount(0);
    setSignal({ left: 0, right: 0 });
    setResult(null);
    setEverLocked(false);
    setStoppedEarly(false);
    setStatus('idle');
  }, []);

  // Manual finish: the user acknowledges the transmission is over. Finalize with
  // whatever is buffered instead of forcing them to wait for the exact-match
  // auto-detect (which a lossy optical stream may never satisfy) or to Cancel
  // and lose everything.
  const finish = useCallback(() => {
    if (completedRef.current) return;
    completedRef.current = true;
    setStoppedEarly(true);
    const buf = bufferRef.current;

    if (mode === 'v2') {
      // Fold in one last scan, then finalize with whatever droplets we hold.
      if (buf.length >= 64) {
        const sampled = sampleCatBlinkV2Bits(buf);
        if (sampled.locked) {
          if (sampled.blinkPeriodMs > 0) {
            setEverLocked(true);
            blinkPeriodMsV2Ref.current = sampled.blinkPeriodMs;
          }
          v2CollectorRef.current.addStream(sampled.whitenedBits);
        }
      }
      snapshotV2();
      // 'complete' when we captured at least one droplet (worth exporting), else timeout.
      setStatus(v2CollectorRef.current.size > 0 ? 'complete' : 'timeout');
      return;
    }

    const decoded = buf.length >= 64 ? decodeCatBlink(buf) : null;
    if (decoded) {
      setResult(decoded);
      if (decoded.blinkPeriodMs > 0) setEverLocked(true);
    }
    // 'complete' when we have bits worth showing (Copy/Save), else 'timeout'.
    setStatus(decoded && decoded.bits > 0 ? 'complete' : 'timeout');
  }, [mode, snapshotV2]);

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
        // In v2, whatever droplets we gathered are still worth exporting.
        if (mode === 'v2') snapshotV2();
        setStatus('timeout');
        return;
      }
      const buf = bufferRef.current;
      if (buf.length < 64) {
        setStatus((s) => (s === 'idle' ? 'sampling' : s));
        return;
      }

      if (mode === 'v2') {
        // Re-scan the growing buffer for frames; dedup-by-seed makes re-feeding
        // the same samples idempotent. Complete at ceil(1.5×k) unique droplets.
        const sampled = sampleCatBlinkV2Bits(buf);
        if (sampled.locked) {
          if (sampled.blinkPeriodMs > 0) {
            setEverLocked(true);
            blinkPeriodMsV2Ref.current = sampled.blinkPeriodMs;
          }
          v2CollectorRef.current.addStream(sampled.whitenedBits);
        }
        const complete = snapshotV2();
        if (complete) {
          completedRef.current = true;
          setStatus('complete');
        } else if (sampled.locked) {
          setStatus('locked');
        } else {
          setStatus('sampling');
        }
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
  }, [scanning, timeoutMs, mode, snapshotV2]);

  // Progress: v1 tracks payload bits from the header; v2 tracks unique droplets
  // toward the ceil(1.5×k) fountain-collect target.
  let expectedBits: number;
  let capturedBits: number;
  let progress: number;
  if (mode === 'v2') {
    const collected = v2?.droplets.length ?? 0;
    const target = v2?.target ?? 0;
    // Surface droplet counts through the existing "bits" fields so the screen's
    // progress math works unchanged (1 unit = 1 droplet here).
    expectedBits = target;
    capturedBits = collected;
    progress = target > 0 ? Math.min(1, collected / target) : 0;
  } else {
    expectedBits = result?.diagnostics.expectedBits ?? 0;
    capturedBits = result?.bits ?? 0;
    progress = expectedBits > 0 ? Math.min(1, capturedBits / expectedBits) : 0;
  }

  return {
    status,
    sampleCount,
    signalLeft: signal.left,
    signalRight: signal.right,
    locked: status === 'locked' || status === 'complete',
    everLocked,
    binary: status === 'complete' ? (result?.binary ?? '') : '',
    bits: status === 'complete' ? (result?.bits ?? 0) : 0,
    blinkPeriodMs:
      mode === 'v2' ? (v2 ? blinkPeriodMsV2Ref.current : 0) : (result?.blinkPeriodMs ?? 0),
    progress,
    capturedBits,
    expectedBits,
    stoppedEarly,
    mode,
    v2: mode === 'v2' ? v2 : null,
    onSample,
    finish,
    reset,
  };
}

