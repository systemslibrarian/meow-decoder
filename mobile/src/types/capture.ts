/**
 * capture.ts — Core data types for the meow-decoder capture protocol.
 *
 * These types mirror the JSON wire protocol defined in the project spec.
 * The mobile app is an intentionally untrusted optical sensor — frame
 * data is treated as opaque base64; no decryption or interpretation
 * of payload content is ever performed.
 */

// ── State Machine ────────────────────────────────────────────────────────────

/**
 * Capture session lifecycle states.
 *
 * Valid transitions:
 *   IDLE → LOADING_REQUEST → AWAITING_GIF → CAPTURING → COMPLETE → EXPORTING
 *   Any active state → CANCELLED | TIMED_OUT → IDLE (via reset)
 *   CAPTURING → ERROR_STATE
 */
export type CaptureState =
  | 'IDLE'
  | 'LOADING_REQUEST'
  | 'AWAITING_GIF'
  | 'CAPTURING'
  | 'PAUSED'
  | 'COMPLETE'
  | 'EXPORTING'
  | 'TIMED_OUT'
  | 'CANCELLED'
  | 'ERROR';

// ── JSON Protocol Types ──────────────────────────────────────────────────────

/**
 * Capture Request — loaded by the app from a JSON file provided by the CLI.
 *
 * Example:
 * {
 *   "action": "capture",
 *   "session_id": "550e8400-e29b-41d4-a716-446655440000",
 *   "expected_frames": 45,
 *   "timeout_seconds": 60
 * }
 */
export interface CaptureRequest {
  /** Must be exactly "capture" */
  action: 'capture';
  /** UUID v4 identifying this session, used to verify frame ownership */
  session_id: string;
  /** Number of source fountain code blocks (not total with redundancy) */
  expected_frames: number;
  /** Seconds before session auto-times-out; defaults to 60 */
  timeout_seconds: number;
}

/**
 * Captured Frame — a single QR code payload extracted from the camera.
 *
 * Frame data is opaque base64. The app never interprets, decodes, or
 * stores this content except in memory during an active session.
 */
export interface CapturedFrame {
  /** Fountain code droplet index */
  index: number;
  /** Opaque base64-encoded fountain code droplet payload */
  data: string;
  /** Unix epoch milliseconds when this frame was captured */
  timestamp_ms: number;
}

/**
 * Capture Response — the JSON exported by the app to Downloads for CLI retrieval.
 *
 * Example:
 * {
 *   "session_id": "550e8400-...",
 *   "frames": [...],
 *   "capture_complete": true,
 *   "frames_captured": 42,
 *   "frames_missed": 3
 * }
 */
export interface CaptureResponse {
  /** Mirrors the session_id from the CaptureRequest */
  session_id: string;
  /** Deduplicated, index-sorted array of captured frames */
  frames: CapturedFrame[];
  /** True when stopped by user or fountain threshold reached; false on timeout */
  capture_complete: boolean;
  /** Number of unique frame indices captured */
  frames_captured: number;
  /** Max(0, expected_frames - frames_captured) */
  frames_missed: number;
}

// ── Progress Metrics ─────────────────────────────────────────────────────────

/**
 * Real-time progress snapshot computed by useCapture.
 */
export interface CaptureProgress {
  /** Unique frames captured so far */
  captured: number;
  /** Original expected_frames from the request */
  expected: number;
  /** captured / expected × 100 (may exceed 100 with fountain redundancy) */
  percentRaw: number;
  /** captured / fountainThreshold × 100 (threshold = expected × FOUNTAIN_OVERHEAD) */
  percentRecoverable: number;
  /** True when captured >= expected × MIN_RECOVERABLE_RATIO (~67%); fountain can likely decode */
  isRecoverable: boolean;
  /** True when captured >= expected × FOUNTAIN_OVERHEAD (recommended threshold) */
  isFountainComplete: boolean;
}

// ── QR Payload ───────────────────────────────────────────────────────────────

/**
 * Raw QR payload parsed from a single camera frame.
 *
 * The app expects each QR code to contain either:
 *   a) FOUNTAIN: prefixed frame data (fountain code droplet)
 *   b) JSON with {index, data, session_id?} fields
 *
 * Any other format is silently ignored.
 */
export interface QRFramePayload {
  index: number;
  data: string;
  session_id?: string;
}

// ── Export Metadata ──────────────────────────────────────────────────────────

/**
 * Result of a JSON export operation.
 */
export interface ExportResult {
  /** Absolute path(s) of the written JSON file(s) */
  paths: string[];
  /** Total bytes written */
  totalBytes: number;
  /** Number of chunks (1 for single-file export) */
  chunkCount: number;
  /** ISO 8601 timestamp of export */
  exportedAt: string;
}
