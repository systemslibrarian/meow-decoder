/**
 * qrDecoder.ts — QR payload parsing and validation.
 *
 * Handles the boundary between raw QR string values and typed CapturedFrame
 * objects. Two payload formats are supported:
 *
 *   1. FOUNTAIN: prefixed — "FOUNTAIN:<k>:<block_size>:<length>:<base64>"
 *      Used when the CLI encodes droplets as fountain frame strings.
 *
 *   2. JSON object — {"index": N, "data": "<base64>", "session_id"?: "..."}
 *      Used when the CLI wraps droplets in a JSON envelope.
 *
 * SECURITY: This module NEVER decodes the data field content.
 * It validates structure only. The base64 payload is treated as opaque bytes.
 */

import { isValidBase64 } from '../utils/base64';
import type { QRFramePayload } from '../types/capture';

// ── Fountain Format ───────────────────────────────────────────────────────────

/** Prefix that identifies a fountain frame string from the CLI */
const FOUNTAIN_PREFIX = 'FOUNTAIN:' as const;

/**
 * Parses a FOUNTAIN: prefixed QR payload string.
 *
 * Format: "FOUNTAIN:<k_blocks>:<block_size>:<original_length>:<base64_droplet>"
 *
 * The droplet index is extracted from inside the packed droplet (first 4 bytes
 * encode the seed/index). For the mobile app we only care about uniqueness, so
 * we derive a synthetic index from the base64 content hash to deduplicate frames.
 *
 * Returns null if the string does not match the expected format.
 */
export function parseFountainPayload(qrValue: string): QRFramePayload | null {
  if (!qrValue.startsWith(FOUNTAIN_PREFIX)) return null;

  const parts = qrValue.split(':');
  // "FOUNTAIN" + k_blocks + block_size + original_length + base64_droplet = 5 parts
  if (parts.length < 5) return null;

  const kBlocks = parseInt(parts[1] ?? '', 10);
  // block_size = parts[2], original_length = parts[3]
  const dropletB64 = parts.slice(4).join(':'); // re-join in case base64 contains ':'

  if (!Number.isFinite(kBlocks) || kBlocks <= 0) return null;
  if (!dropletB64 || !isValidBase64(dropletB64)) return null;

  // Derive a stable index from the droplet content for deduplication.
  // We use a fast djb2-style hash of the first 32 chars — this doesn't need
  // to be cryptographically secure; it just needs to be consistent.
  const index = simpleHash(dropletB64.slice(0, 32));

  return { index, data: dropletB64 };
}

// ── JSON Envelope Format ──────────────────────────────────────────────────────

/**
 * Parses a JSON-envelope QR payload.
 *
 * Expected shape: { index: number, data: string, session_id?: string }
 *
 * Returns null if the string is not valid JSON or is missing required fields.
 * Extra fields are silently ignored.
 */
export function parseJsonPayload(
  qrValue: string,
  expectedSessionId?: string,
): QRFramePayload | null {
  // Quick pre-check to skip obvious non-JSON before expensive parse
  if (!qrValue.startsWith('{')) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(qrValue);
  } catch {
    return null;
  }

  if (typeof parsed !== 'object' || parsed === null) return null;

  const obj = parsed as Record<string, unknown>;

  // Validate required fields
  if (typeof obj['index'] !== 'number' || !Number.isFinite(obj['index'])) return null;
  if (typeof obj['data'] !== 'string') return null;
  if (!isValidBase64(obj['data'])) return null;

  // Session ownership check — if the QR contains a session_id that doesn't
  // match ours, skip it silently. If no session_id is present, accept it
  // (some CLI versions may omit it).
  if (
    typeof obj['session_id'] === 'string' &&
    expectedSessionId !== undefined &&
    obj['session_id'] !== expectedSessionId
  ) {
    return null;
  }

  return {
    index: obj['index'] as number,
    data: obj['data'] as string,
    session_id: typeof obj['session_id'] === 'string' ? obj['session_id'] : undefined,
  };
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

/**
 * Attempts to parse any supported QR payload format.
 *
 * Returns a QRFramePayload on success, null if the value cannot be
 * interpreted as a meow-decoder frame.
 *
 * Call order:
 *   1. FOUNTAIN: prefix check (fast)
 *   2. JSON envelope parse (slower, JSON.parse only if starts with '{')
 */
export function parseQRPayload(
  qrValue: string,
  expectedSessionId?: string,
): QRFramePayload | null {
  if (!qrValue || qrValue.length === 0) return null;

  // FOUNTAIN: format
  if (qrValue.startsWith(FOUNTAIN_PREFIX)) {
    return parseFountainPayload(qrValue);
  }

  // JSON envelope format
  return parseJsonPayload(qrValue, expectedSessionId);
}

// ── Internal Helpers ──────────────────────────────────────────────────────────

/**
 * Fast non-cryptographic string hash (djb2 variant).
 * Used only for synthetic index generation — NOT for security purposes.
 */
function simpleHash(s: string): number {
  let hash = 5381;
  for (let i = 0; i < s.length; i++) {
    // Bitwise OR 0 keeps it a 32-bit int
    hash = ((hash << 5) + hash + s.charCodeAt(i)) | 0;
  }
  // Return absolute value to ensure positive index
  return Math.abs(hash);
}
