/**
 * qrDecoder.ts — QR payload parsing and validation.
 *
 * Handles the boundary between raw QR string values and typed CapturedFrame
 * objects. All QR formats produced by the web demo and CLI are supported:
 *
 *  Multi-frame (fountain coded — scan many, decode from any ~67%):
 *   1. FOUNTAIN:<k>:<block_size>:<length>:<base64>
 *      Web demo animated QR / CLI fountain output.
 *
 *  Single-frame (scan once — full payload in one QR code):
 *   2. MEOW:<base64>      — Standard AES-256-GCM (all modes)
 *   3. FS:<base64>        — Forward Secrecy / X25519 ephemeral (MEOW3)
 *   4. QUANTUM:<base64>   — Schrödinger dual-secret mode
 *   5. HYBRID-PQ:<base64> — Post-quantum hybrid (ML-KEM-768/1024 + X25519)
 *   6. DURESS:<base64>    — Duress / panic-password mode
 *
 *  Legacy chunked (web demo legacy animated format — large payloads only):
 *   7. MEOW-N/total:<base64>   — N-th chunk of a split MEOW: payload
 *   8. DURESS-N/total:<base64> — N-th chunk of a large DURESS: payload
 *
 *  JSON envelope (CLI bridge mode):
 *   9. {"index": N, "data": "<base64>", "session_id"?: "..."}
 *
 * For single-frame formats (MEOW/FS/QUANTUM/HYBRID-PQ/DURESS), the entire
 * QR string is stored as-is in the data field (prefix included) so the
 * desktop decoder can identify the format from the prefix. Index is derived
 * from a content hash for deduplication.
 *
 * SECURITY: This module NEVER decodes the data field content.
 * It validates structure only. All payload content is treated as opaque.
 */

import { isValidBase64 } from '../utils/base64';
import type { QRFramePayload } from '../types/capture';

// ── Prefix Constants ──────────────────────────────────────────────────────────

/** All QR payload prefixes emitted by the meow-decoder web demo */
export const QR_PREFIXES = {
  FOUNTAIN: 'FOUNTAIN:',
  MEOW: 'MEOW:',
  FORWARD_SECRECY: 'FS:',
  QUANTUM: 'QUANTUM:',
  HYBRID_PQ: 'HYBRID-PQ:',
  DURESS: 'DURESS:',
  MEOW_CHUNKED: 'MEOW-',   // Legacy: MEOW-N/total:<b64>
  DURESS_CHUNKED: 'DURESS-', // Legacy: DURESS-N/total:<b64> (large duress payloads)
} as const;

/** All single-frame prefixes (entire QR string = one complete payload) */
const SINGLE_FRAME_PREFIXES = [
  QR_PREFIXES.MEOW,
  QR_PREFIXES.FORWARD_SECRECY,
  QR_PREFIXES.QUANTUM,
  QR_PREFIXES.HYBRID_PQ,
  QR_PREFIXES.DURESS,
] as const;

// ── Fountain Format ───────────────────────────────────────────────────────────

/**
 * Parses a FOUNTAIN: prefixed QR payload string.
 *
 * Format: "FOUNTAIN:<k_blocks>:<block_size>:<original_length>:<base64_droplet>"
 *
 * The droplet index is derived from a hash of the base64 payload to deduplicate
 * frames — we don't need to unpack the binary droplet structure on mobile.
 */
export function parseFountainPayload(qrValue: string): QRFramePayload | null {
  if (!qrValue.startsWith(QR_PREFIXES.FOUNTAIN)) return null;

  const parts = qrValue.split(':');
  // "FOUNTAIN" + k_blocks + block_size + original_length + base64_droplet = 5 parts
  if (parts.length < 5) return null;

  const kBlocks = parseInt(parts[1] ?? '', 10);
  const dropletB64 = parts.slice(4).join(':'); // re-join in case base64 contains ':'

  if (!Number.isFinite(kBlocks) || kBlocks <= 0) return null;
  if (!dropletB64 || !isValidBase64(dropletB64)) return null;

  // Derive a stable dedup index from the droplet content.
  const index = simpleHash(dropletB64.slice(0, 48));
  return { index, data: qrValue }; // store full string — desktop needs metadata
}

// ── Single-Frame Formats ──────────────────────────────────────────────────────

/**
 * Parses a single-frame QR payload (MEOW:, FS:, QUANTUM:, HYBRID-PQ:, DURESS:).
 *
 * The entire QR string (including prefix) is the frame data — the desktop
 * decoder identifies the encryption mode from the prefix.
 * Index is derived from a content hash (dedup guard against scanning twice).
 */
export function parseSingleFramePayload(qrValue: string): QRFramePayload | null {
  const matched = SINGLE_FRAME_PREFIXES.some(prefix => qrValue.startsWith(prefix));
  if (!matched) return null;
  if (qrValue.length < 10) return null; // sanity check — must have actual content

  // Use a hash of the full string for stable dedup index
  const index = simpleHash(qrValue);
  return { index, data: qrValue };
}

// ── Legacy Chunked Format ─────────────────────────────────────────────────────

/**
 * Shared implementation for MEOW-N/total: and DURESS-N/total: chunked formats.
 * @param rest  Everything after the known prefix, e.g. "2/5:AABgAC..."
 */
function parseChunkedRest(qrValue: string, rest: string): QRFramePayload | null {
  const slashIdx = rest.indexOf('/');
  const colonIdx = rest.indexOf(':');
  if (slashIdx === -1 || colonIdx === -1 || colonIdx < slashIdx) return null;

  const nStr = rest.slice(0, slashIdx);
  const n = parseInt(nStr, 10);
  if (!Number.isFinite(n) || n < 1) return null;

  const b64 = rest.slice(colonIdx + 1);
  if (!b64 || !isValidBase64(b64)) return null;

  return { index: n - 1, data: qrValue }; // convert 1-based to 0-based index
}

/**
 * Parses a legacy web-demo chunked QR payload.
 *
 * Handles both formats the web demo produces for large payloads:
 *   - MEOW-N/total:<base64>   — split MEOW: payload
 *   - DURESS-N/total:<base64> — split DURESS: payload
 *
 * Uses N (1-based chunk number) as the frame index for ordered reassembly.
 */
export function parseLegacyChunkedPayload(qrValue: string): QRFramePayload | null {
  if (qrValue.startsWith(QR_PREFIXES.MEOW_CHUNKED)) {
    const rest = qrValue.slice(QR_PREFIXES.MEOW_CHUNKED.length);
    return parseChunkedRest(qrValue, rest);
  }

  if (qrValue.startsWith(QR_PREFIXES.DURESS_CHUNKED)) {
    const rest = qrValue.slice(QR_PREFIXES.DURESS_CHUNKED.length);
    return parseChunkedRest(qrValue, rest);
  }

  return null;
}

// ── JSON Envelope Format ──────────────────────────────────────────────────────

/**
 * Parses a JSON-envelope QR payload (CLI bridge mode).
 *
 * Expected shape: { index: number, data: string, session_id?: string }
 * Extra fields are silently ignored.
 */
export function parseJsonPayload(
  qrValue: string,
  expectedSessionId?: string,
): QRFramePayload | null {
  if (!qrValue.startsWith('{')) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(qrValue);
  } catch {
    return null;
  }

  if (typeof parsed !== 'object' || parsed === null) return null;
  const obj = parsed as Record<string, unknown>;

  if (typeof obj['index'] !== 'number' || !Number.isFinite(obj['index'])) return null;
  if (typeof obj['data'] !== 'string') return null;
  if (!isValidBase64(obj['data'])) return null;

  if (
    typeof obj['session_id'] === 'string' &&
    expectedSessionId !== undefined &&
    obj['session_id'] !== expectedSessionId
  ) {
    return null; // wrong session
  }

  return {
    index: obj['index'] as number,
    data: obj['data'] as string,
    // Conditionally include session_id only when present (exactOptionalPropertyTypes)
    ...(typeof obj['session_id'] === 'string' ? { session_id: obj['session_id'] } : {}),
  };
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

/**
 * Attempts to parse any supported QR payload format into a CapturedFrame.
 *
 * Priority order (fastest/most common first):
 *   1. FOUNTAIN:                        — multi-frame fountain coded
 *   2. MEOW: / FS: / QUANTUM: / HYBRID-PQ: / DURESS: — single-frame
 *   3. MEOW-N/total: / DURESS-N/total:  — legacy chunked
 *   4. JSON envelope                    — CLI bridge mode
 *
 * Returns null for unrecognised QR content (skip silently).
 */
export function parseQRPayload(
  qrValue: string,
  expectedSessionId?: string,
): QRFramePayload | null {
  if (!qrValue || qrValue.length === 0) return null;

  if (qrValue.startsWith(QR_PREFIXES.FOUNTAIN)) {
    return parseFountainPayload(qrValue);
  }

  // Single-frame web demo formats
  const sf = parseSingleFramePayload(qrValue);
  if (sf !== null) return sf;

  // Legacy chunked (MEOW-N/total: and DURESS-N/total:)
  if (
    qrValue.startsWith(QR_PREFIXES.MEOW_CHUNKED) ||
    qrValue.startsWith(QR_PREFIXES.DURESS_CHUNKED)
  ) {
    return parseLegacyChunkedPayload(qrValue);
  }

  // JSON envelope (CLI bridge)
  return parseJsonPayload(qrValue, expectedSessionId);
}

/**
 * Returns true if a QR string looks like any supported meow-decoder format.
 * Useful for the GIF auto-detection heuristic in useQRScanner.
 */
export function isMeowQRPayload(qrValue: string): boolean {
  return parseQRPayload(qrValue) !== null;
}

// ── Internal Helpers ──────────────────────────────────────────────────────────

/**
 * Derive how many source frames to expect from a single scanned transfer frame,
 * so capture can start straight from a looping animation without a setup/request
 * QR. Returns null if the QR isn't a recognised meow transfer frame.
 *
 * Counts by format:
 *   - FOUNTAIN:<k>:<blockSize>:<len>:<b64>  → k (source block count)
 *   - MEOW-N/total: / DURESS-N/total:       → total (chunk count)
 *   - MEOW:/FS:/QUANTUM:/HYBRID-PQ:/DURESS: → 1 (single-frame transfer)
 */
export function deriveExpectedFramesFromFrame(value: string): number | null {
  if (value.startsWith(QR_PREFIXES.FOUNTAIN)) {
    const k = parseInt(value.split(':')[1] ?? '', 10);
    return Number.isFinite(k) && k > 0 ? Math.min(k, 10_000) : null;
  }
  const chunked = /^(?:MEOW|DURESS)-\d+\/(\d+):/.exec(value);
  if (chunked) {
    const total = parseInt(chunked[1] ?? '', 10);
    return Number.isFinite(total) && total > 0 ? Math.min(total, 10_000) : null;
  }
  if (/^(?:MEOW|FS|QUANTUM|HYBRID-PQ|DURESS):/.test(value)) return 1;
  return null;
}

/**
 * Fast non-cryptographic string hash (djb2 variant).
 * Used only for synthetic index generation — NOT for security purposes.
 */
export function simpleHash(s: string): number {
  let hash = 5381;
  for (let i = 0; i < s.length; i++) {
    hash = ((hash << 5) + hash + s.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}
