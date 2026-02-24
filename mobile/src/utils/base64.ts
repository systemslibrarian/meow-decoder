/**
 * base64.ts — Base64 validation helpers.
 *
 * SECURITY: This module intentionally provides NO base64 decoding.
 * Frame payload content is opaque to the mobile app — we validate that
 * data fields contain valid base64, but never decode or examine the content.
 * All decryption happens on trusted air-gapped computers via the CLI.
 */

/** Regex matching standard base64 (with A-Za-z0-9+/= padding) */
const BASE64_STANDARD_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/** Regex matching URL-safe base64 (A-Za-z0-9-_ no padding) */
const BASE64_URL_SAFE_RE = /^[A-Za-z0-9_-]*$/;

/**
 * Returns true if the string is syntactically valid base64.
 *
 * Accepts both standard (RFC 4648 §4) and URL-safe (RFC 4648 §5) variants.
 * Does NOT decode the content — it remains opaque.
 *
 * An empty string is considered valid (encodes zero bytes).
 */
export function isValidBase64(s: string): boolean {
  if (typeof s !== 'string') return false;
  if (s.length === 0) return true;

  // Must be a multiple of 4 chars (standard) — or URL-safe (any length)
  if (s.includes('=')) {
    // Standard base64 with padding
    return s.length % 4 === 0 && BASE64_STANDARD_RE.test(s);
  }

  // Standard without padding or URL-safe
  return BASE64_STANDARD_RE.test(s) || BASE64_URL_SAFE_RE.test(s);
}

/**
 * Estimates the number of decoded bytes a base64 string represents.
 *
 * Formula: floor(base64Length × 3 / 4) - padding chars.
 * Useful for size/memory estimation only; never actually decodes.
 */
export function estimateDecodedBytes(b64: string): number {
  if (!b64 || b64.length === 0) return 0;
  const padChars = (b64.match(/=/g) ?? []).length;
  return Math.floor((b64.length * 3) / 4) - padChars;
}

/**
 * Checks whether a supposed base64 string appears to contain valid fountain
 * code droplet data by validating it is non-empty and within the expected
 * size range for a QR code payload.
 *
 * MAX_QR_PAYLOAD_BYTES: QR version 40-L capacity is ~2953 bytes.
 * After base64 encoding that is ceil(2953 * 4/3) ≈ 3940 chars.
 */
export function isValidDropletBase64(s: string): boolean {
  if (!isValidBase64(s)) return false;
  const estimatedBytes = estimateDecodedBytes(s);
  return estimatedBytes > 0 && estimatedBytes <= 3940;
}
