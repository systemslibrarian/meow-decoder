/**
 * requestValidator.ts — Zod schema validation for capture requests.
 *
 * Every capture request loaded from disk or entered manually is validated
 * against this schema before the app acts on it. This prevents malformed
 * or malicious JSON from corrupting session state.
 *
 * SECURITY: Strict schema — no extra fields allowed; strict UUID check;
 * numeric bounds enforced.
 */

import { z } from 'zod';
import { DEFAULT_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS } from '../constants/config';

// ── Schemas ───────────────────────────────────────────────────────────────────

/**
 * Zod schema for a CaptureRequest loaded from the CLI.
 *
 * Enforces:
 *  - action must be exactly "capture"
 *  - session_id must be a valid UUID v4
 *  - expected_frames must be a positive integer ≤ 10,000
 *  - timeout_seconds optional, defaulting to 60, max 600
 */
export const CaptureRequestSchema = z
  .object({
    action: z.literal('capture'),
    session_id: z
      .string()
      .uuid({ message: 'session_id must be a valid UUID v4' }),
    expected_frames: z
      .number({ invalid_type_error: 'expected_frames must be a number' })
      .int({ message: 'expected_frames must be an integer' })
      .positive({ message: 'expected_frames must be positive' })
      .max(10_000, { message: 'expected_frames must not exceed 10,000' }),
    timeout_seconds: z
      .number({ invalid_type_error: 'timeout_seconds must be a number' })
      .int({ message: 'timeout_seconds must be an integer' })
      .positive({ message: 'timeout_seconds must be positive' })
      .max(MAX_TIMEOUT_SECONDS, {
        message: `timeout_seconds must not exceed ${MAX_TIMEOUT_SECONDS}`,
      })
      .optional()
      .default(DEFAULT_TIMEOUT_SECONDS),
  })
  .strict(); // Reject unexpected fields — prevents injection of extra properties

export type ValidatedCaptureRequest = z.infer<typeof CaptureRequestSchema>;

// ── Validation Helpers ────────────────────────────────────────────────────────

/**
 * Validates and parses a raw JSON value as a CaptureRequest.
 *
 * @throws {z.ZodError} with detailed issue list on validation failure
 * @throws {SyntaxError} if rawJson is a string and not valid JSON
 */
export function validateRequest(raw: unknown): ValidatedCaptureRequest {
  return CaptureRequestSchema.parse(raw);
}

/**
 * Safe validation variant — returns { success, data } or { success, error }
 * without throwing. Prefer this in UI code where you want to inspect
 * validation errors rather than catch exceptions.
 */
export function safeValidateRequest(
  raw: unknown,
): z.SafeParseReturnType<unknown, ValidatedCaptureRequest> {
  return CaptureRequestSchema.safeParse(raw);
}

/**
 * Parses a JSON string and validates it as a CaptureRequest.
 *
 * Combines JSON.parse with Zod validation so callers need only one
 * try/catch block for the full load-from-string flow.
 *
 * @throws {SyntaxError} on invalid JSON
 * @throws {z.ZodError} on schema violation
 */
export function validateRequestFromString(jsonString: string): ValidatedCaptureRequest {
  const raw: unknown = JSON.parse(jsonString);
  return validateRequest(raw);
}

/**
 * Returns a user-friendly error message for the first Zod validation failure.
 */
export function firstErrorMessage(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return 'Invalid capture request';
  const path = issue.path.join('.');
  return path ? `${path}: ${issue.message}` : issue.message;
}
