/**
 * requestValidator.test.ts — Unit tests for Zod capture request validation.
 *
 * Verifies that valid requests pass and malformed/incomplete/injected
 * requests are properly rejected with useful error messages.
 */

import { z } from 'zod';
import {
  validateRequest,
  safeValidateRequest,
  validateRequestFromString,
  firstErrorMessage,
} from '../src/services/requestValidator';

// ── Valid requests ─────────────────────────────────────────────────────────────

describe('validateRequest — valid inputs', () => {
  const validRequest = {
    action: 'capture',
    session_id: '550e8400-e29b-41d4-a716-446655440000',
    expected_frames: 45,
    timeout_seconds: 60,
  };

  it('accepts a fully valid request', () => {
    const result = validateRequest(validRequest);
    expect(result.action).toBe('capture');
    expect(result.session_id).toBe('550e8400-e29b-41d4-a716-446655440000');
    expect(result.expected_frames).toBe(45);
    expect(result.timeout_seconds).toBe(60);
  });

  it('applies default timeout of 60 when omitted', () => {
    const { timeout_seconds: _, ...noTimeout } = validRequest;
    const result = validateRequest(noTimeout);
    expect(result.timeout_seconds).toBe(60);
  });

  it('accepts expected_frames of 1', () => {
    const result = validateRequest({ ...validRequest, expected_frames: 1 });
    expect(result.expected_frames).toBe(1);
  });

  it('accepts expected_frames of 10000', () => {
    const result = validateRequest({ ...validRequest, expected_frames: 10000 });
    expect(result.expected_frames).toBe(10000);
  });

  it('accepts timeout_seconds of 600', () => {
    const result = validateRequest({ ...validRequest, timeout_seconds: 600 });
    expect(result.timeout_seconds).toBe(600);
  });
});

// ── Invalid action ─────────────────────────────────────────────────────────────

describe('validateRequest — invalid action', () => {
  it('rejects action other than "capture"', () => {
    expect(() =>
      validateRequest({
        action: 'decode',
        session_id: '550e8400-e29b-41d4-a716-446655440000',
        expected_frames: 10,
      }),
    ).toThrow(z.ZodError);
  });

  it('rejects missing action', () => {
    expect(() =>
      validateRequest({
        session_id: '550e8400-e29b-41d4-a716-446655440000',
        expected_frames: 10,
      }),
    ).toThrow(z.ZodError);
  });
});

// ── Invalid session_id ─────────────────────────────────────────────────────────

describe('validateRequest — invalid session_id', () => {
  const base = {
    action: 'capture',
    expected_frames: 10,
    timeout_seconds: 60,
  };

  it('rejects non-UUID string', () => {
    expect(() => validateRequest({ ...base, session_id: 'not-a-uuid' })).toThrow(
      z.ZodError,
    );
  });

  it('rejects empty string session_id', () => {
    expect(() => validateRequest({ ...base, session_id: '' })).toThrow(z.ZodError);
  });

  it('rejects numeric session_id', () => {
    expect(() => validateRequest({ ...base, session_id: 12345 })).toThrow(z.ZodError);
  });

  it('rejects missing session_id', () => {
    expect(() => validateRequest({ ...base })).toThrow(z.ZodError);
  });
});

// ── Invalid expected_frames ────────────────────────────────────────────────────

describe('validateRequest — invalid expected_frames', () => {
  const base = {
    action: 'capture',
    session_id: '550e8400-e29b-41d4-a716-446655440000',
    timeout_seconds: 60,
  };

  it('rejects expected_frames of 0', () => {
    expect(() => validateRequest({ ...base, expected_frames: 0 })).toThrow(z.ZodError);
  });

  it('rejects negative expected_frames', () => {
    expect(() => validateRequest({ ...base, expected_frames: -1 })).toThrow(z.ZodError);
  });

  it('rejects expected_frames over 10000', () => {
    expect(() => validateRequest({ ...base, expected_frames: 10001 })).toThrow(z.ZodError);
  });

  it('rejects fractional expected_frames', () => {
    expect(() => validateRequest({ ...base, expected_frames: 3.5 })).toThrow(z.ZodError);
  });

  it('rejects string expected_frames', () => {
    expect(() => validateRequest({ ...base, expected_frames: '45' })).toThrow(z.ZodError);
  });
});

// ── Extra fields strict rejection ──────────────────────────────────────────────

describe('validateRequest — strict extra field rejection', () => {
  it('rejects objects with extra fields', () => {
    expect(() =>
      validateRequest({
        action: 'capture',
        session_id: '550e8400-e29b-41d4-a716-446655440000',
        expected_frames: 10,
        timeout_seconds: 60,
        injected_field: 'evil',
      }),
    ).toThrow(z.ZodError);
  });

  it('rejects objects with prototype pollution attempt', () => {
    expect(() =>
      validateRequest({
        action: 'capture',
        session_id: '550e8400-e29b-41d4-a716-446655440000',
        expected_frames: 10,
        __proto__: { isAdmin: true },
      }),
    ).toThrow(z.ZodError);
  });
});

// ── Safe parse variant ─────────────────────────────────────────────────────────

describe('safeValidateRequest', () => {
  it('returns success: true for valid input', () => {
    const result = safeValidateRequest({
      action: 'capture',
      session_id: '550e8400-e29b-41d4-a716-446655440000',
      expected_frames: 10,
    });
    expect(result.success).toBe(true);
  });

  it('returns success: false for invalid input without throwing', () => {
    const result = safeValidateRequest({ action: 'hack' });
    expect(result.success).toBe(false);
  });
});

// ── String parse ───────────────────────────────────────────────────────────────

describe('validateRequestFromString', () => {
  it('parses and validates valid JSON string', () => {
    const json = JSON.stringify({
      action: 'capture',
      session_id: '550e8400-e29b-41d4-a716-446655440000',
      expected_frames: 42,
    });
    const result = validateRequestFromString(json);
    expect(result.expected_frames).toBe(42);
  });

  it('throws SyntaxError on invalid JSON', () => {
    expect(() => validateRequestFromString('{not valid json')).toThrow(SyntaxError);
  });

  it('throws ZodError on valid JSON with wrong schema', () => {
    const json = JSON.stringify({ action: 'decode' });
    expect(() => validateRequestFromString(json)).toThrow(z.ZodError);
  });
});

// ── Error message helper ───────────────────────────────────────────────────────

describe('firstErrorMessage', () => {
  it('returns a readable message for uuid error', () => {
    const result = safeValidateRequest({
      action: 'capture',
      session_id: 'not-uuid',
      expected_frames: 10,
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const msg = firstErrorMessage(result.error);
      expect(msg).toBeTruthy();
      expect(typeof msg).toBe('string');
    }
  });
});
