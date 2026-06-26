/**
 * session.test.ts — verifies auto-derived session ids are valid (and don't use
 * crypto.getRandomValues, which crashes in Hermes).
 */

import { makeSessionId } from '../src/utils/session';
import { safeValidateRequest } from '../src/services/requestValidator';

describe('makeSessionId', () => {
  it('produces UUID-v4-format ids accepted by the capture-request schema', () => {
    const v4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    for (let i = 0; i < 300; i++) {
      const id = makeSessionId();
      expect(id).toMatch(v4);
      const result = safeValidateRequest({
        action: 'capture',
        session_id: id,
        expected_frames: 10,
        timeout_seconds: 60,
      });
      expect(result.success).toBe(true);
    }
  });

  it('produces distinct ids', () => {
    const ids = new Set(Array.from({ length: 100 }, () => makeSessionId()));
    expect(ids.size).toBe(100);
  });
});
