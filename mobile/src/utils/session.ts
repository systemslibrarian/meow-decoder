/**
 * session.ts — session-id generation for auto-derived capture sessions.
 */

/**
 * Generate a UUID-v4-format string for an auto-derived capture session.
 *
 * Intentionally NOT cryptographic (uses Math.random): React Native's Hermes
 * runtime has no `crypto.getRandomValues`, so the `uuid` package throws at
 * runtime. This id is only a local session label — when capture is started
 * straight from a scanned transfer frame, the frames carry no session to match
 * against — so non-cryptographic randomness is acceptable here.
 */
export function makeSessionId(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
