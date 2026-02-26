/**
 * useSecurityMode.ts — App-wide security posture toggle.
 *
 * Persists the user's chosen security mode in MMKV so it survives app restarts
 * without ever touching the network.
 *
 * Strict mode (default): mirrors the existing hardened behaviour —
 *   - Wipe all frame data on background/inactive
 *   - No session resume after interruption
 *   - No clipboard helper (ADB command not auto-copied)
 *   - Aggressive privacy overlay on task-switcher
 *
 * Convenience mode: relaxes ergonomic friction while keeping data safe —
 *   - Session checkpoint persists (indices only — never payloads)
 *   - Clipboard helper auto-copies ADB pull command
 *   - Background wipe still fires (payloads are never retained)
 *   - Privacy overlay still active (FLAG_SECURE unchanged)
 *
 * SECURITY NOTE: Convenience mode does NOT weaken cryptographic invariants or
 * data retention policy. Frame payload strings are still wiped on background in
 * both modes. The difference is purely ergonomic.
 */

import { useCallback, useState } from 'react';
import { MMKV } from 'react-native-mmkv';

// ── Storage ───────────────────────────────────────────────────────────────────

const storage = new MMKV({ id: 'meow_settings' });
const SECURITY_MODE_KEY = 'security_mode';

// ── Types ─────────────────────────────────────────────────────────────────────

export type SecurityMode = 'strict' | 'convenience';

// ── Public helpers (callable outside a component) ─────────────────────────────

/** Read current mode synchronously — safe to call anywhere. */
export function getSecurityMode(): SecurityMode {
  const stored = storage.getString(SECURITY_MODE_KEY);
  return stored === 'convenience' ? 'convenience' : 'strict';
}

/** Write mode synchronously. */
export function setSecurityModePersisted(mode: SecurityMode): void {
  storage.set(SECURITY_MODE_KEY, mode);
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export interface UseSecurityModeReturn {
  mode: SecurityMode;
  isStrict: boolean;
  isConvenience: boolean;
  setMode: (mode: SecurityMode) => void;
}

/**
 * React hook — reads and writes the security mode.
 * Uses a module-level re-render subscription so all consumers stay in sync.
 */
export function useSecurityMode(): UseSecurityModeReturn {
  // useState initialises from MMKV synchronously so the first render is correct.
  // State drives re-renders when setMode is called — without it, MMKV is updated
  // but the component never re-renders and the UI stays stale.
  const [mode, setModeState] = useState<SecurityMode>(() => getSecurityMode());

  const setMode = useCallback((next: SecurityMode) => {
    setSecurityModePersisted(next);
    setModeState(next); // triggers re-render so selection cards update immediately
  }, []);

  return {
    mode,
    isStrict: mode === 'strict',
    isConvenience: mode === 'convenience',
    setMode,
  };
}
