/**
 * useAudioCues.ts — Optional audio feedback for capture milestones.
 *
 * Plays short, subtle audio cues at key capture milestones when the user has
 * opted in via the Settings screen. Designed for:
 *   - Eyes-free operation (accessibility, holding phone at arm's length)
 *   - Professional capture (headphones in loud environments)
 *
 * Uses react-native-sound for native playback. If the package is not linked
 * (e.g. Expo Go, or dev builds without native modules), the hook degrades
 * gracefully to no-ops.
 *
 * Audio files are bundled as raw resources:
 *   Android: android/app/src/main/res/raw/
 *   iOS:     added to the Xcode project bundle
 *
 * SECURITY: Pure playback — no microphone, no recording, no network.
 * MMKV is used only to read the user's preference; no data is persisted.
 *
 * @example
 *   const { play } = useAudioCues();
 *   play('milestone');   // ~100ms soft chime
 *   play('complete');    // ~200ms success ding
 *   play('error');       // ~150ms gentle error tone
 */

import { useCallback, useRef, useEffect } from 'react';
import { MMKV } from 'react-native-mmkv';

// ── Types ─────────────────────────────────────────────────────────────────────

export type AudioCue = 'milestone' | 'complete' | 'error' | 'start';

export interface UseAudioCuesReturn {
  /** Play a named audio cue. No-op if sounds are disabled or unavailable. */
  play: (cue: AudioCue) => void;
  /** Whether the audio subsystem is available (react-native-sound linked). */
  isAvailable: boolean;
}

// ── MMKV settings key ─────────────────────────────────────────────────────────

const SOUND_ENABLED_KEY = 'sound_enabled';

let _storage: MMKV | null = null;
function getStorage(): MMKV {
  if (!_storage) {
    _storage = new MMKV({ id: 'meow-settings' });
  }
  return _storage;
}

/**
 * Read the user's sound preference from MMKV.
 * Defaults to false (opt-in) to respect the user's attention.
 */
export function isSoundEnabled(): boolean {
  try {
    return getStorage().getBoolean(SOUND_ENABLED_KEY) ?? false;
  } catch {
    return false;
  }
}

/** Update the user's sound preference in MMKV. */
export function setSoundEnabled(enabled: boolean): void {
  try {
    getStorage().set(SOUND_ENABLED_KEY, enabled);
  } catch {
    // MMKV unavailable — ignore
  }
}

// ── Sound loader (lazy, safe) ─────────────────────────────────────────────────

/**
 * We lazy-require react-native-sound at runtime so the app doesn't crash
 * if the native module isn't linked (e.g. in Expo Go or Jest).
 */
let Sound: any = null;
let soundAvailable = false;

function tryLoadSound(): boolean {
  // react-native-sound is intentionally NOT a dependency of this build, and no
  // cue assets are bundled. A static require('react-native-sound') is resolved
  // by Metro at build time; with the package absent the release bundle throws
  // "Requiring unknown module 'undefined'" at runtime and crashes the capture
  // screen on mount. So audio cues are hard-disabled here (the hook degrades to
  // a no-op). To re-enable: add react-native-sound + the cue assets, then
  // restore the guarded require below.
  Sound = {};
  soundAvailable = false;
  return soundAvailable;
}

// Map cue names to bundled resource file names (without extension).
// The actual .wav/.mp3 files live in:
//   Android: android/app/src/main/res/raw/meow_<name>.wav
//   iOS:     ios/MeowCapture/meow_<name>.wav (bundled resource)
const CUE_FILES: Record<AudioCue, string> = {
  start: 'meow_start',
  milestone: 'meow_milestone',
  complete: 'meow_complete',
  error: 'meow_error',
};

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useAudioCues(): UseAudioCuesReturn {
  const soundCacheRef = useRef<Record<string, any>>({});
  const isAvailable = tryLoadSound();

  // Preload all cues on mount so playback is near-instant
  useEffect(() => {
    if (!isAvailable) return;
    const cache = soundCacheRef.current;

    for (const [cue, filename] of Object.entries(CUE_FILES)) {
      if (!cache[cue]) {
        try {
          const s = new Sound(filename, Sound.MAIN_BUNDLE, (err: any) => {
            if (err) {
              // File not bundled yet — degrade gracefully
              delete cache[cue];
            }
          });
          s.setVolume(0.3); // subtle
          cache[cue] = s;
        } catch {
          // native module error — ignore
        }
      }
    }

    return () => {
      // Release native resources on unmount
      for (const s of Object.values(cache)) {
        try { s?.release?.(); } catch { /* ignore */ }
      }
      soundCacheRef.current = {};
    };
  }, [isAvailable]);

  const play = useCallback((cue: AudioCue) => {
    if (!isAvailable || !isSoundEnabled()) return;
    const s = soundCacheRef.current[cue];
    if (s) {
      try {
        s.stop(() => {
          s.play();
        });
      } catch {
        // ignore playback errors
      }
    }
  }, [isAvailable]);

  return { play, isAvailable };
}
