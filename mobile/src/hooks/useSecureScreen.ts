/**
 * useSecureScreen.ts — Platform-level screenshot / screen-recording defense.
 *
 * Android: FLAG_SECURE is set at the Activity window level in MainActivity.kt,
 *   which prevents screenshots, screen recordings, and hides content in the
 *   task switcher across ALL screens. No per-screen toggle needed; this hook
 *   exists for future per-screen granularity and to document the iOS path.
 *
 * iOS: applicationWillResignActive fires just before the OS captures a
 *   snapshot for the task switcher. We signal the component to swap in a
 *   privacy overlay so the snapshot contains a neutral placeholder rather
 *   than live capture data. The component reads `isBackgrounding` and renders
 *   a solid cover View on top of the camera feed.
 *
 * Call this hook at the top of CaptureScreen and ExportScreen.
 */

import { useState, useEffect } from 'react';
import { AppState, type AppStateStatus } from 'react-native';

export interface SecureScreenState {
  /** True between applicationWillResignActive and applicationDidBecomeActive.
   *  Consumers should render a privacy overlay when this is true. */
  isBackgrounding: boolean;
}

export function useSecureScreen(): SecureScreenState {
  const [isBackgrounding, setIsBackgrounding] = useState(false);

  useEffect(() => {
    // Hold the reveal-timer so we can cancel it if the state changes again
    // before the delay fires (e.g. rapid background → foreground → background).
    let revealTimer: ReturnType<typeof setTimeout> | undefined;

    const handleAppStateChange = (nextState: AppStateStatus): void => {
      // Cover the camera feed the moment the OS asks for a snapshot.
      // This fires approximately 100–200 ms before the task-switcher
      // screenshot is taken on both iOS and Android.
      if (nextState === 'inactive' || nextState === 'background') {
        clearTimeout(revealTimer);
        setIsBackgrounding(true);
      } else if (nextState === 'active') {
        // Small delay so the cover doesn't flash on fast foreground resume.
        revealTimer = setTimeout(() => setIsBackgrounding(false), 120);
      }
    };

    const sub = AppState.addEventListener('change', handleAppStateChange);
    return () => {
      sub.remove();
      clearTimeout(revealTimer);
    };
  }, []);

  return { isBackgrounding };
}
