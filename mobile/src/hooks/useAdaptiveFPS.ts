/**
 * useAdaptiveFPS.ts — Adaptive camera frame-rate hook.
 *
 * Returns the best FPS for the current device state:
 *  - Respects device ProMotion / high-refresh capability (up to 60 fps)
 *  - Drops to 15 fps when thermal state is "serious" or "critical" to avoid
 *    throttling the CPU further and draining the battery under load
 *
 * The hook re-evaluates whenever the device reports a new thermal state.
 * On Android, ThermalManager callbacks are surfaced via the React Native
 * DeviceEventEmitter since RN 0.71. On iOS, NSProcessInfo thermal notifications
 * are similarly bridged.
 *
 * Falls back gracefully when the native thermal API is unavailable (old OS,
 * simulator) — just returns a sensible default fps.
 */

import { useState, useEffect } from 'react';
import { NativeEventEmitter, NativeModules, Platform } from 'react-native';
import type { CameraDevice } from 'react-native-vision-camera';

// ── Types ─────────────────────────────────────────────────────────────────────

/** Mirrors Android ThermalStatus / iOS NSProcessInfoThermalState ordinal */
type ThermalState = 'nominal' | 'fair' | 'serious' | 'critical';

// ── Constants ─────────────────────────────────────────────────────────────────

const FPS_NORMAL = 30;
const FPS_PROMO = 60;
const FPS_THROTTLED = 15;

// Thermal states that indicate we should pull back frame rate
const HOT_STATES: ThermalState[] = ['serious', 'critical'];

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * Returns the adaptive target FPS given the current thermal state and the
 * capabilities of the supplied camera device.
 *
 * @param device - Active VisionCamera device (may be undefined during init)
 */
export function useAdaptiveFPS(device: CameraDevice | undefined): number {
  const [thermalState, setThermalState] = useState<ThermalState>('nominal');

  // Subscribe to thermal state changes if the native module is available
  useEffect(() => {
    // React Native does not ship a standard thermal module. The community
    // convention is `RNThermal` (for custom bridges) or DeviceInfo's
    // getThermalState(). We use a best-effort approach: if the module exists,
    // subscribe; otherwise stay at 'nominal' forever.
    const thermalModule = NativeModules['RNThermal'] as
      | { addListener: (event: string) => void; removeListeners: (count: number) => void }
      | undefined;

    if (!thermalModule) return;

    // Suppress the generic-constraint mismatch — NativeEventEmitter works at runtime
    // with any object that has addListener/removeListeners; the tighter static types
    // are only needed for the sub.remove() API we actually call below.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const emitter = new NativeEventEmitter(thermalModule as any);
    const sub = emitter.addListener(
      'thermalStateDidChange',
      (state: { status: string }) => {
        const normalised = state.status?.toLowerCase() as ThermalState | undefined;
        if (normalised) setThermalState(normalised);
      },
    );

    return () => sub.remove();
  }, []);

  if (HOT_STATES.includes(thermalState)) {
    return FPS_THROTTLED;
  }

  // ProMotion: use 60 fps on capable devices if iOS 16+ or Android 12+ signal
  // frame rates >30. Vision Camera exposes this via device.formats.
  // Guard against null/empty formats — some Android emulators expose device
  // objects but have EncoderProfiles with null VideoProfile entries, causing
  // NullPointerException if VisionCamera tries to query codec capabilities.
  if (device && Platform.OS === 'ios') {
    try {
      const supports60 = Array.isArray(device.formats) && device.formats.some(
        (f) => f != null && f.maxFps !== undefined && f.maxFps >= 60,
      );
      if (supports60) return FPS_PROMO;
    } catch {
      // Format query failed — fall through to FPS_NORMAL
    }
  }

  return FPS_NORMAL;
}
