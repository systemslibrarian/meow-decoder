/**
 * useStabilityMonitor.ts — Accelerometer-based device stability detection.
 *
 * Reads the device accelerometer at ~60Hz and computes shake magnitude
 * using the Euclidean distance from the previous reading. When magnitude
 * exceeds SHAKE_THRESHOLD_MS2, the device is deemed unstable and
 * the StabilityIndicator overlay is shown.
 *
 * Falls back gracefully if accelerometer is unavailable (simulator or
 * permission denied) — always reports isStable: true so it never blocks
 * capture on devices without the sensor.
 */

import { useState, useEffect, useRef } from 'react';
import { Accelerometer } from 'react-native-sensors';
import { SHAKE_THRESHOLD_MS2, STABILITY_WINDOW_MS } from '../constants/config';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface StabilityState {
  /** True when device appears steady enough for reliable QR scanning */
  isStable: boolean;
  /** Current shake magnitude in m/s² (0 on sensor unavailable) */
  shakeMagnitude: number;
  /** True if sensor hardware or permissions are unavailable */
  sensorUnavailable: boolean;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useStabilityMonitor(): StabilityState {
  const [isStable, setIsStable] = useState(true);
  const [shakeMagnitude, setShakeMagnitude] = useState(0);
  const [sensorUnavailable, setSensorUnavailable] = useState(false);

  // Rolling buffer of recent magnitudes for smoothing
  const magnitudeBuffer = useRef<{ value: number; time: number }[]>([]);
  const prevReading = useRef<{ x: number; y: number; z: number } | null>(null);

  useEffect(() => {
    let subscription: { unsubscribe: () => void } | null = null;

    try {
      // Accelerometer emits {x, y, z} in m/s²
      const observable = new Accelerometer({ updateInterval: 16 }); // ~60Hz
      subscription = observable.subscribe({
        next: ({ x, y, z }) => {
          const prev = prevReading.current;
          if (prev !== null) {
            // Delta magnitude: how much did the phone move since last reading?
            const dx = x - prev.x;
            const dy = y - prev.y;
            const dz = z - prev.z;
            const magnitude = Math.sqrt(dx * dx + dy * dy + dz * dz);

            const now = Date.now();
            magnitudeBuffer.current.push({ value: magnitude, time: now });

            // Evict readings outside the smoothing window
            const cutoff = now - STABILITY_WINDOW_MS;
            magnitudeBuffer.current = magnitudeBuffer.current.filter(
              (r) => r.time >= cutoff,
            );

            // Average magnitude over the rolling window
            const avg =
              magnitudeBuffer.current.reduce((acc, r) => acc + r.value, 0) /
              Math.max(magnitudeBuffer.current.length, 1);

            setShakeMagnitude(avg);
            setIsStable(avg < SHAKE_THRESHOLD_MS2);
          }
          prevReading.current = { x, y, z };
        },
        error: () => {
          // Sensor unavailable — default to stable so capture isn't blocked
          setSensorUnavailable(true);
          setIsStable(true);
        },
      });
    } catch {
      // react-native-sensors may throw if not linked
      setSensorUnavailable(true);
    }

    return () => {
      subscription?.unsubscribe();
      magnitudeBuffer.current = [];
      prevReading.current = null;
    };
  }, []);

  return { isStable, shakeMagnitude, sensorUnavailable };
}
