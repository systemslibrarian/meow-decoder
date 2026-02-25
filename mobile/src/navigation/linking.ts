/**
 * linking.ts — React Navigation deep-link configuration.
 *
 * URL scheme: meow://
 *
 * Supported routes:
 *   meow://capture?session_id=<uuid>&expected_frames=<n>[&timeout_seconds=<n>]
 *     → Navigates to CaptureScreen with a pre-built CaptureRequest.
 *       All query parameters are validated with Zod before use.
 *
 * The URL scheme must be registered in:
 *   Android: AndroidManifest.xml   (intent-filter with scheme "meow")
 *   iOS:     Info.plist            (CFBundleURLSchemes = ["meow"])
 *
 * Security note: deep-link payloads are untrusted. Zod validation ensures
 * malformed URLs never reach the capture state machine.
 */

import type { LinkingOptions } from '@react-navigation/native';
import { Linking } from 'react-native';
import { z } from 'zod';
import { DEFAULT_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS } from '../constants/config';
import type { RootStackParamList } from '../types/navigation';

// ── Schema ────────────────────────────────────────────────────────────────────

const CaptureQuerySchema = z.object({
  session_id: z.string().uuid(),
  expected_frames: z.coerce.number().int().min(1).max(10_000),
  timeout_seconds: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_TIMEOUT_SECONDS)
    .optional()
    .default(DEFAULT_TIMEOUT_SECONDS),
});

// ── Config ────────────────────────────────────────────────────────────────────

export const linking: LinkingOptions<RootStackParamList> = {
  prefixes: ['meow://'],
  config: {
    screens: {
      // The Capture screen is the only deep-link target.
      // React Navigation will call `getStateFromPath` to parse query params
      // into the correct `request` param shape.
      Capture: 'capture',
    },
  },
  // Custom getStateFromPath: parse + validate incoming deep-link URL
  getStateFromPath(path, options) {
    // Attempt default parse first to get the raw query object
    const defaultParser = require('@react-navigation/native').getStateFromPath;
    const defaultState = defaultParser(path, options) as
      | { routes: Array<{ name: string; params?: Record<string, unknown> }> }
      | undefined;

    if (!defaultState) return undefined;

    const captureRoute = defaultState.routes.find((r) => r.name === 'Capture');
    if (!captureRoute) return defaultState;

    const parsed = CaptureQuerySchema.safeParse(captureRoute.params ?? {});
    if (!parsed.success) {
      // Invalid deep-link — drop it rather than crash
      console.warn('[linking] Invalid deep-link params:', parsed.error.format());
      return undefined;
    }

    const { session_id, expected_frames, timeout_seconds } = parsed.data;

    return {
      routes: [
        {
          name: 'Capture',
          params: {
            request: {
              session_id,
              expected_frames,
              timeout_seconds,
            },
          },
        },
      ],
    };
  },
  // Custom subscribe: honour cold-start URLs via Linking.getInitialURL
  subscribe(listener) {
    const sub = Linking.addEventListener('url', ({ url }) => listener(url));
    void Linking.getInitialURL().then((url) => {
      if (url) listener(url);
    });
    return () => sub.remove();
  },
};
