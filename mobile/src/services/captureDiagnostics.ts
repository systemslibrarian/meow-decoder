/** Measured guidance for a sustained zero-decode QR capture. */

import {
  LOW_LIGHT_DETECT_DELAY_MS,
  LOW_LIGHT_RATE_THRESHOLD,
  SHAKE_THRESHOLD_MS2,
} from '../constants/config';

export const ZERO_DECODE_DIAGNOSIS_MS = LOW_LIGHT_DETECT_DELAY_MS;
export const DARK_LUMINANCE_MAX = 45;
export const GLARE_LUMINANCE_MIN = 215;
export const QR_TOO_FAR_MAX_COVERAGE = 0.18;
export const QR_TOO_CLOSE_MIN_COVERAGE = 0.82;

export type ZeroDecodeReason =
  | 'moving'
  | 'too-dark'
  | 'glare'
  | 'too-close'
  | 'too-far'
  | 'no-geometry';

export interface ZeroDecodeInputs {
  decodeRate: number;
  zeroDecodeMs: number;
  /** Mean sampled Y-plane luminance, 0-255, or null when no sample exists. */
  luminance: number | null;
  /** Accelerometer movement magnitude in m/s^2. */
  shakeMagnitude: number;
  /** Largest QR dimension divided by the corresponding scanner-frame dimension. */
  qrCoverage: number | null;
}

export interface ZeroDecodeDiagnosis {
  reason: ZeroDecodeReason;
  message: string;
}

export function diagnoseZeroDecode({
  decodeRate,
  zeroDecodeMs,
  luminance,
  shakeMagnitude,
  qrCoverage,
}: ZeroDecodeInputs): ZeroDecodeDiagnosis | null {
  if (decodeRate >= LOW_LIGHT_RATE_THRESHOLD || zeroDecodeMs < ZERO_DECODE_DIAGNOSIS_MS) {
    return null;
  }

  if (shakeMagnitude > SHAKE_THRESHOLD_MS2) {
    return {
      reason: 'moving',
      message: 'Moving too much: hold the phone still or rest it on a surface.',
    };
  }
  // A dead/absent luminance sampler must not be diagnosed as darkness or
  // glare — without a measurement we fall through to the honest fallbacks.
  if (luminance !== null && luminance < DARK_LUMINANCE_MAX) {
    return {
      reason: 'too-dark',
      message: 'Image is too dark: raise the sender screen brightness.',
    };
  }
  if (luminance !== null && luminance > GLARE_LUMINANCE_MIN) {
    return {
      reason: 'glare',
      message: 'Screen is too bright or has glare: tilt the phone and lower exposure.',
    };
  }
  if (qrCoverage !== null && qrCoverage > QR_TOO_CLOSE_MIN_COVERAGE) {
    return {
      reason: 'too-close',
      message: 'Too close: move back until the entire QR and white border fit in the guide.',
    };
  }
  if (qrCoverage !== null && qrCoverage < QR_TOO_FAR_MAX_COVERAGE) {
    return {
      reason: 'too-far',
      message: 'Too far: move closer until the QR fills most of the guide.',
    };
  }
  return {
    reason: 'no-geometry',
    message: 'No QR lock yet: center the code, then move closer unless its edges are clipped.',
  };
}
