/**
 * captureSettings.ts — user preferences for the capture flow (MMKV-backed).
 */

import { MMKV } from 'react-native-mmkv';

const STORE_ID = 'meow-settings';
const CALIBRATION_KEY = 'capture_calibration_enabled';

let _storage: MMKV | null = null;
function store(): MMKV {
  if (!_storage) _storage = new MMKV({ id: STORE_ID });
  return _storage;
}

/**
 * Whether to show the pre-capture calibration wizard.
 *
 * Default FALSE (skip). The wizard opens its OWN camera preview, and on
 * single-camera devices that collides with the capture camera (and the prior
 * QR-scanner camera), surfacing as "camera could not start". Skipping it lets
 * capture open the camera once, cleanly. Users who want the guided setup can
 * turn it on in Settings.
 */
export function isCalibrationEnabled(): boolean {
  try {
    return store().getBoolean(CALIBRATION_KEY) ?? false;
  } catch {
    return false;
  }
}

/** Update the calibration-wizard preference. */
export function setCalibrationEnabled(enabled: boolean): void {
  try {
    store().set(CALIBRATION_KEY, enabled);
  } catch {
    // MMKV unavailable — ignore
  }
}
