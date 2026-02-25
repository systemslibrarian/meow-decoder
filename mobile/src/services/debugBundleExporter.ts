/**
 * debugBundleExporter.ts — Sanitized diagnostics bundle for one-tap support artifact.
 *
 * Generates a privacy-safe text report that can be shared with support or
 * pasted in a bug report. Contains ONLY non-sensitive metadata.
 *
 * MUST NOT include:
 *  - Frame/payload contents
 *  - Passwords or secret material
 *  - Full session IDs
 *  - Heap memory addresses
 *
 * DOES include:
 *  - App version, protocol version
 *  - Platform, OS version, screen dimensions
 *  - Permission states (camera)
 *  - Capture session stats (counts, duplicates, progress, timing)
 *  - Truncated session ID (last 8 chars only)
 *  - Feature flags
 *  - Export file metadata (filename, hash, size — no contents)
 *  - Recent error context (if any)
 *
 * SECURITY: No network calls. Write-only to Downloads/Documents.
 * All data is derived from React Native APIs already in scope.
 */

import { Platform, Dimensions, PixelRatio } from 'react-native';
import RNFS from 'react-native-fs';
import { APP_VERSION, PROTOCOL_VERSION, FEATURE_FLAGS } from '../constants/config';
import type { CaptureResponse, ExportResult } from '../types/capture';

export interface DebugBundleInput {
  /** Capture response (we extract stats only, never payload data) */
  response: CaptureResponse;
  /** Export result if available (filenames, hash, size — no contents) */
  exportResult?: ExportResult | null;
  /** Export error message if any */
  exportError?: string | null;
  /** Reason for reaching the export screen */
  reason: 'complete' | 'timeout' | 'manual';
  /** Camera permission state */
  cameraPermission?: 'granted' | 'denied' | 'not-determined' | 'unknown';
}

/**
 * Builds a sanitized debug report string with only safe metadata.
 */
export function buildSanitizedDebugBundle(input: DebugBundleInput): string {
  const { response, exportResult, exportError, reason, cameraPermission } = input;
  const screen = Dimensions.get('window');
  const pixelRatio = PixelRatio.get().toFixed(1);
  const fontScale = PixelRatio.getFontScale().toFixed(2);
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);

  const captured = response.frames_captured;
  const expected = response.frames_missed + response.frames_captured;
  const ratio = expected > 0 ? captured / expected : 0;

  // Extract device model safely from platform constants (no sensitive data)
  const platformConstants: Record<string, unknown> = (Platform.constants ?? {}) as Record<string, unknown>;
  const deviceModel = Platform.OS === 'ios'
    ? (typeof platformConstants['systemName'] === 'string' ? platformConstants['systemName'] : 'iOS') + ' device'
    : (typeof platformConstants['Brand'] === 'string' ? platformConstants['Brand'] : 'Unknown')
      + ' '
      + (typeof platformConstants['Model'] === 'string' ? platformConstants['Model'] : 'device');

  const lines = [
    '╔══════════════════════════════════════════════════════════╗',
    '║     MEOW CAPTURE — SANITIZED DEBUG BUNDLE               ║',
    '║     No payloads or passwords included.                   ║',
    '║     Safe to share for troubleshooting.                   ║',
    '╚══════════════════════════════════════════════════════════╝',
    '',
    `Generated:       ${timestamp}`,
    '',
    '--- App ---',
    `Version:         Meow Capture v${APP_VERSION}`,
    `Protocol:        v${PROTOCOL_VERSION}`,
    `Feature flags:   VIDEO_IMPORT=${FEATURE_FLAGS.VIDEO_IMPORT}`,
    '',
    '--- Device ---',
    `Platform:        ${Platform.OS} ${Platform.Version}`,
    `Device model:    ${deviceModel}`,
    `Screen:          ${Math.round(screen.width)}×${Math.round(screen.height)} @${pixelRatio}x`,
    `Font scale:      ${fontScale}`,
    '',
    '--- Permissions ---',
    `Camera:          ${cameraPermission ?? 'unknown'}`,
    '',
    '--- Capture Session ---',
    `Session ID:      …${response.session_id.slice(-8)} (truncated for privacy)`,
    `Completion:      ${reason}`,
    `Frames captured: ${captured}`,
    `Frames expected: ${expected}`,
    `Frames missed:   ${response.frames_missed}`,
    `Coverage ratio:  ${(ratio * 100).toFixed(1)}%`,
    `Capture result:  ${response.capture_complete ? 'complete' : 'incomplete'}`,
    '',
    '--- Recovery Estimate ---',
    `Ratio:           ${ratio.toFixed(3)}`,
    `Status:          ${ratio >= 1.5 ? 'Transfer complete' : ratio >= 1.0 ? 'Likely recoverable' : ratio >= 0.67 ? 'Possibly recoverable' : 'May not decode'}`,
  ];

  if (exportResult) {
    lines.push(
      '',
      '--- Export ---',
      `Filenames:       ${exportResult.filenames.join(', ')}`,
      `Total bytes:     ${exportResult.totalBytes}`,
      `Chunks:          ${exportResult.chunkCount}`,
      `Exported at:     ${exportResult.exportedAt}`,
      `SHA-256:         ${exportResult.sha256 ? exportResult.sha256.slice(0, 16) + '…' : 'N/A'}`,
    );
  }

  if (exportError) {
    lines.push(
      '',
      '--- Export Error ---',
      `Error:           ${exportError}`,
    );
  }

  lines.push(
    '',
    '--- Security Model ---',
    'Trust model:     Untrusted dumb optical sensor',
    'Crypto on phone: NONE',
    'Network access:  NONE (zero permissions declared)',
    'Screen privacy:  FLAG_SECURE (Android) / overlay (iOS)',
    '',
    '╔══════════════════════════════════════════════════════════╗',
    '║  This report contains NO frame payloads, passwords,     ║',
    '║  encryption keys, or sensitive content.                  ║',
    '║  Safe to share with support or paste in a bug report.   ║',
    '╚══════════════════════════════════════════════════════════╝',
  );

  return lines.join('\n');
}

/**
 * Exports the sanitized debug bundle to a text file in Downloads/Documents.
 *
 * @returns Absolute path of the written file
 */
export async function exportDebugBundle(input: DebugBundleInput): Promise<string> {
  const report = buildSanitizedDebugBundle(input);
  const timestamp = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-');
  const filename = `meow-debug-${timestamp}.txt`;
  const dir = Platform.OS === 'android'
    ? RNFS.DownloadDirectoryPath
    : RNFS.DocumentDirectoryPath;
  const path = `${dir}/${filename}`;
  await RNFS.writeFile(path, report, 'utf8');
  return path;
}
