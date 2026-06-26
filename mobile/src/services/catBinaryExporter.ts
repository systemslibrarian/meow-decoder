/**
 * catBinaryExporter.ts — saves a recovered Cat Mode binary pattern.
 *
 * After the camera decodes the blinking-eye stream (catBlinkDecoder), this is
 * how the result leaves the app: the raw "binary pattern" (a string of 0/1) is
 * written to the Downloads folder as a plain .txt and copied to the clipboard.
 * The user then pastes it into the web demo's Binary Pattern field (Cat Mode
 * Step 3) or the desktop CLI to decrypt — the mobile app itself never decrypts
 * (it is an untrusted optical sensor; see src/types/capture.ts).
 *
 * SECURITY: mirrors jsonExporter.ts — writes only to the scoped, user-visible
 * Downloads/Documents directory, UTF-8 text only, with a non-sensitive filename.
 * The binary is ciphertext bits, not plaintext.
 */

import RNFS from 'react-native-fs';
import Clipboard from '@react-native-clipboard/clipboard';
import { Platform } from 'react-native';
import { APP_VERSION } from '../constants/config';

export interface CatBinaryExportResult {
  /** Absolute path of the written file. */
  path: string;
  /** Filename without directory. */
  filename: string;
  /** Number of bits in the saved pattern. */
  bits: number;
  /** Lightweight non-cryptographic checksum (transfer-error detection aid). */
  checksum: string;
  /** ISO 8601 timestamp of export. */
  exportedAt: string;
}

export interface CatBinaryMeta {
  /** Estimated blink period (ms), recorded in the sidecar header for diagnostics. */
  blinkPeriodMs?: number;
}

/** Thrown when the binary pattern is empty or contains non-0/1 characters. */
export class CatBinaryError extends Error {}

function getExportDirectory(): string {
  // Android exposes a real Downloads folder; iOS apps use their Documents dir
  // (user-accessible via the Files app). Same split as jsonExporter.
  return Platform.OS === 'android' ? RNFS.DownloadDirectoryPath : RNFS.DocumentDirectoryPath;
}

function safeTimestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
}

/**
 * Non-cryptographic 16-hex-char checksum (FNV-1a + DJB2a), matching the
 * convention used by jsonExporter's QR fallback. NOT for security — only to
 * catch copy/transcription errors when moving the pattern to another machine.
 */
function checksumHex(input: string): string {
  let h1 = 0x811c9dc5 >>> 0;
  let h2 = 5381 >>> 0;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = (Math.imul(h2, 33) + c) >>> 0;
  }
  return h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0');
}

/** True only for a non-empty string of '0'/'1' characters. */
export function isValidBinaryPattern(binary: string): boolean {
  return binary.length > 0 && /^[01]+$/.test(binary);
}

/**
 * Write the binary pattern to Downloads as a plain-text file.
 *
 * The file is the raw 0/1 string preceded by a one-line `#`-comment header
 * (bits, blink period, app version, timestamp) so a saved file is self-
 * describing. Consumers that want only the bits should take the last
 * non-comment line; the clipboard copy ({@link copyCatBinary}) is pure bits for
 * direct pasting.
 *
 * @throws CatBinaryError if the pattern is empty or not 0/1.
 */
export async function exportCatBinary(
  binary: string,
  meta: CatBinaryMeta = {},
): Promise<CatBinaryExportResult> {
  if (!isValidBinaryPattern(binary)) {
    throw new CatBinaryError('Binary pattern must be a non-empty string of 0s and 1s.');
  }

  const timestamp = safeTimestamp();
  const filename = `meow-catmode-${timestamp}.txt`;
  const directory = getExportDirectory();
  const path = `${directory}/${filename}`;
  const exportedAt = new Date().toISOString();
  const checksum = checksumHex(binary);

  const header =
    `# meow-decoder Cat Mode binary pattern\n` +
    `# bits=${binary.length} ` +
    (meta.blinkPeriodMs !== undefined ? `blink_period_ms=${Math.round(meta.blinkPeriodMs)} ` : '') +
    `checksum=${checksum} app=${APP_VERSION} captured_at=${exportedAt}\n` +
    `# Paste the line below into the web demo Cat Mode "Binary Pattern" field.\n`;

  await RNFS.writeFile(path, header + binary + '\n', 'utf8');

  return {
    path,
    filename,
    bits: binary.length,
    checksum,
    exportedAt,
  };
}

/** Copy the raw binary pattern (bits only) to the clipboard for pasting. */
export function copyCatBinary(binary: string): void {
  if (!isValidBinaryPattern(binary)) {
    throw new CatBinaryError('Binary pattern must be a non-empty string of 0s and 1s.');
  }
  Clipboard.setString(binary);
}
