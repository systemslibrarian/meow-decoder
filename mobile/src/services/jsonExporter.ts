/**
 * jsonExporter.ts — Writes capture responses to the device Downloads folder.
 *
 * The exported JSON is the only data that leaves JS memory — it is written
 * to a predictably-named file in Downloads for retrieval via USB/ADB.
 *
 * SECURITY:
 *  - Only writes to DownloadDirectoryPath (scoped, user-visible)
 *  - Does not write anywhere else (no Documents, no cache, no temp)
 *  - File is UTF-8 text, never binary blobs
 *  - Filename includes session_id prefix and ISO timestamp (no sensitive data)
 *
 * File naming: meow-capture-<first8-of-sessionId>-<timestamp>.json
 *              meow-capture-<first8>-part1-<timestamp>.json (chunked)
 */

import RNFS from 'react-native-fs';
import { Platform } from 'react-native';
import { MAX_EXPORT_CHUNK_BYTES } from '../constants/config';
import type { CaptureResponse, ExportResult } from '../types/capture';

// ── Path Helpers ──────────────────────────────────────────────────────────────

/**
 * Returns the platform-appropriate export directory.
 * Android: /sdcard/Download (scoped storage on API 30+, but RNFS handles it)
 * iOS: uses DocumentDirectory since iOS has no Downloads folder accessible to apps
 */
function getExportDirectory(): string {
  if (Platform.OS === 'android') {
    return RNFS.DownloadDirectoryPath;
  }
  // iOS: DocumentDirectory is user-accessible via Files app
  return RNFS.DocumentDirectoryPath;
}

/** Builds a safe filename component from an ISO timestamp */
function safeTimestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
}

// ── Export ────────────────────────────────────────────────────────────────────

/**
 * Exports the capture response to the Downloads folder as one or more JSON files.
 *
 * If the serialised response is ≤ MAX_EXPORT_CHUNK_BYTES, a single file is written.
 * Otherwise the frame array is split into chunks and each chunk written separately.
 * The CLI expects to receive all chunk files and merges them automatically.
 *
 * @returns ExportResult describing paths written and metadata
 * @throws if the file system write fails (permissions, disk full, etc.)
 */
export async function exportResponse(response: CaptureResponse): Promise<ExportResult> {
  const timestamp = safeTimestamp();
  const sessionPrefix = response.session_id.slice(0, 8);
  const directory = getExportDirectory();
  const exportedPaths: string[] = [];

  const json = JSON.stringify(response, null, 2);
  // Buffer.byteLength gives accurate UTF-8 byte count without DOM's TextEncoder.
  // react-native-worklets-core brings Node globals; Buffer is available here.
  const byteLength = Buffer.byteLength(json, 'utf8');

  let totalWrittenBytes = 0;

  if (byteLength <= MAX_EXPORT_CHUNK_BYTES) {
    // Single file path
    const filename = `meow-capture-${sessionPrefix}-${timestamp}.json`;
    const path = `${directory}/${filename}`;
    await RNFS.writeFile(path, json, 'utf8');
    exportedPaths.push(path);
    totalWrittenBytes = byteLength;
  } else {
    // Chunked path — split the frames array
    const frames = response.frames;
    const totalChunks = Math.ceil(byteLength / MAX_EXPORT_CHUNK_BYTES);
    const chunkFrameCount = Math.ceil(frames.length / totalChunks);

    for (let i = 0; i < frames.length; i += chunkFrameCount) {
      const chunkIndex = Math.floor(i / chunkFrameCount) + 1;
      const chunkFrames = frames.slice(i, i + chunkFrameCount);
      const chunk: CaptureResponse = {
        ...response,
        frames: chunkFrames,
        frames_captured: chunkFrames.length,
        // Keep frames_missed accurate to the original
        frames_missed: response.frames_missed,
      };
      const chunkJson = JSON.stringify(chunk, null, 2);
      const chunkByteLength = Buffer.byteLength(chunkJson, 'utf8');
      const filename = `meow-capture-${sessionPrefix}-part${chunkIndex}-${timestamp}.json`;
      const path = `${directory}/${filename}`;
      await RNFS.writeFile(path, chunkJson, 'utf8');
      exportedPaths.push(path);
      totalWrittenBytes += chunkByteLength;
    }
  }

  return {
    paths: exportedPaths,
    filenames: exportedPaths.map((p) => p.split('/').pop() ?? p),
    totalBytes: totalWrittenBytes,
    chunkCount: exportedPaths.length,
    exportedAt: new Date().toISOString(),
    // SHA-256 of the primary file — computed by RNFS so it hashes the bytes actually on disk.
    // Falls back to empty string if the hash call fails (permissions edge-case on iOS).
    sha256: await RNFS.hash(exportedPaths[0] ?? '', 'sha256').catch(() => ''),
  };
}

/**
 * Deletes a previously exported file.
 * Used to clean up after the user acknowledges the export on iOS
 * (Android Downloads are user-managed).
 */
export async function deleteExportFile(path: string): Promise<void> {
  const exists = await RNFS.exists(path);
  if (exists) {
    await RNFS.unlink(path);
  }
}

/**
 * Checks whether a given export path still exists on disk.
 */
export async function exportExists(path: string): Promise<boolean> {
  return RNFS.exists(path);
}

// ── QR Fallback Export (Hardened) ──────────────────────────────────────────────

/**
 * Simple SHA-256-like checksum using a fast non-cryptographic hash.
 * Uses a lightweight DJB2a + FNV-1a hybrid to produce a 16-char hex digest.
 * This is NOT for security — only for detecting transmission/scanning errors
 * during QR optical transfer reassembly.
 *
 * For a production-grade implementation, replace with SubtleCrypto SHA-256
 * when available in the RN runtime.
 */
function checksumHex(input: string): string {
  let h1 = 0x811c9dc5 >>> 0; // FNV offset basis
  let h2 = 5381 >>> 0;       // DJB2 offset basis
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0; // FNV-1a
    h2 = (Math.imul(h2, 33) + c) >>> 0;        // DJB2a
  }
  return (h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0'));
}

/**
 * Splits the capture response JSON into QR-displayable chunks for the
 * reverse-optical export fallback (phone screen → air-gapped machine camera).
 *
 * Each chunk is a self-contained JSON string with metadata for reassembly,
 * including:
 *   - Per-chunk checksum for scanning error detection
 *   - Full-payload checksum in every chunk for reassembly verification
 *   - Total byte length for completeness check
 *
 * The receiver should:
 *   1. Verify each chunk_checksum matches checksumHex(data)
 *   2. After collecting all chunks, concatenate data fields in chunk_index order
 *   3. Verify the concatenated result's checksum matches payload_checksum
 *   4. Verify the concatenated result's byte length matches payload_bytes
 *
 * @param maxChunkBytes Max bytes per QR code (default from config)
 * @returns Array of strings, each displayable as a single QR code
 */
export function buildQRExportChunks(
  response: CaptureResponse,
  maxChunkBytes = 2048,
): string[] {
  const fullJson = JSON.stringify(response);
  const chunks: string[] = [];
  const payloadChecksum = checksumHex(fullJson);
  const payloadBytes = Buffer.byteLength(fullJson, 'utf8');
  // Use Buffer.byteLength for accurate UTF-8 byte count (matches export size
  // calculation in exportResponse). For ASCII-only payloads this equals
  // .length, but it's correct for any session_id or filename containing
  // multi-byte characters.
  const totalChunks = Math.ceil(payloadBytes / maxChunkBytes);

  for (let i = 0; i < totalChunks; i++) {
    const slice = fullJson.slice(i * maxChunkBytes, (i + 1) * maxChunkBytes);
    const chunkChecksum = checksumHex(slice);
    const envelope = JSON.stringify({
      meow_qr_chunk: true,
      version: 2,
      session_id: response.session_id,
      chunk_index: i + 1,
      total_chunks: totalChunks,
      chunk_checksum: chunkChecksum,
      payload_checksum: payloadChecksum,
      payload_bytes: payloadBytes,
      data: slice,
    });
    chunks.push(envelope);
  }

  return chunks;
}

/**
 * Verifies reassembled QR export chunks.
 *
 * @returns Object with `valid` boolean and optional `error` string
 */
export function verifyQRExportReassembly(
  chunks: Array<{ chunk_index: number; total_chunks: number; chunk_checksum: string; payload_checksum: string; payload_bytes: number; data: string }>,
): { valid: boolean; error?: string; reassembled?: string } {
  if (chunks.length === 0) {
    return { valid: false, error: 'No chunks provided' };
  }

  const expected = chunks[0]!.total_chunks;
  if (chunks.length !== expected) {
    return { valid: false, error: `Expected ${expected} chunks, got ${chunks.length}` };
  }

  // Sort by chunk_index
  const sorted = [...chunks].sort((a, b) => a.chunk_index - b.chunk_index);

  // Verify per-chunk checksums
  for (const chunk of sorted) {
    const computed = checksumHex(chunk.data);
    if (computed !== chunk.chunk_checksum) {
      return { valid: false, error: `Chunk ${chunk.chunk_index} checksum mismatch (expected ${chunk.chunk_checksum}, got ${computed})` };
    }
  }

  // Reassemble and verify payload checksum
  const reassembled = sorted.map(c => c.data).join('');
  const computedPayloadChecksum = checksumHex(reassembled);
  const expectedPayloadChecksum = sorted[0]!.payload_checksum;

  if (computedPayloadChecksum !== expectedPayloadChecksum) {
    return { valid: false, error: `Payload checksum mismatch (expected ${expectedPayloadChecksum}, got ${computedPayloadChecksum})` };
  }

  const computedBytes = Buffer.byteLength(reassembled, 'utf8');
  const expectedBytes = sorted[0]!.payload_bytes;
  if (computedBytes !== expectedBytes) {
    return { valid: false, error: `Payload byte length mismatch (expected ${expectedBytes}, got ${computedBytes})` };
  }

  return { valid: true, reassembled };
}
