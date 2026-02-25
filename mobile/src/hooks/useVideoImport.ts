/**
 * useVideoImport.ts — Import a video or GIF file and extract QR frames.
 *
 * Provides a DocumentPicker entry-point for picking local video/GIF files,
 * then hands each extracted frame to a frame-extraction service. The service
 * stub below describes the two implementation paths:
 *
 *   A) Native Kotlin/Swift bridge (recommended for production):
 *      Write a TurboModule that uses MediaMetadataRetriever (Android) /
 *      AVAssetImageGenerator (iOS) to extract frames at configurable intervals,
 *      decode QR codes via MLKit/AVFoundation, and return results over the
 *      bridge in batches.
 *
 *   B) react-native-video + Vision Camera frame processor (alternative):
 *      Mount a hidden <Video> component, scrub frame-by-frame, and pass
 *      each frame through the existing useCodeScanner pipeline.
 *
 * SECURITY: Imported video is read-once from local storage; no network.
 * Raw video bytes are never retained — only QR string payloads pass through.
 */

import { useState, useCallback } from 'react';
import { NativeModules } from 'react-native';
import DocumentPicker from 'react-native-document-picker';
import RNFS from 'react-native-fs';
import { Platform } from 'react-native';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface VideoImportResult {
  /** URI of the selected video/GIF file */
  uri: string;
  /** Original filename */
  name: string;
  /** File size in bytes */
  size: number;
  /** MIME type as reported by the OS */
  mimeType: string | null;
}

export interface VideoFramePayload {
  /** QR string value decoded from the frame */
  qrValue: string;
  /** Approximate frame timestamp in milliseconds from file start */
  frameMs: number;
}

export interface UseVideoImportReturn {
  importFromVideo: () => Promise<void>;
  isImporting: boolean;
  importError: string | null;
  /** Clears the last import error */
  clearError: () => void;
  /** True when the native TurboModule bridge is linked and available */
  isNativeBridgeAvailable: boolean;
}

// ── Native bridge availability check ──────────────────────────────────────────

/**
 * Returns true when the native MeowVideoExtractor TurboModule is linked.
 * When true, importFromVideo() will use native frame extraction.
 * When false, HomeScreen should show a graceful "coming soon" modal instead
 * of invoking the import flow at all.
 *
 * SECURITY: No side effects — only checks NativeModules registry.
 */
export function isNativeBridgeAvailable(): boolean {
  return NativeModules.MeowVideoExtractor != null;
}

// ── Frame extractor stub ──────────────────────────────────────────────────────

/**
 * Stub implementation of video frame QR extraction.
 *
 * Replace this with a TurboModule call:
 *   `NativeModules.MeowVideoExtractor.extractQRFrames(uri, { intervalMs: 50 })`
 *
 * The module should return `Promise<VideoFramePayload[]>`.
 *
 * Until the native module is wired up this throws a sentinel error so
 * the HomeScreen can display a clear "coming soon" modal rather
 * than silently failing.
 */
async function extractQRFramesFromVideo(
  _uri: string,
): Promise<VideoFramePayload[]> {
  if (isNativeBridgeAvailable()) {
    // Native bridge is linked — call the TurboModule
    return NativeModules.MeowVideoExtractor.extractQRFrames(_uri, { intervalMs: 50 });
  }
  // TODO: Replace with TurboModule call when native bridge is implemented.
  // Android: com.meowdecoder.videoextractor.VideoFrameExtractorModule
  // iOS:     MeowVideoExtractorModule.swift
  throw new Error('VIDEO_IMPORT_NOT_AVAILABLE');
}

// ── Supported MIME types ──────────────────────────────────────────────────────

// DocumentPicker UTI/MIME accept lists for video and animated image formats
const VIDEO_TYPES = [
  ...DocumentPicker.types.video,
  // GIF (animated) — not categorised as "video" on all platforms
  'image/gif',
  'com.compuserve.gif',
] as string[];

// ── Hook ──────────────────────────────────────────────────────────────────────

/**
 * Hook for importing a local video or GIF file and extracting QR frame payloads.
 *
 * @param onFramesExtracted - Called with all decoded frame payloads on success
 */
export function useVideoImport(
  onFramesExtracted: (frames: VideoFramePayload[]) => void,
): UseVideoImportReturn {
  const [isImporting, setIsImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  const clearError = useCallback(() => setImportError(null), []);

  const importFromVideo = useCallback(async () => {
    setImportError(null);
    setIsImporting(true);

    try {
      const results = await DocumentPicker.pick({
        type: VIDEO_TYPES,
        allowMultiSelection: false,
        // Present the system file browser scoped to media
        ...(Platform.OS === 'ios' ? { presentationStyle: 'fullScreen' } : {}),
      });

      const result = results[0];
      if (!result) return;

      const normalized =
        Platform.OS === 'android'
          ? result.uri
          : decodeURIComponent(result.uri);

      // Verify the file is readable before attempting extraction
      const fileInfo = await RNFS.stat(normalized);
      if (!fileInfo.isFile()) {
        setImportError('Selected item is not a file');
        return;
      }

      // Attempt native frame extraction
      // This will throw until the TurboModule bridge is implemented.
      const frames = await extractQRFramesFromVideo(normalized);

      if (frames.length === 0) {
        setImportError('No QR codes found in the video');
        return;
      }

      onFramesExtracted(frames);
    } catch (err) {
      if (DocumentPicker.isCancel(err)) {
        // User cancelled — not an error condition
        return;
      }
      if (err instanceof Error) {
        setImportError(err.message);
      } else {
        setImportError('Could not import video');
      }
    } finally {
      setIsImporting(false);
    }
  }, [onFramesExtracted]);

  return {
    importFromVideo,
    isImporting,
    importError,
    clearError,
    isNativeBridgeAvailable: isNativeBridgeAvailable(),
  };
}
