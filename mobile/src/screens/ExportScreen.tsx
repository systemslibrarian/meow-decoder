/**
 * ExportScreen.tsx — Review results and export JSON.
 *
 * Displays capture summary statistics and offers two export paths:
 *   1. Primary: write JSON to Downloads (USB/ADB retrieval)
 *   2. Fallback: show static QR codes on screen for reverse-optical transfer
 *
 * After successful export, shows ADB pull instructions.
 */

import React, { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  SafeAreaView,
  Platform,
  ActivityIndicator,
  Share,
  Alert,
} from 'react-native';
import Clipboard from '@react-native-clipboard/clipboard';
import ReactNativeBiometrics from 'react-native-biometrics';
import ReactNativeHapticFeedback from 'react-native-haptic-feedback';
import QRCode from 'react-native-qrcode-svg';
import { exportResponse } from '../services/jsonExporter';
import { buildQRExportChunks } from '../services/jsonExporter';
import type { ExportResult } from '../types/capture';
import type { ExportScreenProps } from '../types/navigation';
import { useCatToast } from '../components/CatToast';
import { Colors, Typography, Spacing, Radius, Shadows } from '../constants/theme';
import { formatPercent, formatFileSize } from '../utils/formatters';
import { CLIPBOARD_WIPE_DELAY_MS } from '../constants/config';

const HAPTIC_OPTIONS = { enableVibrateFallback: true, ignoreAndroidSystemSettings: false };
const rnBiometrics = new ReactNativeBiometrics({ allowDeviceCredentials: true });

// ── Component ─────────────────────────────────────────────────────────────────

export function ExportScreen({ route, navigation }: ExportScreenProps) {
  const { response, reason } = route.params;
  const { showToast } = useCatToast();

  const [exporting, setExporting] = useState(false);
  const [exportResult, setExportResult] = useState<ExportResult | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  // true until the user explicitly taps "Confirm & Export"
  const [awaitingConfirm, setAwaitingConfirm] = useState(true);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  // Clipboard auto-wipe: true while an ADB command is pending clear
  const [clipboardActive, setClipboardActive] = useState(false);
  const clipboardWipeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // QR fallback state
  const [qrMode, setQrMode] = useState(false);
  const [qrChunks, setQrChunks] = useState<string[]>([]);
  const [currentQrIndex, setCurrentQrIndex] = useState(0);

  // Debug bundle state
  const [debugBundleExporting, setDebugBundleExporting] = useState(false);
  const [debugBundlePath, setDebugBundlePath] = useState<string | null>(null);

  // ── Summary stats ──────────────────────────────────────────────────────────
  const captured = response.frames_captured;
  const expected = response.frames_missed + response.frames_captured;
  const ratio = expected > 0 ? captured / expected : 0;
  const pct = formatPercent(ratio);

  const recoveryStatus =
    ratio >= 1.5 ? { label: 'Ready to export — all data captured', color: Colors.catGold } :
    ratio >= 1.0 ? { label: 'Ready to export — good capture', color: Colors.success } :
    ratio >= 0.67 ? { label: 'Ready to export — recovery may need a retry', color: Colors.warning } :
    { label: 'Low coverage — may not decode without recapture', color: Colors.danger };

  // ── Check biometric availability on mount ──────────────────────────────────
  // SECURITY: No auto-export. The user must explicitly confirm and pass
  // biometrics (if available) before any data is written to disk. This
  // prevents an adversary with physical access from getting the export simply
  // by opening the app while it transitions to ExportScreen.
  useEffect(() => {
    void rnBiometrics.isSensorAvailable().then(({ available }: { available: boolean }) => {
      setBiometricAvailable(available);
    }).catch(() => {
      // Biometrics unavailable — fall through to unguarded export button
      setBiometricAvailable(false);
    });
  }, []);

  // ── Clipboard auto-wipe ────────────────────────────────────────────────────
  // Clear the wipe timer on unmount to avoid setting state on an unmounted component.
  useEffect(() => {
    return () => {
      if (clipboardWipeTimerRef.current !== null) {
        clearTimeout(clipboardWipeTimerRef.current);
      }
    };
  }, []);

  const handleCopyAdbCommand = useCallback(() => {
    if (!exportResult) return;
    const adbCmd = `adb pull /sdcard/Download/meow-capture-${response.session_id.slice(0, 8)}*.json ./\nmeow-decoder decode --input meow-capture-*.json`;
    Clipboard.setString(adbCmd);
    ReactNativeHapticFeedback.trigger('impactLight', HAPTIC_OPTIONS);
    setClipboardActive(true);
    showToast({ message: '📋 Command copied — auto-clears in 45 s', type: 'info', durationMs: 3_000 });
    // Cancel any existing timer before starting a new one
    if (clipboardWipeTimerRef.current !== null) {
      clearTimeout(clipboardWipeTimerRef.current);
    }
    clipboardWipeTimerRef.current = setTimeout(() => {
      Clipboard.setString('');
      setClipboardActive(false);
      clipboardWipeTimerRef.current = null;
    }, CLIPBOARD_WIPE_DELAY_MS);
  }, [exportResult, response.session_id, showToast]);
  const handleCopyFilename = useCallback((index: number = 0) => {
    const name = exportResult?.filenames[index] ?? exportResult?.filenames[0];
    if (!name) return;
    Clipboard.setString(name);
    ReactNativeHapticFeedback.trigger('impactLight', HAPTIC_OPTIONS);
    showToast({ message: '📋 Filename copied', type: 'info', durationMs: 2_000 });
    if (clipboardWipeTimerRef.current !== null) clearTimeout(clipboardWipeTimerRef.current);
    clipboardWipeTimerRef.current = setTimeout(() => {
      Clipboard.setString('');
      clipboardWipeTimerRef.current = null;
    }, CLIPBOARD_WIPE_DELAY_MS);
  }, [exportResult, showToast]);

  const handleCopySha256 = useCallback(() => {
    if (!exportResult?.sha256) return;
    Clipboard.setString(exportResult.sha256);
    ReactNativeHapticFeedback.trigger('impactLight', HAPTIC_OPTIONS);
    showToast({ message: '🔑 SHA-256 copied', type: 'info', durationMs: 2_000 });
    if (clipboardWipeTimerRef.current !== null) clearTimeout(clipboardWipeTimerRef.current);
    clipboardWipeTimerRef.current = setTimeout(() => {
      Clipboard.setString('');
      clipboardWipeTimerRef.current = null;
    }, CLIPBOARD_WIPE_DELAY_MS);
  }, [exportResult, showToast]);
  // ── Biometric-gated export handler ─────────────────────────────────────────
  const handleExport = useCallback(async () => {
    // Gate with biometrics when a sensor is enrolled; fall through if not
    if (biometricAvailable) {
      const { success } = await rnBiometrics.simplePrompt({
        promptMessage: 'Confirm export to device storage',
        cancelButtonText: 'Cancel',
      }).catch(() => ({ success: false }));

      if (!success) {
        ReactNativeHapticFeedback.trigger('notificationWarning', HAPTIC_OPTIONS);
        showToast({ message: 'Export cancelled — your captured data is still here. Tap Export again when ready.', type: 'info', durationMs: 4_000 });
        return;
      }
    }

    setAwaitingConfirm(false);
    setExporting(true);
    setExportError(null);
    try {
      const result = await exportResponse(response);
      setExportResult(result);
      ReactNativeHapticFeedback.trigger('notificationSuccess', HAPTIC_OPTIONS);
      showToast({ message: 'Transfer exported — ready to move to the desktop 📦🐾', type: 'success' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      setExportError(`Export failed: ${msg}. Your captured data is still in memory — tap Retry to try again.`);
      ReactNativeHapticFeedback.trigger('notificationError', HAPTIC_OPTIONS);
      showToast({ message: 'Export failed — your data is safe in memory. Check storage space and try again.', type: 'error', durationMs: 5_000 });
    } finally {
      setExporting(false);
    }
  }, [response, showToast, biometricAvailable]);

  // Precompute QR chunks once — used for both the count badge and the actual
  // QR display so we never serialize the full response payload twice.
  const precomputedQrChunks = useMemo(
    () => buildQRExportChunks(response),
    [response],
  );

  // ── QR fallback ────────────────────────────────────────────────────────────
  const startQrFallback = useCallback(() => {
    setQrChunks(precomputedQrChunks);
    setCurrentQrIndex(0);
    setQrMode(true);
  }, [precomputedQrChunks]);

  // ── iOS Share Sheet ────────────────────────────────────────────────────────
  const shareFile = useCallback(async () => {
    if (!exportResult?.paths[0]) return;
    try {
      await Share.share({ url: `file://${exportResult.paths[0]}` });
    } catch {
      // User dismissed share sheet — not an error
    }
  }, [exportResult]);

  // ── Debug bundle export (one-tap sanitized support artifact) ──────────────
  const handleDebugBundleExport = useCallback(async () => {
    setDebugBundleExporting(true);
    try {
      const { exportDebugBundle } = await import('../services/debugBundleExporter');
      const path = await exportDebugBundle({
        response,
        exportResult,
        exportError,
        reason,
        cameraPermission: 'granted', // If we got here, camera was granted
      });
      setDebugBundlePath(path);
      ReactNativeHapticFeedback.trigger('notificationSuccess', HAPTIC_OPTIONS);
      showToast({ message: 'Debug bundle saved — safe to share for troubleshooting', type: 'success', durationMs: 3_000 });
    } catch {
      showToast({ message: 'Could not export debug bundle', type: 'error' });
    } finally {
      setDebugBundleExporting(false);
    }
  }, [response, exportResult, exportError, reason, showToast]);

  // ── Confirmation card (shown before export is triggered) ──────────────────
  if (awaitingConfirm && !exporting && !exportResult) {
    return (
      <SafeAreaView style={styles.safe}>
        <ScrollView contentContainerStyle={styles.scroll}>
          <Text style={styles.title}>
            {reason === 'timeout' ? '⏰ Capture ended early' : '✓ Transfer captured'}
          </Text>
          <Text style={styles.subtitle}>
            Your capture is ready to export for recovery on the receiving computer.
          </Text>

          {/* Summary card */}
          <View style={styles.card} accessibilityRole="summary">
            <View style={styles.statusRow} accessible={true} accessibilityLabel={`Status: ${recoveryStatus.label}`}>
              <Text style={styles.rowLabel}>Status</Text>
              <Text style={[styles.statusValue, { color: recoveryStatus.color }]}>
                {recoveryStatus.label}
              </Text>
            </View>
            <Row label="Frames captured" value={`${captured} / ${expected}`} />
            <Row label="Coverage" value={pct} />
            <Row label="Frames missed" value={String(response.frames_missed)} />
          </View>

          {/* Explicit export CTA */}
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Export Transfer</Text>
            <Text style={styles.cardBody}>
              Saves the captured transfer to this device so you can move it to the
              receiving computer for recovery.
              {biometricAvailable ? '\nBiometric confirmation will be required.' : null}
            </Text>
            <TouchableOpacity
              style={[styles.primaryButton, { backgroundColor: recoveryStatus.color }]}
              onPress={handleExport}
              accessibilityRole="button"
              accessibilityLabel={biometricAvailable ? 'Confirm export with biometrics' : 'Export captured transfer to device storage'}
            >
              <Text style={styles.primaryButtonText}>
                {biometricAvailable ? '🔒 Confirm & Export Transfer' : '📦 Export Transfer'}
              </Text>
            </TouchableOpacity>
          </View>

          {/* QR fallback option */}
          <View style={styles.card}>
            <Text style={styles.cardTitle}>No USB? Use optical transfer</Text>
            <Text style={styles.cardBody}>
              Display the capture as QR codes to scan on the air-gapped machine.
            </Text>
            <TouchableOpacity
              style={styles.secondaryButton}
              onPress={startQrFallback}
              accessibilityRole="button"
            >
              <Text style={styles.secondaryButtonText}>
                📲 Show as QR codes ({precomputedQrChunks.length} screens)
              </Text>
            </TouchableOpacity>
          </View>

          <TouchableOpacity
            style={styles.ghostButton}
            onPress={() => {
              Alert.alert(
                'Discard this capture?',
                'All captured frames will be permanently deleted. This cannot be undone.',
                [
                  { text: 'Keep capture', style: 'cancel' },
                  { text: 'Discard', style: 'destructive', onPress: () => navigation.replace('Home') },
                ],
              );
            }}
            accessibilityRole="button"
            accessibilityLabel="Discard capture and return home. All frames will be deleted."
          >
            <Text style={styles.ghostButtonText}>✕ Discard capture</Text>
          </TouchableOpacity>
        </ScrollView>
      </SafeAreaView>
    );
  }

  // ── QR Mode ────────────────────────────────────────────────────────────────
  if (qrMode && qrChunks.length > 0) {
    const currentChunk = qrChunks[currentQrIndex] ?? '';
    // Parse envelope to show chunk-level checksum info
    let chunkMeta: { chunk_checksum?: string; payload_checksum?: string; total_chunks?: number } = {};
    try { chunkMeta = JSON.parse(currentChunk); } catch { /* ignore */ }
    const isLastChunk = currentQrIndex === qrChunks.length - 1;

    return (
      <SafeAreaView style={styles.safe}>
        <View style={styles.qrContainer}>
          <Text style={styles.qrTitle} accessibilityRole="header">
            QR Export — {currentQrIndex + 1} / {qrChunks.length}
          </Text>
          <Text style={styles.qrSubtitle}>
            Scan each QR code with the air-gapped machine
          </Text>
          {chunkMeta.chunk_checksum && (
            <Text style={styles.qrChecksumText}>
              Chunk checksum: {chunkMeta.chunk_checksum}
            </Text>
          )}
          <View style={styles.qrBox}>
            <QRCode
              value={currentChunk}
              size={280}
              color="#000"
              backgroundColor="#fff"
            />
          </View>
          {isLastChunk && chunkMeta.payload_checksum && (
            <View style={styles.qrVerifyBox}>
              <Text style={styles.qrVerifyTitle}>Reassembly verification</Text>
              <Text style={styles.qrVerifyText}>
                After scanning all {chunkMeta.total_chunks} chunks, verify the
                concatenated payload checksum:
              </Text>
              <Text style={styles.qrVerifyHash}>{chunkMeta.payload_checksum}</Text>
            </View>
          )}
          <View style={styles.qrControls}>
            {currentQrIndex > 0 && (
              <TouchableOpacity
                style={styles.qrNavButton}
                onPress={() => setCurrentQrIndex((i) => i - 1)}
                accessibilityRole="button"
                accessibilityLabel={`Previous QR code, ${currentQrIndex} of ${qrChunks.length}`}
              >
                <Text style={styles.qrNavText}>← Previous</Text>
              </TouchableOpacity>
            )}
            {currentQrIndex < qrChunks.length - 1 ? (
              <TouchableOpacity
                style={[styles.qrNavButton, styles.qrNavPrimary]}
                onPress={() => setCurrentQrIndex((i) => i + 1)}
                accessibilityRole="button"
                accessibilityLabel={`Next QR code, ${currentQrIndex + 2} of ${qrChunks.length}`}
              >
                <Text style={styles.qrNavText}>Next →</Text>
              </TouchableOpacity>
            ) : (
              <TouchableOpacity
                style={[styles.qrNavButton, styles.qrNavPrimary]}
                onPress={() => setQrMode(false)}
                accessibilityRole="button"
                accessibilityLabel="Done with QR export"
              >
                <Text style={styles.qrNavText}>Done ✓</Text>
              </TouchableOpacity>
            )}
          </View>
        </View>
      </SafeAreaView>
    );
  }

  // ── Main export view ───────────────────────────────────────────────────────
  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll}>
        {/* Results header */}
        <Text style={styles.title}>
          {reason === 'timeout' ? '⏰ Capture ended early' : '✓ Transfer captured'}
        </Text>
        {reason === 'timeout' && (
          <Text style={styles.timeoutMsg}>
            Captured {captured} of {expected} frames before timeout.
            {ratio >= 1.0
              ? ' This is likely enough for full recovery.'
              : ratio >= 0.67
                ? ' Recovery may be possible — export and try decoding.'
                : ' This may not be enough to decode. You can start a new capture to get more frames.'}
            {' Your captured data is safe until you leave this screen.'}
          </Text>
        )}

        {/* Summary card */}
        <View style={styles.card}>
          <Row label="Frames captured" value={`${captured} / ${expected}`} />
          <Row label="Coverage" value={pct} />
          <Row label="Frames missed" value={String(response.frames_missed)} />
          <View style={styles.statusRow}>
            <Text style={styles.rowLabel}>Recovery estimate</Text>
            <Text style={[styles.statusValue, { color: recoveryStatus.color }]}>
              {recoveryStatus.label}
            </Text>
          </View>
        </View>

        {/* Export status */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>
            {exportResult ? 'Export complete' : 'Export Transfer'}
          </Text>
          {exporting && (
            <View style={styles.exportingRow}>
              <ActivityIndicator color={Colors.catOrange} />
              <Text style={styles.exportingText}>Saving transfer…</Text>
            </View>
          )}
          {exportError && (
            <Text style={styles.errorText}>{exportError}</Text>
          )}
          {exportResult && (
            <>
              {exportResult.paths.map((path, i) => (
                <TouchableOpacity
                  key={i}
                  onPress={() => handleCopyFilename(i)}
                  accessibilityRole="button"
                  accessibilityLabel={`Copy filename ${exportResult.filenames[i] ?? path.split('/').pop()}`}
                >
                  <Text style={styles.pathText} numberOfLines={2}>
                    📄 {exportResult.filenames[i] ?? path.split('/').pop()}
                    {'  '}
                    <Text style={styles.copyHint}>(tap to copy name)</Text>
                  </Text>
                </TouchableOpacity>
              ))}
              <Text style={styles.sizeText}>
                {formatFileSize(exportResult.totalBytes)}
                {exportResult.chunkCount > 1 && ` (${exportResult.chunkCount} files)`}
              </Text>

              {/* SHA-256 integrity row */}
              {exportResult.sha256 ? (
                <TouchableOpacity
                  style={styles.sha256Row}
                  onPress={handleCopySha256}
                  accessibilityRole="button"
                  accessibilityLabel="Copy SHA-256 hash for desktop verification"
                >
                  <Text style={styles.sha256Label}>SHA-256</Text>
                  <Text style={styles.sha256Hash} numberOfLines={1}>
                    {exportResult.sha256.slice(0, 16)}…{exportResult.sha256.slice(-8)}
                  </Text>
                  <Text style={styles.sha256CopyHint}>Copy  📋</Text>
                </TouchableOpacity>
              ) : null}

              {/* Desktop verify helper */}
              <View style={styles.verifyHintBox}>
                <Text style={styles.verifyHintTitle}>Verification details (optional):</Text>
                <Text style={styles.verifyHintCode}>
                  {`sha256sum ${exportResult.filenames[0] ?? 'meow-capture.json'}`}
                </Text>
              </View>

              {/* ADB instructions */}
              <View style={styles.adbBox}>
                <Text style={styles.adbTitle}>Receive on the desktop:</Text>
                <Text style={styles.adbCode}>
                  {`adb pull /sdcard/Download/meow-capture-${response.session_id.slice(0, 8)}*.json ./\nmeow-decoder decode --input meow-capture-*.json`}
                </Text>
                <TouchableOpacity
                  style={styles.copyButton}
                  onPress={handleCopyAdbCommand}
                  accessibilityRole="button"
                  accessibilityLabel="Copy ADB command to clipboard"
                >
                  <Text style={styles.copyButtonText}>
                    {clipboardActive ? '✅ Copied — clears in 45 s' : '📋 Copy ADB command'}
                  </Text>
                </TouchableOpacity>
              </View>

              {/* iOS share — promoted to primary on iOS */}
              {Platform.OS === 'ios' && (
                <TouchableOpacity
                  style={styles.primaryButton}
                  onPress={shareFile}
                  accessibilityRole="button"
                  accessibilityLabel="Share capture file via iOS Files app"
                >
                  <Text style={styles.primaryButtonText}>
                    📂 Share via Files app
                  </Text>
                </TouchableOpacity>
              )}
            </>
          )}

          {!exporting && exportError && (
            <TouchableOpacity
              style={styles.primaryButton}
              onPress={handleExport}
              accessibilityRole="button"
              accessibilityLabel="Retry export"
            >
              <Text style={styles.primaryButtonText}>Retry Export</Text>
            </TouchableOpacity>
          )}
        </View>

        {/* QR fallback */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>No USB? Use optical transfer</Text>
          <Text style={styles.cardBody}>
            Display the capture as QR codes on this screen and scan them with
            the air-gapped machine's camera.
          </Text>
          <TouchableOpacity
            style={styles.secondaryButton}
            onPress={startQrFallback}
            accessibilityRole="button"
            accessibilityLabel={`Show capture data as ${precomputedQrChunks.length} QR codes for optical transfer`}
          >
            <Text style={styles.secondaryButtonText}>
              📲 Show as QR codes ({precomputedQrChunks.length} screens)
            </Text>
          </TouchableOpacity>
        </View>

        {/* Debug bundle export — safe to share */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Need help? Export debug info</Text>
          <Text style={styles.cardBody}>
            Creates a small text file with capture statistics and device info.
            {'\n\n'}No payloads, passwords, or sensitive content included — safe to share for troubleshooting.
          </Text>
          <TouchableOpacity
            style={styles.secondaryButton}
            onPress={handleDebugBundleExport}
            disabled={debugBundleExporting}
            accessibilityRole="button"
            accessibilityLabel="Export sanitized debug bundle. Contains no sensitive data."
          >
            <Text style={styles.secondaryButtonText}>
              {debugBundleExporting
                ? '⏳ Exporting…'
                : debugBundlePath
                  ? '✅ Debug bundle saved'
                  : '🛡️ Export Debug Bundle'}
            </Text>
          </TouchableOpacity>
          {debugBundlePath && (
            <Text style={styles.debugBundleHint}>
              Saved to Downloads — safe to share with support
            </Text>
          )}
        </View>

        {/* New capture */}
        <TouchableOpacity
          style={styles.ghostButton}
          onPress={() => navigation.replace('Home')}
          accessibilityRole="button"
          accessibilityLabel="Start a new capture session"
        >
          <Text style={styles.ghostButtonText}>← New capture</Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

// ── Sub-component ─────────────────────────────────────────────────────────────

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.row} accessible={true} accessibilityLabel={`${label}: ${value}`}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue}>{value}</Text>
    </View>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: Colors.background },
  scroll: { padding: Spacing.lg, paddingBottom: Spacing.xxxl },
  title: {
    color: Colors.textPrimary,
    fontSize: Typography.xl,
    fontWeight: Typography.bold,
    textAlign: 'center',
    marginBottom: Spacing.xs,
    marginTop: Spacing.lg,
  },
  subtitle: {
    color: Colors.textSecondary,
    fontSize: Typography.md,
    textAlign: 'center',
    marginBottom: Spacing.lg,
    paddingHorizontal: Spacing.lg,
    lineHeight: Typography.md * 1.4,
  },
  timeoutMsg: {
    color: Colors.textSecondary,
    fontSize: Typography.md,
    textAlign: 'center',
    marginBottom: Spacing.lg,
  },
  card: {
    backgroundColor: Colors.backgroundSecondary,
    borderRadius: Radius.lg,
    padding: Spacing.lg,
    marginBottom: Spacing.lg,
    ...Shadows.subtle,
  },
  cardTitle: {
    color: Colors.textPrimary,
    fontSize: Typography.lg,
    fontWeight: Typography.semibold,
    marginBottom: Spacing.sm,
  },
  cardBody: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    lineHeight: Typography.sm * 1.5,
    marginBottom: Spacing.md,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: Spacing.xs,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: Colors.surfaceBorder,
  },
  statusRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: Spacing.xs,
  },
  rowLabel: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
  },
  rowValue: {
    color: Colors.textPrimary,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
  statusValue: {
    fontSize: Typography.sm,
    fontWeight: Typography.bold,
  },
  exportingRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
    paddingVertical: Spacing.sm,
  },
  exportingText: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
  },
  pathText: {
    color: Colors.catOrangeLight,
    fontSize: Typography.sm,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    marginBottom: Spacing.xs,
  },
  copyHint: {
    color: Colors.textSecondary,
    fontSize: Typography.xs ?? 10,
    fontFamily: undefined,
  },
  sizeText: {
    color: Colors.textTertiary,
    fontSize: Typography.xs,
    marginBottom: Spacing.md,
  },
  sha256Row: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(96,200,140,0.07)',
    borderRadius: 6,
    paddingHorizontal: Spacing.sm,
    paddingVertical: 6,
    marginBottom: Spacing.sm,
    gap: 6,
    borderWidth: 1,
    borderColor: 'rgba(96,200,140,0.18)',
  },
  sha256Label: {
    color: '#60c88c',
    fontSize: Typography.xs ?? 10,
    fontWeight: '700',
    letterSpacing: 0.5,
    width: 56,
  },
  sha256Hash: {
    flex: 1,
    color: '#a0d4b8',
    fontSize: Typography.xs ?? 10,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  sha256CopyHint: {
    color: '#60c88c',
    fontSize: Typography.xs ?? 10,
  },
  verifyHintBox: {
    backgroundColor: 'rgba(255,255,255,0.03)',
    borderRadius: 6,
    padding: Spacing.sm,
    marginBottom: Spacing.md,
    borderLeftWidth: 2,
    borderLeftColor: 'rgba(96,200,140,0.3)',
  },
  verifyHintTitle: {
    color: Colors.textSecondary,
    fontSize: Typography.xs ?? 10,
    marginBottom: 3,
  },
  verifyHintCode: {
    color: Colors.catOrangeLight,
    fontSize: Typography.xs ?? 10,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  errorText: {
    color: Colors.danger,
    fontSize: Typography.sm,
    marginBottom: Spacing.md,
  },
  adbBox: {
    backgroundColor: Colors.backgroundTertiary,
    borderRadius: Radius.sm,
    padding: Spacing.md,
    marginBottom: Spacing.md,
  },
  adbTitle: {
    color: Colors.textSecondary,
    fontSize: Typography.xs,
    marginBottom: Spacing.xs,
  },
  adbCode: {
    color: Colors.catOrangeLight,
    fontSize: Typography.xs,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    lineHeight: Typography.xs * 1.8,
  },
  copyButton: {
    marginTop: Spacing.sm,
    paddingVertical: Spacing.xs,
    paddingHorizontal: Spacing.md,
    borderWidth: 1,
    borderColor: Colors.catOrange,
    borderRadius: Radius.sm,
    alignSelf: 'flex-start',
  },
  copyButtonText: {
    color: Colors.catOrange,
    fontSize: Typography.xs,
    fontWeight: Typography.semibold,
  },
  primaryButton: {
    backgroundColor: Colors.catOrange,
    paddingVertical: Spacing.md,
    borderRadius: Radius.full,
    alignItems: 'center',
    marginTop: Spacing.sm,
  },
  primaryButtonText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.bold,
  },
  secondaryButton: {
    borderWidth: 1.5,
    borderColor: Colors.catOrange,
    paddingVertical: Spacing.md,
    borderRadius: Radius.full,
    alignItems: 'center',
  },
  secondaryButtonText: {
    color: Colors.catOrange,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
  ghostButton: {
    alignItems: 'center',
    paddingVertical: Spacing.md,
  },
  ghostButtonText: {
    color: Colors.textTertiary,
    fontSize: Typography.sm,
  },
  debugBundleHint: {
    color: Colors.textTertiary,
    fontSize: Typography.xs ?? 10,
    textAlign: 'center',
    marginTop: Spacing.xs,
    fontStyle: 'italic',
  },
  // QR mode
  qrContainer: {
    flex: 1,
    backgroundColor: Colors.background,
    alignItems: 'center',
    justifyContent: 'center',
    padding: Spacing.lg,
  },
  qrTitle: {
    color: Colors.textPrimary,
    fontSize: Typography.lg,
    fontWeight: Typography.bold,
    marginBottom: Spacing.xs,
  },
  qrSubtitle: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
    marginBottom: Spacing.xl,
    textAlign: 'center',
  },
  qrBox: {
    padding: Spacing.md,
    backgroundColor: '#fff',
    borderRadius: Radius.md,
    marginBottom: Spacing.xl,
  },
  qrControls: {
    flexDirection: 'row',
    gap: Spacing.md,
  },
  qrChecksumText: {
    color: Colors.textTertiary,
    fontSize: Typography.xs ?? 10,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    marginBottom: Spacing.sm,
  },
  qrVerifyBox: {
    backgroundColor: 'rgba(96,200,140,0.07)',
    borderRadius: 8,
    padding: Spacing.sm,
    marginBottom: Spacing.md,
    borderWidth: 1,
    borderColor: 'rgba(96,200,140,0.18)',
    width: '100%',
    maxWidth: 320,
  },
  qrVerifyTitle: {
    color: '#60c88c',
    fontSize: Typography.xs ?? 10,
    fontWeight: '700',
    marginBottom: 4,
  },
  qrVerifyText: {
    color: Colors.textSecondary,
    fontSize: Typography.xs ?? 10,
    lineHeight: (Typography.xs ?? 10) * 1.5,
    marginBottom: 4,
  },
  qrVerifyHash: {
    color: '#a0d4b8',
    fontSize: Typography.xs ?? 10,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    textAlign: 'center',
  },
  qrNavButton: {
    paddingHorizontal: Spacing.xl,
    paddingVertical: Spacing.md,
    borderRadius: Radius.full,
    backgroundColor: Colors.backgroundSecondary,
    borderWidth: 1,
    borderColor: Colors.surfaceBorder,
  },
  qrNavPrimary: {
    backgroundColor: Colors.catOrange,
    borderColor: Colors.catOrange,
  },
  qrNavText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.semibold,
  },
});
