/**
 * ExportScreen.tsx — Review results and export JSON.
 *
 * Displays capture summary statistics and offers two export paths:
 *   1. Primary: write JSON to Downloads (USB/ADB retrieval)
 *   2. Fallback: show static QR codes on screen for reverse-optical transfer
 *
 * After successful export, shows ADB pull instructions.
 */

import React, { useState, useCallback, useEffect } from 'react';
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
} from 'react-native';
import QRCode from 'react-native-qrcode-svg';
import { exportResponse } from '../services/jsonExporter';
import { buildQRExportChunks } from '../services/jsonExporter';
import type { ExportResult } from '../types/capture';
import type { ExportScreenProps } from '../types/navigation';
import { useCatToast } from '../components/CatToast';
import { Colors, Typography, Spacing, Radius, Shadows } from '../constants/theme';
import { formatPercent, formatFileSize } from '../utils/formatters';

// ── Component ─────────────────────────────────────────────────────────────────

export function ExportScreen({ route, navigation }: ExportScreenProps) {
  const { response, reason } = route.params;
  const { showToast } = useCatToast();

  const [exporting, setExporting] = useState(false);
  const [exportResult, setExportResult] = useState<ExportResult | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  // QR fallback state
  const [qrMode, setQrMode] = useState(false);
  const [qrChunks, setQrChunks] = useState<string[]>([]);
  const [currentQrIndex, setCurrentQrIndex] = useState(0);

  // ── Summary stats ──────────────────────────────────────────────────────────
  const captured = response.frames_captured;
  const expected = response.frames_missed + response.frames_captured;
  const ratio = expected > 0 ? captured / expected : 0;
  const pct = formatPercent(ratio);

  const recoveryStatus =
    ratio >= 1.5 ? { label: 'Fountain complete', color: Colors.catGold } :
    ratio >= 1.0 ? { label: 'Likely recoverable', color: Colors.success } :
    ratio >= 0.67 ? { label: 'Possibly recoverable', color: Colors.warning } :
    { label: 'May not decode', color: Colors.danger };

  // ── Export handler ─────────────────────────────────────────────────────────
  const handleExport = useCallback(async () => {
    setExporting(true);
    setExportError(null);
    try {
      const result = await exportResponse(response);
      setExportResult(result);
      showToast({ message: 'Delivered to Downloads! 📦🐾', type: 'success' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      setExportError(`Export failed: ${msg}`);
      showToast({ message: 'Hiss... export failed 🙀', type: 'error' });
    } finally {
      setExporting(false);
    }
  }, [response, showToast]);

  // Auto-export on mount for smooth UX
  useEffect(() => {
    void handleExport();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── QR fallback ────────────────────────────────────────────────────────────
  const startQrFallback = useCallback(() => {
    const chunks = buildQRExportChunks(response);
    setQrChunks(chunks);
    setCurrentQrIndex(0);
    setQrMode(true);
  }, [response]);

  // ── iOS Share Sheet ────────────────────────────────────────────────────────
  const shareFile = useCallback(async () => {
    if (!exportResult?.paths[0]) return;
    try {
      await Share.share({ url: `file://${exportResult.paths[0]}` });
    } catch {
      // User dismissed share sheet — not an error
    }
  }, [exportResult]);

  // ── QR Mode ────────────────────────────────────────────────────────────────
  if (qrMode && qrChunks.length > 0) {
    const currentChunk = qrChunks[currentQrIndex] ?? '';
    return (
      <SafeAreaView style={styles.safe}>
        <View style={styles.qrContainer}>
          <Text style={styles.qrTitle}>
            QR Export — {currentQrIndex + 1} / {qrChunks.length}
          </Text>
          <Text style={styles.qrSubtitle}>
            Scan each QR code with the air-gapped machine
          </Text>
          <View style={styles.qrBox}>
            <QRCode
              value={currentChunk}
              size={280}
              color="#000"
              backgroundColor="#fff"
            />
          </View>
          <View style={styles.qrControls}>
            {currentQrIndex > 0 && (
              <TouchableOpacity
                style={styles.qrNavButton}
                onPress={() => setCurrentQrIndex((i) => i - 1)}
              >
                <Text style={styles.qrNavText}>← Previous</Text>
              </TouchableOpacity>
            )}
            {currentQrIndex < qrChunks.length - 1 ? (
              <TouchableOpacity
                style={[styles.qrNavButton, styles.qrNavPrimary]}
                onPress={() => setCurrentQrIndex((i) => i + 1)}
              >
                <Text style={styles.qrNavText}>Next →</Text>
              </TouchableOpacity>
            ) : (
              <TouchableOpacity
                style={[styles.qrNavButton, styles.qrNavPrimary]}
                onPress={() => setQrMode(false)}
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
          {reason === 'timeout' ? '⏰ Timed out' : '🎉 Capture Complete'}
        </Text>
        {reason === 'timeout' && (
          <Text style={styles.timeoutMsg}>
            We caught {captured} of {expected} frames. That might be enough!
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
          <Text style={styles.cardTitle}>Export to Downloads</Text>
          {exporting && (
            <View style={styles.exportingRow}>
              <ActivityIndicator color={Colors.catOrange} />
              <Text style={styles.exportingText}>Writing JSON...</Text>
            </View>
          )}
          {exportError && (
            <Text style={styles.errorText}>{exportError}</Text>
          )}
          {exportResult && (
            <>
              {exportResult.paths.map((path, i) => (
                <Text key={i} style={styles.pathText} numberOfLines={2}>
                  📄 {path.split('/').pop()}
                </Text>
              ))}
              <Text style={styles.sizeText}>
                {formatFileSize(exportResult.totalBytes)}
                {exportResult.chunkCount > 1 && ` (${exportResult.chunkCount} files)`}
              </Text>

              {/* ADB instructions */}
              <View style={styles.adbBox}>
                <Text style={styles.adbTitle}>Retrieve with ADB:</Text>
                <Text style={styles.adbCode}>
                  {`adb pull /sdcard/Download/meow-capture-${response.session_id.slice(0, 8)}*.json ./\nmeow-decoder decode --input meow-capture-*.json`}
                </Text>
              </View>

              {/* iOS share */}
              {Platform.OS === 'ios' && (
                <TouchableOpacity
                  style={styles.secondaryButton}
                  onPress={shareFile}
                >
                  <Text style={styles.secondaryButtonText}>
                    Share via Files app →
                  </Text>
                </TouchableOpacity>
              )}
            </>
          )}

          {!exporting && exportError && (
            <TouchableOpacity
              style={styles.primaryButton}
              onPress={handleExport}
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
          >
            <Text style={styles.secondaryButtonText}>
              📲 Show as QR codes ({buildQRExportChunks(response).length} screens)
            </Text>
          </TouchableOpacity>
        </View>

        {/* New capture */}
        <TouchableOpacity
          style={styles.ghostButton}
          onPress={() => navigation.navigate('Home')}
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
    <View style={styles.row}>
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
  sizeText: {
    color: Colors.textTertiary,
    fontSize: Typography.xs,
    marginBottom: Spacing.md,
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
