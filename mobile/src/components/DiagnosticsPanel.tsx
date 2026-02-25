/**
 * DiagnosticsPanel.tsx — Hidden developer / field diagnostics overlay.
 *
 * Activated by a long-press on the version badge in HomeScreen.
 * Shows live telemetry without any network transfer; all metrics are
 * derived from RN's own APIs and data already flowing through hooks.
 *
 * Metrics exposed:
 *   - Decode rate (fresh frames/s, last 3 s window)
 *   - Duplicate rate (%)
 *   - Shake magnitude (normalised 0–1)
 *   - Exposure bias (–1 → +1)
 *   - JS-thread lag (ms between `requestAnimationFrame` ticks vs 16.67 ms ideal)
 *   - JS heap estimate (where available via performance.memory)
 *   - Thermal state (basic heuristic from sustained high-lag + high decode rate)
 *   - Session frame count / fountain k blocks / progress %
 *
 * Usage:
 *   <DiagnosticsPanel
 *     visible={showDiag}
 *     onDismiss={() => setShowDiag(false)}
 *     decodeRate={decodeRate}
 *     duplicateRate={duplicateRate}
 *     shakeMagnitude={shakeMagnitude}
 *     exposureBias={exposureBias}
 *     framesCaptured={framesCaptured}
 *     framesExpected={framesExpected}
 *     sessionId={sessionId}
 *   />
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Modal,
  ScrollView,
  Platform,
  PixelRatio,
  Share,
  Dimensions,
} from 'react-native';
import Clipboard from '@react-native-clipboard/clipboard';
import RNFS from 'react-native-fs';
import { APP_VERSION, PROTOCOL_VERSION, FEATURE_FLAGS } from '../constants/config';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DiagnosticsProps {
  visible: boolean;
  onDismiss: () => void;
  decodeRate?: number;
  duplicateRate?: number;
  shakeMagnitude?: number;
  exposureBias?: number;
  framesCaptured?: number;
  framesExpected?: number;
  sessionId?: string;
}

interface DiagSnapshot {
  decodeRate: number;
  duplicateRate: number;
  shakeMagnitude: number;
  exposureBias: number;
  framesCaptured: number;
  framesExpected: number;
  sessionId: string;
  jsLagMs: number;
  heapUsedMB: number;
  heapTotalMB: number;
  thermalState: string;
  timestamp: string;
}

// ── Thermal heuristic ─────────────────────────────────────────────────────────

function estimateThermal(jsLagMs: number, decodeRate: number): string {
  if (jsLagMs > 120) return '🔴 Hot (high JS lag)';
  if (jsLagMs > 60) return '🟠 Warm';
  if (decodeRate > 8) return '🟡 Elevated (active scan)';
  return '🟢 Nominal';
}

// ── JS heap helper (non-standard, available on some engines) ──────────────────

function readHeapMB(): { used: number; total: number } {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mem = (performance as any)?.memory;
    if (mem) {
      return {
        used: Math.round((mem.usedJSHeapSize / 1024 / 1024) * 10) / 10,
        total: Math.round((mem.totalJSHeapSize / 1024 / 1024) * 10) / 10,
      };
    }
  } catch {
    // not available
  }
  return { used: 0, total: 0 };
}

// ── Component ─────────────────────────────────────────────────────────────────

export const DiagnosticsPanel: React.FC<DiagnosticsProps> = ({
  visible,
  onDismiss,
  decodeRate = 0,
  duplicateRate = 0,
  shakeMagnitude = 0,
  exposureBias = 0,
  framesCaptured = 0,
  framesExpected = 0,
  sessionId = '—',
}) => {
  const [snapshot, setSnapshot] = useState<DiagSnapshot | null>(null);
  const [sharing, setSharing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copiedSafe, setCopiedSafe] = useState(false);
  const rafHandle = useRef<number | null>(null);
  const lastFrameTime = useRef<number>(Date.now());
  const lagSamples = useRef<number[]>([]);

  // ── Measure JS-thread lag via rAF deltas ────────────────────────────────────

  const measureLag = useCallback(() => {
    if (!visible) return;
    const now = Date.now();
    const delta = now - lastFrameTime.current;
    lastFrameTime.current = now;

    // 16.67 ms is ideal for 60 fps; delta - 16.67 is the lag.
    const lag = Math.max(0, delta - 16.67);
    lagSamples.current.push(lag);
    if (lagSamples.current.length > 30) lagSamples.current.shift();

    rafHandle.current = requestAnimationFrame(measureLag);
  }, [visible]);

  useEffect(() => {
    if (visible) {
      lastFrameTime.current = Date.now();
      rafHandle.current = requestAnimationFrame(measureLag);
    }
    return () => {
      if (rafHandle.current !== null) cancelAnimationFrame(rafHandle.current);
    };
  }, [visible, measureLag]);

  // ── Snapshot refresh at 1 Hz ─────────────────────────────────────────────────

  useEffect(() => {
    if (!visible) return;

    const tick = () => {
      const avgLag =
        lagSamples.current.length > 0
          ? lagSamples.current.reduce((a, b) => a + b, 0) / lagSamples.current.length
          : 0;

      const heap = readHeapMB();

      setSnapshot({
        decodeRate,
        duplicateRate,
        shakeMagnitude,
        exposureBias,
        framesCaptured,
        framesExpected,
        sessionId,
        jsLagMs: Math.round(avgLag * 10) / 10,
        heapUsedMB: heap.used,
        heapTotalMB: heap.total,
        thermalState: estimateThermal(avgLag, decodeRate),
        timestamp: new Date().toISOString().replace('T', ' ').slice(0, -5),
      });
    };

    tick(); // immediate
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [
    visible,
    decodeRate,
    duplicateRate,
    shakeMagnitude,
    exposureBias,
    framesCaptured,
    framesExpected,
    sessionId,
  ]);

  if (!visible || !snapshot) return null;

  const progress =
    snapshot.framesExpected > 0
      ? ((snapshot.framesCaptured / snapshot.framesExpected) * 100).toFixed(1)
      : '—';

  // ── Build copyable debug report ────────────────────────────────────────────

  const buildDebugReport = (): string => {
    const screen = Dimensions.get('window');
    const fontScale = typeof PixelRatio !== 'undefined' ? PixelRatio.getFontScale().toFixed(2) : 'N/A';
    const pixelRatio = typeof PixelRatio !== 'undefined' ? PixelRatio.get().toFixed(1) : 'N/A';
    const newFrames = snapshot.framesCaptured;
    const dupCount = snapshot.duplicateRate > 0 && snapshot.framesCaptured > 0
      ? Math.round((snapshot.duplicateRate / (1 - snapshot.duplicateRate + 0.001)) * newFrames)
      : 0;

    const lines = [
      '=== Meow Capture Diagnostics Report ===',
      `Report generated: ${snapshot.timestamp}`,
      '',
      '--- App ---',
      `App version:     Meow Capture v${APP_VERSION}`,
      `Protocol:        v${PROTOCOL_VERSION}`,
      `Feature flags:   VIDEO_IMPORT=${FEATURE_FLAGS.VIDEO_IMPORT}`,
      '',
      '--- Device ---',
      `Platform:        ${Platform.OS} ${Platform.Version}`,
      `Screen:          ${Math.round(screen.width)}×${Math.round(screen.height)} @${pixelRatio}x`,
      `Font scale:      ${fontScale}`,
      '',
      '--- Capture ---',
      `Session ID:      …${snapshot.sessionId.slice(-8)} (truncated)`,
      `Decode rate:     ${snapshot.decodeRate.toFixed(1)} fps`,
      `Duplicate rate:  ${(snapshot.duplicateRate * 100).toFixed(0)}%`,
      `New frames:      ${newFrames}`,
      `Duplicate scans: ~${dupCount}`,
      `Expected frames: ${snapshot.framesExpected || '?'}`,
      `Progress:        ${progress}%`,
      '',
      '--- Camera ---',
      `Shake magnitude: ${snapshot.shakeMagnitude.toFixed(3)}`,
      `Exposure bias:   ${snapshot.exposureBias.toFixed(2)}`,
      '',
      '--- Performance ---',
      `JS thread lag:   ${snapshot.jsLagMs} ms`,
      `Heap used:       ${snapshot.heapUsedMB > 0 ? `${snapshot.heapUsedMB} / ${snapshot.heapTotalMB} MB` : 'N/A'}`,
      `Thermal state:   ${snapshot.thermalState}`,
      '',
      '--- Security ---',
      'Trust model:     Untrusted dumb sensor (no crypto on device)',
      'Network:         NONE (zero permissions declared)',
      'Screen privacy:  FLAG_SECURE (Android) / overlay (iOS)',
      '',
      '⚠️  SAFE TO SHARE — no frame payloads, passwords, or',
      '   sensitive content is included in this report.',
      '',
      '(Generated by Meow Capture v' + APP_VERSION + ' diagnostics panel)',
    ];
    return lines.join('\n');
  };

  // ── Share diagnostics as file ──────────────────────────────────────────────
  const handleShareDiagnostics = async () => {
    setSharing(true);
    try {
      const report = buildDebugReport();
      const filename = `meow-diagnostics-${new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-')}.txt`;
      const dir = Platform.OS === 'android' ? RNFS.DownloadDirectoryPath : RNFS.DocumentDirectoryPath;
      const path = `${dir}/${filename}`;
      await RNFS.writeFile(path, report, 'utf8');
      if (Platform.OS === 'ios') {
        await Share.share({ url: `file://${path}`, title: 'Meow Capture Diagnostics' });
      } else {
        // On Android, write to Downloads and inform the user
        setCopied(false);
        Clipboard.setString(report);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch {
      // Fail silently — diagnostics sharing is best-effort
    } finally {
      setSharing(false);
    }
  };

  const handleCopyReport = () => {
    Clipboard.setString(buildDebugReport());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // ── Build privacy-safe report (no session ID, no heap addresses) ───────────

  const buildSafeReport = (): string => {
    const screen = Dimensions.get('window');
    const pixelRatio = typeof PixelRatio !== 'undefined' ? PixelRatio.get().toFixed(1) : 'N/A';
    const fontScale = typeof PixelRatio !== 'undefined' ? PixelRatio.getFontScale().toFixed(2) : 'N/A';
    const lines = [
      '=== Meow Capture — Safe Support Report ===',
      `Timestamp:       ${snapshot.timestamp}`,
      '',
      '--- App ---',
      `App:             Meow Capture v${APP_VERSION}`,
      `Protocol:        v${PROTOCOL_VERSION}`,
      `Feature flags:   VIDEO_IMPORT=${FEATURE_FLAGS.VIDEO_IMPORT}`,
      '',
      '--- Device ---',
      `Platform:        ${Platform.OS} ${Platform.Version}`,
      `Screen:          ${Math.round(screen.width)}×${Math.round(screen.height)} @${pixelRatio}x`,
      `Font scale:      ${fontScale}`,
      '',
      '--- Capture Metrics ---',
      `Decode rate:     ${snapshot.decodeRate.toFixed(1)} fps`,
      `Duplicate rate:  ${(snapshot.duplicateRate * 100).toFixed(0)}%`,
      `Frames captured: ${snapshot.framesCaptured}`,
      `Expected frames: ${snapshot.framesExpected || '?'}`,
      `Progress:        ${progress}%`,
      '',
      '--- Camera ---',
      `Shake magnitude: ${snapshot.shakeMagnitude.toFixed(3)}`,
      `Exposure bias:   ${snapshot.exposureBias.toFixed(2)}`,
      '',
      '--- Performance ---',
      `JS thread lag:   ${snapshot.jsLagMs} ms`,
      `Thermal state:   ${snapshot.thermalState}`,
      '',
      '--- Security ---',
      'Trust model:     Untrusted dumb sensor (no crypto on device)',
      'Network:         NONE (zero permissions declared)',
      '',
      '╔══════════════════════════════════════════════════════════╗',
      '║  NO payloads, passwords, session IDs, encryption keys,  ║',
      '║  or heap addresses included. Safe to share for support. ║',
      '╚══════════════════════════════════════════════════════════╝',
      '',
      '(Generated by Meow Capture v' + APP_VERSION + ' diagnostics)',
    ];
    return lines.join('\n');
  };

  const handleCopySafeReport = () => {
    Clipboard.setString(buildSafeReport());
    setCopiedSafe(true);
    setTimeout(() => setCopiedSafe(false), 2000);
  };

  // ── Rows helper ──────────────────────────────────────────────────────────────

  const Row = ({
    label,
    value,
    highlight,
  }: {
    label: string;
    value: string;
    highlight?: boolean;
  }) => (
    <View style={styles.row} accessible={true} accessibilityLabel={`${label}: ${value}`}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={[styles.rowValue, highlight && styles.rowValueHighlight]}>{value}</Text>
    </View>
  );

  return (
    <Modal visible transparent animationType="fade" statusBarTranslucent onRequestClose={onDismiss} accessibilityViewIsModal>
      <View style={styles.overlay}>
        <View style={styles.panel}>
          {/* Header */}
          <View style={styles.header}>
            <Text style={styles.headerTitle} accessibilityRole="header">🔬 Diagnostics</Text>
            <Text style={styles.timestamp}>{snapshot.timestamp}</Text>
            <TouchableOpacity
              onPress={onDismiss}
              style={styles.closeBtnWrapper}
              accessibilityRole="button"
              accessibilityLabel="Close diagnostics"
            >
              <Text style={styles.closeBtn}>✕</Text>
            </TouchableOpacity>
          </View>

          <ScrollView showsVerticalScrollIndicator={false}>
            {/* Capture metrics */}
            <Text style={styles.sectionTitle} accessibilityRole="header">CAPTURE</Text>
            <Row
              label="Decode rate"
              value={`${snapshot.decodeRate.toFixed(1)} fps`}
              highlight={snapshot.decodeRate >= 3}
            />
            <Row
              label="Duplicate rate"
              value={`${(snapshot.duplicateRate * 100).toFixed(0)}%`}
            />
            <Row
              label="Frames captured"
              value={`${snapshot.framesCaptured} / ${snapshot.framesExpected || '?'}`}
            />
            <Row label="Progress" value={`${progress}%`} highlight={snapshot.framesCaptured > 0} />
            <Row label="Session ID" value={`…${snapshot.sessionId.slice(-8)}`} />

            {/* Camera metrics */}
            <Text style={styles.sectionTitle} accessibilityRole="header">CAMERA</Text>
            <Row
              label="Shake magnitude"
              value={snapshot.shakeMagnitude.toFixed(3)}
              highlight={snapshot.shakeMagnitude < 0.3}
            />
            <Row
              label="Exposure bias"
              value={snapshot.exposureBias.toFixed(2)}
              highlight={Math.abs(snapshot.exposureBias) < 0.2}
            />

            {/* Performance metrics */}
            <Text style={styles.sectionTitle} accessibilityRole="header">PERFORMANCE</Text>
            <Row
              label="JS thread lag"
              value={`${snapshot.jsLagMs} ms`}
              highlight={snapshot.jsLagMs < 20}
            />
            <Row
              label="Heap used"
              value={
                snapshot.heapUsedMB > 0
                  ? `${snapshot.heapUsedMB} / ${snapshot.heapTotalMB} MB`
                  : 'N/A'
              }
            />
            <Row label="Platform" value={`${Platform.OS} ${Platform.Version}`} />
            <Row label="Thermal" value={snapshot.thermalState} />

            <View style={styles.disclaimer}>
              <Text style={styles.disclaimerText}>
                For field debugging only. No data leaves device.
              </Text>
            </View>

            {/* One-tap safe report button — prominent, privacy-explicit */}
            <TouchableOpacity
              style={styles.safeReportBtn}
              onPress={handleCopySafeReport}
              accessibilityRole="button"
              accessibilityLabel="Copy safe report to clipboard. Contains no session IDs or sensitive data."
            >
              <Text style={styles.safeReportText}>
                {copiedSafe ? '✅ Copied!' : '🛡️ Copy Safe Report to Clipboard'}
              </Text>
              {!copiedSafe && (
                <Text style={styles.safeReportHint}>
                  No session IDs, keys, or payloads — safe to share
                </Text>
              )}
            </TouchableOpacity>

            {/* Full debug report — secondary, for developer use */}
            <TouchableOpacity
              style={styles.copyReportBtn}
              onPress={handleCopyReport}
              accessibilityRole="button"
              accessibilityLabel="Copy full debug report to clipboard"
            >
              <Text style={styles.copyReportText}>
                {copied ? '✅ Copied!' : '📋 Copy Full Debug Report'}
              </Text>
            </TouchableOpacity>

            {/* Share as file — iOS uses share sheet, Android saves to Downloads */}
            <TouchableOpacity
              style={styles.copyReportBtn}
              onPress={handleShareDiagnostics}
              disabled={sharing}
              accessibilityRole="button"
              accessibilityLabel="Export diagnostics report as a text file"
            >
              <Text style={styles.copyReportText}>
                {sharing
                  ? '⏳ Exporting…'
                  : Platform.OS === 'ios'
                    ? '📤 Share Diagnostics File'
                    : '💾 Save Diagnostics to Downloads'}
              </Text>
            </TouchableOpacity>
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
};

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.6)',
    padding: 16,
  },
  panel: {
    backgroundColor: '#0d0d18',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: '#2a2a40',
    width: '100%',
    maxHeight: '80%',
    padding: 14,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
    gap: 6,
  },
  headerTitle: {
    flex: 1,
    fontSize: 14,
    fontWeight: '700',
    color: '#e8e8f0',
  },
  timestamp: {
    fontSize: 10,
    color: '#555570',
    fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace' }),
  },
  closeBtn: {
    fontSize: 16,
    color: '#8888a8',
  },
  closeBtnWrapper: {
    minWidth: 44,
    minHeight: 44,
    justifyContent: 'center',
    alignItems: 'center',
    marginLeft: 4,
  },
  sectionTitle: {
    fontSize: 10,
    fontWeight: '700',
    letterSpacing: 1.2,
    color: '#7272A0',
    marginTop: 10,
    marginBottom: 4,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 4,
    borderBottomWidth: 1,
    borderBottomColor: '#1a1a28',
  },
  rowLabel: {
    fontSize: 11,
    color: '#8888a8',
  },
  rowValue: {
    fontSize: 11,
    color: '#8888a8',
    fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace' }),
  },
  rowValueHighlight: {
    color: '#a0d4b8',
  },
  copyReportBtn: {
    marginTop: 8,
    paddingVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#3a3a58',
    backgroundColor: 'rgba(255,255,255,0.04)',
    alignItems: 'center',
  },
  copyReportText: {
    fontSize: 12,
    color: '#a0a0c0',
    fontWeight: '600',
  },
  safeReportBtn: {
    marginTop: 12,
    paddingVertical: 10,
    paddingHorizontal: 16,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#3a7a50',
    backgroundColor: 'rgba(76, 175, 128, 0.10)',
    alignItems: 'center',
  },
  safeReportText: {
    fontSize: 13,
    color: '#4caf80',
    fontWeight: '700',
  },
  safeReportHint: {
    fontSize: 10,
    color: '#6E8A6E',
    marginTop: 3,
    fontStyle: 'italic',
  },
  disclaimer: {
    marginTop: 16,
    paddingTop: 10,
    borderTopWidth: 1,
    borderTopColor: '#1a1a28',
  },
  disclaimerText: {
    fontSize: 11,
    color: '#6E6E8A',
    textAlign: 'center',
    fontStyle: 'italic',
  },
});

export default DiagnosticsPanel;
