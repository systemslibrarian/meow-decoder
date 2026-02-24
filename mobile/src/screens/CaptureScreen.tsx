/**
 * CaptureScreen.tsx — Live camera capture with progress HUD.
 *
 * Orchestrates:
 *  - CameraPreview (Vision Camera + frame processor)
 *  - FrameOverlay (scan region, status badges)
 *  - ProgressHUD (animated progress ring)
 *  - StabilityIndicator (shake warnings)
 *  - CatToast (milestone/event notifications)
 *  - Memory pressure warnings
 *
 * Navigation: on COMPLETE or TIMED_OUT → ExportScreen
 *             on CANCEL → Home
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Platform,
} from 'react-native';
import { useCatToast } from '../components/CatToast';
import { CameraPreview } from '../components/CameraPreview';
import { ProgressHUD } from '../components/ProgressHUD';
import { FrameOverlay } from '../components/FrameOverlay';
import { StabilityIndicator } from '../components/StabilityIndicator';
import { useSessionManager } from '../hooks/useSessionManager';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';
import { formatCountdown } from '../utils/formatters';
import type { CaptureScreenProps } from '../types/navigation';

// ── Component ─────────────────────────────────────────────────────────────────

export function CaptureScreen({ route, navigation }: CaptureScreenProps) {
  const { request } = route.params;
  const { showToast } = useCatToast();

  const {
    status,
    progress,
    error,
    elapsedMs,
    remainingMs,
    isStable,
    shakeMagnitude,
    isNearMemoryLimit,
    lastMilestone,
    loadRequest,
    stop,
    cancel,
    markExporting,
    buildResponse,
    frameProcessor,
  } = useSessionManager();

  // Track whether a QR was detected in the most recent frame tick
  const [qrActive, setQrActive] = useState(false);
  const qrActiveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Load request on mount ──────────────────────────────────────────────────
  useEffect(() => {
    loadRequest(request);
  }, [request, loadRequest]);

  // ── Navigate on terminal states ────────────────────────────────────────────
  useEffect(() => {
    if (status === 'COMPLETE' || status === 'TIMED_OUT') {
      const response = buildResponse();
      if (!response) return;
      markExporting();
      navigation.replace('Export', {
        response,
        reason:
          status === 'TIMED_OUT'
            ? 'timeout'
            : 'complete',
      });
    }
  }, [status, buildResponse, markExporting, navigation]);

  // Handle cancel
  const handleCancel = () => {
    cancel();
    navigation.goBack();
  };

  // ── Milestone toasts ───────────────────────────────────────────────────────
  const firedMilestonesRef = useRef(new Set<number>());
  useEffect(() => {
    if (lastMilestone === null || firedMilestonesRef.current.has(lastMilestone)) return;
    firedMilestonesRef.current.add(lastMilestone);

    const TOASTS: Record<number, { message: string; type: 'milestone' | 'success' }> = {
      0.25: { message: 'Purrfect progress! 25% 🐱', type: 'milestone' },
      0.5: { message: 'Halfway there! 🐾', type: 'milestone' },
      0.75: { message: 'Almost there! 75% 😼', type: 'milestone' },
      1.0: { message: 'Paws up! Fountain frames captured 😸', type: 'success' },
    };

    const toast = TOASTS[lastMilestone];
    if (toast) showToast(toast);
  }, [lastMilestone, showToast]);

  // ── Memory pressure warning ────────────────────────────────────────────────
  const memoryWarnFiredRef = useRef(false);
  useEffect(() => {
    if (isNearMemoryLimit && !memoryWarnFiredRef.current) {
      memoryWarnFiredRef.current = true;
      showToast({
        message: '⚠️ Large capture — consider exporting soon',
        type: 'info',
        durationMs: 4000,
      });
    }
  }, [isNearMemoryLimit, showToast]);

  // ── Error handling ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (status === 'ERROR' && error) {
      showToast({ message: `Error: ${error}`, type: 'error' });
    }
  }, [status, error, showToast]);

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <View style={styles.container}>
      {/* Full-screen camera with frame processor */}
      <CameraPreview frameProcessor={frameProcessor} status={status} />

      {/* Scan region + status badges */}
      <FrameOverlay status={status} qrDetected={qrActive} />

      {/* Stability warning */}
      <StabilityIndicator magnitude={shakeMagnitude} visible={!isStable && status === 'CAPTURING'} />

      {/* Status bar at top */}
      <View style={styles.statusBar}>
        <Text style={styles.statusText}>{statusLabel(status)}</Text>
        {remainingMs !== null && status === 'CAPTURING' && (
          <Text style={styles.timerText}>
            ⏱ {formatCountdown(remainingMs / 1000)}
          </Text>
        )}
      </View>

      {/* Progress HUD (shown once capturing starts) */}
      {progress && (status === 'CAPTURING' || status === 'AWAITING_GIF') && (
        <ProgressHUD
          progress={progress}
          status={status}
          elapsedMs={elapsedMs}
        />
      )}

      {/* Memory pressure banner */}
      {isNearMemoryLimit && (
        <View style={styles.memoryBanner}>
          <Text style={styles.memoryText}>
            ⚠️ High frame count — tap Done soon
          </Text>
        </View>
      )}

      {/* Controls */}
      <View style={styles.controls}>
        <TouchableOpacity
          style={styles.cancelButton}
          onPress={handleCancel}
          accessibilityRole="button"
          accessibilityLabel="Cancel capture"
        >
          <Text style={styles.buttonText}>✕ Cancel</Text>
        </TouchableOpacity>

        {(status === 'CAPTURING' || status === 'AWAITING_GIF') && (
          <TouchableOpacity
            style={[
              styles.stopButton,
              progress?.isRecoverable && styles.stopButtonReady,
            ]}
            onPress={stop}
            accessibilityRole="button"
            accessibilityLabel="Stop capture and export"
          >
            <Text style={styles.buttonText}>
              {progress?.isFountainComplete ? '😸 Done!' : '🐾 Stop'}
            </Text>
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusLabel(status: string): string {
  switch (status) {
    case 'AWAITING_GIF': return '🔍 Point at animated QR code...';
    case 'CAPTURING': return '😼 Catching frames...';
    case 'TIMED_OUT': return "⏰ Time's up! Exporting...";
    case 'COMPLETE': return '✅ Done! Preparing export...';
    default: return '';
  }
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.background },
  statusBar: {
    position: 'absolute',
    top: Platform.OS === 'ios' ? 60 : 40,
    left: 0,
    right: 0,
    alignItems: 'center',
    gap: Spacing.xs,
  },
  statusText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.semibold,
    backgroundColor: Colors.overlayDark,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.xs,
    borderRadius: Radius.full,
    overflow: 'hidden',
  },
  timerText: {
    color: Colors.catGold,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
    backgroundColor: Colors.overlayDark,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.xxs,
    borderRadius: Radius.full,
    overflow: 'hidden',
  },
  memoryBanner: {
    position: 'absolute',
    top: Platform.OS === 'ios' ? 130 : 110,
    left: Spacing.lg,
    right: Spacing.lg,
    backgroundColor: 'rgba(255,159,10,0.85)',
    borderRadius: Radius.md,
    padding: Spacing.sm,
    alignItems: 'center',
  },
  memoryText: {
    color: Colors.textPrimary,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
  controls: {
    position: 'absolute',
    bottom: Platform.OS === 'ios' ? 48 : 32,
    left: 0,
    right: 0,
    flexDirection: 'row',
    justifyContent: 'space-around',
    paddingHorizontal: Spacing.xl,
  },
  cancelButton: {
    backgroundColor: 'rgba(255,59,48,0.85)',
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
    borderRadius: Radius.full,
  },
  stopButton: {
    backgroundColor: 'rgba(255,140,66,0.85)',
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
    borderRadius: Radius.full,
  },
  stopButtonReady: {
    backgroundColor: 'rgba(52,199,89,0.9)',
  },
  buttonText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.bold,
  },
});
