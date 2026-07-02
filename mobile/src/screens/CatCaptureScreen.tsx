/**
 * CatCaptureScreen.tsx — live Cat Mode blink capture.
 *
 * Flow:
 *   1. Open → camera + two DRAGGABLE eye boxes. Live meters move so you can
 *      place each box on the cat's eyes (works for any cat size/position).
 *   2. Tap "Start scanning" right as the cat begins transmitting — the capture
 *      window (and timeout) start then, so aligning never burns the budget.
 *   3. Once the preamble locks, a progress bar + ETA show how much of the
 *      payload has arrived. On completion → binary pattern with Copy / Save.
 *
 * No decryption happens on-device (the app is an untrusted optical sensor).
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Platform,
  Alert,
  ScrollView,
  type LayoutChangeEvent,
} from 'react-native';
import { Camera, useCameraDevice, useCameraPermission } from 'react-native-vision-camera';
import { Gesture, GestureDetector } from 'react-native-gesture-handler';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  clamp,
  runOnJS,
} from 'react-native-reanimated';
import ReactNativeHapticFeedback from 'react-native-haptic-feedback';
import { useCatSession } from '../hooks/useCatSession';
import { useCatBlinkSampler } from '../hooks/useCatBlinkSampler';
import { exportCatBinary, copyCatBinary } from '../services/catBinaryExporter';
import {
  DEFAULT_LEFT_EYE_ROI,
  DEFAULT_RIGHT_EYE_ROI,
  type NormalizedRoi,
} from '../services/roiSampler';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';
import type { CatCaptureScreenProps } from '../types/navigation';

const HAPTIC_OPTIONS = { enableVibrateFallback: true, ignoreAndroidSystemSettings: false };

export function CatCaptureScreen({ navigation }: CatCaptureScreenProps) {
  const { hasPermission, requestPermission } = useCameraPermission();
  const device = useCameraDevice('back');
  const [started, setStarted] = useState(false);

  // Draggable eye boxes. The reanimated shared values drive the smooth on-screen
  // drag; the committed React-state ROIs are what the sampler reads (plain
  // objects — the frame processor runs on the worklets-core runtime and cannot
  // read reanimated shared values). Commit happens on drag release.
  const containerW = useSharedValue(0);
  const containerH = useSharedValue(0);
  const leftBox = useSharedValue<NormalizedRoi>(DEFAULT_LEFT_EYE_ROI);
  const rightBox = useSharedValue<NormalizedRoi>(DEFAULT_RIGHT_EYE_ROI);
  const [leftRoi, setLeftRoi] = useState<NormalizedRoi>(DEFAULT_LEFT_EYE_ROI);
  const [rightRoi, setRightRoi] = useState<NormalizedRoi>(DEFAULT_RIGHT_EYE_ROI);

  const {
    status,
    sampleCount,
    signalLeft,
    signalRight,
    locked,
    everLocked,
    binary,
    bits,
    blinkPeriodMs,
    progress,
    capturedBits,
    expectedBits,
    stoppedEarly,
    onSample,
    finish,
    reset,
  } = useCatSession({ active: true, scanning: started });

  // Derived after the hook (status is its output). The session self-stops its
  // timers on a terminal status via its internal completion latch; these gate
  // the camera/sampler so the hardware powers down once we're done.
  const isTerminal = status === 'complete' || status === 'timeout';
  const active = !isTerminal;
  const scanning = started && !isTerminal;

  const frameProcessor = useCatBlinkSampler({
    onSample,
    enabled: active,
    sampleFps: 30,
    leftRoi,
    rightRoi,
  });

  useEffect(() => {
    if (!hasPermission) void requestPermission();
  }, [hasPermission, requestPermission]);

  useEffect(() => {
    if (status === 'complete') {
      ReactNativeHapticFeedback.trigger('notificationSuccess', HAPTIC_OPTIONS);
    } else if (status === 'timeout') {
      ReactNativeHapticFeedback.trigger('notificationWarning', HAPTIC_OPTIONS);
    }
  }, [status]);

  const onLayout = useCallback(
    (e: LayoutChangeEvent) => {
      containerW.value = e.nativeEvent.layout.width;
      containerH.value = e.nativeEvent.layout.height;
    },
    [containerW, containerH],
  );

  const makePan = useCallback(
    (box: typeof leftBox, commit: (r: NormalizedRoi) => void) =>
      Gesture.Pan()
        .onChange((e) => {
          'worklet';
          const w = containerW.value || 1;
          const h = containerH.value || 1;
          const r = box.value;
          box.value = {
            ...r,
            x: clamp(r.x + e.changeX / w, 0, 1 - r.w),
            y: clamp(r.y + e.changeY / h, 0, 1 - r.h),
          };
        })
        .onEnd(() => {
          'worklet';
          // Commit the final box position to React state for the sampler.
          runOnJS(commit)(box.value);
        }),
    [containerW, containerH],
  );
  const leftPan = useMemo(() => makePan(leftBox, setLeftRoi), [makePan, leftBox]);
  const rightPan = useMemo(() => makePan(rightBox, setRightRoi), [makePan, rightBox]);

  const leftBoxStyle = useAnimatedStyle(() => ({
    left: leftBox.value.x * containerW.value,
    top: leftBox.value.y * containerH.value,
    width: leftBox.value.w * containerW.value,
    height: leftBox.value.h * containerH.value,
  }));
  const rightBoxStyle = useAnimatedStyle(() => ({
    left: rightBox.value.x * containerW.value,
    top: rightBox.value.y * containerH.value,
    width: rightBox.value.w * containerW.value,
    height: rightBox.value.h * containerH.value,
  }));

  const handleStart = useCallback(() => {
    reset();
    setStarted(true);
    ReactNativeHapticFeedback.trigger('impactMedium', HAPTIC_OPTIONS);
  }, [reset]);

  const handleRestart = useCallback(() => {
    reset();
    setStarted(false);
  }, [reset]);

  const handleFinish = useCallback(() => {
    ReactNativeHapticFeedback.trigger('impactMedium', HAPTIC_OPTIONS);
    finish();
  }, [finish]);

  const handleCancel = useCallback(() => {
    reset();
    navigation.goBack();
  }, [reset, navigation]);

  const handleCopy = useCallback(() => {
    try {
      copyCatBinary(binary);
      ReactNativeHapticFeedback.trigger('impactLight', HAPTIC_OPTIONS);
      Alert.alert('Copied', `${bits} bits copied to clipboard.`);
    } catch (e) {
      Alert.alert('Copy failed', e instanceof Error ? e.message : 'Unknown error');
    }
  }, [binary, bits]);

  const handleSave = useCallback(async () => {
    try {
      const res = await exportCatBinary(binary, { blinkPeriodMs });
      ReactNativeHapticFeedback.trigger('notificationSuccess', HAPTIC_OPTIONS);
      Alert.alert('Saved', `Binary pattern saved to:\n${res.filename}\n(${res.bits} bits)`);
    } catch (e) {
      Alert.alert('Save failed', e instanceof Error ? e.message : 'Unknown error');
    }
  }, [binary, blinkPeriodMs]);

  // ── Permission / device gates ──────────────────────────────────────────────
  if (!hasPermission) {
    return (
      <View style={styles.gate}>
        <Text style={styles.gateIcon}>📷</Text>
        <Text style={styles.gateTitle}>Camera access needed</Text>
        <Text style={styles.gateBody}>
          Cat Mode reads the blinking-eye animation through the camera. No images are stored.
        </Text>
        <TouchableOpacity style={styles.primaryBtn} onPress={() => void requestPermission()}>
          <Text style={styles.primaryBtnText}>Grant Permission</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.linkBtn} onPress={handleCancel}>
          <Text style={styles.linkText}>Cancel</Text>
        </TouchableOpacity>
      </View>
    );
  }
  if (!device) {
    return (
      <View style={styles.gate}>
        <Text style={styles.gateTitle}>No camera available</Text>
        <TouchableOpacity style={styles.linkBtn} onPress={handleCancel}>
          <Text style={styles.linkText}>Go back</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const showComplete = status === 'complete';
  const showTimeout = status === 'timeout';
  const showOverlay = showComplete || showTimeout;
  // A manual Finish that ended before the full payload arrived — honest labelling.
  const isPartial = showComplete && stoppedEarly && expectedBits > 0 && bits < expectedBits;

  const remainingFrames = expectedBits > 0 ? Math.max(0, (expectedBits - capturedBits) / 2) : 0;
  const etaSec = blinkPeriodMs > 0 ? Math.round((remainingFrames * blinkPeriodMs) / 1000) : 0;
  const pctText = `${Math.round(progress * 100)}%`;

  return (
    <View style={styles.container} onLayout={onLayout}>
      <Camera
        style={StyleSheet.absoluteFill}
        device={device}
        isActive={active}
        pixelFormat="yuv"
        {...(frameProcessor ? { frameProcessor } : {})}
        audio={false}
      />

      {/* Cat-face alignment outline (framing guide; non-interactive) */}
      {!showOverlay && <CatFaceGuide />}

      {/* Draggable eye boxes */}
      {!showOverlay && (
        <>
          <GestureDetector gesture={leftPan}>
            <Animated.View style={[styles.reticle, locked && styles.reticleLocked, leftBoxStyle]}>
              <Text style={styles.reticleLabel}>L</Text>
            </Animated.View>
          </GestureDetector>
          <GestureDetector gesture={rightPan}>
            <Animated.View style={[styles.reticle, locked && styles.reticleLocked, rightBoxStyle]}>
              <Text style={styles.reticleLabel}>R</Text>
            </Animated.View>
          </GestureDetector>
        </>
      )}

      {/* Always-visible Home button (top-left) */}
      <TouchableOpacity
        style={styles.homeButton}
        onPress={handleCancel}
        accessibilityRole="button"
        accessibilityLabel="Back to main menu"
        hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
      >
        <Text style={styles.homeButtonText}>🏠</Text>
      </TouchableOpacity>

      {/* Top status */}
      <View style={styles.statusBar} pointerEvents="none">
        <Text style={styles.statusText} accessibilityLiveRegion="polite">
          {statusLabel(status, started)}
        </Text>
        {scanning && locked && (
          <Text style={styles.subStatus}>
            🔒 Synced · ~{Math.round(blinkPeriodMs)}ms/blink
          </Text>
        )}
      </View>

      {/* Live diagnostics — helps confirm the boxes are reading the eyes */}
      {!showOverlay && (
        <View style={styles.diag} pointerEvents="none">
          <Text style={styles.diagText}>
            L {Math.round(signalLeft)} · R {Math.round(signalRight)}
            {everLocked ? ` · 🔒 ${Math.round(blinkPeriodMs)}ms` : ' · finding sync…'}
            {scanning ? ` · ${sampleCount} smp` : ''}
          </Text>
        </View>
      )}

      {/* Live eye meters (alignment aid) */}
      {!showOverlay && (
        <View style={styles.meters} pointerEvents="none">
          <EyeMeter label="L" value={signalLeft} />
          <EyeMeter label="R" value={signalRight} />
        </View>
      )}

      {/* Progress (scanning + locked) */}
      {scanning && expectedBits > 0 && (
        <View style={styles.progressWrap} pointerEvents="none">
          <View style={styles.progressBarBg}>
            <View
              style={[styles.progressBarFill, { width: `${Math.round(progress * 100)}%` }]}
            />
          </View>
          <Text style={styles.progressText}>
            {pctText} received · {Math.round(capturedBits / 8)}/{Math.round(expectedBits / 8)} bytes
            {etaSec > 0 ? ` · ~${etaSec}s left` : ''}
          </Text>
        </View>
      )}
      {scanning && expectedBits === 0 && (
        <View style={styles.progressWrap} pointerEvents="none">
          <Text style={styles.progressText}>
            🔍 Searching for the cat’s signal… ({sampleCount} samples)
          </Text>
        </View>
      )}

      {/* Completion panel */}
      {showComplete && (
        <View style={styles.resultPanel}>
          <Text style={styles.resultTitle}>
            {isPartial ? `⏹ Stopped — ${bits} bits` : `✅ Captured ${bits} bits`}
          </Text>
          {isPartial && (
            <Text style={styles.partialWarn}>
              ⚠️ Partial: {Math.round(capturedBits / 8)} of {Math.round(expectedBits / 8)} bytes.
              A partial pattern usually won’t decrypt — scan again from the start of the
              animation to capture the rest. Saved anyway in case it’s useful.
            </Text>
          )}
          <Text style={styles.resultHint}>
            Paste this into the web demo Cat Mode “Binary Pattern” field, or save it for the
            desktop CLI. The phone does not decrypt.
          </Text>
          <ScrollView style={styles.binaryBox} nestedScrollEnabled>
            <Text style={styles.binaryText} selectable>
              {binary}
            </Text>
          </ScrollView>
          <View style={styles.actionRow}>
            <TouchableOpacity style={styles.actionBtn} onPress={handleCopy}>
              <Text style={styles.actionText}>📋 Copy</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.actionBtn} onPress={() => void handleSave()}>
              <Text style={styles.actionText}>💾 Save</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      {/* Timeout panel — with a reason so we know what to tune */}
      {showTimeout && (
        <View style={styles.resultPanel}>
          <Text style={styles.resultTitle}>⏳ Couldn’t read a full pattern</Text>
          <Text style={styles.resultHint}>
            {everLocked
              ? 'Found the signal but missed some frames. Hold the phone steadier, move a little ' +
                'closer, keep the whole cat in frame, then scan again from the start of the animation.'
              : 'Never found the sync pattern. Make sure the cat is actively transmitting (eyes ' +
                'blinking), drag the L/R boxes onto its eyes, then tap Start as the animation begins.'}
          </Text>
        </View>
      )}

      {/* Bottom controls */}
      <View style={styles.controls}>
        <TouchableOpacity style={styles.cancelBtn} onPress={handleCancel}>
          <Text style={styles.controlText}>✕ {showComplete ? 'Done' : 'Cancel'}</Text>
        </TouchableOpacity>

        {/* READY: explicit Start */}
        {!started && !showOverlay && (
          <TouchableOpacity style={styles.startBtn} onPress={handleStart}>
            <Text style={styles.controlText}>▶ Start scanning</Text>
          </TouchableOpacity>
        )}

        {/* SCANNING: manual finish — acknowledge the transmission is done so the
            phone finalizes with what it has instead of scanning until timeout. */}
        {started && !showOverlay && (
          <TouchableOpacity
            style={styles.finishBtn}
            onPress={handleFinish}
            accessibilityRole="button"
            accessibilityLabel="Finish — transmission is done, use what was received"
          >
            <Text style={styles.controlText}>✓ Finish</Text>
          </TouchableOpacity>
        )}

        {/* Terminal: scan again */}
        {showOverlay && (
          <TouchableOpacity style={styles.restartBtn} onPress={handleRestart}>
            <Text style={styles.controlText}>↺ Scan again</Text>
          </TouchableOpacity>
        )}
      </View>

      {/* READY hint */}
      {!started && !showOverlay && (
        <View style={styles.readyHint} pointerEvents="none">
          <Text style={styles.readyHintText}>
            Line the cat screen up inside the 16:9 frame. The L / R boxes sit on the eyes
            automatically — only drag them if your cat video differs. When it starts blinking, tap Start.
          </Text>
        </View>
      )}
    </View>
  );
}

// ── Sub-components ──────────────────────────────────────────────────────────

function EyeMeter({ label, value }: { label: string; value: number }) {
  const h = Math.max(2, Math.min(100, (value / 255) * 100));
  return (
    <View style={styles.meterCol}>
      <View style={styles.meterTrack}>
        <View style={[styles.meterFill, { height: `${h}%` }]} />
      </View>
      <Text style={styles.meterLabel}>{label}</Text>
    </View>
  );
}

/**
 * 16:9 framing guide that mirrors the web demo's transmit canvas (743×417).
 * The web "cat" is a 16:9 video, so lining the other screen up inside this frame
 * puts its eyes where the pre-placed L/R boxes already sit — no dragging needed
 * for the standard cat. Purely visual; the actual sampling uses the L/R boxes. */
function CatFaceGuide() {
  return (
    <View style={styles.faceGuide} pointerEvents="none">
      <View style={styles.canvasFrame} />
      <Text style={styles.canvasCaption}>
        Line the cat screen up inside this 16:9 frame — the L / R boxes are already on its eyes
      </Text>
    </View>
  );
}

function statusLabel(status: string, started: boolean): string {
  switch (status) {
    case 'complete':
      return '✅ Pattern captured';
    case 'timeout':
      return '⏳ Timed out';
    case 'locked':
      return '🐱 Reading blinks — hold steady';
    case 'sampling':
      return '📡 Scanning…';
    default:
      return started ? '📡 Scanning…' : '👁 Align the boxes on the cat’s eyes';
  }
}

// ── Styles ──────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  actionBtn: {
    alignItems: 'center',
    backgroundColor: Colors.catOrange,
    borderRadius: Radius.full,
    flex: 1,
    paddingVertical: Spacing.md,
  },
  actionRow: { flexDirection: 'row', gap: Spacing.sm },
  actionText: { color: Colors.textPrimary, fontSize: Typography.md, fontWeight: Typography.bold },
  binaryBox: {
    backgroundColor: Colors.backgroundTertiary,
    borderRadius: Radius.sm,
    flex: 1,
    marginBottom: Spacing.md,
    padding: Spacing.sm,
  },
  binaryText: {
    color: Colors.catOrangeLight,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    fontSize: Typography.xs,
  },
  cancelBtn: {
    backgroundColor: 'rgba(255,59,48,0.85)',
    borderRadius: Radius.full,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
  },
  canvasCaption: {
    backgroundColor: Colors.overlayDark,
    borderRadius: Radius.full,
    color: Colors.textPrimary,
    fontSize: Typography.xs,
    marginTop: Spacing.sm,
    overflow: 'hidden',
    paddingHorizontal: Spacing.sm,
    paddingVertical: 2,
    textAlign: 'center',
  },
  canvasFrame: {
    aspectRatio: 16 / 9,
    borderColor: Colors.catOrange,
    borderRadius: Radius.md,
    borderStyle: 'dashed',
    borderWidth: 2,
    opacity: 0.55,
    width: '92%',
  },
  container: { backgroundColor: Colors.background, flex: 1 },
  controlText: { color: Colors.textPrimary, fontSize: Typography.md, fontWeight: Typography.bold },
  controls: {
    bottom: Platform.OS === 'ios' ? 48 : 32,
    flexDirection: 'row',
    justifyContent: 'space-around',
    left: 0,
    paddingHorizontal: Spacing.xl,
    position: 'absolute',
    right: 0,
  },
  diag: {
    alignItems: 'center',
    left: 0,
    position: 'absolute',
    right: 0,
    top: Platform.OS === 'ios' ? 104 : 84,
  },
  diagText: {
    backgroundColor: Colors.overlayDark,
    borderRadius: Radius.full,
    color: Colors.textSecondary,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    fontSize: Typography.xs,
    overflow: 'hidden',
    paddingHorizontal: Spacing.sm,
    paddingVertical: 2,
  },
  faceGuide: {
    alignItems: 'center',
    left: 0,
    position: 'absolute',
    right: 0,
    top: '11%',
  },
  finishBtn: {
    backgroundColor: 'rgba(52,199,89,0.9)',
    borderRadius: Radius.full,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
  },
  gate: {
    alignItems: 'center',
    backgroundColor: Colors.background,
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: Spacing.xl,
  },
  gateBody: {
    color: Colors.textSecondary,
    fontSize: Typography.md,
    marginBottom: Spacing.xl,
    textAlign: 'center',
  },
  gateIcon: { fontSize: 64, marginBottom: Spacing.lg },
  gateTitle: {
    color: Colors.textPrimary,
    fontSize: Typography.xl,
    fontWeight: Typography.semibold,
    marginBottom: Spacing.sm,
    textAlign: 'center',
  },
  homeButton: {
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.55)',
    borderRadius: Radius.full,
    height: 44,
    justifyContent: 'center',
    left: Spacing.lg,
    position: 'absolute',
    top: Platform.OS === 'ios' ? 56 : 36,
    width: 44,
    zIndex: 20,
  },
  homeButtonText: { fontSize: 22 },
  linkBtn: { marginTop: Spacing.lg },
  linkText: { color: Colors.textSecondary, fontSize: Typography.sm },
  meterCol: { alignItems: 'center' },
  meterFill: { backgroundColor: Colors.catOrange, width: '100%' },
  meterLabel: { color: Colors.textSecondary, fontSize: Typography.xs, marginTop: 2 },
  meterTrack: {
    backgroundColor: 'rgba(0,0,0,0.5)',
    borderRadius: Radius.sm,
    height: 90,
    justifyContent: 'flex-end',
    overflow: 'hidden',
    width: 14,
  },
  meters: { flexDirection: 'row', gap: Spacing.sm, position: 'absolute', right: Spacing.lg, top: '42%' },
  partialWarn: {
    color: Colors.catGold,
    fontSize: Typography.sm,
    marginBottom: Spacing.sm,
  },
  primaryBtn: {
    backgroundColor: Colors.catOrange,
    borderRadius: Radius.full,
    paddingHorizontal: Spacing.xl,
    paddingVertical: Spacing.md,
  },
  primaryBtnText: { color: Colors.textPrimary, fontSize: Typography.md, fontWeight: Typography.bold },
  progressBarBg: {
    backgroundColor: 'rgba(255,255,255,0.18)',
    borderRadius: Radius.full,
    height: 10,
    overflow: 'hidden',
    width: '100%',
  },
  progressBarFill: { backgroundColor: 'rgba(52,199,89,0.95)', height: '100%' },
  progressText: {
    color: Colors.textPrimary,
    fontSize: Typography.sm,
    marginTop: Spacing.xs,
    textAlign: 'center',
  },
  progressWrap: {
    left: Spacing.lg,
    position: 'absolute',
    right: Spacing.lg,
    top: Platform.OS === 'ios' ? 130 : 110,
  },
  readyHint: {
    bottom: Platform.OS === 'ios' ? 110 : 92,
    left: Spacing.lg,
    position: 'absolute',
    right: Spacing.lg,
  },
  readyHintText: {
    backgroundColor: Colors.overlayDark,
    borderRadius: Radius.md,
    color: Colors.textPrimary,
    fontSize: Typography.sm,
    overflow: 'hidden',
    padding: Spacing.sm,
    textAlign: 'center',
  },
  restartBtn: {
    backgroundColor: 'rgba(90,120,200,0.85)',
    borderRadius: Radius.full,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
  },
  resultHint: { color: Colors.textSecondary, fontSize: Typography.sm, marginBottom: Spacing.md },
  resultPanel: {
    backgroundColor: Colors.backgroundSecondary,
    borderRadius: Radius.lg,
    bottom: 110,
    left: Spacing.lg,
    padding: Spacing.lg,
    position: 'absolute',
    right: Spacing.lg,
    top: Platform.OS === 'ios' ? 120 : 100,
  },
  resultTitle: {
    color: Colors.textPrimary,
    fontSize: Typography.lg,
    fontWeight: Typography.bold,
    marginBottom: Spacing.xs,
  },
  reticle: {
    alignItems: 'center',
    backgroundColor: 'rgba(255,140,66,0.10)',
    borderColor: Colors.catOrange,
    borderRadius: Radius.md,
    borderWidth: 2,
    justifyContent: 'center',
    position: 'absolute',
  },
  reticleLabel: { color: Colors.catOrange, fontSize: Typography.lg, fontWeight: Typography.bold, opacity: 0.8 },
  reticleLocked: {
    backgroundColor: 'rgba(52,199,89,0.12)',
    borderColor: 'rgba(52,199,89,0.95)',
  },
  startBtn: {
    backgroundColor: 'rgba(52,199,89,0.9)',
    borderRadius: Radius.full,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
  },
  statusBar: {
    alignItems: 'center',
    gap: Spacing.xxs,
    left: 0,
    position: 'absolute',
    right: 0,
    top: Platform.OS === 'ios' ? 60 : 40,
  },
  statusText: {
    backgroundColor: Colors.overlayDark,
    borderRadius: Radius.full,
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.semibold,
    overflow: 'hidden',
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.xs,
  },
  subStatus: {
    backgroundColor: Colors.overlayDark,
    borderRadius: Radius.full,
    color: Colors.catGold,
    fontSize: Typography.sm,
    overflow: 'hidden',
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.xxs,
  },
});
