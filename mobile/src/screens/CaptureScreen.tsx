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

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  AppState,
  Platform,
  BackHandler,
  Alert,
  AccessibilityInfo,
} from 'react-native';
import ReactNativeHapticFeedback from 'react-native-haptic-feedback';
import { useCatToast } from '../components/CatToast';
import { CameraPreview } from '../components/CameraPreview';
import { ProgressHUD } from '../components/ProgressHUD';
import { FrameOverlay } from '../components/FrameOverlay';
import { StabilityIndicator } from '../components/StabilityIndicator';
import { CatWhiskerHUD } from '../components/CatWhiskerHUD';
import { CaptureCoachPanel } from '../components/CaptureCoachPanel';
import { CalibrationWizard } from '../components/CalibrationWizard';
import { useSessionManager } from '../hooks/useSessionManager';
import { useSecureScreen } from '../hooks/useSecureScreen';
import { useStallDetector } from '../hooks/useStallDetector';
import { useLowLightDetector } from '../hooks/useLowLightDetector';
import { useAudioCues } from '../hooks/useAudioCues';
import { useCameraHealthCheck } from '../hooks/useCameraHealthCheck';
import { useCaptureFrameMetrics } from '../hooks/useCaptureFrameMetrics';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';
import { formatCountdown, recoveryConfidenceLabel } from '../utils/formatters';
import { isCalibrationEnabled } from '../utils/captureSettings';
import { PURR_HAPTIC_INTERVAL_MS } from '../constants/config';
import type { CaptureScreenProps } from '../types/navigation';

const HAPTIC_OPTIONS = { enableVibrateFallback: true, ignoreAndroidSystemSettings: false };

// ── Component ─────────────────────────────────────────────────────────────────

export function CaptureScreen({ route, navigation }: CaptureScreenProps) {
  const { request } = route.params;
  const { showToast } = useCatToast();
  const { play: playAudioCue } = useAudioCues();

  // ── Calibration wizard state ───────────────────────────────────────────────
  // Off by default: the wizard opens its own camera, which on single-camera
  // devices collides with the capture camera ("camera could not start").
  // Opt in via Settings. When skipped, the request is loaded directly on mount.
  const [showCalibration, setShowCalibration] = useState(() => isCalibrationEnabled());
  const calibrationCompleteRef = useRef(false);

  // ── Security: privacy overlay + FLAG_SECURE (Android via MainActivity.kt) ──
  const { isBackgrounding } = useSecureScreen();

  const {
    status,
    progress,
    error,
    elapsedMs,
    remainingMs,
    capturedCount,
    decodeRate,
    duplicateRate,
    qrDecodedCount,
    qrCoverage,
    loopsCompleted,
    loopExhausted,
    isStable,
    shakeMagnitude,
    isNearMemoryLimit,
    lastMilestone,
    loadRequest,
    stop,
    cancel,
    pause,
    resume,
    markExporting,
    buildResponse,
    codeScanner,
  } = useSessionManager();

  const {
    frameProcessor: captureFrameProcessor,
    framesSeen,
    luminance,
  } = useCaptureFrameMetrics({
    enabled: status === 'AWAITING_GIF' || status === 'CAPTURING',
  });

  // qrActive / qrActiveTimer are reserved for future QR-blink feedback;
  // omitted for now to keep strict noUnusedLocals clean.

  const handleCalibrationComplete = () => {
    calibrationCompleteRef.current = true;
    setShowCalibration(false);
    // Call loadRequest directly — the ref is stable (useCallback []), so a
    // useEffect on [request, loadRequest] would only fire on mount (before
    // calibration finishes) and never again, meaning loadRequest would never run.
    loadRequest(request);
  };

  const handleCalibrationSkip = () => {
    calibrationCompleteRef.current = true;
    setShowCalibration(false);
    loadRequest(request);
  };

  // When calibration is skipped (default), load the request once on mount so
  // capture starts immediately and the camera opens cleanly (single instance).
  useEffect(() => {
    if (!showCalibration && !calibrationCompleteRef.current) {
      calibrationCompleteRef.current = true;
      loadRequest(request);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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

  // ── Foreground recovery ────────────────────────────────────────────────────
  // useCapture dispatches RESET when the app backgrounds (security wipe).
  // On returning to foreground the screen is in a terminal IDLE state —
  // send the user home so they can start a clean session rather than staring
  // at a dead camera feed with no frames.
  const didBackgroundRef = useRef(false);
  useEffect(() => {
    const sub = AppState.addEventListener('change', (nextState) => {
      if (nextState === 'background' || nextState === 'inactive') {
        didBackgroundRef.current = true;
      } else if (nextState === 'active' && didBackgroundRef.current) {
        didBackgroundRef.current = false;
        navigation.replace('Home');
      }
    });
    return () => sub.remove();
  }, [navigation]);

  // Handle cancel (with haptic)
  const handleCancel = () => {
    ReactNativeHapticFeedback.trigger('impactMedium', HAPTIC_OPTIONS);
    cancel();
    navigation.goBack();
  };

  // Always-visible Home button. Confirms before discarding an active capture,
  // otherwise returns straight to the main menu.
  const handleHomePress = () => {
    if (status === 'CAPTURING' || status === 'AWAITING_GIF' || status === 'PAUSED') {
      Alert.alert('Leave capture?', 'All captured frames will be lost.', [
        { text: 'Stay', style: 'cancel' },
        { text: 'Leave', style: 'destructive', onPress: handleCancel },
      ]);
    } else {
      cancel();
      navigation.replace('Home');
    }
  };

  // Android hardware back button — confirm before discarding active capture
  useEffect(() => {
    const onBack = () => {
      if (status === 'CAPTURING' || status === 'AWAITING_GIF' || status === 'PAUSED') {
        Alert.alert(
          'Discard capture?',
          'All captured frames will be lost.',
          [
            { text: 'Stay', style: 'cancel' },
            { text: 'Discard', style: 'destructive', onPress: handleCancel },
          ],
        );
        return true; // consume back event
      }
      return false;
    };
    const sub = BackHandler.addEventListener('hardwareBackPress', onBack);
    return () => sub.remove();
  }, [status]); // eslint-disable-line react-hooks/exhaustive-deps

  // Panic wipe — long-press cancel for 3 s: RESET + navigate Home immediately.
  // Provides a quick escape for high-pressure situations (activist / journalist use).
  const handlePanicWipe = () => {
    ReactNativeHapticFeedback.trigger('notificationError', HAPTIC_OPTIONS);
    cancel(); // dispatches RESET internally
    navigation.replace('Home');
  };

  // Handle manual stop (with haptic)
  const handleStop = () => {
    ReactNativeHapticFeedback.trigger('impactHeavy', HAPTIC_OPTIONS);
    stop();
  };

  // Handle pause / resume toggle
  const handlePauseResume = () => {
    ReactNativeHapticFeedback.trigger('impactLight', HAPTIC_OPTIONS);
    if (status === 'CAPTURING') {
      pause();
    } else if (status === 'PAUSED') {
      resume();
    }
  };

  // ── Stall detection + graduated auto-recovery ───────────────────────────────────
  // Imperative ref wired to CameraPreview.nudgeExposure for stall auto-recovery.
  const autoRecoveryRef = useRef<((delta: number) => void) | null>(null);
  // Count consecutive stalls in the current capture session.
  const stallCountRef = useRef(0);

  useStallDetector({
    frameCount: capturedCount,
    active: status === 'CAPTURING',
    onStall: () => {
      stallCountRef.current += 1;
      if (stallCountRef.current === 1) {
        showToast({
          message: 'No new frames arriving. Try moving the camera closer, adjusting the angle, or checking that the GIF is still playing on the other screen.',
          type: 'info',
          durationMs: 6_000,
        });
      } else if (stallCountRef.current === 2) {
        // Do NOT auto-brighten: when scanning a bright emissive screen the usual
        // cause is glare/over-exposure, and raising exposure washes the QR out
        // further. Steer the user to the right manual control instead.
        showToast({
          message: 'Still stalled. If the QR looks washed out, tap ☀− to cut glare; if it looks dim, tap ☀+. A slight tilt also clears reflections.',
          type: 'info',
          durationMs: 6_000,
        });
      } else {
        showToast({
          message: 'Still not receiving frames. Try turning on your phone flashlight, or move about 10 cm closer to the other screen. Your data so far is safe.',
          type: 'info',
          durationMs: 7_000,
        });
      }
    },
  });

  // Stall reset also resets coach exposure bias tracking
  // Reset stall counter whenever frames start flowing again
  useEffect(() => {
    stallCountRef.current = 0;
  }, [capturedCount]);

  // ── Exposure bias tracking for CaptureCoachPanel ───────────────────────────
  const [exposureBias, setExposureBias] = useState(0);
  const handleExposureBiasChange = useRef((bias: number) => setExposureBias(bias)).current;

  const showZeroDecodeHint = useCallback(
    (message: string) => showToast({ message, type: 'info', durationMs: 5_000 }),
    [showToast],
  );

  // Read-only diagnosis: no automatic exposure or torch changes.
  const zeroDecodeDiagnosis = useLowLightDetector({
    decodeRate,
    luminance,
    shakeMagnitude,
    qrCoverage,
    active: status === 'CAPTURING',
    showHint: showZeroDecodeHint,
  });

  // ── Camera health self-test (F7) ──────────────────────────────────────────
  useCameraHealthCheck({
    status,
    capturedCount,
    showHint: (message: string) => showToast({ message, type: 'info', durationMs: 6_000 }),
  });

  // ── Purr haptic pulse — gentle tactile feedback per captured frame ──────────
  const lastPurrTimeRef = useRef(0);
  useEffect(() => {
    if (status !== 'CAPTURING') return;
    const now = Date.now();
    if (now - lastPurrTimeRef.current >= PURR_HAPTIC_INTERVAL_MS) {
      lastPurrTimeRef.current = now;
      ReactNativeHapticFeedback.trigger('selection', HAPTIC_OPTIONS);
    }
  }, [capturedCount, status]);

  // ── Milestone toasts + haptics ─────────────────────────────────────────────
  const firedMilestonesRef = useRef(new Set<number>());
  useEffect(() => {
    if (lastMilestone === null || firedMilestonesRef.current.has(lastMilestone)) return;
    firedMilestonesRef.current.add(lastMilestone);

    // Graduated haptic: light ticks for progress, success pop for completion
    if (lastMilestone === 1.0) {
      ReactNativeHapticFeedback.trigger('notificationSuccess', HAPTIC_OPTIONS);
      playAudioCue('complete');
    } else {
      ReactNativeHapticFeedback.trigger('impactLight', HAPTIC_OPTIONS);
      playAudioCue('milestone');
    }

    const TOASTS: Record<number, { message: string; type: 'milestone' | 'success' }> = {
      0.25: { message: 'Keep scanning — good start', type: 'milestone' },
      0.5: { message: 'Halfway there — keep holding steady', type: 'milestone' },
      0.75: { message: 'Almost done — keep going', type: 'milestone' },
      1.0: { message: 'Transfer captured — safe to stop now.', type: 'success' },
    };

    const toast = TOASTS[lastMilestone];
    if (toast) showToast(toast);

    // ── VoiceOver/TalkBack accessibility announcement ─────────────────────
    // Announce milestone and safe-to-stop in a format screen-reader users can act on.
    const pct = Math.round(lastMilestone * 100);
    const safeToStop = lastMilestone >= 1.0;
    const a11yMsg = safeToStop
      ? `Capture ${pct} percent. Fountain complete. Safe to stop now.`
      : `Capture ${pct} percent.`;
    AccessibilityInfo.announceForAccessibility(a11yMsg);
  }, [lastMilestone, showToast]);

  // ── Loop completion feedback ───────────────────────────────────────────────
  // The optical channel carries no "the animation has finished a cycle" signal,
  // so useLoopDetector reconstructs it from the frame-index stream. Surface two
  // honest events: the first completed loop, and "whole loop seen but frames
  // are still missing" (which means frames are being physically dropped).
  const loopToastFiredRef = useRef(false);
  useEffect(() => {
    if (status !== 'CAPTURING') return;
    if (loopsCompleted >= 1 && !loopToastFiredRef.current) {
      loopToastFiredRef.current = true;
      ReactNativeHapticFeedback.trigger('impactLight', HAPTIC_OPTIONS);
      showToast({
        message: '🔁 The animation has looped once. Keep holding steady — extra passes fill in any frames missed the first time.',
        type: 'info',
        durationMs: 5_000,
      });
    }
  }, [loopsCompleted, status, showToast]);

  const exhaustedToastFiredRef = useRef(false);
  useEffect(() => {
    if (status !== 'CAPTURING') return;
    if (!loopExhausted || exhaustedToastFiredRef.current) return;
    exhaustedToastFiredRef.current = true;
    if (progress && progress.captured >= progress.expected) {
      // Whole loop seen and every block captured — finishing automatically.
      showToast({
        message: '✓ You have now captured every frame of the animation. Finishing up…',
        type: 'success',
        durationMs: 6_000,
      });
      AccessibilityInfo.announceForAccessibility('All frames captured. Finishing up.');
    } else {
      // Seen every frame the loop offers, yet still short — frames are dropping.
      ReactNativeHapticFeedback.trigger('notificationWarning', HAPTIC_OPTIONS);
      showToast({
        message: 'You have seen the whole animation, but some frames are still being missed. Move a little closer, hold steadier, or add light — then keep scanning to catch them on the next pass.',
        type: 'info',
        durationMs: 8_000,
      });
      AccessibilityInfo.announceForAccessibility('Whole animation seen but frames are still missing. Adjust position and keep scanning.');
    }
  }, [loopExhausted, status, progress, showToast]);

  // NOTE: no loopExhausted-based auto-stop. The loop detector keys off repeated
  // frame indices, so re-scanning the SAME on-screen frame (animation paused, or
  // a slow frame held under the camera) looks like an "exhausted loop" and would
  // end capture after a single frame. Capture now ends only on the fountain
  // threshold (useCapture auto-completes), the session timeout, or a manual tap.
  // loopExhausted is kept purely for the coaching toast below.

  // Reset loop-event latches when a new capture session starts.
  useEffect(() => {
    if (status === 'AWAITING_GIF' || status === 'IDLE') {
      loopToastFiredRef.current = false;
      exhaustedToastFiredRef.current = false;
    }
  }, [status]);

  // ── Memory pressure warning ────────────────────────────────────────────────
  const memoryWarnFiredRef = useRef(false);
  useEffect(() => {
    if (isNearMemoryLimit && !memoryWarnFiredRef.current) {
      memoryWarnFiredRef.current = true;
      showToast({
        message: 'Large number of frames captured. Tap Done soon to avoid running out of memory. Your data is safe.',
        type: 'info',
        durationMs: 5000,
      });
    }
  }, [isNearMemoryLimit, showToast]);

  // ── Error handling ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (status === 'ERROR' && error) {
      showToast({ message: `Something went wrong: ${error}. Your data is safe — go back and try again.`, type: 'error', durationMs: 6_000 });
      playAudioCue('error');
    }
  }, [status, error, showToast, playAudioCue]);

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <View style={styles.container}>
      {/* Full-screen camera with native code scanner + privacy overlay */}
      <CameraPreview
        codeScanner={codeScanner}
        status={status}
        {...(captureFrameProcessor ? { frameProcessor: captureFrameProcessor } : {})}
        isBackgrounding={isBackgrounding}
        onAutoRecoveryRef={autoRecoveryRef}
        onExposureBiasChange={handleExposureBiasChange}
      />

      {/* Scan region + status badges */}
      <FrameOverlay status={status} qrDetected={status === 'CAPTURING'} />

      {/* Stability warning pill + animated cat whisker HUD */}
      <StabilityIndicator magnitude={shakeMagnitude} visible={!isStable && status === 'CAPTURING'} />
      <CatWhiskerHUD
        shakeMagnitude={shakeMagnitude}
        visible={status === 'CAPTURING' || status === 'PAUSED'}
      />

      {/* Live coaching hints — distance, brightness, duplicate rate, decode rate */}
      <CaptureCoachPanel
        decodeRate={decodeRate}
        duplicateRate={duplicateRate}
        shakeMagnitude={shakeMagnitude}
        exposureBias={exposureBias}
        zeroDecodeDiagnosis={zeroDecodeDiagnosis}
        safeToStop={
          !!progress && recoveryConfidenceLabel(progress.captured, progress.expected).safeToStop
        }
        visible={status === 'CAPTURING' || status === 'AWAITING_GIF'}
      />

      {/* Always-visible Home button (top-left) */}
      <TouchableOpacity
        style={styles.homeButton}
        onPress={handleHomePress}
        accessibilityRole="button"
        accessibilityLabel="Back to main menu"
        hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
      >
        <Text style={styles.homeButtonText}>🏠</Text>
      </TouchableOpacity>

      {/* Status bar at top */}
      <View style={styles.statusBar}>
        <Text
          style={styles.statusText}
          accessibilityLiveRegion="polite"
          accessibilityLabel={statusLabel(status)}
        >
          {statusLabel(status)}
        </Text>
        {remainingMs !== null && status === 'CAPTURING' && (
          <Text
            style={styles.timerText}
            accessibilityLabel={`Time remaining: ${formatCountdown(remainingMs / 1000)}`}
            accessibilityLiveRegion="assertive"
          >
            ⏱ {formatCountdown(remainingMs / 1000)}
          </Text>
        )}
      </View>

      {/* Progress HUD (shown once capturing starts) */}
      {progress && (status === 'CAPTURING' || status === 'AWAITING_GIF' || status === 'PAUSED') && (
        <ProgressHUD
          progress={progress}
          status={status}
          elapsedMs={elapsedMs}
          decodeRate={decodeRate}
          duplicateRate={duplicateRate}
          framesSeen={framesSeen}
          qrDecodedCount={qrDecodedCount}
          loopsCompleted={loopsCompleted}
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
          onLongPress={handlePanicWipe}
          delayLongPress={3000}
          accessibilityRole="button"
          accessibilityLabel="Cancel capture. Hold for 3 seconds to panic-wipe."
          accessibilityHint="Hold 3 seconds to immediately clear all data and return home"
        >
          <Text style={styles.buttonText}>✕ Cancel</Text>
        </TouchableOpacity>

        {(status === 'CAPTURING' || status === 'PAUSED') && (
          <TouchableOpacity
            style={styles.pauseButton}
            onPress={handlePauseResume}
            accessibilityRole="button"
            accessibilityLabel={status === 'PAUSED' ? 'Resume capture' : 'Pause capture'}
          >
            <Text style={styles.buttonText}>
              {status === 'PAUSED' ? '▶️ Resume' : '⏸ Pause'}
            </Text>
          </TouchableOpacity>
        )}

        {(status === 'CAPTURING' || status === 'AWAITING_GIF' || status === 'PAUSED') && (() => {
          // "Done" (green) uses the SAME signal as the ProgressHUD's
          // "✓ Safe to stop — tap Done" pill (recoveryConfidenceLabel.safeToStop),
          // so the guidance and the button can never disagree. NOT loopExhausted
          // (which can fire after a single re-scanned frame).
          const allCaptured =
            !!progress && recoveryConfidenceLabel(progress.captured, progress.expected).safeToStop;
          return (
          <TouchableOpacity
            style={[styles.stopButton, allCaptured && styles.stopButtonReady]}
            onPress={handleStop}
            accessibilityRole="button"
            accessibilityLabel={allCaptured ? 'All frames captured — finish and export' : 'Stop capture and export'}
          >
            <Text style={styles.buttonText}>
              {allCaptured ? '✓ Done' : '🐾 Stop'}
            </Text>
          </TouchableOpacity>
          );
        })()}
      </View>

      {/* Pre-scan calibration wizard (shown on mount, before capture begins) */}
      <CalibrationWizard
        visible={showCalibration}
        onComplete={handleCalibrationComplete}
        onDismiss={handleCalibrationSkip}
      />
    </View>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusLabel(status: string): string {
  switch (status) {
    case 'AWAITING_GIF': return '🔍 Point camera at the sender screen';
    case 'CAPTURING': return '😼 Scanning — hold steady';
    case 'PAUSED': return '⏸ Paused — tap Resume to continue';
    case 'TIMED_OUT': return '⏰ Time\'s up — preparing your transfer…';
    case 'COMPLETE': return '✅ Transfer captured — preparing for export…';
    default: return '';
  }
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.background },
  homeButton: {
    position: 'absolute',
    top: Platform.OS === 'ios' ? 56 : 36,
    left: Spacing.lg,
    width: 44,
    height: 44,
    borderRadius: Radius.full,
    backgroundColor: 'rgba(0,0,0,0.55)',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 20,
  },
  homeButtonText: { fontSize: 22 },
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
  pauseButton: {
    backgroundColor: 'rgba(90,120,200,0.85)',
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
