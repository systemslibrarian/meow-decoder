/**
 * CameraPreview.tsx — Vision Camera v4 wrapper with native code scanner.
 *
 * Features:
 *  - Native QR scanning via VisionCamera v4 useCodeScanner (MLKit / AVFoundation)
 *  - Pinch-to-zoom with clamped range (1× → min(maxZoom, 6×))
 *  - Exposure bias quick-adjust (−2 … +2 in 0.5 steps) for glare & low-light
 *  - Torch toggle
 *  - Privacy overlay on app backgrounding (iOS task-switcher snapshot defense)
 *  - Camera stays inactive during IDLE/COMPLETE/EXPORTING to conserve battery
 */

import React, { useCallback, useState, useEffect } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Linking,
  Platform,
} from 'react-native';
import { Gesture, GestureDetector } from 'react-native-gesture-handler';
import Animated, {
  useSharedValue,
  useAnimatedProps,
  clamp,
} from 'react-native-reanimated';
import {
  Camera,
  useCameraDevice,
  useCameraPermission,
  type CodeScanner,
} from 'react-native-vision-camera';
import type { CaptureState } from '../types/capture';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';
import { useAdaptiveFPS } from '../hooks/useAdaptiveFPS';

// Animated Camera lets us drive the `zoom` prop from a shared value
// on the UI thread — no JS-thread round-trip per gesture event.
const AnimatedCamera = Animated.createAnimatedComponent(Camera);

// ── Props ─────────────────────────────────────────────────────────────────────

interface CameraPreviewProps {
  /** VisionCamera v4 code scanner — pass codeScanner from useQRScanner */
  codeScanner: CodeScanner;
  /** Current capture status — controls isActive prop */
  status: CaptureState;
  /** Show torch toggle button */
  showTorchToggle?: boolean;
  /** When true renders a solid privacy overlay (iOS task-switcher defense) */
  isBackgrounding?: boolean;
  /**
   * Mutable ref that CaptureScreen can use to imperatively nudge exposure bias.
   * Assigned on mount; callers invoke ref.current(+0.5) to brighten.
   */
  onAutoRecoveryRef?: React.MutableRefObject<((delta: number) => void) | null>;
  /**
   * Called whenever exposureBias changes so parent components (e.g. CaptureCoachPanel)
   * can read the current value without prop-drilling through the full state machine.
   */
  onExposureBiasChange?: (bias: number) => void;
  /**
   * Called whenever the torch state changes so parent components (e.g. useLowLightDetector)
   * can track whether the flashlight is currently active.
   */
  onTorchChange?: (on: boolean) => void;
}

// ── Component ─────────────────────────────────────────────────────────────────

export const CameraPreview = React.memo(function CameraPreview({
  codeScanner,
  status,
  showTorchToggle = true,
  isBackgrounding = false,
  onAutoRecoveryRef,
  onExposureBiasChange,
  onTorchChange,
}: CameraPreviewProps) {
  const { hasPermission, requestPermission } = useCameraPermission();
  const device = useCameraDevice('back');
  const adaptiveFPS = useAdaptiveFPS(device);
  const [torch, setTorch] = useState<'off' | 'on'>('off');
  const [exposureBias, setExposureBias] = useState(0);
  // Track native camera errors (e.g. EncoderProfiles NullPointerException on
  // some Android emulators/devices). Show a friendly fallback instead of crashing.
  const [cameraError, setCameraError] = useState<string | null>(null);

  // ── Pinch-to-zoom ─────────────────────────────────────────────────────────
  const zoomSV = useSharedValue(device?.neutralZoom ?? 1);
  const pinchStartZoom = useSharedValue(1);

  const pinchGesture = Gesture.Pinch()
    .onStart(() => {
      pinchStartZoom.value = zoomSV.value;
    })
    .onUpdate((e) => {
      const minZ = device?.minZoom ?? 1;
      // Cap at 6× — beyond this QR decode reliability degrades significantly
      const maxZ = Math.min(device?.maxZoom ?? 10, 6);
      zoomSV.value = clamp(pinchStartZoom.value * e.scale, minZ, maxZ);
    });

  const animatedCameraProps = useAnimatedProps(() => ({
    zoom: zoomSV.value,
  }));

  const toggleTorch = useCallback(() => setTorch((p) => {
    const next = p === 'off' ? 'on' : 'off';
    onTorchChange?.(next === 'on');
    return next;
  }), [onTorchChange]);
  const openSettings = useCallback(() => void Linking.openSettings(), []);

  const nudgeExposure = useCallback((delta: number) => {
    setExposureBias((v) => {
      const next = v + delta;
      const snapped = Math.round(Math.max(-2, Math.min(2, next)) * 2) / 2;
      onExposureBiasChange?.(snapped);
      return snapped;
    });
  }, [onExposureBiasChange]);

  // Wire the imperative auto-recovery ref so CaptureScreen can nudge exposure
  // without needing a full prop re-render cycle through the state machine.
  useEffect(() => {
    if (onAutoRecoveryRef) {
      onAutoRecoveryRef.current = nudgeExposure;
      return () => { onAutoRecoveryRef.current = null; };
    }
    return undefined;
  }, [onAutoRecoveryRef, nudgeExposure]);

  // PAUSED: camera stays warm to avoid 500–1500 ms cold-start on Resume.
  // Security: codeScanner has its own `!enabled` guard (useQRScanner) that
  // prevents any frame dispatch while status === 'PAUSED'. isActive only
  // controls the hardware device — not the scanning pipeline.
  const isActive =
    status !== 'IDLE' &&
    status !== 'COMPLETE' &&
    status !== 'EXPORTING' &&
    !isBackgrounding;

  // ── Permission denied ──────────────────────────────────────────────────────
  if (!hasPermission) {
    return (
      <View style={styles.centered}>
        <Text style={styles.permissionIcon} importantForAccessibility="no">📷</Text>
        <Text style={styles.permissionTitle} accessibilityRole="header">Camera access needed</Text>
        <Text style={styles.permissionBody}>
          meow-decoder uses the camera to scan animated QR codes. No images
          are stored or transmitted.
        </Text>
        <TouchableOpacity
          style={styles.permissionButton}
          onPress={Platform.OS === 'ios' ? openSettings : requestPermission}
          accessibilityRole="button"
          accessibilityLabel="Grant camera permission"
        >
          <Text style={styles.permissionButtonText}>
            {Platform.OS === 'ios' ? 'Open Settings' : 'Grant Permission'}
          </Text>
        </TouchableOpacity>
      </View>
    );
  }

  // ── No camera device ──────────────────────────────────────────────────────
  if (!device) {
    return (
      <View style={styles.centered} accessible={true} accessibilityRole="alert" accessibilityLabel="No camera available. This device does not have a usable back camera.">
        <Text style={styles.permissionTitle} accessibilityRole="header">No camera available</Text>
        <Text style={styles.permissionBody}>
          This device does not have a usable back camera.
        </Text>
      </View>
    );
  }

  return (
    <GestureDetector gesture={pinchGesture}>
      <View style={styles.fill}>
        {/* ── Camera feed ─────────────────────────────────────────────────── */}
        {cameraError ? (
          /* Friendly fallback when the camera hardware/driver fails at startup.
           * Common on Android emulators: EncoderProfiles$VideoProfile.getCodec()
           * returns null for missing codec profiles, causing a NullPointerException
           * inside VisionCamera's native layer. Showing this instead of crashing. */
          <View style={[StyleSheet.absoluteFill, styles.centered]} accessible accessibilityRole="alert">
            <Text style={styles.permissionIcon} importantForAccessibility="no">📷</Text>
            <Text style={styles.permissionTitle} accessibilityRole="header">Camera unavailable</Text>
            <Text style={styles.permissionBody}>
              The camera could not start on this device.
              {__DEV__ ? ` (${cameraError})` : ' Try on a physical device.'}
            </Text>
          </View>
        ) : (
          <AnimatedCamera
            style={StyleSheet.absoluteFill}
            device={device}
            isActive={isActive}
            codeScanner={codeScanner}
            fps={adaptiveFPS}
            pixelFormat="yuv"
            torch={torch}
            enableZoomGesture={false}  // handled via GestureDetector above
            audio={false}              // microphone permission must NOT be requested
            // Exposure bias: compensates for bright laptop screens (glare)
            // or dim environments. Range: device.minExposure … device.maxExposure
            exposure={exposureBias}
            animatedProps={animatedCameraProps}
            onError={(e) => {
              // Catch native camera errors (EncoderProfiles NPE, etc.) so the
              // JS thread does not crash — surface a recoverable UI instead.
              if (__DEV__) { console.warn('[CameraPreview] Native camera error:', e); }
              setCameraError(e.message);
            }}
          />
        )}

        {/* ── Privacy overlay (iOS task-switcher snapshot defense) ───────── */}
        {isBackgrounding && (
          <View
            style={styles.privacyOverlay}
            accessible={true}
            accessibilityRole="alert"
            accessibilityLabel="Screen content hidden for privacy"
          >
            <Text style={styles.privacyIcon}>🐱</Text>
          </View>
        )}

        {/* ── Torch toggle ────────────────────────────────────────────────── */}
        {showTorchToggle && device.hasTorch && !isBackgrounding && (
          <TouchableOpacity
            style={styles.torchButton}
            onPress={toggleTorch}
            accessibilityLabel={torch === 'on' ? 'Turn torch off' : 'Turn torch on'}
            accessibilityRole="button"
          >
            <Text style={styles.torchIcon}>{torch === 'on' ? '🔦' : '💡'}</Text>
          </TouchableOpacity>
        )}

        {/* ── Exposure bias controls ───────────────────────────────────────── */}
        {isActive && !isBackgrounding && (
          <View style={styles.exposureRow}>
            <TouchableOpacity
              style={styles.exposureBtn}
              onPress={() => nudgeExposure(-0.5)}
              accessibilityLabel="Decrease exposure — reduce glare from bright screen"
              accessibilityRole="button"
            >
              <Text style={styles.exposureText}>☀−</Text>
            </TouchableOpacity>
            <Text
              style={styles.exposureLabel}
              accessibilityLabel={`Exposure bias ${exposureBias}`}
            >
              {exposureBias > 0 ? `+${exposureBias}` : String(exposureBias)}
            </Text>
            <TouchableOpacity
              style={styles.exposureBtn}
              onPress={() => nudgeExposure(0.5)}
              accessibilityLabel="Increase exposure — brighten dim screen"
              accessibilityRole="button"
            >
              <Text style={styles.exposureText}>☀+</Text>
            </TouchableOpacity>
          </View>
        )}
      </View>
    </GestureDetector>
  );
});

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  fill: {
    flex: 1,
  },
  centered: {
    flex: 1,
    backgroundColor: Colors.background,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: Spacing.xl,
  },
  permissionIcon: {
    fontSize: 64,
    marginBottom: Spacing.lg,
  },
  permissionTitle: {
    color: Colors.textPrimary,
    fontSize: Typography.xl,
    fontWeight: Typography.semibold,
    marginBottom: Spacing.sm,
    textAlign: 'center',
  },
  permissionBody: {
    color: Colors.textSecondary,
    fontSize: Typography.md,
    textAlign: 'center',
    lineHeight: Typography.md * Typography.normal,
    marginBottom: Spacing.xl,
  },
  permissionButton: {
    backgroundColor: Colors.catOrange,
    paddingHorizontal: Spacing.xl,
    paddingVertical: Spacing.md,
    borderRadius: Radius.full,
  },
  permissionButtonText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.bold,
  },
  // Privacy overlay — covers camera feed during app backgrounding so the
  // OS task-switcher snapshot shows a neutral placeholder.
  privacyOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: Colors.background,
    justifyContent: 'center',
    alignItems: 'center',
  },
  privacyIcon: {
    fontSize: 64,
    opacity: 0.3,
  },
  torchButton: {
    position: 'absolute',
    top: Platform.OS === 'ios' ? 60 : 40,
    right: Spacing.lg,
    width: 48,
    height: 48,
    borderRadius: Radius.md,
    backgroundColor: 'rgba(0,0,0,0.55)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  torchIcon: {
    fontSize: 24,
  },
  // Exposure controls — bottom-center pill
  exposureRow: {
    position: 'absolute',
    bottom: 108,
    alignSelf: 'center',
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.60)',
    borderRadius: Radius.full,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.xs,
    gap: Spacing.xs,
  },
  exposureBtn: {
    padding: Spacing.xs,
    minWidth: 44,
    minHeight: 44,
    justifyContent: 'center',
    alignItems: 'center',
  },
  exposureText: {
    color: Colors.textPrimary,
    fontSize: Typography.md,
    fontWeight: Typography.semibold,
  },
  exposureLabel: {
    color: Colors.catGold,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
    minWidth: 28,
    textAlign: 'center',
  },
});
