/**
 * CameraPreview.tsx — Vision Camera wrapper with frame processor.
 *
 * Encapsulates camera permission handling, device selection, and
 * mounting the frame processor returned by useQRScanner.
 *
 * The camera stays active only while a capture session is in progress,
 * releasing resources during IDLE and COMPLETE states to conserve battery
 * and reduce thermal load.
 */

import React, { useCallback, useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Linking,
  Platform,
} from 'react-native';
import {
  Camera,
  useCameraDevice,
  useCameraPermission,
} from 'react-native-vision-camera';
import type { FrameProcessor } from 'react-native-vision-camera';
import type { CaptureState } from '../types/capture';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';
import { CAMERA_FPS } from '../constants/config';

// ── Props ─────────────────────────────────────────────────────────────────────

interface CameraPreviewProps {
  /** The frame processor from useQRScanner — runs on worklet thread */
  frameProcessor: FrameProcessor;
  /** Current capture status — controls isActive prop */
  status: CaptureState;
  /** Show torch toggle button */
  showTorchToggle?: boolean;
}

// ── Component ─────────────────────────────────────────────────────────────────

export const CameraPreview = React.memo(function CameraPreview({
  frameProcessor,
  status,
  showTorchToggle = true,
}: CameraPreviewProps) {
  const { hasPermission, requestPermission } = useCameraPermission();
  const device = useCameraDevice('back');
  const [torch, setTorch] = useState<'off' | 'on'>('off');

  const isActive =
    status === 'AWAITING_GIF' || status === 'CAPTURING';

  const toggleTorch = useCallback(() => {
    setTorch((prev) => (prev === 'off' ? 'on' : 'off'));
  }, []);

  const openSettings = useCallback(() => {
    void Linking.openSettings();
  }, []);

  // ── Permission denied ─────────────────────────────────────────────────────
  if (!hasPermission) {
    return (
      <View style={styles.centered}>
        <Text style={styles.permissionIcon}>📷</Text>
        <Text style={styles.permissionTitle}>Camera access needed</Text>
        <Text style={styles.permissionBody}>
          meow-decoder uses the camera to scan animated QR codes. No images
          are stored or transmitted.
        </Text>
        <TouchableOpacity
          style={styles.permissionButton}
          onPress={hasPermission === false ? openSettings : requestPermission}
          accessibilityRole="button"
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
      <View style={styles.centered}>
        <Text style={styles.permissionTitle}>No camera available</Text>
        <Text style={styles.permissionBody}>
          This device does not have a usable back camera.
        </Text>
      </View>
    );
  }

  // ── Active camera feed ────────────────────────────────────────────────────
  return (
    <View style={styles.fill}>
      <Camera
        style={StyleSheet.absoluteFill}
        device={device}
        isActive={isActive}
        frameProcessor={frameProcessor}
        fps={CAMERA_FPS}
        pixelFormat="yuv"
        torch={torch}
        enableZoomGesture={false}
        // Disable audio — microphone permission must not be requested
        audio={false}
      />

      {/* Torch toggle */}
      {showTorchToggle && device.hasTorch && (
        <TouchableOpacity
          style={styles.torchButton}
          onPress={toggleTorch}
          accessibilityLabel={torch === 'on' ? 'Turn torch off' : 'Turn torch on'}
          accessibilityRole="button"
        >
          <Text style={styles.torchIcon}>{torch === 'on' ? '🔦' : '💡'}</Text>
        </TouchableOpacity>
      )}
    </View>
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
  torchButton: {
    position: 'absolute',
    top: 60,
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
});
