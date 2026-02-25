/**
 * FrameOverlay.tsx — Visual QR detection bounding box and status badges.
 *
 * Renders the animated scan-region rectangle and status badges that
 * indicate whether a QR code is currently visible in the frame.
 *
 * The corner decorations animate to signal detection state changes.
 */

import React, { useEffect } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withRepeat,
  withSequence,
  Easing,
  useReducedMotion,
} from 'react-native-reanimated';
import type { CaptureState } from '../types/capture';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';

// ── Props ─────────────────────────────────────────────────────────────────────

interface FrameOverlayProps {
  status: CaptureState;
  /** True when a QR code is actively detected in the current camera frame */
  qrDetected: boolean;
}

const SCAN_BOX_SIZE = 280;
const CORNER_SIZE = 24;
const CORNER_THICKNESS = 3;

// ── Component ─────────────────────────────────────────────────────────────────

export const FrameOverlay = React.memo(function FrameOverlay({
  status,
  qrDetected,
}: FrameOverlayProps) {
  const borderOpacity = useSharedValue(0.8);
  const scanLineY = useSharedValue(0);
  const reducedMotion = useReducedMotion();

  const borderColor =
    status === 'CAPTURING' && qrDetected
      ? Colors.success
      : status === 'CAPTURING'
      ? Colors.catGold
      : status === 'AWAITING_GIF'
      ? Colors.catOrange
      : Colors.textTertiary;

  // Pulse when waiting for a QR code
  useEffect(() => {
    if (status === 'AWAITING_GIF' && !reducedMotion) {
      borderOpacity.value = withRepeat(
        withSequence(
          withTiming(0.4, { duration: 800, easing: Easing.inOut(Easing.ease) }),
          withTiming(1.0, { duration: 800, easing: Easing.inOut(Easing.ease) }),
        ),
        -1,
        true,
      );
    } else {
      borderOpacity.value = withTiming(1, { duration: 200 });
    }
  }, [status, borderOpacity, reducedMotion]);

  // Scan-line animation during CAPTURING
  useEffect(() => {
    if (status === 'CAPTURING' && !reducedMotion) {
      scanLineY.value = 0;
      scanLineY.value = withRepeat(
        withTiming(SCAN_BOX_SIZE, {
          duration: 1800,
          easing: Easing.inOut(Easing.ease),
        }),
        -1,
        false,
      );
    } else {
      scanLineY.value = 0;
    }
  }, [status, scanLineY, reducedMotion]);

  const borderAnimStyle = useAnimatedStyle(() => ({
    opacity: borderOpacity.value,
  }));

  const scanLineStyle = useAnimatedStyle(() => ({
    transform: [{ translateY: scanLineY.value }],
    opacity: status === 'CAPTURING' ? 0.7 : 0,
  }));

  return (
    <View style={styles.container} pointerEvents="none">
      {/* Darkened edges outside scan region */}
      <View style={[styles.shadeTop]} />
      <View style={styles.middleRow}>
        <View style={styles.shadeSide} />

        {/* Scan region box */}
        <Animated.View
          style={[
            styles.scanBox,
            borderAnimStyle,
            { borderColor },
          ]}
        >
          {/* Corner decorations */}
          <View style={[styles.corner, styles.cornerTL, { borderColor }]} />
          <View style={[styles.corner, styles.cornerTR, { borderColor }]} />
          <View style={[styles.corner, styles.cornerBL, { borderColor }]} />
          <View style={[styles.corner, styles.cornerBR, { borderColor }]} />

          {/* Animated scan line */}
          <Animated.View style={[styles.scanLine, scanLineStyle]} />
        </Animated.View>

        <View style={styles.shadeSide} />
      </View>
      <View style={styles.shadeBottom}>
        {/* Status badge below scan box */}
        <View
          style={[styles.badge, { backgroundColor: badgeBg(status, qrDetected) }]}
          accessible={true}
          accessibilityRole="text"
          accessibilityLabel={badgeLabelA11y(status, qrDetected)}
          accessibilityLiveRegion="polite"
        >
          <Text style={styles.badgeText}>{badgeLabel(status, qrDetected)}</Text>
        </View>
      </View>
    </View>
  );
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function badgeLabel(status: CaptureState, qrDetected: boolean): string {
  switch (status) {
    case 'AWAITING_GIF': return '🔍 Searching for QR code...';
    case 'CAPTURING':
      return qrDetected ? '📡 Capturing...' : '⏳ Waiting for next frame...';
    case 'PAUSED': return '⏸ Paused';
    case 'COMPLETE': return '✅ Capture complete';
    case 'TIMED_OUT': return '⏰ Timed out';
    default: return '';
  }
}

/** Plain-text version of badge label for screen readers (no emoji) */
function badgeLabelA11y(status: CaptureState, qrDetected: boolean): string {
  switch (status) {
    case 'AWAITING_GIF': return 'Searching for QR code';
    case 'CAPTURING':
      return qrDetected ? 'Capturing frames' : 'Waiting for next frame';
    case 'PAUSED': return 'Capture paused';
    case 'COMPLETE': return 'Capture complete';
    case 'TIMED_OUT': return 'Capture timed out';
    default: return '';
  }
}

function badgeBg(status: CaptureState, qrDetected: boolean): string {
  if (status === 'TIMED_OUT') return 'rgba(255,159,10,0.85)';
  if (status === 'COMPLETE') return 'rgba(52,199,89,0.85)';
  if (status === 'PAUSED') return 'rgba(90,120,200,0.85)';
  if (status === 'CAPTURING' && qrDetected) return 'rgba(52,199,89,0.75)';
  return 'rgba(0,0,0,0.65)';
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const SHADE = 'rgba(0,0,0,0.55)';

const styles = StyleSheet.create({
  container: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'center',
    alignItems: 'center',
  },
  shadeTop: {
    width: '100%',
    flex: 1,
    backgroundColor: SHADE,
  },
  middleRow: {
    flexDirection: 'row',
    height: SCAN_BOX_SIZE,
  },
  shadeSide: {
    flex: 1,
    backgroundColor: SHADE,
  },
  shadeBottom: {
    width: '100%',
    flex: 1,
    backgroundColor: SHADE,
    alignItems: 'center',
    paddingTop: Spacing.md,
  },
  scanBox: {
    width: SCAN_BOX_SIZE,
    height: SCAN_BOX_SIZE,
    borderWidth: 1.5,
    borderRadius: Radius.md,
    overflow: 'hidden',
    backgroundColor: 'transparent',
  },
  corner: {
    position: 'absolute',
    width: CORNER_SIZE,
    height: CORNER_SIZE,
    borderColor: Colors.catGold,
  },
  cornerTL: {
    top: 0,
    left: 0,
    borderTopWidth: CORNER_THICKNESS,
    borderLeftWidth: CORNER_THICKNESS,
    borderTopLeftRadius: Radius.sm,
  },
  cornerTR: {
    top: 0,
    right: 0,
    borderTopWidth: CORNER_THICKNESS,
    borderRightWidth: CORNER_THICKNESS,
    borderTopRightRadius: Radius.sm,
  },
  cornerBL: {
    bottom: 0,
    left: 0,
    borderBottomWidth: CORNER_THICKNESS,
    borderLeftWidth: CORNER_THICKNESS,
    borderBottomLeftRadius: Radius.sm,
  },
  cornerBR: {
    bottom: 0,
    right: 0,
    borderBottomWidth: CORNER_THICKNESS,
    borderRightWidth: CORNER_THICKNESS,
    borderBottomRightRadius: Radius.sm,
  },
  scanLine: {
    position: 'absolute',
    left: 0,
    right: 0,
    height: 2,
    backgroundColor: Colors.catGold,
  },
  badge: {
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.xs,
    borderRadius: Radius.full,
  },
  badgeText: {
    color: Colors.textPrimary,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
});
