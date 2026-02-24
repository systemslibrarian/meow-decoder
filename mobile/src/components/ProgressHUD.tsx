/**
 * ProgressHUD.tsx — Real-time capture progress overlay.
 *
 * Displays:
 *  - Animated circular arc progress ring
 *  - Frame count (captured / expected)
 *  - Recoverability label
 *  - Elapsed time and ETA
 *
 * Uses react-native-reanimated for smooth arc animation without
 * driving the JS thread on every frame.
 */

import React, { useEffect } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Animated, {
  useAnimatedStyle,
  useSharedValue,
  withTiming,
  Easing,
} from 'react-native-reanimated';
import type { CaptureProgress } from '../types/capture';
import type { CaptureState } from '../types/capture';
import { Colors, Typography, Spacing, Radius, Shadows } from '../constants/theme';
import { progressColor } from '../constants/theme';
import {
  formatFrameCount,
  formatElapsed,
  estimateETA,
  recoverabilityLabel,
} from '../utils/formatters';

// ── Props ─────────────────────────────────────────────────────────────────────

interface ProgressHUDProps {
  progress: CaptureProgress;
  status: CaptureState;
  elapsedMs: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const HUD_SIZE = 120;
const RING_STROKE = 8;
const RING_RADIUS = (HUD_SIZE - RING_STROKE) / 2;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

// ── Component ─────────────────────────────────────────────────────────────────

export const ProgressHUD = React.memo(function ProgressHUD({
  progress,
  status,
  elapsedMs,
}: ProgressHUDProps) {
  // Animate the fill fraction (0–1, capped at 1 for display)
  const fillFraction = useSharedValue(0);

  useEffect(() => {
    const target = Math.min(progress.percentRecoverable / 100, 1);
    fillFraction.value = withTiming(target, {
      duration: 400,
      easing: Easing.out(Easing.quad),
    });
  }, [progress.percentRecoverable, fillFraction]);

  const animatedRingStyle = useAnimatedStyle(() => {
    const strokeDashoffset =
      RING_CIRCUMFERENCE - fillFraction.value * RING_CIRCUMFERENCE;
    return { strokeDashoffset };
  });

  const ringColor = progressColor(progress.percentRecoverable);

  const eta = estimateETA(progress.captured, progress.expected, elapsedMs);
  const recovLabel = recoverabilityLabel(progress.captured, progress.expected);

  const isActiveCapture =
    status === 'CAPTURING' || status === 'AWAITING_GIF';

  return (
    <View style={styles.container} accessibilityLabel="Capture progress">
      {/* Ring + counter */}
      <View style={styles.ringContainer}>
        {/* Background ring */}
        <View
          style={[
            styles.ringBg,
            { borderColor: Colors.backgroundTertiary },
          ]}
        />
        {/* Animated fill ring — using Animated.View as a wrapper trick
            since RN SVG is not in scope; we use border arc hack */}
        <Animated.View
          style={[
            styles.ringFill,
            animatedRingStyle,
            { borderColor: ringColor },
          ]}
        />
        {/* Centre counter */}
        <View style={styles.centreText}>
          <Text style={[styles.countText, { color: ringColor }]}>
            {progress.captured}
          </Text>
          <Text style={styles.expectedText}>/{progress.expected}</Text>
        </View>
      </View>

      {/* Labels */}
      <View style={styles.labels}>
        <Text style={[styles.statusLabel, { color: ringColor }]}>
          {recovLabel}
        </Text>
        <Text style={styles.timeLabel}>
          {isActiveCapture ? formatElapsed(elapsedMs) : ''}
          {isActiveCapture && eta ? `  ${eta}` : ''}
        </Text>
        <Text style={styles.frameLabel}>
          {formatFrameCount(progress.captured, progress.expected)} frames
        </Text>
      </View>
    </View>
  );
});

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    position: 'absolute',
    bottom: 120,
    alignSelf: 'center',
    alignItems: 'center',
    backgroundColor: Colors.overlayDark,
    borderRadius: Radius.lg,
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.lg,
    ...Shadows.medium,
  },
  ringContainer: {
    width: HUD_SIZE,
    height: HUD_SIZE,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: Spacing.sm,
  },
  ringBg: {
    position: 'absolute',
    width: HUD_SIZE - RING_STROKE,
    height: HUD_SIZE - RING_STROKE,
    borderRadius: (HUD_SIZE - RING_STROKE) / 2,
    borderWidth: RING_STROKE,
    borderColor: Colors.backgroundTertiary,
  },
  ringFill: {
    position: 'absolute',
    width: HUD_SIZE - RING_STROKE,
    height: HUD_SIZE - RING_STROKE,
    borderRadius: (HUD_SIZE - RING_STROKE) / 2,
    borderWidth: RING_STROKE,
    borderColor: Colors.success,
    // Note: true arc animation requires react-native-svg ProgressArc or
    // a custom skia canvas. This border approach gives a visual approximation.
    // For production, swap to a proper SVG arc component.
  },
  centreText: {
    flexDirection: 'row',
    alignItems: 'baseline',
  },
  countText: {
    fontSize: Typography.xl,
    fontWeight: Typography.bold,
    color: Colors.textPrimary,
  },
  expectedText: {
    fontSize: Typography.md,
    fontWeight: Typography.regular,
    color: Colors.textSecondary,
  },
  labels: {
    alignItems: 'center',
    gap: Spacing.xxs,
  },
  statusLabel: {
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
    color: Colors.success,
  },
  timeLabel: {
    fontSize: Typography.xs,
    color: Colors.textSecondary,
  },
  frameLabel: {
    fontSize: Typography.xs,
    color: Colors.textTertiary,
  },
});
