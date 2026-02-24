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

/** Total width of the animated progress track in logical pixels */
const TRACK_WIDTH = HUD_SIZE;

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

  // Animate fill bar width — `number` is always a valid ViewStyle prop
  // (unlike SVG strokeDashoffset which is not in DefaultStyle).
  const animatedFillStyle = useAnimatedStyle(() => ({
    width: fillFraction.value * TRACK_WIDTH,
  }));

  const ringColor = progressColor(progress.percentRecoverable);

  const eta = estimateETA(progress.captured, progress.expected, elapsedMs);
  const recovLabel = recoverabilityLabel(progress.captured, progress.expected);

  const isActiveCapture =
    status === 'CAPTURING' || status === 'AWAITING_GIF';

  return (
    <View style={styles.container} accessibilityLabel="Capture progress">
      {/* Frame counter */}
      <View style={styles.counterRow}>
        <Text style={[styles.countText, { color: ringColor }]}>
          {progress.captured}
        </Text>
        <Text style={styles.expectedText}>/{progress.expected}</Text>
      </View>

      {/* Animated linear progress bar */}
      <View style={styles.track}>
        <Animated.View
          style={[
            styles.fill,
            animatedFillStyle,
            { backgroundColor: ringColor },
          ]}
        />
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
  counterRow: {
    flexDirection: 'row',
    alignItems: 'baseline',
    marginBottom: Spacing.sm,
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
  track: {
    width: TRACK_WIDTH,
    height: 8,
    backgroundColor: Colors.backgroundTertiary,
    borderRadius: 4,
    overflow: 'hidden',
    marginBottom: Spacing.sm,
  },
  fill: {
    height: 8,
    borderRadius: 4,
    // width is driven by Reanimated animatedFillStyle
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
