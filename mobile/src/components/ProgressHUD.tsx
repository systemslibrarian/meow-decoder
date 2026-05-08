/**
 * ProgressHUD.tsx — Real-time capture progress overlay.
 *
 * Displays:
 *  - Animated circular arc progress ring (SVG strokeDashoffset)
 *  - Frame count (captured / expected) centred inside the ring
 *  - Recoverability label
 *  - Elapsed time and ETA
 *
 * The arc is driven by react-native-reanimated useAnimatedProps so the
 * stroke animation runs on the UI thread without JS-thread involvement.
 *
 * Ring geometry:
 *   viewBox = 128×128, ring centre = (64, 64)
 *   radius  = 56 → circumference ≈ 351.86 px
 *   strokeDashoffset maps [0, 1] progress → [CIRCUMFERENCE, 0]
 *   Transform rotate(-90) starts the arc at the 12 o'clock position.
 */

import React, { useEffect } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Animated, {
  useAnimatedProps,
  useSharedValue,
  withTiming,
  Easing,
} from 'react-native-reanimated';
import Svg, { Circle } from 'react-native-svg';

// Local SVG-circle prop shape (react-native-svg 14.1.0 doesn't re-export
// CircleProps from the package root). Flattened to number | string to keep
// animatedProps inference strict-safe.
type SvgCircleProps = {
  cx?: number | string; cy?: number | string; r?: number | string;
  stroke?: string; strokeWidth?: number | string; fill?: string;
  strokeLinecap?: 'butt' | 'round' | 'square';
  strokeDasharray?: number | string | (number | string)[];
  strokeDashoffset?: number | string;
  transform?: string; opacity?: number;
};

// Must be created at module level — not inside the component.
// Cast to ComponentClass so createAnimatedComponent picks the correct overload.
const AnimatedCircle = Animated.createAnimatedComponent(
  Circle as unknown as React.ComponentClass<SvgCircleProps>,
);
import type { CaptureProgress } from '../types/capture';
import type { CaptureState } from '../types/capture';
import { Colors, Typography, Spacing, Radius, Shadows } from '../constants/theme';
import { progressColor } from '../constants/theme';
import {
  formatFrameCount,
  formatElapsed,
  estimateETA,
  recoveryConfidenceLabel,
  decodeRateDisplay,
} from '../utils/formatters';

// ── Props ─────────────────────────────────────────────────────────────────────

interface ProgressHUDProps {
  progress: CaptureProgress;
  status: CaptureState;
  elapsedMs: number;
  /** Fresh decoded droplets per second (from useQRScanner) */
  decodeRate?: number;
  /** Duplicate scan fraction 0–1 (from useQRScanner) */
  duplicateRate?: number;
}

// ── Ring geometry constants ───────────────────────────────────────────────────

const SVG_SIZE = 128;
const RING_RADIUS = 56;
const STROKE_WIDTH = 8;
const CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS; // ≈ 351.86

// ── Component ─────────────────────────────────────────────────────────────────

export const ProgressHUD = React.memo(function ProgressHUD({
  progress,
  status,
  elapsedMs,
  decodeRate,
  duplicateRate,
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

  // Drive strokeDashoffset on the UI thread via animatedProps
  const animatedArcProps = useAnimatedProps<{ strokeDashoffset: number }>(() => ({
    strokeDashoffset: CIRCUMFERENCE * (1 - fillFraction.value),
  }));

  const ringColor = progressColor(progress.percentRecoverable);

  const eta = estimateETA(progress.captured, progress.expected, elapsedMs);
  const confidence = recoveryConfidenceLabel(progress.captured, progress.expected);

  const isActiveCapture =
    status === 'CAPTURING' || status === 'AWAITING_GIF';

  return (
    <View
      style={styles.container}
      accessible={true}
      accessibilityLabel={`Capture progress: ${Math.round(progress.percentRecoverable)} percent. ${confidence.label}. ${confidence.sublabel}${confidence.safeToStop ? '. Safe to stop now.' : ''}`}
      accessibilityRole="progressbar"
      accessibilityValue={{ min: 0, max: 100, now: Math.round(progress.percentRecoverable) }}
      accessibilityLiveRegion="polite"
    >
      {/* ── SVG progress ring ──────────────────────────────────────── */}
      <View style={styles.ringWrapper} importantForAccessibility="no-hide-descendants">
        <Svg
          width={SVG_SIZE}
          height={SVG_SIZE}
          viewBox={`0 0 ${SVG_SIZE} ${SVG_SIZE}`}
          style={styles.svg}
        >
          {/* Background track */}
          <Circle
            cx={SVG_SIZE / 2}
            cy={SVG_SIZE / 2}
            r={RING_RADIUS}
            stroke={Colors.surfaceBorder}
            strokeWidth={STROKE_WIDTH}
            fill="none"
          />
          {/* Progress arc — starts at 12 o'clock via rotate(-90, 64, 64) */}
          <AnimatedCircle
            cx={SVG_SIZE / 2}
            cy={SVG_SIZE / 2}
            r={RING_RADIUS}
            stroke={ringColor}
            strokeWidth={STROKE_WIDTH}
            fill="none"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            animatedProps={animatedArcProps}
            transform={`rotate(-90, ${SVG_SIZE / 2}, ${SVG_SIZE / 2})`}
          />
        </Svg>

        {/* ── Centred frame count overlay ──────────────────────────── */}
        <View style={styles.centreOverlay} pointerEvents="none">
          <Text style={[styles.frameCount, { color: ringColor }]}>
            {formatFrameCount(progress.captured, progress.expected)}
          </Text>
          <Text style={styles.recovLabel}>{confidence.label}</Text>
        </View>
      </View>

      {/* ── Confidence sublabel + safe-to-stop pill ─────────────────── */}
      <Text style={styles.sublabel}>{confidence.sublabel}</Text>
      {confidence.safeToStop && (
        <View style={styles.safeToStopPill}>
          <Text style={styles.safeToStopText}>✓ Safe to stop — tap Done</Text>
        </View>
      )}

      {/* ── Decode rate row (shown once signal established) ─────────── */}
      {decodeRate !== undefined && duplicateRate !== undefined && decodeRate > 0 && (
        <Text style={styles.decodeRateText}>
          {decodeRateDisplay(decodeRate, duplicateRate)}
        </Text>
      )}

      {/* ── Footer row: elapsed + ETA ───────────────────────────────── */}
      {isActiveCapture && (
        <View style={styles.footer}>
          <Text style={styles.timerText}>{formatElapsed(elapsedMs)}</Text>
          {eta !== null && (
            <Text style={styles.etaText}>ETA {eta}</Text>
          )}
        </View>
      )}
    </View>
  );
});

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  centreOverlay: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  container: {
    alignItems: 'center',
    alignSelf: 'center',
    backgroundColor: Colors.overlayDark,
    borderRadius: Radius.lg,
    bottom: 120,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
    position: 'absolute',
    ...Shadows.medium,
  },
  decodeRateText: {
    color: Colors.textSecondary,
    fontFamily: 'monospace' as const,
    fontSize: Typography.xs,
    marginTop: Spacing.xs,
    opacity: 0.75,
  },
  etaText: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
  },
  footer: {
    flexDirection: 'row',
    gap: Spacing.lg,
    marginTop: Spacing.sm,
  },
  frameCount: {
    fontSize: Typography.lg,
    fontWeight: Typography.bold,
    textAlign: 'center',
  },
  recovLabel: {
    color: Colors.textSecondary,
    fontSize: Typography.xs,
    marginTop: 2,
    textAlign: 'center',
  },
  ringWrapper: {
    alignItems: 'center',
    height: SVG_SIZE,
    justifyContent: 'center',
    width: SVG_SIZE,
  },
  safeToStopPill: {
    backgroundColor: 'rgba(52,199,89,0.18)',
    borderColor: 'rgba(52,199,89,0.5)',
    borderRadius: Radius.full,
    borderWidth: 1,
    marginTop: Spacing.xs,
    paddingHorizontal: Spacing.md,
    paddingVertical: 2,
  },
  safeToStopText: {
    color: '#34C759',
    fontSize: Typography.xs,
    fontWeight: Typography.semibold,
  },
  sublabel: {
    color: Colors.textSecondary,
    fontSize: Typography.xs,
    marginTop: Spacing.xs,
    maxWidth: 200,
    textAlign: 'center',
  },
  svg: {
    position: 'absolute',
  },
  timerText: {
    color: Colors.textSecondary,
    fontSize: Typography.sm,
  },
});
