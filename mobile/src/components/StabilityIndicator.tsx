/**
 * StabilityIndicator.tsx — Shake / blur warning overlay.
 *
 * Shown on top of the camera preview when useStabilityMonitor reports
 * that the device is being held unsteadily. Fades in/out smoothly using
 * react-native-reanimated.
 */

import React, { useEffect } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  Easing,
} from 'react-native-reanimated';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';

// ── Props ─────────────────────────────────────────────────────────────────────

interface StabilityIndicatorProps {
  /** Current shake magnitude in m/s² */
  magnitude: number;
  /** Whether to show the indicator */
  visible: boolean;
}

// ── Component ─────────────────────────────────────────────────────────────────

export const StabilityIndicator = React.memo(function StabilityIndicator({
  magnitude,
  visible,
}: StabilityIndicatorProps) {
  const opacity = useSharedValue(0);

  useEffect(() => {
    opacity.value = withTiming(visible ? 1 : 0, {
      duration: 200,
      easing: Easing.inOut(Easing.ease),
    });
  }, [visible, opacity]);

  const animatedStyle = useAnimatedStyle(() => ({
    opacity: opacity.value,
  }));

  // Describe severity by magnitude bucketing
  const severity = magnitude > 5 ? 'high' : magnitude > 3 ? 'medium' : 'low';
  const icon = severity === 'high' ? '🙀' : '😾';
  const message =
    severity === 'high'
      ? 'Hold very still!'
      : 'Hold steady for better capture';

  return (
    <Animated.View
      style={[styles.container, animatedStyle]}
      pointerEvents="none"
      accessibilityLabel="Device unstable — hold steady"
    >
      <View style={styles.pill}>
        <Text style={styles.icon}>{icon}</Text>
        <Text style={styles.text}>{message}</Text>
      </View>
    </Animated.View>
  );
});

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    position: 'absolute',
    top: 120,
    left: 0,
    right: 0,
    alignItems: 'center',
  },
  pill: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(255, 59, 48, 0.85)',
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    borderRadius: Radius.full,
    gap: Spacing.xs,
  },
  icon: {
    fontSize: Typography.md,
  },
  text: {
    color: Colors.textPrimary,
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
});
