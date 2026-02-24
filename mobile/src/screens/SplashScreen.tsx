/**
 * SplashScreen.tsx — Animated intro screen.
 *
 * Displays the app logo with a cat-eye opening animation, version number,
 * and transitions automatically to Home (or Onboarding on first launch).
 */

import React, { useEffect } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withSequence,
  withDelay,
  Easing,
  runOnJS,
} from 'react-native-reanimated';
import { Colors, Typography, Spacing } from '../constants/theme';
import { APP_VERSION } from '../constants/config';
import type { SplashScreenProps } from '../types/navigation';

// ── Constants ─────────────────────────────────────────────────────────────────

const FIRST_LAUNCH_KEY = 'meow_has_launched';

// ── Component ─────────────────────────────────────────────────────────────────

export function SplashScreen({ navigation }: SplashScreenProps) {
  // Eye opening: scaleY starts at 0.05 (closed) → 1 (open)
  const eyeScale = useSharedValue(0.05);
  const logoOpacity = useSharedValue(0);
  const textOpacity = useSharedValue(0);

  const navigateNext = () => {
    // Check if user has seen onboarding (stored in MMKV or AsyncStorage)
    // For simplicity we always go to Home here; OnboardingScreen is shown
    // via the navigator's initial route logic in App.tsx.
    navigation.replace('Home');
  };

  useEffect(() => {
    // Sequence: logo appears → eye opens → text fades in → navigate
    logoOpacity.value = withTiming(1, { duration: 300 });

    eyeScale.value = withDelay(
      200,
      withSequence(
        withTiming(1, { duration: 600, easing: Easing.out(Easing.back(1.2)) }),
      ),
    );

    textOpacity.value = withDelay(700, withTiming(1, { duration: 400 }));

    // Navigate after animation completes
    const timer = setTimeout(navigateNext, 1_800);
    return () => clearTimeout(timer);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const logoStyle = useAnimatedStyle(() => ({
    opacity: logoOpacity.value,
    transform: [{ scaleY: eyeScale.value }],
  }));

  const textStyle = useAnimatedStyle(() => ({
    opacity: textOpacity.value,
  }));

  return (
    <View style={styles.container}>
      <Animated.Text style={[styles.logo, logoStyle]}>🐱</Animated.Text>
      <Animated.View style={[styles.textGroup, textStyle]}>
        <Text style={styles.title}>meow-decoder</Text>
        <Text style={styles.subtitle}>Optical air-gap capture</Text>
        <Text style={styles.version}>v{APP_VERSION}</Text>
      </Animated.View>
    </View>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: Colors.background,
    justifyContent: 'center',
    alignItems: 'center',
  },
  logo: {
    fontSize: 96,
    marginBottom: Spacing.xl,
  },
  textGroup: {
    alignItems: 'center',
  },
  title: {
    color: Colors.catOrange,
    fontSize: Typography.xxl,
    fontWeight: Typography.heavy,
    letterSpacing: 1,
  },
  subtitle: {
    color: Colors.textSecondary,
    fontSize: Typography.md,
    marginTop: Spacing.xs,
  },
  version: {
    color: Colors.textTertiary,
    fontSize: Typography.sm,
    marginTop: Spacing.sm,
  },
});
