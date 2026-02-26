/**
 * SplashScreen.tsx — Animated intro screen.
 *
 * Displays the branded yarn-ball + QR app icon with a cat-eye opening
 * animation, version number, and transitions automatically to Home
 * (or Onboarding on first launch).
 */

import React, { useEffect } from 'react';
import { View, Text, StyleSheet, useColorScheme } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withTiming,
  withSequence,
  withDelay,
  Easing,
  useReducedMotion,
} from 'react-native-reanimated';
import { Colors, Typography, Spacing } from '../constants/theme';
import { APP_VERSION } from '../constants/config';
import { AppIcon } from '../components/AppIcon';
import type { SplashScreenProps } from '../types/navigation';

// ── Component ─────────────────────────────────────────────────────────────────

export function SplashScreen({ navigation }: SplashScreenProps) {
  const colorScheme = useColorScheme();
  const iconVariant = colorScheme === 'light' ? 'light' : 'dark';

  // Eye opening: scaleY starts at 0.05 (closed) → 1 (open)
  const eyeScale = useSharedValue(0.05);
  const logoOpacity = useSharedValue(0);
  const textOpacity = useSharedValue(0);
  const reducedMotion = useReducedMotion();

  const navigateNext = () => {
    navigation.replace('Home');
  };

  useEffect(() => {
    if (reducedMotion) {
      // Skip all animation — instantly visible, shorter wait
      logoOpacity.value = 1;
      eyeScale.value = 1;
      textOpacity.value = 1;
      const timer = setTimeout(navigateNext, 600);
      return () => clearTimeout(timer);
    }

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
    <View style={styles.container} accessible accessibilityLabel="Meow Capture splash screen">
      <Animated.View style={[styles.logoContainer, logoStyle]}>
        <AppIcon size={160} variant={iconVariant} />
      </Animated.View>
      <Animated.View style={[styles.textGroup, textStyle]}>
        <Text style={styles.title}>Meow Capture</Text>
        <Text style={styles.subtitle}>Secure optical air-gap capture</Text>
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
  logoContainer: {
    marginBottom: Spacing.xl,
    alignItems: 'center',
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
