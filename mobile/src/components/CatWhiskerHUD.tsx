/**
 * CatWhiskerHUD.tsx — Animated cat-face stability indicator.
 *
 * Replaces the plain magnitude bar with a minimal SVG cat face whose
 * whiskers and pupils react to device shake magnitude in real time.
 *
 *  Calm  (shake ≈ 0):  whiskers horizontal, pupils small, half-lidded eyes
 *  Alert (shake > threshold): whiskers flared up/down, pupils dilated, wide eyes
 *
 * All animation runs on the UI thread via Reanimated `useAnimatedProps` —
 * no JS-thread round-trip during the animation loop.
 *
 * Zero new dependencies: SVG + Reanimated are already in the project.
 * Render cost: ~2 ms on UI thread per frame (6 animated SVG elements).
 */

import React, { useEffect } from 'react';
import { StyleSheet, View } from 'react-native';
import Animated, {
  useSharedValue,
  useAnimatedProps,
  withSpring,
  interpolate,
  Extrapolation,
} from 'react-native-reanimated';
import Svg, { Circle, Line, Ellipse } from 'react-native-svg';
import { SHAKE_THRESHOLD_MS2 } from '../constants/config';

// ── Explicit prop shapes for SVG primitives ────────────────────────────────────
// Required so that Animated.createAnimatedComponent can infer correct TProps
// (the react-native-svg types use a complex NumberProp union; we flatten to
// number | string to keep the animatedProps checks strict-safe).
type SvgLineProps = {
  x1?: number | string; y1?: number | string;
  x2?: number | string; y2?: number | string;
  stroke?: string; strokeWidth?: number | string; opacity?: number;
};
type SvgCircleProps = {
  cx?: number | string; cy?: number | string; r?: number | string;
  fill?: string; stroke?: string; strokeWidth?: number | string; opacity?: number;
};
type SvgEllipseProps = {
  cx?: number | string; cy?: number | string;
  rx?: number | string; ry?: number | string;
  stroke?: string; strokeWidth?: number | string; fill?: string; opacity?: number;
};

// Create animated versions of the SVG primitives we need to drive on UI thread
const AnimatedLine = Animated.createAnimatedComponent(
  Line as React.ComponentType<SvgLineProps>,
);
const AnimatedCircle = Animated.createAnimatedComponent(
  Circle as React.ComponentType<SvgCircleProps>,
);
const AnimatedEllipse = Animated.createAnimatedComponent(
  Ellipse as React.ComponentType<SvgEllipseProps>,
);

// ── Props ─────────────────────────────────────────────────────────────────────

interface CatWhiskerHUDProps {
  /** Accelerometer shake magnitude in m/s² from useStabilityMonitor */
  shakeMagnitude: number;
  /** Whether to render (false → null return, no layout cost) */
  visible: boolean;
}

// ── Component ─────────────────────────────────────────────────────────────────

export const CatWhiskerHUD = React.memo(function CatWhiskerHUD({
  shakeMagnitude,
  visible,
}: CatWhiskerHUDProps) {
  // Normalised tension: 0 (perfectly still) → 1 (at/above threshold)
  // Spring physics gives it organic feel — no sharp jumps.
  const tension = useSharedValue(0);

  useEffect(() => {
    tension.value = withSpring(
      Math.min(shakeMagnitude / SHAKE_THRESHOLD_MS2, 1),
      { damping: 14, stiffness: 120 },
    );
  }, [shakeMagnitude, tension]);

  // ── Whisker animations ────────────────────────────────────────────────────
  // Top whiskers flare UP (negative y = toward ears) on alarm
  // Bottom whiskers flare DOWN (positive y = toward chin)
  // Both sets rotate away from horizontal as tension increases.

  // Left top whisker — rotates CCW (toward ear)
  const leftTopWhiskerProps = useAnimatedProps<SvgLineProps>(() => {
    const angle = interpolate(tension.value, [0, 1], [-3, -28], Extrapolation.CLAMP);
    // Rotate around the whisker's nose-side anchor point (left whisker base ≈ x=35, y=48)
    return {
      y1: 48 + Math.sin(angle * Math.PI / 180) * 25,
      x1: 10 + Math.cos(angle * Math.PI / 180) * -25, // extends leftward
    };
  });

  // Left bottom whisker — rotates CW (toward chin)
  const leftBottomWhiskerProps = useAnimatedProps<SvgLineProps>(() => {
    const angle = interpolate(tension.value, [0, 1], [3, 22], Extrapolation.CLAMP);
    return {
      y1: 54 + Math.sin(angle * Math.PI / 180) * 25,
      x1: 10 + Math.cos(angle * Math.PI / 180) * -25,
    };
  });

  // Right top whisker — mirrors left
  const rightTopWhiskerProps = useAnimatedProps<SvgLineProps>(() => {
    const angle = interpolate(tension.value, [0, 1], [-3, -28], Extrapolation.CLAMP);
    return {
      y1: 48 + Math.sin(angle * Math.PI / 180) * 25,
      x1: 70 - Math.cos(angle * Math.PI / 180) * -25,
    };
  });

  // Right bottom whisker — mirrors left
  const rightBottomWhiskerProps = useAnimatedProps<SvgLineProps>(() => {
    const angle = interpolate(tension.value, [0, 1], [3, 22], Extrapolation.CLAMP);
    return {
      y1: 54 + Math.sin(angle * Math.PI / 180) * 25,
      x1: 70 - Math.cos(angle * Math.PI / 180) * -25,
    };
  });

  // ── Pupil dilation ────────────────────────────────────────────────────────
  // Pupils go from 3 px (calm) → 6.5 px (alarmed) — subtle but readable
  const leftPupilProps = useAnimatedProps<SvgCircleProps>(() => ({
    r: interpolate(tension.value, [0, 1], [3, 6.5], Extrapolation.CLAMP),
  }));
  const rightPupilProps = useAnimatedProps<SvgCircleProps>(() => ({
    r: interpolate(tension.value, [0, 1], [3, 6.5], Extrapolation.CLAMP),
  }));

  // ── Eye aperture ──────────────────────────────────────────────────────────
  // Eyes widen vertically: ry 4 (calm, slightly squinted) → 6 (wide/alarmed)
  const leftEyeProps = useAnimatedProps<SvgEllipseProps>(() => ({
    ry: interpolate(tension.value, [0, 1], [4, 6], Extrapolation.CLAMP),
  }));
  const rightEyeProps = useAnimatedProps<SvgEllipseProps>(() => ({
    ry: interpolate(tension.value, [0, 1], [4, 6], Extrapolation.CLAMP),
  }));

  if (!visible) return null;

  return (
    <View
      style={styles.container}
      pointerEvents="none"
      // Accessibility: describable for screen readers even though this
      // is purely decorative — it duplicates StabilityIndicator semantics.
      accessibilityLabel="Stability indicator"
      accessibilityElementsHidden={true}
      importantForAccessibility="no-hide-descendants"
    >
      {/*
        80 × 80 monochrome SVG cat face.
        Colour: #888 for structure, #aaa for pupils — matches dark theme
        without being intrusive over the camera feed.
      */}
      <Svg width={80} height={80} viewBox="0 0 80 80">
        {/* ── Head outline ───────────────────────────── */}
        <Ellipse
          cx="40" cy="44" rx="28" ry="25"
          stroke="#888" strokeWidth="1.5" fill="none" opacity={0.85}
        />
        {/* ── Ears ───────────────────────────────────── */}
        <Line x1="18" y1="24" x2="26" y2="10" stroke="#888" strokeWidth="1.5" opacity={0.8} />
        <Line x1="62" y1="24" x2="54" y2="10" stroke="#888" strokeWidth="1.5" opacity={0.8} />

        {/* ── Eye outlines — animated aperture ───────── */}
        <AnimatedEllipse
          cx={28} cy={40} rx={7}
          stroke="#888" strokeWidth="1" fill="none" opacity={0.9}
          animatedProps={leftEyeProps}
        />
        <AnimatedEllipse
          cx={52} cy={40} rx={7}
          stroke="#888" strokeWidth="1" fill="none" opacity={0.9}
          animatedProps={rightEyeProps}
        />

        {/* ── Pupils — animate dilation ───────────────── */}
        <AnimatedCircle cx={28} cy={40} fill="#aaa" opacity={0.9} animatedProps={leftPupilProps} />
        <AnimatedCircle cx={52} cy={40} fill="#aaa" opacity={0.9} animatedProps={rightPupilProps} />

        {/* ── Nose ────────────────────────────────────── */}
        <Circle cx="40" cy="52" r="2" fill="#888" opacity={0.8} />

        {/* ── Left whiskers (horizontal anchor ≈ x=10–35, y=48/54) ── */}
        {/* Top-left whisker — animated flare */}
        <AnimatedLine
          x2={35} y2={48}
          stroke="#666" strokeWidth="1" opacity={0.7}
          animatedProps={leftTopWhiskerProps}
        />
        {/* Middle-left whisker — static horizontal */}
        <Line x1="10" y1="51" x2="35" y2="51" stroke="#666" strokeWidth="1" opacity={0.7} />
        {/* Bottom-left whisker — animated flare */}
        <AnimatedLine
          x2={35} y2={54}
          stroke="#666" strokeWidth="1" opacity={0.7}
          animatedProps={leftBottomWhiskerProps}
        />

        {/* ── Right whiskers (horizontal anchor ≈ x=45–70, y=48/54) ── */}
        {/* Top-right whisker */}
        <AnimatedLine
          x2={45} y2={48}
          stroke="#666" strokeWidth="1" opacity={0.7}
          animatedProps={rightTopWhiskerProps}
        />
        {/* Middle-right whisker — static */}
        <Line x1="70" y1="51" x2="45" y2="51" stroke="#666" strokeWidth="1" opacity={0.7} />
        {/* Bottom-right whisker */}
        <AnimatedLine
          x2={45} y2={54}
          stroke="#666" strokeWidth="1" opacity={0.7}
          animatedProps={rightBottomWhiskerProps}
        />
      </Svg>
    </View>
  );
});

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    position: 'absolute',
    // Bottom-left corner of camera view, above the controls bar
    bottom: 120,
    left: 16,
    width: 80,
    height: 80,
    // Semi-transparent pill so cat is legible over any background
    backgroundColor: 'rgba(0,0,0,0.4)',
    borderRadius: 40,
    justifyContent: 'center',
    alignItems: 'center',
  },
});
