/**
 * CaptureCoachPanel.tsx — Live coaching hints during capture.
 *
 * Reads the already-tracked telemetry (decodeRate, duplicateRate,
 * shakeMagnitude, exposureBias) and derives actionable hints in priority
 * order. Shown as a compact pill-row beneath the ProgressHUD — unobtrusive
 * during good captures, clearly visible when something needs attention.
 *
 * Priority ladder (only the highest-priority active hint is shown as the
 * primary hint; up to two secondary hints may follow):
 *   1. Camera stalled / no signal         → Move camera / check screen
 *   2. High shake                         → Hold steady
 *   3. Dark / underexposed (bias at −2)   → Increase screen brightness
 *   4. Very high duplicate rate (≥ 80%)   → Move closer / PWM flicker
 *   5. Good decode rate but not yet safe  → Keep going
 *   6. Safe to stop                       → Done hint (echoes ProgressHUD)
 *
 * Zero new dependencies — uses Colors/Typography/Spacing already in scope.
 * All layout is static (no animations) to avoid competing with the progress
 * ring animation on the UI thread.
 */

import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Colors, Typography, Spacing, Radius } from '../constants/theme';
import { SHAKE_THRESHOLD_MS2 } from '../constants/config';

// ── Types ─────────────────────────────────────────────────────────────────────

interface CaptureCoachPanelProps {
  /** Fresh decoded droplets per second (from useQRScanner, rolling 3 s) */
  decodeRate: number;
  /** Fraction of all QR scans that were duplicates 0–1 */
  duplicateRate: number;
  /** Accelerometer shake magnitude m/s² */
  shakeMagnitude: number;
  /** Current camera exposure bias –2…+2 */
  exposureBias: number;
  /** True once fountain threshold is met */
  safeToStop: boolean;
  /** Whether the panel should render at all */
  visible: boolean;
}

// ── Hint derivation ───────────────────────────────────────────────────────────

interface Hint {
  icon: string;
  text: string;
  severity: 'ok' | 'info' | 'warn' | 'crit';
}

function deriveHints(
  decodeRate: number,
  duplicateRate: number,
  shakeMagnitude: number,
  exposureBias: number,
  safeToStop: boolean,
): Hint[] {
  const hints: Hint[] = [];

  // ── No signal at all ──────────────────────────────────────────────────────
  if (decodeRate < 0.1) {
    hints.push({
      icon: '🔍',
      text: 'No signal — point at the animated QR',
      severity: 'crit',
    });
    return hints; // nothing else is meaningful without any signal
  }

  // ── Excessive shake ───────────────────────────────────────────────────────
  if (shakeMagnitude > SHAKE_THRESHOLD_MS2 * 1.5) {
    hints.push({
      icon: '📵',
      text: 'Hold very still — phone is shaking',
      severity: 'crit',
    });
  } else if (shakeMagnitude > SHAKE_THRESHOLD_MS2) {
    hints.push({
      icon: '✋',
      text: 'Hold steady for better scan rate',
      severity: 'warn',
    });
  }

  // ── Exposure / brightness ─────────────────────────────────────────────────
  if (exposureBias <= -1.5) {
    hints.push({
      icon: '☀️',
      text: 'Very dark — increase screen brightness or tap ☀️+',
      severity: 'crit',
    });
  } else if (exposureBias <= -0.5) {
    hints.push({
      icon: '🌤',
      text: 'Slightly dark — try increasing screen brightness',
      severity: 'info',
    });
  }

  // ── High duplicate rate ───────────────────────────────────────────────────
  // ≥ 80% duplicates means the GIF is cycling but the phone isn't advancing.
  // Either too far away (QR too small) or PWM flicker is causing missed frames.
  if (duplicateRate >= 0.8 && decodeRate < 2.0) {
    hints.push({
      icon: '📏',
      text: 'Too many duplicates — move 5 cm closer or tilt screen slightly',
      severity: 'warn',
    });
  } else if (duplicateRate >= 0.8) {
    hints.push({
      icon: '🔄',
      text: 'High duplicate rate — try lowering display refresh (PWM flicker)',
      severity: 'info',
    });
  }

  // ── Good rate summary ─────────────────────────────────────────────────────
  if (hints.length === 0) {
    if (safeToStop) {
      hints.push({
        icon: '😸',
        text: 'Purrfect — safe to stop now!',
        severity: 'ok',
      });
    } else if (decodeRate >= 3.0) {
      hints.push({
        icon: '🐾',
        text: `${decodeRate.toFixed(1)} fps — excellent signal, keep going`,
        severity: 'ok',
      });
    } else {
      hints.push({
        icon: '📡',
        text: `${decodeRate.toFixed(1)} fps — receiving — keep camera steady`,
        severity: 'info',
      });
    }
  }

  return hints.slice(0, 3); // cap at 3 hints to avoid visual noise
}

// ── Severity → colour map ─────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<Hint['severity'], string> = {
  crit: 'rgba(255,59,48,0.85)',
  warn: 'rgba(255,159,10,0.85)',
  info: 'rgba(10,132,255,0.75)',
  ok:   'rgba(52,199,89,0.75)',
};

// ── Component ─────────────────────────────────────────────────────────────────

export const CaptureCoachPanel = React.memo(function CaptureCoachPanel({
  decodeRate,
  duplicateRate,
  shakeMagnitude,
  exposureBias,
  safeToStop,
  visible,
}: CaptureCoachPanelProps) {
  if (!visible) return null;

  const hints = deriveHints(decodeRate, duplicateRate, shakeMagnitude, exposureBias, safeToStop);

  return (
    <View
      style={styles.container}
      accessibilityLabel={hints.map((h) => h.text).join('. ')}
      accessibilityLiveRegion="polite"
    >
      {hints.map((hint, idx) => (
        <View
          key={idx}
          style={[
            styles.pill,
            { backgroundColor: SEVERITY_COLORS[hint.severity] },
            idx === 0 && styles.pillPrimary,
          ]}
        >
          <Text style={[styles.pillText, idx === 0 && styles.pillTextPrimary]}>
            {hint.icon}  {hint.text}
          </Text>
        </View>
      ))}
    </View>
  );
});

// ── Styles ─────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    position: 'absolute',
    bottom: 200,
    left: Spacing.lg,
    right: Spacing.lg,
    gap: Spacing.xs,
    alignItems: 'center',
  },
  pill: {
    borderRadius: Radius.full,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.xs,
    maxWidth: '100%',
  },
  pillPrimary: {
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.sm,
  },
  pillText: {
    color: Colors.textPrimary,
    fontSize: Typography.xs,
    fontWeight: Typography.medium,
    textAlign: 'center',
  },
  pillTextPrimary: {
    fontSize: Typography.sm,
    fontWeight: Typography.semibold,
  },
});
