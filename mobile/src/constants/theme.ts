/**
 * theme.ts — Cat-themed colour palette, typography, and spacing constants.
 *
 * A single source of truth for all visual tokens keeps the app consistent
 * and makes themed components easy to build.
 */

// ── Colour Palette ────────────────────────────────────────────────────────────

export const Colors = {
  // Primary brand
  catOrange: '#FF8C42',
  catOrangeDark: '#CC6E2C',
  catOrangeLight: '#FFB07A',

  // Accent
  catGold: '#FFC820',
  catGoldDark: '#D4A800',

  // Status colours
  success: '#34C759',     // iOS green — "recoverable"
  successDark: '#248A3D',
  warning: '#FF9F0A',     // iOS orange — "approaching threshold"
  warningDark: '#C27700',
  danger: '#FF3B30',      // iOS red — "not enough frames"
  dangerDark: '#C0392B',
  info: '#0A84FF',        // iOS blue — informational

  // Neutrals
  background: '#000000',
  backgroundSecondary: '#1C1C1E',
  backgroundTertiary: '#2C2C2E',
  surface: '#1C1C1E',
  surfaceBorder: 'rgba(255, 255, 255, 0.1)',

  // Text
  textPrimary: '#FFFFFF',
  textSecondary: 'rgba(255, 255, 255, 0.7)',
  textTertiary: 'rgba(255, 255, 255, 0.45)',
  textDisabled: 'rgba(255, 255, 255, 0.25)',

  // Overlay
  overlayDark: 'rgba(0, 0, 0, 0.6)',
  overlayLight: 'rgba(255, 255, 255, 0.08)',

  // Scan region
  scanBorder: 'rgba(255, 200, 50, 0.8)',
  scanActive: 'rgba(255, 200, 50, 0.15)',
  scanCorner: '#FFC820',

  // Transparent
  transparent: 'transparent',
} as const;

export type ColorKey = keyof typeof Colors;

// ── Typography ────────────────────────────────────────────────────────────────

export const Typography = {
  // Sizes
  xs: 11,
  sm: 13,
  md: 16,
  lg: 20,
  xl: 24,
  xxl: 32,
  hero: 48,

  // Weights
  regular: '400' as const,
  medium: '500' as const,
  semibold: '600' as const,
  bold: '700' as const,
  heavy: '800' as const,

  // Line heights (multiplier)
  tight: 1.2,
  normal: 1.5,
  loose: 1.8,
} as const;

// ── Spacing ───────────────────────────────────────────────────────────────────

export const Spacing = {
  xxs: 2,
  xs: 4,
  sm: 8,
  md: 16,
  lg: 24,
  xl: 32,
  xxl: 48,
  xxxl: 64,
} as const;

// ── Border Radius ─────────────────────────────────────────────────────────────

export const Radius = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 24,
  full: 9999,
} as const;

// ── Shadows ───────────────────────────────────────────────────────────────────

export const Shadows = {
  subtle: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.2,
    shadowRadius: 2,
    elevation: 2,
  },
  medium: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 6,
  },
  strong: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.44,
    shadowRadius: 16,
    elevation: 12,
  },
} as const;

// ── Progress Bar Colours ──────────────────────────────────────────────────────

/**
 * Returns the fill colour for the progress indicator based on how close
 * we are to the fountain threshold.
 */
export function progressColor(percentRecoverable: number): string {
  if (percentRecoverable >= 100) return Colors.catGold;  // fountain complete
  if (percentRecoverable >= 67) return Colors.success;   // likely recoverable
  if (percentRecoverable >= 40) return Colors.warning;   // marginal
  return Colors.danger;                                   // not enough
}
