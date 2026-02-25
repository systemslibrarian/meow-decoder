/**
 * AppIcon.tsx — Branded yarn-ball + QR motif icon with dark/light variants.
 *
 * Used in the SplashScreen and anywhere else a branded mark is needed.
 * Built with react-native-svg so it scales crisply at any resolution
 * and adapts to the system colour scheme.
 *
 * Design language:
 *   - Central yarn ball (cat toy) rendered as overlapping circular arcs
 *   - Subtle 3×3 QR finder-pattern squares embedded in the lower-right
 *   - Cat-ear silhouette on top
 *   - Dark mode: gold-on-black (default)   Light mode: dark-on-cream
 *
 * Usage:
 *   <AppIcon size={160} variant="dark" />
 */

import React from 'react';
import Svg, {
  Circle,
  G,
  Path,
  Rect,
} from 'react-native-svg';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AppIconProps {
  /** Overall width & height in points (default 160) */
  size?: number;
  /** Colour variant: "dark" (gold on black) or "light" (brand on cream) */
  variant?: 'dark' | 'light';
}

// ── Colour palettes ───────────────────────────────────────────────────────────

const PALETTE = {
  dark: {
    bg: '#0a0a0f',
    yarn: '#f5c842',        // catGold
    yarnArc: '#d4a800',     // catGoldDark
    accent: '#FF8C42',      // catOrange
    qr: 'rgba(245,200,66,0.35)',
    ear: '#f5c842',
  },
  light: {
    bg: '#FFF8EC',
    yarn: '#CC6E2C',        // catOrangeDark
    yarnArc: '#FF8C42',     // catOrange
    accent: '#D4A800',
    qr: 'rgba(204,110,44,0.30)',
    ear: '#CC6E2C',
  },
};

// ── Component ─────────────────────────────────────────────────────────────────

export const AppIcon: React.FC<AppIconProps> = ({
  size = 160,
  variant = 'dark',
}) => {
  const s = size;
  const c = PALETTE[variant];
  // All coordinates are relative to a 160×160 viewBox, SVG scales the rest.

  return (
    <Svg
      width={s}
      height={s}
      viewBox="0 0 160 160"
      accessibilityRole="image"
      accessibilityLabel="Meow Decoder app icon: yarn ball with QR pattern and cat ears"
    >
      {/* Background circle */}
      <Circle cx="80" cy="80" r="76" fill={c.bg} />

      {/* Cat ears (top-left and top-right triangles) */}
      <G opacity={0.95}>
        <Path
          d="M48 42 L60 62 L36 62 Z"
          fill={c.ear}
        />
        <Path
          d="M112 42 L124 62 L100 62 Z"
          fill={c.ear}
        />
        {/* Inner ear accents */}
        <Path
          d="M50 48 L57 58 L43 58 Z"
          fill={c.accent}
          opacity={0.5}
        />
        <Path
          d="M110 48 L117 58 L103 58 Z"
          fill={c.accent}
          opacity={0.5}
        />
      </G>

      {/* Yarn ball — overlapping arcs to give a wound-thread look */}
      <G opacity={0.9}>
        {/* Base ball */}
        <Circle cx="80" cy="85" r="30" fill={c.yarn} opacity={0.25} />

        {/* Thread arcs (6 curves, rotated) */}
        <Path
          d="M55 80 Q80 55 105 80"
          stroke={c.yarn}
          strokeWidth="2.5"
          fill="none"
          strokeLinecap="round"
        />
        <Path
          d="M58 92 Q80 68 102 92"
          stroke={c.yarnArc}
          strokeWidth="2"
          fill="none"
          strokeLinecap="round"
        />
        <Path
          d="M60 75 Q80 100 100 75"
          stroke={c.yarn}
          strokeWidth="2.5"
          fill="none"
          strokeLinecap="round"
        />
        <Path
          d="M63 98 Q80 75 97 98"
          stroke={c.yarnArc}
          strokeWidth="2"
          fill="none"
          strokeLinecap="round"
        />
        {/* Diagonal arcs */}
        <Path
          d="M60 70 Q90 85 65 105"
          stroke={c.yarn}
          strokeWidth="2"
          fill="none"
          strokeLinecap="round"
        />
        <Path
          d="M100 70 Q70 85 95 105"
          stroke={c.yarnArc}
          strokeWidth="2"
          fill="none"
          strokeLinecap="round"
        />
        {/* Trailing thread strand from ball */}
        <Path
          d="M108 95 Q118 100 120 112 Q122 122 115 128"
          stroke={c.yarn}
          strokeWidth="2"
          fill="none"
          strokeLinecap="round"
          strokeDasharray="4 3"
        />
      </G>

      {/* Subtle QR finder-pattern motif (lower-right) — 3 nested squares */}
      <G opacity={0.55}>
        {/* Outer finder */}
        <Rect x="108" y="108" width="18" height="18" rx="2" fill="none" stroke={c.qr} strokeWidth="2" />
        {/* Middle gap */}
        <Rect x="112" y="112" width="10" height="10" rx="1" fill="none" stroke={c.qr} strokeWidth="1" />
        {/* Inner dot */}
        <Rect x="115" y="115" width="4" height="4" rx="0.5" fill={c.qr} />

        {/* Small data modules */}
        <Rect x="108" y="130" width="3" height="3" fill={c.qr} />
        <Rect x="114" y="130" width="3" height="3" fill={c.qr} />
        <Rect x="130" y="108" width="3" height="3" fill={c.qr} />
        <Rect x="130" y="114" width="3" height="3" fill={c.qr} />
      </G>
    </Svg>
  );
};

export default AppIcon;
