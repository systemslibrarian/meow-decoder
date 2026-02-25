/**
 * formatters.ts — Display formatting utilities.
 *
 * Pure functions with no side effects — safe to call in render paths.
 */

// ── Time ──────────────────────────────────────────────────────────────────────

/**
 * Formats elapsed milliseconds as a human-readable string.
 *
 * Examples: 1500 → "1s", 65000 → "1m 5s", 3600000 → "1h 0m"
 */
export function formatElapsed(ms: number): string {
  if (ms < 0) return '0s';
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

/**
 * Formats a countdown (remaining seconds) as MM:SS.
 *
 * Examples: 65 → "01:05", 3 → "00:03"
 */
export function formatCountdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${String(m).padStart(2, '0')}:${String(rem).padStart(2, '0')}`;
}

// ── Percentages ───────────────────────────────────────────────────────────────

/**
 * Formats a fraction (0–1+) as a rounded percentage string.
 *
 * Caps display at 100% for UI clarity (actual values may exceed 1.0
 * once fountain overhead is met).
 *
 * Examples: 0.333 → "33%", 1.5 → "100%"
 *
 * @param capAt100 - Clamp display value at 100%. Default true.
 */
export function formatPercent(fraction: number, capAt100 = true): string {
  const pct = Math.round(fraction * 100);
  const display = capAt100 ? Math.min(pct, 100) : pct;
  return `${display}%`;
}

/**
 * Returns a recoverability label based on how many frames have been captured
 * relative to the expected count.
 */
export function recoverabilityLabel(captured: number, expected: number): string {
  if (expected === 0) return 'Waiting...';
  const ratio = captured / expected;
  if (ratio >= 1.5) return 'Transfer complete — all data captured';
  if (ratio >= 1.0) return 'Likely recoverable — good capture';
  if (ratio >= 0.67) return 'Possibly recoverable — try decoding';
  return 'Insufficient frames — may not decode';
}

// ── File Size ─────────────────────────────────────────────────────────────────

/**
 * Formats byte count as a human-readable file size.
 *
 * Examples: 1024 → "1.0 KB", 1500000 → "1.4 MB"
 */
export function formatFileSize(bytes: number): string {
  if (bytes < 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// ── Frame Stats ───────────────────────────────────────────────────────────────

/**
 * Formats frame capture status as a compact display string.
 *
 * Example: formatFrameCount(32, 45) → "32 / 45"
 */
export function formatFrameCount(captured: number, expected: number): string {
  return `${captured} / ${expected}`;
}

/**
 * Estimates remaining capture time based on current scan rate.
 *
 * @param captured - Frames captured so far
 * @param target - Total frames needed
 * @param elapsedMs - Milliseconds elapsed since scan started
 * @returns Human-readable ETA string, or null if insufficient data
 */
export function estimateETA(
  captured: number,
  target: number,
  elapsedMs: number,
): string | null {
  if (captured <= 0 || elapsedMs <= 0) return null;
  const remaining = target - captured;
  if (remaining <= 0) return '< 1s';
  const ratePerMs = captured / elapsedMs;
  const etaMs = remaining / ratePerMs;
  return `~${formatElapsed(etaMs)} left`;
}

// ── Recovery Confidence ───────────────────────────────────────────────────────

/**
 * Returns a tiered recovery confidence label with action guidance.
 *
 * Ratios are based on LT fountain code theory:
 *  ≥ 1.5× → fountain complete, safe to stop (0% failure risk)
 *  ≥ 1.2× → strong confidence (rare failure under clean conditions)
 *  ≥ 1.0× → likely recoverable (1–5% failure risk)
 *  ≥ 0.67× → marginal (may decode with retries)
 *  < 0.67× → insufficient
 */
export function recoveryConfidenceLabel(captured: number, expected: number): {
  label: string;
  sublabel: string;
  safeToStop: boolean;
  color: 'success' | 'gold' | 'warning' | 'danger' | 'dim';
} {
  if (expected === 0) return {
    label: 'Waiting…',
    sublabel: 'Point camera at the animated QR code on screen',
    safeToStop: false,
    color: 'dim',
  };
  const ratio = captured / expected;
  if (ratio >= 1.5) return {
    label: 'Transfer complete',
    sublabel: 'You have all the data needed — tap Done whenever ready',
    safeToStop: true,
    color: 'gold',
  };
  if (ratio >= 1.2) return {
    label: 'Strong recovery confidence',
    sublabel: 'Safe to stop now — a few more seconds gives best results',
    safeToStop: true,
    color: 'success',
  };
  if (ratio >= 1.0) return {
    label: 'Good progress',
    sublabel: 'Keep scanning — building safety margin for reliable recovery',
    safeToStop: false,
    color: 'success',
  };
  if (ratio >= 0.67) return {
    label: 'Getting there',
    sublabel: `About ${Math.ceil(expected - captured)} more frames needed for reliable recovery`,
    safeToStop: false,
    color: 'warning',
  };
  return {
    label: 'Keep scanning',
    sublabel: `Need at least ${Math.ceil(expected * 0.67 - captured)} more frames before recovery is possible`,
    safeToStop: false,
    color: 'danger',
  };
}

/**
 * Formats live decode-rate statistics for the capture feedback panel.
 *
 * @param freshPerSec - New unique droplets received per second
 * @param duplicateRate - Fraction of all scans that were duplicates (0–1)
 */
export function decodeRateDisplay(freshPerSec: number, duplicateRate: number): string {
  const fps = freshPerSec.toFixed(1);
  const dupPct = Math.round(duplicateRate * 100);
  if (freshPerSec < 0.1) return '— fps (no signal)';
  return `${fps} fps · ${dupPct}% dup`;
}
