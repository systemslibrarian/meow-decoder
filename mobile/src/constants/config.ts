/**
 * config.ts — App-wide configuration constants.
 *
 * Centralising all magic numbers here ensures changes propagate consistently
 * and makes security-relevant thresholds easy to audit.
 */

// ── Fountain Code Parameters ──────────────────────────────────────────────────

/**
 * Fountain code overhead factor: how many times expected_frames we need
 * to capture before declaring the transfer "fountain complete" (best quality).
 * Matches the Python CLI's default 1.5× redundancy setting.
 */
export const FOUNTAIN_OVERHEAD = 1.5 as const;

/**
 * Minimum fraction of expected_frames to consider recovery possible at all.
 * Below this the CLI is unlikely to reconstruct the file even with retries.
 */
export const MIN_RECOVERABLE_RATIO = 0.67 as const;

// ── Session Timing ────────────────────────────────────────────────────────────

/** Default session timeout in seconds when not specified by capture request */
export const DEFAULT_TIMEOUT_SECONDS = 60 as const;

/** Maximum allowed timeout from a capture request (10 minutes) */
export const MAX_TIMEOUT_SECONDS = 600 as const;

// ── GIF Auto-Detection ────────────────────────────────────────────────────────

/**
 * Detection window in milliseconds. We look at QR codes scanned within this
 * window and count unique values to detect animated GIF rotation.
 */
export const GIF_DETECT_WINDOW_MS = 500 as const;

/**
 * Minimum unique QR codes within GIF_DETECT_WINDOW_MS to trigger auto-start.
 * 3 distinct codes in 500ms strongly implies an animated GIF.
 */
export const GIF_DETECT_MIN_UNIQUE = 3 as const;

// ── QR Scanner ────────────────────────────────────────────────────────────────

/**
 * Minimum milliseconds between storing the same QR payload again.
 * Prevents processing the same physical frame multiple times at 30fps.
 */
export const QR_DEDUP_INTERVAL_MS = 50 as const;

/** Target camera frame rate. Vision Camera will try to honour this. */
export const CAMERA_FPS = 30 as const;

// ── Export ────────────────────────────────────────────────────────────────────

/** Maximum single-file export size in bytes before chunking (5 MB) */
// Note: arithmetic expressions cannot use `as const` — use the literal value directly.
export const MAX_EXPORT_CHUNK_BYTES = 5_242_880 as const;

// ── Stability Monitor ─────────────────────────────────────────────────────────

/**
 * Accelerometer magnitude (in m/s²) above which we show the "hold steady"
 * warning. Standard gravity is ~9.8; we add a delta for intentional shake.
 */
export const SHAKE_THRESHOLD_MS2 = 2.5 as const;

/**
 * Rolling window for accelerometer smoothing (milliseconds).
 * Short enough to be responsive; long enough to filter noise.
 */
export const STABILITY_WINDOW_MS = 300 as const;

// ── Memory Pressure ───────────────────────────────────────────────────────────

/**
 * Warn the user when frame count approaches this threshold.
 * Large captures with many frames can exhaust JS heap on older devices.
 */
export const MEMORY_WARN_FRAME_COUNT = 800 as const;

// ── QR Code Fallback Export ───────────────────────────────────────────────────

/**
 * Maximum bytes per QR code used in the reverse-optical export fallback.
 * QR version 40-L can hold ~2953 bytes; 2048 gives comfortable headroom
 * for base64 overhead and chunk metadata.
 */
export const QR_EXPORT_CHUNK_BYTES = 2048 as const;

// ── Milestone Thresholds (for sounds/toasts) ──────────────────────────────────

export const MILESTONE_THRESHOLDS = [0.25, 0.5, 0.75, 1.0] as const;
export type MilestoneThreshold = typeof MILESTONE_THRESHOLDS[number];

// ── Feature Flags ─────────────────────────────────────────────────────────

/**
 * Feature flags for incomplete or experimental features.
 * Set to `false` to hide the UI entry-point entirely.
 * When `true`, the feature is shown but may fall back to a "coming soon" modal
 * if the native bridge (TurboModule) is not linked in the current build.
 */
export const FEATURE_FLAGS = {
  /** Video/GIF import via native frame extraction bridge (TurboModule stub) */
  VIDEO_IMPORT: false,
  /**
   * Live Cat Mode blink capture (optical brightness channel). Requires the
   * react-native-worklets-core native module to be linked in the build (the
   * frame-processor sampler depends on it). Keep false until a device build
   * includes that dependency, then flip to true to surface the entry point.
   */
  CAT_MODE: true,
} as const;

// ── Cat Mode Capture ──────────────────────────────────────────────────────────

/**
 * Maximum time (ms) a live Cat Mode blink capture will keep recording without
 * recovering a complete payload before giving up. A full transmission of a
 * modest payload at the slow 200 ms blink rate runs ~1–2 minutes, so 3 minutes
 * leaves headroom for aiming and a few missed passes while still bounding how
 * long the camera can run if the signal is never decodable.
 */
export const CAT_CAPTURE_TIMEOUT_MS = 180_000 as const;

// ── App Version ───────────────────────────────────────────────────────────────

export const APP_VERSION = '3.2.3' as const;
export const PROTOCOL_VERSION = '1' as const;

// ── Stall Detection ───────────────────────────────────────────────────────────

/**
 * Milliseconds without a new frame before we surface a "stalled" hint to the
 * user during an active CAPTURING session.
 */
export const STALL_DETECT_MS = 5_000 as const;

// ── Clipboard Auto-Wipe ───────────────────────────────────────────────────────

/**
 * Milliseconds after copying the ADB command before we automatically clear
 * the clipboard. 45 s gives the user time to switch apps and paste while
 * minimising the forensic window.
 */
export const CLIPBOARD_WIPE_DELAY_MS = 45_000 as const;

// ── Capture Haptics ───────────────────────────────────────────────────────────

/**
 * Interval (ms) between "purr" haptic pulses emitted during active scanning
 * whenever a fresh frame was just decoded. Gives tactile confirmation that
 * the GIF is still being read without hammering the vibration motor.
 */
export const PURR_HAPTIC_INTERVAL_MS = 300 as const;

// ── Low-Light Detection ───────────────────────────────────────────────────────

/**
 * QR decode rate (frames/second) below which the low-light auto-nudge kicks in.
 * A rate below 1 fps usually means poor visibility, glare, or out-of-focus.
 */
export const LOW_LIGHT_RATE_THRESHOLD = 1.0 as const;

/**
 * Milliseconds the decode rate must stay below LOW_LIGHT_RATE_THRESHOLD before
 * the first coaching hint fires. Prevents false positives during brief pauses.
 */
export const LOW_LIGHT_DETECT_DELAY_MS = 2_000 as const;

