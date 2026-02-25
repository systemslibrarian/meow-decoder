# Meow Capture — React Native Mobile Companion App

Optical air-gap file transfer companion for [meow-decoder](../README.md). Scans animated QR code GIFs from any screen using your phone camera and exports the captured frame data as a structured JSON file for desktop decryption.

**No network. No cloud. No traces.**

> **v3.1 (2026)** — Full accessibility + polish pass. Respects Reduce Motion system preference (SplashScreen, FrameOverlay, CatToast). VoiceOver/TalkBack announces toasts (`accessibilityLiveRegion`). `KeyboardAvoidingView` on Home; error banners announced; haptics on file load; stale errors cleared on re-focus. OnboardingScreen shows "Open Settings" recovery when camera permission is denied. Android hardware back button prompts confirmation before discarding an active capture session. 267/267 tests, strict TypeScript.
>
> **v3 (2026)** — Major UX hardening. SVG arc progress ring with fountain-threshold indicator. Adaptive frame-rate scanning (60 Hz → 10 Hz back-off). Stall detector toasts when no new frames arrive for 4 s. Pause / resume capture mid-session. Panic wipe via 3-second long-press cancel. Clipboard auto-wipe after export. Universal-link / deep-link support (`meow://capture?…`). VoiceOver improvements on StabilityIndicator.
>
> **v2 (2026)** — Production-hardened release. Native VisionCamera v4 scanner, biometric export gate, FLAG_SECURE screenshot blocking, pinch-to-zoom + exposure control, haptic feedback, dynamic type, and full strict TypeScript coverage.

---

## Prerequisites

| Tool | Version |
|------|---------|
| Node.js | ≥ 20 |
| React Native CLI | 0.73.4 |
| Xcode | ≥ 15 (iOS) |
| Android Studio | ≥ Iguana (Android) |
| Ruby | ≥ 3.0 (iOS CocoaPods) |
| Java | JDK 17+ (Android) |

### System libraries

**macOS (iOS):**
```bash
brew install cocoapods
```

**libzbar (not required)** — QR decoding is handled on-device by the OS (MLKit on Android, AVFoundation on iOS) via VisionCamera v4's native `useCodeScanner`. No additional system libraries needed.

---

## Quick Start

```bash
# Install JS dependencies
cd mobile
npm install

# iOS
cd ios && pod install && cd ..
npx react-native run-ios

# Android
npx react-native run-android
```

---

## Usage Flow

```
┌─────────────────────────────────────────────────────────┐
│  Desktop (web demo or CLI encoder)                      │
│  Opens wasm_browser_example.html — choose a mode:      │
│    Standard / FS / Schrödinger / Hybrid-PQ / Duress     │
│  → Displays QR code (static or animated GIF) on screen  │
└────────────────────┬────────────────────────────────────┘
                     │ Camera (optical, air-gapped)
                     ▼
┌─────────────────────────────────────────────────────────┐
│  MeowCapture (this app)                                 │
│  1. Home  — load capture request JSON (session params)  │
│  2. Camera — aim at screen, app scans QR frames         │
│     • Single QR: immediately captured & complete        │
│     • Fountain GIF: scan until progress bar fills       │
│  3. Export — save captured_frames.json to Downloads     │
└────────────────────┬────────────────────────────────────┘
                     │ USB/ADB transfer or manual copy
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Desktop (meow-decoder or web demo decrypt tab)         │
│  $ meow-decode-gif -i captured_frames.json -p "pass"   │
└─────────────────────────────────────────────────────────┘
```

### Step-by-step

1. **Open the web demo** on the desktop (`examples/wasm_browser_example.html` or
   `web_demo/wasm_browser_example_FULL.html`). Choose any encryption mode:
   Standard, Forward Secrecy, Schrödinger, Post-Quantum, or Duress.

2. **Encrypt** a file or message in the demo. For multi-frame (animated QR),
   the payload is too large for one code and will be fountain-coded automatically.
   For single-frame, a static QR appears.

3. **Generate a capture request** (or enter manually in the app):
   - Multi-frame: set `expected_frames` to the droplet count shown in the demo log.
   - Single-frame: set `expected_frames: 1`.
   ```bash
   # CLI alternative
   meow-encode --print-request -i file.pdf
   ```

4. **Load the request** in the app — tap "Load JSON File" on the Home screen, or
   enter the session UUID and frame count manually.

5. **Point your camera** at the QR on screen:
   - **Single-frame modes**: app captures the QR and immediately completes.
   - **Fountain animated GIF**: hold steady until the progress bar reaches 100%.

6. **Confirm & Export** — tap **Confirm & Export** on the Export screen.
   If Face ID / fingerprint is enrolled, biometric confirmation is required before
   any data is written to disk. Transfer `meow_capture_<session_id>.json`
   back to the desktop via USB.

7. **Decrypt** — paste the captured JSON into the web demo's decrypt tab, or use the CLI:
   ```bash
   meow-decode-gif -i meow_capture_<session_id>.json -p "password"
   ```

---

## Supported QR Modes

The app recognises every QR format produced by the web demo (`wasm_browser_example.html`,
`wasm_browser_example_FULL.html`) and the Python CLI encoder.

### Multi-frame (fountain coded — animated GIF)

| Format | Prefix | Source | Notes |
|--------|--------|--------|-------|
| Fountain | `FOUNTAIN:<k>:<block_size>:<length>:<b64>` | Web demo animated QR / CLI | Each frame is a fountain droplet. Capture any ~67% of frames to decode. App auto-completes at `ceil(expected_frames × 1.5)`. |

### Single-frame (static QR — scan once)

| Format | Prefix | Web Demo Mode | Notes |
|--------|--------|---------------|-------|
| Standard | `MEOW:<b64>` | Standard / Normal | AES-256-GCM password encryption. |
| Forward Secrecy | `FS:<b64>` | Forward Secrecy | X25519 ephemeral key exchange (MEOW3). |
| Schrödinger | `QUANTUM:<b64>` | Schrödinger | Dual-secret plausible deniability. |
| Post-Quantum Hybrid | `HYBRID-PQ:<b64>` | Post-Quantum | ML-KEM-768/1024 + X25519 (MEOW5/MEOW4). |
| Duress | `DURESS:<b64>` | Duress | Panic-password aware; reveals decoy on wrong key. |

### Legacy chunked (web demo older animated format)

| Format | Prefix | Notes |
|--------|--------|-------|
| MEOW chunks | `MEOW-N/total:<b64>` | Split MEOW: payload across N QR frames. Index = N-1. |

### CLI bridge (JSON envelope)

| Format | Shape | Notes |
|--------|-------|-------|
| JSON | `{"index": N, "data": "<b64>", "session_id"?: "..."}` | Used by `meow-encode --mobile-bridge`. |

**Behaviour by format type:**

- **Single-frame** (`MEOW:`, `FS:`, `QUANTUM:`, `HYBRID-PQ:`, `DURESS:`): capture session
  auto-starts and auto-completes on the first valid scan. Set `expected_frames: 1`
  in the capture request.
- **Fountain / multi-frame**: camera stays active until fountain threshold is met
  (`captured >= ceil(expected_frames × 1.5)`).
- **Unknown prefixes** (e.g. arbitrary QR codes in the environment) are silently
  ignored — only meow-format strings trigger the capture state machine.

---

## Capture Request JSON Format

The app validates all incoming requests with Zod strict schema. Extra fields are rejected.

```json
{
  "action": "capture",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "expected_frames": 45,
  "timeout_seconds": 120
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `action` | `"capture"` | ✓ | Must be exactly `"capture"` |
| `session_id` | UUID v4 | ✓ | Validated as UUID regex |
| `expected_frames` | integer | ✓ | 1 for single-frame modes; fountain frame count for multi-frame |
| `timeout_seconds` | integer | — | 1–600, defaults to 60 |

---

## Output JSON Format

```json
{
  "schema_version": "1",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "captured_at": "2024-01-15T10:30:00.000Z",
  "elapsed_ms": 45230,
  "total_frames": 47,
  "frames": [
    { "index": 0, "data": "FOUNTAIN:10:800:4523:AAB...", "timestamp_ms": 1705312200123 },
    { "index": 1, "data": "FOUNTAIN:10:800:4523:CCF...", "timestamp_ms": 1705312200223 }
  ]
}
```

The `data` field contains the raw QR string **including its format prefix**:

| Capture mode | Example `data` value |
|-------------|----------------------|
| Fountain multi-frame | `FOUNTAIN:10:800:4523:AABg...` |
| Standard | `MEOW:AABg...` |
| Forward Secrecy | `FS:AABg...` |
| Schrödinger | `QUANTUM:AABg...` |
| Post-Quantum | `HYBRID-PQ:AABg...` |
| Duress | `DURESS:AABg...` |
| Legacy chunked | `MEOW-1/5:AABg...` |
| CLI bridge | `{"index":0,"data":"..."}` (stored as-is) |

The desktop decoder identifies the encryption mode from the prefix and dispatches accordingly.

---

## Permissions

| Permission | Platform | Why |
|-----------|----------|-----|
| `CAMERA` | Android + iOS | Scan QR codes from screen — no images ever stored or transmitted |
| `WRITE_EXTERNAL_STORAGE` | Android ≤ 9 | Write export JSON to Downloads folder |
| `VIBRATE` | Android | Haptic feedback: progress ticks, milestone pops, export outcome |
| `USE_BIOMETRIC` + `USE_FINGERPRINT` | Android | Biometric export gate (falls back gracefully if not enrolled) |

**Explicitly not requested:** `INTERNET`, `RECORD_AUDIO`, `ACCESS_FINE_LOCATION`, `READ_CONTACTS`, `READ_EXTERNAL_STORAGE`, `BLUETOOTH`, or any permission not in the table above.

The `INTERNET` permission is deliberately absent from `AndroidManifest.xml` — the OS enforces zero network access at the platform level, not just in application code.

---

## Security Model

| Control | Implementation |
|---------|---------------|
| **Zero network** | No `INTERNET` permission — OS-enforced, not application-level |
| **Screenshot blocking** | `FLAG_SECURE` in `MainActivity.onCreate` — blocks screenshots, screen recording, and task-switcher thumbnail on Android |
| **iOS task-switcher defense** | `isBackgrounding` renders a solid privacy overlay when `applicationWillResignActive` fires, before the OS captures its snapshot |
| **Biometric export gate** | `react-native-biometrics` prompts Face ID / fingerprint / PIN before writing any data to disk |
| **Memory wipe on background** | `AppState` listener dispatches `RESET` (clears all frames from React state) on background or inactive |
| **Foreground recovery** | On returning from background the app navigates to Home — the wiped session cannot be resumed |
| **Panic wipe** | 3-second long-press on Cancel triggers immediate `RESET` + navigation to Home — no confirmation needed |
| **Android back guard** | Hardware back during CAPTURING / AWAITING_GIF / PAUSED triggers a confirmation alert before discarding frames |
| **Clipboard wipe** | Export JSON string is removed from the clipboard 30 s after sharing |
| **Explicit export only** | `ExportScreen` shows a confirmation card; no auto-export on mount |
| **Input validation** | Every capture request validated with Zod `.strict()` schema; extra fields and malformed UUIDs rejected |
| **No decryption on device** | Frame data stored as opaque base64 strings; all crypto operations happen on the desktop |
| **No image retention** | VisionCamera `useCodeScanner` passes only decoded string values to JS — camera frames never reach app memory |
| **`audio={false}`** | Microphone disabled on the `<Camera>` component |

---

## Camera Controls

The capture screen exposes live controls for real-world scanning conditions:

| Control | How to use | Purpose |
|---------|-----------|---------|
| **Pinch to zoom** | Standard two-finger pinch | Move further from screen; range 1× – 6× (capped to preserve decode quality) |
| **Exposure − / +** | Tap ☀️− or ☀️+ buttons | −2 … +2 in 0.5 steps; reduce glare from bright screens or boost dim displays |
| **Torch** | Tap 💡 button | Illuminates surroundings in low light (hardware torch required) |
| **Pause / Resume** | Tap ⏸ / ▶️ button during CAPTURING | Freeze scanning without losing captured frames; resumes from same state |
| **Stop** | Tap ⏹ button | Finalises early — exports whatever frames have been collected |
| **Panic wipe** | Long-press Cancel for 3 s | Instantly wipes all captured frames and navigates Home — for high-pressure situations |
| **Stability indicator** | Automatic | Accelerometer warns when device motion may cause motion blur |
| **Stall detector** | Automatic | Toasts after 4 s with no new frames — prompts you to adjust camera position |

---

## Development

```bash
# Install JS dependencies
npm install

# Run Jest unit tests (267 tests)
npm test

# TypeScript strict type check (zero errors)
npm run type-check

# Lint (zero warnings)
npm run lint

# Auto-format
npm run format

# iOS — install CocoaPods then launch
npm run pod-install
npx react-native run-ios

# Android
npx react-native run-android
```

### Project structure

```
mobile/
├── src/
│   ├── types/
│   │   ├── capture.ts          # CaptureRequest, CaptureResponse, CapturedFrame, ExportResult
│   │   ├── navigation.ts       # Typed screen props for React Navigation
│   │   └── declarations.d.ts   # Ambient module types (react-native-biometrics)
│   ├── constants/
│   │   ├── config.ts           # FOUNTAIN_OVERHEAD, milestone thresholds, FPS, dedup timing
│   │   └── theme.ts            # Palette, PixelRatio-scaled typography, spacing, shadows
│   ├── utils/                  # base64 validation, formatters (pure, fully tested)
│   ├── services/
│   │   ├── requestValidator.ts # Zod .strict() schema + safeValidateRequest
│   │   ├── qrDecoder.ts        # Prefix-based format detection, payload parsing
│   │   ├── frameCollector.ts   # Dedup, fountain threshold tracking
│   │   └── jsonExporter.ts     # RNFS write, chunked export, QR fallback chunks
│   ├── hooks/
│   │   ├── useCapture.ts           # useReducer state machine (IDLE→AWAITING_GIF→CAPTURING→PAUSED→COMPLETE)
│   │   ├── useQRScanner.ts         # VisionCamera v4 useCodeScanner (MLKit / AVFoundation); adaptive FPS
│   │   ├── useStabilityMonitor.ts  # Accelerometer-based shake detection
│   │   ├── useStallDetector.ts     # Detects 4 s+ periods with no new frames; fires toast callback
│   │   ├── useSessionManager.ts    # Orchestrates capture + scanner + stability
│   │   └── useSecureScreen.ts      # isBackgrounding flag for iOS privacy overlay
│   ├── components/
│   │   ├── CameraPreview.tsx       # AnimatedCamera, pinch zoom, exposure bias, torch, privacy overlay
│   │   ├── ProgressHUD.tsx         # SVG arc ring with fountain-threshold indicator
│   │   ├── FrameOverlay.tsx        # Scan corners, status badges (AWAITING/CAPTURING/PAUSED/COMPLETE), reduce-motion-aware scan line
│   │   ├── StabilityIndicator.tsx  # Shake magnitude bar
│   │   └── CatToast.tsx            # Queued slide-up toasts with accessibilityLiveRegion
│   ├── screens/
│   │   ├── SplashScreen.tsx        # Cat-eye animation; respects Reduce Motion system preference
│   │   ├── OnboardingScreen.tsx    # First-run camera permission with Settings recovery on denial
│   │   ├── HomeScreen.tsx          # Load capture request (file picker or manual entry); KeyboardAvoidingView
│   │   ├── CaptureScreen.tsx       # Live camera, haptics, pause/resume, panic wipe, Android back guard
│   │   └── ExportScreen.tsx        # Biometric-gated confirm → JSON export or QR fallback
│   ├── navigation/
│   │   └── AppNavigator.tsx        # NativeStack; gesture disabled on CaptureScreen
│   └── App.tsx                     # GestureHandlerRootView, MeowDarkTheme, CatToastProvider
├── __tests__/              # Jest unit tests — pure logic, no render tests
├── __mocks__/              # Native module mocks (VisionCamera, biometrics, RNFS, MMKV, sensors)
├── android/
│   └── app/src/main/
│       ├── AndroidManifest.xml       # CAMERA + VIBRATE + USE_BIOMETRIC; NO INTERNET
│       └── java/…/MainActivity.kt   # FLAG_SECURE in onCreate
└── ios/                    # NSCameraUsageDescription only in Info.plist
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Blank camera preview | Permission denied | Settings → Apps → MeowCapture → Permissions → Camera |
| "Open Settings" button shown on Onboarding | Camera permission denied at OS level | Tap it — leads directly to the app's permission page |
| Frames not incrementing | Camera too far | Move 20–40 cm from screen |
| Low frame count warning | Motion blur | Use stability indicator; hold phone still |
| "No new frames" toast | Stall detected | Shift camera position slightly or adjust exposure |
| App completes instantly (0 frames shown) | expected_frames=0 in request JSON | Set expected_frames to the frame count from the demo log |
| Single-frame mode never auto-completes | expected_frames > 1 | Set expected_frames: 1 for static MEOW:/FS:/etc. QR codes |
| Export silently fails | Downloads folder full | Free storage and retry |
| Timeout before completion | GIF too fast / poor lighting | Increase `timeout_seconds`; use ☀️− / ☀️+ to compensate for glare |
| "Invalid request" error | Extra fields in request JSON | Remove unrecognised fields; see schema above |
| Non-meow QR silently ignored | Unknown prefix in environment | App only collects meow-prefixed codes; others are dropped |
| Biometric prompt never shows | No biometric enrolled on device | Falls back to unguarded export button automatically |
| Export button not visible | Still on confirm card | Tap **Confirm & Export** (or **Export to Downloads** if no biometrics) |
| Glare making QR unreadable | Bright laptop screen | Tap ☀️− to reduce exposure bias; tilt phone slightly off-axis |
| Android back button dismisses capture | Expected — guarded | A confirmation dialog appears before frames are discarded |

### ADB extract (Android)

If the picker doesn't show the file, pull it directly:

```bash
adb pull /sdcard/Download/meow_capture_<session_id>.json ./
```

---

## Fountain Code Tolerance

Applies to **multi-frame fountain coded QRs** (`FOUNTAIN:` prefix) only.
Single-frame modes (`MEOW:`, `FS:`, `QUANTUM:`, `HYBRID-PQ:`, `DURESS:`) complete in one scan.

For fountain-coded animated GIFs, the app uses a 1.5× redundancy factor.
Capture completes automatically when:

```
captured_frames ≥ ceil(expected_frames × 1.5)
```

This means you can expect successful decryption even with ~33% frame loss due to:
- Camera motion blur during scanning
- Screen refresh timing mismatches
- QR scan failures on low-contrast frames

---

---

## Key Dependencies

| Package | Version | Role |
|---------|---------|------|
| `react-native-vision-camera` | ^4.0.0 | Native QR scanning via `useCodeScanner` (MLKit / AVFoundation) |
| `react-native-biometrics` | ^3.0.1 | Biometric export gate (Face ID, fingerprint, device PIN fallback) |
| `react-native-reanimated` | ^3.6.2 | UI-thread pinch zoom via `useAnimatedProps` |
| `react-native-gesture-handler` | ^2.14.1 | `Gesture.Pinch()` for zoom, swipe-back guard on CaptureScreen |
| `react-native-haptic-feedback` | ^2.2.0 | Progress ticks, milestone pops, export success/error |
| `react-native-sensors` | ^7.3.6 | Accelerometer for stability monitor |
| `react-native-mmkv` | ^2.12.2 | Synchronous first-launch flag (settings only — never frame data) |
| `react-native-fs` | ^2.20.0 | Write export JSON to Downloads folder |
| `zod` | ^3.22.4 | Strict capture-request schema validation |

**Removed in v2:** `vision-camera-code-scanner` (abandoned, used a fragile worklet `require()` hack, broken on Android 14+ / iOS 17+) and `react-native-worklets-core` (no longer needed for QR scanning).

**Added in v3:** `@react-navigation/native` deep-link support (universal links `meow://capture?…`). No new runtime dependencies — v3 features are built from existing packages (`react-native-reanimated` SVG arc, `react-native-haptic-feedback`, built-in `BackHandler`/`Linking` APIs).

---

## License

MIT — see [../LICENSE](../LICENSE)
