# Meow Capture — React Native Mobile Companion App

Optical air-gap file transfer companion for [meow-decoder](../README.md). Scans animated QR code GIFs from any screen using your phone camera and exports the captured frame data as a structured JSON file for desktop decryption.

**No network. No cloud. No traces.**

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

6. **Export** — tap "Save to Downloads". Transfer `meow_capture_<session_id>.json`
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
| `CAMERA` | Android + iOS | Scan QR codes — no images stored |
| `WRITE_EXTERNAL_STORAGE` | Android ≤ 9 | Write JSON to Downloads folder |
| `VIBRATE` | Android | Haptic feedback on milestones |

**Not requested:** INTERNET, RECORD_AUDIO, ACCESS_FINE_LOCATION, READ_CONTACTS, or any permission not listed above.

---

## Security Model

- **Air-gap preserved**: No `INTERNET` permission — platform enforces no network calls.
- **No persistence**: Frame data lives in React state only. Cleared immediately on app backgrounding.
- **Camera only**: AppState listener wipes all captured frames if app moves to background.
- **Explicit export only**: Data reaches disk only when user taps "Save to Downloads".
- **Input validation**: Every capture request validated through Zod strict schema before use.
- **No decoding on device**: Base64 frame data is stored as opaque strings; decryption happens on the desktop.

---

## Development

```bash
# Run Jest unit tests
npm test

# TypeScript type check
npm run typecheck

# Lint
npm run lint

# Format
npm run format
```

### Project structure

```
mobile/
├── src/
│   ├── types/          # CaptureRequest, CaptureResponse, etc.
│   ├── constants/      # FOUNTAIN_OVERHEAD, theme, config values
│   ├── utils/          # base64 validation, formatters (pure functions)
│   ├── services/       # requestValidator, qrDecoder, frameCollector, jsonExporter
│   ├── hooks/          # useCapture, useQRScanner, useStabilityMonitor, useSessionManager
│   ├── components/     # CameraPreview, ProgressHUD, FrameOverlay, CatToast, StabilityIndicator
│   ├── screens/        # SplashScreen, OnboardingScreen, HomeScreen, CaptureScreen, ExportScreen
│   ├── navigation/     # AppNavigator (NativeStack)
│   └── App.tsx         # Root component
├── __tests__/          # Jest unit tests (pure logic only)
├── __mocks__/          # Native module mocks for Jest
├── android/            # Android project (camera-only AndroidManifest.xml)
└── ios/                # iOS project (NSCameraUsageDescription only in Info.plist)
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Blank camera preview | Permission denied | Settings → Apps → MeowCapture → Permissions → Camera |
| Frames not incrementing | Camera too far | Move 20–40 cm from screen |
| Low frame count warning | Motion blur | Use stability indicator; hold phone still |
| App completes instantly (0 frames shown) | expected_frames=0 in request JSON | Set expected_frames to the frame count from the demo log |
| Single-frame mode never auto-completes | expected_frames > 1 | Set expected_frames: 1 for static MEOW:/FS:/etc. QR codes |
| Export silently fails | Downloads folder full | Free storage and retry |
| Timeout before completion | GIF too fast / poor lighting | Increase `timeout_seconds` in request JSON |
| "Invalid request" error | Extra fields in JSON | Remove unrecognised fields; see schema above |
| "Unknown QR format" (not shown, silently skipped) | Non-meow QR in environment | App only collects meow-prefixed QR codes; others are discarded |

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

## Legacy Native Bridge

The `react-native/` subdirectory contains the original WebSocket-based prototype
(`MeowScanner.tsx`, `useBridge.ts`). It is superseded by this full implementation
but kept for reference.

---

## License

MIT — see [../LICENSE](../LICENSE)

---

## Current Status

The React Native bridge is production-ready with:
1. Full JSON wire protocol for phone→CLI scanning
2. WebSocket and stdin/file transport modes
3. CLI integration via `--mobile-bridge` flag

## Platform Support

### iOS (Swift)

**Location:** `ios/MeowDecoder/`

**Requirements:**
- Xcode 15+
- iOS 16+ deployment target
- Swift 5.9+

**Integration approach:**
1. Build crypto_core as xcframework via cargo-lipo
2. Swift wrapper via C-FFI bindings
3. SwiftUI demo app

**Build (future):**
```bash
# Install iOS targets
rustup target add aarch64-apple-ios x86_64-apple-ios

# Build universal binary
cargo lipo --release --features pure-crypto

# Generate Swift bindings
cbindgen --lang c --output MeowCrypto.h
```

### Android (Kotlin)

**Location:** `android/meowdecoder/`

**Requirements:**
- Android Studio Hedgehog+
- Android NDK r25+
- Kotlin 1.9+

**Integration approach:**
1. Build crypto_core as .so via cargo-ndk
2. JNI bindings via jni-rs
3. Jetpack Compose demo app

**Build (future):**
```bash
# Install Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi

# Build with NDK
cargo ndk -t armeabi-v7a -t arm64-v8a -o android/jniLibs build --release
```

## API Stubs

Both platforms expose the same API surface:

```
MeowCrypto
├── deriveKey(password: String, salt: Data) -> Data
├── encrypt(plaintext: Data, key: Data, nonce: Data) -> Data
├── decrypt(ciphertext: Data, key: Data, nonce: Data) -> Data
├── generateNonce() -> Data
├── generateSalt() -> Data
├── hmacSha256(key: Data, message: Data) -> Data
└── constantTimeEqual(a: Data, b: Data) -> Bool
```

## Security Considerations

### iOS
- Use Keychain for key storage
- Enable Data Protection
- Use Secure Enclave for biometric unlock
- Never log sensitive data

### Android
- Use EncryptedSharedPreferences or Keystore
- Enable android:extractNativeLibs="false"
- Use StrongBox if available
- Follow MASVS guidelines

## Testing

Mobile unit tests should verify:
1. Key derivation produces consistent results
2. Encrypt/decrypt roundtrip works
3. Wrong password fails gracefully
4. Memory is zeroed after operations

## Roadmap

1. ~~**Phase 1:** Swift/Kotlin stubs~~ ✅
2. ~~**Phase 2:** Rust-to-native FFI bindings~~ ✅
3. ~~**Phase 3:** Platform-specific key storage~~ ✅
4. ~~**Phase 4:** QR scanner integration~~ ✅ (React Native bridge)
5. ~~**Phase 5:** Full encode/decode flow~~ ✅
6. **Phase 6:** App Store / Play Store release (planned)

## Contributing

Mobile development help wanted! See CONTRIBUTING.md for guidelines.

Key areas:
- Swift package for iOS
- Kotlin multiplatform for Android
- React Native / Flutter wrappers
- Secure enclave integration
