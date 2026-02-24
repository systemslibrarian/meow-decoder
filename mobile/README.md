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
│  Desktop (meow-encoder)                                 │
│  $ meow-encode -i secret.pdf -o secret.gif -p "pass"   │
│  → Displays animated QR GIF on screen                   │
└────────────────────┬────────────────────────────────────┘
                     │ Camera (optical, air-gapped)
                     ▼
┌─────────────────────────────────────────────────────────┐
│  MeowCapture (this app)                                 │
│  1. Home  — load capture request JSON (session params)  │
│  2. Camera — aim at screen, app scans QR frames         │
│  3. Export — save captured_frames.json to Downloads     │
└────────────────────┬────────────────────────────────────┘
                     │ USB/ADB transfer or manual copy
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Desktop (meow-decoder)                                 │
│  $ meow-decode-gif -i captured_frames.json -p "pass"   │
└─────────────────────────────────────────────────────────┘
```

### Step-by-step

1. **Generate a capture request** on the desktop:
   ```bash
   meow-encode --print-request -i file.pdf
   # Outputs capture_request.json with session_id and expected_frames
   ```

2. **Load the request** in the app — tap "Load JSON File" on the Home screen and select `capture_request.json`, OR enter the session UUID manually.

3. **Point your camera** at the GIF playing on the desktop screen. Keep the phone steady; the stability indicator turns green.

4. **Wait for completion** — the app shows live frame progress. Fountain coding means you don't need every frame; ~67% suffices.

5. **Export** — when capture completes, tap "Save to Downloads". Transfer `meow_capture_<session_id>.json` back to the desktop via USB.

6. **Decrypt** on the desktop:
   ```bash
   meow-decode-gif -i meow_capture_<session_id>.json -p "password"
   ```

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
| `expected_frames` | integer | ✓ | 1–10,000 |
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
| Export silently fails | Downloads folder full | Free storage and retry |
| Timeout before completion | GIF too fast / poor lighting | Increase `timeout_seconds` in request JSON |
| "Invalid request" error | Extra fields in JSON | Remove unrecognized fields; see schema above |

### ADB extract (Android)

If the picker doesn't show the file, pull it directly:

```bash
adb pull /sdcard/Download/meow_capture_<session_id>.json ./
```

---

## Fountain Code Tolerance

The app uses a 1.5× redundancy factor. Capture completes automatically when:

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
