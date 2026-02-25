# 📱 Mobile App Architecture

> **Principle:** The phone is a **dumb scanner** — it captures QR frames and
> exports them as JSON for USB/ADB retrieval.  **Zero crypto runs on the
> device.**

---

## Current Mode: Local JSON Export (v3.2)

The mobile app's primary (and currently only active) workflow is fully offline
JSON export. No network, no bridge server, no WebSocket.

```
┌──────────────┐        USB / ADB pull           ┌──────────────────┐
│  Mobile App  │  ──────────────────────────────► │  Desktop CLI     │
│  (React      │  meow-capture-*.json (Downloads) │  (Python)        │
│   Native)    │                                   │                  │
│              │                                   │  → decode_gif()  │
└──────┬───────┘                                   └────────┬─────────┘
       │                                                    │
   Camera +                                           Fountain decode
   QR scan                                            + AES-256-GCM
   (on device)                                        (on workstation)
```

### Local Export Data Flow

1. **Phone** opens camera → detects animated GIF displayed on air-gapped screen.
2. Each frame is decoded to raw QR bytes on-device (using `react-native-vision-camera`).
3. Frames are collected in memory by `useCapture` (indices + base64 payloads).
4. User taps **Export** → biometric gate (if available) → JSON written to Downloads.
5. User retrieves file via **USB/ADB** (`adb pull`) or **iOS Files/AirDrop**.
6. Desktop CLI reassembles fountain-coded stream → decrypt → verify.

### Fallback: QR Reverse-Optical Export

If USB is unavailable, ExportScreen can display the captured JSON as a series
of QR codes for the desktop to scan back (reverse optical transfer).

### Security Boundaries (Local Mode)

| Boundary | Trust | Notes |
|----------|-------|-------|
| Phone ↔ air-gapped screen | Optical | Camera captures QR codes off screen |
| Phone → Desktop (USB) | Physical transfer | JSON file, no live connection |
| Phone storage | Untrusted | Phone never sees plaintext, keys, or passwords |
| Clipboard | Time-limited | ADB commands auto-wiped after 45 s |

**Key invariant:** The phone *never* receives the password, derived key, or
plaintext.  If the phone is compromised, the attacker gains only the same
ciphertext visible on the air-gapped screen.

---

## Future Mode: WebSocket Bridge (Optional / Advanced)

> **Status:** Not implemented in the mobile app. Bridge server and protocol are
> designed but not wired. See `bridge/` for reference implementations.
> **The local JSON export flow above is the primary and only active mode.**
> All release UI entry points use the JSON export path.
> The bridge mode is documented here for future development reference only.

For real-time streaming without USB, a future mode will support a local
WebSocket bridge between the phone and a workstation on the same LAN or USB.

```
┌──────────────┐          JSON / WebSocket           ┌──────────────────┐
│  Mobile App  │  ──────────────────────────────────► │  meow-bridge CLI │
│  (React      │  { frame_index, qr_bytes_b64, … }   │  (Python)        │
│   Native)    │ ◄────────────────────────────────── │                  │
│              │  { status, progress, … }             │  → decode_gif()  │
└──────┬───────┘                                      └────────┬─────────┘
       │                                                       │
   Camera +                                              Fountain decode
   QR scan                                               + AES-256-GCM
   (on device)                                           (on workstation)
```

### Wire Protocol (JSON-over-WebSocket)

All messages are UTF-8 JSON, one message per WebSocket frame.

#### `scan_start`
Sent once when the user begins scanning.

```json
{
  "type": "scan_start",
  "device_id": "iPhone-15-Pro",
  "timestamp_ms": 1706745600000
}
```

#### `frame`
Sent for each QR code frame captured by the camera.

```json
{
  "type": "frame",
  "seq": 0,
  "qr_bytes_b64": "<base64-encoded raw QR payload>",
  "timestamp_ms": 1706745600100
}
```

| Field | Type | Description |
|-------|------|-------------|
| `seq` | int | Monotonically increasing sequence number (phone-side counter) |
| `qr_bytes_b64` | string | Base64-encoded raw bytes from the QR code |
| `timestamp_ms` | int | Unix epoch milliseconds when the frame was captured |

#### `scan_end`
Sent when the user stops scanning (or all frames received).

```json
{
  "type": "scan_end",
  "total_frames_sent": 42,
  "timestamp_ms": 1706745602000
}
```

#### CLI → Phone Messages

##### `ack`
Sent after each `frame` is received and validated.

```json
{
  "type": "ack",
  "seq": 0,
  "accepted": true,
  "reason": ""
}
```

##### `progress`
Sent periodically during decoding to update the phone UI.

```json
{
  "type": "progress",
  "frames_received": 35,
  "frames_needed": 42,
  "blocks_decoded": 20,
  "blocks_total": 28,
  "percent": 71.4
}
```

##### `result`
Sent when decoding completes or fails.

```json
{
  "type": "result",
  "success": true,
  "output_file": "secret.pdf",
  "output_size": 102400,
  "elapsed_s": 3.2,
  "error": null
}
```

##### `error`
Sent on fatal errors.

```json
{
  "type": "error",
  "code": "HMAC_FAIL",
  "message": "Wrong password or corrupted data"
}
```

#### Error Codes

| Code | Meaning |
|------|---------|
| `HMAC_FAIL` | HMAC verification failed (wrong password) |
| `DECODE_INCOMPLETE` | Not enough frames received |
| `QR_CORRUPT` | QR payload could not be parsed |
| `MANIFEST_INVALID` | First frame (manifest) failed validation |
| `INTERNAL` | Unexpected server error |

---

### CLI Bridge Server (`meow-bridge`)

#### Usage

```bash
# Start bridge server (waits for phone connection)
meow-bridge --output secret.pdf --password "hunter2" --port 9999

# With verbose + tamper report
meow-bridge --output secret.pdf -p "hunter2" --verbose --tamper-report
```

#### Implementation Notes

The bridge server is intentionally minimal:

1. Opens a WebSocket server on `localhost:<port>`.
2. Accepts `frame` messages →  collects raw QR bytes in memory.
3. On `scan_end` (or sufficient frames), assembles the byte stream as if
   reading from a GIF and passes to `decode_gif()` internals (manifest
   parsing → fountain decode → decrypt).
4. Streams `progress` and `result` back to the phone.

The server does **not** persist frames to disk (to minimize attack surface).

---

### React Native Scanner Component (Bridge Mode)

#### Dependencies

```json
{
  "react-native-vision-camera": "^4.0.0",
  "react-native-worklets-core": "^1.0.0"
}
```

#### Minimal Component API

```tsx
<MeowScanner
  bridgeUrl="ws://192.168.1.42:9999"
  onProgress={(p) => setProgress(p.percent)}
  onResult={(r) => Alert.alert(r.success ? "Done!" : "Failed", r.message)}
  onError={(e) => Alert.alert("Error", e.message)}
/>
```

#### Component Responsibilities

1. Request camera permission
2. Open camera with QR code detection enabled
3. On each QR detection, base64-encode the raw bytes and send as `frame`
4. De-duplicate frames (skip if same bytes as previous frame)
5. Display progress from `progress` messages
6. Show result when `result` message arrives

#### What the Component Does NOT Do

- **No crypto** — no key derivation, no decryption
- **No password handling** — password is entered on the CLI side
- **No file storage** — raw bytes are forwarded, not saved
- **No internet access** — only local WebSocket to CLI

---

### Transport Options (Bridge Mode)

#### Option A: Wi-Fi (Default)

Phone and workstation on same LAN. Phone connects to
`ws://<workstation-ip>:9999`.

**Pros:** Wireless, easy setup.
**Cons:** Requires same network; mDNS/Bonjour can simplify discovery.

#### Option B: USB (Higher Security)

Use ADB (Android) or a Lightning relay (iOS) to forward a local port:

```bash
# Android
adb forward tcp:9999 tcp:9999

# iOS (via libimobiledevice)
iproxy 9999 9999
```

Phone connects to `ws://localhost:9999` (which is forwarded to the
workstation).

**Pros:** No network exposure. Better for high-security use.
**Cons:** Requires cable + tooling.

---

## React Native App Component Tree (v3.2)

```
AppNavigator (native-stack)
├── SplashScreen
├── OnboardingScreen
├── HomeScreen
│   ├── CalibrationWizard        ← 5-step preflight (permissions, QR test, light, brightness, thermal)
│   ├── DiagnosticsPanel         ← hidden long-press panel (JS lag, heap, FPS, thermal heuristic, safe-to-share export)
│   ├── RequestQR modal          ← Camera + useCodeScanner to scan request from sender screen
│   └── [video import button]    ← useVideoImport (feature-flagged OFF — hidden from release UI)
├── CaptureScreen
│   ├── CameraPreview            ← pinch zoom, exposure nudge, shake detection
│   ├── CatWhiskerHUD            ← animated progress ring (Reanimated 3)
│   ├── ProgressHUD              ← confidence label, safeToStop pill, decode-rate row
│   └── CaptureCoachPanel        ← live coaching hints (shake / light / decode rate)
├── ExportScreen                 ← biometric gate, SHA-256 verify, ADB + filename copy
└── SettingsScreen               ← Strict / Convenience security mode toggle (MMKV-backed)
```

### Key hooks (v3.2)

| Hook | Purpose |
|------|---------|
| `useQRScanner` | ML-Kit/AVFoundation code scanner + decode-rate / duplicate-rate ring buffers |
| `useSessionManager` | Fountain-decode state machine; exposes `decodeRate`, `duplicateRate` |
| `useCapture` | `useReducer`-based capture state + MMKV checkpoint (indices only) |
| `useSecurityMode` | MMKV-backed strict/convenience toggle |
| `useVideoImport` | TurboModule bridge stub for local video frame extraction (feature-flagged OFF in release) |

### New components in v3.2

| Component | File | Description |
|-----------|------|-------------|
| `CaptureCoachPanel` | `components/CaptureCoachPanel.tsx` | Priority-ranked live hints derived from decode rate, duplicate rate, shake, exposure |
| `CalibrationWizard` | `components/CalibrationWizard.tsx` | Modal preflight checklist with live QR scan test |
| `DiagnosticsPanel` | `components/DiagnosticsPanel.tsx` | Hidden long-press overlay: JS lag via rAF, heap, thermal, FPS |
| `SettingsScreen` | `screens/SettingsScreen.tsx` | Strict vs Convenience security mode with full implications table |

---

```
mobile/
├── ARCHITECTURE.md          ← this file
├── README.md                ← platform stubs overview
├── bridge/
│   ├── protocol.py          ← wire protocol message classes
│   └── server.py            ← WebSocket bridge server (future)
├── react-native/
│   ├── MeowScanner.tsx      ← scanner component (reference impl)
│   └── useBridge.ts         ← WebSocket hook
├── android/
│   └── MeowCrypto.kt        ← native crypto stubs
└── ios/
    └── MeowCrypto.swift      ← native crypto stubs
```

---

## Security Checklist for Mobile Bridge

- [ ] Phone never receives password or derived key
- [ ] WebSocket binds to `localhost` by default (no remote access)
- [ ] USB transport preferred for high-security scenarios
- [ ] No QR frame data persisted on phone
- [ ] Bridge server validates frame sizes (max 4 KiB per QR payload)
- [ ] Rate limiting: max 100 frames/second to prevent DoS
- [ ] TLS optional for LAN (`wss://`) but not required for localhost

---

## Future Work

1. **mDNS/Bonjour discovery** — phone auto-discovers CLI on LAN
2. **Bidirectional mode** — encode on workstation, phone displays QR for
   another air-gapped device
3. **Multi-device fan-out** — multiple phones scan different portions
   (clowder mode)
4. **Flutter / native alternatives** — port scanner to non-RN frameworks

---

## React Native New Architecture Readiness (Fabric + TurboModules)

### Current State (RN 0.73.4, Old Architecture)

The app currently uses the **Old Architecture** (Paper renderer + Bridge modules).
Migration to the New Architecture (`newArchEnabled=true`) is tracked below.

### How to Enable

**Android** — `android/gradle.properties`:
```properties
newArchEnabled=true
```

**iOS** — `ios/Podfile` post-install:
```ruby
:fabric_enabled => true
```

### Dependency Compatibility Matrix

| Dependency | New Arch Ready | Notes |
|------------|:--------------:|-------|
| `react-native-vision-camera` v4 | ✅ | Native Fabric renderer since v3 |
| `react-native-reanimated` v3 | ✅ | Full TurboModule + Fabric support |
| `react-native-gesture-handler` v2 | ✅ | Fabric-aware since 2.12 |
| `react-native-mmkv` | ✅ | Pure JSI, no Bridge dependency |
| `react-native-biometrics` | ⚠️ | Works but not yet a TurboModule — Bridge interop layer handles it |
| `react-native-haptic-feedback` | ⚠️ | Bridge interop; consider `expo-haptics` TurboModule alternative |
| `react-native-sensors` | ❌ | **Not New Arch compatible** — needs replacement with `expo-sensors` or a custom TurboModule |
| `react-native-sound` | ⚠️ | Bridge interop; consider `expo-av` TurboModule alternative |
| `react-native-svg` | ✅ | Fabric support since 15.0 |
| `react-native-document-picker` | ⚠️ | Bridge interop — works under compatibility layer |
| `react-native-fs` | ⚠️ | Bridge interop — consider `expo-file-system` for native TurboModule |
| `react-native-safe-area-context` | ✅ | Full Fabric support |

### Migration Steps

1. **Enable `newArchEnabled=true`** in Android gradle.properties
2. **Test all screens** — Paper→Fabric renderer change can cause layout shifts
3. **Replace `react-native-sensors`** — highest-priority blocker:
   - Option A: `expo-sensors` (TurboModule, drop-in replacement)
   - Option B: Custom JSI accelerometer module (minimal surface area)
4. **Verify Bridge interop** — modules marked ⚠️ should work via the interop layer
   but may have minor timing differences
5. **Performance benchmark** — measure camera pipeline latency before/after:
   - Frame decode rate should stay ≥ 15 fps at 30 fps camera
   - Gesture response (pinch zoom) should be < 16ms

### Risk Assessment

- **Low risk**: Vision Camera, Reanimated, Gesture Handler — already Fabric-native
- **Medium risk**: MMKV (JSI adapter change), Biometrics, Sound (interop layer)
- **High risk**: `react-native-sensors` — must be replaced before enabling New Arch
- **Estimated effort**: 2-3 days for a developer familiar with the codebase
