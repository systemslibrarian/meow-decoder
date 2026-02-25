# 📱 Mobile Bridge Architecture

> **Principle:** The phone is a **dumb scanner** — it captures QR frames and
> streams raw bytes to the CLI over a local channel.  **Zero crypto runs on the
> device.**

---

## Overview

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

### Data Flow

1. **Phone** opens camera → detects animated GIF displayed on air-gapped screen.
2. Each frame is decoded to raw QR bytes on-device (using the phone camera's
   built-in QR engine or `react-native-vision-camera`).
3. Raw QR bytes are wrapped in a thin JSON envelope and sent to the
   **meow-bridge** CLI server over:
   - **Wi-Fi** — WebSocket on `ws://localhost:9999` (phone and workstation on
     same LAN), or
   - **USB** — ADB port-forward / Lightning relay piping stdin.
4. The CLI reassembles frames into the fountain-coded stream and runs the
   standard `decode_gif()` pipeline (Argon2id → AES-GCM → decompress →
   verify SHA-256).
5. CLI streams progress / status messages back to the phone for UI feedback.

### Security Boundaries

| Boundary | Trust | Notes |
|----------|-------|-------|
| Phone ↔ air-gapped screen | Optical | Camera captures QR codes off screen |
| Phone ↔ CLI (LAN/USB) | Local transport | No secrets traverse this channel — only raw QR bytes |
| CLI workstation | Trusted | All crypto, key derivation, decryption happen here |
| Phone storage | Untrusted | Phone never sees plaintext, keys, or passwords |

**Key invariant:** The phone *never* receives the password, derived key, or
plaintext.  If the phone is compromised, the attacker gains only the same
ciphertext visible on the air-gapped screen.

---

## Wire Protocol (JSON-over-WebSocket)

All messages are UTF-8 JSON, one message per WebSocket frame.

### Phone → CLI Messages

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

### CLI → Phone Messages

#### `ack`
Sent after each `frame` is received and validated.

```json
{
  "type": "ack",
  "seq": 0,
  "accepted": true,
  "reason": ""
}
```

#### `progress`
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

#### `result`
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

#### `error`
Sent on fatal errors.

```json
{
  "type": "error",
  "code": "HMAC_FAIL",
  "message": "Wrong password or corrupted data"
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| `HMAC_FAIL` | HMAC verification failed (wrong password) |
| `DECODE_INCOMPLETE` | Not enough frames received |
| `QR_CORRUPT` | QR payload could not be parsed |
| `MANIFEST_INVALID` | First frame (manifest) failed validation |
| `INTERNAL` | Unexpected server error |

---

## CLI Bridge Server (`meow-bridge`)

### Usage

```bash
# Start bridge server (waits for phone connection)
meow-bridge --output secret.pdf --password "hunter2" --port 9999

# With verbose + tamper report
meow-bridge --output secret.pdf -p "hunter2" --verbose --tamper-report
```

### Implementation Notes

The bridge server is intentionally minimal:

1. Opens a WebSocket server on `localhost:<port>`.
2. Accepts `frame` messages →  collects raw QR bytes in memory.
3. On `scan_end` (or sufficient frames), assembles the byte stream as if
   reading from a GIF and passes to `decode_gif()` internals (manifest
   parsing → fountain decode → decrypt).
4. Streams `progress` and `result` back to the phone.

The server does **not** persist frames to disk (to minimize attack surface).

---

## React Native Scanner Component

### Dependencies

```json
{
  "react-native-vision-camera": "^4.0.0",
  "react-native-worklets-core": "^1.0.0"
}
```

### Minimal Component API

```tsx
<MeowScanner
  bridgeUrl="ws://192.168.1.42:9999"
  onProgress={(p) => setProgress(p.percent)}
  onResult={(r) => Alert.alert(r.success ? "Done!" : "Failed", r.message)}
  onError={(e) => Alert.alert("Error", e.message)}
/>
```

### Component Responsibilities

1. Request camera permission
2. Open camera with QR code detection enabled
3. On each QR detection, base64-encode the raw bytes and send as `frame`
4. De-duplicate frames (skip if same bytes as previous frame)
5. Display progress from `progress` messages
6. Show result when `result` message arrives

### What the Component Does NOT Do

- **No crypto** — no key derivation, no decryption
- **No password handling** — password is entered on the CLI side
- **No file storage** — raw bytes are forwarded, not saved
- **No internet access** — only local WebSocket to CLI

---

## Transport Options

### Option A: Wi-Fi (Default)

Phone and workstation on same LAN. Phone connects to
`ws://<workstation-ip>:9999`.

**Pros:** Wireless, easy setup.
**Cons:** Requires same network; mDNS/Bonjour can simplify discovery.

### Option B: USB (Higher Security)

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
│   ├── DiagnosticsPanel         ← hidden long-press panel (JS lag, heap, FPS, thermal heuristic)
│   ├── RequestQR modal          ← Camera + useCodeScanner to scan request from sender screen
│   └── [import video button]    ← useVideoImport (TurboModule stub)
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
| `useVideoImport` | TurboModule bridge stub for local video frame extraction |

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
