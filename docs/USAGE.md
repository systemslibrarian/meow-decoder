# 🐾 Usage Guide — Teaching the Cat New Tricks

*Everything you need to encode, transmit, and decode secrets through the air gap. The cat handles the hard parts — you just point the camera.*

## 📱 Meow Capture — Mobile App

The fastest way to scan QR codes from your screen is the **Meow Capture** companion app:

- **Android:** [Download v3.2.2 APK](https://github.com/systemslibrarian/meow-decoder/raw/main/releases/android/meow-decoder-v3.2.2-release.apk) — sideload (allow unknown apps in Settings → Apps → Special app access)
- **iOS:** Coming soon
- **Google Play / App Store:** Both listings coming soon

Install the APK, grant camera permission, and point it at your screen — the app handles QR scanning, fountain decoding, and JSON export entirely on-device with no network access.

---

This project moves data through **animated QR-code GIFs**.

At a high level:

1. **Encode** a file into an animated GIF (each frame is a QR code).
2. **Transmit** that GIF (file transfer) **or** display it on a screen.
3. **Decode** by reading frames back (from the GIF file or a webcam capture) and reconstructing the original bytes.

**🌊 Frame Loss Tolerance:** Multi-frame QR codes (payloads >2500 bytes) use fountain codes (Luby Transform rateless erasure coding) that allow decoding from ANY ~67% of frames. This means you can miss up to 33% of frames during phone camera capture (due to autofocus lag, motion blur, low framerates) and still decode successfully. Works in both Python CLI and JavaScript web demo.

> Tip: If you just want a working end-to-end demo, use Docker:
>
> ```bash
> git clone https://github.com/systemslibrarian/meow-decoder.git
> cd meow-decoder
> docker compose up --build
> ```

---

## 🔐 Encode a file into a QR GIF

*Hiss! Your file gets compressed, encrypted, fountain-coded, and wrapped in QR frames — all in one command.*

### Option A: CLI (recommended)

From the repo root:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements.lock  # Hash-verified dependencies

python -m meow_decoder.encode --input path/to/input.bin --output out.gif
```

You will be prompted for a password (used for encryption).
You can also pass `--password` (⚠️ this may leak in shell history / process list).

### Output

- `out.gif` — the animated QR GIF you can transmit or display.

---

## 🔓 Decode back to the original file

*The cat coughs up the file. (Gracefully.)*

### Option A: Decode from a GIF file

If you have the GIF file itself:

```bash
python -m meow_decoder.decode_gif --input out.gif --output recovered.bin
```

---

## 🌐 Browser-Based Encryption (No Install)

For quick testing or when you can't install Python, use the **WASM Web Demo**:

### Setup

```bash
git clone https://github.com/systemslibrarian/meow-decoder.git
cd meow-decoder

# Build with Post-Quantum support (recommended)
wasm-pack build crypto_core --target web --release --features wasm-pq

# Start server
make meow-build
# Open: http://localhost:8080/examples/wasm_browser_example.html
```

### Available Modes

| Mode | Use Case |
|------|----------|
| 🔐 Standard | Simple password encryption |
| 🔑 Forward Secrecy | Each message uses ephemeral key |
| 🔮 Post-Quantum | Future-proof quantum resistance |
| 🐱 Schrödinger | Two passwords reveal different secrets |
| 📹 Webcam | Scan QR codes from camera (with fountain code frame loss tolerance!) |
| 🚨 Duress | Panic password destroys keys |

### 🌊 Fountain Codes in Web Demo

**NEW:** The webcam scanner now supports multi-frame QR codes with frame loss tolerance!

**How it works:**
1. Large payloads (>2500 bytes) generate animated QR with fountain-encoded droplets
2. Each frame contains a self-contained droplet (not sequential chunks)
3. Webcam scanner collects droplets as they're seen
4. Real-time progress: "Collecting: 8 scanned, 80% decoded (4/5 blocks)"
5. Success when enough droplets collected (typically ~1.2-1.5× minimum needed)

**Benefits:**
- ✅ Works with hand-held phone cameras (motion tolerant)
- ✅ Tolerates autofocus lag and frame drops
- ✅ No "perfect scan" required—just point and wait
- ✅ Visual feedback shows decode progress in real-time

See the fountain coding section in [ARCHITECTURE.md](ARCHITECTURE.md) for technical details.

### Security Level

The web demo lets you choose security strength:

- **Fast** (64 MiB, 3 iter) — Quick demos
- **Standard** (128 MiB, 8 iter) — General use
- **High** (256 MiB, 15 iter) — Sensitive data
- **Paranoid** (512 MiB, 20 iter) — **Matches CLI production defaults** for life-critical data

⚠️ **For maximum security equivalent to the CLI, select "Paranoid" mode.**

---

## 📱 Phone + Webcam Scanning — The Air-Gap Pounce

*The cat leaps across the gap: screen → camera → decoded. No network, no app, no trust required.*

This is the “air-gap-ish” flow: **sender displays the QR GIF on a screen**, receiver captures frames with a camera.

### Sender (computer)

1. Encode your file into `out.gif`.
2. Open `out.gif` in any image viewer **that plays animated GIFs**.
3. Fullscreen it.
4. Keep it looping during capture.

**Practical tips**
- Increase screen brightness.
- Avoid reflections/glare.
- Keep the QR codes large on-screen (don’t let the viewer scale them down too small).

### Receiver (computer with webcam)

Use the webcam capture decoder (best reliability):

```bash
python -m meow_decoder.webcam_enhanced
```

Point the webcam at the sender’s screen and follow the on-screen prompts.
When enough frames are captured, the decoder reconstructs and writes the recovered file.

> If you don’t have a webcam: you can use your phone as a webcam for your computer.
> - iPhone/macOS: **Continuity Camera**
> - Android/Windows/macOS: apps like **DroidCam** or **Camo**
>
> The key idea is: the decoding runs on your computer, but the phone provides the camera feed.

### Receiver (phone only)

Right now, Meow Decoder’s decoding tools are Python-based, so decoding is easiest on a computer.

If you *must* use only a phone, the practical workaround is:
1. Use the phone to **record a video** of the looping GIF on the sender’s screen.
2. Transfer the video to a computer.
3. Extract frames (ffmpeg) and then decode (a helper script can be added if you want this flow fully supported).

If you want, I can add:
- `scripts/video_to_frames.py` (ffmpeg wrapper)
- `scripts/decode_frames.py` (decode from a folder of PNG frames)

---

## 📲 Mobile Capture

### Meow Capture App (Recommended — iOS + Android)

**[Meow Capture](../mobile/README.md)** is a secure offline QR capture companion app for air-gapped file transfer. It handles the entire capture pipeline on-device.

**Workflow:**

1. Run `meow-encode` on the desktop to produce the GIF and a `request.json`:
   ```bash
   meow-encode -i secret.pdf -o secret.gif -p "password" --output-request request.json
   ```
2. Open Meow Capture on the phone → **Load JSON File** (or **Scan Request QR** shown on desktop).
3. Point the camera at the looping GIF. The app tracks fountain-code progress in real time.
4. At ≥1.5× threshold the app shows **✓ Safe to stop**. Tap **Confirm & Export**.
5. Biometric confirmation writes the capture JSON to `Downloads/`.
6. Retrieve via USB:
   ```bash
   adb pull /sdcard/Download/meow-capture-<session_id>.json ./
   meow-decode-gif -i meow-capture-<session_id>.json -p "password"
   ```

**Multi-device merge** — combine two phone captures for maximum coverage:
```bash
python -m meow_decoder.merge \
    --input capture-a.json capture-b.json \
    --output merged.json
meow-decode-gif -i merged.json -p "password"
```

Key security properties:
- No `INTERNET` permission declared (OS-enforced zero network access)
- Frame payload strings wiped from JS memory on any background/inactive transition
- Biometric gate (Face ID / fingerprint) required before export writes to disk
- `FLAG_SECURE` + iOS snapshot overlay blocks screenshots and task-switcher preview
- Panic wipe: 3-second long-press on Capture HUD zeroes all session state

> **Strict vs Convenience mode:** tap ⚙️ in the app → Settings to choose between
> aggressive wipe-on-background (Strict, default) or checkpoint-persist (Convenience).

---

## 📲 Mobile Bridge CLI (Programmatic / Advanced)

*For scripting or CI — streams raw QR payloads from a phone directly to the CLI decoder.*

The mobile bridge connects phone-based QR scanning directly to the CLI decoder over JSON.

### File mode (import from mobile app export)

```bash
# Read frames exported from mobile app
meow-decode-gif --mobile-bridge --input-frames frames.json -o out.pdf -p "password"
```

### WebSocket mode (direct phone connection)

```bash
# Start WebSocket server, phone connects directly
meow-decode-gif --mobile-bridge --bridge-mode websocket --bridge-port 8765 -o out.pdf -p "password"
```

The phone app connects to `ws://<your-ip>:8765` and streams frames in real-time.

### Stdin mode (pipe from adb)

```bash
# Pipe from Android device
adb shell cat /sdcard/meow_frames.json | meow-decode-gif --mobile-bridge -o out.pdf -p "password"
```

### Generate capture request

```bash
# Create a JSON request for the mobile app
meow-decode-gif --mobile-bridge --output-request request.json
```

---

## 🔐 Hardware Keys (HSM, YubiKey, TPM)

*Lock the cat flap with real hardware — keys that never leave the device.*

Hardware security modules provide tamper-resistant key storage.

### YubiKey (PIV)

```bash
# Encode with YubiKey
meow-encode -i secret.pdf -o secret.gif --yubikey --yubikey-slot 9a

# Decode with YubiKey
meow-decode-gif -i secret.gif -o out.pdf --yubikey --yubikey-slot 9a
```

### HSM (PKCS#11)

```bash
# Encode with HSM slot
meow-encode -i secret.pdf -o secret.gif --hsm-slot 0 --hsm-pin 123456

# Decode with HSM
meow-decode-gif -i secret.gif -o out.pdf --hsm-slot 0 --hsm-pin 123456
```

### TPM 2.0

```bash
# Derive key from TPM
meow-encode -i secret.pdf -o secret.gif --tpm-derive

# Unseal with TPM
meow-decode-gif -i secret.gif -o out.pdf --tpm-unseal
```

### Auto-detect hardware

```bash
# Check available hardware
meow-decode-gif --hardware-status

# Auto-select available hardware
meow-encode -i secret.pdf -o secret.gif --hardware-auto
```

---

## 🐱 Cat Mode: Optical Air-Gap File Transfer

Cat Mode enables secure file transfer via animated blinking cat eyes displayed on screen and captured by phone camera. This provides a true air-gapped data channel with visual verification.

### Quick Start

1. **Load the web demo** (`examples/wasm_browser_example.html`)
2. **Switch to Cat Mode** tab
3. **Enter your message** and set blink speed (default 100ms works well)
4. **Click "Start Blinking"** - cat eyes will blink the encoded message
5. **Record with phone camera** (10-15 seconds, include 2-3 extra seconds)
6. **Upload video** in Step 2
7. **Click "Analyze Video"** to decode

### Best Practices for Recording

#### 📹 Video Capture Settings

- **Resolution:** 1080p or 720p (higher is better for accuracy)
- **Frame Rate:** 30 FPS minimum, 60 FPS ideal
- **Duration:** Record 2-3 seconds BEYOND message end
- **Stability:** Hold phone steady (use tripod if available)
- **Format:** MP4 or WebM (avoid heavy compression)

#### 💡 Lighting Conditions

- **Even, diffuse lighting** - avoid harsh shadows
- **No glare** on screen - angle camera slightly if needed
- **Consistent brightness** - avoid flickering lights
- **Screen brightness:** 80-100% for best green detection
- **Background:** Dark room reduces ambient light interference

#### 📐 Camera Position

- **Distance:** 30-60 cm (12-24 inches) from screen
- **Angle:** Perpendicular to screen (0-15° tilt max)
- **Focus:** Center cat face in frame, eyes clearly visible
- **Avoid:** Autofocus hunting during recording (tap to lock focus)

### Recording Checklist

✅ Screen brightness at 80%+
✅ Dark background behind screen
✅ Phone held steady or on tripod
✅ Cat face centered in frame
✅ No glare on screen
✅ Recording started BEFORE blinking begins
✅ Recording continued 2-3 seconds AFTER blinking ends
✅ Focus locked (no autofocus during recording)

### Decoding Workflow

1. **Upload Video** - Select your recorded MP4/WebM file
2. **Auto-Detection** - System analyzes green levels automatically
3. **Live Metrics** - Watch real-time confidence and CRC stats
4. **Decode Success** - Message appears if >85% frames confident

### Understanding Live Metrics

| Metric | Meaning | Good Value |
|--------|---------|------------|
| **Frames** | Total frames analyzed | > 300 |
| **Confident** | % frames with clear on/off | > 80% |
| **Transitions** | State changes detected | ≈ bit_count |
| **Bits** | Binary data recovered | Expected length |
| **CRC Pass** | Packets validated | > 85% |
| **CRC Fail** | Corrupted packets | < 15% |
| **Session** | Locked session ID | Hex value |
| **Wrong Session** | Rejected foreign packets | 0 |

### Troubleshooting Guide

#### Problem: Low Confidence % (< 70%)

**Likely Causes:**
- Uneven lighting (shadows, glare)
- Wrong threshold (manual override may help)
- Cat face too small in frame
- Out of focus or motion blur

**Solutions:**
1. Re-record with better lighting
2. Adjust screen brightness to 100%
3. Move camera closer (but not too close)
4. Use manual focus lock on phone
5. Try "Auto" sensitivity if stuck

#### Problem: High CRC Fail Rate (> 20%)

**Likely Causes:**
- Timing jitter (frame rate drops)
- Compression artifacts
- Fast blink speed for low frame rate camera
- Phone dropped frames during recording

**Solutions:**
1. Use shorter messages (reduces error accumulation)
2. Slow down blink speed to 150ms or 200ms
3. Record in higher quality (less compression)
4. Close other apps during recording
5. Re-record if phone overheated

#### Problem: No Transitions Detected

**Likely Causes:**
- Wrong ROI (not targeting eyes)
- Static video (no blinking)
- Extreme over/underexposure

**Solutions:**
1. Manually select ROI around cat eyes
2. Verify blinking animation is visible on screen
3. Check screen brightness not at 0%
4. Try different camera exposure settings

#### Problem: Session Lock Failures

**Likely Causes:**
- Multiple transmission sources in frame
- Recording started mid-transmission
- Interference from other screens

**Solutions:**
1. Ensure only ONE cat animation visible
2. Start recording BEFORE blinking begins
3. Block other screens from camera view
4. Use "Reset Session" button and try again

### Optimal Conditions Summary

| Parameter | Optimal Value | Acceptable Range |
|-----------|---------------|------------------|
| Distance | 40-50 cm | 30-60 cm |
| Screen Brightness | 90-100% | 80-100% |
| Ambient Light | Dim | Dark to moderate |
| Video Resolution | 1080p | 720p-1080p |
| Frame Rate | 60 FPS | 30-60 FPS |
| Blink Speed | 100ms | 80-150ms |
| Recording Extra Time | 3 seconds | 2-5 seconds |

### Diagnostics Export

After decoding (successful or failed), click **"📋 Export Diagnostics (JSON)"** to save comprehensive analysis:

**JSON Export includes:**
- Video metadata (resolution, FPS, duration)
- Frame-by-frame green scores
- Adaptive threshold calibrations
- Hysteresis state transitions
- CRC validation results
- Quality confidence metrics
- Human-readable recommendations

**CSV Export** (📊 Export Frames) provides per-frame data for analysis in Excel/Python:
```csv
frame,timestamp_ms,green_score,state,confidence,stable
0,0.0,47.234,off,0.920,true
1,33.3,149.821,on,0.954,true
2,66.7,151.003,on,0.961,true
```

### Advanced: Manual Threshold Tuning

If auto-detection fails:

1. **Note the green levels** in console log (min/max range)
2. **Estimate threshold** = min + (max - min) × 0.4
3. **(Not yet implemented: manual slider)**
4. Retry analysis with adjusted threshold

### Security Considerations for Cat Mode

- ✅ **Air-gapped:** No network, Bluetooth, or NFC involved
- ✅ **Visual verification:** You can see the data transfer happen
- ✅ **Single-use transmission:** Each video is unique
- ⚠️ **Shoulder surfing:** Record in private location
- ⚠️ **Camera security:** Ensure phone not compromised
- ⚠️ **Screen recording prevention:** Some apps block screen capture

---

## 🐾 Troubleshooting — Coughing Up Hairballs

*When things don't go as planned, start here.*

### `pyzbar` / `zbar` errors
`pyzbar` requires the `zbar` shared library.

- **Ubuntu/Debian:** `sudo apt-get install libzbar0`
- **macOS:** `brew install zbar`

Docker already installs it.

### Webcam decoding is flaky
- Make the QR code bigger on-screen.
- Reduce camera motion.
- Improve lighting and reduce glare.
- Increase capture time / frame count.

---

## ⚠️ Security Notes (Read This — The Cat Insists)

*These are not suggestions. The cat will hiss if you ignore them.*

- Treat `--password` on the command line as sensitive (it can leak).
- Prefer interactive prompts or environment variables in automation.
- See:
  - `SECURITY.md`
  - `docs/THREAT_MODEL.md`
