# Usage Guide

This project moves data through **animated QR-code GIFs**.

At a high level:

1. **Encode** a file into an animated GIF (each frame is a QR code).
2. **Transmit** that GIF (file transfer) **or** display it on a screen.
3. **Decode** by reading frames back (from the GIF file or a webcam capture) and reconstructing the original bytes.

> Tip: If you just want a working end-to-end demo, use Docker:
>
> ```bash
> git clone https://github.com/systemslibrarian/meow-decoder.git
> cd meow-decoder
> docker compose up --build
> ```

---

## Encode a file into a QR GIF

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

## Decode back to the original file

### Option A: Decode from a GIF file

If you have the GIF file itself:

```bash
python -m meow_decoder.decode_gif --input out.gif --output recovered.bin
```

---

## Phone + webcam scanning workflow (screen-to-camera)

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

## Mobile Bridge (React Native scanner)

The mobile bridge connects phone-based QR scanning directly to the CLI decoder.

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

## Hardware Keys (HSM, YubiKey, TPM)

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

## Troubleshooting

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

## Security notes (read this)

- Treat `--password` on the command line as sensitive (it can leak).
- Prefer interactive prompts or environment variables in automation.
- See:
  - `SECURITY.md`
  - `docs/THREAT_MODEL.md`
  - `docs/RELEASE_INTEGRITY.md`
