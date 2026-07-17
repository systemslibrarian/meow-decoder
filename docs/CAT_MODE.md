# Cat Mode Optical Transfer

**Maturity:** Experimental  
**Recommended transfer:** Standard animated QR  
**Automated optical status:** Passing on 2026-07-17  
**Real-device status:** No controlled phone/display measurements recorded yet

Cat Mode is a presentation layer for the web demo's encrypted payload. In the current **Blended** presentation ("Cat Mode 2 · Blended") the cat stays fully visible — no dimming — behind a high-contrast QR inset, and the cat's eyes perform a brief cosmetic blink on every optical frame advance, making the blink the visible heartbeat of the transfer. Meow Capture reads the inset with its normal native QR scanner and collects fountain droplets until the transfer threshold is reached.

Cat Mode no longer uses blinking eyes as the data channel for the user-facing transfer: the blink is purely cosmetic and carries no bits. The old blink encoder and decoder remain available only for compatibility with previously recorded research artifacts. A roadmap for restoring true blink transport as an optional slow mode is in [CAT_MODE_BLINK_ROADMAP.md](CAT_MODE_BLINK_ROADMAP.md).

## End-to-end flow

1. Open `web_demo/wasm_browser_example_FULL.html` and select **Cat**.
2. Enter a message and password.
3. Select **Fullscreen Cat**.
4. Select **Start Transmitting** inside the fullscreen stage.
5. Use **Cat Mode · Experimental** or **Scan Sender Screen** in Meow Capture.
6. Aim at the white QR inset during the three-second countdown.
7. Keep scanning while the frame sequence loops.
8. Meow Capture auto-completes after collecting `ceil(k_blocks * 1.5)` unique droplets and exports the captured frames for recovery.

## Active transmit parameters

| Parameter | Value |
|---|---:|
| Fountain block size | 128 bytes |
| Fountain redundancy | 4.0x |
| Minimum transmitted frames | 8 |
| Default frame interval | 500 ms (2 frames/s) |
| Scheduler | `requestAnimationFrame` |
| Drift handling | Fixed-deadline increments; hidden tabs pause advancement |
| Countdown | 3 seconds |
| QR error correction | M |
| QR quiet zone | 4 modules |
| QR backing raster | 560 x 560 pixels |
| QR colors | `#000000` on `#ffffff` |
| Looping | Infinite until Stop |

The web stage displays the parameters it actually uses, plus frame number, total frames, and loop count. Test code can override countdown and frame interval through `window.__MEOW_CAT_TEST_CONFIG__`; production defaults remain those in the table.

### Fullscreen behavior

Cat Mode requests element fullscreen through the standard Fullscreen API, with the WebKit-prefixed method as a compatibility fallback. If an element fullscreen request is unsupported or rejected, including non-video elements on iOS Safari, the stage switches to a fixed full-window fallback. Start, Stop, current frame, loop count, and Exit controls remain inside either presentation.

In the Blended presentation the cat canvas is rendered at full opacity throughout transmission. The QR inset is sized to keep the cat prominent while remaining reliably scannable: `min(72%, 400px)` of the stage in the normal view, and `min(58vw, 58vh, 480px)` in fullscreen, where it is anchored slightly below center so more of the cat face shows above the inset. The white shell and quiet zone are never overlapped, and the calibration corners remain at the shell edges.

The controls reserve 112 CSS pixels below the optical layer. They do not cover the QR quiet zone or finder patterns.

## Wire format

Each rendered QR contains this ASCII envelope:

```text
FOUNTAIN:<k_blocks>:<block_size>:<original_length>:<base64_droplet>
```

The decoded droplet bytes are:

```text
seed(4, BE) || count(2, BE) || indices(count * 2, BE) || data(block_size)
```

Fountain coding is applied to an already-encrypted `MEOW:` web payload. The receiver reconstructs that exact encrypted payload; it does not interpret droplet contents while capturing.

This web envelope is separate from the CLI/GIF format in which frame 0 is a signed MEOW manifest. Cat Mode does not disable, forge, or bypass core manifest signing. It also does not claim that its first fountain frame is a protocol manifest.

## Mobile telemetry

During QR capture, Meow Capture displays:

| Metric | Meaning |
|---|---|
| Frames seen | Camera frames sampled by the privacy-preserving 5 Hz luminance processor |
| QRs decoded | Values returned by the native VisionCamera scanner, including repeats |
| Unique | Deduplicated Meow fountain droplets retained in memory |
| Duplicates | Duplicate fraction in the rolling scanner window |
| Needed | Unique droplets remaining to the `ceil(1.5 * k_blocks)` completion target |
| Fresh rate | New unique droplets per second over a rolling three-second window |
| ETA | `droplets_needed / fresh_rate`; shown as waiting when the rate is zero |

No camera image is saved by telemetry. The diagnostics frame processor samples at most about 512 Y-plane pixels five times per second and sends only mean luminance to the JavaScript thread.

After three seconds with zero fresh droplets, guidance uses measured inputs in this priority order:

| Reason | Trigger |
|---|---:|
| Moving too much | Accelerometer magnitude greater than 2.5 m/s^2 |
| Too dark | Mean Y-plane luminance below 45 |
| Glare / too bright | Mean Y-plane luminance above 215 |
| Too close | Last decoded QR dimension greater than 82% of scanner frame |
| Too far | Last decoded QR dimension less than 18% of scanner frame |
| No geometry | No QR bounds are available; center the code and adjust distance without claiming a measured cause |

These are operational heuristics, not calibrated camera exposure standards. Real-device validation must record false hints as failures in the hardware matrix.

## Automated optical measurements

The reproducible harness runs a real headless browser at 1280 x 720, enters Cat Mode, enters fullscreen, starts transmission, screenshots every unique rendered frame, and decodes the screenshots through `QRCodeReader` and the Python `FountainDecoder`.

Measurement date: **2026-07-17**  
Browser used for the recorded local run: **Microsoft Edge through Playwright**  
Decoder used for the recorded local run: **OpenCV fallback through the existing `QRCodeReader` API**  
Test payload: **8 source blocks, 32 transmitted frames, 16.0-second loop**

| Profile | Blur sigma | Motion kernel | Shear | JPEG quality | Brightness | Gamma | Perspective | Dropped | Received | QR reads | QR read rate | Unique consumed | Result |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Clean | 0.00 | 1 px | 0 px | 100 | 1.00 | 1.00 | 0.0% | 0/32 | 32 | 32 | 100.0% | 8 | Pass |
| Mild | 0.35 | 3 px | 1 px | 92 | 0.97 | 1.03 | 0.4% | 3/32 | 29 | 27 | 93.1% | 14 | Pass |
| Moderate | 0.55 | 3 px | 2 px | 84 | 0.92 | 1.08 | 0.8% | 8/32 | 24 | 21 | 87.5% | 13 | Pass |
| Severe | 0.75 | 5 px | 3 px | 76 | 0.86 | 1.14 | 1.2% | 12/32 | 20 | 18 | 90.0% | 10 | Pass |

`Unique consumed` stops when fountain reconstruction completes; it is not the number of all decodable frames in the sequence. Frame drops use deterministic seed `20260717`.

The 3.0x schedule was rejected: with deterministic coded droplets, the severe profile reproducibly recovered only 7 of 8 source blocks from 11 unique droplets. Cat Mode therefore uses 4.0x. Plain QR mode's settings were not changed.

QR error correction H was also rejected for this live-camera surface. Its denser symbol produced a fresh-payload severe run that stalled at 7 of 8 blocks despite 4.0x redundancy. Error correction M renders larger modules at the same 560-pixel raster; it passed three independent severe runs plus the complete matrix above. This changes Cat Mode only.

Run the full harness with:

```sh
make test-cat-mode
```

Prerequisites are the project Python dependencies, Node dependencies, and a Playwright Chromium installation. CI runs this as the gating **Cat Mode Optical Loop** job and uploads rendered frames on failure.

## Real-device measurements

No controlled distance/lux result has been run or checked into this repository as of 2026-07-17. Therefore this document makes no claim such as "decodes at 45 cm under 300 lux."

The required matrix and pass criteria are in `docs/HARDWARE_TEST_MATRIX.md`. Until at least the baseline row passes three consecutive trials on a physical phone and display, Cat Mode remains Experimental regardless of automated results.

## Limits and failure conditions

- Cat Mode currently transmits text entered in the web demo, not arbitrary files.
- The Cat web surface uses password-based Argon2id plus AES-256-GCM. It does not add forward secrecy or post-quantum mode.
- A loop contains `max(8, 4 * ceil(encrypted_payload_bytes / 128))` frames. Larger messages take proportionally longer.
- QR version is selected by the browser QR library from frame content; the 560-pixel raster and 128-byte blocks preserve larger modules than the previous 256-byte experiment.
- Fullscreen enlarges the rendered inset but does not create optical guarantees. Display pixel density, camera focus, rolling shutter, PWM, reflections, and physical distance still require hardware measurement.
- Sending through messaging-app recompression is outside the live camera path and may fail.
- The legacy blinking-eye receiver does not collect droplets and is not the current Cat Mode workflow. The Blended presentation's eye blink is cosmetic only; restoring true blink→app transport as an optional slow mode is tracked in [CAT_MODE_BLINK_ROADMAP.md](CAT_MODE_BLINK_ROADMAP.md).
- Standard animated QR remains the Recommended tier and should be used when camouflage is not required.
