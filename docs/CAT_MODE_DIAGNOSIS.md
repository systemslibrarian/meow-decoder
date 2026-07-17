# Cat Mode Optical Transport Diagnosis

**Date:** 2026-07-17  
**Branch inspected:** `security/fable-bug-hunt-fixes`  
**Scope:** Current source only. No Cat Mode implementation changes preceded this report.

## Executive finding

The requested flow cannot close today, even through a perfect optical channel. The repository has two incompatible Cat Mode wire protocols:

1. The repository entry page redirects to `web_demo/wasm_browser_example_FULL.html`, whose Cat tab transmits a finite stream of CRC-framed, packed WASM ciphertext by changing green carrier pixels to black. It does not emit QR frames, a protocol manifest, or fountain droplets ([index.html:L5-L8](../index.html#L5-L8), [web_demo/wasm_browser_example_FULL.html:L4477-L4555](../web_demo/wasm_browser_example_FULL.html#L4477-L4555), [web_demo/wasm_browser_example_FULL.html:L4652-L4682](../web_demo/wasm_browser_example_FULL.html#L4652-L4682)).
2. Meow Capture's normal `Capture` screen collects `FOUNTAIN:` QR strings, while its separate `CatCapture` screen samples two luminance regions and expects the older Flask Cat transmitter's whitened 68-byte payload format. The Cat screen exports a bit string for later desktop decryption; it never collects droplets or reports receiver-side plaintext success ([mobile/src/services/qrDecoder.ts:L20-L31](../mobile/src/services/qrDecoder.ts#L20-L31), [mobile/src/services/catBlinkDecoder.ts:L7-L20](../mobile/src/services/catBlinkDecoder.ts#L7-L20), [mobile/src/screens/CatCaptureScreen.tsx:L326-L352](../mobile/src/screens/CatCaptureScreen.tsx#L326-L352)).

A read-only synthetic probe fed the real mobile `decodeCatBlink()` function a noiseless 30 fps stream using the active WASM sender's 200 ms lead-in/sync/packet layout. It failed with `locked=false`, `reason="bad_header"`, `origLen=3756306825`, and `compLen=1807475424`. This rules out camera blur, glare, frame loss, and button timing as the primary break. The incompatible parser is visible at the exact point where mobile de-whitens the first 64 recovered bits as `orig_len || comp_len` ([mobile/src/services/catBlinkDecoder.ts:L401-L444](../mobile/src/services/catBlinkDecoder.ts#L401-L444)).

There are also two independent deterministic blockers:

- Only `#catCanvasStage` enters fullscreen, but the Start and Fullscreen buttons are siblings outside that element. After **Fullscreen Cat**, the active page has no visible **Start Transmitting** control ([web_demo/wasm_browser_example_FULL.html:L1151-L1188](../web_demo/wasm_browser_example_FULL.html#L1151-L1188), [web_demo/wasm_browser_example_FULL.html:L4176-L4201](../web_demo/wasm_browser_example_FULL.html#L4176-L4201)).
- The default 15-byte message, single-eye mode, 2x redundancy, and 200 ms interval require 1,336 intervals, or **267.2 seconds**, while mobile times out after **180 seconds**. The calculation is `56 framing bits + 2 * 8 * (15-byte packet header + 34-byte packed header + 15-byte plaintext + 16-byte GCM tag)` ([web_demo/wasm_browser_example_FULL.html:L1155-L1177](../web_demo/wasm_browser_example_FULL.html#L1155-L1177), [web_demo/wasm_browser_example_FULL.html:L1771-L1804](../web_demo/wasm_browser_example_FULL.html#L1771-L1804), [web_demo/cat-mode-protocol.js:L44-L49](../web_demo/cat-mode-protocol.js#L44-L49), [web_demo/wasm_browser_example_FULL.html:L4500-L4548](../web_demo/wasm_browser_example_FULL.html#L4500-L4548), [mobile/src/constants/config.ts:L118-L130](../mobile/src/constants/config.ts#L118-L130)).

## Current path map

### Active static web Cat path

The top-level page redirects to the self-contained WASM demo ([index.html:L5-L8](../index.html#L5-L8)). Its Cat tab contains a 400x400 backing canvas; the only selectable interval is 200 ms, dual-eye is off by default, and packet repetition is 2x by default ([web_demo/wasm_browser_example_FULL.html:L1151-L1183](../web_demo/wasm_browser_example_FULL.html#L1151-L1183)).

`buildCatBinaryPayload()` encrypts into the web-only packed-v3 layout, splits the result into CatProtocol packets of at most 256 payload bytes, then adds an 8-bit dark lead-in, 16 alternating bits, an 8- or 16-bit alternating sync word, repeated packet bits, and a 16-bit end marker ([web_demo/wasm_browser_example_FULL.html:L1771-L1804](../web_demo/wasm_browser_example_FULL.html#L1771-L1804), [web_demo/wasm_browser_example_FULL.html:L4477-L4555](../web_demo/wasm_browser_example_FULL.html#L4477-L4555)). CatProtocol packets use a 15-byte little-endian header plus CRC32; they are not fountain droplets ([web_demo/cat-mode-protocol.js:L1-L17](../web_demo/cat-mode-protocol.js#L1-L17), [web_demo/cat-mode-protocol.js:L141-L212](../web_demo/cat-mode-protocol.js#L141-L212)).

The sender converts those bits into one `{left,right}` state per interval. Single-eye mode duplicates one bit into both eyes; dual-eye mode keeps the header single-eye, inserts a `0xFD` marker, and then carries two payload bits per interval ([web_demo/wasm_browser_example_FULL.html:L4609-L4677](../web_demo/wasm_browser_example_FULL.html#L4609-L4677)). The stream is finite: reaching `effectiveIntervals` calls `catModeStop()` rather than beginning another loop ([web_demo/wasm_browser_example_FULL.html:L4770-L4805](../web_demo/wasm_browser_example_FULL.html#L4770-L4805)).

### Older Flask Cat path

Flask still exposes `/cat-mode`, but it is a different implementation ([web_demo/app.py:L357-L360](../web_demo/app.py#L357-L360)). That template sends a whitened custom payload behind a 6-frame OFF guard, 8 ON frames, 8 OFF frames, 4 alternating frames, and two bits per data frame, continuously looping until Stop ([web_demo/templates/cat_mode.html:L695-L700](../web_demo/templates/cat_mode.html#L695-L700), [web_demo/templates/cat_mode.html:L812-L860](../web_demo/templates/cat_mode.html#L812-L860), [web_demo/templates/cat_mode.html:L898-L943](../web_demo/templates/cat_mode.html#L898-L943)). Its server endpoint packs `orig_len(4) || comp_len(4) || sha256(32) || salt(16) || nonce(12) || ciphertext`, which is the 68-byte layout the mobile Cat decoder expects ([web_demo/app.py:L498-L548](../web_demo/app.py#L498-L548), [mobile/src/services/catBlinkDecoder.ts:L87-L95](../mobile/src/services/catBlinkDecoder.ts#L87-L95)).

The mobile golden tests synthesize this older Flask layout, not the active static sender. Their oracle explicitly reproduces the 8 ON / 8 OFF / 4 alternating preamble, whitening, 68-byte header, and two-bit frames ([mobile/__tests__/catBlinkDecoder.test.ts:L1-L10](../mobile/__tests__/catBlinkDecoder.test.ts#L1-L10), [mobile/__tests__/catBlinkDecoder.test.ts:L34-L72](../mobile/__tests__/catBlinkDecoder.test.ts#L34-L72)). This is why those tests can pass while the user-facing static flow cannot.

### Mobile QR/fountain path

The normal mobile scanner accepts `FOUNTAIN:<k>:<block_size>:<length>:<base64>` and stores each decoded QR as an opaque `CapturedFrame`; it does not invoke the fountain decoder on-device ([mobile/src/services/qrDecoder.ts:L20-L31](../mobile/src/services/qrDecoder.ts#L20-L31), [mobile/src/services/qrDecoder.ts:L59-L85](../mobile/src/services/qrDecoder.ts#L59-L85), [mobile/src/types/capture.ts:L1-L8](../mobile/src/types/capture.ts#L1-L8)). Its state machine auto-completes collection at `ceil(expected_frames * 1.5)`, then exports captured values for desktop recovery ([mobile/src/constants/config.ts:L8-L14](../mobile/src/constants/config.ts#L8-L14), [mobile/src/hooks/useCapture.ts:L205-L219](../mobile/src/hooks/useCapture.ts#L205-L219)).

The separate Cat screen is reached through its own `CatCapture` navigation route and uses `useCatBlinkSampler`, not `useQRScanner` ([mobile/src/screens/HomeScreen.tsx:L491-L503](../mobile/src/screens/HomeScreen.tsx#L491-L503), [mobile/src/navigation/AppNavigator.tsx:L68-L77](../mobile/src/navigation/AppNavigator.tsx#L68-L77), [mobile/src/screens/CatCaptureScreen.tsx:L78-L94](../mobile/src/screens/CatCaptureScreen.tsx#L78-L94)). Therefore no current Cat UI route can increment `unique droplets`, `droplets needed`, or fountain completion.

## Answers to the six diagnostic questions

### 1. What is the transmit frame rate, and what governs it?

For the active static Cat path, the sole interval is **200 ms**, so the optical symbol rate is **5 state changes/s**. That is 5 bit/s in default single-eye mode or 10 bit/s during the payload portion of optional dual-eye mode ([web_demo/wasm_browser_example_FULL.html:L1165-L1172](../web_demo/wasm_browser_example_FULL.html#L1165-L1172), [web_demo/wasm_browser_example_FULL.html:L4652-L4677](../web_demo/wasm_browser_example_FULL.html#L4652-L4677)).

Pacing uses `requestAnimationFrame`. It compares the rAF timestamp with `bitStartTime`, advances in a `while` loop, and adds exactly `speed` to the prior deadline, which is explicit drift correction. It does not use `setInterval` or GIF timing ([web_demo/wasm_browser_example_FULL.html:L4770-L4798](../web_demo/wasm_browser_example_FULL.html#L4770-L4798)). `canvas.captureStream(30)` records at a requested 30 video frames/s, but that recording rate does not govern the 5 Hz eye states ([web_demo/wasm_browser_example_FULL.html:L4703-L4730](../web_demo/wasm_browser_example_FULL.html#L4703-L4730)).

For comparison, the normal Python QR artifact defaults to **2 GIF frames/s**, governed by a 500 ms GIF frame duration, not rAF ([meow_decoder/config.py:L58-L69](../meow_decoder/config.py#L58-L69), [meow_decoder/gif_handler.py:L10-L25](../meow_decoder/gif_handler.py#L10-L25)). That path is not used by the active Cat tab.

### 2. What is the mobile capture frame rate, and does it Nyquist-satisfy transmit?

The Cat frame processor requests at most **30 samples/s** through `runAtTargetFps(30)` ([mobile/src/screens/CatCaptureScreen.tsx:L78-L94](../mobile/src/screens/CatCaptureScreen.tsx#L78-L94), [mobile/src/hooks/useCatBlinkSampler.ts:L57-L91](../mobile/src/hooks/useCatBlinkSampler.ts#L57-L91)). At a 5 Hz symbol rate, that nominally yields 6 samples per symbol and exceeds the two-samples-per-symbol Nyquist floor of 10 samples/s.

It is not a hardware guarantee. `CatCaptureScreen` does not pass an `fps` or selected `format` prop to its `<Camera>`; `runAtTargetFps` only throttles work and cannot make a slower camera produce 30 frames/s ([mobile/src/screens/CatCaptureScreen.tsx:L218-L230](../mobile/src/screens/CatCaptureScreen.tsx#L218-L230), [mobile/src/hooks/useCatBlinkSampler.ts:L85-L91](../mobile/src/hooks/useCatBlinkSampler.ts#L85-L91)). The normal QR camera also deliberately leaves `fps` unset and uses the device default, although it requests a 1920x1080 format where available ([mobile/src/components/CameraPreview.tsx:L87-L100](../mobile/src/components/CameraPreview.tsx#L87-L100), [mobile/src/components/CameraPreview.tsx:L218-L234](../mobile/src/components/CameraPreview.tsx#L218-L234)).

Conclusion: **nominal yes, operationally unverified**. More importantly, a perfect 30 fps synthetic capture still fails the current wire contract, so increasing camera FPS cannot repair the primary defect.

### 3. Does Cat Mode change QR version, module size, contrast, or quiet zone?

It does not modify those parameters; it removes the QR entirely.

| Property | Plain Python QR path | Active Cat path | Delta |
|---|---:|---:|---:|
| QR version | Minimum v25 (`fit=True` may grow it) | None | QR transport removed |
| Error correction | H | None | Removed |
| Module size | 14 output pixels | None | Removed |
| Quiet zone | 4 modules | None | Removed |
| Nominal minimum raster | `(117 + 8) * 14 = 1750` px square | 400x400 carrier canvas | Not comparable |
| Signal contrast | Black on white | Original green pixels versus black | Binary carrier replaces finder/timing patterns |

The QR defaults and base85 conversion are set in the Python generator ([meow_decoder/config.py:L58-L69](../meow_decoder/config.py#L58-L69), [meow_decoder/qr_code.py:L31-L54](../meow_decoder/qr_code.py#L31-L54), [meow_decoder/qr_code.py:L65-L94](../meow_decoder/qr_code.py#L65-L94)). The active Cat renderer instead finds pixels where `g > 100`, `g > 1.3*r`, and `a > 100`, then writes RGB `(0,0,0)` for an OFF state ([web_demo/wasm_browser_example_FULL.html:L4310-L4355](../web_demo/wasm_browser_example_FULL.html#L4310-L4355), [web_demo/wasm_browser_example_FULL.html:L4370-L4420](../web_demo/wasm_browser_example_FULL.html#L4370-L4420)).

### 4. Does manifest frame 0 survive Cat Mode's presentation layer?

**No. There is no protocol manifest frame 0 in this path.** The normative QR encoder appends the MAC'd manifest first, then signature metadata frames, then MAC'd fountain droplets ([meow_decoder/encode.py:L558-L618](../meow_decoder/encode.py#L558-L618)). The protocol likewise defines frame 0 as manifest bytes and frame 1+ as packed droplets ([docs/PROTOCOL.md:L98-L131](PROTOCOL.md#L98-L131), [docs/PROTOCOL.md:L156-L165](PROTOCOL.md#L156-L165)).

The active Cat path starts from the web-only packed-v3 payload and wraps it in CatProtocol CRC packets ([web_demo/wasm_browser_example_FULL.html:L1771-L1804](../web_demo/wasm_browser_example_FULL.html#L1771-L1804), [web_demo/wasm_browser_example_FULL.html:L4477-L4507](../web_demo/wasm_browser_example_FULL.html#L4477-L4507)). The older Flask Cat path also sends a custom 68-byte encryption header rather than the normative MEOW2/3/4/5 manifest ([web_demo/app.py:L531-L548](../web_demo/app.py#L531-L548)). Neither Cat transport can be handed to the existing manifest/fountain decoder as a sequence of protocol frames.

### 5. Does fullscreen change rendered module size in device pixels, and cross the camera limit?

There are no QR modules to resize. Fullscreen CSS scales the 400x400 backing canvas to `min(92vw, 92vh)` without resizing its backing store ([web_demo/wasm_browser_example_FULL.html:L354-L386](../web_demo/wasm_browser_example_FULL.html#L354-L386), [web_demo/wasm_browser_example_FULL.html:L1151-L1153](../web_demo/wasm_browser_example_FULL.html#L1151-L1153)). Examples at device-pixel ratio 1:

- 1280x720 viewport: 662.4 displayed pixels, **1.656x** interpolation from the backing canvas.
- 1920x1080 viewport: 993.6 displayed pixels, **2.484x** interpolation.

At device-pixel ratio `d`, the composited raster occupies approximately the CSS dimension times `d`, but it still contains only 400x400 source samples because no code multiplies the canvas backing dimensions by `devicePixelRatio` ([web_demo/wasm_browser_example_FULL.html:L1151-L1153](../web_demo/wasm_browser_example_FULL.html#L1151-L1153), [web_demo/wasm_browser_example_FULL.html:L4210-L4238](../web_demo/wasm_browser_example_FULL.html#L4210-L4238)).

A local measurement reproducing the page's detector against `assets/MeowDecoderDemo.png` found that the 743x417 source is drawn as 400x224 at offset `(0,88)`. The selected left and right regions are 84x132 and 118x163 backing pixels, respectively. Those boxes include the decorative green ear and antenna because detection takes bounding boxes over all qualifying green pixels in the upper 65% of the image, rather than connected components limited to the eyes ([web_demo/wasm_browser_example_FULL.html:L4210-L4238](../web_demo/wasm_browser_example_FULL.html#L4210-L4238), [web_demo/wasm_browser_example_FULL.html:L4310-L4364](../web_demo/wasm_browser_example_FULL.html#L4310-L4364)).

No checked-in hardware result ties viewport size, monitor pitch, camera field of view, focus distance, or ROI occupancy to a decode threshold. Therefore the source does **not** support an honest claim that fullscreen crosses a phone camera's resolvable limit at a “typical” distance. The deterministic format failure occurs at perfect resolution, before that question matters.

### 6. Is Cat Mode using stego/carrier LSB embedding, and is its QR readable afterward?

The active Cat tab uses a visible carrier, but **not LSB steganography**. It copies the original image and sets qualifying green pixels to black for OFF; it never embeds payload bits into pixel least-significant bits ([web_demo/wasm_browser_example_FULL.html:L4370-L4420](../web_demo/wasm_browser_example_FULL.html#L4370-L4420)). Because it contains no QR, QR readability after LSB embedding is not applicable.

The core encoder has separate `logo_eyes` / `cat_eyes_blink` carrier code, and the decoder has a separate LSB fallback, but the active WASM Cat handler does not call either path ([meow_decoder/encode.py:L628-L675](../meow_decoder/encode.py#L628-L675), [meow_decoder/decode_gif.py:L259-L307](../meow_decoder/decode_gif.py#L259-L307)). Pixel-LSB stego is also forced to APNG elsewhere because GIF palette quantization destroys those bits; that is a different feature from this blinking-eye page.

## Normative protocol versus Cat transports

| Layer | Normative QR/GIF protocol | Active static Cat | Mobile Cat decoder |
|---|---|---|---|
| First logical frame | Authenticated MEOW manifest | 8 dark bits, then alternating bits | Searches for 8 ON + 8 OFF + 4 alternating frames |
| Payload unit | Packed fountain droplet | CatProtocol packet bitstream | Whitened custom encrypted blob |
| Integrity | Manifest HMAC, optional frame MAC, AEAD | Packet CRC32 plus inner AEAD | Does not parse CRC packets or verify AEAD |
| Loss recovery | 2.5x fountain droplets by current Python default | Whole packet stream repeated 1x/2x | No droplet decoder; requires a complete bit pattern |
| Completion | Fountain decoder reconstructs `k_blocks` | Finite schedule ends once | Exact byte count inferred from legacy header |

The normative manifest/droplet contract is specified in [docs/PROTOCOL.md:L98-L190](PROTOCOL.md#L98-L190). Current fountain droplets serialize as `seed(4) || count(2) || indices(2*count) || data(block_size)` ([meow_decoder/fountain.py:L499-L549](../meow_decoder/fountain.py#L499-L549)). With the default 512-byte block and a degree-1 systematic droplet, that is 520 bytes; the 8-byte frame MAC makes 528 bytes, and base85 makes 660 QR characters ([meow_decoder/config.py:L58-L69](../meow_decoder/config.py#L58-L69), [meow_decoder/qr_code.py:L65-L94](../meow_decoder/qr_code.py#L65-L94), [docs/PROTOCOL.md:L74-L77](PROTOCOL.md#L74-L77)). None of those bytes enter the active Cat sender.

There is one adjacent protocol documentation gap: the Python encoder inserts mandatory signature metadata QR frames between frame 0 and droplets, while `PROTOCOL.md` still says every frame 1+ is a droplet ([meow_decoder/encode.py:L376-L469](../meow_decoder/encode.py#L376-L469), [meow_decoder/encode.py:L584-L618](../meow_decoder/encode.py#L584-L618), [docs/PROTOCOL.md:L156-L165](PROTOCOL.md#L156-L165)). This does not cause the Cat failure, but the Tier 1 oracle must follow implementation ordering rather than assuming the abbreviated document layout.

## Root causes, in fix order

1. **Wire-protocol fork:** the active web sender and mobile Cat decoder cannot interoperate. This fails with a perfect synthetic channel.
2. **Wrong transport for the stated product flow:** CatCapture reconstructs a complete legacy bitstream, whereas the requested receiver workflow and telemetry are droplet-based.
3. **Default duration exceeds receiver timeout:** 267.2 seconds to send the default message versus a 180-second Cat capture timeout.
4. **Fullscreen control loss:** Start is outside the fullscreen subtree; rejection only logs or alerts, with no iOS non-video fallback ([web_demo/wasm_browser_example_FULL.html:L4176-L4201](../web_demo/wasm_browser_example_FULL.html#L4176-L4201)).
5. **No acquisition/calibration target:** the sender exposes only the cat bitmap and changing green regions; the receiver requires manually dragged L/R boxes ([mobile/src/screens/CatCaptureScreen.tsx:L99-L139](../mobile/src/screens/CatCaptureScreen.tsx#L99-L139)).
6. **Failure is late and coarse:** Cat capture shows sample count while searching, but only distinguishes “never found sync” from “missed frames” at the terminal timeout ([mobile/src/screens/CatCaptureScreen.tsx:L315-L376](../mobile/src/screens/CatCaptureScreen.tsx#L315-L376)).

## Direction for the harness and fix

The requested screenshot-to-existing-Python-decoder Tier 1 harness cannot honestly assert fountain reconstruction against the current blinking-eye Cat tab because that tab emits no manifest or droplets. The harness should first encode the intended contract as a failing test: Cat presentation frames must contain the same authenticated manifest and fountain droplet bytes as plain QR mode, and screenshots must decode through the existing QR/fountain pipeline.

The defensible presentation fix is the proposed hybrid: keep the cat as the experimental visual carrier, but render a stable, high-contrast QR inset with a four-module quiet zone and the same protocol frames as plain mode. That preserves crypto and fountain behavior, lets Meow Capture use its existing QR session state machine and telemetry, and limits Cat Mode's experimental behavior to presentation. The current eye-blink protocol can remain separately labeled as a legacy research transport, but it should not be presented as the droplet-based Cat Mode workflow.

Cat camouflage remains **Experimental**, while standard encrypted transfer and guided mobile capture remain **Recommended**, matching the trust taxonomy ([docs/TRUST_CENTER.md:L65-L84](TRUST_CENTER.md#L65-L84), [docs/TRUST_CENTER.md:L103-L118](TRUST_CENTER.md#L103-L118)).