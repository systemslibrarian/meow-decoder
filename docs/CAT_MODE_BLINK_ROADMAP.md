# Cat Mode Blink Transport Roadmap

**Status:** Planned — not implemented
**Goal:** Restore true blink→app optical transport as an optional slow mode alongside the current Blended QR-inset presentation.

The Blended presentation ([CAT_MODE.md](CAT_MODE.md)) keeps the cat fully visible and blinks its eyes on every transmitted frame, but that blink is purely cosmetic — all data travels through the fountain QR inset. This roadmap covers what it would take to make the blink itself a real, camera-decodable transport again.

## Roadmap

1. **Unify the wire format.** Reconcile the web blink emitter's framing (preamble, sync word, header bits) with the orphaned mobile `CatCaptureScreen` sampler so both sides speak one blink protocol instead of two divergent research artifacts.
2. **Fountain-code the blink bits.** Apply fountain coding to the blink bit-stream so dropped or misread blinks degrade gracefully instead of corrupting the whole transfer, mirroring the QR path's droplet model.
3. **Re-wire the capture route.** Bring the orphaned `CatCapture` route back into the mobile app behind a "Blink capture (slow)" entry so the mode is discoverable but clearly separated from the fast QR path.
4. **Camera hardening.** Lock exposure during capture, sample at ≥2× the blink rate (Nyquist), apply the July 2026 VFR timing lessons (variable frame rate, seek, and frame-count pitfalls from recorded-video decode), and reuse the privacy-preserving 5 Hz luminance frame-processor including its LIMITED-device bind fallback.
5. **CI closure.** Extend the Gate 4b-style harness (browser pixels → Python decode) to screenshot a blink stream and decode it end-to-end, so the blink transport gets the same automated proof as the QR inset.
6. **Device validation.** Add a blink row to [HARDWARE_TEST_MATRIX.md](HARDWARE_TEST_MATRIX.md) and require a 3/3 baseline pass on real hardware before the mode leaves Experimental.

## Physics reality check

Blink transport runs at roughly 5–10 bit/s, so it is only practical for payloads under about 100 bytes, and even those take minutes per transfer. It is intentionally a fun/camouflage mode — it will never be fast, and the QR inset remains the recommended Cat Mode transport.
