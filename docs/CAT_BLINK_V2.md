# Cat Blink v2 — fountain-coded optical blink transport

**Status:** Experimental (codec + round-trip tests landed; emitter/decoder/device
integration tracked in `docs/CAT_MODE_BLINK_ROADMAP.md`).

Cat Blink v2 is the wire format that makes the blinking-eye transmission
decodable by a live phone camera. It replaces the two incompatible legacy blink
formats (the standalone-demo CatProtocol-packet stream and the
`cat_video.py`/Flask 68-byte-header stream) with **one** format shared by every
producer and consumer, and adds a **fountain-coding layer** so a phone that
misses some blinks (glare, motion, a slow frame) still reconstructs the message
by watching the loop a little longer — exactly like the QR fountain path.

This document specifies the bit-exact wire format. The reference implementation
is `web_demo/static/cat-blink-v2.js` (JS) and `meow_decoder/cat_blink_v2.py`
(Python); both are exercised by round-trip tests including simulated blink loss.

## Why v2

- The blink channel carries ~5–10 bits/s. A single uncoded pass of a multi-
  hundred-byte payload that drops even one blink is unrecoverable — the legacy
  streams had no erasure coding, only whitening (a line code, not FEC).
- v2 reuses the **existing fountain droplet layout** already spoken by the QR
  path, `crypto_core/meow_fountain`, `meow_decoder/fountain.py`, and the mobile
  decoder. The blink path and QR path now share one FEC layer; only the
  *transport framing* differs.

## Layers

```
  message ──AES-256-GCM+Argon2id──▶ encrypted payload (MEOW: packed bytes)
          ──fountain encode───────▶ stream of droplets (existing layout)
          ──v2 frame + CRC───────▶ per-droplet byte frame
          ──MSB-first bits───────▶ bitstream
          ──MEOW-LCG whitening───▶ whitened bitstream
          ──2-bit blink packing──▶ eye states (green=1 / dark=0), looped
```

Decoding reverses each step; the fountain layer means the decoder needs *any*
sufficient subset of frames, not a contiguous run.

### Droplet layout (unchanged, shared with QR path)

```
seed(4, BE) || count(2, BE) || indices(count × 2, BE) || data(block_size)
```

### v2 frame (one per droplet)

Every droplet is wrapped in a self-describing, CRC-protected frame so the
decoder can (a) find frame boundaries in a free-running loop, (b) reject a
frame corrupted by a misread blink, and (c) learn the fountain parameters from
any single good frame.

| Field            | Bytes | Notes                                                        |
|------------------|------:|-------------------------------------------------------------|
| `SYNC`           | 3     | `0xB1 0x17 0x5E` ("BLInk SEed") — frame-boundary marker      |
| `version`        | 1     | `0x02` for this spec (`0x01` = legacy, never emitted by v2)  |
| `k_blocks`       | 2, BE | fountain source-block count (u16, 1–65535)                  |
| `block_size`     | 2, BE | fountain block size in bytes (u16, 1–4096 for blink)        |
| `original_length`| 4, BE | exact payload length before fountain zero-padding (u32)     |
| `droplet`        | var   | packed droplet (layout above); its length is derivable      |
| `crc16`          | 2, BE | CRC-16/CCITT-FALSE over `version…droplet` (SYNC excluded)    |

`droplet` length is not stored explicitly: `count` (bytes 4–5 of the droplet)
gives `droplet_len = 4 + 2 + count·2 + block_size`, so the decoder knows exactly
how many bytes to read once it has `block_size` and the droplet's own `count`.

CRC-16/CCITT-FALSE: poly `0x1021`, init `0xFFFF`, no reflection, no final XOR.

### Bit serialization

Each frame's bytes are emitted **MSB-first** (bit 7 of byte 0 first), matching
the legacy blink bit order and `cat_video.py`'s `bytesToBinary`.

### Whitening (unchanged from legacy)

The full bitstream is XORed with the MEOW-LCG keystream before transmission and
again on receive (self-inverse). Seed `0x4D454F57`, LCG
`seed = (seed·1103515245 + 12345) & 0x7FFFFFFF`, mask bit `(seed >> 16) & 1`,
**advance-before-mask** ordering. This is the identical keystream in
`mobile/src/services/catWhitening.ts` and `cat_video.py::whiten`; v2 keeps it so
long same-state runs (which desync NRZ blink timing) stay broken up. Whitening
is applied per-frame from a fresh seed so a lost frame never desyncs the
keystream of later frames.

### Blink packing (physical layer, unchanged)

`green = 1`, `dark = 0`. Dual-eye: even bit → left eye, odd bit → right eye
(2 bits/blink). Single-eye: 1 bit/blink, both eyes identical. A free-running
**loop** re-emits the whole droplet sequence indefinitely; the decoder syncs on
`SYNC` and collects unique droplets across loops until the fountain completes.

Preamble/sync-run framing that lets the sampler find the blink clock is the
same as legacy (20-frame preamble, 6-frame loop guard) and is out of scope for
this codec spec — it lives in the sampler.

## Completion

- **Reconstructing receiver** (web self-test, desktop): stop when the fountain
  decoder reports complete (`k_blocks` blocks recovered).
- **Collecting receiver** (phone, deferring decode to desktop): stop at
  `ceil(1.5 × k_blocks)` unique droplets — the same threshold the QR path uses.

## Versioning / back-compat

The `version` byte and distinct `SYNC` marker mean a v2 decoder can refuse a
legacy v1 stream cleanly, and legacy decoders (which look for their own
preamble/packet magic, not `SYNC`) ignore v2. Old recorded blink videos still
decode through the untouched legacy `cat_video.py` path. Nothing in v2 changes
the crypto — it is a transport/FEC layer over an already-encrypted payload.

## Reality check

Even fountain-coded, the blink channel is ~5–10 bits/s: practical only for short
messages (≈ under 100 bytes, a minute or two per transfer). v2 makes blink→app
*reliable*, not *fast*. Standard animated QR remains the recommended tier; Cat
Blink is a fun/camouflage mode.
