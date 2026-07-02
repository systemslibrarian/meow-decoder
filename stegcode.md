# stegcode.md — Cryptography Audit Map of the Steganography Features

> **Purpose:** A per-file inventory of every cryptographic primitive and operation
> that backs the steganography ("stego") features of meow-decoder, so the crypto
> can be audited in isolation.
>
> **Scope:** The stego carrier/embedding modules under `meow_decoder/`, plus the
> shared crypto helpers they depend on. File:line references point at the relevant
> call sites. References were gathered by reading the source; re-confirm exact line
> numbers against the working tree before signing off, as the code is under active
> development (`feat/capture-ux-loop-detection`).
>
> **Legend:** ✅ sound / appropriate · ⚠️ scrutinize · 🔴 critical — auditor must verify
>
> **Generated:** 2026-06-24

---

## Remediation status (branch `feat/capture-ux-loop-detection`)

Hardening applied after the initial audit:

- **Stego crypto fails closed (was: silent Python fallback).** `derive_frame_seed`,
  `derive_walk_seed`, `generate_pixel_walk`, and `prepare_payload(encrypt=False)` now
  raise `SecurityDegradationError` in production when the constant-time Rust backend is
  absent, instead of silently using the non-constant-time Python path. Gated on
  `MEOW_PRODUCTION_MODE` (override: `MEOW_STEGO_REQUIRE_RUST`). See `stego_multilayer.py`
  `_require_rust_or_fail()`.
- **Cross-channel binding for the comment channel.** The comment channel's own HMAC is
  now treated as an *extraction hint*, not an authentication boundary; the decoder selects
  the comment candidate that satisfies the **outer payload HMAC** over the full reassembly
  (`MultiLayerStegoDecoder.decode`). This closes a shadowing DoS + cross-message
  linkability oracle where a MAC-valid comment block harvested from another same-key
  message could displace the real one.

Verified already-handled during remediation (no change needed):

- `frame_mac_seed` is authenticated — bound in `SchrodingerManifest.pack_core_for_auth()`.
- Nonce reuse detection is exact and lock-atomic (`nonce.py`); not a lossy LRU.
- Bulk channels (primary/secondary/temporal/disposal/tertiary) were already bound by the
  outer HMAC over the reassembled concatenation.

Deferred (needs a design decision / Rust changes): Schrödinger plaintext-size timing
leak (size-class padding), per-message embedding-seed salt, explicit protocol-version
downgrade resistance.

---

## Table of contents

**Stego carrier / embedding modules**
1. [stego_advanced.py](#1-stego_advancedpy)
2. [stego_gif_binary.py](#2-stego_gif_binarypy)
3. [stego_multilayer.py](#3-stego_multilayerpy) — *crypto-heavy*
4. [adversarial_carrier.py](#4-adversarial_carrierpy)
5. [decorrelation.py](#5-decorrelationpy)
6. [metadata_obfuscation.py](#6-metadata_obfuscationpy)
7. [size_normalizer.py](#7-size_normalizerpy)
8. [decoy_generator.py](#8-decoy_generatorpy)
9. [schrodinger_encode.py](#9-schrodinger_encodepy) — *crypto-heavy*
10. [schrodinger_decode.py](#10-schrodinger_decodepy) — *crypto-heavy*
11. [dual_stream.py](#11-dual_streampy) — *crypto-heavy*
12. [logo_eyes.py](#12-logo_eyespy)
13. [cat_blink.py](#13-cat_blinkpy)
14. [gif_handler.py](#14-gif_handlerpy)
15. [decode_gif.py](#15-decode_gifpy)
16. [qr_code.py](#16-qr_codepy)

**Shared crypto helpers**
- [crypto.py](#crypto-py)
- [crypto_backend.py](#crypto_backend-py)
- [nonce.py](#nonce-py)
- [frame_mac.py](#frame_mac-py)

**[Cross-cutting findings & auditor checklist](#cross-cutting-findings--auditor-checklist)**

---

## Crypto stack at a glance

| Concern | Primitive | Where |
|---|---|---|
| AEAD encryption | AES-256-GCM (Rust handle backend) | `crypto_backend.aes_gcm_encrypt/decrypt` |
| Password KDF | Argon2id (configurable presets) | `crypto.py`, `argon2_presets.py` |
| Key derivation / domain separation | HKDF-SHA256 | `crypto_backend.derive_key_hkdf`, `nonce.py` |
| Message authentication | HMAC-SHA256 (manifest); HMAC-SHA256 truncated to 8 B (frame MAC) | `crypto.py`, `frame_mac.py` |
| Hashing | SHA-256 | throughout |
| CSPRNG | `secrets`, `os.urandom` | throughout |
| Non-crypto PRNG (obfuscation only) | SHA-256 hash-chain, NumPy Mersenne Twister | `adversarial_carrier.py`, `stego_multilayer.py` |
| Constant-time compare | `secrets.compare_digest`, Rust `constant_time_compare` | `frame_mac.py`, `dual_stream.py`, `schrodinger_decode.py` |

**Architectural rule:** secret key material lives inside opaque Rust *handles*; the
Python layer never sees raw key bytes. A Python crypto fallback exists for some stego
PRNG paths and is explicitly documented as **NOT constant-time / test-only**. Production
code gates on the Rust backend being present.

---

## 1. `stego_advanced.py`

**Role:** Advanced LSB steganography — adaptive bit-depth (1–3 bits), Floyd–Steinberg
dithering, PSNR quality metric, optional visual obfuscation.

**Crypto used:**
- `import secrets` (line ~19); `secrets.randbits(32)` (line ~150) — animation seed (non-security).

**Shared helpers:** none (PIL/NumPy only).

**Auditor notes:**
- ✅ No real crypto; pure LSB embedding. Payload must be pre-encrypted by the caller.
- ⚠️ LSB stego is inherently steganalysis-detectable (acknowledged in comments).
- ⚠️ PSNR threshold is a cosmetic quality gate, not a security control.

---

## 2. `stego_gif_binary.py`

**Role:** GIF89a binary parser/editor exposing stego channels (GCE disposal bits,
comment-extension injection, application-extension handling).

**Crypto used:** none — pure format manipulation.

**Shared helpers:** none.

**Auditor notes:**
- ✅ No crypto. Module header correctly states embedded data **MUST be pre-encrypted and
  MAC'd by the caller**.

---

## 3. `stego_multilayer.py`

**Role:** Production multi-channel stego — primary LSB walk + STC (Syndrome-Trellis
Codes), GIF timing channel, palette permutation, disposal/comment channels, temporal
inter-frame deltas, saliency-adaptive embedding costs, coercion resistance. **This is the
crypto-heaviest stego module.**

**Crypto used — Rust backend (primary path):**
- `import meow_crypto_rs` (line ~71); capability probe `stego_derive_frame_seed` (line ~74).
- `stego_derive_frame_seed()` — HKDF-SHA256 per-frame seed (line ~407).
- `stego_derive_walk_seed()` — walk permutation seed (line ~414).
- `stego_generate_pixel_walk()` — Rust Fisher–Yates shuffle (line ~441).
- `stego_compute_adaptive_costs()` + `stego_stc_encode()` (lines ~905–920); `stego_stc_decode()` (line ~989).
- `stego_timing_encode/decode()` (lines ~1042 / ~1093).
- `stego_palette_encode/decode()` (lines ~1222 / ~1301).
- Channel subkey derivation via HMAC-SHA256 inside Rust (`_derive_channel_subkey_handle`, line ~95); opaque key import (`_import_master_key_handle`, line ~128); handle zeroization (`_drop_handle_safe`, lines ~116–125).

**Crypto used — Python fallback (test-only, NOT constant-time):**
- `_py_derive_frame_seed()` — HKDF extract+expand via `hashlib.sha256` + `hmac` (lines ~321–347).
- `_py_derive_walk_seed()` (lines ~350–360).
- `_py_generate_pixel_walk()` — SHA-256 hash-chain PRNG with rejection sampling (lines ~363–396).
- `_py_palette_encode()` — Lehmer-code permutation, SHA-256-seeded with rejection sampling (lines ~1306–1344).

**Crypto used — payload protection (`prepare_payload`, lines ~476–543):**
- `zlib.compress(level=9)` (line ~499) — compression (not crypto).
- AES-256-GCM via `hb.aes_gcm_encrypt()` (lines ~527–534); nonce `os.urandom(12)` (line ~531).
- Outer HMAC-SHA256 via `hb.hmac_sha256_to_handle()` + `hb.hmac_sha256()` (lines ~540–541).

**HKDF domain-separation labels (lines ~214–222, ~332–335):**
`meow_stego_primary_lsb_v1`, `..._secondary_timing_v1`, `..._tertiary_palette_v1`,
`..._disposal_gce_v1`, `..._comment_ext_v1:enc`, `..._comment_ext_v1:mac`,
`..._saliency_cost_v1`, `..._immunize_noise_v1`, `..._temporal_delta_v1`,
`..._adversarial_perturb_v1`, `..._procedural_cat_v1`.

**Shared helpers:** `stego_gif_binary`, `crypto_backend.get_handle_backend`.

**Auditor notes:**
- 🔴 **Python fallback path (lines ~321–396, ~1328–1330)** uses SHA-256 chaining as a
  PRNG and is **not constant-time** (documented). Confirm production gates on Rust
  availability (checks at ~880, ~985) and that the fallback cannot be reached in prod.
- ⚠️ `np.random.randint()` (NumPy Mersenne Twister, ~line 274) for obfuscation noise —
  **not a CSPRNG**, but scoped to visual obfuscation (acceptable if it never gates secrecy).
- ✅ HKDF domain separation per channel; secret keys stay in Rust handles; handles
  zeroized; Fisher–Yates uses rejection sampling (avoids modulo bias).

---

## 4. `adversarial_carrier.py`

**Role:** Procedural noise generator to resist steganalysis (sensor/texture/DCT-matched
noise, histogram equalization).

**Crypto used:**
- `import secrets`; `secrets.token_bytes(32)` seed (line ~145).
- `SeededRNG` (lines ~75–122): SHA-256 hash-chain PRNG — `hashlib.sha256(seed)` init (line ~83),
  counter-based `_next_block()` (line ~89), `random_float` / `random_gaussian` (Box–Muller) /
  `randint` with rejection sampling.

**Shared helpers:** none.

**Auditor notes:**
- ⚠️ `SeededRNG` is **explicitly NOT cryptographically secure** (docstring) — used for
  procedural noise only; verify it is never used to derive key material or nonces.
- ⚠️ Self-described as "detection-resistant ≠ detection-proof"; DCT-matched noise is simplified.

---

## 5. `decorrelation.py`

**Role:** Inter-file decorrelation to defeat fingerprinting (jitter block size, redundancy,
FPS, QR border).

**Crypto used:**
- `_csprng_int()` — `os.urandom(4)` + rejection sampling against modulo bias (lines ~62–81).
- `_csprng_float()` — `os.urandom(8)` (lines ~84–96).

**Shared helpers:** none.

**Auditor notes:**
- ✅ Correct CSPRNG (`os.urandom`) with proper rejection sampling; security-critical
  parameters explicitly left unmodified.

---

## 6. `metadata_obfuscation.py`

**Role:** Metadata obfuscation — length padding to size classes, frame-order
randomization, frame-count padding, parameter obfuscation.

**Crypto used:**
- `import secrets`; padding `secrets.token_bytes()` (line ~96); shuffle seed
  `secrets.token_bytes(32)` (line ~177); decoy frames `secrets.token_bytes()` (line ~249);
  param offset `secrets.randbelow()` (line ~277).
- HMAC-SHA256 deterministic Fisher–Yates shuffle: `hmac.new(seed, i.to_bytes(4,"big"), sha256)`
  (lines ~184–191).

**Shared helpers:** none.

**Auditor notes:**
- ✅ Proper `secrets` usage; HMAC-based deterministic shuffle is sound; seed gives domain separation.
- ⚠️ Parameter obfuscation (line ~273) is **mild obfuscation only** (acknowledged) — not adversarially secure.

---

## 7. `size_normalizer.py`

**Role:** Normalize payload size to fixed size classes (4 KB–64 MB) and frame count to a
quantum to suppress size side-channels.

**Crypto used:**
- `import secrets`; `secrets.token_bytes(pad_len)` padding (line ~137).

**Shared helpers:** none.

**Auditor notes:**
- ✅ Proper CSPRNG padding. Frame-count padding relies on fountain redundancy (valid
  droplets). Length header integrity relies on the authenticated manifest, not this module.

---

## 8. `decoy_generator.py`

**Role:** Generate innocent decoy files (PDFs, shopping lists, fake JPEGs, ZIPs) for
plausible deniability.

**Crypto used:**
- `import secrets`; `secrets.SystemRandom()` sampling (lines ~107, ~132);
  `secrets.randbelow()` (lines ~109, ~111, ~136); `secrets.token_bytes()` fake body (line ~124).

**Shared helpers:** none.

**Auditor notes:**
- ✅ Decoy content generation only; CSPRNG used throughout. Not a cryptographic component
  itself, but relevant to the deniability threat model.

---

## 9. `schrodinger_encode.py`

**Role:** Dual-reality ("Schrödinger's Yarn Ball") encoder — two independent secrets
interleaved for plausible deniability. **Crypto-heavy.**

**Crypto used:**
- Argon2id KDF for both realities via `hb.derive_key_argon2id()` (lines ~295–308); params
  `ARGON2_MEMORY / ITERATIONS / PARALLELISM` imported from `crypto` (lines ~34–39).
- HKDF domain separation: `schrodinger_enc_key_v1`, `schrodinger_hmac_key_v1` (lines ~311–314).
- AES-256-GCM metadata encryption `hb.aes_gcm_encrypt()` (lines ~335–336).
- Manifest HMAC-SHA256 `hb.hmac_sha256()` (lines ~358–359).
- CSPRNG: salts `secrets.token_bytes(16)` (line ~261), nonces `secrets.token_bytes(12)` (line ~263),
  `frame_mac_seed` `secrets.token_bytes(16)` (line ~270, **public, not secret**).
- Reality interleaving via `quantum_mixer.entangle_realities` (line ~287).

**Shared helpers:** `crypto`, `crypto_backend`, `fountain`, `qr_code`, `gif_handler`,
`frame_mac`, `quantum_mixer`.

**Auditor notes:**
- 🔴 Verify identical-password rejection (lines ~252–256) — prevents deniability collapse.
- ✅ Key handles never exposed to Python; both Argon2id derivations run (no timing oracle);
  intermediate handles dropped/zeroized; `frame_mac_seed` is authenticated in the manifest core (line ~138).
- ⚠️ Confirm `frame_mac_seed` is treated as public (stored plaintext) and never as a key.

---

## 10. `schrodinger_decode.py`

**Role:** Timing-equalized dual-reality decoder. **Crypto-heavy; timing-safety critical.**

**Crypto used:**
- **Always** derives both Argon2id master keys regardless of which password matches
  (`hb.derive_key_argon2id()`, lines ~75–88) — timing equalization.
- HKDF both HMAC/enc keys (`hb.derive_key_hkdf()`, lines ~91–102), labels
  `schrodinger_hmac_key_v1` / `schrodinger_enc_key_v1`.
- HMAC-SHA256 for both realities (lines ~106–107).
- Constant-time compare `constant_time_compare()` (lines ~114–115).
- AES-256-GCM both metadata decrypt attempts, exceptions swallowed for parity (lines ~145–157).
- Timing jitter `time.sleep(secrets.randbelow(10)/1000.0)` (line ~167).

**Shared helpers:** `crypto`, `crypto_backend`.

**Auditor notes:**
- 🔴 **Timing equalization is the core security property** — verify both Argon2id runs,
  both HMAC checks, both enc-key derivations, and both metadata decrypts execute on every
  call (lines ~75–157). This is the highest-value audit target in the stego suite.
- 🔴 Acknowledged **NOT-EQUALIZED**: actual file decryption only runs for the matched
  reality (lines ~64–70, ~187–217) because plaintext sizes differ. Assess residual leakage.

---

## 11. `dual_stream.py`

**Role:** Always-dual encoder — produces two independent sub-streams always; single-secret
mode emits a *real encrypted* dummy stream for indistinguishability. **Crypto-heavy.**

**Crypto used:**
- Argon2id for both streams `hb.derive_key_argon2id()` (lines ~301–314).
- HKDF labels `meow_dual_enc_a_v1`, `meow_dual_enc_b_v1`, `meow_dual_hmac_a_v1`,
  `meow_dual_hmac_b_v1` (lines ~68–71), applied lines ~316–319.
- AES-256-GCM both streams `hb.aes_gcm_encrypt()` (lines ~347–348).
- HMAC-SHA256 both streams `hb.hmac_sha256()` (lines ~373–374).
- CSPRNG: dummy password `secrets.token_bytes(32)` (line ~261), dummy data / padding / salts /
  nonces `secrets.token_bytes()` (lines ~262, ~285, ~292, ~296–299).
- Constant-time HMAC verification `secrets.compare_digest()` both checks (lines ~461–464).

**Shared helpers:** `crypto`, `crypto_backend`.

**Auditor notes:**
- 🔴 **`flags = 0x00` ALWAYS (line ~270)** — stream type must **never** be encoded in
  plaintext (this was previously a critical vuln). Verify it stays constant.
- 🔴 Constant-time decode always derives both Argon2ids and both HMACs before any branch
  (lines ~432–449). Verify no early-exit leaks single- vs dual-secret mode.
- ✅ Dummy stream is a genuine encryption under an intentionally-unknown password (lines ~243–268).
- ⚠️ Per-stream file-size differences may leak mode statistically (acknowledged, lines ~45–49).

---

## 12. `logo_eyes.py`

**Role:** Embed QR codes visibly in the logo's eye regions, or LSB-embed in those regions.

**Crypto used:** none (NumPy image processing).

**Auditor notes:** ✅ No crypto; carrier generation + LSB only.

---

## 13. `cat_blink.py`

**Role:** Cat-mode blink protocol — encode 2 bits per blink frame via green-eye blinks.

**Crypto used:** none (signal processing / statistical period estimation).

**Auditor notes:** ✅ No crypto.

---

## 14. `gif_handler.py`

**Role:** Assemble GIF animations from QR frames (FPS, loop count) via PIL.

**Crypto used:** none directly.

**Auditor notes:** ✅ No crypto; transport/encoding. Payload is encrypted upstream.

---

## 15. `decode_gif.py`

**Role:** GIF decoder CLI — reconstructs a file from a GIF animation.

**Crypto used:** no primitives implemented here; orchestrates the crypto helpers it imports
(`crypto`, `crypto_backend`, `fountain`, `qr_code`, `gif_handler`) — lines ~18–30.

**Auditor notes:** ⚠️ Decryption/verification happens through the imported helpers — audit
those for the actual primitives; this file is glue/CLI.

---

## 16. `qr_code.py`

**Role:** QR generation (`qrcode`) and reading (`pyzbar` + OpenCV).

**Crypto used:** none. `base64.b85encode()` (line ~90) is encoding, not crypto.

**Auditor notes:** ✅ No crypto; data encoding only.

---

# Shared crypto helpers

<a id="crypto-py"></a>
## `crypto.py`

- `MAGIC = b"MEOW3"` manifest magic (line ~50).
- Argon2 parameters via preset system (lines ~62–65); `MANIFEST_HMAC_KEY_PREFIX =
  b"meow_manifest_auth_v2"` (line ~68).
- `build_canonical_aad()` — AAD construction for AES-GCM (lines ~109–153).
- `Manifest` dataclass with optional forward secrecy (`ephemeral_public_key`) and
  post-quantum (`pq_ciphertext`) fields (lines ~156–192).
- Primitives: AES-256-GCM (handle), HMAC-SHA256, SHA-256, HKDF (via AAD/domain separation), Argon2id.
- ⚠️ Python fallback documented as **NOT constant-time** (line ~328). `PRODUCTION_MODE` guard (lines ~35–46).

<a id="crypto_backend-py"></a>
## `crypto_backend.py`

- Rust backend availability check (lines ~22–35); `_PRODUCTION_MODE` guard (lines ~27–28, "CRIT-03").
- `RustCryptoBackend`: `derive_key_argon2id()` (~96–114), `derive_key_hkdf()` (~116),
  `aes_gcm_encrypt()` (~141–144), `aes_gcm_decrypt()` (~146–149).
- ✅ `PythonCryptoBackend` has been **removed**; Rust backend is **required** in production.

<a id="nonce-py"></a>
## `nonce.py`

- HKDF info labels `aes-gcm-nonce-v1` (line ~49), `aes-gcm-transfer-v1` (line ~56).
- `NonceGenerator` with reuse detection (lines ~62–209); `generate()` HKDF-derived
  deterministic nonce (lines ~102–149); `generate_for_transfer()` context-bound (lines ~151–203).
- ✅ HKDF-SHA256 nonce derivation; bounded SACK-style reuse window; thread-safe (lock at ~85).

<a id="frame_mac-py"></a>
## `frame_mac.py`

- `MAC_SIZE = 8` — 64-bit **truncated** HMAC-SHA256 (rationale lines ~6–47).
- `compute_frame_mac()` via Rust handles (lines ~146–194); `verify_frame_mac()` with
  `secrets.compare_digest()` (lines ~196–230); HKDF key derivation (lines ~72–143).
- ✅ Truncation justified as a DoS pre-filter; full security from layered defense
  (frame MAC + manifest HMAC + AES-GCM).

---

# Cross-cutting findings & auditor checklist

### Strengths
- Crypto is Rust-backed (constant-time intent via `subtle`, zeroization via `zeroize`).
- Handle-based design: raw secret keys never reach Python.
- Comprehensive HKDF domain separation across every stego channel and mode.
- Timing equalization in dual-reality / dual-stream decode paths.
- CSPRNG (`secrets`, `os.urandom`) used for all security-relevant randomness; rejection
  sampling used to avoid modulo bias.
- Nonce reuse detection with bounded memory; multi-layer authentication.

### 🔴 Critical items to verify
1. **Python crypto/PRNG fallback** in `stego_multilayer.py` (lines ~321–396, ~1328–1330)
   is NOT constant-time. Confirm production hard-gates on the Rust backend and the fallback
   is unreachable outside tests.
2. **Timing equalization** in `schrodinger_decode.py` (~75–167) and `dual_stream.py`
   (~432–464): confirm both Argon2id derivations, both HMAC checks, both decrypt attempts
   always run; profile for residual differences.
3. **`dual_stream.py` `flags = 0x00`** (line ~270) must never encode stream type in plaintext.
4. **Acknowledged size leakage** in dual-stream / Schrödinger non-equalized file decryption —
   assess whether plaintext-size differences are an acceptable residual.

### ⚠️ Non-CSPRNG usage (must remain non-security)
- `adversarial_carrier.SeededRNG` (SHA-256 hash-chain) and `stego_multilayer` NumPy
  `np.random.randint()` are noise/obfuscation only. Confirm neither ever derives keys, nonces,
  salts, or embedding seeds that gate confidentiality.

### Build/runtime checks for the auditor
- Confirm `meow_crypto_rs` is built with overflow checks and pinned `subtle` / `zeroize` versions.
- Unit-test `NonceGenerator` reuse window under concurrent decode.
- Treat all stego channels as an **obfuscation layer**, not a confidentiality primitive — the
  confidentiality/authentication guarantees come from AES-256-GCM + Argon2id + HMAC, not from
  the LSB/STC/timing/palette embedding itself.
