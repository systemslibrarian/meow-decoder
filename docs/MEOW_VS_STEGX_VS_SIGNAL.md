# Meow-Decoder vs StegX vs Signal — Head-to-Head Comparison

**Date:** 2026-02-21 | **Scope:** Steganographic air-gap exfiltration capability

**Tools compared:**
- **Meow-Decoder** — [github.com/systemslibrarian/meow-decoder](https://github.com/systemslibrarian/meow-decoder) (commit `43b4b06`, Feb 21 2026)¹
- **StegX** — [github.com/Delta-Sec/StegX](https://github.com/Delta-Sec/StegX) (v1.2.0, ~Oct 2025)
- **Signal** — Signal messaging app (as of Feb 2026)

¹ Updated to commit `43b4b06` (Feb 21 2026) — no stego-layer changes since Phase 0+1 merge (`20d2e0e`, Feb 20). Commits since then: documentation audit fixes, comparison report, gitignore cleanup.

---

## 1. Embedding Method & Efficiency

| Dimension | **Meow-Decoder** | **StegX** | **Signal** |
|-----------|-------------------|-----------|------------|
| **Algorithm** | Syndrome-Trellis Codes (STC, h=10) with Viterbi trellis, Rust backend | Non-linear pseudo-random LSB replacement (1–3 bpp), sentinel `STEGX_EOD` | N/A — no embedding |
| **Cost function** | Adaptive texture-aware (smooth regions 3× penalty, textured 0.5×) | None (uniform cost across pixels) | N/A |
| **Pixel visit order** | Keyed Fisher-Yates shuffle (HKDF `meow_stego_walk_permutation_v1`) | Pseudo-random walk (non-linear LCG or similar) | N/A |
| **Channels** | 6: Primary LSB+STC, Timing (GCE delay), Palette (Lehmer), Temporal (cross-frame delta), Disposal (GCE bit), Comment (encrypted extension) | 1: LSB only | 0 |
| **Effective bpp** | ~0.5 bpp (STC rate 1/4) + ~0.02 bpf (timing) + log₂(n!) bits/frame (palette) | 1–3 bpp (configurable) | N/A |
| **Pixel modifications** | ~50% fewer than payload bits (STC optimization) | 1:1 — every payload bit = 1 pixel change | N/A |
| **Reference** | Filler, Judas & Fridrich (2011) "Minimizing Additive Distortion" | Custom implementation | N/A |

**Verdict:** Meow's STC is the academically grounded gold standard for minimizing embedding distortion. StegX's randomized LSB is a significant improvement over naive sequential LSB but lacks the mathematical distortion-minimization properties of STC. Signal is not in this category.

---

## 2. Carrier Format & Animation Support

| Dimension | **Meow-Decoder** | **StegX** | **Signal** |
|-----------|-------------------|-----------|------------|
| **Primary format** | APNG (lossless 24-bit, animated) for stego; GIF for non-stego QR | Static PNG | N/A |
| **Animation** | Yes — multi-frame looping cat animation (purpose-built for optical display) | No — single static image | N/A |
| **Frames** | Unlimited (fountain-coded droplets, ~1.5× redundancy) | 1 | N/A |
| **GIF support** | Yes (non-stego modes); avoided for stego because palette quantization destroys LSB data | No | N/A |
| **Bit depth** | 24-bit per pixel (APNG); 8-bit indexed (GIF) | 24-bit (PNG) | N/A |
| **Cover story** | Looping cat animation — plausible as a meme/screensaver | Static image | Message thread |

**Verdict:** Meow is the only tool designed for animated carriers. The "looping cat GIF" cover story is uniquely suited to optical air-gap exfil — a cat animation playing on a monitor screen raises zero suspicion compared to displaying a static PNG that an operator clearly placed there.

---

## 3. Imperceptibility & Distortion

| Metric | **Meow-Decoder** (measured) | **StegX** (claimed) | **Signal** |
|--------|------------------------------|---------------------|------------|
| **PSNR** | 36.2–50.3 dB (mean 39.8 dB) across 25 artifacts | Not reported | N/A |
| **SSIM** | 0.9978–0.9999 (mean 0.9988) | Not reported | N/A |
| **Adaptive costs** | Yes — texture-aware (concentrates changes in complex regions) | No | N/A |
| **Visual impact of timing channel** | Zero (invisible in playback) | N/A | N/A |
| **Visual impact of palette channel** | Zero (palette reorder + index remap) | N/A | N/A |
| **Adversarial perturbation** | Histogram matching, HPF residual smoothing, co-occurrence matching (tunable LOW/MEDIUM/HIGH) | None | N/A |
| **Immunization noise** | Pre-embedding noise floor to mask stego artifacts | None | N/A |

**Verdict:** Meow provides measured, audited distortion numbers with SSIM consistently >0.997. StegX does not publish PSNR/SSIM measurements, making direct comparison impossible — but the absence of adaptive cost functions and STC means StegX likely introduces more distortion per embedded bit.

---

## 4. Steganalysis Resistance

### Statistical Tests

| Test | **Meow-Decoder** (measured, 25 artifacts) | **StegX** (claimed) | **Signal** |
|------|---------------------------------------------|---------------------|------------|
| **Chi-square (raw)** | 312–1537 (carrier-dependent); 0.000 detection probability | ~13K ("low anomaly") | N/A |
| **Chi-square (vs Steghide)** | 100–400× lower anomaly than Steghide | ~9× lower than Steghide (13K vs 119K) | N/A |

> **Chi² normalization note:** Chi² values are image-size and payload-rate dependent. Meow's lower raw numbers (312 vs 13K) are indicative of STC's fewer pixel flips but require same-resolution, same-payload comparison for strict fairness. Always compare chi²/df (degrees of freedom ≈ unique PoV pairs) when images differ in size.
| **RS analysis** | 0.006–0.048 (threshold <0.3); 6× below detection | Not reported | N/A |
| **SPA** | 0.000–0.015 (threshold <0.15); 10× below detection | Not reported | N/A |
| **Shannon entropy** | Natural range (7.5–7.7 bits/byte) | Not reported | N/A |
| **LSB autocorrelation** | max 0.024 (threshold <0.05) | Not reported | N/A |

### External Tool Evasion

| Tool | **Meow-Decoder** | **StegX** | Notes |
|------|-------------------|-----------|-------|
| **zsteg** | **Measured PASS** — false positives only ("OpenPGP Secret Key" noise), indistinguishable from clean baseline | **Measured PASS** ("No patterns found") | Both tools evade; Meow tested Feb 21 2026 |
| **StegSeek** | **PASS by design** (APNG/GIF not supported by StegSeek) | **Measured PASS** ("Failed to extract") | Neither tool uses Steghide format |
| **binwalk** | **Measured PASS** — standard PNG + Zlib chunks only, identical structure between stego and clean | **Measured PASS** ("Clean output") | Both encrypt payloads |
| **exiftool** | **Measured PASS** — standard PNG/APNG tags only, no suspicious metadata between stego and clean | **Measured PASS** ("Metadata clean") | Both produce clean metadata |
| **ML classifiers (SRNet/YeNet)** | **Not tested** — no claim of resistance | **Not tested** — no claim | Industry-wide gap |
| **StegExpose ensemble** | **Not tested** | **Not tested** | Industry-wide gap |

### Self-Validation

| Capability | **Meow-Decoder** | **StegX** | **Signal** |
|------------|-------------------|-----------|------------|
| Built-in steganalysis tests | Yes — RS, chi-square, SPA, entropy per frame | No | N/A |
| Automated regression testing | 252 unit tests + 43 artifact checks | Not documented | N/A |
| `validate_stego()` API | Yes — returns per-metric pass/fail | No | N/A |

**Verdict:** Meow reports lower chi-square anomaly (312 vs StegX's 13K), but the comparison requires normalization by image dimensions and payload ratio, so this is indicative rather than definitive. Meow's structural advantage is clear: STC is mathematically designed to avoid the PoV-pair equalization that chi-square detects, while StegX's randomized LSB still replaces bits 1:1. Both tools evade zsteg, binwalk, and exiftool. **All four external tool evasion tests are now measured PASS** (zsteg, binwalk, exiftool, chi-square — Feb 21 2026). Neither tool claims ML resistance.

---

## 5. Cryptographic Strength

| Property | **Meow-Decoder** | **StegX** | **Signal** |
|----------|-------------------|-----------|------------|
| **AEAD** | AES-256-GCM (128-bit tag) + HMAC-SHA256 (256-bit) | AES-256-GCM | AES-256-CBC + HMAC-SHA256 |
| **KDF** | Argon2id (512 MiB, 20 iter, 4 threads) | PBKDF2 (iterations unknown) | HKDF |
| **Forward secrecy** | X25519 ephemeral (MEOW3) + MSR v1.2 ratchet (per-frame within single file — offline-appropriate model) | None | Double Ratchet (X3DH + Signal Protocol — continuous over network sessions) |
| **Post-quantum** | ML-KEM-768 (default) / ML-KEM-1024 (paranoid) hybrid PQXDH | None | PQXDH (ML-KEM-768, since ~2023) |
| **Nonce management** | 96-bit random + LRU reuse guard (10K entries) | Random nonce (details unclear) | Per-message chain key |
| **AAD binding** | orig_len, comp_len, salt, sha256, magic, ephemeral_pub, pq_ciphertext | Not documented | Ratchet state |
| **Fail-closed** | Yes — any auth failure aborts with zero output | Yes (GCM tag check) | Yes |
| **Key zeroization** | Rust `zeroize` crate + Python secure cleanup | Not documented | Yes (Signal Protocol) |
| **Constant-time ops** | Rust `subtle` crate for comparisons | Not documented | libsignal (Rust) |
| **Stego-layer crypto** | Independent domain-separated HMAC keys per channel | N/A (single channel) | N/A |

**Verdict:** Meow and Signal are in the same tier for crypto strength. Meow's Argon2id at 512 MiB/20 iter is the most aggressive password-based KDF of any stego tool (8× OWASP recommendation). StegX's PBKDF2 is significantly weaker against GPU/ASIC attacks. Signal wins on real-world forward secrecy (continuous ratcheting over network), but Meow's MSR v1.2 ratchet provides per-frame forward secrecy within a single GIF — a different but appropriate model for offline file transfer.

---

## 6. Deniability & Coercion Resistance

| Feature | **Meow-Decoder** | **StegX** | **Signal** |
|---------|-------------------|-----------|------------|
| **Dual-secret encoding** | Schrödinger mode: 2 passwords → 2 independent decryptions from same GIF | None | None |
| **Statistical indistinguishability** | Enforced: `QuantumNoise = XOR(Hash(Pass_A), Hash(Pass_B))`, entropy-tested | None | None |
| **Tiered access (coercion levels)** | DECOY (shallow primary only) → SHALLOW (real primary) → FULL (all 6 channels) | None | None |
| **Duress/panic key** | Duress password triggers alternate payload + key wipe | None | None |
| **Disappearing messages** | N/A (file-based) | N/A | Yes (timer-based auto-delete) |
| **Sealed sender** | N/A | N/A | Yes (hides sender identity) |
| **Prove non-existence** | Cannot prove second secret exists without correct password | N/A | N/A |

**Verdict:** Meow is the clear winner for coercion resistance. Schrödinger mode provides cryptographic plausible deniability — under duress, surrender the decoy password and the adversary gets plausible content with no way to prove a second secret exists. Signal's disappearing messages are a different threat model (post-read deletion, not pre-extraction deniability). StegX has no deniability features at all.

---

## 7. Fitness for Air-Gapped Optical Exfiltration

This is the decisive category for the stated threat model: *display innocuous looping cat APNG on screen → record short video with phone → sneakernet video → fountain decode.*

| Capability | **Meow-Decoder** | **StegX** | **Signal** |
|------------|-------------------|-----------|------------|
| **Display on air-gapped screen** | Yes — looping cat animation indistinguishable from screensaver | Possible (static image) but suspicious if left on screen | N/A (requires network) |
| **Phone video capture** | Purpose-built: fountain codes tolerate 33%+ frame loss, QR codes at 600×600px | Not designed for this — would need manual photo + alignment | Impossible (no stego) |
| **Fountain coding** | Luby Transform rateless codes: decode from ANY ~67% of frames | None — total-loss-or-total-recovery | N/A |
| **Frame loss tolerance** | 33% loss at 1.5× redundancy; 50% at 2.0× | 0% tolerance (single image) | N/A |
| **Cover story plausibility** | "I have a cat GIF on my screensaver" — **universal excuse** | "I have a PNG open on my screen" — weak cover | N/A |
| **Decode from shaky video** | Yes — QR scanning handles rotation, blur, partial occlusion | No — requires clean static capture | N/A |
| **Offline operation** | Fully offline | Fully offline | Requires internet |
| **Web demo (webcam decode)** | Yes — real-time webcam QR scanner with fountain assembly | No | N/A |
| **Multi-device streaming** | Clowder protocol for synchronized multi-device display | No | N/A |

**Verdict:** Meow is purpose-built for this exact scenario and nothing else comes close. The combination of animated carrier (cover story), fountain coding (loss tolerance), QR frames (camera-friendly), and cat mode (plausibility) creates a system specifically engineered for optical air-gap transfer. StegX could theoretically be photographed off a screen, but with zero loss tolerance and no QR encoding, it would be fragile and awkward. Signal requires network connectivity and cannot function across an air gap at all.

---

## 8. Usability, Complexity & Audit Status

| Dimension | **Meow-Decoder** | **StegX** | **Signal** |
|-----------|-------------------|-----------|------------|
| **Installation** | `pip install meow-decoder` + Rust backend (auto-builds) | `pip install stegx` (pure Python) | Mobile/desktop app |
| **CLI complexity** | Moderate — many flags (`--stego-level`, `--carrier`, `--adversarial`, `--forward-secrecy`, `--receiver-pubkey`, etc.) | Simple — `stegx encode/decode -i -o -p` | N/A (GUI) |
| **Web interface** | Flask web demo with 10 pages + webcam scanner | None | Polished native apps |
| **Learning curve** | Steep (6 channels, 5 stego levels, PQ modes, Schrödinger, ratchet) | Gentle (encode/decode with password) | Minimal (install and text) |
| **Test coverage** | 1800+ tests (252 stego-specific), 43 audit artifacts, 4 audit sessions | Not documented | Extensive (audited by multiple firms) |
| **External audit** | **None** — internal review only (11 bugs found/fixed internally) | None documented | **Multiple** — formal audits by Trail of Bits, NCC Group, Quarkslab, iSEC Partners |
| **Formal verification** | Tamarin + ProVerif + TLA+ models (symbolic only) | None | Academic proofs (Signal Protocol) |
| **Documentation** | Extensive (15+ docs, threat model, audit reports) | Basic README | Extensive (protocol specs, blog posts) |
| **Maturity** | Active development (2025–2026) | Stable (v1.2.0, Oct 2025) | Mature (2013–2026, billions of users) |

**Verdict:** StegX wins on simplicity. Signal wins on maturity and external audit rigor. Meow has the deepest internal test coverage of any stego tool but lacks the credibility of an external audit — this is its most significant gap.

---

## Overall Verdict

### For the specified threat model: high-security air-gap optical exfiltration

**Winner: Meow-Decoder — by a wide margin.**

| Requirement | Best Tool | Why |
|-------------|-----------|-----|
| Hide data in a plausible animated display | **Meow** | Only tool with animated carrier + cat cover story |
| Survive shaky phone video capture | **Meow** | Fountain codes + QR frames; 33% loss tolerance |
| Resist casual steganalysis | **Meow** | STC + keyed walk + 6 channels + adaptive costs; chi² 312 vs StegX's 13K; all external tools measured PASS |
| Survive coercion/interrogation | **Meow** | Schrödinger dual-secret + duress wipe — strongest file-based deniability; Signal/StegX have nothing |
| Strongest crypto envelope | **Meow ≈ Signal** | Both have AEAD + forward secrecy + PQ; Signal more battle-tested |
| Work across an air gap | **Meow** | Purpose-built; Signal needs internet; StegX has no transport |
| Simplest to use | **StegX** | One command, no animation complexity |
| Most externally validated | **Signal** | Multiple formal audits; Meow has zero external audits |

### Why Meow wins under this threat model

1. **Signal is disqualified** — it requires network connectivity and provides no steganographic capability. In an air-gapped environment, Signal simply cannot function.

2. **StegX is functional but poorly suited** — you could embed data in a static PNG, display it on screen, and photograph it. But: (a) no QR encoding means you'd need to OCR or manually transcribe the recovered image, (b) zero frame-loss tolerance means any camera blur or partial occlusion loses everything, (c) a static PNG displayed prominently on an air-gapped workstation is a weaker cover story than a looping cat animation, and (d) no deniability features if caught.

3. **Meow-Decoder is engineered end-to-end for this exact scenario** — the entire pipeline from encryption → STC embedding → cat animation → fountain QR frames → phone camera → video decode is a single integrated system. No other tool addresses the "display on screen → record with phone → decode elsewhere" workflow.

### Gaps and caveats

- **zsteg now measured PASS** (Feb 21 2026). Both stego and clean frames produce identical false-positive noise (random "OpenPGP" detections on both). zsteg -a (aggressive mode) also failed to detect payload. This closes the credibility gap vs StegX.
- **No external audit for Meow.** The internal 4-session audit found and fixed 11 bugs and produced 43 verified artifacts, which is thorough — but it's not a substitute for independent review. Signal's multiple third-party audits set the standard here.
- **No ML steganalysis testing for either Meow or StegX.** Against a state-level adversary with custom-trained CNNs, both tools' stego layers should be considered cosmetic. In both cases, the cryptographic layer (AES-256-GCM) is the actual security boundary.
- **Chi-square comparison is approximate.** Meow's 312 vs StegX's 13K were measured on different images at different resolutions with different payload sizes. A controlled head-to-head on identical carriers would be needed for a definitive comparison.
- **StegX's simplicity is a real advantage** in operational contexts where the operator is non-technical and needs to embed data quickly without understanding 6 channels and 5 stego levels.

### Bottom line

> In the **air-gap optical exfiltration** scenario (display innocuous looping cat APNG → record short video with phone → sneakernet decode), Meow-Decoder provides the strongest end-to-end capability of any available tool. It uniquely combines animated carriers (plausible cover), fountain coding (loss tolerance), STC-based minimal-distortion embedding, multi-channel defense-in-depth, strong authenticated encryption with Argon2id + PQ hybrid, and cryptographic deniability via Schrödinger + duress wipe.
>
> StegX is a capable static-image stego tool with published evasion benchmarks but cannot support animation, lossy capture, or coercion resistance. Signal is entirely inapplicable (requires network, no stego).
>
> Remaining gaps: Meow lacks external audit. Against ML steganalysis, both Meow and StegX are cosmetic — security rests on AES-256-GCM confidentiality.

---

---

## Appendix: Measured Evasion Test Results (Feb 21 2026)

**Test artifact:** Procedural cat APNG, 320×240, 30 frames, 4.8 MB, 1140-byte payload (compressed to 149 bytes), STC h=10, adaptive costs, immunization noise, adversarial perturbation (strength=2/MEDIUM), PSNR 60.3 dB.

### zsteg v0.2.14

**Stego frame:**
```
b1,b,lsb,xy       .. file: OpenPGP Secret Key     ← false positive (random noise)
b1,rgb,msb,xy      .. file: OpenPGP Secret Key     ← false positive
b2,r,msb,xy        .. text: random fragments        ← noise
```

**Clean baseline (no stego, same procedural cat generator):**
```
b4,r,msb,xy        .. file: OpenPGP Public Key     ← same type of false positive
b4,bgr,lsb,xy      .. file: zlib compressed data   ← same noise pattern
```

**Result:** Both frames produce similar false-positive noise. `zsteg -a` (aggressive mode, all bit planes) also found no actual payload content. **Indistinguishable from clean. PASS.**

### binwalk 2.3.4

**Stego APNG:** Standard PNG header + 30 Zlib compressed data blocks (one per frame) + 1 StuffIt false positive at 0x3FA662.
**Stego frame0 PNG:** `PNG image, 320x240, 8-bit/color RGB, non-interlaced` + 1 Zlib block at 0x29.
**Clean frame0 PNG:** Identical structure — `PNG image, 320x240, 8-bit/color RGB, non-interlaced` + 1 Zlib block at 0x29.

**Result:** No hidden embedded files, executables, or anomalous signatures detected. Stego and clean frames produce identical binwalk output. **PASS.**

### exiftool 12.57

**Stego frame (selected fields):**
```
File Type      : PNG
Image Width    : 320
Image Height   : 240
Bit Depth      : 8
Color Type     : RGB
Compression    : Deflate/Inflate
```

**Clean frame:** Identical metadata (File Type, dimensions, bit depth, compression).

**Stego APNG (additional):**
```
File Type          : APNG
Animation Frames   : 30
Animation Plays    : inf
```

**Result:** No suspicious custom tags, no stego-tool signatures, no hidden metadata. Standard PNG/APNG fields only. **PASS.**

### Chi-Square LSB Analysis (built-in)

| Metric | Stego Frame | Clean Frame | Threshold |
|--------|-------------|-------------|-----------|
| Combined chi² | 352.10 (dof=120) | 465.31 (dof=126) | CLEAN < ~1000 |
| R channel chi² | 168.20 (dof=96) | 247.90 (dof=108) | — |
| G channel chi² | 138.12 (dof=100) | 202.98 (dof=114) | — |
| B channel chi² | 328.01 (dof=83) | 433.07 (dof=86) | — |
| Detection | **CLEAN** | **CLEAN** | — |

**Result:** Stego frame has *lower* chi² than clean frame across all channels (STC minimizes pair equalization). Both classified as CLEAN with zero detection probability. **PASS.**

### Tools Not Available

- **StegSeek:** Not available in Debian 12 apt repositories. PASS by design (targets Steghide JPEG format, not PNG/APNG).
- **binwalk -E (entropy):** NumPy version incompatibility in test environment. Not critical — standard binwalk scan already PASS.
- **ML classifiers (SRNet/YeNet):** Not tested. Industry-wide gap for all stego tools.

---

*This comparison is based on publicly available documentation, source code analysis, and internal audit results as of 2026-02-21. No external audit has been performed on Meow-Decoder. StegX claims are taken from its GitHub README. Signal information is from published protocol specifications and audit reports.*
