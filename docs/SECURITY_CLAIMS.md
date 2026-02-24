# Security Claims — Canonical Truth File

**Version:** 1.0.0
**Last Updated:** 2026-02-25
**Status:** This document is the authoritative source of truth for security claims.

---

## What This Project IS

- An optical air-gap file transfer tool that encrypts files into animated GIFs.
- Uses AES-256-GCM authenticated encryption with Argon2id key derivation.
- Implements X25519 ephemeral key exchange for forward secrecy.
- Includes a Signal-inspired symmetric ratchet for per-frame forward secrecy.
  - **Not Signal; no equivalence claim.**
- Offers experimental ML-KEM-768/1024 post-quantum hybrid encryption.
  - **PQ mode is experimental. Not externally audited.**
- Implemented primarily in Rust for crypto primitives (AES-GCM, HKDF, X25519, Argon2id).
- Tested with 3435+ automated tests enforced in CI (2462 Python + 973 Rust).

## What This Project Is NOT

- **Not externally audited.** No third-party security audit has been performed.
- **Not Signal.** The ratchet is inspired by Signal's design but is a different
  protocol operating in a different threat model (unidirectional, air-gapped).
  No equivalence claim is made.
- **Not formally verified** in the mathematical sense. Proof sketches and Tamarin/ProVerif
  models exist as design aids, but CI does not enforce proof checking. The AEAD wrapper
  has Verus annotations but these are not CI-gated.
- **Not NIST-certified.** References to "NIST Level 5" describe the target security
  level of ML-KEM-1024, not a certification status.

## Accurate Language Guide

| Instead of...                       | Say...                                                    |
|-------------------------------------|-----------------------------------------------------------|
| "Signal parity"                     | "Signal-inspired goals"                                   |
| "Signal-grade PCS"                  | "Signal-inspired PCS via asymmetric root rotation"        |
| "NIST Level 5" (as marketing)      | "Targets NIST PQ Level 5 (ML-KEM-1024, experimental)"    |
| "formally verified"                | "proof sketches / Verus annotations (not CI-enforced)"    |
| "security-reviewed v1.0"           | "internal review — no external audit"                     |

## Formal Methods Status

| Artifact                     | Tool         | CI-Enforced? | Status             |
|------------------------------|-------------|--------------|---------------------|
| AEAD wrapper properties      | Verus       | No           | Annotations exist   |
| Protocol models              | Tamarin     | No           | Proof sketches      |
| Protocol models              | ProVerif    | No           | Proof sketches      |
| Domain separation            | Lean 4      | No           | Proof sketches      |
| TLA+ liveness                | TLC         | No           | Design aid          |

**Bottom line:** Formal methods artifacts are design aids and notes, not
proof of correctness. They are NOT CI-enforced. Do not claim "formally
verified" without qualification.

## Steganography Claims

- **NOT steganographically secure** against forensic analysis or ML classifiers.
  Stego provides cosmetic cover against casual observation only.
- Multi-layer stego system has been internally audited (4 sessions, 43 artifacts,
  252 unit tests, 11 bugs fixed). See `docs/STEGO_AUDIT_REPORT.md`.
- Verified steganalysis resistance: RS < 0.05, Chi² = 0.000, SPA < 0.02 across
  all tested configurations. These metrics indicate resistance to basic statistical
  detectors only — ML classifiers are explicitly out-of-scope.
- STC (Syndrome-Trellis Codes) implemented via Rust Viterbi trellis. Rate 1/4,
  100% reliable across all tested seeds. Not externally audited.
- **Known-carrier attacks** are a fundamental limitation (not fixable). If the
  adversary has the original carrier image, stego is trivially detectable.
- APNG output format required — GIF palette quantization destroys LSB stego data.

## Disclosure

If you find a security vulnerability, please report it via the process
described in [SECURITY.md](../SECURITY.md).
