# 🔐 Meow-Decoder Security Audit & Gap-Filling (v1.0)

**Status:** Draft audit scaffold (machine-checkable items + gaps)

This document is a structured audit checklist and gap report for a v1.0 security‑reviewed release. It is intentionally conservative: if a property is undocumented, untested, or unenforced, it is treated as **missing**.

---

## 1) Threat Model (Explicit)

### Attacker Capabilities
- **Passive observer:** can record GIF/QR frames; can observe frame count and timing.
- **Active tampering:** can drop, reorder, replay, or modify frames.
- **Chosen‑input:** can supply crafted files for encode to trigger edge cases.
- **Replay:** can feed old frames into a new decode session.
- **Brute‑force:** can attempt offline password guessing with captured frames.
- **Memory inspection:** can inspect process memory on compromised endpoints.

### Assets
- **Plaintext:** the original file contents.
- **Keys:** derived encryption keys, KDF secrets, ephemeral keys.
- **Metadata:** file size class, frame count, manifest version.
- **Plausibly deniable content:** Schrödinger dual‑secret contents.

### Trust Boundaries
- **Encoder:** trusted host running encode.
- **Decoder:** trusted host running decode.
- **Transport:** untrusted optical channel (screen ↔ camera).
- **User environment:** assumed uncompromised for confidentiality.

### Explicit Non‑Goals
- Protecting against compromised endpoints.
- Defeating physical coercion or legal compulsion.
- Side‑channel resistance beyond constant‑time crypto (power/EM/cache).
- Preventing screen recording / shoulder‑surfing.

---

## 2) Cryptographic Correctness Audit (Initial Findings)

### ✅ Observed / Verified in Code
- **AES‑256‑GCM** uses 12‑byte nonces and AEAD tags.
- **AAD binding** includes sizes, salt, hash, version magic, and ephemeral key (FS).
- **Argon2id** parameters are high (512 MiB, 20 iter) in `crypto.py`.
- **HMAC** uses domain separation and constant‑time comparison.
- **Nonce reuse guard** exists (best‑effort cache).

### ⚠️ Known/Expected Gaps (Require Verification)
- **Rust backend requirement** enforcement needs continuous CI validation.
- **Schrödinger claim** (“neither secret can prove the other exists”) is unproven.


**Required fixes are tracked in Issues section below.**

---

## 3) Protocol Definition (Current State)

Primary protocol spec lives in [docs/protocol.md](protocol.md), which defines:
- Manifest format (byte‑level)
- AAD construction
- Frame MAC format
- Fountain droplet encoding
- Decode failure rules

**Audit action:** ensure protocol.md is the **single source of truth** and is versioned with manifest versions.

---

## 4) Formal Methods Scaffolding (Current State)

- **TLA+**: protocol state machine + safety invariants in [formal/tla](../formal/tla)
- **ProVerif**: symbolic model in [formal/proverif](../formal/proverif)
- **Verus**: wrapper invariants for Rust core in [crypto_core](../crypto_core)

**Hardware-sealed key state** is now modeled in TLA+ (seal/unseal/tamper + invariants).

**Out of scope:** AES‑GCM primitive correctness, side‑channel resilience on Python.

---

## 5) Failure & Abuse Modes (Checklist)

| Scenario | Current Behavior | Required Behavior |
|---|---|---|
| Wrong password | HMAC fails, error | ✅ fail closed, no output |
| Modified ciphertext | AEAD tag fails | ✅ fail closed |
| Reused nonce | Guard rejects | ✅ abort encryption |
| Truncated manifest | length check fails | ✅ fail closed |
| Duress password | returns decoy | ✅ decoy only |
| Corrupted frames | frame MAC rejects | ✅ discard frame |
| Replay frames | HMAC/nonce/session mismatch | ✅ fail closed |

---

## 6) Test Suite Upgrade (Initial Gaps)

- Add deterministic **crypto misuse tests** (nonce reuse, AAD mismatch).
- Add **threat‑model tests** mapping to docs/THREAT_MODEL.md.
- Add **Schrödinger mode** indistinguishability tests (statistical + adversary model).

---

## 7) Documentation for Reviewers

- README should avoid claiming proven security without referencing formal methods and assumptions.
- SECURITY.md should list precise guarantees vs assumptions.
- SECURITY_ASSUMPTIONS.md is the canonical list of trust assumptions.

---

## 8) Issues Found (Actionable)

### Critical
1) **Rust backend enforcement**
   - Risk: security regression if a fallback reappears.
   - Fix: keep Rust-only enforcement and CI checks.

2) **Schrödinger mode claim unproven**
   - Risk: over‑claiming security; possible distinguishers.
   - Fix: downgrade claim or produce formal cryptographic analysis.

### High
2) **Hardware security not fully wired to CLI**
   - Risk: security features exist but are not usable in production.
   - Fix: CLI flags + Rust backend binding + docs + tests.

---

## 9) Verified vs Assumed Checklist

### Verified (via code/model/tests)
- Auth‑then‑output state machine (TLA+).
- Frame MAC tamper rejection (protocol + code).
- Nonce uniqueness (best‑effort guard).

### Assumed
- Endpoint integrity.
- RNG correctness.
- Side‑channel resistance beyond Rust constant‑time operations.
- Schrödinger mode deniability claim.

---

*Last Updated: 2026‑01‑28*
