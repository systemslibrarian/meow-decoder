# 🐱 Meow-Infused Ultimate Security Roadmap - TODO ASAP

**Created:** 2026-01-29  
**Status:** In Progress  
**Resume From:** Priority 1 (Audit Prep) - partially complete

---

## ✅ COMPLETED SO FAR

1. **THREAT_MODEL.md expanded** with:
   - Quantum Harvest Adversary (harvest-now-decrypt-later)
   - Side-Channel Adversary (cache/timing)
   - Remote Timing Adversary (network-based)
   - Formal Coverage Map (TLA+, ProVerif, Verus mapping)
   - Side-Channel Analysis section with mitigations table

2. **AUDIT_OUTREACH.md created** with:
   - Email templates for Trail of Bits, NCC Group, OTF, FPF
   - Audit scope summary
   - Funding sources list
   - Pre-audit checklist

---

## 📋 REMAINING TASKS

### Priority 1: Audit Prep (90% done)
- [ ] Create `docs/SELF_AUDIT_TEMPLATE.md` - internal audit checklist
- [ ] Add bug-bounty placeholder section to SECURITY.md

### Priority 2: Hardware CLI Integration
- [ ] Add `--use-hsm --slot=ID` flag to encode.py and decode_gif.py
- [ ] Add `--yubikey-piv --pin=...` flag with touch prompt
- [ ] Add `--tpm-seal --pcrs=0,7` and `--tpm-unseal` flags
- [ ] Add `--hsm-fallback-prompt` for graceful degradation
- [ ] Wire Python CLI to existing `hardware_integration.py` module
- [ ] Add integration tests mocking hardware (pytest fixtures)
- [ ] Cat-themed examples: "Purr your master key with YubiKey 😻"

### Priority 3: Switch to liboqs-rust (oqs crate)
- [ ] Add `oqs = "0.10"` to crypto_core/Cargo.toml under optional deps
- [ ] Create feature flag `liboqs-native` vs current `pq-crypto` (ml-kem/ml-dsa)
- [ ] Refactor `crypto_core/src/pq.rs` to support both backends
- [ ] Update README with liboqs build instructions
- [ ] Benchmark: compare pqcrypto vs oqs performance

### Priority 4: Side-Channel & Dependency Hardening
- [ ] Add SBOM generation to CI (`cyclonedx-py`, `cargo-sbom`)
- [ ] Document masked AES in `docs/SIDE_CHANNEL_HARDENING.md`
- [ ] Add cat-pun warnings for supply-chain issues (cargo-deny output)
- [ ] Integrate `cargo-vet` for crate audits

### Priority 5: Deniability/Coercion Boost
- [ ] Extend Tamarin model for time-lock duress properties
- [ ] Extend ProVerif model with duress password indistinguishability
- [ ] Add `--purr-mode` flag for ultra-verbose cat-themed logging
- [ ] Add `--dead-mans-switch` CLI wrapper for timelock_duress.py

### Priority 6: Polish & Future-Proof
- [ ] Create Mermaid protocol diagrams in `docs/PROTOCOL_DIAGRAMS.md`
- [ ] Add `--nine-lives` retry flag (automatic 9 retries with cat facts)
- [ ] Add `meow_about()` ASCII cat art to cat_utils.py
- [ ] Add random cat facts on idle/progress bar
- [ ] Add `purr_encrypt()`, `hiss_decrypt()`, `claw_verify_signature()` API wrappers
- [ ] Add `scratch_fountain_decode()` alias
- [ ] Add `meow_log()` with cat emojis 😻🐾🧶
- [ ] Easter egg: `--summon-void-cat` does something fun

---

## 🐱 CAT LORE REQUIREMENTS (Throughout)

**CRITICAL:** Never remove, rename, or strip any cat meme names, files, flags, strings, or branding. Instead, AMPLIFY cat lore massively:

- All new functions should have cat-themed aliases
- Error messages should include cat puns
- Progress bars should show cat emojis
- ASCII art for success/failure states
- Cat facts during long operations
- Meow sounds (optional audio)

---

## 📁 FILES TO CREATE/MODIFY

### Create:
- `docs/SELF_AUDIT_TEMPLATE.md` - Pre-audit checklist
- `docs/SIDE_CHANNEL_HARDENING.md` - SCA documentation
- `docs/PROTOCOL_DIAGRAMS.md` - Mermaid diagrams

### Modify:
- `SECURITY.md` - Add bug-bounty placeholder
- `crypto_core/Cargo.toml` - Add oqs crate
- `meow_decoder/encode.py` - Add hardware CLI flags
- `meow_decoder/decode_gif.py` - Add hardware CLI flags
- `meow_decoder/cat_utils.py` - Add meow_about(), purr_encrypt() etc.
- `formal/proverif/` - Extend duress model
- `formal/tamarin/` - Extend time-lock model

---

## 🚀 QUICK RESUME COMMAND

When ready to resume, just say:

> "Continue the Meow-Infused Ultimate Security Roadmap from todoasap.md"

I'll pick up from Priority 1 completion (SELF_AUDIT_TEMPLATE.md) and proceed through all priorities.

---

*🐱 "The cat remembers where it left off!" 😺*
