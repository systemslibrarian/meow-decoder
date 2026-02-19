# 🛡️ Security Roadmap — Sharpening the Claws

*Where the cat has been, and where it’s going. Completed items have been tested, reviewed, and merged. Planned items are being stalked.*

**Meow Decoder v1.0 (INTERNAL REVIEW — no external audit)**

This document outlines security improvements. Internal milestone labels (v5.x) are historical.

---

## ✅ Completed (v1.0 Release)

### Crypto Hardening
- [x] **Argon2id Ultra-Hardened**: 512 MiB memory, 20 iterations (~5-10s per attempt)
- [x] **Post-Quantum Default**: ML-KEM-768 + X25519 PQXDH hybrid (default), ML-KEM-1024 (paranoid)
- [x] **Dilithium3 Signatures**: Quantum-resistant manifest authentication
- [x] **Rust Backend Required**: Constant-time operations via `subtle` crate
- [x] **Memory Zeroing**: `zeroize` crate for automatic secret cleanup

### Protocol Security
- [x] **64-bit Monotonic Counters**: Replay protection with no wrap tolerance
- [x] **Per-Frame MAC**: 8-byte HMAC-SHA256 for DoS protection
- [x] **Nonce Reuse Guard**: Per-process cache prevents AES-GCM nonce reuse
- [x] **HKDF Domain Separation**: Unique `info` strings for all subkeys
- [x] **AAD Binding**: All manifest fields bound to ciphertext

### Forward Secrecy
- [x] **X25519 Ephemeral Keys**: Generated per-encryption, never stored
- [x] **Double Ratchet**: Signal-style key evolution for streaming
- [x] **Key Zeroization**: Ephemeral keys zeroed after use

### Testing & CI
- [x] **AFL++ Fuzzing**: Continuous fuzzing for manifest/fountain/crypto
- [x] **Mutation Testing**: mutmut for crypto-critical code paths
- [x] **Security Scanning**: pip-audit, cargo-audit, Bandit in CI
- [x] **3-Gate CI Pipeline**: Fast tests + security coverage ≥ 85% + lint/type-check (MT-2)
- [x] **Strict Pytest Markers**: `security`, `adversarial`, `crypto`, `fuzz`, `slow`, `integration`, `cat` (ST-4)
- [x] **Security Coverage Gate**: TIER 1 crypto modules ≥ 85% on PRs (ST-5)
- [x] **Manifest Bounds Validation**: Numeric bounds + decompression-bomb protection (ST-2)
- [x] **Timing Attack Harness**: Statistical timing tests for password/duress paths (MT-5)

---

## 🔄 Short-Term (Next Release)

### Enhanced Testing
- [x] **Property-Based Testing**: Hypothesis for invariant verification (`tests/test_property_based.py`)
- [x] **Differential Testing**: Archived after Rust-only enforcement (Python fallback removed)
- [x] **Coverage Goals**: 70%+ baseline with branch tracking on crypto-critical paths
- [x] **Hardware Mocks**: In-memory/mock HSM/YubiKey/TPM providers for CI without real devices

### Documentation
- [x] **Security Invariants Doc**: Formal listing of all security invariants (`docs/SECURITY_INVARIANTS.md`)
- [x] **Attack Surface Analysis**: Updated threat model with mitigations
- [x] **Secure Usage Checklist**: OPSEC guidance (`docs/SECURE_USAGE_CHECKLIST.md`) (MT-6)
- [x] **Argon2id Benchmarks**: KDF tuning & hardware timings (`docs/ARGON2ID_BENCHMARKS.md`) (ST-7)
- [x] **OpenSSF Improvement Plan**: 5-phase scorecard improvement (`OpenSSFImprovements.md`)
- [x] **Supply Chain Security**: Hash-pinned deps, Sigstore signed releases, SLSA provenance

### New Features
- [x] **Canonical AAD**: Deterministic `version_byte || fields` construction (`canonical_aad.py`) (MT-1)
- [x] **Tamper Timeline**: Frame-by-frame MAC report with cluster detection (`tamper_report.py`) (MT-7)
- [x] **Mobile Bridge Protocol**: JSON-over-WebSocket phone→CLI bridge (`mobile/bridge/protocol.py`) (MT-8)
- [x] **Self-Test CLI**: `meow-encode --self-test` verifies backend, roundtrip, fountain (ST-6)
- [x] **Duplicate Quarantine**: Deprecated paths moved to `meow_decoder/experimental/` (ST-1)
- [x] **CLI Hardware Flags**: `--hsm-slot`, `--tpm-derive`, `--hardware-auto` wired (ST-8)

---

## 🔮 Medium-Term (6-12 Months)

### Hardware Security
- [x] **HSM Integration**: PKCS#11 interface for hardware key storage
	- Fully integrated with CLI (`--hsm-slot`, `--hsm-pin`)
- [x] **YubiKey Support**: FIDO2/PIV for key derivation factor
	- Fully integrated with CLI (`--yubikey`, `--yubikey-slot`, `--yubikey-pin`)
- [x] **TPM 2.0 Binding**: Seal keys to platform state
	- Fully integrated with CLI (`--tpm-derive`, `--tpm-unseal`)

### Rust Expansion
- [x] **Rust Crypto Backend Complete**: Full migration of secret-handling crypto from Python → Rust
    - All 52 PyO3 bindings implemented: Argon2id, HKDF, AES-GCM, AES-CTR, HMAC, SHA-256, X25519, ML-KEM, + opaque handle registry
	- Constant-time via `subtle` crate, secure zeroing via `zeroize` crate
	- CI enforces `RUST_BACKEND_REQUIRED=1` — no Python fallback
	- 397 tests passing (383 protocol + 14 enforcement)
	- See `todo-crypto.md` for full migration details
- [x] **cargo-fuzz + Property Test Suite**: Full adversarial fuzzing infrastructure for Rust crypto backend
	- 5 libFuzzer targets: `fuzz_decrypt_frame`, `fuzz_header_parse`, `fuzz_hybrid_decapsulate`, `fuzz_ratchet_step`, `fuzz_full_decode_pipeline`
	- 14 proptest property tests: nonce uniqueness, ratchet monotonicity, replay, PCS healing, hybrid combiner, AAD canonicalization
	- 19 FFI boundary fuzz tests simulating Python→Rust calls with attacker-controlled inputs
	- `panic = "abort"` in release profile; ASan/UBSan/Miri CI jobs
	- CI workflow: `rust-security-suite.yml`

---
### Formal Methods
- [ ] **Formal Verification**: CI-gated Verus/Coq proofs for crypto primitives

### Third-Party Audit
- [ ] **Professional Audit**: Engage security firm for full review
- [ ] **Penetration Testing**: Red team assessment
- [ ] **CVE Process**: Establish responsible disclosure workflow

### Certification (If Demand Exists)
- [ ] **FIPS 140-3**: Module validation
- [ ] **Common Criteria**: EAL evaluation

---

## Summary

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Basic encryption (AES-GCM, Argon2id) | ✅ Complete |
| 2 | Forward secrecy (X25519, ratcheting) | ✅ Complete |
| 3 | Post-quantum hybrid (ML-KEM-768/1024 PQXDH) | ✅ Complete |
| 4 | Rust crypto backend (52 PyO3 bindings) | ✅ Complete |
| 5 | Hardware keys (HSM/YubiKey/TPM) | ✅ Complete |
| 6 | Opaque handle migration (M1–M9) | ✅ Complete |
| 7 | Third-party audit | 🔮 Planned |

---

For security vulnerabilities, see [SECURITY.md](../SECURITY.md) for responsible disclosure.

---

*Last Updated: February 18, 2026*
