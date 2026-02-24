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
- [x] **Secure Usage Checklist**: OPSEC guidance (see `docs/USAGE.md` and `docs/THREAT_MODEL.md`) (MT-6)
- [x] **Argon2id Benchmarks**: KDF tuning & hardware timings (see `docs/THREAT_MODEL.md` brute-force section) (ST-7)
- [x] **OpenSSF Improvement Plan**: 5-phase scorecard improvement (completed, guidance integrated into CI)
- [x] **Supply Chain Security**: Hash-pinned deps, Sigstore signed releases, SLSA provenance

### New Features
- [x] **Canonical AAD**: Deterministic `version_byte || fields` construction (`canonical_aad.py`) (MT-1)
- [x] **Tamper Timeline**: Frame-by-frame MAC report with cluster detection (`tamper_report.py`) (MT-7)
- [x] **Mobile Bridge Protocol**: JSON-over-WebSocket phone→CLI bridge (`mobile/bridge/protocol.py`) (MT-8)
- [x] **Self-Test CLI**: `meow-encode --self-test` verifies backend, roundtrip, fountain (ST-6)
- [x] **Duplicate Quarantine**: Deprecated paths moved to `meow_decoder/experimental/` (ST-1)
- [x] **CLI Hardware Flags**: `--hsm-slot`, `--tpm-seal`, `--hardware-auto` wired (ST-8)

---

## 🔮 Medium-Term (6-12 Months)

### Hardware Security
- [x] **HSM Integration**: PKCS#11 interface for hardware key storage
	- Fully integrated with CLI (`--hsm-slot`, `--hsm-pin`)
- [x] **YubiKey Support**: FIDO2/PIV for key derivation factor
	- Fully integrated with CLI (`--yubikey`, `--yubikey-slot`, `--yubikey-pin`)
- [x] **TPM 2.0 Binding**: Seal keys to platform state
	- Fully integrated with CLI (`--tpm-seal`, `--tpm-unseal`)

### Rust Expansion
- [x] **Rust Crypto Backend Complete**: Full migration of secret-handling crypto from Python → Rust
    - All 73 PyO3 bindings implemented: Argon2id, HKDF, AES-GCM, AES-CTR, HMAC, SHA-256, X25519, ML-KEM, + opaque handle registry
	- Constant-time via `subtle` crate, secure zeroing via `zeroize` crate
	- CI enforces `RUST_BACKEND_REQUIRED=1` — no Python fallback
	- 2,380+ Python tests + 676 Rust tests passing across 83+ test files
	- See `todo-crypto.md` for full migration details
- [x] **cargo-fuzz + Property Test Suite**: Full adversarial fuzzing infrastructure for Rust crypto backend
	- 5 libFuzzer targets: `fuzz_decrypt_frame`, `fuzz_header_parse`, `fuzz_hybrid_decapsulate`, `fuzz_ratchet_step`, `fuzz_full_decode_pipeline`
	- 14 proptest property tests: nonce uniqueness, ratchet monotonicity, replay, PCS healing, hybrid combiner, AAD canonicalization
	- 19 FFI boundary fuzz tests simulating Python→Rust calls with attacker-controlled inputs
	- `panic = "abort"` in release profile; ASan/UBSan/Miri CI jobs
	- CI workflow: `rust-security-suite.yml`
- [x] **Multi-Layer Steganography Adversarial Review**: Comprehensive security audit of 3-channel stego system
	- 8 bugs fixed: 3 critical (nonce reuse, fail-open, seed mismatch, STC broken), 3 high (palette NO-OPs, capacity warn-only), 1 medium (Fisher-Yates bias)
	- 80 adversarial tests (`tests/test_stego_adversarial.py`) + 17 Hypothesis fuzz tests (`tests/test_stego_fuzz.py`)
	- Static analysis clean: clippy, Bandit, flake8
	- 464 total tests passing (321 Rust + 126 Python + 17 fuzz)
	- Strength evaluation published: `docs/STEGO_STRENGTH_EVALUATION.md`
- [x] **Multi-Layer Steganography Phase 1**: Temporal, adversarial, and cat mode pipeline upgrades
	- 3 new channels: TemporalChannelEncoder (cross-frame delta parity), AdversarialPerturbationLayer (steganalysis hardening), ProceduralCatGenerator (unique carrier generation)
	- Cat Mode fix: APNG output (lossless) replaces GIF (lossy palette quantization destroyed LSB stego data)
	- `decode_gif.py`: Automatic stego LSB extraction fallback + frame index tracking for MAC verification
	- 49 Phase 1 tests + 20 web demo integration tests (4 modes × 5 runs)
	- Duress mode test: X25519 forward secrecy keypair for distinct manifest format
- [x] **Stego 4-Session Audit Complete**: Internal audit of 6-channel multi-layer stego system
	- 43/43 artifacts PASS (RS <0.05, Chi²=0.000, SPA <0.02, PSNR 36–50 dB)
	- 11 bugs found and fixed across 4 audit sessions (4 critical, 4 high, 3 medium)
	- STC Viterbi trellis: 100% reliable, ~50× faster than Gaussian elimination
	- Published: `docs/STEGO_AUDIT_REPORT.md`, updated `docs/STEGO_STRENGTH_EVALUATION.md`
	- Evasion testing: binwalk PASS, exiftool PASS, chi² PASS, zsteg measured PASS
	- 252 stego-specific unit tests PASS

### Documentation & Quality (Feb 21, 2026)
- [x] **README Accuracy Audit**: Fixed CLI flags, test count (400→1800+), stego levels, 7 dead doc links
- [x] **QUICKSTART Accuracy Audit**: Fixed broken demo (password, content, forward secrecy flags, dead links)
- [x] **Web Demo README Audit**: Fixed GitHub URLs, file size limits, line refs, project structure (5→10 templates)
- [x] **demo.gif Regenerated**: Replaced legacy-format demo.gif with current MEOW2 format (John 3:16, working roundtrip)
- [x] **Self-Test Bugs Fixed**: `meow-encode --self-test` now 4/4 PASS (fixed `get_backend_name`, fountain `original_length`)
- [x] **Entry Point Added**: `meow-schrodinger-encode` CLI command registered in `pyproject.toml`
- [x] **Comparison Report**: Head-to-head Meow vs StegX vs Signal analysis (`docs/MEOW_VS_STEGX_VS_SIGNAL.md`)
- [x] **1800+ Tests Passing**: Full test suite green (1819 passed, 22 skipped, 0 failed)

### Comprehensive Bug Audit (Feb 25, 2026)
- [x] **16 Security/Correctness Fixes**: Rust nonce CAS loops, X25519 zero-check, HKDF length enforcement, ML-KEM-1024 paranoid dispatch, fountain thread safety, stego LSB preservation, deferred ratchet init, config safety, Schrödinger password validation
- [x] **Rust Hardening**: `OsRng` for `secure_random()`, ML-KEM-1024 PyO3 exports
- [x] **3435+ Tests Passing**: 2462 Python + 973 Rust tests across 68+ test files

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
| 4 | Rust crypto backend (73 PyO3 bindings) | ✅ Complete |
| 5 | Hardware keys (HSM/YubiKey/TPM) | ✅ Complete |
| 6 | Opaque handle migration (M1–M9) | ✅ Complete |
| 7 | Multi-layer stego audit (4 sessions, 43 artifacts) | ✅ Complete |
| 8 | Documentation accuracy audit & comparison report | ✅ Complete |
| 9 | Comprehensive bug audit (16 fixes, Rust + Python) | ✅ Complete |
| 10 | Third-party audit | 🔮 Planned |

---

For security vulnerabilities, see [SECURITY.md](../SECURITY.md) for responsible disclosure.

---

*Last Updated: February 25, 2026*
